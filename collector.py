#!/usr/bin/env python3
"""FlowTrack collector: NetFlow v5/v9 and IPFIX -> enrichment -> ClickHouse.

- Every record is stored as received: FortiOS (and NetFlow v9/IPFIX in general) export
  DELTA counters per active-timeout interval, so traffic = sum of records.
- Inside/outside endpoint and direction come from the exporter's WAN interfaces when they
  are configured (exporters.json), otherwise from RFC 1918 / CGNAT address ranges.
- Optionally forwards every received datagram unchanged to other collectors (FT_FORWARD),
  so an existing collector keeps working on the same exporter feed.
"""
import json
import multiprocessing as mp
import os
import queue
import select
import signal
import socket
import struct
import sys
import time
from collections import deque
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ftcore  # noqa: E402
from common import (STATE_DIR, VERSION, CHError, Geo, apply_schema, ch, classify_l7, describe_listeners, edition,  # noqa: E402
                    exporters_mtime, flows_retention_days, is_private, listen_label, listen_signature, load_exporters, open_listeners, service_name)

BIND = os.environ.get('FT_BIND', '0.0.0.0')
PORT = int(os.environ.get('FT_PORT', '2055'))
FORWARD = [(h, int(p)) for h, p in (x.strip().rsplit(':', 1) for x in os.environ.get('FT_FORWARD', '').split(',') if x.strip())]
ALLOW = {x.strip() for x in os.environ.get('FT_EXPORTERS', '').split(',') if x.strip()}
TEMPLATES_FILE = os.path.join(STATE_DIR, 'templates.json')
RCVBUF = int(os.environ.get('FT_RCVBUF', str(32 * 1024 * 1024)))   # capped by net.core.rmem_max (install.sh raises it)
BATCH_SECONDS = 2.0
BATCH_MAX = 20000
BUFFER_MAX = 500000        # rows kept in memory while ClickHouse is down
SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'schema.sql')
DISPATCH_EVERY = 64        # packets per batch handed to a worker (or after DISPATCH_SECONDS)
DISPATCH_SECONDS = 0.02
DUP_WINDOW = 2.0           # s: the same packet again from the same exporter within this time is a copy (dropped)
QUEUE_MAX = 500            # batches waiting per worker (~32k packets, a few seconds of a burst); beyond that: queue drops


def workers_setting(v=None):
    """FT_WORKERS: number of decoding processes; 'auto' = half the CPUs, at most 4."""
    v = (os.environ.get('FT_WORKERS', 'auto') if v is None else v).strip().lower()
    if v in ('', 'auto'):
        return max(1, min(4, (os.cpu_count() or 2) // 2))
    try:
        return max(1, min(64, int(v)))
    except ValueError:
        return 1


def log(msg):
    print(f'[flowtrack] {msg}', flush=True)


def norm_addr(ip):
    """'::ffff:192.0.2.1' (IPv4 on a dual-stack socket) -> '192.0.2.1'; drop IPv6 zone ids."""
    ip = ip.split('%', 1)[0]
    return ip[7:] if ip.startswith('::ffff:') and '.' in ip else ip


def parse_ratio(v):
    """'1:1000' / '1000' -> 1000; anything invalid -> 1."""
    try:
        n = int(str(v).split(':')[-1])
        return n if n >= 1 else 1
    except (TypeError, ValueError):
        return 1


def utc(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def utc_ms(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]


class Exporter:
    """What the configuration says about an exporter; decoding state (templates, sampling learned from options
    records, the interfaces seen on ingress) lives in the compiled core."""
    def __init__(self, ip, cfg):
        self.ip = ip
        self.configure(cfg)

    def configure(self, cfg):
        self.wan = set(cfg.get('wan_ifs', []))
        self.local_if = cfg.get('local_if')          # FortiOS: 0 = the firewall itself
        self.self_ips = {norm_addr(str(x)) for x in cfg.get('public_ips', [])}   # the device's own public addresses
        self.cfg_sampling = parse_ratio(cfg.get('sampling', '1:1'))


# ---- packet accounting without decoding records: sequence numbers -> lost packets, and which packets
# carry templates / options data (every worker must see those). Runs in the receiver for every packet.
class Accounting:
    def __init__(self):
        self.ex = {}

    def take(self):
        """{ip: {packets, lost, version, dup_packets}} since the last call."""
        out = {ip: {'packets': x['packets'], 'lost': x['lost'], 'version': x['version'], 'dup_packets': x['dups']}
               for ip, x in self.ex.items() if x['packets'] or x['dups']}
        for x in self.ex.values():
            x['packets'] = x['lost'] = x['dups'] = 0
        return out

    def account(self, ip, data, now=None):
        """Count the packet; True if it carries templates or options records, None if it repeats a packet
        received within DUP_WINDOW (the caller drops it: neither stored nor counted for loss)."""
        x = self.ex.get(ip)
        if x is None:
            x = self.ex[ip] = {'packets': 0, 'lost': 0, 'version': 0, 'tpl': {}, 'seq': {}, 'dups': 0, 'recent': {}, 'order': deque()}
        # some exporters send the same packet several times (seen: RouterOS 7 after a traffic-flow change sent every
        # packet 4x, each copy with its own sequence counter), so compare everything except the sequence number
        now = time.monotonic() if now is None else now
        recent, order = x['recent'], x['order']
        while order and now - order[0][0] > DUP_WINDOW:
            t, k = order.popleft()
            if recent.get(k) == t:
                del recent[k]
        key = hash(packet_body(data))
        if key in recent:
            x['dups'] += 1
            return None
        recent[key] = now
        order.append((now, key))
        x['packets'] += 1
        try:
            ver, seq, dom, nrec, shared = peek(data, x['tpl'])
        except (struct.error, IndexError):
            return True                     # malformed: let a worker count it as a decode error
        if ver in (5, 9, 10):
            x['version'] = ver
        if seq is None:
            return shared
        last = x['seq'].get(dom)
        if last is not None:
            diff = (seq - last[0]) % 2**32
            if ver == 9:                     # v9 counts export packets
                if 0 < diff < 100000:
                    x['lost'] += diff - 1
            elif last[1] is not None and 0 < diff < 1000000:   # v5 counts flows, IPFIX data records
                x['lost'] += max(0, diff - last[1])
        x['seq'][dom] = (seq, nrec)
        return shared


def _tpl_fields(body, off, n, ipfix):
    """Length of a record made of n fields starting at off (None if variable-length) and the new offset."""
    length = 0
    for _ in range(n):
        ftype, flen = struct.unpack_from('!HH', body, off)
        off += 4
        if ipfix and ftype & 0x8000:
            off += 4                         # enterprise number
        if flen == 0xFFFF:
            length = None
        elif length is not None:
            length += flen
    return length, off


def packet_body(data):
    """The packet without its sequence number (copies of one export differ only there)."""
    if len(data) >= 20:
        ver = data[1] if data[0] == 0 else 0
        if ver == 9:
            return data[:12] + data[16:]
        if ver == 10:
            return data[:8] + data[12:]
        if ver == 5:
            return data[:16] + data[20:]
    return data


def peek(data, tpl):
    """(version, sequence, domain, data records or None if unknown, carries templates/options data).
    tpl = {(domain, template id): (record length or None, is options template)}, learned here."""
    ver, = struct.unpack_from('!H', data)
    if ver == 5:
        count, = struct.unpack_from('!H', data, 2)
        seq, = struct.unpack_from('!I', data, 16)
        return 5, seq, 0, count, False
    if ver == 9:
        seq, dom = struct.unpack_from('!II', data, 12)
        pos, t_id, o_id, ipfix = 20, 0, 1, False
    elif ver == 10:
        seq, dom = struct.unpack_from('!II', data, 8)
        pos, t_id, o_id, ipfix = 16, 2, 3, True
    else:
        return ver, None, 0, None, False
    nrec, shared = 0, False
    while pos + 4 <= len(data):
        sid, slen = struct.unpack_from('!HH', data, pos)
        if slen < 4:
            break
        body = data[pos + 4:pos + slen]
        if sid == t_id:
            shared, off = True, 0
            while off + 4 <= len(body):
                tid, n = struct.unpack_from('!HH', body, off)
                if tid < 256:                # padding
                    break
                length, off = _tpl_fields(body, off + 4, n, ipfix)
                tpl[(dom, tid)] = (length, False)
        elif sid == o_id:
            shared, off = True, 0
            while off + 6 <= len(body):
                tid, a, b = struct.unpack_from('!HHH', body, off)
                if tid < 256:
                    break
                n = a if ipfix else (a + b) // 4          # IPFIX: field count; v9: scope + option bytes
                length, off = _tpl_fields(body, off + 6, n, ipfix)
                tpl[(dom, tid)] = (length, True)
        elif sid >= 256:
            t = tpl.get((dom, sid))
            if t is None or not t[0]:
                nrec = None                  # unknown template: records cannot be counted
            else:
                shared = shared or t[1]      # options data (sampler configuration)
                if nrec is not None:
                    nrec += (slen - 4) // t[0]
        pos += slen
    return ver, seq, dom, nrec, shared


class Collector:
    """Decodes packets and writes flows to ClickHouse. One per worker process; the receiver feeds it.
    Used directly (tests, benchmarks), it also does the packet accounting itself."""
    def __init__(self, worker=0, accounting=True, workers=1, rate_limit=True):
        self.worker = worker
        self.workers = max(1, workers)
        # the edition's records/s limit, shared evenly by the workers (the receiver spreads packets round-robin);
        # rate_limit=False is for benchmarks that measure the decoder itself
        self.rate_limited = rate_limit
        self.rps = edition()['rps'] if rate_limit else None
        # the compiled core decodes and applies the limit (rate=0, unlimited, exists in test builds of it only)
        self.dec = ftcore.Decoder(self.workers) if rate_limit else ftcore.Decoder(self.workers, rate=0)
        self.geo = Geo()
        self.cfg = load_exporters()
        self.cfg_mtime = exporters_mtime()
        self.exporters = {}
        self.acct = Accounting() if accounting else None
        self.buf = []
        self.dropped = 0
        self._saved_templates = None
        self.last_flush = self.last_tick = time.time()

    def exporter(self, ip):
        e = self.exporters.get(ip)
        if e is None:
            e = self.exporters[ip] = Exporter(ip, self.cfg.get(ip, {}))
            if self.worker == 0:
                log(f'new exporter {ip} (wan interfaces: {sorted(e.wan) or "not configured, using RFC1918"})')
        return e

    # ------------------------------------------------------------ records
    def store(self, e, f):
        """One decoded flow (a tuple from the core, already within the records/s limit) -> a row."""
        (src, dst, nbytes, npkts, proto, sport, dport, in_if, out_if, obs,
         nat_src, nat_sport, nat_dst, nat_dport, start, end, app_tag, rate) = f
        if rate <= 1:
            rate = e.cfg_sampling
        if rate > 1:                    # sampled exporters report 1 of every N packets: scale up
            nbytes, npkts = nbytes * rate, npkts * rate

        # inside / outside endpoint and direction
        if e.wan and out_if in e.wan and in_if not in e.wan:
            d, ii, ei = 'up', (src, sport), (dst, dport)
        elif e.wan and in_if in e.wan and out_if not in e.wan:
            d, ii, ei = 'down', (dst, dport), (src, sport)
        else:
            # no WAN interface matched: decide by address — the device's own public addresses count as inside
            ps, pd = is_private(src) or src in e.self_ips, is_private(dst) or dst in e.self_ips
            if ps and not pd:
                d, ii, ei = 'up', (src, sport), (dst, dport)
            elif pd and not ps:
                d, ii, ei = 'down', (dst, dport), (src, sport)
            elif ps and pd:
                d, ii, ei = 'internal', (src, sport), (dst, dport)
            else:
                d, ii, ei = 'transit', (src, sport), (dst, dport)

        if d == 'up':
            nat_ip, nat_port = nat_src, nat_sport
        elif d == 'down':
            nat_ip, nat_port = nat_dst, nat_dport
        else:
            nat_ip, nat_port = '', 0
        if nat_ip in ('0.0.0.0', '::'):
            nat_ip, nat_port = '', 0

        country, city, lat, lon, asn, as_org = self.geo.lookup(ei[0])
        l7, port_service = classify_l7(proto, ei[1])
        self.buf.append({
            'ts': utc(end), 'ts_start': utc_ms(start), 'exporter': e.ip, 'in_if': in_if, 'out_if': out_if, 'dir': d,
            'int_ip': ii[0], 'int_port': ii[1], 'ext_ip': ei[0], 'ext_port': ei[1], 'proto': proto,
            'nat_ip': nat_ip, 'nat_port': nat_port, 'bytes': nbytes, 'packets': npkts, 'sampling': rate,
            'l7': l7, 'service': service_name(port_service, asn, as_org, ei[0]),
            'country': country, 'city': city, 'lat': lat, 'lon': lon, 'asn': asn, 'as_org': as_org,
            'app_tag': app_tag, 'obs': obs,
        })

    def handle_packet(self, data, addr, learn_only=False):
        """learn_only: another worker stores this packet's flows; only learn its templates / sampling here."""
        ip = norm_addr(addr[0])
        if ALLOW and ip not in ALLOW and ip not in self.cfg:     # allow-list = env + devices configured (incl. from the UI)
            return
        if self.acct:
            self.acct.account(ip, data)
        e = self.exporter(ip)
        for f in self.dec.packet(ip, data, time.time(), learn_only):
            self.store(e, f)

    # ------------------------------------------------------------ output
    def flush(self):
        if not self.buf:
            return
        batch = self.buf[:BATCH_MAX]
        body = '\n'.join(json.dumps(r, separators=(',', ':')) for r in batch).encode()
        try:
            ch('INSERT INTO flows FORMAT JSONEachRow', data=body, timeout=20)
            del self.buf[:len(batch)]
        except (CHError, OSError) as ex:
            log(f'WARN insert failed ({len(self.buf)} rows buffered): {str(ex)[:200]}')
            if len(self.buf) > BUFFER_MAX:
                drop = len(self.buf) - BUFFER_MAX
                del self.buf[:drop]
                self.dropped += drop

    def take_stats(self):
        """Per-exporter decoding counters since the last call, plus this worker's output state."""
        exp = {}
        stats, license_dropped = self.dec.take_stats()
        for ip, x in stats.items():
            if x['last_error']:
                log(f"WARN {x['decode_errors']} packet(s) from {ip} could not be decoded: {x['last_error']}")
            if x['records'] or x['no_template'] or x['decode_errors'] or x['dup_dropped']:
                e = self.exporter(ip)
                exp[ip] = {k: x[k] for k in ('records', 'no_template', 'decode_errors', 'dup_dropped', 'templates')}
                exp[ip]['sampling'] = max(x['sampling'], x['opt_sampling'] or 1, e.cfg_sampling)
        out = {'exp': exp, 'buffered': len(self.buf), 'dropped_rows': self.dropped, 'license_dropped': license_dropped}
        self.dropped = 0
        return out

    def save_templates(self):
        text = self.dec.templates_json()
        if text == self._saved_templates:
            return
        try:
            tmp = TEMPLATES_FILE + '.tmp'
            with open(tmp, 'w') as f:
                f.write(text)
            os.replace(tmp, TEMPLATES_FILE)
            self._saved_templates = text
        except OSError as ex:
            log(f'WARN cannot save templates: {ex}')

    def load_templates(self):
        try:
            with open(TEMPLATES_FILE) as f:
                text = f.read()
            data = json.loads(text)
        except FileNotFoundError:
            return
        except (OSError, ValueError) as ex:
            log(f'WARN cannot read saved templates: {ex}')
            return
        n = 0
        for ip, t in data.items():
            if ALLOW and ip not in ALLOW and ip not in self.cfg:
                continue
            self.exporter(ip)
            try:
                n += self.dec.load_templates(ip, json.dumps(t))
            except ValueError as ex:
                log(f'WARN skipping saved templates of {ip}: {ex}')
        self._saved_templates = text
        log(f'restored {n} templates for {len(data)} exporter(s)')

    def reload_config(self):
        """Pick up devices added/edited in the UI without a restart."""
        mt = exporters_mtime()
        if mt == self.cfg_mtime:
            return
        self.cfg_mtime, self.cfg = mt, load_exporters()
        for ip, e in self.exporters.items():
            e.configure(self.cfg.get(ip, {}))
        log(f'exporter config reloaded ({len(self.cfg)} configured)')

    def tick(self, now):
        if now - self.last_flush >= BATCH_SECONDS or len(self.buf) >= BATCH_MAX:
            self.flush()
            self.last_flush = now
        if now - self.last_tick >= 10:
            self.last_tick = now
            if self.worker == 0:            # every worker sees every template; one of them saves them
                self.save_templates()
            self.reload_config()
            if self.rate_limited:            # a license change applies without a restart (the core's limiter follows)
                self.rps = edition()['rps']


def worker_main(n, q, results, ppid, workers=1):
    """Decoding process: batches of (packet, exporter ip, learn_only) from the receiver -> ClickHouse."""
    signal.signal(signal.SIGTERM, signal.SIG_IGN)     # the receiver stops us with a sentinel after draining
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    c = Collector(worker=n, accounting=False, workers=workers)
    c.load_templates()
    last_report = time.time()
    while True:
        try:
            batch = q.get(timeout=0.5)
        except queue.Empty:
            batch = ()
        if batch is None:
            break
        for data, ip, learn in batch:
            c.handle_packet(data, (ip, 0), learn)
        now = time.time()
        c.tick(now)
        if now - last_report >= 10:
            results.put((n, c.take_stats()))
            last_report = now
        if os.getppid() != ppid:            # receiver gone (killed): stop instead of idling forever
            break
    while c.buf:                             # write everything that is left; stop only if ClickHouse fails
        left = len(c.buf)
        c.flush()
        if len(c.buf) >= left:
            log(f'WARN worker {n}: {len(c.buf)} rows not written at shutdown')
            c.dropped += len(c.buf)
            break
    if n == 0:
        c.save_templates()
    results.put((n, c.take_stats()))


class Receiver:
    """Reads the UDP socket as fast as possible, accounts packets per exporter, and spreads them over the
    workers round-robin. Packets carrying templates or options data go to every worker (one stores the
    flows, the others only learn), so a single busy exporter is decoded in parallel."""

    def __init__(self, workers):
        self.n = workers
        self.acct = Accounting()
        self.cfg = load_exporters()
        self.cfg_mtime = exporters_mtime()
        self.exp_acc, self.col_acc = {}, self.empty_col()
        self.worker_state = {}
        self.rr = 0
        self.last_rx = (0, 0)

    @staticmethod
    def empty_col():
        return {'packets': 0, 'socket_drops': 0, 'queue_drops': 0, 'dropped_rows': 0, 'license_drops': 0, 'rx_queue_peak': 0}

    def start_worker(self, i):
        p = self.ctx.Process(target=worker_main, args=(i, self.queues[i], self.results, os.getpid(), self.n), name=f'flowtrack-worker-{i}', daemon=True)
        p.start()
        self.procs[i] = p

    def dispatch(self):
        for i, items in enumerate(self.pending):
            if not items:
                continue
            try:
                self.queues[i].put_nowait(items)
            except queue.Full:
                self.col_acc['queue_drops'] += sum(1 for it in items if not it[2])
            self.pending[i] = []
        self.npending = 0

    def drain_results(self):
        while True:
            try:
                n, st = self.results.get_nowait()
            except queue.Empty:
                return
            self.worker_state[n] = st['buffered']
            self.col_acc['dropped_rows'] += st['dropped_rows']
            self.col_acc['license_drops'] += st.get('license_dropped', 0)
            for ip, x in st['exp'].items():
                a = self.exp_acc.setdefault(ip, {'packets': 0, 'lost': 0, 'version': 0, 'records': 0, 'no_template': 0, 'dup_dropped': 0,
                                                 'decode_errors': 0, 'templates': 0, 'sampling': 1})
                for k in ('records', 'no_template', 'decode_errors', 'dup_dropped'):
                    a[k] += x[k]
                a['templates'] = max(a['templates'], x['templates'])
                a['sampling'] = max(a['sampling'], x['sampling'])

    def sample_socket(self):
        """Kernel counters of our socket: cumulative drops (receive buffer full) and bytes queued now."""
        st = socket_counters(self.socks)
        if st is None:
            return
        drops, rxq = st
        if drops >= self.last_rx[0]:
            self.col_acc['socket_drops'] += drops - self.last_rx[0]
        self.last_rx = (drops, rxq)
        self.col_acc['rx_queue_peak'] = max(self.col_acc['rx_queue_peak'], rxq)

    def write_stats(self):
        for ip, x in self.acct.take().items():
            a = self.exp_acc.setdefault(ip, {'packets': 0, 'lost': 0, 'version': 0, 'records': 0, 'no_template': 0, 'dup_dropped': 0,
                                             'decode_errors': 0, 'templates': 0, 'sampling': 1})
            a['packets'] += x['packets']
            a['lost'] += x['lost']
            a['dup_packets'] = a.get('dup_packets', 0) + x['dup_packets']
            a['version'] = x['version'] or a['version']
        now = utc(time.time())
        rows = [{'ts': now, 'exporter': ip, **a} for ip, a in self.exp_acc.items() if a['packets'] or a['records']]
        col = {'ts': now, 'workers': sum(1 for p in self.procs if p.is_alive()), 'rcvbuf': self.rcvbuf,
               'buffered': sum(self.worker_state.values()), **self.col_acc}
        try:
            if rows:
                ch('INSERT INTO exporter_stats FORMAT JSONEachRow', data='\n'.join(json.dumps(r) for r in rows).encode())
            self.exp_acc = {}
            ch('INSERT INTO collector_stats FORMAT JSONEachRow', data=json.dumps(col).encode())
            self.col_acc = self.empty_col()
        except (CHError, OSError) as ex:
            log(f'WARN stats insert failed: {str(ex)[:200]}')

    def apply_retention(self):
        """A license entered in the UI may keep flow details longer: raise the TTL without a restart (never lower it)."""
        days = edition()['retention_days']
        if days != getattr(self, 'retention_target', None):
            try:
                kept = flows_retention_days(days)
                self.retention_target = days
                log(f'flow details kept {kept} days')
            except (CHError, OSError) as ex:
                log(f'WARN could not check the retention of flows: {ex}')

    def reload_config(self):
        mt = exporters_mtime()
        if mt != self.cfg_mtime:
            self.cfg_mtime, self.cfg = mt, load_exporters()

    def run(self):
        for attempt in range(60):
            try:
                apply_schema(SCHEMA)
                break
            except (CHError, OSError) as ex:
                log(f'waiting for ClickHouse ({ex.__class__.__name__}) ...')
                time.sleep(2)
        else:
            log('ClickHouse not reachable, exiting')
            sys.exit(1)
        ed = edition()
        log(f"FlowTrack {VERSION}, edition {ed['name']} ({ed['status']}): {ed['rps'] or 'unlimited'} records/s")
        self.apply_retention()
        try:
            self.listeners = open_listeners(BIND, PORT, socket.SOCK_DGRAM, set_rcvbuf, log)
        except (OSError, ValueError) as ex:
            log(f'cannot listen on FT_BIND={BIND!r} port {PORT}: {ex}')
            sys.exit(1)
        self.socks = [s for s, _ in self.listeners]
        self.listen_sig = listen_signature(BIND)
        for sock in self.socks:
            sock.setblocking(False)
        self.rcvbuf = self.socks[0].getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        fwd_socks = {fwd: socket.socket(socket.AF_INET6 if ':' in fwd[0] else socket.AF_INET, socket.SOCK_DGRAM) for fwd in FORWARD}
        self.ctx = mp.get_context('spawn')
        self.queues = [self.ctx.Queue(maxsize=QUEUE_MAX) for _ in range(self.n)]
        self.results = self.ctx.Queue()
        self.procs = [None] * self.n
        for i in range(self.n):
            self.start_worker(i)
        self.pending, self.npending = [[] for _ in range(self.n)], 0
        listen = describe_listeners(self.listeners)
        where = '; '.join(listen_label(x) for x in listen)
        log(f'listening on UDP {PORT}: {where}; {self.n} worker(s); socket buffer {self.rcvbuf // 1024} KiB; '
            f'forwarding to {FORWARD or "nobody"}; exporters allowed: {sorted(ALLOW) or "any"}')
        write_state({'port': PORT, 'bind': BIND, 'listen': listen, 'workers': self.n, 'started': int(time.time())})
        if self.rcvbuf < RCVBUF:
            log(f'NOTE socket buffer capped by net.core.rmem_max; raise it to {RCVBUF} to absorb bursts (install.sh does)')
        stop = False

        def on_signal(*_):
            nonlocal stop
            stop = True
        signal.signal(signal.SIGTERM, on_signal)
        signal.signal(signal.SIGINT, on_signal)

        last_dispatch = last_sec = last_min = time.time()
        while not stop:
            try:
                ready = select.select(self.socks, [], [], DISPATCH_SECONDS)[0]
            except (OSError, ValueError):
                if stop:
                    break
                raise
            for sock in ready:
                for _ in range(DISPATCH_EVERY):          # drain a burst, then let the other sockets have a turn
                    try:
                        data, addr = sock.recvfrom(65535)
                    except (BlockingIOError, InterruptedError):
                        break
                    for fwd in FORWARD:
                        try:
                            fwd_socks[fwd].sendto(data, fwd)
                        except OSError:
                            pass
                    ip = norm_addr(addr[0])
                    if ALLOW and ip not in ALLOW and ip not in self.cfg:
                        continue
                    self.col_acc['packets'] += 1
                    shared = self.acct.account(ip, data)
                    if shared is None:
                        continue                         # a repeated copy of a packet already taken
                    if shared:
                        for i in range(self.n):
                            self.pending[i].append((data, ip, i != self.rr))
                    else:
                        self.pending[self.rr].append((data, ip, False))
                    self.rr = (self.rr + 1) % self.n
                    self.npending += 1
            now = time.time()
            if self.npending >= DISPATCH_EVERY or (self.npending and now - last_dispatch >= DISPATCH_SECONDS):
                self.dispatch()
                last_dispatch = now
            if now - last_sec >= 1:
                last_sec = now
                self.sample_socket()
                self.drain_results()
                for i, p in enumerate(self.procs):
                    if not p.is_alive():
                        log(f'WARN worker {i} exited (code {p.exitcode}); restarting')
                        self.start_worker(i)
            if now - last_min >= 60:
                last_min = now
                self.write_stats()
                self.reload_config()
                self.apply_retention()
                sig = listen_signature(BIND)
                if sig != self.listen_sig:          # an interface got another address (DHCP): systemd restarts us
                    log(f'listening addresses changed ({", ".join(self.listen_sig)} -> {", ".join(sig or ["none"])}); restarting')
                    stop = True
        self.dispatch()
        for q in self.queues:
            try:
                q.put(None, timeout=5)
            except queue.Full:
                pass
        deadline = time.time() + 60
        for p in self.procs:
            p.join(max(0.1, deadline - time.time()))
        self.sample_socket()
        self.drain_results()
        self.write_stats()
        log('stopped')


def socket_counters(socks):
    """(drops, bytes queued) summed over our UDP sockets, from /proc/net/udp[6]; None if not found."""
    inodes = {str(os.fstat(s.fileno()).st_ino) for s in socks}
    drops = queued = found = 0
    for path in ('/proc/net/udp6', '/proc/net/udp'):
        try:
            with open(path) as f:
                next(f)
                for line in f:
                    p = line.split()
                    if len(p) > 12 and p[9] in inodes:
                        drops += int(p[-1])
                        queued += int(p[4].split(':')[1], 16)
                        found += 1
        except (OSError, StopIteration, ValueError):
            continue
    return (drops, queued) if found else None


def write_state(info):
    """What the collector listens on, for the web UI (it may bind elsewhere than the web server)."""
    try:
        tmp = os.path.join(STATE_DIR, 'collector.json.tmp')
        with open(tmp, 'w') as f:
            json.dump(info, f)
        os.replace(tmp, os.path.join(STATE_DIR, 'collector.json'))
    except OSError as ex:
        log(f'WARN cannot write collector state: {ex}')


def set_rcvbuf(s):
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF)


def udp_listener(bind, port):
    """The first socket for FT_BIND-style `bind` (tests use this)."""
    return open_listeners(bind, port, socket.SOCK_DGRAM, set_rcvbuf, log)[0][0]


if __name__ == '__main__':
    Receiver(workers_setting()).run()
