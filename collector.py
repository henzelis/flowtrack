#!/usr/bin/env python3
"""flowtrack-collector: NetFlow v9 collector for FortiGate -> SQLite.

FortiOS NetFlow v9 semantics (verified on a live FortiOS 7.4 capture):
- ONE record per direction of a session (src/dst swapped pairs).
- IN_BYTES == OUT_BYTES in each record = bytes of that direction.
- Records are DELTAS: a long session is re-exported every active-flow-timeout,
  and each export covers only [FIRST_SWITCHED, LAST_SWITCHED] — the next
  export's FIRST_SWITCHED equals the previous LAST_SWITCHED. So the correct
  accounting is simply: sum every record. No per-session state is needed.
- INPUT_SNMP/OUTPUT_SNMP carry interface snmp-index. Direction is taken from
  them: leaving via WAN = up, entering via WAN = down. Index 0 = the firewall
  itself (its own VPN tunnels, syslog, management traffic).

Each record's bytes are spread across the minutes its [FIRST, LAST] interval
covers, so charts reflect when traffic actually flowed, not when it was exported.

Table:
  usage_min(ts, host, down_bytes, up_bytes, pkts, flows) -- per minute x host,
  plus a synthetic host '__WAN__' with the WAN totals. Powers all charts.
"""
import ipaddress
import os
import signal
import socket
import sqlite3
import time

from netflow import parse_packet
from netflow.v9 import V9TemplateNotRecognized

# Configuration via environment variables (see README / deploy/flowtrack.env.example).
BIND_HOST = os.environ.get('FLOWTRACK_BIND', '0.0.0.0')
BIND_PORT = int(os.environ.get('FLOWTRACK_PORT', '2055'))
DATA_DIR = os.environ.get('FLOWTRACK_DATA_DIR', '/opt/flowtrack')
DB_PATH = os.path.join(DATA_DIR, 'data.db')
# snmp-index of the WAN interface on FortiGate (check: show system interface wan)
WAN_SNMP_INDEX = int(os.environ.get('FLOWTRACK_WAN_SNMP_INDEX', '1'))
# Exporter IPs allowed to send NetFlow, comma-separated. Empty = accept any (not recommended).
EXPORTERS = {ip.strip() for ip in os.environ.get('FLOWTRACK_EXPORTERS', '').split(',') if ip.strip()}
FLUSH_EVERY = 15            # seconds between DB writes
STATS_EVERY = 600           # seconds between stats log lines
FW_HOST = 'firewall'        # host label for traffic the firewall itself originates/terminates
LOCAL_SNMP_INDEX = 0

SCHEMA = """
CREATE TABLE IF NOT EXISTS usage_min (
    ts INTEGER NOT NULL,
    host TEXT NOT NULL,
    down_bytes INTEGER NOT NULL DEFAULT 0,
    up_bytes INTEGER NOT NULL DEFAULT 0,
    pkts INTEGER NOT NULL DEFAULT 0,
    flows INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ts, host)
);
"""


def log(msg):
    print(f'[flowtrack] {msg}', flush=True)


def ipstr(v):
    """Normalize an IP field (int or str) to its canonical string, or None."""
    if v is None:
        return None
    try:
        return str(ipaddress.ip_address(int(v) if isinstance(v, int) or str(v).isdigit() else str(v)))
    except (ValueError, TypeError):
        return None


def intfield(rec, name):
    try:
        return int(rec.get(name) or 0)
    except (TypeError, ValueError):
        return 0


def open_db():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=NORMAL')
    db.executescript(SCHEMA)
    cols = {r[1] for r in db.execute('PRAGMA table_info(usage_min)')}
    if 'flows' not in cols:     # DB created by v1
        db.execute('ALTER TABLE usage_min ADD COLUMN flows INTEGER NOT NULL DEFAULT 0')
    db.commit()
    return db


def classify(rec):
    """Return (host, direction) for a WAN-crossing record, else None.
    host = the inside endpoint (LAN IP before NAT, or 'firewall')."""
    in_if, out_if = intfield(rec, 'INPUT_SNMP'), intfield(rec, 'OUTPUT_SNMP')
    if out_if == WAN_SNMP_INDEX and in_if != WAN_SNMP_INDEX:
        if in_if == LOCAL_SNMP_INDEX:
            return FW_HOST, 'up'
        host = ipstr(rec.get('IPV4_SRC_ADDR')) or ipstr(rec.get('IPV6_SRC_ADDR'))
        return (host, 'up') if host else None
    if in_if == WAN_SNMP_INDEX and out_if != WAN_SNMP_INDEX:
        if out_if == LOCAL_SNMP_INDEX:
            return FW_HOST, 'down'
        host = ipstr(rec.get('IPV4_DST_ADDR')) or ipstr(rec.get('IPV6_DST_ADDR'))
        return (host, 'down') if host else None
    return None     # not WAN-crossing (LAN<->LAN, or WAN hairpin)


def flow_interval(rec, header, now):
    """Unix [start, end] of the record, from sysUptime-relative FIRST/LAST_SWITCHED."""
    uptime, export_ts = header.uptime, header.timestamp
    first, last = intfield(rec, 'FIRST_SWITCHED'), intfield(rec, 'LAST_SWITCHED')
    if not export_ts or not last:
        return now, now
    # sysUptime is a 32-bit ms counter; handle wrap between switch time and export
    age_last = (uptime - last) % 2**32 / 1000.0
    age_first = (uptime - first) % 2**32 / 1000.0
    end = export_ts - age_last
    start = export_ts - age_first
    if not (now - 86400 < start <= end <= now + 120):   # clock skew / garbage: fall back
        return now, now
    return start, end


class Collector:
    def __init__(self):
        self.db = open_db()
        self.buckets = {}       # (minute_ts, host) -> [down, up, pkts, flows]
        self.templates = {}     # exporter ip -> netflow template store
        self.last_seq = {}      # exporter ip -> last v9 sequence number
        self.stats = dict(records=0, wan_records=0, bytes=0, no_template=0,
                          foreign=0, decode_errors=0, lost_packets=0)

    def add(self, ts_min, host, down, up, pkts, flows):
        b = self.buckets.setdefault((ts_min, host), [0, 0, 0, 0])
        b[0] += down
        b[1] += up
        b[2] += pkts
        b[3] += flows

    def handle_record(self, rec, header, now):
        self.stats['records'] += 1
        cls = classify(rec)
        if cls is None:
            return
        host, direction = cls
        nbytes = max(intfield(rec, 'IN_BYTES'), intfield(rec, 'OUT_BYTES'))
        npkts = max(intfield(rec, 'IN_PKTS'), intfield(rec, 'OUT_PKTS'))
        if nbytes <= 0:
            return
        self.stats['wan_records'] += 1
        self.stats['bytes'] += nbytes

        start, end = flow_interval(rec, header, now)
        # spread bytes/packets over the minutes the interval covers, proportionally
        span = end - start
        m0, m1 = int(start) // 60 * 60, int(end) // 60 * 60
        if span <= 0 or m0 == m1:
            parts = [(m1, nbytes, npkts)]
        else:
            parts, left_b, left_p = [], nbytes, npkts
            m = m0
            while m <= m1:
                if m == m1:
                    b, p = left_b, left_p
                else:
                    frac = (min(m + 60, end) - max(m, start)) / span
                    b, p = int(nbytes * frac), int(npkts * frac)
                    left_b -= b
                    left_p -= p
                parts.append((m, b, p))
                m += 60
        for i, (m, b, p) in enumerate(parts):
            flows = 1 if i == len(parts) - 1 else 0
            down, up = (b, 0) if direction == 'down' else (0, b)
            self.add(m, host, down, up, p, flows)
            self.add(m, '__WAN__', down, up, p, flows)

    def handle_packet(self, data, addr):
        src = addr[0]
        if EXPORTERS and src not in EXPORTERS:
            self.stats['foreign'] += 1
            return
        tpl = self.templates.setdefault(src, {'netflow': {}, 'ipfix': {}})
        try:
            pkt = parse_packet(data, tpl)
        except V9TemplateNotRecognized:
            self.stats['no_template'] += 1   # template arrives shortly; packet skipped
            return
        except Exception as e:
            self.stats['decode_errors'] += 1
            log(f'WARN decode error from {src}: {e}')
            return
        hdr = pkt.header
        seq = getattr(hdr, 'sequence', None)
        if seq is not None:
            prev = self.last_seq.get(src)
            # FortiOS increments the v9 sequence per export packet
            if prev is not None and 0 < (seq - prev) % 2**32 < 10000:
                self.stats['lost_packets'] += (seq - prev) % 2**32 - 1
            self.last_seq[src] = seq
        now = time.time()
        for f in pkt.flows:
            self.handle_record(f.data if hasattr(f, 'data') else dict(vars(f)), hdr, now)

    def flush(self):
        if not self.buckets:
            return
        rows = [(ts, h, d, u, p, n) for (ts, h), (d, u, p, n) in self.buckets.items()]
        self.db.executemany(
            'INSERT INTO usage_min (ts, host, down_bytes, up_bytes, pkts, flows)'
            ' VALUES (?,?,?,?,?,?)'
            ' ON CONFLICT(ts, host) DO UPDATE SET'
            '   down_bytes = down_bytes + excluded.down_bytes,'
            '   up_bytes = up_bytes + excluded.up_bytes,'
            '   pkts = pkts + excluded.pkts,'
            '   flows = flows + excluded.flows', rows)
        self.db.commit()
        self.buckets.clear()

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        sock.bind((BIND_HOST, BIND_PORT))
        sock.settimeout(1.0)
        log(f'listening on {BIND_HOST}:{BIND_PORT}, wan snmp-index={WAN_SNMP_INDEX}, '
            f'exporters={",".join(sorted(EXPORTERS)) or "ANY"}')

        stop = False

        def on_signal(*_):
            nonlocal stop
            stop = True

        signal.signal(signal.SIGTERM, on_signal)
        signal.signal(signal.SIGINT, on_signal)

        last_flush = last_stats = time.time()
        while not stop:
            try:
                data, addr = sock.recvfrom(65535)
                self.handle_packet(data, addr)
            except socket.timeout:
                pass
            now = time.time()
            if now - last_flush >= FLUSH_EVERY:
                try:
                    self.flush()
                except sqlite3.Error as e:
                    log(f'WARN flush failed (will retry): {e}')
                last_flush = now
            if now - last_stats >= STATS_EVERY:
                log(' '.join(f'{k}={v}' for k, v in self.stats.items()))
                last_stats = now

        self.flush()
        self.db.close()
        log('stopped. ' + ' '.join(f'{k}={v}' for k, v in self.stats.items()))


if __name__ == '__main__':
    os.makedirs(DATA_DIR, exist_ok=True)
    Collector().run()
