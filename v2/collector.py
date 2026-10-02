#!/usr/bin/env python3
"""FlowTrack v2 collector: NetFlow v5/v9 and IPFIX -> enrichment -> ClickHouse.

- Every record is stored as received: FortiOS (and NetFlow v9/IPFIX in general) export
  DELTA counters per active-timeout interval, so traffic = sum of records.
- Inside/outside endpoint and direction come from the exporter's WAN interfaces when they
  are configured (exporters.json), otherwise from RFC 1918 / CGNAT address ranges.
- Optionally forwards every received datagram unchanged to other collectors (FT_FORWARD),
  so an existing collector keeps working on the same exporter feed.
"""
import json
import os
import signal
import socket
import sys
import time
from datetime import datetime, timezone

from netflow import parse_packet
from netflow.ipfix import IPFIXTemplateNotRecognized
from netflow.v9 import V9TemplateNotRecognized

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (CHError, Geo, apply_schema, ch, classify_l7, ipstr, is_private,  # noqa: E402
                    load_json, service_name)

BIND = os.environ.get('FT_BIND', '0.0.0.0')
PORT = int(os.environ.get('FT_PORT', '2055'))
FORWARD = [(h, int(p)) for h, p in (x.strip().rsplit(':', 1) for x in os.environ.get('FT_FORWARD', '').split(',') if x.strip())]
ALLOW = {x.strip() for x in os.environ.get('FT_EXPORTERS', '').split(',') if x.strip()}
BATCH_SECONDS = 2.0
BATCH_MAX = 20000
BUFFER_MAX = 500000        # rows kept in memory while ClickHouse is down
SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'schema.sql')


def log(msg):
    print(f'[flowtrack2] {msg}', flush=True)


def g(rec, *names, default=None):
    for n in names:
        v = rec.get(n)
        if v is not None:
            return v
    return default


def gi(rec, *names):
    try:
        return int(g(rec, *names, default=0) or 0)
    except (TypeError, ValueError):
        return 0


def utc(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def utc_ms(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]


class Exporter:
    def __init__(self, ip, cfg):
        self.ip = ip
        self.wan = set(cfg.get('wan_ifs', []))
        self.local_if = cfg.get('local_if')          # FortiOS: 0 = the firewall itself
        self.templates = {'netflow': {}, 'ipfix': {}}
        self.last_seq = None
        self.version = 0
        self._last_count = 0
        self.reset()

    def reset(self):
        self.packets = self.records = self.lost = self.no_template = self.decode_errors = 0


class Collector:
    def __init__(self):
        self.geo = Geo()
        self.cfg = load_json('exporters.json', {})
        self.exporters = {}
        self.buf = []
        self.dropped = 0
        self.last_flush = self.last_stats = time.time()

    def exporter(self, ip):
        e = self.exporters.get(ip)
        if e is None:
            e = self.exporters[ip] = Exporter(ip, self.cfg.get(ip, {}))
            log(f'new exporter {ip} (wan interfaces: {sorted(e.wan) or "not configured, using RFC1918"})')
        return e

    # ------------------------------------------------------------ records
    def flow_times(self, rec, version, hdr, now):
        """Unix (start, end) of a record."""
        if version == 10:
            end = gi(rec, 'flowEndMilliseconds') / 1000 or gi(rec, 'flowEndSeconds')
            start = gi(rec, 'flowStartMilliseconds') / 1000 or gi(rec, 'flowStartSeconds')
            if not end:
                export = getattr(hdr, 'export_uptime', 0) or now   # IPFIX header field = export time (unix s)
                end = start = export
            start = start or end
        else:
            uptime, export = getattr(hdr, 'uptime', 0), getattr(hdr, 'timestamp', 0)
            first, last = gi(rec, 'FIRST_SWITCHED'), gi(rec, 'LAST_SWITCHED')
            if not export or not last:
                return now, now
            end = export - ((uptime - last) % 2**32) / 1000.0
            start = export - ((uptime - first) % 2**32) / 1000.0
        if not (now - 86400 < start <= end <= now + 120):      # exporter clock skew: trust arrival time
            return now, now
        return start, end

    def handle_record(self, e, rec, version, hdr, now):
        src = ipstr(g(rec, 'IPV4_SRC_ADDR', 'IPV6_SRC_ADDR', 'sourceIPv4Address', 'sourceIPv6Address'))
        dst = ipstr(g(rec, 'IPV4_DST_ADDR', 'IPV6_DST_ADDR', 'destinationIPv4Address', 'destinationIPv6Address'))
        if not src or not dst:
            return
        nbytes = max(gi(rec, 'IN_BYTES', 'IN_OCTETS', 'octetDeltaCount'), gi(rec, 'OUT_BYTES', 'postOctetDeltaCount'))
        npkts = max(gi(rec, 'IN_PKTS', 'IN_PACKETS', 'packetDeltaCount'), gi(rec, 'OUT_PKTS', 'postPacketDeltaCount'))
        if nbytes <= 0:
            return
        proto = gi(rec, 'PROTOCOL', 'PROTO', 'protocolIdentifier')
        sport = gi(rec, 'L4_SRC_PORT', 'SRC_PORT', 'sourceTransportPort')
        dport = gi(rec, 'L4_DST_PORT', 'DST_PORT', 'destinationTransportPort')
        in_if = gi(rec, 'INPUT_SNMP', 'INPUT', 'ingressInterface')
        out_if = gi(rec, 'OUTPUT_SNMP', 'OUTPUT', 'egressInterface')

        # inside / outside endpoint and direction
        if e.wan and out_if in e.wan and in_if not in e.wan:
            d, ii, ei = 'up', (src, sport), (dst, dport)
        elif e.wan and in_if in e.wan and out_if not in e.wan:
            d, ii, ei = 'down', (dst, dport), (src, sport)
        else:
            ps, pd = is_private(src), is_private(dst)
            if ps and not pd:
                d, ii, ei = 'up', (src, sport), (dst, dport)
            elif pd and not ps:
                d, ii, ei = 'down', (dst, dport), (src, sport)
            elif ps and pd:
                d, ii, ei = 'internal', (src, sport), (dst, dport)
            else:
                d, ii, ei = 'transit', (src, sport), (dst, dport)

        if d == 'up':
            nat_ip = ipstr(g(rec, 'NF_F_XLATE_SRC_ADDR_IPV4', 'postNATSourceIPv4Address', 'postNATSourceIPv6Address'))
            nat_port = gi(rec, 'NF_F_XLATE_SRC_PORT', 'postNAPTSourceTransportPort')
        elif d == 'down':
            nat_ip = ipstr(g(rec, 'NF_F_XLATE_DST_ADDR_IPV4', 'postNATDestinationIPv4Address', 'postNATDestinationIPv6Address'))
            nat_port = gi(rec, 'NF_F_XLATE_DST_PORT', 'postNAPTDestinationTransportPort')
        else:
            nat_ip, nat_port = '', 0
        if nat_ip in ('0.0.0.0', '::'):
            nat_ip, nat_port = '', 0

        country, city, lat, lon, asn, as_org = self.geo.lookup(ei[0])
        l7, port_service = classify_l7(proto, ei[1])
        start, end = self.flow_times(rec, version, hdr, now)
        app_tag = gi(rec, 'APPLICATION_TAG', 'applicationId')
        self.buf.append({
            'ts': utc(end), 'ts_start': utc_ms(start), 'exporter': e.ip, 'in_if': in_if, 'out_if': out_if, 'dir': d,
            'int_ip': ii[0], 'int_port': ii[1], 'ext_ip': ei[0], 'ext_port': ei[1], 'proto': proto,
            'nat_ip': nat_ip, 'nat_port': nat_port, 'bytes': nbytes, 'packets': npkts,
            'l7': l7, 'service': service_name(port_service, asn, as_org, ei[0]),
            'country': country, 'city': city, 'lat': lat, 'lon': lon, 'asn': asn, 'as_org': as_org,
            'app_tag': app_tag if app_tag < 2**64 else 0,
        })
        e.records += 1

    def handle_packet(self, data, addr):
        for fwd in FORWARD:
            try:
                self.fwd_sock.sendto(data, fwd)
            except OSError:
                pass
        ip = addr[0]
        if ALLOW and ip not in ALLOW:
            return
        e = self.exporter(ip)
        e.packets += 1
        try:
            pkt = parse_packet(data, e.templates)
        except (V9TemplateNotRecognized, IPFIXTemplateNotRecognized):
            e.no_template += 1
            return
        except Exception as ex:
            e.decode_errors += 1
            if e.decode_errors <= 5:
                log(f'WARN decode error from {ip}: {ex}')
            return
        hdr = pkt.header
        e.version = hdr.version
        seq = getattr(hdr, 'sequence', getattr(hdr, 'sequence_number', None))
        if seq is not None and hdr.version == 9:
            # v9 counts export packets; IPFIX counts records (checked below), v5 counts flows
            if e.last_seq is not None and 0 < (seq - e.last_seq) % 2**32 < 100000:
                e.lost += (seq - e.last_seq) % 2**32 - 1
            e.last_seq = seq
        elif seq is not None and hdr.version in (5, 10):
            if e.last_seq is not None and 0 < (seq - e.last_seq) % 2**32 < 1000000:
                e.lost += (seq - e.last_seq) % 2**32 - e._last_count
            e.last_seq = seq
        now = time.time()
        flows = pkt.flows
        e._last_count = len(flows)
        for f in flows:
            if hasattr(f, 'data') and isinstance(f.data, dict):
                rec = f.data
            elif hasattr(f, 'fields'):
                rec = {k: getattr(f, k, None) for k in f.fields}
            else:
                rec = dict(vars(f))
            self.handle_record(e, rec, hdr.version, hdr, now)

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

    def write_stats(self):
        now = utc(time.time())
        rows = []
        for e in self.exporters.values():
            rows.append({'ts': now, 'exporter': e.ip, 'version': e.version, 'packets': e.packets, 'records': e.records,
                         'lost': e.lost, 'no_template': e.no_template, 'decode_errors': e.decode_errors,
                         'templates': len(e.templates['netflow']) + len(e.templates['ipfix'])})
        if not rows:
            return
        try:
            ch('INSERT INTO exporter_stats FORMAT JSONEachRow', data='\n'.join(json.dumps(r) for r in rows).encode())
            for e in self.exporters.values():
                e.reset()
        except (CHError, OSError) as ex:
            log(f'WARN stats insert failed: {str(ex)[:200]}')

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
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        sock.bind((BIND, PORT))
        sock.settimeout(0.5)
        self.fwd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        log(f'listening on {BIND}:{PORT}; forwarding to {FORWARD or "nobody"}; exporters allowed: {sorted(ALLOW) or "any"}')
        stop = False

        def on_signal(*_):
            nonlocal stop
            stop = True
        signal.signal(signal.SIGTERM, on_signal)
        signal.signal(signal.SIGINT, on_signal)

        while not stop:
            try:
                data, addr = sock.recvfrom(65535)
                self.handle_packet(data, addr)
            except socket.timeout:
                pass
            now = time.time()
            if now - self.last_flush >= BATCH_SECONDS or len(self.buf) >= BATCH_MAX:
                self.flush()
                self.last_flush = now
            if now - self.last_stats >= 60:
                self.write_stats()
                self.last_stats = now
        self.flush()
        self.write_stats()
        log('stopped')


if __name__ == '__main__':
    Collector().run()
