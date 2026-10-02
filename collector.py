#!/usr/bin/env python3
"""flowtrack-collector: NetFlow v9 collector for FortiGate -> SQLite.

Design (verified against live FortiOS 7.4 exports):
- FortiGate reports ONE record per direction of a session (src/dst swapped pairs).
- IN_BYTES == OUT_BYTES in each record = total bytes of that direction.
- Re-reports are CUMULATIVE since session start (active-flow-timeout=60s),
  so we track running max per 5-tuple and only add the delta.
- A byte-count DROP on a tuple means 5-tuple reuse by a NEW session ->
  finalize old, start fresh with this record's cumulative value.
- INPUT_SNMP/OUTPUT_SNMP carry interface snmp-index (wan=1) => WAN-touching filter.

Tables:
  usage_min(ts_minute, host, down_bytes, up_bytes, pkts)  -- tiny, powers all charts
  sessions(id, ts_start, ts_end, src, dst, sport, dport, proto, bytes) -- finalized flows
"""
import socket
import time
import json
import os
import sys
import sqlite3
import ipaddress
from netflow import parse_packet
from netflow.v9 import V9TemplateNotRecognized

# Configuration via environment variables (see README / deploy/flowtrack.env.example).
BIND_HOST = os.environ.get('FLOWTRACK_BIND', '0.0.0.0')
BIND_PORT = int(os.environ.get('FLOWTRACK_PORT', '2055'))
DATA_DIR = os.environ.get('FLOWTRACK_DATA_DIR', '/opt/flowtrack')
DB_PATH = os.path.join(DATA_DIR, 'data.db')
STATE_PATH = os.path.join(DATA_DIR, 'state.json')
# snmp-index of the WAN interface on FortiGate (check: show system interface wan)
WAN_SNMP_INDEX = int(os.environ.get('FLOWTRACK_WAN_SNMP_INDEX', '1'))
# FW's own public IP(s), comma-separated — appears as src/dst in some records,
# labeled as host 'firewall' instead of being dropped.
OUR_WAN_IPS = {ip.strip() for ip in os.environ.get('FLOWTRACK_FW_PUBLIC_IPS', '').split(',') if ip.strip()}
FINALIZE_GAP = 45           # seconds without a re-report => session closed

SCHEMA = """
CREATE TABLE IF NOT EXISTS usage_min (
    ts INTEGER NOT NULL,
    host TEXT NOT NULL,
    down_bytes INTEGER NOT NULL DEFAULT 0,
    up_bytes INTEGER NOT NULL DEFAULT 0,
    pkts INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ts, host)
);
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_start INTEGER NOT NULL,
    ts_end INTEGER NOT NULL,
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    sport INTEGER, dport INTEGER, proto INTEGER,
    bytes INTEGER NOT NULL,
    direction TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_ts ON sessions(ts_start);
"""


def ipstr(v):
    """Normalize an IP field (int or str) to dotted string."""
    if v is None:
        return None
    try:
        return str(ipaddress.ip_address(int(v)))
    except (ValueError, TypeError):
        s = str(v).strip()
        return s or None


def norm_ip(v):
    """Return ipaddress object or None."""
    if v is None:
        return None
    try:
        if isinstance(v, int) or str(v).isdigit():
            return ipaddress.ip_address(int(v))
        return ipaddress.ip_address(str(v))
    except (ValueError, TypeError):
        return None


class Collector:
    def __init__(self):
        self.db = sqlite3.connect(DB_PATH)
        self.db.executescript(SCHEMA)
        self.db.commit()
        # open sessions: key -> dict(bytes=running_max, first_ts, last_ts, meta...)
        self.open = {}
        if os.path.exists(STATE_PATH):
            try:
                with open(STATE_PATH) as f:
                    self.open = json.load(f)
                print(f'[flowtrack] restored {len(self.open)} open sessions from state', flush=True)
            except Exception as e:
                print(f'[flowtrack] WARN state restore failed: {e}', flush=True)
        # in-memory minute buckets: (minute_ts, host) -> [down, up, pkts]
        self.buckets = {}
        self.last_flush = time.time()
        self.total_records = 0

    def minute_bucket(self):
        return int(time.time()) // 60 * 60

    def add_bytes(self, ts_min, host, down, up, pkts=0):
        key = (ts_min, host)
        b = self.buckets.setdefault(key, [0, 0, 0])
        b[0] += down
        b[1] += up
        b[2] += pkts

    def classify(self, src, dst, in_snmp, out_snmp):
        """Return (host_label, direction) or None if not WAN-touching.
        host: private endpoint IP, 'firewall', or None for pure public->public."""
        touches_wan = (in_snmp == WAN_SNMP_INDEX) or (out_snmp == WAN_SNMP_INDEX)
        if not touches_wan:
            return None
        src_o, dst_o = norm_ip(src), norm_ip(dst)
        host = None
        for o in (src_o, dst_o):
            if o is not None and (o.is_private or o.is_loopback):
                host = str(o)
                break
        if src_o is not None and str(src_o) in OUR_WAN_IPS:
            host = 'firewall'
        if dst_o is not None and str(dst_o) in OUR_WAN_IPS:
            host = host or 'firewall'
        # direction from WAN perspective
        if src_o is not None and dst_o is not None:
            src_pub = src_o.is_global and str(src_o) not in OUR_WAN_IPS
            dst_pub = dst_o.is_global and str(dst_o) not in OUR_WAN_IPS
            if src_pub and not dst_pub:
                direction = 'down'   # internet -> LAN host
            elif dst_pub and not src_pub:
                direction = 'up'     # LAN host -> internet
            else:
                direction = 'wan'    # public<->public / fw-own; still WAN bytes
        else:
            direction = 'wan'
        if host is None:
            host = 'firewall'
        return host, direction

    def handle_record(self, rec):
        src = ipstr(rec.get('IPV4_SRC_ADDR')) or ipstr(rec.get('IPV6_SRC_ADDR'))
        dst = ipstr(rec.get('IPV4_DST_ADDR')) or ipstr(rec.get('IPV6_DST_ADDR'))
        if not src or not dst:
            return
        try:
            inb = int(rec.get('IN_BYTES', 0) or 0)
            outb = int(rec.get('OUT_BYTES', 0) or 0)
        except (TypeError, ValueError):
            return
        nbytes = max(inb, outb)
        npkts = max(int(rec.get('IN_PKTS', 0) or 0), int(rec.get('OUT_PKTS', 0) or 0))

        cls = self.classify(src, dst, rec.get('INPUT_SNMP'), rec.get('OUTPUT_SNMP'))
        if cls is None:
            return
        host, direction = cls

        key = f'{src}|{dst}|{rec.get("L4_SRC_PORT", 0)}|{rec.get("PROTOCOL", 0)}'
        now = time.time()
        st = self.open.get(key)
        if st is None:
            self.open[key] = {'bytes': nbytes, 'first_ts': now, 'last_ts': now,
                              'src': src, 'dst': dst, 'host': host, 'dir': direction}
            delta = nbytes  # full cumulative value of the (new) session
        else:
            if nbytes >= st['bytes']:
                delta = nbytes - st['bytes']      # growth since last report
                st['last_ts'] = now
                st['bytes'] = nbytes
            else:
                # counter dropped => 5-tuple reused by a NEW session.
                # finalize old instance, start new one with its own cumulative value.
                self.finalize(key)
                self.open[key] = {'bytes': nbytes, 'first_ts': now, 'last_ts': now,
                                  'src': src, 'dst': dst, 'host': host, 'dir': direction}
                delta = nbytes

        if delta > 0:
            ts_min = int(now) // 60 * 60
            down = delta if direction == 'down' else 0
            up = delta if direction in ('up', 'wan') else 0
            self.add_bytes(ts_min, host, down, up, npkts if delta else 0)
            # synthetic WAN total row (every byte touching the wan interface)
            self.add_bytes(ts_min, '__WAN__', down + up, 0, 0)

    def finalize(self, key):
        st = self.open.pop(key, None)
        if not st:
            return
        try:
            self.db.execute(
                'INSERT INTO sessions (ts_start, ts_end, src, dst, sport, dport, proto, bytes, direction)'
                ' VALUES (?,?,?,?,?,?,?,?,?)',
                (int(st['first_ts']), int(st['last_ts']), st['src'], st['dst'],
                 0, 0, 0, int(st['bytes']), st.get('dir', '?')))
        except sqlite3.Error as e:
            print(f'[flowtrack] WARN finalize insert failed: {e}', flush=True)

    def flush(self):
        # close stale sessions (no re-report for FINALIZE_GAP seconds)
        now = time.time()
        stale = [k for k, st in self.open.items() if now - st['last_ts'] > FINALIZE_GAP]
        for k in stale:
            self.finalize(k)
        # persist minute buckets
        if self.buckets:
            rows = [(ts, h, d, u, p) for (ts, h), (d, u, p) in self.buckets.items()]
            self.db.executemany(
                'INSERT INTO usage_min (ts, host, down_bytes, up_bytes, pkts)'
                ' VALUES (?,?,?,?,?)'
                ' ON CONFLICT(ts, host) DO UPDATE SET'
                '   down_bytes = down_bytes + excluded.down_bytes,'
                '   up_bytes = up_bytes + excluded.up_bytes,'
                '   pkts = pkts + excluded.pkts', rows)
            self.buckets.clear()
        self.db.commit()
        # persist open-session state (survives restarts: no double/lost counts)
        tmp = STATE_PATH + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(self.open, f)
        os.replace(tmp, STATE_PATH)

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((BIND_HOST, BIND_PORT))
        print(f'[flowtrack] listening on {BIND_HOST}:{BIND_PORT}', flush=True)

        templates = {'netflow': {}, 'ipfix': {}}   # dict! (library bug seeds a list otherwise)
        stop = False

        def sigterm(*_):
            nonlocal stop
            stop = True

        import signal
        signal.signal(signal.SIGTERM, sigterm)
        signal.signal(signal.SIGINT, sigterm)

        while not stop:
            sock.settimeout(1.0)
            try:
                data, addr = sock.recvfrom(65535)
                pkt = parse_packet(data, templates)
                for f in pkt.flows:
                    self.handle_record(f.data if hasattr(f, 'data') else dict(vars(f)))
                    self.total_records += 1
            except socket.timeout:
                pass
            except V9TemplateNotRecognized:
                pass   # template arrives shortly; record skipped (documented loss)
            except Exception as e:
                print(f'[flowtrack] WARN decode error: {e}', flush=True)

            if time.time() - self.last_flush > 60:
                try:
                    self.flush()
                except Exception as e:
                    print(f'[flowtrack] WARN flush failed: {e}', flush=True)
                self.last_flush = time.time()
                if self.total_records and self.total_records % 500 < 100:
                    print(f'[flowtrack] records={self.total_records} open_sessions={len(self.open)}', flush=True)

        # graceful shutdown: finalize everything, flush all
        for k in list(self.open.keys()):
            self.finalize(k)
        self.flush()
        self.db.close()
        print(f'[flowtrack] stopped. total_records={self.total_records}', flush=True)


if __name__ == '__main__':
    os.makedirs(DATA_DIR, exist_ok=True)
    Collector().run()
