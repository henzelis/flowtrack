"""Interface counters over SNMP (FlowTrack 1.14.0): what each interface of a device really carried, every minute.

Flows say who talked to whom, but only for the traffic a device exports (an interface without a sampler, a VAP of
FortiGate, traffic the device itself sends) and in 5-minute steps. The interface's own counters count every octet.
For each device with SNMP on (Settings → Devices) the collector reads every POLL seconds the 64-bit octet counters of
IF-MIB ifXTable (32-bit ifTable ones where a device has no ifXTable — a 32-bit counter of a 1 Gbit/s port wraps in 34 s,
so a wrap between two reads is undone), errors, discards and the state, and keeps them in `if_counters` with
src = 'snmp' — the table the sFlow counter samples already go to (src = 'sflow'). Rates are the difference of two
rows (rates_sql); a counter that went down (a reboot, a wrap) starts again. (1.16.2) Rates thread: they are made once,
in 5-minute buckets, into `if_rate5` — Capacity reads those.

Status for the web: STATE_DIR/snmp_counters.json {device: {t, ok, interfaces, error}}."""
import json
import os
import threading
import time
from datetime import datetime, timezone

import rollups
import snmp
from common import STATE_DIR, CHError, ch

POLL = 60
STATUS = os.path.join(STATE_DIR, 'snmp_counters.json')
HC = {'in_octets': '1.3.6.1.2.1.31.1.1.1.6', 'out_octets': '1.3.6.1.2.1.31.1.1.1.10',
      'in_ucast': '1.3.6.1.2.1.31.1.1.1.7', 'out_ucast': '1.3.6.1.2.1.31.1.1.1.11'}
LOW = {'in_octets': '1.3.6.1.2.1.2.2.1.10', 'out_octets': '1.3.6.1.2.1.2.2.1.16',
       'in_ucast': '1.3.6.1.2.1.2.2.1.11', 'out_ucast': '1.3.6.1.2.1.2.2.1.17'}
COMMON = {'in_discards': '1.3.6.1.2.1.2.2.1.13', 'in_errors': '1.3.6.1.2.1.2.2.1.14', 'out_discards': '1.3.6.1.2.1.2.2.1.19',
          'out_errors': '1.3.6.1.2.1.2.2.1.20', 'if_type': '1.3.6.1.2.1.2.2.1.3', 'admin': '1.3.6.1.2.1.2.2.1.7',
          'oper': '1.3.6.1.2.1.2.2.1.8', 'speed_m': '1.3.6.1.2.1.31.1.1.1.15'}
SKIP_TYPES = {24}             # softwareLoopback: nothing to plan for


def read(ip, entry):
    """{if_index: {column: value}} of one device, one pass. Raises snmp.SnmpError (the first failing walk ends it:
    a device that does not answer costs one timeout, not ten)."""
    out = {}
    with snmp.Session(ip, entry) as s:
        def walk(cols):
            for key, col in cols.items():
                for o, _, v in s.walk(col):
                    idx = snmp._suffix(o, col)
                    if idx and idx.isdigit():
                        out.setdefault(int(idx), {})[key] = v
        walk({'in_octets': HC['in_octets']})
        wide = bool(out)
        walk({k: v for k, v in HC.items() if k != 'in_octets'} if wide else LOW)
        walk(COMMON)
    for v in out.values():
        v['wide'] = wide
    return out


def rows(ip, found, t):
    """if_counters rows (src 'snmp') for what read() found at unix time t."""
    ts = datetime.fromtimestamp(t, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    out = []
    for idx, v in sorted(found.items()):
        if v.get('if_type') in SKIP_TYPES or 'in_octets' not in v or 'out_octets' not in v:
            continue
        out.append({'ts': ts, 'exporter': ip, 'if_index': idx, 'if_type': int(v.get('if_type') or 0),
                    'speed': int(v.get('speed_m') or 0) * 1_000_000, 'direction': 0,
                    'status': (1 if v.get('admin') == 1 else 0) | (2 if v.get('oper') == 1 else 0),
                    'in_octets': int(v['in_octets']), 'out_octets': int(v['out_octets']),
                    'in_ucast': int(v.get('in_ucast') or 0), 'out_ucast': int(v.get('out_ucast') or 0),
                    'in_discards': int(v.get('in_discards') or 0), 'in_errors': int(v.get('in_errors') or 0),
                    'out_discards': int(v.get('out_discards') or 0), 'out_errors': int(v.get('out_errors') or 0),
                    'wide': 1 if v.get('wide') else 0, 'src': 'snmp'})
    return out


def _status(ip, rec):
    try:
        with open(STATUS) as f:
            d = json.load(f)
    except (OSError, ValueError):
        d = {}
    d = {k: v for k, v in d.items() if k in snmp.load_settings()}       # devices removed or switched off
    if rec is not None:
        d[ip] = rec
    tmp = STATUS + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(d, f)
    os.chmod(tmp, 0o640)
    os.replace(tmp, STATUS)


def load_status():
    try:
        with open(STATUS) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


class Poller:
    """The collector's thread: every POLL seconds each device with SNMP on, one after another (a slow device delays
    the next by its timeout, never stops it)."""

    def __init__(self, log=print):
        self.log, self.said = log, {}

    def once(self, now=None):
        now = now or time.time()
        for ip, entry in snmp.load_settings().items():
            if not entry.get('enabled'):
                continue
            t = int(time.time())
            try:
                found = read(ip, entry)
                r = rows(ip, found, t)
                if r:
                    ch('INSERT INTO if_counters FORMAT JSONEachRow', data='\n'.join(json.dumps(x, separators=(',', ':')) for x in r).encode(), timeout=20)
                _status(ip, {'t': t, 'ok': True, 'interfaces': len(r), 'wide': bool(r and r[0]['wide'])})
                if self.said.pop(ip, None):
                    self.log(f'snmp counters {ip}: answering again ({len(r)} interfaces)')
            except snmp.SnmpError as e:
                _status(ip, {'t': t, 'ok': False, 'error': e.code, 'detail': e.detail[:200]})
                if ip not in self.said or now - self.said[ip] > 3600:      # once an hour per device, not every minute
                    self.log(f'WARN snmp counters {ip}: {e.code} {e.detail[:120]}')
                    self.said[ip] = now
            except (CHError, OSError) as e:
                self.log(f'WARN snmp counters {ip}: not stored: {str(e)[:150]}')

    def run(self):
        if not snmp.available():
            return
        while True:
            start = time.time()
            try:
                self.once(start)
            except Exception as e:          # never let the thread die
                self.log(f'WARN snmp counters: {e}')
            time.sleep(max(5, POLL - (time.time() - start)))


def start(log=print):
    threading.Thread(target=Poller(log).run, name='snmp-counters', daemon=True).start()


# ---------------------------------------------------------------- (1.16.2) rates in 5-minute buckets
BUCKET = 300
RATE_LAG = 300          # reads this recent are left for the next pass: a write may still be on its way
MAX_GAP = 900           # two reads further apart make no rate (rates_sql): a bucket's rates need this much before it


def rates_sql(where='', c0='c0', t1='t1'):
    """Rates from the interface counters (SNMP every minute, sFlow counter samples): one row per read and direction
    (d 0 = into the device through the interface, 1 = out of it) with the octets since the previous read of the same
    source and the seconds between, for the reads from {c0} to {t1}. A 32-bit counter that wrapped is undone; a counter
    that went down (reboot), a gap over 15 minutes or more than the port can carry is left out. (api._counter_rates
    before 1.16.2.)"""
    return f"""SELECT exporter, i, src, x.1 AS d, ts, if(x.2 < 0 AND wide = 0, x.2 + 4294967296, x.2) AS delta, dt FROM (
            SELECT exporter, if_index AS i, src, ts, wide, speed, dateDiff('second', lagInFrame(ts) OVER w, ts) AS dt,
                toInt64(in_octets) - toInt64(lagInFrame(in_octets) OVER w) AS di, toInt64(out_octets) - toInt64(lagInFrame(out_octets) OVER w) AS dout
            FROM if_counters WHERE ts >= toDateTime({{{c0}:UInt32}}) AND ts < toDateTime({{{t1}:UInt32}}){where}
            WINDOW w AS (PARTITION BY exporter, if_index, src ORDER BY ts ROWS BETWEEN 1 PRECEDING AND CURRENT ROW))
        ARRAY JOIN [(0, di), (1, dout)] AS x
        WHERE dt BETWEEN 10 AND {MAX_GAP} AND delta >= 0 AND (speed = 0 OR delta * 8 <= speed * dt * 1.1)"""


def five_sql(t0='t0', t1='t1', c0='c0'):
    """The 5-minute buckets of the reads from {t0} to {t1}, made from the counters ({c0} = t0 - MAX_GAP: the read before
    the first of them)"""
    return f"""SELECT toStartOfInterval(ts, INTERVAL {BUCKET} SECOND) AS t5, exporter, i, src, d, sum(delta) AS b, sum(dt) AS sdt,
            max(delta * 8 / dt) AS pk FROM ({rates_sql(c0=c0, t1=t1)}) WHERE ts >= toDateTime({{{t0}:UInt32}}) GROUP BY t5, exporter, i, src, d"""


def make_rates(t0, t1):
    """if_rate5 for the buckets from t0 to t1 (both bucket boundaries)"""
    ch(f'INSERT INTO if_rate5 (t5, exporter, i, src, d, b, sdt, pk) SELECT t5, exporter, i, src, d, b, sdt, pk FROM ({five_sql()})',
       {'t0': t0, 't1': t1, 'c0': t0 - MAX_GAP}, timeout=600, settings={'max_threads': 2})


def rates_state():
    """(made up to, complete from): the buckets before `made up to` are in if_rate5 from `complete from` on (0: all
    the counters there are); None before the thread first ran"""
    st = rollups._get_state()
    if 'ifrate:done' not in st:
        return None
    return st['ifrate:done'], st.get('ifrate:ready_from', 0)


class Rates:
    """The collector's thread: every minute the new whole buckets; after an upgrade first the history of the counters,
    a day at a time, newest first (Capacity reads if_rate5 once the period it shows is in)."""
    def __init__(self, log=print):
        self.log = log

    def once(self, now=None):
        now = int(now or time.time())
        st = rollups._get_state()
        if 'ifrate:done' not in st:
            cut = (now - RATE_LAG) // BUCKET * BUCKET
            rollups._set('ifrate:ready_from', cut)
            rollups._set('ifrate:done', cut)
            st = {'ifrate:done': cut, 'ifrate:ready_from': cut}
        done, rf = st['ifrate:done'], st.get('ifrate:ready_from', 0)
        upto = (now - RATE_LAG) // BUCKET * BUCKET
        if upto > done:
            make_rates(done, upto)
            rollups._set('ifrate:done', upto)
        if rf:                          # the history: one day per pass, newest first
            old = ch("SELECT toUnixTimestamp(min(ts)) AS t, count() AS n FROM if_counters WHERE ts < toDateTime({rf:UInt32})", {'rf': rf}, fmt='JSON')
            if not old or not int(old[0]['n']):
                rollups._set('ifrate:ready_from', 0)
                self.log('interface counters: rates of the whole history in 5-minute buckets')
                return False
            lo = max(int(old[0]['t']) // BUCKET * BUCKET, rf - 86400)
            make_rates(lo, rf)
            rollups._set('ifrate:ready_from', lo)
            return True                 # more history: the next pass at once
        return False

    def run(self):
        while True:
            try:
                more = self.once()
            except (CHError, OSError, ValueError, KeyError) as ex:
                self.log(f'WARN interface counter rates: {str(ex)[:300]}')
                more = False
            time.sleep(1 if more else 60)


def start_rates(log=print):
    threading.Thread(target=Rates(log).run, name='counter-rates', daemon=True).start()
