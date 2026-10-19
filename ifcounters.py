"""Interface counters over SNMP (FlowTrack 1.14.0): what each interface of a device really carried, every minute.

Flows say who talked to whom, but only for the traffic a device exports (an interface without a sampler, a VAP of
FortiGate, traffic the device itself sends) and in 5-minute steps. The interface's own counters count every octet.
For each device with SNMP on (Settings → Devices) the collector reads every POLL seconds the 64-bit octet counters of
IF-MIB ifXTable (32-bit ifTable ones where a device has no ifXTable — a 32-bit counter of a 1 Gbit/s port wraps in 34 s,
so a wrap between two reads is undone), errors, discards and the state, and keeps them in `if_counters` with
src = 'snmp' — the table the sFlow counter samples already go to (src = 'sflow'). Rates are the difference of two
rows (api.counter_days); a counter that went down (a reboot, a wrap) starts again.

Status for the web: STATE_DIR/snmp_counters.json {device: {t, ok, interfaces, error}}."""
import json
import os
import threading
import time
from datetime import datetime, timezone

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
