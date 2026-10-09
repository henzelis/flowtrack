"""SNMP v2c / v3: the names and addresses of a device's interfaces (Settings → Devices).

NetFlow carries interface indexes only. With SNMP on, FlowTrack reads IF-MIB (ifName, ifDescr, ifAlias, ifOperStatus,
ifHighSpeed) and IP-MIB (ipAddrTable, ipAddressTable) when the device is saved and then every hour. The names and
addresses are used wherever the user entered none by hand (Through device, Path analysis).

The polls run the net-snmp tools (package `snmp`). Community and v3 keys go to them in a private snmp.conf
(SNMPCONFPATH), never on the command line. Settings with the secrets: STATE_DIR/snmp.json (0600); what the last poll
found: STATE_DIR/snmp_data.json.
"""
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time

from common import STATE_DIR

SETTINGS = os.path.join(STATE_DIR, 'snmp.json')
DATA = os.path.join(STATE_DIR, 'snmp_data.json')
INTERVAL = 3600          # a good poll is repeated hourly
RETRY = 600              # a failed one after 10 minutes
TIMEOUT, RETRIES = 2, 1  # per request (net-snmp -t / -r)

AUTH = ('MD5', 'SHA', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512')
PRIV = ('DES', 'AES', 'AES-192', 'AES-256')
LEVELS = ('noAuthNoPriv', 'authNoPriv', 'authPriv')
SECRETS = ('community', 'auth_pass', 'priv_pass')

SYS = {'1.3.6.1.2.1.1.5.0': 'name', '1.3.6.1.2.1.1.1.0': 'descr', '1.3.6.1.2.1.1.2.0': 'oid'}
IF_COLS = {'1.3.6.1.2.1.31.1.1.1.1': 'name', '1.3.6.1.2.1.2.2.1.2': 'descr', '1.3.6.1.2.1.31.1.1.1.18': 'alias',
           '1.3.6.1.2.1.2.2.1.8': 'oper', '1.3.6.1.2.1.31.1.1.1.15': 'speed'}
IPADDR_IF, IPADDR_MASK = '1.3.6.1.2.1.4.20.1.2', '1.3.6.1.2.1.4.20.1.3'                          # IPv4, every device
IPADDRESS_IF, IPADDRESS_TYPE, IPADDRESS_PREFIX = '1.3.6.1.2.1.4.34.1.3', '1.3.6.1.2.1.4.34.1.4', '1.3.6.1.2.1.4.34.1.5'  # v4 + v6


class SnmpError(Exception):
    """code: timeout | user | auth | priv | level | host | tool | other; detail: the tool's own words"""

    def __init__(self, code, detail=''):
        super().__init__(f'{code}: {detail}')
        self.code, self.detail = code, detail


# ------------------------------------------------------------------ settings

def _load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {}


def _save(path, data, mode):
    tmp = path + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'w') as f:
        json.dump(data, f, indent=1, ensure_ascii=False)
    os.replace(tmp, path)


_lock = threading.Lock()


def load_settings():
    return _load(SETTINGS)


def save_settings(ip, entry):
    """entry=None forgets the device (settings and what was polled)."""
    with _lock:
        s = _load(SETTINGS)
        if entry is None:
            s.pop(ip, None)
        else:
            s[ip] = entry
        _save(SETTINGS, s, 0o600)
        if entry is None or not entry.get('enabled'):
            d = _load(DATA)
            if d.pop(ip, None) is not None:
                _save(DATA, d, 0o640)


def public(entry):
    """The settings without the secrets (for the browser): has_<secret> says one is stored."""
    out = {k: v for k, v in (entry or {}).items() if k not in SECRETS}
    out.update({'has_' + k: bool((entry or {}).get(k)) for k in SECRETS})
    return out


def check_text(v, field, n=64, minimum=0):
    """A value for snmp.conf: one line, no surrounding spaces, not starting with a quote (net-snmp would unquote it)."""
    v = '' if v is None else str(v)
    if len(v) > n or any(ord(c) < 32 or ord(c) == 127 for c in v) or v != v.strip() or (v and v[0] in '"\''):
        raise ValueError(field)
    if v and len(v) < minimum:
        raise ValueError(field)
    return v


def settings_from(body, old):
    """Validated settings from the form; an empty secret keeps the stored one. Raises ValueError(field)."""
    b = body or {}
    if not b.get('enabled'):
        return {**(old or {}), 'enabled': False} if old else {'enabled': False}
    version = str(b.get('version') or '2c')
    if version not in ('2c', '3'):
        raise ValueError('version')
    host = check_text(b.get('host'), 'host', 253)
    if host and not re.fullmatch(r'[A-Za-z0-9.\-:]+', host):
        raise ValueError('host')
    try:
        port = int(b.get('port') or 161)
    except (TypeError, ValueError):
        raise ValueError('port')
    if not 0 < port < 65536:
        raise ValueError('port')
    e = {'enabled': True, 'version': version, 'host': host, 'port': port}
    keep = lambda k: check_text(b.get(k), k, 64, 8 if k != 'community' else 1) or (old or {}).get(k, '')
    if version == '2c':
        e['community'] = keep('community')
        if not e['community']:
            raise ValueError('community')
        return e
    e['user'] = check_text(b.get('user'), 'user', 32)
    if not e['user']:
        raise ValueError('user')
    e['level'] = str(b.get('level') or 'authPriv')
    if e['level'] not in LEVELS:
        raise ValueError('level')
    if e['level'] != 'noAuthNoPriv':
        e['auth_proto'] = str(b.get('auth_proto') or 'SHA')
        if e['auth_proto'] not in AUTH:
            raise ValueError('auth_proto')
        e['auth_pass'] = keep('auth_pass')
        if not e['auth_pass']:
            raise ValueError('auth_pass')
    if e['level'] == 'authPriv':
        e['priv_proto'] = str(b.get('priv_proto') or 'AES')
        if e['priv_proto'] not in PRIV:
            raise ValueError('priv_proto')
        e['priv_pass'] = keep('priv_pass')
        if not e['priv_pass']:
            raise ValueError('priv_pass')
    return e


# ------------------------------------------------------------------ the net-snmp tools

def available():
    return bool(shutil.which('snmpget') and shutil.which('snmpbulkwalk'))


def _conf(entry):
    if entry.get('version') == '3':
        lines = ['defVersion 3', f"defSecurityName {entry['user']}", f"defSecurityLevel {entry.get('level', 'authPriv')}"]
        if entry.get('level') != 'noAuthNoPriv':
            lines += [f"defAuthType {entry['auth_proto']}", f"defAuthPassphrase {entry['auth_pass']}"]
        if entry.get('level') == 'authPriv':
            lines += [f"defPrivType {entry['priv_proto']}", f"defPrivPassphrase {entry['priv_pass']}"]
    else:
        lines = ['defVersion 2c', f"defCommunity {entry['community']}"]
    return '\n'.join(lines) + '\n'


def _target(ip, entry):
    host = entry.get('host') or ip
    try:
        six = ipaddress.ip_address(host).version == 6
    except ValueError:
        six = False
    return f"udp6:[{host}]:{entry.get('port', 161)}" if six else f"udp:{host}:{entry.get('port', 161)}"


def classify(err):
    if 'Timeout' in err:
        return 'timeout'
    if 'Unknown user name' in err:
        return 'user'
    if 'Authentication failure' in err or 'wrong digest' in err.lower():
        return 'auth'
    if 'Decryption error' in err:
        return 'priv'
    if 'Unsupported security level' in err:
        return 'level'
    if 'Unknown host' in err:
        return 'host'
    return 'other'


class Session:
    """The net-snmp tools with this device's settings in a private snmp.conf (removed on close)."""

    def __init__(self, ip, entry):
        if not available():
            raise SnmpError('tool', 'snmpget / snmpbulkwalk not found (package snmp)')
        self.target = _target(ip, entry)
        self.dir = tempfile.mkdtemp(prefix='ft-snmp-')
        fd = os.open(os.path.join(self.dir, 'snmp.conf'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(_conf(entry))
        self.env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'SNMPCONFPATH': self.dir, 'SNMP_PERSISTENT_DIR': self.dir,
                    'HOME': self.dir, 'MIBS': '', 'MIBDIRS': '/dev/null'}

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def run(self, tool, opts, oids):
        cmd = [tool, '-m', '', '-M', '/dev/null', '-On', '-Oe', '-Ot', '-Ox', '-t', str(TIMEOUT), '-r', str(RETRIES), *opts, self.target, *oids]
        try:
            r = subprocess.run(cmd, env=self.env, capture_output=True, text=True, errors='replace', timeout=300)
        except subprocess.TimeoutExpired:
            raise SnmpError('timeout', f'{tool} ran over 5 minutes')
        rows = parse(r.stdout)
        err = '\n'.join(x for x in (r.stderr.strip() or r.stdout.strip()).splitlines() if not x.startswith('Created directory'))
        if r.returncode and not rows:
            raise SnmpError(classify(err), err.splitlines()[0] if err else f'{tool} exit {r.returncode}')
        return rows

    def get(self, *oids):
        return self.run('snmpget', [], oids)

    def walk(self, oid):
        return self.run('snmpbulkwalk', ['-Cr25'], [oid])


LINE = re.compile(r'^\.?([\d.]+) = (?:([A-Za-z][\w-]*): ?)?(.*)$')
NO_VALUE = ('No Such Object', 'No Such Instance', 'No more variables')


def parse(out):
    """net-snmp -On output -> [(oid, type, value)]; a long Hex-STRING continues on the next lines."""
    rows = []
    for line in out.splitlines():
        m = LINE.match(line)
        if m:
            rows.append([m[1], m[2] or '', m[3]])
        elif rows and line.strip():
            rows[-1][2] += ' ' + line.strip()
    return [(o, t, value(t, v)) for o, t, v in rows if not (not t and v.startswith(NO_VALUE))]


def value(t, v):
    v = v.strip()
    if t == 'Hex-STRING':
        try:
            return bytes.fromhex(v.replace(' ', '')).decode('utf-8', 'replace')
        except ValueError:
            return ''
    if t == 'STRING' or (not t and v.startswith('"')):
        return v[1:-1].replace('\\"', '"').replace('\\\\', '\\') if len(v) >= 2 and v[0] == v[-1] == '"' else v
    if t in ('INTEGER', 'Gauge32', 'Counter32', 'Counter64', 'Unsigned32', 'Timeticks'):
        m = re.match(r'-?\d+', v.split('(')[-1])
        return int(m.group()) if m else 0
    if t == 'OID':
        return v.lstrip('.')
    return v


# ------------------------------------------------------------------ one poll

def _suffix(oid, col):
    return oid[len(col) + 1:] if oid.startswith(col + '.') else None


def _v4(index):
    parts = (index or '').split('.')
    return '.'.join(parts[:4]) if len(parts) >= 4 and all(x.isdigit() and int(x) < 256 for x in parts[:4]) else None


def _inet(parts):
    """InetAddress index parts (type, len, bytes…) -> ipaddress object, or None (zone-scoped / unknown)."""
    if len(parts) < 2:
        return None
    t, n, b = parts[0], parts[1], parts[2:2 + parts[1]]
    if len(b) != n:
        return None
    if t == 1 and n == 4:
        return ipaddress.IPv4Address(bytes(b))
    if t == 2 and n == 16:
        return ipaddress.IPv6Address(bytes(b))
    return None


def poll(ip, entry):
    """What the device tells about itself and its interfaces. Raises SnmpError."""
    with Session(ip, entry) as s:
        sysrows = s.get(*SYS)
        info = {SYS[o]: v for o, _, v in sysrows if o in SYS}
        if not info:
            raise SnmpError('other', 'no answer for the system group')
        ifs = {}
        for col, key in IF_COLS.items():
            for o, _, v in s.walk(col):
                idx = _suffix(o, col)
                if idx and idx.isdigit():
                    ifs.setdefault(idx, {})[key] = v
        addrs = {}

        def add(idx, net):
            if net.ip.is_loopback or net.ip.is_link_local or net.ip.is_unspecified:
                return
            lst = addrs.setdefault(str(idx), [])
            if str(net) not in lst:
                lst.append(str(net))

        # the index is the address; FortiOS with `set append-index enable` adds one more number: keep 4 octets
        v4 = {}
        for o, _, v in s.walk(IPADDR_IF):
            a = _v4(_suffix(o, IPADDR_IF))
            if a:
                v4[a] = [v, 32]
        for o, _, v in s.walk(IPADDR_MASK):
            a = _v4(_suffix(o, IPADDR_MASK))
            if a in v4:
                try:
                    v4[a][1] = ipaddress.IPv4Network(f'0.0.0.0/{v}').prefixlen
                except ValueError:
                    pass
        for a, (idx, plen) in v4.items():
            try:
                add(idx, ipaddress.ip_interface(f'{a}/{plen}'))
            except ValueError:
                pass
        # ipAddressTable: IPv6 (and IPv4 on devices that dropped ipAddrTable); unicast only
        kind, where, plen = {}, {}, {}
        for o, _, v in s.walk(IPADDRESS_TYPE):
            kind[_suffix(o, IPADDRESS_TYPE)] = v
        if kind:
            for o, _, v in s.walk(IPADDRESS_IF):
                where[_suffix(o, IPADDRESS_IF)] = v
            for o, _, v in s.walk(IPADDRESS_PREFIX):
                last = str(v).rsplit('.', 1)[-1]
                plen[_suffix(o, IPADDRESS_PREFIX)] = int(last) if last.isdigit() and str(v) != '0.0' else None
        for k, idx in where.items():
            if kind.get(k) != 1:                          # 1 = unicast (2 anycast, 3 broadcast)
                continue
            a = _inet([int(x) for x in k.split('.')]) if k else None
            if a is None or (a.version == 4 and v4):
                continue
            n = plen.get(k)
            try:
                add(idx, ipaddress.ip_interface(f'{a}/{n if n is not None else a.max_prefixlen}'))
            except ValueError:
                pass
    for i in ifs.values():
        i['name'] = (i.get('name') or i.get('descr') or '').strip()
    return {'sys': info, 'ifs': ifs, 'addrs': addrs}


def summary(found):
    return {'sys': found['sys'], 'interfaces': len(found['ifs']), 'addresses': sum(len(v) for v in found['addrs'].values())}


# ------------------------------------------------------------------ stored results

def load_data():
    return _load(DATA)


def data_mtime():
    try:
        return os.path.getmtime(DATA)
    except OSError:
        return 0


def poll_and_store(ip, entry=None):
    """Poll one device with its stored settings and keep the result; a failure keeps the last good data."""
    entry = entry or load_settings().get(ip)
    if not entry or not entry.get('enabled'):
        return None
    now = int(time.time())
    try:
        found = poll(ip, entry)
        rec = {'t': now, 'ok': True, **found}
    except SnmpError as e:
        rec = {'t': now, 'ok': False, 'error': e.code, 'detail': e.detail[:300]}
    with _lock:
        d = _load(DATA)
        if not load_settings().get(ip, {}).get('enabled'):
            return rec                                   # switched off while polling
        if not rec['ok']:
            prev = d.get(ip, {})
            rec.update({k: prev[k] for k in ('sys', 'ifs', 'addrs') if k in prev})
            rec['t_ok'] = prev.get('t_ok') or (prev.get('t') if prev.get('ok') else 0)
        else:
            rec['t_ok'] = now
        d[ip] = rec
        _save(DATA, d, 0o640)
    return rec


def due(now=None):
    """Devices whose poll is due: never polled, an hour after a good poll, 10 minutes after a failed one."""
    now = now or time.time()
    d = load_data()
    out = []
    for ip, e in load_settings().items():
        if not e.get('enabled'):
            continue
        r = d.get(ip)
        if r is None or now - r.get('t', 0) >= (INTERVAL if r.get('ok') else RETRY):
            out.append(ip)
    return out


class Poller(threading.Thread):
    """Background polls in the web server; kick() polls one device soon (after a save)."""

    def __init__(self):
        super().__init__(daemon=True, name='snmp-poller')
        self.wake = threading.Event()
        self.asked = set()
        self.alock = threading.Lock()

    def kick(self, ip):
        with self.alock:
            self.asked.add(ip)
        self.wake.set()

    def run(self):
        while True:
            self.wake.wait(60)
            self.wake.clear()
            with self.alock:
                asked, self.asked = self.asked, set()
            for ip in list(asked) + [x for x in due() if x not in asked]:
                try:
                    poll_and_store(ip)
                except Exception as e:      # one bad device must not stop the others
                    print(f'snmp poll {ip}: {e}', flush=True)


# ------------------------------------------------------------------ use

def merge(exporters, data=None, settings=None):
    """Exporters with SNMP names / addresses filled in where none were entered by hand."""
    data = load_data() if data is None else data
    settings = load_settings() if settings is None else settings
    out = {}
    for ip, c in exporters.items():
        d = data.get(ip)
        if not d or not settings.get(ip, {}).get('enabled') or not (d.get('ifs') or d.get('addrs')):
            out[ip] = c
            continue
        names = {k: i['name'] for k, i in d.get('ifs', {}).items() if i.get('name')}
        names.update(c.get('if_names') or {})
        addrs = {k: list(v) for k, v in d.get('addrs', {}).items() if v}
        addrs.update(c.get('if_addrs') or {})
        out[ip] = {**c, 'if_names': names, 'if_addrs': addrs}
    return out
