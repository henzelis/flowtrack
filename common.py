"""Shared FlowTrack helpers: config, ClickHouse HTTP client, enrichment."""
import base64
import ipaddress
import json
import os
import socket
import subprocess
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from functools import lru_cache

import ftcore

CONFIG_DIR = os.environ.get('FT_CONFIG_DIR', '/etc/flowtrack')
GEOIP_DIR = os.environ.get('FT_GEOIP_DIR', '/opt/flowtrack/geoip')
CH_URL = os.environ.get('FT_CH_URL', 'http://127.0.0.1:8123')
CH_USER = os.environ.get('FT_CH_USER', 'default')
CH_PASSWORD = os.environ.get('FT_CH_PASSWORD', '')
CH_DB = os.environ.get('FT_CH_DB', 'flowtrack')


STATE_DIR = os.environ.get('FT_STATE_DIR', '/var/lib/flowtrack')
try:                                  # the release number, one file at the top of the repository
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'VERSION')) as _f:
        VERSION = _f.read().strip()
except OSError:
    VERSION = 'dev'
UI_EXPORTERS = os.path.join(STATE_DIR, 'exporters.json')


def load_exporters():
    """/etc exporters.json (deployment) overlaid with devices managed from the UI (state dir).
    A UI entry set to null hides a deployment entry."""
    merged = dict(load_json('exporters.json', {}))
    try:
        with open(UI_EXPORTERS) as f:
            for ip, cfg in json.load(f).items():
                if cfg is None:
                    merged.pop(ip, None)
                else:
                    merged[ip] = {**merged.get(ip, {}), **cfg}
    except (FileNotFoundError, ValueError):
        pass
    return merged


def exporters_mtime():
    mt = []
    for p in (os.path.join(CONFIG_DIR, 'exporters.json'), UI_EXPORTERS):
        try:
            mt.append(os.path.getmtime(p))
        except OSError:
            mt.append(0)
    return tuple(mt)


def load_ui_exporter(ip):
    """The UI-managed entry for one exporter (empty dict if none)."""
    try:
        with open(UI_EXPORTERS) as f:
            return json.load(f).get(ip) or {}
    except (FileNotFoundError, ValueError):
        return {}


def save_ui_exporter(ip, cfg):
    """cfg=None deletes the device. Atomic write; readable by the service group only."""
    try:
        with open(UI_EXPORTERS) as f:
            data = json.load(f)
    except (FileNotFoundError, ValueError):
        data = {}
    data[ip] = cfg
    tmp = UI_EXPORTERS + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, 'w') as f:
        json.dump(data, f, indent=1, ensure_ascii=False)
    os.replace(tmp, UI_EXPORTERS)


def load_json(name, default):
    try:
        with open(os.path.join(CONFIG_DIR, name)) as f:
            return json.load(f)
    except FileNotFoundError:
        return default


# ---------------------------------------------------------------- language
# Texts shown to people come in English and Ukrainian: tr('English', 'Українська'). The web server sets the
# language per request from the ft_lang cookie; everything else (logs, stored data) is English.
_lang = threading.local()


def set_lang(lang):
    _lang.value = 'uk' if lang == 'uk' else 'en'


def tr(en, uk):
    return uk if getattr(_lang, 'value', 'en') == 'uk' else en


# ---------------------------------------------------------------- listening sockets
# FT_BIND (NetFlow/IPFIX) and FT_WEB_BIND (web UI) take a comma-separated list of interface names and/or
# IP addresses; empty, 'all', '0.0.0.0' or '::' = every interface. An interface name means its current
# addresses; the services restart themselves when those change (DHCP). With specific interfaces, localhost
# is served too, so health checks, SSH tunnels and a local reverse proxy keep working.
ALL_IFACES = ('', '*', 'any', 'all', '0.0.0.0', '::')
LOOPBACK = ('127.0.0.1', '::1')


def bind_targets(spec):
    """'ens19, 203.0.113.5' -> [('', 'ens19'), ('203.0.113.5', None)]; [('', None)] = all interfaces."""
    items = [x.strip() for x in str(spec or '').split(',') if x.strip()]
    if not items or any(x.lower() in ALL_IFACES for x in items):
        return [('', None)]
    names = {n for _, n in socket.if_nameindex()}
    out = []
    for it in items:
        try:
            out.append((str(ipaddress.ip_address(it)), None))
        except ValueError:
            if it not in names:
                raise ValueError(f'unknown interface or address: {it!r} (interfaces: {", ".join(sorted(names))})')
            out.append(('', it))
    return out


def iface_addrs(dev):
    """Current global addresses of an interface (IPv4 first)."""
    try:
        r = subprocess.run(['ip', '-j', 'addr', 'show', 'dev', dev], capture_output=True, text=True, timeout=5)
        data = json.loads(r.stdout or '[]')
    except (OSError, ValueError, subprocess.SubprocessError):
        return []
    addrs = [(a.get('family'), a.get('local')) for d in data for a in d.get('addr_info', []) if a.get('scope') == 'global' and a.get('local')]
    return [ip for fam, ip in sorted(addrs, key=lambda x: x[0] != 'inet')]


def bind_plan(spec):
    """[(address, interface or None)] to bind right now; [('::', None)] = all interfaces (dual-stack)."""
    plan = []
    for host, dev in bind_targets(spec):
        if not host and not dev:
            return [('::', None)]
        if dev:
            addrs = iface_addrs(dev)
            if not addrs:
                raise OSError(f'interface {dev} has no IP address yet')
            plan += [(a, dev) for a in addrs]
        else:
            plan.append((host, None))
    plan += [(a, None) for a in LOOPBACK if a not in {h for h, _ in plan}]
    return plan


def _bound(host, port, socktype, configure):
    """One bound socket; '::' listens on IPv4 too (dual-stack), falling back to IPv4 when IPv6 is off."""
    fam = socket.AF_INET6 if ':' in host else socket.AF_INET
    s = None
    try:
        s = socket.socket(fam, socktype)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        configure(s)
        if fam == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0 if host == '::' else 1)
        s.bind((host, port))
        return s
    except OSError:
        if s:
            s.close()
        if host != '::':
            raise
        return _bound('0.0.0.0', port, socktype, configure)


def open_listeners(spec, port, socktype, configure=lambda s: None, log=print):
    """Bound (not yet listening) sockets for FT_BIND / FT_WEB_BIND, as [(socket, interface or None)].
    ::1 is skipped quietly when IPv6 is disabled."""
    out = []
    for host, dev in bind_plan(spec):
        try:
            out.append((_bound(host, port, socktype, configure), dev))
        except OSError:
            if host == '::1':
                continue
            for s, _ in out:
                s.close()
            raise
    return out


def listen_signature(spec):
    """Addresses the spec resolves to now; compare with the value at start to notice a changed DHCP address."""
    try:
        return sorted(h for h, _ in bind_plan(spec))
    except (OSError, ValueError):
        return None


def listen_label(item):
    """'ens19 (203.0.113.5)', '203.0.113.5' or 'all interfaces' for one describe_listeners() entry."""
    if item['iface']:
        return item['iface'] + (f" ({', '.join(item['addrs'])})" if item['addrs'] else '')
    return ', '.join(item['addrs']) or 'all interfaces (IPv4 + IPv6)'


def describe_listeners(listeners):
    """[{'iface': 'ens19' | None, 'addrs': [...]}] for the UI: where clients can send to (loopback left out)."""
    out = []
    only_loopback = all(s.getsockname()[0] in LOOPBACK for s, _ in listeners)
    for s, dev in listeners:
        host = s.getsockname()[0]
        if host in LOOPBACK and not only_loopback:
            continue
        addrs = [] if host in ('::', '0.0.0.0') else [host]
        prev = next((x for x in out if x['iface'] == dev), None) if dev else None
        if prev:
            prev['addrs'] += [a for a in addrs if a not in prev['addrs']]
        else:
            out.append({'iface': dev, 'addrs': addrs})
    return out


# ---------------------------------------------------------------- ClickHouse

class CHError(Exception):
    pass


def ch(query, params=None, data=None, fmt=None, timeout=30):
    """Run a query over the ClickHouse HTTP interface.
    params: {name: value} bound to {name:Type} placeholders (server-side, no string interpolation).
    data: bytes to POST after the query (for INSERT ... FORMAT JSONEachRow).
    Returns parsed JSON rows for fmt='JSON', else raw text."""
    # WHERE must see real columns even when a SELECT alias has the same name (any(service) AS service)
    qs = {'database': CH_DB, 'prefer_column_name_to_alias': '1'}
    for k, v in (params or {}).items():
        if isinstance(v, (list, tuple)):     # Array(String) literal
            v = '[' + ','.join("'" + str(x).replace('\\', '\\\\').replace("'", "\\'") + "'" for x in v) + ']'
        qs['param_' + k] = v if isinstance(v, str) else str(v)
    if fmt:
        query = f'{query} FORMAT {fmt}'
    if data is None:
        url, body = f'{CH_URL}/?{urllib.parse.urlencode(qs)}', query.encode()
    else:
        qs['query'] = query
        url, body = f'{CH_URL}/?{urllib.parse.urlencode(qs)}', data
    req = urllib.request.Request(url, data=body, method='POST')
    req.add_header('Authorization', 'Basic ' + base64.b64encode(f'{CH_USER}:{CH_PASSWORD}'.encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            out = r.read().decode()
    except urllib.error.HTTPError as e:
        raise CHError(e.read().decode()[:500]) from None
    if fmt == 'JSON':
        return json.loads(out)['data']
    return out


def apply_schema(path):
    with open(path) as f:
        text = '\n'.join(line.split('--', 1)[0] for line in f.read().splitlines())   # drop comments first
    for stmt in text.split(';'):
        if stmt.strip():
            ch(stmt)


# ---------------------------------------------------------------- editions
# FlowTrack Community is this repository. A license (licensing.py) bound to this installation raises the limits
# below; FlowTrack Pro features come from a module (`flowtrack_pro` in FT_PRO_DIR) that adds API routes and UI
# scripts while the license is active. The core knows nothing about what Pro does: it only asks `edition()`.
# for display only: the limits themselves are enforced by the compiled core
COMMUNITY = {'name': 'community', 'rps': ftcore.COMMUNITY_RPS, 'retention_days': ftcore.COMMUNITY_RETENTION_DAYS}
LICENSE_FILE = os.path.join(STATE_DIR, 'license.key')
PRO_DIR = os.environ.get('FT_PRO_DIR', '/opt/flowtrack/pro')
_edition = {'key': None, 'value': None}


def pro_module():
    """The installed Pro module, or None."""
    if PRO_DIR not in sys.path and os.path.isdir(PRO_DIR):
        sys.path.insert(0, PRO_DIR)
    try:
        import flowtrack_pro
        return flowtrack_pro
    except ImportError:
        return None


def read_license():
    try:
        with open(LICENSE_FILE) as f:
            return f.read().strip()
    except OSError:
        return ''


def edition():
    """Limits and extensions in effect: {'name', 'rps' (None = unlimited), 'retention_days', 'features',
    'license': {...} or None, 'status': 'community' | 'active' | 'expired' | 'invalid' | 'other_instance' |
    'returned' | 'clock', 'message', 'module'}. The compiled core decides (and its RateLimit follows the result).
    Licenses are time-limited: after the end date the Community limits apply again (stored data is kept). Cached
    until the license file changes, re-checked every minute."""
    import time as _t
    try:
        mt = os.stat(LICENSE_FILE).st_mtime
    except OSError:
        mt = None
    key = (mt, int(_t.time() // 60))
    if _edition['key'] == key and _edition['value'] is not None:
        return _edition['value']
    out = dict(ftcore.edition(os.path.dirname(LICENSE_FILE)), module=bool(pro_module()))
    _edition.update(key=key, value=out)
    return out


def save_license(text):
    """Activate a license code (it must be valid for this installation now); '' removes it. -> edition()."""
    import licensing
    text = (text or '').strip()
    if text:
        licensing.check(text)                # raises LicenseError (a ValueError) with the reason
        tmp = LICENSE_FILE + '.tmp'
        with open(tmp, 'w') as f:
            f.write(licensing.normalized(text) + '\n')
        os.chmod(tmp, 0o640)
        os.replace(tmp, LICENSE_FILE)
    elif os.path.exists(LICENSE_FILE):
        os.remove(LICENSE_FILE)
    _edition['value'] = None
    return edition()


def deactivate_license():
    """Deactivate the installed license to move it to another server -> the return code for the vendor.
    This installation refuses that license from then on."""
    import licensing
    text = read_license()
    if not text:
        raise ValueError('no license is installed')
    code = licensing.deactivate(text)
    os.remove(LICENSE_FILE)
    _edition['value'] = None
    return code


_TTL_RE = None


def flows_retention_days(target=None):
    """Days of flow details ClickHouse keeps (the TTL of `flows`). With `target`, the TTL is raised to it when
    shorter — never lowered, so an expired license or a smaller edition never deletes stored data, and installs
    made before the 14-day Community limit keep their 30 days."""
    global _TTL_RE
    if _TTL_RE is None:
        import re
        _TTL_RE = re.compile(r'TTL ts \+ (?:toIntervalDay\((\d+)\)|INTERVAL (\d+) DAY)')
    rows = ch("SELECT create_table_query AS q FROM system.tables WHERE database = currentDatabase() AND name = 'flows'", fmt='JSON')
    m = _TTL_RE.search(rows[0]['q']) if rows else None
    cur = int(m.group(1) or m.group(2)) if m else 0
    if target and cur and target > cur:
        ch(f'ALTER TABLE flows MODIFY TTL ts + INTERVAL {int(target)} DAY')
        cur = int(target)
    return cur


# ---------------------------------------------------------------- enrichment

def ipstr(v):
    """Normalize an address field (int, str, ipaddress object) to canonical text, or ''."""
    if v is None:
        return ''
    if type(v) is str:                               # hot path: the netflow library hands addresses over as text
        return _ip_text(v)
    if type(v) is int and 0 <= v < 4294967296:
        return _ipv4_text(v)
    try:
        if isinstance(v, int) or (isinstance(v, str) and v.isdigit()):
            return str(ipaddress.ip_address(int(v)))
        return str(ipaddress.ip_address(str(v)))
    except ValueError:
        return ''


@lru_cache(maxsize=262144)
def _ip_text(v):
    """Validated, canonical form of a textual address (addresses repeat a lot, so this is cached)."""
    try:
        return str(ipaddress.ip_address(v.strip()))
    except ValueError:
        return ''


@lru_cache(maxsize=131072)
def _ipv4_text(v):
    return f'{v >> 24}.{(v >> 16) & 255}.{(v >> 8) & 255}.{v & 255}'


@lru_cache(maxsize=65536)
def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local or a in ipaddress.ip_network('100.64.0.0/10')


class Geo:
    """GeoIP + ASN lookups from DB-IP Lite mmdb files (CC BY 4.0, https://db-ip.com)."""

    def __init__(self):
        self.city = self.asn = None
        try:
            import maxminddb
            self.city = maxminddb.open_database(os.path.join(GEOIP_DIR, 'dbip-city.mmdb'))
            self.asn = maxminddb.open_database(os.path.join(GEOIP_DIR, 'dbip-asn.mmdb'))
        except Exception as e:      # collector still works without enrichment
            print(f'[flowtrack] WARN GeoIP unavailable: {e}', flush=True)
        self.lookup = lru_cache(maxsize=200000)(self._lookup)

    def _lookup(self, ip):
        country = city = as_org = ''
        lat = lon = 0.0
        asn = 0
        if self.city and ip and not is_private(ip):
            r = self.city.get(ip) or {}
            country = (r.get('country') or {}).get('iso_code', '') or ''
            city = ((r.get('city') or {}).get('names') or {}).get('en', '') or ''
            city = city.split(' (')[0]          # 'San Francisco (Financial District)' -> 'San Francisco'
            loc = r.get('location') or {}
            lat, lon = float(loc.get('latitude') or 0), float(loc.get('longitude') or 0)
        if self.asn and ip and not is_private(ip):
            r = self.asn.get(ip) or {}
            asn = int(r.get('autonomous_system_number') or 0)
            as_org = r.get('autonomous_system_organization', '') or ''
        return country, city, lat, lon, asn, as_org


# well-known ports -> (L7 protocol, service name if the port alone identifies it)
PORTS = {
    (6, 443): ('HTTPS', None), (17, 443): ('QUIC', None), (6, 80): ('HTTP', None), (6, 8080): ('HTTP', None),
    (17, 53): ('DNS', 'DNS'), (6, 53): ('DNS', 'DNS'), (6, 853): ('DoT', 'DNS'), (17, 853): ('DoQ', 'DNS'),
    (17, 123): ('NTP', 'NTP'), (6, 22): ('SSH', None), (6, 3389): ('RDP', None), (17, 3389): ('RDP', None),
    (17, 1701): ('L2TP', 'VPN L2TP'), (17, 500): ('IPsec', 'VPN IPsec'), (17, 4500): ('IPsec', 'VPN IPsec'),
    (17, 51820): ('WireGuard', 'VPN WireGuard'), (17, 1194): ('OpenVPN', 'VPN OpenVPN'), (6, 1194): ('OpenVPN', 'VPN OpenVPN'),
    (6, 25): ('SMTP', None), (6, 465): ('SMTPS', None), (6, 587): ('SMTP', None), (6, 993): ('IMAPS', None), (6, 995): ('POP3S', None),
    (6, 514): ('Syslog', None), (17, 514): ('Syslog', None), (6, 5222): ('XMPP', None), (6, 5228): ('FCM', 'Google Push'),
    (6, 5229): ('FCM', 'Google Push'), (6, 5230): ('FCM', 'Google Push'), (6, 445): ('SMB', None), (6, 21): ('FTP', None),
    (17, 3478): ('STUN', None), (17, 19302): ('STUN', None), (6, 1883): ('MQTT', None), (6, 8883): ('MQTTS', None),
    (17, 161): ('SNMP', None), (17, 162): ('SNMP', None), (17, 2055): ('NetFlow', None), (17, 6343): ('sFlow', None),
}
PROTO_NAMES = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 132: 'SCTP'}
ASN_SERVICES = {
    15169: 'Google', 396982: 'Google Cloud', 36040: 'YouTube', 13335: 'Cloudflare', 62041: 'Telegram', 59930: 'Telegram',
    32934: 'Meta', 8075: 'Microsoft', 8068: 'Microsoft', 16509: 'Amazon AWS', 14618: 'Amazon AWS', 399358: 'Anthropic',
    36459: 'GitHub', 2906: 'Netflix', 54113: 'Fastly', 20940: 'Akamai', 16625: 'Akamai', 32590: 'Valve / Steam',
    714: 'Apple', 6185: 'Apple', 13414: 'X (Twitter)', 138699: 'TikTok', 396986: 'ByteDance', 19281: 'Quad9',
    41231: 'Canonical', 24940: 'Hetzner', 16276: 'OVH', 14061: 'DigitalOcean', 40934: 'Fortinet', 46489: 'Twitch',
    3356: 'Lumen', 1299: 'Arelion', 174: 'Cogent', 210079: 'EuroByte', 13238: 'Yandex', 47541: 'VK', 30103: 'Zoom',
    44907: 'Discord', 49544: 'i3D.net', 63949: 'Akamai Linode', 20473: 'Vultr', 8560: 'IONOS', 51167: 'Contabo',
    40401: 'Backblaze', 21342: 'Akamai', 22822: 'Edgio', 15133: 'Edgio', 26101: 'Yahoo', 4837: 'China Unicom',
}
_SUFFIXES = (' llc', ' inc.', ' inc', ' ltd.', ' ltd', ' limited', ' gmbh', ' b.v.', ' bv', ' s.a.', ' sa', ' ag',
             ' corporation', ' corp.', ' corp', ' co.', ' pbc', ' pe', ' llp', ' plc', ' ab', ' oy', ' sp. z o.o.')


@lru_cache(maxsize=8192)
def clean_org(org):
    s = org.strip().rstrip(',')
    low = s.lower()
    changed = True
    while changed:
        changed = False
        for suf in _SUFFIXES:
            if low.endswith(suf):
                s, low, changed = s[:-len(suf)].rstrip(' ,'), low[:-len(suf)].rstrip(' ,'), True
    return s


def classify_l7(proto, port):
    """(L7 protocol, port-derived service or None)."""
    hit = PORTS.get((proto, port))
    if hit:
        return hit
    name = PROTO_NAMES.get(proto, f'IP/{proto}')
    if proto in (6, 17) and port:
        return (f'{name}/{port}' if port < 1024 else f'{name} other'), None
    return name, None


def service_name(port_service, asn, as_org, ext_ip):
    if port_service:
        return port_service
    if asn in ASN_SERVICES:
        return ASN_SERVICES[asn]
    if as_org:
        return clean_org(as_org)
    return 'Local network' if is_private(ext_ip) else 'Unknown'
