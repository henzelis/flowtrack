"""Shared FlowTrack v2 helpers: config, ClickHouse HTTP client, enrichment."""
import base64
import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from functools import lru_cache

CONFIG_DIR = os.environ.get('FT_CONFIG_DIR', '/etc/flowtrack-v2')
GEOIP_DIR = os.environ.get('FT_GEOIP_DIR', '/opt/flowtrack-v2/geoip')
CH_URL = os.environ.get('FT_CH_URL', 'http://127.0.0.1:8123')
CH_USER = os.environ.get('FT_CH_USER', 'default')
CH_PASSWORD = os.environ.get('FT_CH_PASSWORD', '')
CH_DB = os.environ.get('FT_CH_DB', 'flowtrack')


def load_json(name, default):
    try:
        with open(os.path.join(CONFIG_DIR, name)) as f:
            return json.load(f)
    except FileNotFoundError:
        return default


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


# ---------------------------------------------------------------- enrichment

def ipstr(v):
    """Normalize an address field (int, str, ipaddress object) to canonical text, or ''."""
    if v is None:
        return ''
    try:
        if isinstance(v, int) or (isinstance(v, str) and v.isdigit()):
            return str(ipaddress.ip_address(int(v)))
        return str(ipaddress.ip_address(str(v)))
    except ValueError:
        return ''


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
        return (f'{name}/{port}' if port < 1024 else f'{name} інше'), None
    return name, None


def service_name(port_service, asn, as_org, ext_ip):
    if port_service:
        return port_service
    if asn in ASN_SERVICES:
        return ASN_SERVICES[asn]
    if as_org:
        return clean_org(as_org)
    return 'Локальна мережа' if is_private(ext_ip) else 'Невідомо'
