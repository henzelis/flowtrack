"""Detections (FlowTrack 1.6.0): port scans, password guessing, probes of management services, aggressive web
clients, DDoS / floods and inside hosts that scan. The collector runs them over every closed 10-minute window and
keeps what it finds in the `events` table: one event per kind and source (or service) that grows while the activity
goes on, so a scanner that knocks all day is one line, not a hundred.

Who opened a connection is the heart of it: NetFlow has no "initiator" field and FortiGate sends no TCP flags.
A session's two records (and both halves of a NAT translation) are put together, and the side that is a service is
the one that was called:
  1. our address:port that many outside addresses call from varying ports (learned hourly: `ev_services` kind L)
     or a well-known port -> the outside end opened it;
  2. an outside address:port that we call from many ports of ours, none of them well-known (kind R), or a
     well-known port there -> we opened it;
  3. otherwise unknown: such sessions count only for the port scan rule (a scanner's source port is no service).
Firewalls export only the traffic they let through, so scans of closed ports stay invisible there; what is seen are
calls to the services that are open.

Settings (on/off, priority, thresholds per kind; addresses, networks and ASNs to ignore; which services are public
or sensitive) live in STATE_DIR/events.json, written by the web UI."""
import calendar
import ipaddress
import json
import os
import time

from common import STATE_DIR, CHError, ch, tr

CONFIG = os.path.join(STATE_DIR, 'events.json')
STATE = os.path.join(STATE_DIR, 'detect_state.json')
WINDOW = 600            # seconds; rules count within one window
LAG = 180               # a window is looked at this long after its end (records of short sessions have arrived)
BACKFILL = 86400        # the first start looks at the last day
LEARN_EVERY = 3600      # services and DDoS baselines are learned again hourly
KEEP_SOURCES = 5000     # distinct sources kept per probe digest

# ports where something listens (a session to one of them was opened by the other end)
KNOWN = (21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 137, 138, 139, 143, 161, 389, 443, 445, 465, 500, 514, 587, 636,
         853, 873, 993, 995, 1080, 1194, 1433, 1521, 1701, 1723, 1883, 1900, 2049, 2055, 2375, 2376, 3128, 3306, 3389,
         3478, 4443, 4500, 5000, 5060, 5222, 5228, 5432, 5900, 5985, 5986, 6379, 6443, 8000, 8008, 8080, 8081, 8291,
         8443, 8728, 8729, 8883, 8888, 9000, 9090, 9200, 9443, 10443, 11211, 19302, 27017, 51820)
# management and remote-access services: many logins from one address are password guessing
SENSITIVE = (21, 22, 23, 445, 1433, 2375, 3306, 3389, 4443, 5432, 5900, 5985, 5986, 6379, 8291, 8443, 8728, 8729,
             9200, 10443, 27017)
# services meant for everybody: no scan / guessing rules, only floods and aggressive clients
PUBLIC = (80, 443, 8080)
# UDP services abused for reflection: their answers arrive without our questions
AMPLIFIERS = (17, 19, 53, 111, 123, 161, 389, 520, 1900, 3702, 5353, 11211, 37810)
# web and name lookups reach many addresses on their own: an inside scan there needs more of them
BUSY = (53, 80, 123, 443)
PRIVATE = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '127.0.0.0/8', 'fc00::/7', 'fe80::/10', '::1/128')
SEVERITIES = ('info', 'warn', 'crit')

# kind -> defaults; numbers are thresholds (their limits in LIMITS)
KINDS = {
    'port_scan':    {'on': True, 'sev': 'warn', 'ports': 10, 'services': 3, 'hosts': 10},
    'brute_force':  {'on': True, 'sev': 'warn', 'sessions': 30},
    'probes':       {'on': True, 'sev': 'info'},
    'heavy_client': {'on': True, 'sev': 'info', 'sessions': 200},
    'ddos':         {'on': True, 'sev': 'crit', 'factor': 10, 'min_sessions': 2000, 'min_mbps': 200, 'refl_mbps': 20, 'minutes': 3},
    'inside_scan':  {'on': True, 'sev': 'crit', 'hosts': 50, 'hosts_busy': 200, 'ports': 10},
    'lateral_scan': {'on': True, 'sev': 'crit', 'hosts': 10, 'ports': 10},
    # computed by the API from the last day of flows (api_alerts)
    'sustained_upload': {'on': True, 'sev': 'warn'},
    'burst':        {'on': True, 'sev': 'info'},
    'new_country':  {'on': True, 'sev': 'info'},
}
NAMES = {'port_scan': ('Port scan', 'Сканування портів'), 'brute_force': ('Password guessing', 'Перебір паролів'),
         'probes': ('Probes of management services', 'Зондування сервісів керування'), 'heavy_client': ('Aggressive client', 'Агресивний клієнт'),
         'ddos': ('DDoS / flood', 'DDoS / флуд'), 'inside_scan': ('Inside host scans the internet', 'Внутрішній хост сканує інтернет'),
         'lateral_scan': ('Scan inside the network', 'Сканування всередині мережі'), 'sustained_upload': ('Sustained upload', 'Тривале вивантаження'),
         'burst': ('Traffic burst', 'Сплеск трафіку'), 'new_country': ('New destination', 'Новий напрямок')}
LIMITS = {'ports': (2, 65535), 'services': (2, 100), 'hosts': (2, 100000), 'sessions': (2, 10 ** 7), 'factor': (2, 1000),
          'min_sessions': (1, 10 ** 8), 'min_mbps': (1, 10 ** 6), 'refl_mbps': (1, 10 ** 6), 'minutes': (1, 10),
          'hosts_busy': (2, 100000)}
GAPS = {'probes': 86400}    # an event goes on while its activity comes back within this gap (default 1 hour)
GAP = 3600
# big groupings may spill to disk instead of failing (as the API's heavy queries)
_MEM = int(os.environ.get('FT_CH_MEMORY_MB', '1024')) * 1024 * 1024 * 2 // 5
HEAVY = {'max_memory_usage': _MEM, 'max_bytes_before_external_group_by': _MEM * 2 // 5}


# ---------------------------------------------------------------- settings
def defaults():
    return {'kinds': {k: dict(v) for k, v in KINDS.items()}, 'ignore': [], 'sensitive': list(SENSITIVE),
            'public': list(PUBLIC), 'roles': {}}


def load_config():
    cfg = defaults()
    try:
        with open(CONFIG) as f:
            saved = json.load(f)
    except (FileNotFoundError, ValueError):
        return cfg
    for k, v in (saved.get('kinds') or {}).items():
        if k in cfg['kinds'] and isinstance(v, dict):
            cfg['kinds'][k].update({x: y for x, y in v.items() if x in cfg['kinds'][k]})
    for k in ('ignore', 'sensitive', 'public', 'roles'):
        if k in saved:
            cfg[k] = saved[k]
    return cfg


def _ignore_item(s):
    s = str(s).strip()
    if s.upper().startswith('AS') and s[2:].isdigit():
        return 'AS' + str(int(s[2:]))
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        pass
    try:
        return str(ipaddress.ip_network(s, strict=False))
    except ValueError:
        raise ValueError(tr(f'not an address, network or ASN: {s}', f'не адреса, мережа чи ASN: {s}')) from None


def _ports(v):
    out = []
    for p in v if isinstance(v, list) else str(v).replace(',', ' ').split():
        try:
            p = int(p)
        except (TypeError, ValueError):
            raise ValueError(tr(f'not a port: {p}', f'не порт: {p}')) from None
        if not 1 <= p <= 65535:
            raise ValueError(tr(f'not a port: {p}', f'не порт: {p}'))
        out.append(p)
    return sorted(set(out))


def validate(body):
    """The settings from the UI, checked; raises ValueError with a message for people."""
    cfg = defaults()
    for k, v in (body.get('kinds') or {}).items():
        if k not in cfg['kinds'] or not isinstance(v, dict):
            continue
        d = cfg['kinds'][k]
        if 'on' in v:
            d['on'] = bool(v['on'])
        if v.get('sev') in SEVERITIES:
            d['sev'] = v['sev']
        for x in d:
            if x in LIMITS and x in v:
                lo, hi = LIMITS[x]
                try:
                    n = int(v[x])
                except (TypeError, ValueError):
                    raise ValueError(tr(f'{NAMES[k][0]}: the thresholds must be numbers', f'{NAMES[k][1]}: пороги мають бути числами')) from None
                if not lo <= n <= hi:
                    raise ValueError(tr(f'{NAMES[k][0]}: a threshold must be {lo:,}–{hi:,}', f'{NAMES[k][1]}: поріг має бути від {lo:,} до {hi:,}'))
                d[x] = n
    ign = body.get('ignore', [])
    ign = ign if isinstance(ign, list) else str(ign).replace(',', ' ').split()
    cfg['ignore'] = sorted({_ignore_item(s) for s in ign if str(s).strip()})
    if len(cfg['ignore']) > 5000:
        raise ValueError(tr('at most 5000 entries to ignore', 'не більше 5000 винятків'))
    if 'sensitive' in body:
        cfg['sensitive'] = _ports(body['sensitive'])
    if 'public' in body:
        cfg['public'] = _ports(body['public'])
    roles = body.get('roles') or {}
    if not isinstance(roles, dict):
        raise ValueError('roles')
    for ep, role in roles.items():
        if role not in ('public', 'sensitive', 'normal') or not _endpoint(ep):
            raise ValueError(tr(f'bad service role: {ep}', f'хибна роль сервісу: {ep}'))
    cfg['roles'] = {ep: r for ep, r in roles.items()}
    return cfg


def _endpoint(ep):
    """'ip:port/proto' (IPv6 as [ip]:port/proto) -> (ip, port, proto) or None."""
    try:
        hp, proto = ep.rsplit('/', 1)
        host, port = hp.rsplit(':', 1)
        host = host[1:-1] if host.startswith('[') else host
        return str(ipaddress.ip_address(host)), int(port), int(proto)
    except (ValueError, AttributeError):
        return None


def endpoint(ip, port, proto):
    return f"{'[' + ip + ']' if ':' in ip else ip}:{port}/{proto}"


def save_config(cfg):
    tmp = CONFIG + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, 'w') as f:
        json.dump(cfg, f, indent=1, ensure_ascii=False)
    os.replace(tmp, CONFIG)


def add_ignore(value):
    cfg = load_config()
    item = _ignore_item(value)
    if item not in cfg['ignore']:
        cfg['ignore'] = sorted(cfg['ignore'] + [item])
        save_config(cfg)
    return cfg


class Ignore:
    """Addresses, networks and ASNs whose events are neither recorded nor shown."""

    def __init__(self, items):
        self.ips = [x for x in items if not x.startswith('AS') and '/' not in x]
        self.nets = [x for x in items if '/' in x]
        self.asns = [int(x[2:]) for x in items if x.startswith('AS')]
        self._nets = [ipaddress.ip_network(x) for x in self.nets]

    def params(self):
        return {'ign_ips': self.ips, 'ign_nets': self.nets, 'ign_asns': self.asns}

    def __contains__(self, item):
        ip, asn = item
        if not ip:
            return False
        if ip in self.ips or (asn and asn in self.asns):
            return True
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a.version == n.version and a in n for n in self._nets)


def _ignored(ip, asn='0'):
    """SQL: the address is on the ignore list (parameters from Ignore.params())."""
    return (f"(has({{ign_ips:Array(String)}}, {ip}) OR arrayExists(n -> isIPAddressInRange(if({ip} = '', '0.0.0.0', {ip}), n), {{ign_nets:Array(String)}})"
            f" OR has({{ign_asns:Array(UInt32)}}, {asn}))")


def _private(ip):
    return f"arrayExists(n -> isIPAddressInRange(if({ip} = '', '0.0.0.0', {ip}), n), [{', '.join(repr(n) for n in PRIVATE)}])"


def _arr(nums):
    return '[' + ','.join(str(int(n)) for n in nums) + ']'


# ---------------------------------------------------------------- learning
def learn(log=print):
    """Services on our side (L) and outside servers we call (R) over the last day; DDoS baselines."""
    known = _arr(KNOWN)
    # our address:port called by many outside addresses from varying, not well-known ports. Answers to our own calls
    # come from 443, 53 ... and are left out before grouping (on a busy network they are nearly all records); a PAT
    # port reused towards several servers is thereby no service either.
    ch(f"""INSERT INTO ev_services (kind, ip, port, proto, peers, updated)
        SELECT 'L', int_ip, int_port, proto, uniq(ext_ip) AS peers, now() FROM flows
        WHERE ts >= now() - INTERVAL 1 DAY AND dir = 'down' AND proto IN (6, 17) AND ext_port >= 1024 AND NOT has({known}, ext_port)
        GROUP BY int_ip, int_port, proto
        HAVING peers >= 5 AND uniq(ext_port) >= 5""", settings=HEAVY, timeout=600)
    # an outside address:port we call from many ports of ours, none well-known (only such ports need learning:
    # well-known ones count as servers anyway)
    ch(f"""INSERT INTO ev_services (kind, ip, port, proto, peers, updated)
        SELECT 'R', ext_ip, ext_port, proto, uniq(int_port) AS peers, now() FROM flows
        WHERE ts >= now() - INTERVAL 1 DAY AND dir = 'up' AND proto IN (6, 17) AND ext_port >= 1024 AND NOT has({known}, ext_port)
        GROUP BY ext_ip, ext_port, proto
        HAVING peers >= 5 AND uniqIf(int_port, int_port < 1024 OR has({known}, int_port)) < 0.1 * peers""", settings=HEAVY, timeout=600)
    base = {'svc': {}, 'wan': {}, 'refl': {}}
    # sessions a minute to each of our services (one inbound record per session) and inbound bits/s per device:
    # their 99th percentile over a week
    for r in ch(f"""SELECT ip, port, proto, quantile(0.99)(n) AS p99 FROM
            (SELECT int_ip AS ip, int_port AS port, proto, toStartOfMinute(ts) AS m, count() AS n FROM flows
             WHERE ts >= now() - INTERVAL 7 DAY AND ts < now() - INTERVAL 1 HOUR AND dir = 'down'
               AND (int_ip, int_port, proto) IN (SELECT ip, port, proto FROM ev_services WHERE kind = 'L' AND updated > now() - INTERVAL 1 DAY)
             GROUP BY ip, port, proto, m)
            GROUP BY ip, port, proto""", fmt='JSON', settings=HEAVY, timeout=600):
        base['svc'][(r['ip'], int(r['port']), int(r['proto']))] = float(r['p99'])
    for r in ch("""SELECT exporter, quantile(0.99)(bps) AS p99 FROM
            (SELECT exporter, toStartOfMinute(ts) AS m, sum(bytes) * 8 / 60 AS bps FROM flows
             WHERE ts >= now() - INTERVAL 7 DAY AND ts < now() - INTERVAL 1 HOUR AND dir = 'down' GROUP BY exporter, m)
            GROUP BY exporter""", fmt='JSON', settings=HEAVY, timeout=600):
        base['wan'][r['exporter']] = float(r['p99'])
    for r in ch(f"""SELECT exporter, quantile(0.99)(bps) AS p99 FROM
            (SELECT exporter, toStartOfMinute(ts) AS m, sum(bytes) * 8 / 60 AS bps FROM flows
             WHERE ts >= now() - INTERVAL 7 DAY AND ts < now() - INTERVAL 1 HOUR AND dir = 'down' AND proto = 17 AND has({_arr(AMPLIFIERS)}, ext_port)
             GROUP BY exporter, m)
            GROUP BY exporter""", fmt='JSON', settings=HEAVY, timeout=600):
        base['refl'][r['exporter']] = float(r['p99'])
    return base


def services(cfg):
    """Learned services on our side with their role (for the settings page)."""
    rows = ch("""SELECT ip, port, proto, max(peers) AS np FROM ev_services
        WHERE kind = 'L' AND updated > now() - INTERVAL 1 DAY GROUP BY ip, port, proto ORDER BY np DESC LIMIT 200""", fmt='JSON')
    out = []
    for r in rows:
        ep = endpoint(r['ip'], int(r['port']), int(r['proto']))
        out.append({'ep': ep, 'ip': r['ip'], 'port': int(r['port']), 'proto': int(r['proto']), 'peers': int(r['np']),
                    'role': role_of(cfg, ep, int(r['port'])), 'set': ep in cfg['roles']})
    return out


def role_of(cfg, ep, port):
    return cfg['roles'].get(ep) or ('public' if port in cfg['public'] else 'sensitive' if port in cfg['sensitive'] else 'normal')


# ---------------------------------------------------------------- one window
def _sessions(cfg):
    """WITH ... X: the sessions of the window {t0}..{t1} with their initiator and the role of our end."""
    roles = cfg['roles']
    eps = {r: [ep for ep, x in roles.items() if x == r] for r in ('public', 'sensitive', 'normal')}
    ep = "concat(if(position(e.1, ':') > 0, concat('[', e.1, ']'), e.1), ':', toString(e.2), '/', toString(proto))"
    known = _arr(KNOWN)
    return f"""WITH
 learned_l AS (SELECT ip, port, proto FROM ev_services WHERE kind = 'L' AND updated > now() - INTERVAL 1 DAY),
 learned_r AS (SELECT ip, port, proto FROM ev_services WHERE kind = 'R' AND updated > now() - INTERVAL 1 DAY),
 S AS (SELECT exporter, proto, ext_ip, ext_port,
         if(nat_ip != '' AND nat_ip < int_ip, nat_ip, int_ip) AS ci, if(nat_ip != '' AND nat_ip < int_ip, nat_port, int_port) AS cp,
         argMin(int_ip, NOT {_private('int_ip')}) AS h_ip, argMin(int_port, NOT {_private('int_ip')}) AS h_port,
         groupUniqArray((int_ip, int_port)) AS eps, toStartOfMinute(min(ts)) AS m,
         any(country) AS cc, any(as_org) AS org, any(asn) AS a_asn,
         countIf(dir = 'down') AS nd, countIf(dir = 'up') AS nu, sumIf(packets, dir = 'up') AS pu, sumIf(packets, dir = 'down') AS pd, sumIf(bytes, dir = 'down') AS bd
       FROM flows WHERE ts >= {{t0:DateTime}} AND ts < {{t1:DateTime}} AND dir IN ('up', 'down') AND proto IN (6, 17)
       GROUP BY exporter, proto, ext_ip, ext_port, ci, cp),
 X AS (SELECT *, h_ip AS int_ip, h_port AS int_port, h_ip AS tgt,
         arrayExists(e -> (e.1, e.2, proto) IN learned_l, eps) AS listening,
         (listening OR arrayExists(e -> e.2 < 1024 OR has({known}, e.2), eps)) AS in_srv,
         (ext_port < 1024 OR has({known}, ext_port) OR (ext_ip, ext_port, proto) IN learned_r) AS out_srv,
         multiIf(in_srv AND NOT out_srv, 'out', out_srv AND NOT in_srv, 'in',
                 in_srv AND out_srv, if(listening AND NOT (ext_port < 1024 OR has({known}, ext_port)), 'out', 'both'), 'unk') AS init,
         -- we sent and got nothing back (or only a reset)
         (nu > 0 AND (nd = 0 OR (pu <= 2 AND pd <= 1))) AS failed,
         -- a role set for the service wins; else its port (of the inside end for destination NAT: as listed in the settings)
         multiIf(arrayExists(e -> has({_sarr(eps['public'])}, {ep}), eps), 'public',
                 arrayExists(e -> has({_sarr(eps['sensitive'])}, {ep}), eps), 'sensitive',
                 arrayExists(e -> has({_sarr(eps['normal'])}, {ep}), eps), 'normal',
                 has({_arr(cfg['public'])}, h_port), 'public', has({_arr(cfg['sensitive'])}, h_port), 'sensitive', 'normal') AS role
       FROM S)
"""


def _sarr(items):
    return "CAST([" + ','.join("'" + str(x).replace('\\', '').replace("'", '') + "'" for x in items) + "] AS Array(String))"


def rules(cfg, base, t0, t1):
    """Hits of every enabled rule in the window [t0, t1): dicts kind, key, exporter, src, dst, port, proto, value, info."""
    K, ign = cfg['kinds'], Ignore(cfg['ignore'])
    p = dict(ign.params(), t0=t0, t1=t1)
    X = _sessions(cfg)
    hits = []

    def q(sql):
        return ch(X + sql, p, fmt='JSON', timeout=120, settings=HEAVY)

    if K['port_scan']['on']:
        k = K['port_scan']
        for r in q(f"""SELECT ext_ip, any(exporter) AS ex, uniqExact(int_port) AS ports,
                uniqExactIf(int_port, listening AND role != 'public') AS svcs, uniqExact(tgt) AS hosts, count() AS n,
                arraySlice(arraySort(groupUniqArray(int_port)), 1, 40) AS plist, groupUniqArray(10)(tgt) AS tlist, any(cc) AS c, any(org) AS o, any(a_asn) AS asn
                FROM X WHERE init IN ('out', 'unk') AND NOT {_ignored('ext_ip', 'a_asn')}
                GROUP BY ext_ip HAVING ports >= {k['ports']} OR svcs >= {k['services']}"""):
            hits.append(_hit('port_scan', r['ext_ip'], r, src=r['ext_ip'], value=max(int(r['ports']), int(r['svcs'])),
                             info={'ports': r['plist'], 'targets': r['tlist'], 'sessions': int(r['n']), 'how': 'ports' if int(r['ports']) >= k['ports'] else 'services'}))
        for r in q(f"""SELECT ext_ip, int_port, any(exporter) AS ex, uniqExact(tgt) AS hosts, count() AS n,
                groupUniqArray(10)(tgt) AS tlist, any(cc) AS c, any(org) AS o, any(a_asn) AS asn
                FROM X WHERE init = 'out' AND NOT {_ignored('ext_ip', 'a_asn')}
                GROUP BY ext_ip, int_port HAVING hosts >= {k['hosts']}"""):
            hits.append(_hit('port_scan', r['ext_ip'], r, src=r['ext_ip'], port=int(r['int_port']), value=int(r['hosts']),
                             info={'ports': [int(r['int_port'])], 'targets': r['tlist'], 'sessions': int(r['n']), 'how': 'hosts'}))
    if K['brute_force']['on']:
        for r in q(f"""SELECT ext_ip, tgt, int_port, proto, any(exporter) AS ex, count() AS n, any(cc) AS c, any(org) AS o, any(a_asn) AS asn
                FROM X WHERE init = 'out' AND role = 'sensitive' AND NOT {_ignored('ext_ip', 'a_asn')}
                GROUP BY ext_ip, tgt, int_port, proto HAVING n >= {K['brute_force']['sessions']}"""):
            hits.append(_hit('brute_force', f"{r['ext_ip']}>{endpoint(r['tgt'], int(r['int_port']), int(r['proto']))}", r,
                             src=r['ext_ip'], dst=r['tgt'], port=int(r['int_port']), proto=int(r['proto']), value=int(r['n']),
                             info={'sessions': int(r['n'])}))
    if K['probes']['on']:
        for r in q(f"""SELECT tgt, int_port, proto, any(exporter) AS ex, uniqExact(ext_ip) AS srcs, count() AS n,
                groupUniqArray({KEEP_SOURCES})(ext_ip) AS slist, topK(5)(cc) AS top
                FROM X WHERE init = 'out' AND role = 'sensitive' AND NOT {_ignored('ext_ip', 'a_asn')}
                GROUP BY tgt, int_port, proto"""):
            day = time.strftime('%Y-%m-%d', time.gmtime(t0))
            hits.append(_hit('probes', f"{endpoint(r['tgt'], int(r['int_port']), int(r['proto']))}@{day}", r,
                             dst=r['tgt'], port=int(r['int_port']), proto=int(r['proto']), value=int(r['srcs']),
                             info={'sources': r['slist'], 'sessions': int(r['n']), 'countries': [c for c in r['top'] if c]}))
    if K['heavy_client']['on']:
        for r in q(f"""SELECT ext_ip, tgt, int_port, proto, any(exporter) AS ex, count() AS n, any(cc) AS c, any(org) AS o, any(a_asn) AS asn
                FROM X WHERE init = 'out' AND role = 'public' AND NOT {_ignored('ext_ip', 'a_asn')}
                GROUP BY ext_ip, tgt, int_port, proto HAVING n >= {K['heavy_client']['sessions']}"""):
            hits.append(_hit('heavy_client', f"{r['ext_ip']}>{endpoint(r['tgt'], int(r['int_port']), int(r['proto']))}", r,
                             src=r['ext_ip'], dst=r['tgt'], port=int(r['int_port']), proto=int(r['proto']), value=int(r['n']),
                             info={'sessions': int(r['n'])}))
    if K['inside_scan']['on']:
        k = K['inside_scan']
        for r in q(f"""SELECT int_ip, ext_port, any(exporter) AS ex, uniqExact(ext_ip) AS dsts, count() AS n, groupUniqArray(10)(ext_ip) AS dlist
                FROM X WHERE init = 'in' AND NOT {_ignored('int_ip')}
                GROUP BY int_ip, ext_port HAVING dsts >= if(has({_arr(BUSY)}, ext_port), {k['hosts_busy']}, {k['hosts']}) AND countIf(failed) >= 0.8 * n"""):
            hits.append(_hit('inside_scan', r['int_ip'], r, src=r['int_ip'], port=int(r['ext_port']), value=int(r['dsts']),
                             info={'how': 'hosts', 'targets': r['dlist'], 'ports': [int(r['ext_port'])], 'sessions': int(r['n'])}))
        for r in q(f"""SELECT int_ip, ext_ip, any(exporter) AS ex, uniqExact(ext_port) AS ports, count() AS n, arraySlice(arraySort(groupUniqArray(ext_port)), 1, 40) AS plist
                FROM X WHERE init IN ('in', 'unk') AND NOT {_ignored('int_ip')}
                GROUP BY int_ip, ext_ip HAVING ports >= {k['ports']} AND countIf(failed) >= 0.8 * n"""):
            hits.append(_hit('inside_scan', r['int_ip'], r, src=r['int_ip'], dst=r['ext_ip'], value=int(r['ports']),
                             info={'how': 'ports', 'targets': [r['ext_ip']], 'ports': r['plist'], 'sessions': int(r['n'])}))
    if K['lateral_scan']['on']:
        hits += lateral(K['lateral_scan'], p)
    if K['ddos']['on']:
        hits += ddos(K['ddos'], base, p)
    return hits


def lateral(k, p):
    """Inside -> inside: one host calls many hosts on one port, or many ports of one host, with tiny unanswered probes.
    Internal records are oriented source -> destination: a call is answered when the reverse record exists (so a
    server's answers to its clients' random ports never count); the source port must look like a client's."""
    known, quiet = _arr(KNOWN), _arr((53, 67, 68, 123, 137, 138, 1900, 5353, 5355))
    win = "ts >= {t0:DateTime} AND ts < {t1:DateTime} AND dir = 'internal' AND proto IN (6, 17)"
    # a probe is tiny: a few packets that got no answer (a device that exports one direction only shows no answers
    # at all, but real conversations are bigger than that)
    base = f"""SELECT any(exporter) AS ex, int_ip AS a, ext_ip AS b, ext_port AS bp, count() AS recs,
            (proto, ext_ip, ext_port, int_ip, int_port) IN (SELECT proto, int_ip, int_port, ext_ip, ext_port FROM flows WHERE {win})
            OR sum(packets) > 3 AS answered
        FROM flows WHERE {win} AND NOT (int_port < 1024 OR has({known}, int_port)) AND NOT has({quiet}, ext_port) AND NOT {_ignored('int_ip')}
        GROUP BY proto, int_ip, int_port, ext_ip, ext_port"""
    hits = []
    for r in ch(f"""SELECT a, bp, any(ex) AS ex, uniqExactIf(b, NOT answered) AS hosts, count() AS n, groupUniqArrayIf(10)(b, NOT answered) AS dlist
            FROM ({base}) GROUP BY a, bp HAVING hosts >= {k['hosts']} AND countIf(NOT answered) >= 0.8 * n""", p, fmt='JSON'):
        hits.append(_hit('lateral_scan', r['a'], r, src=r['a'], port=int(r['bp']), value=int(r['hosts']),
                         info={'how': 'hosts', 'targets': r['dlist'], 'ports': [int(r['bp'])], 'sessions': int(r['n'])}))
    for r in ch(f"""SELECT a, b, any(ex) AS ex, uniqExactIf(bp, NOT answered) AS ports, count() AS n, arraySlice(arraySort(groupUniqArrayIf(bp, NOT answered)), 1, 40) AS plist
            FROM ({base}) GROUP BY a, b HAVING ports >= {k['ports']} AND countIf(NOT answered) >= 0.8 * n""", p, fmt='JSON'):
        hits.append(_hit('lateral_scan', r['a'], r, src=r['a'], dst=r['b'], value=int(r['ports']),
                         info={'how': 'ports', 'targets': [r['b']], 'ports': r['plist'], 'sessions': int(r['n'])}))
    return hits


def ddos(k, base, p):
    """Floods: a minute far above the service's (or the device's) own 99th percentile and above an absolute floor,
    in at least `minutes` minutes of the window; the same for UDP from amplifier ports (reflection)."""
    hits = []
    rows = ch(f"""SELECT int_ip, int_port, proto, any(exporter) AS ex, toStartOfMinute(ts) AS m, count() AS n, uniqExact(ext_ip) AS srcs
        FROM flows WHERE ts >= {{t0:DateTime}} AND ts < {{t1:DateTime}} AND dir = 'down'
          AND (int_ip, int_port, proto) IN (SELECT ip, port, proto FROM ev_services WHERE kind = 'L' AND updated > now() - INTERVAL 1 DAY)
        GROUP BY int_ip, int_port, proto, m""", p, fmt='JSON')
    per = {}
    for r in rows:
        key = (r['int_ip'], int(r['int_port']), int(r['proto']))
        limit = max(k['factor'] * base['svc'].get(key, 0), k['min_sessions'])
        if int(r['n']) >= limit:
            per.setdefault(key, []).append(r)
    for (ip, port, proto), ms in per.items():
        if len(ms) >= k['minutes']:
            top = max(ms, key=lambda r: int(r['n']))
            hits.append(_hit('ddos', f'svc {endpoint(ip, port, proto)}', top, dst=ip, port=port, proto=proto, value=int(top['n']),
                             info={'how': 'sessions', 'per_minute': int(top['n']), 'srcs': int(top['srcs']), 'minutes': len(ms),
                                   'baseline': round(base['svc'].get((ip, port, proto), 0), 1)}))
    per = {}
    for r in ch("""SELECT exporter AS ex, toStartOfMinute(ts) AS m, sum(bytes) * 8 / 60 AS bps, uniqExact(ext_ip) AS srcs FROM flows
            WHERE ts >= {t0:DateTime} AND ts < {t1:DateTime} AND dir = 'down' GROUP BY ex, m""", p, fmt='JSON'):
        if float(r['bps']) >= max(k['factor'] * base['wan'].get(r['ex'], 0), k['min_mbps'] * 1e6):
            per.setdefault(r['ex'], []).append(r)
    for ex, ms in per.items():
        if len(ms) >= k['minutes']:
            top = max(ms, key=lambda r: float(r['bps']))
            hits.append(_hit('ddos', f'wan {ex}', top, value=float(top['bps']),
                             info={'how': 'volume', 'bps': float(top['bps']), 'srcs': int(top['srcs']), 'minutes': len(ms),
                                   'baseline': round(base['wan'].get(ex, 0))}))
    # reflection: inbound UDP from amplifier ports far above its own usual peak (answers to our own lookups are in
    # that peak; counting records, not pairs, keeps it right on devices that export one direction only)
    per = {}
    for r in ch(f"""SELECT exporter AS ex, toStartOfMinute(ts) AS m, sum(bytes) * 8 / 60 AS bps, uniqExact(ext_ip) AS srcs,
            groupUniqArray(5)(ext_port) AS plist FROM flows
            WHERE ts >= {{t0:DateTime}} AND ts < {{t1:DateTime}} AND dir = 'down' AND proto = 17 AND has({_arr(AMPLIFIERS)}, ext_port)
            GROUP BY ex, m""", p, fmt='JSON'):
        if float(r['bps']) >= max(k['factor'] * base['refl'].get(r['ex'], 0), k['refl_mbps'] * 1e6) and int(r['srcs']) >= 20:
            per.setdefault(r['ex'], []).append(r)
    for ex, ms in per.items():
        if len(ms) >= k['minutes']:
            top = max(ms, key=lambda r: float(r['bps']))
            hits.append(_hit('ddos', f'refl {ex}', top, value=float(top['bps']),
                             info={'how': 'reflection', 'bps': float(top['bps']), 'srcs': int(top['srcs']), 'minutes': len(ms),
                                   'baseline': round(base['refl'].get(ex, 0)),
                                   'ports': top['plist']}))
    return hits


def _hit(kind, key, r, src='', dst='', port=0, proto=0, value=0, info=None):
    info = dict(info or {})
    for a, b in (('c', 'country'), ('o', 'org'), ('asn', 'asn')):
        if r.get(a):
            info[b] = int(r[a]) if a == 'asn' else r[a]
    return {'kind': kind, 'key': key, 'exporter': r.get('ex', ''), 'src': src, 'dst': dst, 'port': port, 'proto': proto,
            'value': float(value), 'info': info}


# ---------------------------------------------------------------- events
def merge_info(old, new):
    out = dict(old)
    for k, v in new.items():
        if k in ('ports', 'targets', 'countries'):
            out[k] = list(dict.fromkeys(list(old.get(k, [])) + list(v)))[:50]
        elif k == 'sources':
            out[k] = list(dict.fromkeys(list(old.get(k, [])) + list(v)))[:KEEP_SOURCES]
        elif k == 'sessions':
            out[k] = int(old.get(k, 0)) + int(v)
        elif k in ('per_minute', 'bps', 'minutes', 'srcs') and isinstance(v, (int, float)):
            out[k] = max(v, old.get(k, 0))
        else:
            out[k] = v
    return out


def store(hits, t0, t1):
    """Merge the window's hits into open events (same kind and key, activity within the gap) or start new ones."""
    if not hits:
        return 0
    by = {}
    for h in hits:            # one rule may hit the same key twice in a window (e.g. ports and hosts)
        k = (h['kind'], h['key'])
        if k in by:
            o = by[k]
            o['info'], o['value'] = merge_info(o['info'], h['info']), max(o['value'], h['value'])
            o['info']['sessions'] = max(int(o['info'].get('sessions', 0)), int(h['info'].get('sessions', 0)))
        else:
            by[k] = h
    kinds = sorted({k[0] for k in by})
    open_ = {}
    for r in ch("""SELECT kind, key, first_seen, last_seen, hits, value, info FROM events FINAL
            WHERE kind IN {kinds:Array(String)} AND key IN {keys:Array(String)} AND last_seen >= {since:DateTime}""",
                {'kinds': kinds, 'keys': sorted({k[1] for k in by}), 'since': t0 - max([GAP] + list(GAPS.values()))}, fmt='JSON'):
        gap = GAPS.get(r['kind'], GAP)
        last = _ts(r['last_seen'])
        k = (r['kind'], r['key'])
        if last >= t0 - gap and (k not in open_ or _ts(open_[k]['first_seen']) < _ts(r['first_seen'])):
            open_[k] = r
    rows, ver = [], time.time_ns()
    for k, h in by.items():
        o = open_.get(k)
        if o:
            info = merge_info(json.loads(o['info'] or '{}'), h['info'])
            first, n, value = _ts(o['first_seen']), int(o['hits']) + 1, max(float(o['value']), h['value'])
        else:
            info, first, n, value = h['info'], t0, 1, h['value']
        rows.append({'kind': h['kind'], 'key': h['key'], 'first_seen': first, 'last_seen': max(t1, _ts(o['last_seen']) if o else 0),
                     'hits': n, 'exporter': h['exporter'], 'src': h['src'], 'dst': h['dst'], 'port': h['port'], 'proto': h['proto'],
                     'value': value, 'info': json.dumps(info, ensure_ascii=False), 'ver': ver})
    ch('INSERT INTO events FORMAT JSONEachRow', data='\n'.join(json.dumps(r) for r in rows).encode())
    return len(rows)


def _ts(v):
    if isinstance(v, (int, float)):
        return int(v)
    return calendar.timegm(time.strptime(v, '%Y-%m-%d %H:%M:%S'))      # ClickHouse answers in UTC


class Detector:
    """The collector's background thread: every closed window once, a day back at the first start."""

    def __init__(self, log=print):
        self.log, self.base, self.learned = log, {'svc': {}, 'wan': {}, 'refl': {}}, 0

    def state(self):
        try:
            with open(STATE) as f:
                return json.load(f)
        except (FileNotFoundError, ValueError):
            return {}

    def save_state(self, done):
        tmp = STATE + '.tmp'
        with open(tmp, 'w') as f:
            json.dump({'done': done}, f)
        os.replace(tmp, STATE)

    def tick(self, now=None):
        now = int(now or time.time())
        if now - self.learned >= LEARN_EVERY:
            self.base, self.learned = learn(self.log), now
        cfg = load_config()
        done = self.state().get('done') or (now - BACKFILL) // WINDOW * WINDOW
        done = max(done, (now - BACKFILL) // WINDOW * WINDOW)     # off for days: only the last one
        found = 0
        while done + WINDOW <= now - LAG:
            found += store(rules(cfg, self.base, done, done + WINDOW), done, done + WINDOW)
            done += WINDOW
            self.save_state(done)
        return found

    def run(self):
        while True:
            try:
                n = self.tick()
                if n:
                    self.log(f'detections: {n} event update{"s" if n != 1 else ""}')
            except (CHError, OSError, ValueError, KeyError) as ex:
                self.log(f'WARN detections: {str(ex)[:300]}')
            time.sleep(60)


# ---------------------------------------------------------------- reading (web API)
def recent(cfg, since, until=None):
    """Stored events active in [since, until], with their texts; ignored sources and disabled kinds left out."""
    ign = Ignore(cfg['ignore'])
    out = []
    for r in ch("""SELECT kind, key, first_seen, last_seen, hits, exporter, src, dst, port, proto, value, info FROM events FINAL
            WHERE last_seen >= {since:DateTime} AND first_seen <= {until:DateTime} ORDER BY last_seen DESC LIMIT 5000""",
                {'since': int(since), 'until': int(until or time.time())}, fmt='JSON'):
        k = cfg['kinds'].get(r['kind'])
        if not k or not k['on']:
            continue
        info = json.loads(r['info'] or '{}')
        if (r['src'], info.get('asn')) in ign:
            continue
        r['info'] = info
        title, text = describe(r)
        out.append({'sev': k['sev'], 'kind': r['kind'], 'title': title, 'text': text, 'when': r['last_seen'],
                    'first': r['first_seen'], 'last': r['last_seen'], 'hits': int(r['hits']), 'src': r['src'], 'dst': r['dst'],
                    'ip': r['src'] or r['dst'], 'port': int(r['port']), 'country': info.get('country', ''), 'org': info.get('org', ''),
                    'asn': info.get('asn', 0), 'exporter': r['exporter'], 'stored': True,
                    'addrs': list(info.get('targets', [])) + list(info.get('sources', [])), 'ports': [int(x) for x in info.get('ports', [])],
                    'fk': _filter_of(r)[0], 'fv': _filter_of(r)[1]})
    return out


def _filter_of(r):
    """The filter the event's Filter button sets on the other pages: an outside source is an outside address there
    (`dst`), an inside one or our attacked service an inside host (`ip`), a device-wide flood the device."""
    if r['kind'] in ('port_scan', 'brute_force', 'heavy_client'):
        return 'dst', r['src']
    if r['kind'] in ('inside_scan', 'lateral_scan'):
        return 'ip', r['src']
    if r['dst']:
        return 'ip', r['dst']
    return 'device', r['exporter']


PROTO = {6: 'TCP', 17: 'UDP'}


def _who(r):
    i = r['info']
    extra = ', '.join(x for x in (i.get('country', ''), i.get('org', '')) if x)
    return f"{r['src']} ({extra})" if extra else r['src']


def _plist(ports, n=12):
    ports = sorted(int(p) for p in ports)
    return ', '.join(map(str, ports[:n])) + (' …' if len(ports) > n else '')


def _mbps(v):
    return f'{float(v) / 1e6:,.0f}'


def describe(r):
    """Title and text of a stored event in the language of the request."""
    i, kind, port = r['info'], r['kind'], int(r['port'])
    svc = f"{r['dst']}:{port}" if r['dst'] else str(port)
    if kind == 'port_scan':
        how = i.get('how')
        if how == 'hosts':
            return (tr('Network sweep', 'Обхід мережі'),
                    tr(f"{_who(r)} called port {_plist(i.get('ports', []))} on {len(i.get('targets', []))}+ of our addresses.",
                       f"{_who(r)} звертався до порту {_plist(i.get('ports', []))} на {len(i.get('targets', []))}+ наших адресах."))
        n = max(int(r['value']), len(i.get('ports', [])))
        return (tr('Port scan', 'Сканування портів'),
                tr(f"{_who(r)} tried {n:,} ports of ours: {_plist(i.get('ports', []))}.",
                   f"{_who(r)} перебирав {n:,} наших портів: {_plist(i.get('ports', []))}."))
    if kind == 'brute_force':
        return (tr('Password guessing', 'Перебір паролів'),
                tr(f"{_who(r)} opened {i.get('sessions', 0):,} sessions to {svc}" + (f", up to {int(r['value']):,} in 10 min." if int(r['hits']) > 1 else ' in 10 min.'),
                   f"{_who(r)} відкрив {i.get('sessions', 0):,} сесій до {svc}" + (f", до {int(r['value']):,} за 10 хв." if int(r['hits']) > 1 else ' за 10 хв.')))
    if kind == 'probes':
        n = len(i.get('sources', []))
        cc = ', '.join(i.get('countries', [])[:5])
        return (tr(f'Probes of {svc}', f'Зондування {svc}'),
                tr(f"{n:,} outside address{'es' if n != 1 else ''} called this management service ({i.get('sessions', 0):,} sessions)" + (f"; most from {cc}." if cc else '.'),
                   f"До цього сервісу керування звертались зовнішні адреси: {n:,} ({i.get('sessions', 0):,} сесій)" + (f"; найбільше з {cc}." if cc else '.')))
    if kind == 'heavy_client':
        return (tr('Aggressive client', 'Агресивний клієнт'),
                tr(f"{_who(r)}: {i.get('sessions', 0):,} sessions to {svc}" + (f", up to {int(r['value']):,} in 10 min." if int(r['hits']) > 1 else ' in 10 min.'),
                   f"{_who(r)}: {i.get('sessions', 0):,} сесій до {svc}" + (f", до {int(r['value']):,} за 10 хв." if int(r['hits']) > 1 else ' за 10 хв.')))
    if kind == 'ddos':
        how = i.get('how')
        if how == 'sessions':
            return (tr(f'Flood of {svc}', f'Флуд на {svc}'),
                    tr(f"Up to {i.get('per_minute', 0):,} new sessions a minute from {i.get('srcs', 0):,} addresses (usual peak {round(i.get('baseline', 0)):,}), {i.get('minutes', 0)} min.",
                       f"До {i.get('per_minute', 0):,} нових сесій за хвилину з {i.get('srcs', 0):,} адрес (звичайний пік {round(i.get('baseline', 0)):,}), {i.get('minutes', 0)} хв."))
        if how == 'reflection':
            return (tr('Reflection attack', 'Атака відбиттям'),
                    tr(f"Up to {_mbps(i.get('bps', 0))} Mbit/s of UDP from ports {_plist(i.get('ports', []))} (usual peak {_mbps(i.get('baseline', 0))} Mbit/s), from {i.get('srcs', 0):,} addresses, {i.get('minutes', 0)} min.",
                       f"До {_mbps(i.get('bps', 0))} Мбіт/с UDP з портів {_plist(i.get('ports', []))} (звичайний пік {_mbps(i.get('baseline', 0))} Мбіт/с), з {i.get('srcs', 0):,} адрес, {i.get('minutes', 0)} хв."))
        return (tr('Traffic flood', 'Флуд трафіку'),
                tr(f"Inbound up to {_mbps(i.get('bps', 0))} Mbit/s on {r['exporter']} (usual peak {_mbps(i.get('baseline', 0))} Mbit/s), {i.get('minutes', 0)} min, {i.get('srcs', 0):,} addresses.",
                   f"Вхідний трафік до {_mbps(i.get('bps', 0))} Мбіт/с на {r['exporter']} (звичайний пік {_mbps(i.get('baseline', 0))} Мбіт/с), {i.get('minutes', 0)} хв, {i.get('srcs', 0):,} адрес."))
    if kind in ('inside_scan', 'lateral_scan'):
        title = tr('Inside host scans the internet', 'Внутрішній хост сканує інтернет') if kind == 'inside_scan' else tr('Scan inside the network', 'Сканування всередині мережі')
        if i.get('how') == 'ports':
            n = max(int(r['value']), len(i.get('ports', [])))
            return (title, tr(f"{r['src']} tried {n:,} ports of {r['dst']} without answers: {_plist(i.get('ports', []))}. Check the device.",
                              f"{r['src']} перебирав {n:,} портів {r['dst']} без відповідей: {_plist(i.get('ports', []))}. Перевірте пристрій."))
        return (title, tr(f"{r['src']} called port {port} on {int(r['value']):,} addresses, mostly without an answer. Check the device.",
                          f"{r['src']} звертався до порту {port} на {int(r['value']):,} адресах, здебільшого без відповіді. Перевірте пристрій."))
    return kind, ''
