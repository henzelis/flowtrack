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
import threading
import time

import notify
import reputation
from common import STATE_DIR, CHError, N_, ch, tr, trn

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
    # (1.12.0) an interface above pct % of its capacity (own figures, else its speed) in every 5 minutes of `span` minutes
    'link_load':    {'on': True, 'sev': 'warn', 'pct': 85, 'span': 15},
    # IP reputation (reputation.py)
    'malware_contact': {'on': True, 'sev': 'crit'},
    'listed_contact': {'on': True, 'sev': 'warn'},
    'listed_inbound': {'on': True, 'sev': 'info'},
    # computed by the API from the last day of flows (api_alerts)
    'sustained_upload': {'on': True, 'sev': 'warn'},
    'burst':        {'on': True, 'sev': 'info'},
    'new_country':  {'on': True, 'sev': 'info'},
}
NAMES = {'port_scan': N_('Port scan'), 'brute_force': N_('Password guessing'), 'probes': N_('Probes of management services'),
         'heavy_client': N_('Aggressive client'), 'ddos': N_('DDoS / flood'), 'inside_scan': N_('Inside host scans the internet'),
         'lateral_scan': N_('Scan inside the network'), 'sustained_upload': N_('Sustained upload'), 'burst': N_('Traffic burst'),
         'new_country': N_('New destination'), 'malware_contact': N_('Contact with malware infrastructure'),
         'listed_contact': N_('Contact with a listed address'), 'listed_inbound': N_('Listed addresses calling us'),
         'link_load': N_('Link near capacity')}
LIMITS = {'ports': (2, 65535), 'services': (2, 100), 'hosts': (2, 100000), 'sessions': (2, 10 ** 7), 'factor': (2, 1000),
          'min_sessions': (1, 10 ** 8), 'min_mbps': (1, 10 ** 6), 'refl_mbps': (1, 10 ** 6), 'minutes': (1, 10), 'pct': (10, 100), 'span': (5, 60),
          'hosts_busy': (2, 100000)}
GAPS = {'probes': 86400, 'listed_inbound': 86400}    # an event goes on while its activity comes back within this gap (default 1 hour)
GAP = 3600
# big groupings may spill to disk instead of failing (as the API's heavy queries)
_MEM = int(os.environ.get('FT_CH_MEMORY_MB', '1024')) * 1024 * 1024 * 2 // 5
HEAVY = {'max_memory_usage': _MEM, 'max_bytes_before_external_group_by': _MEM * 2 // 5}


# ---------------------------------------------------------------- settings
def defaults():
    return {'kinds': {k: dict(v) for k, v in KINDS.items()}, 'ignore': [], 'exclude': [], 'sensitive': list(SENSITIVE),
            'public': list(PUBLIC), 'roles': {}, 'lists': {n: True for n in reputation.LISTS}, 'own_list': []}


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
    for k in ('ignore', 'exclude', 'sensitive', 'public', 'roles', 'own_list'):
        if k in saved:
            cfg[k] = saved[k]
    cfg['lists'].update({n: bool(v) for n, v in (saved.get('lists') or {}).items() if n in cfg['lists']})
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
        raise ValueError(tr('not an address, network or ASN: {value}', value=s)) from None


def _ports(v):
    out = []
    for p in v if isinstance(v, list) else str(v).replace(',', ' ').split():
        try:
            p = int(p)
        except (TypeError, ValueError):
            raise ValueError(tr('not a port: {port}', port=p)) from None
        if not 1 <= p <= 65535:
            raise ValueError(tr('not a port: {port}', port=p))
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
                    raise ValueError(tr('{kind}: the thresholds must be numbers', kind=tr(NAMES[k]))) from None
                if not lo <= n <= hi:
                    raise ValueError(tr('{kind}: a threshold must be {lo}–{hi}', kind=tr(NAMES[k]), lo=f'{lo:,}', hi=f'{hi:,}'))
                d[x] = n
    ign = body.get('ignore', [])
    ign = ign if isinstance(ign, list) else str(ign).replace(',', ' ').split()
    cfg['ignore'] = sorted({_ignore_item(s) for s in ign if str(s).strip()})
    if len(cfg['ignore']) > 5000:
        raise ValueError(tr('at most 5000 entries to ignore'))
    if 'sensitive' in body:
        cfg['sensitive'] = _ports(body['sensitive'])
    if 'public' in body:
        cfg['public'] = _ports(body['public'])
    roles = body.get('roles') or {}
    if not isinstance(roles, dict):
        raise ValueError('roles')
    for ep, role in roles.items():
        if role not in ('public', 'sensitive', 'normal') or not _endpoint(ep):
            raise ValueError(tr('bad service role: {service}', service=ep))
    cfg['roles'] = {ep: r for ep, r in roles.items()}
    lists = body.get('lists') or {}
    cfg['lists'].update({n: bool(v) for n, v in (lists.items() if isinstance(lists, dict) else []) if n in cfg['lists']})
    own = body.get('own_list', [])
    own = own if isinstance(own, list) else str(own).replace(',', ' ').split()
    out = set()
    for x in (str(x).strip() for x in own):
        if not x:
            continue
        try:
            out.add(str(ipaddress.ip_network(x, strict=False)) if '/' in x else str(ipaddress.ip_address(x)))
        except ValueError:
            raise ValueError(tr('own list: not an address or network: {value}', value=x)) from None
    if len(out) > 20000:
        raise ValueError(tr('own list: at most 20,000 entries'))
    cfg['own_list'] = sorted(out)
    cfg['exclude'] = exclusions(body.get('exclude', []))
    return cfg


# (1.8.3) Exclusions: events of one connection in one direction are not shown nor notified — e.g. a nightly backup
# from a host of ours to a server:port (upload), or a monitoring system that calls our service (download). A rule:
# source (who opened it) and / or target address or network, the target port (0 = any), the direction.
# The direction of an event: upload when it is about what we send or call out, download when about what arrives.
UPLOAD_KINDS = ('sustained_upload', 'inside_scan', 'lateral_scan', 'malware_contact', 'listed_contact', 'new_country', 'burst')
DIRECTIONS = ('up', 'down', 'any')


def _net(v):
    v = str(v or '').strip()
    if not v:
        return ''
    try:
        return str(ipaddress.ip_network(v, strict=False)) if '/' in v else str(ipaddress.ip_address(v))
    except ValueError:
        raise ValueError(tr('exclusion: not an address or network: {value}', value=v)) from None


def exclusions(rules):
    """The exclusion rules from the UI, checked."""
    out = []
    for r in rules if isinstance(rules, list) else []:
        if not isinstance(r, dict):
            continue
        try:
            port = int(r.get('port') or 0)
        except (TypeError, ValueError):
            raise ValueError(tr('not a port: {port}', port=r.get('port'))) from None
        if not 0 <= port <= 65535:
            raise ValueError(tr('not a port: {port}', port=port))
        d = r.get('dir') or 'any'
        if d not in DIRECTIONS:
            raise ValueError('dir')
        x = {'src': _net(r.get('src')), 'dst': _net(r.get('dst')), 'port': port, 'dir': d}
        if not x['src'] and not x['dst']:
            raise ValueError(tr('exclusion: give a source or a target address'))
        if x not in out:
            out.append(x)
    if len(out) > 1000:
        raise ValueError(tr('at most 1000 exclusions'))
    return out


class Exclude:
    """Is an event excluded by a rule? `kind`, `src` (who opened it), `dst`, `port` as stored."""

    def __init__(self, rules):
        self.rules = [(ipaddress.ip_network(r['src'], strict=False) if r['src'] else None,
                       ipaddress.ip_network(r['dst'], strict=False) if r['dst'] else None, int(r['port']), r['dir']) for r in rules or ()]

    @staticmethod
    def _in(ip, net):
        if net is None:
            return True
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return a.version == net.version and a in net

    def __call__(self, kind, src, dst, port):
        if not self.rules:
            return False
        d = 'up' if kind in UPLOAD_KINDS else 'down'
        return any((rd == 'any' or rd == d) and (not rp or rp == int(port or 0)) and self._in(src, rs) and self._in(dst, rt)
                   for rs, rt, rp, rd in self.rules)


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


def add_exclusion(rule):
    cfg = load_config()
    cfg['exclude'] = exclusions(list(cfg.get('exclude') or []) + [rule])
    save_config(cfg)
    return cfg


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
         countIf(dir = 'down') AS nd, countIf(dir = 'up') AS nu, sumIf(packets, dir = 'up') AS pu, sumIf(packets, dir = 'down') AS pd, sumIf(bytes, dir = 'down') AS bd, sumIf(bytes, dir = 'up') AS bu
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


def rules(cfg, base, t0, t1, rep=None):
    """Hits of every enabled rule in the window [t0, t1): dicts kind, key, exporter, src, dst, port, proto, value, info.
    rep: a reputation.Index (None: no reputation checks)."""
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
    if K['link_load']['on']:
        hits += link_load(K['link_load'], t1)
    if rep is not None and rep.size:
        for h in hits:                # an attacker on a list says so in its event
            if h['kind'] in ('port_scan', 'brute_force', 'heavy_client'):
                names = rep.lookup(h['src'])
                if names:
                    h['info']['lists'] = sorted(names)
        if any(K[k]['on'] for k in ('malware_contact', 'listed_contact', 'listed_inbound')):
            hits += reputation_hits(K, rep, X, p, t0)
    return hits


def reputation_hits(K, rep, X, p, t0):
    """The window's outside addresses that are on a list: one bisection each in Python (no per-record cost). Then,
    for those few, the sessions: opened by us -> a contact event per listed address (malware infrastructure:
    critical); opened by them -> the day's summary of listed addresses calling us."""
    ips = ch("SELECT DISTINCT ext_ip FROM flows WHERE ts >= {t0:DateTime} AND ts < {t1:DateTime} AND dir IN ('up', 'down')",
             p, fmt='TSV', settings=HEAVY).split()
    found = {ip: names for ip in ips for names in (rep.lookup(ip),) if names}
    if not found:
        return []
    hits, day = [], time.strftime('%Y-%m-%d', time.gmtime(t0))
    pr = dict(p, rep_ips=sorted(found))
    # who opened it: us — or both ends are services and ours is not one that listens (NTP to NTP, IKE to IKE);
    # them — or both ends look like services but ours listens (scanners send from low ports too)
    for r in ch(X + f"""SELECT ext_ip, multiIf(init = 'in' OR (init = 'both' AND NOT listening), 'we',
                                    init = 'out' OR (init = 'both' AND listening), 'they', 'unknown') AS who, any(exporter) AS ex, count() AS n, countIf(failed) AS nf, sum(bu) AS sent, sum(bd) AS got,
            groupUniqArray(20)(int_ip) AS hosts, arraySlice(arraySort(groupUniqArray(ext_port)), 1, 20) AS eports,
            arraySlice(arraySort(groupUniqArray(int_port)), 1, 20) AS iports, any(cc) AS c, any(org) AS o, any(a_asn) AS asn
            FROM X WHERE ext_ip IN {{rep_ips:Array(String)}} AND NOT {_ignored('ext_ip', 'a_asn')}
            GROUP BY ext_ip, who""", pr, fmt='JSON', timeout=120, settings=HEAVY):
        names = sorted(found[r['ext_ip']])
        if r['who'] == 'we':                     # a host of ours talks to it
            kind = 'malware_contact' if reputation.category(names) == 'malware' else 'listed_contact'
            if K[kind]['on']:
                hits.append(_hit(kind, r['ext_ip'], r, src=r['hosts'][0] if r['hosts'] else '', dst=r['ext_ip'], value=int(r['n']),
                                 info={'lists': names, 'hosts': r['hosts'], 'ports': r['eports'], 'sessions': int(r['n']),
                                       'failed': int(r['nf']), 'sent': int(r['sent']), 'got': int(r['got'])}))
        elif r['who'] == 'they' and K['listed_inbound']['on']:
            hits.append(_hit('listed_inbound', f'@{day}', {'ex': r['ex']}, value=1,
                             info={'srcmap': {r['ext_ip']: names}, 'ports': r['iports'], 'sessions': int(r['n'])}))
    return hits


def lateral(k, p):
    """Inside -> inside: one host calls many hosts on one port, or many ports of one host, with tiny unanswered probes.
    The records are taken source -> destination: a call is answered when the reverse record exists (so a server's
    answers to its clients' random ports never count); the source port must look like a client's."""
    known, quiet = _arr(KNOWN), _arr((53, 67, 68, 123, 137, 138, 1900, 5353, 5355))
    # since 1.7.0 inside records are stored client -> server ('internal_back' = the server's answer): turned back to
    # source -> destination here, so a probe is judged by its own packets whichever side the ports point to
    sw = "dir = 'internal_back'"
    recs = (f"(SELECT exporter, proto, packets, if({sw}, ext_ip, int_ip) AS int_ip, if({sw}, ext_port, int_port) AS int_port, "
            f"if({sw}, int_ip, ext_ip) AS ext_ip, if({sw}, int_port, ext_port) AS ext_port FROM flows "
            "WHERE ts >= {t0:DateTime} AND ts < {t1:DateTime} AND dir IN ('internal', 'internal_back') AND proto IN (6, 17))")
    # a probe is tiny: a few packets that got no answer (a device that exports one direction only shows no answers
    # at all, but real conversations are bigger than that)
    base = f"""SELECT any(exporter) AS ex, int_ip AS a, ext_ip AS b, ext_port AS bp, count() AS recs,
            (proto, ext_ip, ext_port, int_ip, int_port) IN (SELECT proto, int_ip, int_port, ext_ip, ext_port FROM {recs})
            OR sum(packets) > 3 AS answered
        FROM {recs} WHERE NOT (int_port < 1024 OR has({known}, int_port)) AND NOT has({quiet}, ext_port) AND NOT {_ignored('int_ip')}
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


def capacities():
    """exporter -> ifIndex -> (name, Mbit/s in, Mbit/s out) of the interfaces whose capacity is known: the operator's
    own figures (Settings → Devices → Interfaces), else the speed SNMP reads (ifHighSpeed)."""
    import snmp
    from common import load_exporters
    exp, sset, sdata = load_exporters(), snmp.load_settings(), snmp.load_data()
    out = {}
    for ip, c in exp.items():
        sn = (sdata.get(ip) or {}).get('ifs') or {} if sset.get(ip, {}).get('enabled') else {}
        names, caps = c.get('if_names') or {}, {}
        for k, i in sn.items():
            if str(k).isdigit() and i.get('speed'):
                caps[int(k)] = (names.get(str(k)) or i.get('name') or f'if {k}', float(i['speed']), float(i['speed']))
        for k, v in (c.get('if_caps') or {}).items():
            if str(k).isdigit():
                caps[int(k)] = (names.get(str(k)) or (sn.get(str(k)) or {}).get('name') or f'if {k}', float(v[0]), float(v[1]))
        if caps:
            out[ip] = (c.get('name') or ip, caps)
    return out


def link_load(k, t1):
    """(1.12.0) Interfaces that stayed above k['pct'] % of their capacity, in or out, in every 5 minutes of the last
    k['span'] minutes (the 5-minute interface totals: a short burst within them does not count)."""
    caps = capacities()
    if not caps:
        return []
    n, end = k['span'] // 5, t1 // 300 * 300
    rows = ch("""SELECT exporter, toUnixTimestamp(ts) AS t, in_if, out_if, sum(bytes) AS b FROM agg_iface
        WHERE ts >= toDateTime({a:UInt32}) AND ts < toDateTime({b:UInt32}) AND exporter IN {ex:Array(String)}
        GROUP BY exporter, t, in_if, out_if""", {'a': end - n * 300, 'b': end, 'ex': list(caps)}, fmt='JSON', timeout=60)
    acc = {}
    for r in rows:
        for idx, d in ((int(r['in_if']), 'in'), (int(r['out_if']), 'out')):
            if idx in caps[r['exporter']][1]:
                b = acc.setdefault((r['exporter'], idx, d), {})
                b[int(r['t'])] = b.get(int(r['t']), 0) + int(r['b'])
    hits = []
    for (ex, idx, d), b in acc.items():
        name, cin, cout = caps[ex][1][idx]
        cap = (cin if d == 'in' else cout) * 1e6
        pcts = [b.get(end - (i + 1) * 300, 0) * 8 / 300 / cap * 100 for i in range(n)]
        if cap and min(pcts) >= k['pct']:
            peak = max(pcts)
            hits.append({'kind': 'link_load', 'key': f'{ex}/{idx}/{d}', 'exporter': ex, 'src': '', 'dst': '', 'port': idx, 'proto': 0,
                         'value': round(peak, 1), 'info': {'device': caps[ex][0], 'if': idx, 'name': name, 'dir': d, 'pct': round(peak, 1),
                                                           'min_pct': round(min(pcts), 1), 'mbps': round(peak * cap / 100 / 1e6, 1),
                                                           'cap': cap / 1e6, 'minutes': k['span'], 'over': k['pct']}})
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
        if k in ('ports', 'targets', 'countries', 'hosts', 'lists'):
            out[k] = list(dict.fromkeys(list(old.get(k, [])) + list(v)))[:50]
        elif k == 'srcmap':
            m = dict(old.get(k, {}))
            for ip, names in v.items():
                if ip in m or len(m) < KEEP_SOURCES:
                    m[ip] = sorted(set(m.get(ip, [])) | set(names))
            out[k] = m
        elif k in ('failed', 'sent', 'got'):
            out[k] = int(old.get(k, 0)) + int(v)
        elif k == 'sources':
            out[k] = list(dict.fromkeys(list(old.get(k, [])) + list(v)))[:KEEP_SOURCES]
        elif k == 'sessions':
            out[k] = int(old.get(k, 0)) + int(v)
        elif k in ('per_minute', 'bps', 'minutes', 'srcs') and isinstance(v, (int, float)):
            out[k] = max(v, old.get(k, 0))
        else:
            out[k] = v
    return out


def store(hits, t0, t1, new=None):
    """Merge the window's hits into open events (same kind and key, activity within the gap) or start new ones.
    new: a list that gets the rows of the events that start here (for the notifications)."""
    if not hits:
        return 0
    by = {}
    for h in hits:            # one rule may hit the same key twice in a window (e.g. ports and hosts)
        k = (h['kind'], h['key'])
        if k in by:
            o = by[k]
            sessions = max(int(o['info'].get('sessions', 0)), int(h['info'].get('sessions', 0)))
            o['info'], o['value'] = merge_info(o['info'], h['info']), max(o['value'], h['value'])
            if h['kind'] != 'listed_inbound':     # the same activity seen by two variants of a rule; the summary adds up
                o['info']['sessions'] = sessions
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
        if 'srcmap' in info:
            value = len(info['srcmap'])
        rows.append({'kind': h['kind'], 'key': h['key'], 'first_seen': first, 'last_seen': max(t1, _ts(o['last_seen']) if o else 0),
                     'hits': n, 'exporter': h['exporter'], 'src': h['src'], 'dst': h['dst'], 'port': h['port'], 'proto': h['proto'],
                     'value': value, 'info': json.dumps(info, ensure_ascii=False), 'ver': ver})
    ch('INSERT INTO events FORMAT JSONEachRow', data='\n'.join(json.dumps(r) for r in rows).encode())
    if new is not None:
        new += [dict(r, info=json.loads(r['info'])) for r in rows if r['hits'] == 1 and r['first_seen'] == t0]
    return len(rows)


def _ts(v):
    if isinstance(v, (int, float)):
        return int(v)
    return calendar.timegm(time.strptime(v, '%Y-%m-%d %H:%M:%S'))      # ClickHouse answers in UTC


class Detector:
    """The collector's background thread: every closed window once, a day back at the first start."""

    def __init__(self, log=print):
        self.log, self.base, self.learned = log, {'svc': {}, 'wan': {}, 'refl': {}}, 0
        self.rep = reputation.Index()
        self.notifier = notify.Notifier(log)

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
        lists = [n for n, on in cfg['lists'].items() if on]
        done = self.state().get('done') or (now - BACKFILL) // WINDOW * WINDOW
        done = max(done, (now - BACKFILL) // WINDOW * WINDOW)     # off for days: only the last one
        found = 0
        while done + WINDOW <= now - LAG:
            if self.rep.build(lists, cfg['own_list']):      # a list downloaded meanwhile (only file times are compared)
                self.log(f'reputation: {self.rep.size:,} networks from {len(lists)} list{"s" if len(lists) != 1 else ""}'
                         + (f" + {len(cfg['own_list']):,} own" if cfg['own_list'] else ''))
            new = []
            found += store(rules(cfg, self.base, done, done + WINDOW, self.rep), done, done + WINDOW, new)
            exc = Exclude(cfg.get('exclude'))
            on = [r for r in new if cfg['kinds'].get(r['kind'], {}).get('on') and (r['src'], r['info'].get('asn')) not in Ignore(cfg['ignore'])
                  and not exc(r['kind'], r['src'], r['dst'], r['port'])]
            self.notifier.push([{'kind': r['kind'], 'row': r} for r in on], cfg['kinds'], done + WINDOW)
            done += WINDOW
            self.save_state(done)
        return found

    def update_lists(self):
        try:
            cfg = load_config()
            if any(cfg['kinds'][k]['on'] for k in ('malware_contact', 'listed_contact', 'listed_inbound')):
                done = reputation.update([n for n, on in cfg['lists'].items() if on], self.log)
                if done:
                    self.log(f"reputation lists updated: {', '.join(done)}")
        except Exception as ex:
            self.log(f'WARN reputation lists: {str(ex)[:300]}')

    def updates(self):
        """Downloads of the reputation lists, in a thread of their own: a slow site never holds up the windows."""
        while True:
            time.sleep(600)
            self.update_lists()

    def run(self):
        if not reputation.meta():        # the first start: the lists first, so the day looked back at is checked too
            self.update_lists()
        threading.Thread(target=self.updates, name='reputation', daemon=True).start()
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
    ign, exc = Ignore(cfg['ignore']), Exclude(cfg.get('exclude'))
    out = []
    for r in ch("""SELECT kind, key, first_seen, last_seen, hits, exporter, src, dst, port, proto, value, info FROM events FINAL
            WHERE last_seen >= {since:DateTime} AND first_seen <= {until:DateTime} ORDER BY last_seen DESC LIMIT 5000""",
                {'since': int(since), 'until': int(until or time.time())}, fmt='JSON'):
        k = cfg['kinds'].get(r['kind'])
        if not k or not k['on']:
            continue
        info = json.loads(r['info'] or '{}')
        if (r['src'], info.get('asn')) in ign or exc(r['kind'], r['src'], r['dst'], r['port']):
            continue
        r['info'] = info
        title, text = describe(r)
        out.append({'sev': k['sev'], 'kind': r['kind'], 'title': title, 'text': text, 'when': r['last_seen'],
                    'first': r['first_seen'], 'last': r['last_seen'], 'hits': int(r['hits']), 'src': r['src'], 'dst': r['dst'],
                    'ip': r['src'] or r['dst'], 'port': int(r['port']), 'country': info.get('country', ''), 'org': info.get('org', ''),
                    'asn': info.get('asn', 0), 'exporter': r['exporter'], 'stored': True,
                    'addrs': list(info.get('targets', [])) + list(info.get('sources', [])) + list(info.get('hosts', [])) + list(info.get('srcmap', {})),
                    'ports': [int(x) for x in info.get('ports', [])],
                    'fk': _filter_of(r)[0], 'fv': _filter_of(r)[1]})
    return out


def _filter_of(r):
    """The filter the event's Filter button sets on the other pages: an outside source is an outside address there
    (`dst`), an inside one or our attacked service an inside host (`ip`), a device-wide flood the device."""
    if r['kind'] in ('port_scan', 'brute_force', 'heavy_client'):
        return 'dst', r['src']
    if r['kind'] in ('malware_contact', 'listed_contact'):       # the listed address: every host of ours that talked to it
        return 'dst', r['dst']
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


def _lists(names):
    return ', '.join(reputation.TITLES.get(n, n) for n in names)


def describe(r):
    """Title and text of a stored event in the language of the request."""
    title, text = _describe(r)
    names = r['info'].get('lists')
    if names and r['kind'] in ('port_scan', 'brute_force', 'heavy_client'):
        text += tr(' On reputation lists: {lists}.', lists=_lists(names))
    return title, text


def _bytes(n):
    n = float(n)
    for u in ('B', 'KB', 'MB', 'GB'):
        if n < 1000 or u == 'GB':
            return f'{n:,.0f} {u}' if u == 'B' else f'{n:,.1f} {u}'
        n /= 1000
    return ''


def _describe(r):
    i, kind, port = r['info'], r['kind'], int(r['port'])
    svc = f"{r['dst']}:{port}" if r['dst'] else str(port)
    if kind == 'port_scan':
        how = i.get('how')
        if how == 'hosts':
            return (tr('Network sweep'),
                    tr('{who} called port {ports} on {n}+ of our addresses.', who=_who(r), ports=_plist(i.get('ports', [])), n=len(i.get('targets', []))))
        n = max(int(r['value']), len(i.get('ports', [])))
        return (tr('Port scan'),
                tr('{who} tried {n} ports of ours: {ports}.', who=_who(r), n=f'{n:,}', ports=_plist(i.get('ports', []))))
    many = dict(who=_who(r), sessions=f"{i.get('sessions', 0):,}", svc=svc, peak=f"{int(r['value']):,}") if kind in ('brute_force', 'heavy_client') else {}
    if kind == 'brute_force':
        return (tr('Password guessing'),
                tr('{who} opened {sessions} sessions to {svc}, up to {peak} in 10 min.', **many) if int(r['hits']) > 1
                else tr('{who} opened {sessions} sessions to {svc} in 10 min.', **many))
    if kind == 'probes':
        n = len(i.get('sources', []))
        cc = ', '.join(i.get('countries', [])[:5])
        kw = dict(n=f'{n:,}', sessions=f"{i.get('sessions', 0):,}", cc=cc)
        return (tr('Probes of {svc}', svc=svc),
                trn(n, '{n} outside address called this management service ({sessions} sessions); most from {cc}.',
                    '{n} outside addresses called this management service ({sessions} sessions); most from {cc}.', **kw) if cc else
                trn(n, '{n} outside address called this management service ({sessions} sessions).',
                    '{n} outside addresses called this management service ({sessions} sessions).', **kw))
    if kind == 'heavy_client':
        return (tr('Aggressive client'),
                tr('{who}: {sessions} sessions to {svc}, up to {peak} in 10 min.', **many) if int(r['hits']) > 1
                else tr('{who}: {sessions} sessions to {svc} in 10 min.', **many))
    if kind == 'link_load':
        kw = dict(device=i.get('device', r.get('exporter', '')), name=i.get('name', ''), mbps=f"{i.get('mbps', 0):g}", cap=f"{i.get('cap', 0):g}",
                  pct=f"{i.get('pct', 0):g}", over=i.get('over', 85), minutes=i.get('minutes', 15))
        return (tr('Link near capacity: {name}', name=kw['name']),
                tr('{device} · {name}: incoming traffic up to {mbps} of {cap} Mbit/s ({pct}%), above {over}% for {minutes} min.', **kw)
                if i.get('dir') == 'in' else
                tr('{device} · {name}: outgoing traffic up to {mbps} of {cap} Mbit/s ({pct}%), above {over}% for {minutes} min.', **kw))
    if kind == 'ddos':
        how = i.get('how')
        kw = dict(srcs=f"{i.get('srcs', 0):,}", minutes=i.get('minutes', 0), mbps=_mbps(i.get('bps', 0)), base_mbps=_mbps(i.get('baseline', 0)))
        if how == 'sessions':
            return (tr('Flood of {svc}', svc=svc),
                    tr('Up to {per_minute} new sessions a minute from {srcs} addresses (usual peak {base}), {minutes} min.',
                       per_minute=f"{i.get('per_minute', 0):,}", base=f"{round(i.get('baseline', 0)):,}", **kw))
        if how == 'reflection':
            return (tr('Reflection attack'),
                    tr('Up to {mbps} Mbit/s of UDP from ports {ports} (usual peak {base_mbps} Mbit/s), from {srcs} addresses, {minutes} min.',
                       ports=_plist(i.get('ports', [])), **kw))
        return (tr('Traffic flood'),
                tr('Inbound up to {mbps} Mbit/s on {device} (usual peak {base_mbps} Mbit/s), {minutes} min, {srcs} addresses.', device=r['exporter'], **kw))
    if kind in ('malware_contact', 'listed_contact'):
        hosts = i.get('hosts', [])
        who = ', '.join(hosts[:5]) + (f' +{len(hosts) - 5}' if len(hosts) > 5 else '')
        extra = ', '.join(x for x in (i.get('country', ''), i.get('org', '')) if x)
        dst = f"{r['dst']} ({extra})" if extra else r['dst']
        cat = reputation.category(i.get('lists', []))
        what = {'malware': tr('a botnet controller or malware host'),
                'drop': tr('a netblock run by criminals (do not route)'),
                'anon': tr('a Tor exit relay')}.get(cat, tr('a host seen attacking others'))
        ok = i.get('sessions', 0) - i.get('failed', 0)
        n = i.get('sessions', 0)
        text = trn(n, '{who} opened {n} session to {dst}, ports {ports} — {what} ({lists}).', '{who} opened {n} sessions to {dst}, ports {ports} — {what} ({lists}).',
                   n=f'{n:,}', who=who, dst=dst, ports=_plist(i.get('ports', [])), what=what, lists=_lists(i.get('lists', [])))
        text += ' ' + (tr('Sent {sent}, received {got}.', sent=_bytes(i.get('sent', 0)), got=_bytes(i.get('got', 0))) if ok > 0 else tr('No answer came back.'))
        if kind == 'malware_contact':
            text += ' ' + tr('Check the device.')
        return (tr('Contact with malware infrastructure') if kind == 'malware_contact' else tr('Contact with a listed address'), text)
    if kind == 'listed_inbound':
        m = i.get('srcmap', {})
        per = {}
        for names in m.values():
            for n in names:
                per[n] = per.get(n, 0) + 1
        top = ', '.join(f'{reputation.TITLES.get(n, n)} {c:,}' for n, c in sorted(per.items(), key=lambda x: -x[1]))
        return (tr('Listed addresses calling us'),
                trn(len(m), '{n} address from reputation lists called our services ({sessions} sessions; ports {ports}): {top}.',
                    '{n} addresses from reputation lists called our services ({sessions} sessions; ports {ports}): {top}.',
                    n=f'{len(m):,}', sessions=f"{i.get('sessions', 0):,}", ports=_plist(i.get('ports', []), 8), top=top))
    if kind in ('inside_scan', 'lateral_scan'):
        title = tr('Inside host scans the internet') if kind == 'inside_scan' else tr('Scan inside the network')
        if i.get('how') == 'ports':
            n = max(int(r['value']), len(i.get('ports', [])))
            return (title, tr('{src} tried {n} ports of {dst} without answers: {ports}. Check the device.',
                              src=r['src'], n=f'{n:,}', dst=r['dst'], ports=_plist(i.get('ports', []))))
        return (title, tr('{src} called port {port} on {n} addresses, mostly without an answer. Check the device.',
                          src=r['src'], port=port, n=f"{int(r['value']):,}"))
    return kind, ''
