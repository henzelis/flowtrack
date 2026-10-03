#!/usr/bin/env python3
"""FlowTrack API + web UI server (stdlib HTTP server, ClickHouse over HTTP).

All user input reaches ClickHouse only as bound query parameters ({name:Type}),
never by string interpolation; dimension names come from fixed whitelists.
"""
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auth import Auth, AuthError  # noqa: E402
from common import CHError, ch, exporters_mtime, is_private, load_exporters, load_json, load_ui_exporter, save_ui_exporter  # noqa: E402

BIND = os.environ.get('FT_WEB_BIND', '0.0.0.0')
PORT = int(os.environ.get('FT_WEB_PORT', '3030'))
TLS_CERT = os.environ.get('FT_TLS_CERT', '')
TLS_KEY = os.environ.get('FT_TLS_KEY', '')
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web')
RANGES = {'1h': 3600, '6h': 6 * 3600, '24h': 86400, '7d': 7 * 86400, '30d': 30 * 86400}
STEP = {3600: 60, 6 * 3600: 300, 86400: 300, 7 * 86400: 3600, 30 * 86400: 4 * 3600}

# filter key -> (column, ClickHouse type)
FILTERS = {
    'ip': ('int_ip', 'String'), 'dst': ('ext_ip', 'String'), 'service': ('service', 'String'), 'l7': ('l7', 'String'),
    'country': ('country', 'String'), 'city': ('city', 'String'), 'port': ('ext_port', 'UInt16'), 'device': ('exporter', 'String'),
    'dir': ('dir', 'String'), 'proto': ('proto', 'UInt8'),
}
DIMS = {'int_ip': 'int_ip', 'ext_ip': 'ext_ip', 'service': 'service', 'l7': 'l7', 'country': 'country', 'city': 'city',
        'asn': 'asn', 'ext_port': 'ext_port', 'exporter': 'exporter', 'dir': 'dir', 'proto': 'proto'}


# ------------------------------------------------------------------ names

class Names:
    """Inside host names: hosts.json (manual) > exporter self IPs > reverse DNS (cached, async)."""

    def __init__(self):
        self.pool = ThreadPoolExecutor(max_workers=4)
        self.cache, self.pending = {}, set()
        self.lock = threading.Lock()
        self.reload()

    def reload(self):
        self.manual = load_json('hosts.json', {})
        self.exporters = load_exporters()
        self.mtime = exporters_mtime()
        self.self_ips = {}
        for ip, e in self.exporters.items():
            for pub in e.get('public_ips', []) + [ip]:
                self.self_ips[pub] = f"{e.get('name', ip)} (self)"

    def _resolve(self, ip):
        try:
            name = socket.gethostbyaddr(ip)[0]
        except OSError:
            name = ''
        with self.lock:
            self.cache[ip] = (name, time.time())
            self.pending.discard(ip)

    def get(self, ip):
        if ip in self.manual:
            return self.manual[ip]
        if ip in self.self_ips:
            return self.self_ips[ip]
        with self.lock:
            hit = self.cache.get(ip)
            if (hit is None or time.time() - hit[1] > 3600) and ip not in self.pending and is_private(ip):
                self.pending.add(ip)
                self.pool.submit(self._resolve, ip)
        return hit[0] if hit else ''


NAMES = Names()


# ------------------------------------------------------------------ query building

class BadRequest(Exception):
    pass


def scope(q):
    """-> (where_sql, params, range_seconds, step). Time window is anchored to now()."""
    rng = RANGES.get(q.get('range', ['24h'])[0], 86400)
    where, params = ['ts >= now() - toIntervalSecond({rng:UInt32})'], {'rng': rng}
    try:
        flt = json.loads(q.get('f', ['[]'])[0])
    except ValueError:
        raise BadRequest('bad filter JSON')
    for i, f in enumerate(flt if isinstance(flt, list) else []):
        k, v, neg = f.get('k'), str(f.get('v', '')), bool(f.get('neg'))
        if k == 'asn':
            if v.upper().startswith('AS'):
                v = v[2:]
            if v.isdigit():
                cond = f'asn = {{f{i}:UInt32}}'
            else:
                cond = f'positionCaseInsensitive(as_org, {{f{i}:String}}) > 0'
        elif k in FILTERS:
            col, typ = FILTERS[k]
            if typ != 'String' and not v.isdigit():
                raise BadRequest(f'bad value for {k}')
            cond = f'{col} = {{f{i}:{typ}}}'
        else:
            continue
        where.append(f'NOT ({cond})' if neg else cond)
        params[f'f{i}'] = v
    return ' AND '.join(where), params, rng, STEP[rng]


def q1(q, key, default, cast=str):
    try:
        return cast(q.get(key, [default])[0])
    except (TypeError, ValueError):
        raise BadRequest(f'bad {key}')


def host_obj(ip):
    return {'ip': ip, 'name': NAMES.get(ip), 'private': is_private(ip)}


def exporters_cfg():
    if exporters_mtime() != NAMES.mtime:
        NAMES.reload()
    return NAMES.exporters


# ------------------------------------------------------------------ endpoints

def api_meta(q):
    exp = exporters_cfg()
    seen = ch("SELECT exporter, max(ts) AS last FROM exporter_stats GROUP BY exporter", fmt='JSON')
    devices = []
    for r in seen:
        c = exp.get(r['exporter'], {})
        devices.append({'ip': r['exporter'], 'name': c.get('name', r['exporter']), 'vendor': c.get('vendor', ''), 'model': c.get('model', ''),
                        'if_names': c.get('if_names', {}), 'local_if': c.get('local_if'),
                        'city': c.get('city', ''), 'country': c.get('country', ''), 'lat': c.get('lat'), 'lon': c.get('lon'), 'last': r['last']})
    oldest = ch("SELECT toUnixTimestamp(min(ts)) AS t FROM flows", fmt='JSON')
    return {'devices': devices, 'now': int(time.time()), 'oldest': int(oldest[0]['t']) if oldest else 0,
            'ranges': list(RANGES), 'geo_attribution': 'IP Geolocation by DB-IP (db-ip.com), CC BY 4.0'}


def api_summary(q):
    where, p, rng, step = scope(q)
    # current and previous window in one pass
    wprev = where.replace('ts >= now() - toIntervalSecond({rng:UInt32})', 'ts >= now() - toIntervalSecond({rng2:UInt32})')
    p['rng2'] = rng * 2
    r = ch(f"""SELECT
        sumIf(bytes, cur) AS s_bytes, sumIf(bytes, cur AND dir = 'up') AS s_up, sumIf(bytes, cur AND dir = 'down') AS s_down,
        countIf(cur) AS s_flows, sumIf(packets, cur) AS s_packets,
        uniqExactIf(int_ip, cur) + uniqExactIf(ext_ip, cur) AS s_ips, uniqExactIf(int_ip, cur) AS s_hosts, uniqExactIf(int_ip, NOT cur) AS s_p_hosts,
        sumIf(bytes, NOT cur) AS s_p_bytes, countIf(NOT cur) AS s_p_flows, uniqExactIf(int_ip, NOT cur) + uniqExactIf(ext_ip, NOT cur) AS s_p_ips,
        toUnixTimestamp(min(ts)) AS s_oldest
      FROM (SELECT ts, dir, bytes, packets, int_ip, ext_ip, ts >= now() - toIntervalSecond({{rng:UInt32}}) AS cur FROM flows WHERE {wprev})""", p, fmt='JSON')[0]
    r = {k[2:]: v for k, v in r.items()}
    top = ch(f"SELECT service AS k, sum(bytes) AS b FROM flows WHERE {where} GROUP BY k ORDER BY b DESC LIMIT 1", p, fmt='JSON')
    r = {k: int(v) for k, v in r.items()}
    # history starts when the collector started receiving (late-exported flows can carry older timestamps)
    started = ch("SELECT toUnixTimestamp(min(ts)) - 60 AS t FROM exporter_stats", fmt='JSON')
    if started and int(started[0]['t']) > 0:
        r['oldest'] = max(r['oldest'], int(started[0]['t']))
    r['has_prev'] = r['oldest'] <= time.time() - 2 * rng + step
    r['range'] = rng
    r['top_service'] = top[0]['k'] if top else None
    r['top_service_bytes'] = int(top[0]['b']) if top else 0
    return r


def api_series(q):
    where, p, rng, step = scope(q)
    by = q1(q, 'by', '')
    p['step'] = step
    bucket = 'toUnixTimestamp(toStartOfInterval(ts, toIntervalSecond({step:UInt32})))'
    if by in DIMS:
        top = q1(q, 'top', '7', int)
        p['top'] = max(1, min(top, 20))
        col = DIMS[by]
        rows = ch(f"""WITH (SELECT groupArray(k) FROM (SELECT toString({col}) AS k FROM flows WHERE {where} GROUP BY k ORDER BY sum(bytes) DESC LIMIT {{top:UInt8}})) AS tops
            SELECT {bucket} AS t, if(has(tops, toString({col})), toString({col}), '__other') AS k, sum(bytes) AS b
            FROM flows WHERE {where} GROUP BY t, k ORDER BY t""", p, fmt='JSON')
        return {'step': step, 'range': rng, 'rows': [[int(r['t']), r['k'], int(r['b'])] for r in rows]}
    rows = ch(f"""SELECT {bucket} AS t, sumIf(bytes, dir = 'down') AS dn, sumIf(bytes, dir = 'up') AS up,
            sumIf(bytes, dir NOT IN ('up', 'down')) AS other, count() AS fl
        FROM flows WHERE {where} GROUP BY t ORDER BY t""", p, fmt='JSON')
    return {'step': step, 'range': rng, 'rows': [[int(r['t']), int(r['dn']), int(r['up']), int(r['other']), int(r['fl'])] for r in rows]}


def api_top(q):
    where, p, rng, step = scope(q)
    dim = q1(q, 'dim', 'int_ip')
    p['lim'] = max(1, min(q1(q, 'limit', '10', int), 500))
    if dim == 'conv':
        rows = ch(f"""SELECT int_ip, ext_ip, any(service) AS service, any(country) AS country, any(city) AS city,
                sumIf(bytes, dir = 'up') AS up, sumIf(bytes, dir != 'up') AS dn, count() AS fl, sum(packets) AS pk
            FROM flows WHERE {where} GROUP BY int_ip, ext_ip ORDER BY up + dn DESC LIMIT {{lim:UInt16}}""", p, fmt='JSON')
        for r in rows:
            r['name'] = NAMES.get(r['int_ip'])
    elif dim == 'host_svc':     # each inside host with its main service and L7 protocol
        rows = ch(f"""SELECT int_ip AS k, argMax(service, b) AS service, argMax(l7, b) AS l7, argMax(proto, b) AS proto,
                sum(u) AS up, sum(d) AS dn, sum(f) AS fl, 0 AS pk
            FROM (SELECT int_ip, service, l7, proto, sum(bytes) AS b, sumIf(bytes, dir = 'up') AS u, sumIf(bytes, dir != 'up') AS d, count() AS f
                  FROM flows WHERE {where} GROUP BY int_ip, service, l7, proto)
            GROUP BY k ORDER BY up + dn DESC LIMIT {{lim:UInt16}}""", p, fmt='JSON')
        for r in rows:
            r['name'] = NAMES.get(r['k'])
            r['proto'] = int(r['proto'])
    elif dim in DIMS:
        col = DIMS[dim]
        extra = ''
        if dim == 'ext_ip':
            extra = ', any(service) AS service, any(country) AS country, any(city) AS city, any(asn) AS asn, any(as_org) AS as_org'
        elif dim == 'asn':
            extra = ', any(as_org) AS as_org, any(country) AS country'
        elif dim == 'service':
            extra = ', uniqExact(int_ip) AS hosts, any(l7) AS l7'
        elif dim == 'city':
            extra = ', any(country) AS country, any(lat) AS la, any(lon) AS lo'
        elif dim == 'ext_port':
            extra = ', any(l7) AS l7, any(proto) AS proto_n, uniqExact(int_ip) AS hosts, uniqExact(ext_ip) AS peers, any(service) AS service'
        rows = ch(f"""SELECT toString({col}) AS k, sumIf(bytes, dir = 'up') AS up, sumIf(bytes, dir != 'up') AS dn,
                count() AS fl, sum(packets) AS pk {extra}
            FROM flows WHERE {where} GROUP BY k ORDER BY up + dn DESC LIMIT {{lim:UInt16}}""", p, fmt='JSON')
        if dim == 'int_ip':
            for r in rows:
                r['name'] = NAMES.get(r['k'])
    else:
        raise BadRequest('bad dim')
    tot = ch(f"SELECT sum(bytes) AS b FROM flows WHERE {where}", p, fmt='JSON')[0]['b']
    for r in rows:
        for k in ('up', 'dn', 'fl', 'pk', 'hosts', 'asn', 'peers', 'proto_n'):
            if k in r:
                r[k] = int(r[k])
    return {'total': int(tot), 'rows': rows}


def api_river(q):
    """Top-N inside x top-N outside endpoints; link values for the live window (last 15 min) or the whole range."""
    where, p, rng, step = scope(q)
    metric = {'bytes': 'bytes', 'packets': 'packets', 'flows': '1'}.get(q1(q, 'metric', 'bytes'), 'bytes')
    p['n'] = max(3, min(q1(q, 'top', '10', int), 20))
    live = q1(q, 'live', '1') == '1'
    win = max(60, min(q1(q, 'win', '120', int), 900))
    if live:    # nodes = what is active in the last 15 min; values = the last `win` seconds
        where = where + ' AND ts >= now() - INTERVAL 15 MINUTE'
    tops = ch(f"""SELECT
            (SELECT groupArray(k) FROM (SELECT int_ip AS k FROM flows WHERE {where} GROUP BY k ORDER BY sum({metric}) DESC LIMIT {{n:UInt8}})) AS l,
            (SELECT groupArray(k) FROM (SELECT ext_ip AS k FROM flows WHERE {where} GROUP BY k ORDER BY sum({metric}) DESC LIMIT {{n:UInt8}})) AS r,
            (SELECT uniqExact(int_ip) FROM flows WHERE {where}) AS nl, (SELECT uniqExact(ext_ip) FROM flows WHERE {where}) AS nr,
            (SELECT toUnixTimestamp(max(ts)) FROM flows WHERE {where}) AS last""", p, fmt='JSON')[0]
    left, right = tops['l'], tops['r']
    p['L'], p['R'] = left, right
    wwin = where
    if live:
        p['wend'] = int(tops['last'] or time.time())
        p['win'] = win
        wwin = where + ' AND ts > toDateTime({wend:UInt32}) - toIntervalSecond({win:UInt32}) AND ts <= toDateTime({wend:UInt32})'
    links = ch(f"""SELECT if(has({{L:Array(String)}}, int_ip), int_ip, '__other') AS l, if(has({{R:Array(String)}}, ext_ip), ext_ip, '__other') AS r,
            sumIf({metric}, dir = 'up') AS up, sumIf({metric}, dir != 'up') AS dn, toUnixTimestamp(max(ts)) AS t
        FROM flows WHERE {wwin} GROUP BY l, r""", p, fmt='JSON')
    info = {}
    if right:
        for r in ch(f"SELECT ext_ip, any(service) AS service, any(country) AS country, any(city) AS city FROM flows WHERE {where} AND has({{R:Array(String)}}, ext_ip) GROUP BY ext_ip", p, fmt='JSON'):
            info[r['ext_ip']] = r
    more_l, more_r = int(tops['nl']) > len(left), int(tops['nr']) > len(right)
    out = [{'l': x['l'], 'r': x['r'], 'up': float(x['up']), 'dn': float(x['dn']), 't': int(x['t'])} for x in links
           if (x['l'] != '__other' or more_l) and (x['r'] != '__other' or more_r)]
    return {'left': [host_obj(ip) for ip in left], 'right': [{'ip': ip, **{k: info.get(ip, {}).get(k, '') for k in ('service', 'country', 'city')}} for ip in right],
            'more_left': more_l, 'more_right': more_r, 'links': out, 'window_end': p.get('wend'), 'window': win if live else rng, 'live': live, 'range': rng}


def api_flows(q):
    where, p, rng, step = scope(q)
    p['lim'] = max(1, min(q1(q, 'limit', '50', int), 1000))
    rows = ch(f"""SELECT toUnixTimestamp(ts) AS t, toFloat64(ts_start) AS t0, exporter, in_if, out_if, toString(dir) AS dir, int_ip, int_port, ext_ip, ext_port,
            proto, nat_ip, nat_port, bytes, packets, l7, service, country, city, asn, as_org, sampling
        FROM flows WHERE {where} ORDER BY ts DESC LIMIT {{lim:UInt16}}""", p, fmt='JSON')
    for r in rows:
        r['name'] = NAMES.get(r['int_ip'])
        for k in ('t', 'in_if', 'out_if', 'int_port', 'ext_port', 'proto', 'nat_port', 'bytes', 'packets', 'asn', 'sampling'):
            r[k] = int(r[k])
    return {'rows': rows}


def api_live(q):
    """Flows that ended after `since` (unix s) — the map draws an arc for each as it arrives."""
    where, p, rng, step = scope(q)
    p['since'] = q1(q, 'since', str(int(time.time()) - 90), int)
    rows = ch(f"""SELECT toUnixTimestamp(ts) AS t, exporter, toString(dir) AS dir, int_ip, ext_ip, ext_port, service, country, city, lat, lon, bytes
        FROM flows WHERE {where} AND ts > toDateTime({{since:UInt32}}) AND lat != 0 ORDER BY ts LIMIT 300""", p, fmt='JSON')
    for r in rows:
        r['t'], r['bytes'], r['ext_port'] = int(r['t']), int(r['bytes']), int(r['ext_port'])
        r['name'] = NAMES.get(r['int_ip'])
    return {'rows': rows, 'now': int(time.time())}


def api_geo(q):
    where, p, rng, step = scope(q)
    rows = ch(f"""SELECT exporter, country, city, any(lat) AS la, any(lon) AS lo, sumIf(bytes, dir = 'up') AS up, sumIf(bytes, dir != 'up') AS dn, count() AS fl
        FROM flows WHERE {where} AND lat != 0 GROUP BY exporter, country, city ORDER BY up + dn DESC LIMIT 300""", p, fmt='JSON')
    for r in rows:
        r['up'], r['dn'], r['fl'] = int(r['up']), int(r['dn']), int(r['fl'])
    return {'rows': rows}


def iface(c, idx, nbytes, ext, seen=()):
    names = c.get('if_names', {})
    role = 'wan' if idx in c.get('wan_ifs', []) else 'local' if c.get('local_if') == idx and c.get('local_if') is not None else 'lan'
    custom = names.get(str(idx), '')
    return {'index': idx, 'name': custom or ('local' if role == 'local' else f'if {idx}'), 'custom_name': custom,
            'role': role, 'wan': role == 'wan', 'bytes': nbytes, 'ext_share': round(ext / nbytes, 3) if nbytes else 0,
            'addrs': c.get('if_addrs', {}).get(str(idx), []), 'seen_addrs': list(seen)}


def interfaces_of(c, rows, seen_addrs):
    """Interfaces seen in the data, plus those only mentioned in the settings (so a WAN index that never
    shows up in the data is visible and can be corrected)."""
    out = [iface(c, int(r['i']), int(r['bytes']), int(r['ext']), seen_addrs.get(int(r['i']), ())) for r in rows]
    seen = {i['index'] for i in out}
    configured = set(c.get('wan_ifs', [])) | {int(k) for key in ('if_names', 'if_addrs') for k in c.get(key, {}) if str(k).isdigit()}
    if c.get('local_if') is not None:
        configured.add(int(c['local_if']))
    for idx in sorted(configured - seen):
        out.append({**iface(c, idx, 0, 0), 'unseen': True})
    return sorted(out, key=lambda i: i['index'])


def api_devices(q):
    exp = exporters_cfg()
    stats = ch("""SELECT exporter, argMax(version, ts) AS version, sum(packets) AS packets, sum(records) AS records, sum(lost) AS lost,
            sum(no_template) AS no_template, sum(decode_errors) AS errors, argMax(templates, ts) AS templates, max(sampling) AS sampling_n,
            toUnixTimestamp(max(ts)) AS last, dateDiff('second', min(ts), max(ts)) + 60 AS span
        FROM exporter_stats WHERE ts >= now() - INTERVAL 15 MINUTE GROUP BY exporter""", fmt='JSON')
    # every interface seen in 24 h. ext = bytes for which the far end on this interface is a public address:
    # packets arriving FROM the internet (source public) or leaving TO it (destination public). The internet
    # uplink scores near 100 %, LAN ports near 0 %. The devices' own public addresses do not count as public.
    selfs = sorted({str(x) for c in exp.values() for x in c.get('public_ips', [])})
    pub = ("(NOT (isIPAddressInRange({x}, '10.0.0.0/8') OR isIPAddressInRange({x}, '172.16.0.0/12') OR isIPAddressInRange({x}, '192.168.0.0/16')"
           " OR isIPAddressInRange({x}, '100.64.0.0/10') OR isIPAddressInRange({x}, '127.0.0.0/8') OR isIPAddressInRange({x}, '169.254.0.0/16')"
           " OR isIPAddressInRange({x}, 'fc00::/7') OR isIPAddressInRange({x}, 'fe80::/10') OR {x} = '::1' OR has({{selfs:Array(String)}}, {x})))")
    src = "if(dir = 'down', ext_ip, int_ip)"     # who sent the packet
    dst = "if(dir = 'down', int_ip, ext_ip)"     # who received it
    ifs = ch(f"""SELECT exporter, i, sum(b) AS bytes, sum(e) AS ext FROM (
            SELECT exporter, in_if AS i, bytes AS b, if({pub.format(x=src)}, bytes, 0) AS e FROM flows WHERE ts >= now() - INTERVAL 1 DAY
            UNION ALL SELECT exporter, out_if AS i, bytes AS b, if({pub.format(x=dst)}, bytes, 0) AS e FROM flows WHERE ts >= now() - INTERVAL 1 DAY)
        GROUP BY exporter, i ORDER BY exporter, i""", {'selfs': selfs}, fmt='JSON')
    # NetFlow does not carry interface addresses; show what the data reveals so the user can recognise ports:
    # the source NAT address used when leaving an interface (the uplink's public IP) and the private /24
    # networks that send traffic into it (LAN segments). Only addresses with at least 10 % of the interface's flows.
    hints = ch("""SELECT exporter, i, a FROM (
            SELECT exporter, i, a, c, sum(c) OVER (PARTITION BY exporter, i) AS t FROM (
                SELECT exporter, out_if AS i, nat_ip AS a, count() AS c FROM flows
                WHERE ts >= now() - INTERVAL 1 DAY AND dir = 'up' AND nat_ip != '' AND nat_ip != int_ip GROUP BY exporter, i, a
                UNION ALL
                SELECT exporter, in_if AS i, concat(IPv4NumToString(bitAnd(IPv4StringToNumOrDefault(int_ip), 4294967040)), '/24') AS a, count() AS c FROM flows
                WHERE ts >= now() - INTERVAL 1 DAY AND dir IN ('up', 'internal') AND int_ip != exporter AND isIPv4String(int_ip)
                  AND (isIPAddressInRange(int_ip, '10.0.0.0/8') OR isIPAddressInRange(int_ip, '172.16.0.0/12') OR isIPAddressInRange(int_ip, '192.168.0.0/16'))
                GROUP BY exporter, i, a))
        WHERE c >= 0.1 * t ORDER BY exporter, i, c DESC LIMIT 3 BY exporter, i""", fmt='JSON')
    seen_addrs = {}
    for h in hints:
        seen_addrs.setdefault(h['exporter'], {}).setdefault(int(h['i']), []).append(h['a'])
    out = []
    seen = {s['exporter'] for s in stats}
    for ip in exp:
        if ip not in seen:
            stats.append({'exporter': ip, 'version': 0, 'packets': 0, 'records': 0, 'lost': 0, 'no_template': 0, 'errors': 0, 'templates': 0, 'last': 0, 'span': 60, 'sampling_n': 0})
    for s in stats:
        c = exp.get(s['exporter'], {})
        names = c.get('if_names', {})
        recs, span = int(s['records']), max(60, int(s['span']))
        out.append({'ip': s['exporter'], 'name': c.get('name', s['exporter']), 'vendor': c.get('vendor', ''), 'model': c.get('model', ''),
                    'site': ', '.join(x for x in (c.get('city', ''), c.get('country', '')) if x), 'proto': {5: 'NetFlow v5', 9: 'NetFlow v9', 10: 'IPFIX'}.get(int(s['version']), f"v{s['version']}"),
                    'rps': round(recs / span, 1), 'packets': int(s['packets']), 'records': recs, 'lost': int(s['lost']),
                    'loss_pct': round(100 * int(s['lost']) / max(1, int(s['packets']) + int(s['lost'])), 2), 'no_template': int(s['no_template']),
                    'errors': int(s['errors']), 'templates': int(s['templates']), 'last': int(s['last']),
                    'sampling': f"1:{int(s['sampling_n'])}" if int(s.get('sampling_n') or 0) > 1 else c.get('sampling', '1:1'),
                    'wan_ifs': c.get('wan_ifs', []), 'configured': s['exporter'] in exp,
                    'config': {k: c.get(k) for k in ('name', 'vendor', 'model', 'wan_ifs', 'local_if', 'public_ips', 'city', 'country', 'lat', 'lon', 'sampling')},
                    'interfaces': interfaces_of(c, [r for r in ifs if r['exporter'] == s['exporter']], seen_addrs.get(s['exporter'], {}))})
    return {'devices': out}


def api_host(q):
    ip = q1(q, 'ip', '')
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise BadRequest('bad ip')
    q = dict(q)
    q['f'] = [json.dumps([{'k': 'ip', 'v': ip}])]
    return {'host': host_obj(ip), 'summary': api_summary(q), 'series': api_series(q),
            'services': api_top({**q, 'dim': ['service'], 'limit': ['8']}), 'dests': api_top({**q, 'dim': ['ext_ip'], 'limit': ['8']}),
            'ports': api_top({**q, 'dim': ['l7'], 'limit': ['6']})}


def api_alerts(q):
    """Detections computed on the fly from the last day of flows."""
    out = []
    for r in ch("""SELECT int_ip, ext_ip, any(service) AS service, any(ext_port) AS port, count() AS mins, sum(b) * 8 / (count() * 60) AS bps, min(m) AS since
            FROM (SELECT int_ip, ext_ip, service, ext_port, toStartOfMinute(ts) AS m, sum(bytes) AS b FROM flows
                  WHERE ts >= now() - INTERVAL 3 HOUR AND dir = 'up' GROUP BY int_ip, ext_ip, service, ext_port, m HAVING b * 8 / 60 > 5000000)
            GROUP BY int_ip, ext_ip HAVING mins >= 45 ORDER BY bps DESC LIMIT 5""", fmt='JSON'):
        out.append({'sev': 'warn', 'kind': 'sustained_upload', 'ip': r['int_ip'], 'name': NAMES.get(r['int_ip']),
                    'title': 'Тривале вивантаження', 'text': f"{NAMES.get(r['int_ip']) or r['int_ip']} → {r['ext_ip']}:{r['port']} ({r['service']}) — {float(r['bps']) / 1e6:.1f} Мбіт/с протягом {r['mins']} хв за останні 3 год.",
                    'when': r['since']})
    for r in ch("""SELECT exporter, sum(lost) AS lost_n, sum(packets) AS packets_n FROM exporter_stats WHERE ts >= now() - INTERVAL 1 HOUR GROUP BY exporter HAVING lost_n > 0""", fmt='JSON'):
        r['lost'], r['packets'] = r['lost_n'], r['packets_n']
        pct = 100 * int(r['lost']) / max(1, int(r['packets']) + int(r['lost']))
        out.append({'sev': 'warn' if pct < 2 else 'crit', 'kind': 'export_loss', 'device': r['exporter'], 'title': 'Втрати експорту',
                    'text': f"{exporters_cfg().get(r['exporter'], {}).get('name', r['exporter'])}: втрачено {r['lost']} пакетів ({pct:.2f}%) за годину. Перевірте канал до колектора.", 'when': 'за годину'})
    for r in ch("""SELECT int_ip, country, min(ts) AS first FROM flows WHERE ts >= now() - INTERVAL 1 DAY AND country != '' GROUP BY int_ip, country
            HAVING (int_ip, country) NOT IN (SELECT int_ip, country FROM flows WHERE ts < now() - INTERVAL 1 DAY AND ts >= now() - INTERVAL 7 DAY GROUP BY int_ip, country)
               AND (SELECT min(ts) FROM flows) < now() - INTERVAL 2 DAY
            ORDER BY first DESC LIMIT 5""", fmt='JSON'):
        out.append({'sev': 'info', 'kind': 'new_country', 'ip': r['int_ip'], 'name': NAMES.get(r['int_ip']), 'title': 'Новий напрямок',
                    'text': f"{NAMES.get(r['int_ip']) or r['int_ip']} вперше за тиждень звернувся до країни {r['country']}.", 'when': r['first']})
    for r in ch("""WITH per AS (SELECT int_ip, toStartOfFiveMinutes(ts) AS m, sum(bytes) AS b FROM flows WHERE ts >= now() - INTERVAL 1 DAY GROUP BY int_ip, m)
            SELECT int_ip, max(b) AS peak, quantile(0.5)(b) AS med, argMax(m, b) AS at FROM per GROUP BY int_ip
            HAVING count() > 24 AND peak > 100000000 AND peak > 8 * med AND at >= now() - INTERVAL 3 HOUR ORDER BY peak DESC LIMIT 5""", fmt='JSON'):
        out.append({'sev': 'info', 'kind': 'burst', 'ip': r['int_ip'], 'name': NAMES.get(r['int_ip']), 'title': 'Сплеск трафіку',
                    'text': f"{NAMES.get(r['int_ip']) or r['int_ip']}: {int(r['peak']) / 1e6:.0f} MB за 5 хв — у {float(r['peak']) / max(1.0, float(r['med'])):.0f}× вище медіани за добу.", 'when': r['at']})
    return {'alerts': out}


def _str(v, n, field):
    if v is None or v == '':
        return ''
    if not isinstance(v, str) or len(v) > n:
        raise BadRequest(f'поле {field}: до {n} символів')
    return v.strip()


def device_from_body(b):
    try:
        ip = str(ipaddress.ip_address(str(b.get('ip', '')).strip()))
    except ValueError:
        raise BadRequest('Некоректна IP-адреса експорту')
    cfg = {'name': _str(b.get('name'), 64, 'назва') or ip, 'vendor': _str(b.get('vendor'), 64, 'виробник'), 'model': _str(b.get('model'), 64, 'модель'),
           'city': _str(b.get('city'), 64, 'місто'), 'sampling': _str(b.get('sampling'), 16, 'вибірка') or '1:1'}
    cc = _str(b.get('country'), 2, 'країна').upper()
    if cc and not cc.isalpha():
        raise BadRequest('Код країни — дві латинські літери')
    cfg['country'] = cc
    try:
        cfg['wan_ifs'] = sorted({int(x) for x in (b.get('wan_ifs') or []) if 0 <= int(x) < 2**32})
        cfg['local_if'] = None if b.get('local_if') in (None, '') else int(b['local_if'])
        for k, lim in (('lat', 90), ('lon', 180)):
            v = b.get(k)
            cfg[k] = None if v in (None, '') else float(v)
            if cfg[k] is not None and abs(cfg[k]) > lim:
                raise ValueError
    except (TypeError, ValueError):
        raise BadRequest('Інтерфейси — цілі числа; широта/довгота — числа в межах ±90/±180')
    pubs = []
    for x in (b.get('public_ips') or [])[:16]:
        try:
            pubs.append(str(ipaddress.ip_address(str(x).strip())))
        except ValueError:
            raise BadRequest(f'Некоректна публічна IP: {x}')
    cfg['public_ips'] = pubs
    old = exporters_cfg().get(ip, {})
    for k in ('if_names', 'if_addrs'):
        if old.get(k):
            cfg[k] = old[k]
    return ip, cfg


def post_device_save(body, user):
    ip, cfg = device_from_body(body)
    save_ui_exporter(ip, cfg)
    NAMES.reload()
    return {'ok': True, 'ip': ip}


def post_device_interfaces(body, user):
    try:
        ip = str(ipaddress.ip_address(str(body.get('ip', '')).strip()))
    except ValueError:
        raise BadRequest('Некоректна IP-адреса пристрою')
    items = body.get('interfaces')
    if not isinstance(items, list) or len(items) > 1024:
        raise BadRequest('Очікується список інтерфейсів')
    names, addrs, wan, local = {}, {}, [], None
    for it in items:
        try:
            idx = int(it.get('index'))
        except (TypeError, ValueError, AttributeError):
            raise BadRequest('Індекс інтерфейсу має бути числом')
        if not 0 <= idx < 2**32:
            raise BadRequest('Індекс інтерфейсу поза межами')
        name = str(it.get('name') or '').strip()
        if len(name) > 32 or any(ord(ch_) < 32 for ch_ in name):
            raise BadRequest(f'Назва інтерфейсу {idx}: до 32 символів, без керівних символів')
        if name:
            names[str(idx)] = name
        raw = it.get('addrs') or []
        if isinstance(raw, str):
            raw = raw.replace(',', ' ').split()
        if not isinstance(raw, list) or len(raw) > 8:
            raise BadRequest(f'Інтерфейс {idx}: до 8 адрес')
        try:
            # 'a.b.c.d/nn' keeps its prefix (interface address with mask), a bare address stays bare
            ok = [str(ipaddress.ip_interface(a) if '/' in a else ipaddress.ip_address(a)) for a in (str(x).strip() for x in raw) if a]
        except ValueError as e:
            raise BadRequest(f'Інтерфейс {idx}: некоректна адреса ({e})')
        if ok:
            addrs[str(idx)] = ok
        role = it.get('role', 'lan')
        if role == 'wan':
            wan.append(idx)
        elif role == 'local':
            if local is not None:
                raise BadRequest('Роль «сам пристрій» може мати лише один інтерфейс')
            local = idx
        elif role != 'lan':
            raise BadRequest('Роль: lan, wan або local')
    merged = exporters_cfg().get(ip, {})
    entry = load_ui_exporter(ip)
    entry.update({'if_names': names, 'if_addrs': addrs, 'wan_ifs': sorted(set(wan)), 'local_if': local})
    entry.setdefault('name', merged.get('name', ip))
    save_ui_exporter(ip, entry)
    NAMES.reload()
    return {'ok': True}


def post_device_delete(body, user):
    ip = str(body.get('ip', ''))
    if ip not in exporters_cfg():
        raise BadRequest('Пристрій не налаштований')
    save_ui_exporter(ip, None)
    NAMES.reload()
    return {'ok': True}


ROUTES = {'/api/meta': api_meta, '/api/summary': api_summary, '/api/series': api_series, '/api/top': api_top, '/api/river': api_river,
          '/api/flows': api_flows, '/api/live': api_live, '/api/geo': api_geo, '/api/devices': api_devices, '/api/host': api_host,
          '/api/alerts': api_alerts}
STATIC = {'.html': 'text/html; charset=utf-8', '.js': 'application/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.woff2': 'font/woff2'}


AUTH = None
ADMIN_GET = {'/api/users'}
COOKIE = 'ft_session'


class H(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    timeout = 60          # idle keep-alive connections do not hold a thread forever

    def log_message(self, *a):
        pass

    def token(self):
        c = SimpleCookie()
        try:
            c.load(self.headers.get('Cookie', ''))
        except Exception:
            return None
        m = c.get(COOKIE)
        return m.value if m else None

    def client_ip(self):
        ip = self.client_address[0]
        return ip[7:] if ip.startswith('::ffff:') and '.' in ip else ip

    def set_cookie(self, value, max_age):
        tls = isinstance(self.connection, ssl.SSLSocket) or self.headers.get('X-Forwarded-Proto') == 'https'
        secure = '; Secure' if tls else ''
        self._cookie = f'{COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}'

    def json(self, code, obj):
        self.send(code, json.dumps(obj, default=str).encode(), 'application/json')

    def send(self, code, body, ctype, cache='no-store'):
        self.send_response(code)
        if getattr(self, '_cookie', None):
            self.send_header('Set-Cookie', self._cookie)
            self._cookie = None
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', cache)
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path.startswith('/api/'):
            user = AUTH.session_user(self.token())
            if not user:
                return self.json(401, {'error': 'login required'})
            if u.path == '/api/me':
                return self.json(200, AUTH.public(user))
            if u.path in ADMIN_GET:
                if AUTH.users[user]['role'] != 'admin':
                    return self.json(403, {'error': 'Потрібні права адміністратора'})
                return self.json(200, {'users': AUTH.list_users()})
        fn = ROUTES.get(u.path)
        if fn:
            try:
                return self.send(200, json.dumps(fn(parse_qs(u.query)), default=str).encode(), 'application/json')
            except BadRequest as e:
                return self.send(400, json.dumps({'error': str(e)}).encode(), 'application/json')
            except (CHError, OSError) as e:
                print(f'[flowtrack-api] {u.path}: {e}', flush=True)
                return self.send(502, json.dumps({'error': 'database error'}).encode(), 'application/json')
        path = 'index.html' if u.path in ('/', '') else u.path.lstrip('/')
        full = os.path.realpath(os.path.join(WEB_DIR, path))
        if not full.startswith(os.path.realpath(WEB_DIR) + os.sep) or not os.path.isfile(full):
            return self.send(404, b'not found', 'text/plain')
        with open(full, 'rb') as f:
            body = f.read()
        ext = os.path.splitext(full)[1]
        self.send(200, body, STATIC.get(ext, 'application/octet-stream'), 'no-cache' if ext == '.html' else 'max-age=86400')


    def do_POST(self):
        u = urlparse(self.path)
        if not u.path.startswith('/api/'):
            return self.json(404, {'error': 'not found'})
        # CSRF: browsers only send JSON cross-site with a CORS preflight, which we never grant; cookie is SameSite=Strict too
        if not self.headers.get('Content-Type', '').startswith('application/json'):
            return self.json(415, {'error': 'JSON expected'})
        n = int(self.headers.get('Content-Length') or 0)
        if n > 65536:
            return self.json(413, {'error': 'too large'})
        try:
            body = json.loads(self.rfile.read(n) or b'{}')
            if not isinstance(body, dict):
                raise ValueError
        except ValueError:
            return self.json(400, {'error': 'bad JSON'})
        try:
            if u.path == '/api/login':
                token = AUTH.login(body.get('username'), body.get('password'), self.client_ip())
                self.set_cookie(token, 7 * 86400)
                return self.json(200, AUTH.public(body['username']))
            tok = self.token()
            user = AUTH.session_user(tok)
            if not user:
                return self.json(401, {'error': 'login required'})
            if u.path == '/api/logout':
                AUTH.logout(tok)
                self.set_cookie('', 0)
                return self.json(200, {'ok': True})
            if u.path == '/api/me/password':
                AUTH.change_own_password(user, body.get('current'), body.get('new'), tok)
                return self.json(200, AUTH.public(user))
            admin_routes = {
                '/api/users': lambda: AUTH.create_user(body.get('name'), body.get('role'), body.get('password')),
                '/api/users/update': lambda: AUTH.update_user(user, body.get('name'), body.get('role'), body.get('password')),
                '/api/users/delete': lambda: AUTH.delete_user(user, body.get('name')),
                '/api/devices/save': lambda: post_device_save(body, user),
                '/api/devices/delete': lambda: post_device_delete(body, user),
                '/api/devices/interfaces': lambda: post_device_interfaces(body, user),
            }
            if u.path not in admin_routes:
                return self.json(404, {'error': 'not found'})
            if AUTH.users[user]['role'] != 'admin':
                return self.json(403, {'error': 'Потрібні права адміністратора'})
            res = admin_routes[u.path]()
            return self.json(200, res if isinstance(res, dict) else {'ok': True})
        except AuthError as e:
            return self.json(429 if 'спроб' in str(e) else 400, {'error': str(e)})
        except BadRequest as e:
            return self.json(400, {'error': str(e)})
        except OSError as e:
            print(f'[flowtrack-api] POST {u.path}: {e}', flush=True)
            return self.json(500, {'error': 'не вдалося зберегти'})


_HOST_RE = re.compile(r'^[A-Za-z0-9.\-]+$|^\[[0-9A-Fa-f:.]+\]$')


def redirect_to_https(sock, port):
    """A plain-HTTP request on the HTTPS port: answer with a redirect to the same URL over HTTPS."""
    try:
        data = sock.recv(8192).decode('latin-1')
    except OSError:
        return
    lines = data.split('\r\n')
    parts = lines[0].split(' ') if lines else []
    path = parts[1] if len(parts) >= 2 and parts[1].startswith('/') else '/'
    host = ''
    for line in lines[1:]:
        if line.lower().startswith('host:'):
            host = line.split(':', 1)[1].strip()
            break
    if host.startswith('['):
        host = host.split(']')[0] + ']'
    else:
        host = host.split(':')[0]
    if not _HOST_RE.match(host or '-'):
        host = sock.getsockname()[0]
        host = host[7:] if host.startswith('::ffff:') and '.' in host else host
        if ':' in host:
            host = f'[{host}]'
    if any(c in path for c in '\r\n ') or len(path) > 2000:
        path = '/'
    body = f'HTTP/1.1 301 Moved Permanently\r\nLocation: https://{host}:{port}{path}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
    try:
        sock.sendall(body.encode('latin-1'))
    except OSError:
        pass


class Server(ThreadingHTTPServer):
    """HTTP(S) server. With TLS, the same port also answers plain HTTP with a redirect to HTTPS:
    the first byte of a TLS connection is a handshake record (0x16), anything else is HTTP.
    TLS handshakes run in the per-connection thread, so slow clients never block accept()."""
    daemon_threads = True

    def __init__(self, addr, handler, ctx=None, family=socket.AF_INET):
        self.address_family = family
        super().__init__(addr, handler)
        self.ctx = ctx

    def server_bind(self):
        if self.address_family == socket.AF_INET6:       # accept IPv4 too (dual-stack)
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()

    def finish_request(self, request, client_address):
        if not self.ctx:
            return super().finish_request(request, client_address)
        try:
            request.settimeout(10)
            first = request.recv(1, socket.MSG_PEEK)
        except OSError:
            return
        if not first:
            return
        if first != b'\x16':
            return redirect_to_https(request, self.server_address[1])
        try:
            tls = self.ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return              # e.g. the browser rejected the self-signed certificate and closed
        try:
            self.RequestHandlerClass(tls, client_address, self)
        finally:
            try:
                tls.close()
            except OSError:
                pass


def tls_context():
    if not (TLS_CERT and TLS_KEY):
        return None
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(TLS_CERT, TLS_KEY)
    return ctx


if __name__ == '__main__':
    AUTH = Auth()
    ctx = tls_context()
    if BIND in ('', '0.0.0.0', '::') or ':' in BIND:
        try:
            srv = Server(('::' if BIND in ('', '0.0.0.0', '::') else BIND, PORT), H, ctx, socket.AF_INET6)
        except OSError:                  # IPv6 disabled on this host
            if ':' in BIND and BIND != '::':
                raise
            srv = Server(('0.0.0.0', PORT), H, ctx)
    else:
        srv = Server((BIND, PORT), H, ctx)
    print(f'[flowtrack-api] serving on {"https" if ctx else "http"}://{BIND}:{PORT}'
          f'{" (plain HTTP redirects to HTTPS)" if ctx else ""}', flush=True)
    srv.serve_forever()
