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
import licensing  # noqa: E402
from common import (COMMUNITY, STATE_DIR, VERSION, CHError, ch, describe_listeners, edition, exporters_mtime, save_license, deactivate_license, license_checkin, iface_addrs, is_private, listen_signature,  # noqa: E402
                    listen_label, load_exporters, load_json, load_ui_exporter, open_listeners, save_ui_exporter, set_lang, tr)

BIND = os.environ.get('FT_WEB_BIND', '0.0.0.0')
PORT = int(os.environ.get('FT_WEB_PORT', '3030'))
WEB_LISTEN = []          # set at start: what this web server listens on
TLS_CERT = os.environ.get('FT_TLS_CERT', '')
TLS_KEY = os.environ.get('FT_TLS_KEY', '')
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web')
RANGES = {'1h': 3600, '6h': 6 * 3600, '24h': 86400, '7d': 7 * 86400, '30d': 30 * 86400}
STEP = {3600: 60, 6 * 3600: 300, 86400: 300, 7 * 86400: 3600, 30 * 86400: 4 * 3600}
NICE_STEPS = (60, 120, 300, 600, 900, 1800, 3600, 7200, 4 * 3600)
_stored = {'t': 0, 'days': 0}


def view_days():
    """Days of flow details the UI and API show. Without a license: the edition's days, even when older records are
    still stored (kept from an ended license, they show again with the next one). With a license: everything
    stored. The longest `keep_days` stored is re-read every minute."""
    ed = edition()
    days = ed['retention_days']
    if ed['status'] == 'active':
        if time.time() - _stored['t'] > 60:
            try:
                _stored['days'] = int(ch("SELECT max(keep_days) AS d FROM flows", fmt='JSON')[0]['d'])
            except (CHError, OSError, LookupError, TypeError, ValueError):
                pass
            _stored['t'] = time.time()
        days = max(days, _stored['days'])
    return days


def period(q):
    """-> (t0, t1, custom): a preset ('range') ends now; a custom period is 'from'/'to' in unix seconds."""
    now = int(time.time())
    if q.get('from') and q.get('to'):
        try:
            t0, t1 = int(q['from'][0]), int(q['to'][0])
        except ValueError:
            raise BadRequest('bad from/to')
        t1 = min(t1, now + 60)
        if t1 - t0 < 60:
            raise BadRequest('the period must be at least a minute long')
        if t1 - t0 > (view_days() + 1) * 86400:
            raise BadRequest(f'the period can be at most {view_days() + 1} days long')
        return t0, t1, True
    return now - RANGES.get(q.get('range', ['24h'])[0], 86400), now, False

# filter key -> (column, ClickHouse type)
FILTERS = {
    'ip': ('int_ip', 'String'), 'dst': ('ext_ip', 'String'), 'service': ('service', 'String'), 'l7': ('l7', 'String'),
    'country': ('country', 'String'), 'city': ('city', 'String'), 'port': ('ext_port', 'UInt16'), 'device': ('exporter', 'String'),
    'dir': ('dir', 'String'), 'proto': ('proto', 'UInt8'), 'in_if': ('in_if', 'UInt32'), 'out_if': ('out_if', 'UInt32'),
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
    """-> (where_sql, params, range_seconds, step). The window is a preset that ends now, or a custom from/to;
    params carry t0/t1 (unix s) and 'custom'."""
    t0, t1, custom = period(q)
    rng = t1 - t0
    # never older than the edition shows (also for the previous window that summary compares with)
    where = ['ts >= toDateTime({t0:UInt32})', 'ts >= toDateTime({floor:UInt32})']
    params = {'t0': t0, 't1': t1, 'custom': custom, 'floor': int(time.time()) - view_days() * 86400}
    if custom:
        where.append('ts < toDateTime({t1:UInt32})')
    # traffic scope: internet (inside <-> outside, default), internal (inside <-> inside) or all
    traffic = q.get('t', ['internet'])[0]
    if traffic == 'internet':
        where.append("dir IN ('up', 'down')")
    elif traffic == 'internal':
        where.append("dir = 'internal'")
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
        elif k == 'iface':
            if not v.isdigit():
                raise BadRequest('bad value for iface')
            cond = f'(in_if = {{f{i}:UInt32}} OR out_if = {{f{i}:UInt32}})'
        elif k in FILTERS:
            col, typ = FILTERS[k]
            if typ != 'String' and not v.isdigit():
                raise BadRequest(f'bad value for {k}')
            cond = f'{col} = {{f{i}:{typ}}}'
        else:
            continue
        where.append(f'NOT ({cond})' if neg else cond)
        params[f'f{i}'] = v
    step = STEP.get(rng) if not custom else None
    if not step:    # custom: the smallest round step that keeps the chart within ~300 points
        step = next((x for x in NICE_STEPS if rng / x <= 300), NICE_STEPS[-1])
    return ' AND '.join(where), params, rng, step


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


_listen_cache = [0, None]


def listen_info():
    """Where the collector receives NetFlow (from its state file) and where this web server listens; interface
    addresses are read live, so a changed DHCP address shows up."""
    if time.time() - _listen_cache[0] < 15:
        return _listen_cache[1]
    def live(items):
        return [{'iface': x['iface'], 'addrs': (iface_addrs(x['iface']) or x['addrs']) if x['iface'] else x['addrs']} for x in items]
    try:
        with open(os.path.join(STATE_DIR, 'collector.json')) as f:
            st = json.load(f)
        netflow = {'port': int(st['port']), 'listen': live(st.get('listen') or [])}
    except (OSError, ValueError, KeyError, TypeError):
        netflow = None
    out = {'netflow': netflow, 'web': {'port': PORT, 'listen': live(WEB_LISTEN)}}
    _listen_cache[:] = [time.time(), out]
    return out


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
    oldest = ch("SELECT toUnixTimestamp(min(ts)) AS t FROM flows WHERE ts >= now() - toIntervalDay({d:UInt16})", {'d': view_days()}, fmt='JSON')
    return {'devices': devices, 'now': int(time.time()), 'oldest': int(oldest[0]['t']) if oldest else 0, 'listen': listen_info(),
            'ranges': list(RANGES), 'geo_attribution': 'IP Geolocation by DB-IP (db-ip.com), CC BY 4.0', 'edition': edition_info(), 'version': VERSION}


def edition_info(admin=False):
    """What the UI shows about the edition; the license's customer/expiry and the error message only to admins."""
    ed = edition()
    out = {'name': ed['name'], 'status': ed['status'], 'rps': ed['rps'], 'retention_days': ed['retention_days'], 'view_days': view_days(),
           'community_days': COMMUNITY['retention_days']}
    col = collector_health(24 * 60)
    out['license_drops_24h'] = col['license_drops'] if col else 0
    lic = ed['license'] or {}
    out['expires'], out['days_left'] = lic.get('expires'), lic.get('days_left')    # every user sees when the edition ends
    if admin:
        out['license'], out['message'] = ed['license'], license_message(ed['status'], ed['message'], ed['license'])
        out['instance'], out['request'] = licensing.instance_id(), licensing.request_code()
        out['online'] = bool((ed['license'] or {}).get('online'))
        out['lease_until'], out['last_checkin'] = ed.get('lease_until'), licensing.last_checkin()
    return out


_LICENSE_UK = {
    'this is not a FlowTrack license code': 'це не код ліцензії FlowTrack',
    'the license code was mistyped or cut short': 'код ліцензії введено з помилкою або не повністю',
    'this license is for another FlowTrack version': 'ця ліцензія для іншої версії FlowTrack',
    'this license is for another FlowTrack edition': 'ця ліцензія для іншої редакції FlowTrack',
    'the license was not issued by FlowTrack or was altered': 'ліцензію видав не FlowTrack або її змінено',
    'this license was deactivated on this server to move it elsewhere': 'цю ліцензію деактивовано на цьому сервері для перенесення на інший',
    'the system clock is behind — set the correct date and time (NTP)': 'системний годинник відстає — встановіть правильні дату й час (NTP)',
    'no license is installed': 'ліцензію не встановлено',
}


_SERVER_UK = {
    'unknown': 'цей ліцензійний ключ невідомий серверу ліцензій',
    'revoked': 'цей ліцензійний ключ відкликано',
    'expired': 'термін дії цього ліцензійного ключа минув',
    'returned': 'цю ліцензію деактивовано або звільнено, тут вона більше не діє',
    'unreachable': 'сервер ліцензій недоступний — перевірте з’єднання з інтернетом (або введіть ліцензію FTL-… від постачальника)',
    'busy': 'забагато запитів до сервера ліцензій — спробуйте за хвилину',
    'error': 'помилка сервера ліцензій — спробуйте пізніше',
}


def license_message(code, msg, lic=None):
    """A licensing message in the UI language."""
    lic = lic or {}
    if code == 'in_use':
        inst = re.search(r'installation (\S+)', msg)
        return tr(msg, f"цей ключ уже активний на інсталяції {inst.group(1) if inst else '?'} — спершу деактивуйте його там "
                       '(Налаштування → Ліцензія) або попросіть постачальника звільнити його')
    if code == 'unconfirmed':
        when = re.search(r'since (\d{4}-\d{2}-\d{2})', msg)
        return tr(msg, f'сервер ліцензій не підтверджував цю ліцензію з {when.group(1)} — перевірте з’єднання з ним' if when
                  else 'цю онлайн-ліцензію ще не підтвердив сервер ліцензій')
    if code == 'unknown' and 'license key' not in msg:
        return tr(msg, 'цю ліцензію не видавав сервер ліцензій')
    if code == 'invalid' and 'license key' in msg:
        return tr(msg, 'це не ліцензійний ключ FlowTrack' if 'not a' in msg else 'ліцензійний ключ введено з помилкою або не повністю')
    if code in _SERVER_UK and msg not in _LICENSE_UK and (code != 'expired' or 'license key' in msg):
        return tr(msg, _SERVER_UK[code])        # from the license server
    if code == 'expired' and lic.get('expires'):
        return tr(msg, 'ліцензія закінчилась ' + time.strftime('%Y-%m-%d', time.gmtime(lic['expires'])))
    if code == 'other_instance':
        return tr(msg, f"цю ліцензію видано для інсталяції {lic.get('instance')}, а не для цієї ({licensing.instance_id()})")
    return tr(msg, _LICENSE_UK.get(msg, msg)) if msg else ''


def post_license(body):
    try:
        save_license(body.get('key', ''))
    except ValueError as ex:
        raise BadRequest(license_message(getattr(ex, 'code', 'invalid'), str(ex), getattr(ex, 'license', None))) from None
    return edition_info(admin=True)


def post_license_deactivate():
    try:
        r = deactivate_license(with_code=True)
    except ValueError as ex:
        raise BadRequest(license_message('invalid', str(ex))) from None
    return dict(edition_info(admin=True), return_code=r['return_code'], released=r['released'])


def post_license_checkin():
    try:
        license_checkin()
    except ValueError as ex:
        raise BadRequest(license_message(getattr(ex, 'code', 'error'), str(ex))) from None
    return edition_info(admin=True)


def api_summary(q):
    where, p, rng, step = scope(q)
    # current and previous window in one pass
    wprev = where.replace('ts >= toDateTime({t0:UInt32})', 'ts >= toDateTime({p0:UInt32})', 1)
    p['p0'] = p['t0'] - rng
    r = ch(f"""SELECT
        sumIf(bytes, cur) AS s_bytes, sumIf(bytes, cur AND dir IN ('up', 'internal')) AS s_up, sumIf(bytes, cur AND dir NOT IN ('up', 'internal')) AS s_down,
        countIf(cur) AS s_flows, sumIf(packets, cur) AS s_packets,
        uniqExactIf(int_ip, cur) + uniqExactIf(ext_ip, cur) AS s_ips, uniqExactIf(int_ip, cur) AS s_hosts, uniqExactIf(int_ip, NOT cur) AS s_p_hosts,
        sumIf(bytes, NOT cur) AS s_p_bytes, countIf(NOT cur) AS s_p_flows, uniqExactIf(int_ip, NOT cur) + uniqExactIf(ext_ip, NOT cur) AS s_p_ips,
        toUnixTimestamp(min(ts)) AS s_oldest
      FROM (SELECT ts, dir, bytes, packets, int_ip, ext_ip, ts >= toDateTime({{t0:UInt32}}) AS cur FROM flows WHERE {wprev})""", p, fmt='JSON')[0]
    r = {k[2:]: v for k, v in r.items()}
    top = ch(f"SELECT service AS k, sum(bytes) AS b FROM flows WHERE {where} GROUP BY k ORDER BY b DESC LIMIT 1", p, fmt='JSON')
    r = {k: int(v) for k, v in r.items()}
    # history starts when the collector started receiving (late-exported flows can carry older timestamps)
    started = ch("SELECT toUnixTimestamp(min(ts)) - 60 AS t FROM exporter_stats", fmt='JSON')
    if started and int(started[0]['t']) > 0:
        r['oldest'] = max(r['oldest'], int(started[0]['t']))
    r['has_prev'] = r['oldest'] <= p['t0'] - rng + step
    r['range'], r['from'], r['to'], r['custom'] = rng, p['t0'], p['t1'], p['custom']
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
        return {'step': step, 'range': rng, 'from': p['t0'], 'to': p['t1'], 'rows': [[int(r['t']), r['k'], int(r['b'])] for r in rows]}
    rows = ch(f"""SELECT {bucket} AS t, sumIf(bytes, dir = 'down') AS dn, sumIf(bytes, dir IN ('up', 'internal')) AS up,
            sumIf(bytes, dir NOT IN ('up', 'down')) AS other, count() AS fl
        FROM flows WHERE {where} GROUP BY t ORDER BY t""", p, fmt='JSON')
    return {'step': step, 'range': rng, 'from': p['t0'], 'to': p['t1'], 'rows': [[int(r['t']), int(r['dn']), int(r['up']), int(r['other']), int(r['fl'])] for r in rows]}


def api_top(q):
    where, p, rng, step = scope(q)
    dim = q1(q, 'dim', 'int_ip')
    p['lim'] = max(1, min(q1(q, 'limit', '10', int), 500))
    if dim == 'conv':
        rows = ch(f"""SELECT int_ip, ext_ip, any(service) AS service, any(country) AS country, any(city) AS city,
                sumIf(bytes, dir IN ('up', 'internal')) AS up, sumIf(bytes, dir NOT IN ('up', 'internal')) AS dn, count() AS fl, sum(packets) AS pk
            FROM flows WHERE {where} GROUP BY int_ip, ext_ip ORDER BY up + dn DESC LIMIT {{lim:UInt16}}""", p, fmt='JSON')
        for r in rows:
            r['name'] = NAMES.get(r['int_ip'])
    elif dim == 'host_svc':     # each inside host with its main service and L7 protocol
        rows = ch(f"""SELECT int_ip AS k, argMax(service, b) AS service, argMax(l7, b) AS l7, argMax(proto, b) AS proto,
                sum(u) AS up, sum(d) AS dn, sum(f) AS fl, 0 AS pk
            FROM (SELECT int_ip, service, l7, proto, sum(bytes) AS b, sumIf(bytes, dir IN ('up', 'internal')) AS u, sumIf(bytes, dir NOT IN ('up', 'internal')) AS d, count() AS f
                  FROM flows WHERE {where} GROUP BY int_ip, service, l7, proto)
            GROUP BY k ORDER BY up + dn DESC LIMIT {{lim:UInt16}}""", p, fmt='JSON')
        for r in rows:
            r['name'] = NAMES.get(r['k'])
            r['proto'] = int(r['proto'])
    elif dim == 'int_ip' and q1(q, 't', 'internet') == 'internal':
        # inside <-> inside: a host is both the source (int_ip) and the destination (ext_ip) of records;
        # count what it sent (up) and what it received (dn)
        rows = ch(f"""SELECT k, sum(u) AS up, sum(d) AS dn, sum(f) AS fl, sum(pk_) AS pk FROM (
                SELECT int_ip AS k, bytes AS u, 0 AS d, 1 AS f, packets AS pk_ FROM flows WHERE {where}
                UNION ALL SELECT ext_ip AS k, 0 AS u, bytes AS d, 1 AS f, packets AS pk_ FROM flows WHERE {where})
            GROUP BY k ORDER BY up + dn DESC LIMIT {{lim:UInt16}}""", p, fmt='JSON')
        for r in rows:
            r['name'] = NAMES.get(r['k'])
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
        rows = ch(f"""SELECT toString({col}) AS k, sumIf(bytes, dir IN ('up', 'internal')) AS up, sumIf(bytes, dir NOT IN ('up', 'internal')) AS dn,
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


def live_end(q):
    """End of a live window: the newest record of the chosen device(s), or of all exporters. Only the device
    filter counts, so adding other filters never moves the window back in time."""
    try:
        flt = json.loads(q.get('f', ['[]'])[0])
    except ValueError:
        flt = []
    devs = [str(f.get('v')) for f in (flt if isinstance(flt, list) else []) if isinstance(f, dict) and f.get('k') == 'device' and not f.get('neg')]
    cond = ' AND exporter IN {devs:Array(String)}' if devs else ''
    last = ch(f"SELECT toUnixTimestamp(max(ts)) AS t FROM flows WHERE ts >= now() - INTERVAL 15 MINUTE{cond}", {'devs': devs}, fmt='JSON')
    return int(last[0]['t']) if last and int(last[0]['t']) else int(time.time())


def live_window(q, where, p, default='1'):
    """Narrow `where` to the live window (the last `win` seconds of collected data) unless `live=0` or a custom period
    is chosen (a past period has no live window). -> (where, live)."""
    if q1(q, 'live', default) != '1' or p['custom']:
        return where, False
    p['wend'] = live_end(q)      # the window ends at the newest collected record (of the chosen device), so filters never shift it
    p['win'] = max(60, min(q1(q, 'win', '120', int), 900))
    return where + ' AND ts > toDateTime({wend:UInt32}) - toIntervalSecond({win:UInt32}) AND ts <= toDateTime({wend:UInt32})', True


def api_river(q):
    """Top-N inside x top-N outside endpoints with link values, all from one window: the live window (the last
    `win` seconds of collected data) or the whole range."""
    where, p, rng, step = scope(q)
    metric = {'bytes': 'bytes', 'packets': 'packets', 'flows': '1'}.get(q1(q, 'metric', 'bytes'), 'bytes')
    p['n'] = max(3, min(q1(q, 'top', '10', int), 20))
    where, live = live_window(q, where, p)
    win = p.get('win', 0)
    tops = ch(f"""SELECT
            (SELECT groupArray(k) FROM (SELECT int_ip AS k FROM flows WHERE {where} GROUP BY k ORDER BY sum({metric}) DESC LIMIT {{n:UInt8}})) AS l,
            (SELECT groupArray(k) FROM (SELECT ext_ip AS k FROM flows WHERE {where} GROUP BY k ORDER BY sum({metric}) DESC LIMIT {{n:UInt8}})) AS r,
            (SELECT uniqExact(int_ip) FROM flows WHERE {where}) AS nl, (SELECT uniqExact(ext_ip) FROM flows WHERE {where}) AS nr""", p, fmt='JSON')[0]
    left, right = tops['l'], tops['r']
    p['L'], p['R'] = left, right
    links = ch(f"""SELECT if(has({{L:Array(String)}}, int_ip), int_ip, '__other') AS l, if(has({{R:Array(String)}}, ext_ip), ext_ip, '__other') AS r,
            sumIf({metric}, dir IN ('up', 'internal')) AS up, sumIf({metric}, dir NOT IN ('up', 'internal')) AS dn, toUnixTimestamp(max(ts)) AS t
        FROM flows WHERE {where} GROUP BY l, r""", p, fmt='JSON')
    info = {}
    if right:
        for r in ch(f"SELECT ext_ip, any(service) AS service, any(country) AS country, any(city) AS city FROM flows WHERE {where} AND has({{R:Array(String)}}, ext_ip) GROUP BY ext_ip", p, fmt='JSON'):
            info[r['ext_ip']] = r
    more_l, more_r = int(tops['nl']) > len(left), int(tops['nr']) > len(right)
    out = [{'l': x['l'], 'r': x['r'], 'up': float(x['up']), 'dn': float(x['dn']), 't': int(x['t'])} for x in links
           if (x['l'] != '__other' or more_l) and (x['r'] != '__other' or more_r)]
    return {'left': [host_obj(ip) for ip in left], 'right': [{'ip': ip, 'name': NAMES.get(ip) if is_private(ip) else '', **{k: info.get(ip, {}).get(k, '') for k in ('service', 'country', 'city')}} for ip in right],
            'more_left': more_l, 'more_right': more_r, 'links': out, 'window_end': p.get('wend'), 'window': win if live else rng, 'live': live, 'range': rng}


def api_paths(q):
    """Traffic through an exporter: (input interface -> output interface) pairs with volume, hosts and services.
    The device comes from the 'device' filter; live = the last `win` seconds of data, otherwise the range."""
    where, p, rng, step = scope(q)
    metric = {'bytes': 'bytes', 'packets': 'packets', 'flows': '1'}.get(q1(q, 'metric', 'bytes'), 'bytes')
    live = q1(q, 'live', '0') == '1' and not p['custom']
    win = max(60, min(q1(q, 'win', '120', int), 900))
    wend = None
    if live:
        wend = live_end(q)
        p['wend'], p['win'] = wend, win
        where += ' AND ts > toDateTime({wend:UInt32}) - toIntervalSecond({win:UInt32}) AND ts <= toDateTime({wend:UInt32})'
    rows = ch(f"""SELECT in_if, out_if, sum({metric}) AS v, sum(bytes) AS b, sum(packets) AS pk, count() AS fl,
            uniqExact(int_ip) AS hosts, topKWeighted(3)(service, bytes) AS services,
            sumIf(bytes, dir IN ('up', 'down')) AS internet, sumIf(bytes, dir = 'internal') AS internal
        FROM flows WHERE {where} GROUP BY in_if, out_if ORDER BY v DESC LIMIT 80""", p, fmt='JSON')
    for r in rows:
        for k in ('in_if', 'out_if', 'b', 'pk', 'fl', 'hosts', 'internet', 'internal'):
            r[k] = int(r[k])
        r['v'] = float(r['v'])
    return {'rows': rows, 'live': live, 'window_end': wend, 'window': win if live else rng, 'range': rng}


def api_devmap(q):
    """One exporter as a box with ports: interface pairs (paths through the box), the inside hosts behind each
    inside interface and the outside addresses behind each WAN interface. Same time window rules as api_paths."""
    where, p, rng, step = scope(q)
    metric = {'bytes': 'bytes', 'packets': 'packets', 'flows': '1'}.get(q1(q, 'metric', 'bytes'), 'bytes')
    live = q1(q, 'live', '0') == '1' and not p['custom']
    win = max(60, min(q1(q, 'win', '120', int), 900))
    wend = None
    if live:
        wend = live_end(q)
        p['wend'], p['win'] = wend, win
        where += ' AND ts > toDateTime({wend:UInt32}) - toIntervalSecond({win:UInt32}) AND ts <= toDateTime({wend:UInt32})'
    p['n'] = max(3, min(q1(q, 'top', '10', int), 20))
    paths = ch(f"""SELECT in_if, out_if, sum({metric}) AS v, sumIf({metric}, dir = 'up') AS up, sumIf({metric}, dir = 'down') AS dn,
            sumIf({metric}, dir NOT IN ('up', 'down')) AS other, count() AS fl, uniqExact(int_ip) AS hosts,
            topKWeighted(3)(service, toUInt64({metric})) AS services
        FROM flows WHERE {where} GROUP BY in_if, out_if ORDER BY v DESC LIMIT 60""", p, fmt='JSON')
    # an inside host enters the box through: in_if when it sends (up, or the source of an internal record),
    # out_if when it receives (down, or the destination of an internal record)
    inside = ch(f"""SELECT host, iface, sum(u) AS up, sum(d) AS dn, sum(u) + sum(d) AS v FROM (
            SELECT int_ip AS host, if(dir = 'down', out_if, in_if) AS iface, if(dir = 'down', 0, {metric}) AS u, if(dir = 'down', {metric}, 0) AS d
                FROM flows WHERE {where} AND dir IN ('up', 'down', 'internal')
            UNION ALL SELECT ext_ip, out_if, 0, {metric} FROM flows WHERE {where} AND dir = 'internal')
        GROUP BY host, iface ORDER BY v DESC LIMIT {{n:UInt8}} BY iface LIMIT 60""", p, fmt='JSON')
    outside = ch(f"""SELECT ext_ip AS host, if(dir = 'up', out_if, in_if) AS iface, sumIf({metric}, dir = 'up') AS up, sumIf({metric}, dir = 'down') AS dn,
            sum({metric}) AS v, any(service) AS service, any(country) AS country, any(city) AS city
        FROM flows WHERE {where} AND dir IN ('up', 'down') GROUP BY host, iface ORDER BY v DESC LIMIT {{n:UInt8}}""", p, fmt='JSON')
    num = ('in_if', 'out_if', 'iface', 'fl', 'hosts')
    for rows in (paths, inside, outside):
        for r in rows:
            for k, val in list(r.items()):
                if k in num:
                    r[k] = int(val)
                elif k in ('v', 'up', 'dn', 'other'):
                    r[k] = float(val)
    for r in inside:
        r['name'] = NAMES.get(r['host'])
    return {'paths': paths, 'inside': inside, 'outside': outside, 'live': live, 'window_end': wend, 'window': win if live else rng, 'range': rng}


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
    where, live = live_window(q, where, p, default='0')
    rows = ch(f"""SELECT exporter, country, city, any(lat) AS la, any(lon) AS lo, sumIf(bytes, dir IN ('up', 'internal')) AS up, sumIf(bytes, dir NOT IN ('up', 'internal')) AS dn, count() AS fl
        FROM flows WHERE {where} AND lat != 0 GROUP BY exporter, country, city ORDER BY up + dn DESC LIMIT 300""", p, fmt='JSON')
    for r in rows:
        r['up'], r['dn'], r['fl'] = int(r['up']), int(r['dn']), int(r['fl'])
    return {'rows': rows, 'live': live, 'window': p.get('win', 0), 'window_end': p.get('wend', 0)}


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


def collector_health(minutes=15):
    """Receiver totals for the last minutes (None before the collector wrote any)."""
    try:
        # workers: the newest non-zero value — a collector that stops writes a last row with its workers already gone
        r = ch(f"""SELECT count() AS n, if(countIf(workers > 0) > 0, argMaxIf(workers, ts, workers > 0), 0) AS workers, argMax(rcvbuf, ts) AS rcvbuf, sum(packets) AS packets,
                sum(socket_drops) AS socket_drops, sum(queue_drops) AS queue_drops, sum(dropped_rows) AS dropped_rows, sum(license_drops) AS license_drops,
                max(rx_queue_peak) AS rx_queue_peak, argMax(buffered, ts) AS buffered, toUnixTimestamp(max(ts)) AS last
            FROM collector_stats WHERE ts >= now() - INTERVAL {int(minutes)} MINUTE""", fmt='JSON')[0]
    except CHError:                    # table appears when the new collector starts
        return None
    if not int(r['n']):
        return None
    out = {k: int(v) for k, v in r.items() if k != 'n'}
    out['minutes'] = minutes
    return out


def api_devices(q):
    exp = exporters_cfg()
    stats = ch("""SELECT exporter, argMax(version, ts) AS version, sum(packets) AS packets, sum(records) AS records, sum(lost) AS lost,
            sum(no_template) AS no_template, sum(decode_errors) AS errors, argMax(templates, ts) AS templates, argMax(sampling, ts) AS sampling_n,
            sum(dup_dropped) AS dup_dropped, sum(dup_packets) AS dup_packets,
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
    # records reported twice although the exporter sends no direction field (both directions monitored on
    # several interfaces): identical flow, interfaces, start time and size
    dups = {r['exporter']: r for r in ch("""SELECT exporter, count() AS n, uniqExact(cityHash64(int_ip, ext_ip, int_port, ext_port, proto, in_if, out_if, ts_start, bytes)) AS u,
            countIf(obs != 255) AS with_dir FROM flows WHERE ts >= now() - INTERVAL 15 MINUTE GROUP BY exporter""", fmt='JSON')}
    # the latest minute's sampling, unless the devices were edited since: the collector applies a new ratio within
    # about a minute, so until its stats cover that time show the configured one (changed in the UI -> shown at once)
    cfg_changed = max(exporters_mtime())
    out = []
    seen = {s['exporter'] for s in stats}
    for ip in exp:
        if ip not in seen:
            stats.append({'exporter': ip, 'version': 0, 'packets': 0, 'records': 0, 'lost': 0, 'no_template': 0, 'errors': 0, 'templates': 0, 'last': 0, 'span': 60, 'sampling_n': 0, 'dup_dropped': 0, 'dup_packets': 0})
    for s in stats:
        c = exp.get(s['exporter'], {})
        names = c.get('if_names', {})
        recs, span = int(s['records']), max(60, int(s['span']))
        out.append({'ip': s['exporter'], 'name': c.get('name', s['exporter']), 'vendor': c.get('vendor', ''), 'model': c.get('model', ''),
                    'site': ', '.join(x for x in (c.get('city', ''), c.get('country', '')) if x), 'proto': {5: 'NetFlow v5', 9: 'NetFlow v9', 10: 'IPFIX'}.get(int(s['version']), f"v{s['version']}"),
                    'rps': round(recs / span, 1), 'packets': int(s['packets']), 'records': recs, 'lost': int(s['lost']),
                    'loss_pct': round(100 * int(s['lost']) / max(1, int(s['packets']) + int(s['lost'])), 2), 'no_template': int(s['no_template']),
                    'errors': int(s['errors']), 'templates': int(s['templates']), 'last': int(s['last']),
                    'dup_dropped': int(s.get('dup_dropped') or 0), 'dup_packets': int(s.get('dup_packets') or 0),
                    'dup_pct': round(100 * (int(dups[s['exporter']]['n']) - int(dups[s['exporter']]['u'])) / max(1, int(dups[s['exporter']]['n'])), 2) if s['exporter'] in dups else 0,
                    'direction_field': bool(s['exporter'] in dups and int(dups[s['exporter']]['with_dir'])),
                    'sampling': f"1:{int(s['sampling_n'])}" if int(s.get('sampling_n') or 0) > 1 and int(s['last']) > cfg_changed + 120 else c.get('sampling', '1:1'),
                    'wan_ifs': c.get('wan_ifs', []), 'configured': s['exporter'] in exp,
                    'config': {k: c.get(k) for k in ('name', 'vendor', 'model', 'wan_ifs', 'local_if', 'public_ips', 'city', 'country', 'lat', 'lon', 'sampling')},
                    'interfaces': interfaces_of(c, [r for r in ifs if r['exporter'] == s['exporter']], seen_addrs.get(s['exporter'], {}))})
    return {'devices': out, 'collector': collector_health(), 'listen': listen_info()}


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
                    'title': tr('Sustained upload', 'Тривале вивантаження'),
                    'text': tr(f"{NAMES.get(r['int_ip']) or r['int_ip']} → {r['ext_ip']}:{r['port']} ({r['service']}) — {float(r['bps']) / 1e6:.1f} Mbit/s for {r['mins']} min in the last 3 h.",
                               f"{NAMES.get(r['int_ip']) or r['int_ip']} → {r['ext_ip']}:{r['port']} ({r['service']}) — {float(r['bps']) / 1e6:.1f} Мбіт/с протягом {r['mins']} хв за останні 3 год."),
                    'when': r['since']})
    for r in ch("""SELECT exporter, sum(lost) AS lost_n, sum(packets) AS packets_n FROM exporter_stats WHERE ts >= now() - INTERVAL 1 HOUR GROUP BY exporter HAVING lost_n > 0""", fmt='JSON'):
        r['lost'], r['packets'] = r['lost_n'], r['packets_n']
        pct = 100 * int(r['lost']) / max(1, int(r['packets']) + int(r['lost']))
        out.append({'sev': 'warn' if pct < 2 else 'crit', 'kind': 'export_loss', 'device': r['exporter'], 'title': tr('Export loss', 'Втрати експорту'),
                    'text': tr(f"{exporters_cfg().get(r['exporter'], {}).get('name', r['exporter'])}: {r['lost']} packets ({pct:.2f}%) lost in the last hour. Check the path to the collector.",
                               f"{exporters_cfg().get(r['exporter'], {}).get('name', r['exporter'])}: втрачено {r['lost']} пакетів ({pct:.2f}%) за годину. Перевірте канал до колектора."),
                    'when': tr('last hour', 'за годину')})
    col = collector_health(60)
    if col and col['socket_drops'] + col['queue_drops']:
        lost = col['socket_drops'] + col['queue_drops']
        pct = 100 * lost / max(1, col['packets'] + lost)
        out.append({'sev': 'warn' if pct < 1 else 'crit', 'kind': 'collector_drops', 'title': tr('Collector falling behind', 'Колектор не встигає'),
                    'text': tr(f"{lost} packets ({pct:.2f}%) dropped in the last hour: socket buffer {col['socket_drops']}, worker queues {col['queue_drops']}. "
                               f"Raise FT_WORKERS in /etc/flowtrack/env (now {col['workers']}) or net.core.rmem_max.",
                               f"За годину відкинуто {lost} пакетів ({pct:.2f}%): буфер сокета — {col['socket_drops']}, черга воркерів — {col['queue_drops']}. "
                               f"Збільште FT_WORKERS у /etc/flowtrack/env (зараз {col['workers']}) або net.core.rmem_max."), 'when': tr('last hour', 'за годину')})
    ed = edition()
    lic = ed['license'] or {}
    if ed['status'] == 'expired':
        out.append({'sev': 'crit', 'kind': 'license_expired', 'title': tr('FlowTrack Pro license expired', 'Ліцензія FlowTrack Pro закінчилась'),
                    'text': tr(f"{ed['message'].capitalize()}. The Community limits apply again ({COMMUNITY['rps']:,} records/s, {COMMUNITY['retention_days']} days); stored data is kept, records older than {COMMUNITY['retention_days']} days show again with a renewed key. Enter it in Settings → License.",
                               f"Ліцензія діяла до {time.strftime('%d.%m.%Y', time.gmtime(lic.get('expires') or 0))}. Знову діють ліміти Community ({COMMUNITY['rps']:,} записів/с, {COMMUNITY['retention_days']} днів); збережені дані лишаються, записи, старші за {COMMUNITY['retention_days']} днів, знову видно з подовженим ключем. Введіть його у «Налаштування → Ліцензія»."),
                    'when': time.strftime('%Y-%m-%d', time.gmtime(lic.get('expires') or 0))})
    elif ed['status'] in ('invalid', 'other_instance', 'returned', 'clock'):
        out.append({'sev': 'crit', 'kind': 'license_invalid', 'title': tr('The license does not work on this server', 'Ліцензія не діє на цьому сервері'),
                    'text': tr(f"{license_message(ed['status'], ed['message'], lic).capitalize()}. The Community limits apply ({COMMUNITY['rps']:,} records/s, {COMMUNITY['retention_days']} days); stored data is kept. See Settings → License.",
                               f"{license_message(ed['status'], ed['message'], lic).capitalize()}. Діють ліміти Community ({COMMUNITY['rps']:,} записів/с, {COMMUNITY['retention_days']} днів); збережені дані лишаються. Див. «Налаштування → Ліцензія»."),
                    'when': tr('now', 'зараз')})
    elif ed['status'] == 'active' and lic.get('days_left', 99) < 14:
        out.append({'sev': 'warn', 'kind': 'license_expiring', 'title': tr('FlowTrack Pro license ends soon', 'Ліцензія FlowTrack Pro скоро закінчиться'),
                    'text': tr(f"The license ends on {time.strftime('%Y-%m-%d', time.gmtime(lic['expires']))} ({lic['days_left']} day{'' if lic['days_left'] == 1 else 's'} left). After that the Community limits apply.",
                               f"Ліцензія діє до {time.strftime('%d.%m.%Y', time.gmtime(lic['expires']))} (лишилось днів: {lic['days_left']}). Після цього діятимуть ліміти Community."),
                    'when': tr(f"{lic['days_left']} day{'' if lic['days_left'] == 1 else 's'} left", f"лишилось {lic['days_left']} дн.")})
    if col and col.get('license_drops'):
        out.append({'sev': 'warn', 'kind': 'license_limit', 'title': tr('Edition limit reached', 'Досягнуто ліміту редакції'),
                    'text': tr(f"{col['license_drops']} records were not stored in the last hour: the traffic exceeds {ed['rps']:,} records/s, the limit of FlowTrack Community. "
                               "FlowTrack Pro has no limit.",
                               f"За годину {col['license_drops']} записів не збережено: трафік перевищує {ed['rps']:,} записів/с — ліміт FlowTrack Community. "
                               "У FlowTrack Pro ліміту немає."), 'when': tr('last hour', 'за годину')})
    if col and col['dropped_rows']:
        out.append({'sev': 'crit', 'kind': 'rows_dropped', 'title': tr('Records not stored', 'Записи не збережено'),
                    'text': tr(f"{col['dropped_rows']} records did not reach the database in the last hour: ClickHouse was unavailable longer than the collector buffer lasts.",
                               f"За годину {col['dropped_rows']} записів не потрапили в базу: ClickHouse був недоступний довше, ніж вміщує буфер колектора."), 'when': tr('last hour', 'за годину')})
    for r in ch("""SELECT int_ip, country, min(ts) AS first FROM flows WHERE ts >= now() - INTERVAL 1 DAY AND country != '' GROUP BY int_ip, country
            HAVING (int_ip, country) NOT IN (SELECT int_ip, country FROM flows WHERE ts < now() - INTERVAL 1 DAY AND ts >= now() - INTERVAL 7 DAY GROUP BY int_ip, country)
               AND (SELECT min(ts) FROM flows) < now() - INTERVAL 2 DAY
            ORDER BY first DESC LIMIT 5""", fmt='JSON'):
        out.append({'sev': 'info', 'kind': 'new_country', 'ip': r['int_ip'], 'name': NAMES.get(r['int_ip']), 'title': tr('New destination', 'Новий напрямок'),
                    'text': tr(f"{NAMES.get(r['int_ip']) or r['int_ip']} contacted {r['country']} for the first time this week.",
                               f"{NAMES.get(r['int_ip']) or r['int_ip']} вперше за тиждень звернувся до країни {r['country']}."), 'when': r['first']})
    for r in ch("""WITH per AS (SELECT int_ip, toStartOfFiveMinutes(ts) AS m, sum(bytes) AS b FROM flows WHERE ts >= now() - INTERVAL 1 DAY GROUP BY int_ip, m)
            SELECT int_ip, max(b) AS peak, quantile(0.5)(b) AS med, argMax(m, b) AS at FROM per GROUP BY int_ip
            HAVING count() > 24 AND peak > 100000000 AND peak > 8 * med AND at >= now() - INTERVAL 3 HOUR ORDER BY peak DESC LIMIT 5""", fmt='JSON'):
        out.append({'sev': 'info', 'kind': 'burst', 'ip': r['int_ip'], 'name': NAMES.get(r['int_ip']), 'title': tr('Traffic burst', 'Сплеск трафіку'),
                    'text': tr(f"{NAMES.get(r['int_ip']) or r['int_ip']}: {int(r['peak']) / 1e6:.0f} MB in 5 min — {float(r['peak']) / max(1.0, float(r['med'])):.0f}× the daily median.",
                               f"{NAMES.get(r['int_ip']) or r['int_ip']}: {int(r['peak']) / 1e6:.0f} MB за 5 хв — у {float(r['peak']) / max(1.0, float(r['med'])):.0f}× вище медіани за добу."), 'when': r['at']})
    return {'alerts': out}


def _str(v, n, field):
    if v is None or v == '':
        return ''
    if not isinstance(v, str) or len(v) > n:
        raise BadRequest(tr(f'{field}: up to {n} characters', f'{field}: до {n} символів'))
    return v.strip()


def device_from_body(b):
    try:
        ip = str(ipaddress.ip_address(str(b.get('ip', '')).strip()))
    except ValueError:
        raise BadRequest(tr('Invalid exporter IP address', 'Некоректна IP-адреса експорту'))
    cfg = {'name': _str(b.get('name'), 64, tr('name', 'назва')) or ip, 'vendor': _str(b.get('vendor'), 64, tr('vendor', 'виробник')), 'model': _str(b.get('model'), 64, tr('model', 'модель')),
           'city': _str(b.get('city'), 64, tr('city', 'місто')), 'sampling': _str(b.get('sampling'), 16, tr('sampling', 'вибірка')) or '1:1'}
    cc = _str(b.get('country'), 2, tr('country', 'країна')).upper()
    if cc and not cc.isalpha():
        raise BadRequest(tr('Country code: two Latin letters', 'Код країни — дві латинські літери'))
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
        raise BadRequest(tr('Interfaces are whole numbers; latitude/longitude are numbers within ±90/±180', 'Інтерфейси — цілі числа; широта/довгота — числа в межах ±90/±180'))
    pubs = []
    for x in (b.get('public_ips') or [])[:16]:
        try:
            pubs.append(str(ipaddress.ip_address(str(x).strip())))
        except ValueError:
            raise BadRequest(tr(f'Invalid public IP: {x}', f'Некоректна публічна IP: {x}'))
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
        raise BadRequest(tr('Invalid device IP address', 'Некоректна IP-адреса пристрою'))
    items = body.get('interfaces')
    if not isinstance(items, list) or len(items) > 1024:
        raise BadRequest(tr('A list of interfaces is expected', 'Очікується список інтерфейсів'))
    names, addrs, wan, local = {}, {}, [], None
    for it in items:
        try:
            idx = int(it.get('index'))
        except (TypeError, ValueError, AttributeError):
            raise BadRequest(tr('The interface index must be a number', 'Індекс інтерфейсу має бути числом'))
        if not 0 <= idx < 2**32:
            raise BadRequest(tr('Interface index out of range', 'Індекс інтерфейсу поза межами'))
        name = str(it.get('name') or '').strip()
        if len(name) > 32 or any(ord(ch_) < 32 for ch_ in name):
            raise BadRequest(tr(f'Interface {idx} name: up to 32 characters, no control characters', f'Назва інтерфейсу {idx}: до 32 символів, без керівних символів'))
        if name:
            names[str(idx)] = name
        raw = it.get('addrs') or []
        if isinstance(raw, str):
            raw = raw.replace(',', ' ').split()
        if not isinstance(raw, list) or len(raw) > 8:
            raise BadRequest(tr(f'Interface {idx}: up to 8 addresses', f'Інтерфейс {idx}: до 8 адрес'))
        try:
            # 'a.b.c.d/nn' keeps its prefix (interface address with mask), a bare address stays bare
            ok = [str(ipaddress.ip_interface(a) if '/' in a else ipaddress.ip_address(a)) for a in (str(x).strip() for x in raw) if a]
        except ValueError as e:
            raise BadRequest(tr(f'Interface {idx}: invalid address ({e})', f'Інтерфейс {idx}: некоректна адреса ({e})'))
        if ok:
            addrs[str(idx)] = ok
        role = it.get('role', 'lan')
        if role == 'wan':
            wan.append(idx)
        elif role == 'local':
            if local is not None:
                raise BadRequest(tr('Only one interface can have the role «the device itself»', 'Роль «сам пристрій» може мати лише один інтерфейс'))
            local = idx
        elif role != 'lan':
            raise BadRequest(tr('Role: lan, wan or local', 'Роль: lan, wan або local'))
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
        raise BadRequest(tr('The device is not configured', 'Пристрій не налаштований'))
    save_ui_exporter(ip, None)
    NAMES.reload()
    return {'ok': True}


ROUTES = {'/api/meta': api_meta, '/api/summary': api_summary, '/api/series': api_series, '/api/top': api_top, '/api/river': api_river,
          '/api/flows': api_flows, '/api/paths': api_paths, '/api/devmap': api_devmap, '/api/live': api_live, '/api/geo': api_geo, '/api/devices': api_devices, '/api/host': api_host,
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

    def cookie(self, name):
        c = SimpleCookie()
        try:
            c.load(self.headers.get('Cookie', ''))
        except Exception:
            return None
        m = c.get(name)
        return m.value if m else None

    def token(self):
        return self.cookie(COOKIE)

    def parse_request(self):
        ok = super().parse_request()
        if ok:
            set_lang(self.cookie('ft_lang'))      # errors and events in the language of the UI
        return ok

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
            if u.path == '/api/edition':
                return self.json(200, edition_info(admin=AUTH.users[user]['role'] == 'admin'))
            if u.path in ADMIN_GET:
                if AUTH.users[user]['role'] != 'admin':
                    return self.json(403, {'error': tr('Administrator rights required', 'Потрібні права адміністратора')})
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
        root = WEB_DIR
        full = os.path.realpath(os.path.join(root, path))
        if not full.startswith(os.path.realpath(root) + os.sep) or not os.path.isfile(full):
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
                '/api/license': lambda: post_license(body),
                '/api/license/deactivate': post_license_deactivate,
                '/api/license/checkin': post_license_checkin,
            }
            if u.path not in admin_routes:
                return self.json(404, {'error': 'not found'})
            if AUTH.users[user]['role'] != 'admin':
                return self.json(403, {'error': tr('Administrator rights required', 'Потрібні права адміністратора')})
            res = admin_routes[u.path]()
            return self.json(200, res if isinstance(res, dict) else {'ok': True})
        except AuthError as e:
            return self.json(e.status, {'error': str(e)})
        except BadRequest as e:
            return self.json(400, {'error': str(e)})
        except OSError as e:
            print(f'[flowtrack-api] POST {u.path}: {e}', flush=True)
            return self.json(500, {'error': tr('could not save', 'не вдалося зберегти')})


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

    def __init__(self, sock, handler, ctx=None):
        """sock: an already bound socket from common.open_listeners (any interface / address / family)."""
        self.address_family = sock.family
        super().__init__(sock.getsockname()[:2], handler, bind_and_activate=False)
        self.socket.close()
        self.socket = sock
        self.server_address = sock.getsockname()
        self.server_name, self.server_port = str(self.server_address[0]), self.server_address[1]
        self.server_activate()
        self.ctx = ctx

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
    try:
        LISTENERS = open_listeners(BIND, PORT, socket.SOCK_STREAM, log=lambda m: print(f'[flowtrack-api] {m}', flush=True))
    except (OSError, ValueError) as e:
        print(f'[flowtrack-api] cannot listen on FT_WEB_BIND={BIND!r} port {PORT}: {e}', flush=True)
        sys.exit(1)
    WEB_LISTEN = describe_listeners(LISTENERS)
    servers = [Server(sock, H, ctx) for sock, _ in LISTENERS]
    where = '; '.join(listen_label(x) for x in WEB_LISTEN)
    print(f'[flowtrack-api] serving {"https" if ctx else "http"} on TCP {PORT}: {where}'
          f'{" (plain HTTP redirects to HTTPS)" if ctx else ""}', flush=True)
    def watch_addresses(start=listen_signature(BIND)):
        while True:                      # an interface got another address (DHCP): exit, systemd restarts us
            time.sleep(30)
            sig = listen_signature(BIND)
            if sig != start:
                print(f'[flowtrack-api] listening addresses changed ({", ".join(start)} -> {", ".join(sig or ["none"])}); restarting', flush=True)
                os._exit(3)
    if any(dev for _, dev in LISTENERS):
        threading.Thread(target=watch_addresses, daemon=True).start()
    for srv in servers[1:]:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    servers[0].serve_forever()
