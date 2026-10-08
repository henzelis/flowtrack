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
import rollups  # noqa: E402
import topology  # noqa: E402
from common import (COMMUNITY, STATE_DIR, VERSION, CHError, ch, describe_listeners, edition, exporters_mtime, save_license, deactivate_license, license_checkin, iface_addrs, is_private, listen_signature,  # noqa: E402
                    listen_label, load_exporters, load_json, load_ui_exporter, open_listeners, save_ui_exporter, set_lang, tr)

# pre-aggregated 5-minute totals for long periods (rollups.py); FT_ROLLUPS=0 reads only the records (for comparisons)
USE_ROLLUPS = os.environ.get('FT_ROLLUPS', '1') != '0'
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
    ntime, fcols = len(where), set()     # what follows are filters: src() puts them over pre-aggregated data too
    try:
        flt = json.loads(q.get('f', ['[]'])[0])
    except ValueError:
        raise BadRequest('bad filter JSON')
    flt = flt if isinstance(flt, list) else []
    # one host chosen (positive `ip` filter): the records are read from its point of view (host_view), so what it
    # received from other inside hosts counts too, as dir 'internal_in'
    host = next((str(f.get('v', '')) for f in flt if isinstance(f, dict) and f.get('k') == 'ip' and not f.get('neg')), '')
    internal = "toString(dir) IN ('internal', 'internal_in')" if host else "dir = 'internal'"
    # traffic scope: internet (inside <-> outside, default), internal (inside <-> inside) or all
    traffic = q.get('t', ['internet'])[0]
    if traffic == 'internet':
        where.append("dir IN ('up', 'down')")
        fcols.add('dir')
    elif traffic == 'internal':
        where.append(internal)
        fcols.add('dir')
    for i, f in enumerate(flt):
        if not isinstance(f, dict):
            continue
        k, v, neg = f.get('k'), str(f.get('v', '')), bool(f.get('neg'))
        if k == 'ip' and neg:      # leave a host out: at either end
            cond = f'(int_ip = {{f{i}:String}} OR ext_ip = {{f{i}:String}})'
            fcols |= {'int_ip', 'ext_ip'}
        elif k == 'dir' and v == 'internal':
            cond = internal
            fcols.add('dir')
        elif k == 'asn':
            if v.upper().startswith('AS'):
                v = v[2:]
            if v.isdigit():
                cond = f'asn = {{f{i}:UInt32}}'
                fcols.add('asn')
            else:
                cond = f'positionCaseInsensitive(as_org, {{f{i}:String}}) > 0'
                fcols.add('as_org')
        elif k == 'host':         # either end (Path analysis: a host's conversations in both directions)
            cond = f'(int_ip = {{f{i}:String}} OR ext_ip = {{f{i}:String}})'
            fcols |= {'int_ip', 'ext_ip'}
        elif k == 'iface':
            if not v.isdigit():
                raise BadRequest('bad value for iface')
            cond = f'(in_if = {{f{i}:UInt32}} OR out_if = {{f{i}:UInt32}})'
            fcols |= {'in_if', 'out_if'}
        elif k in FILTERS:
            col, typ = FILTERS[k]
            if typ != 'String' and not v.isdigit():
                raise BadRequest(f'bad value for {k}')
            cond = f'{col} = {{f{i}:{typ}}}'
            fcols.add(col)
        else:
            continue
        where.append(f'NOT ({cond})' if neg else cond)
        params[f'f{i}'] = v
    step = STEP.get(rng) if not custom else None
    if not step:    # custom: the smallest round step that keeps the chart within ~300 points
        step = next((x for x in NICE_STEPS if rng / x <= 300), NICE_STEPS[-1])
    # for src(): the filters alone, the columns they use and the period ("_" params are not sent to ClickHouse)
    params['_flows'] = 'flows'
    if host:
        params['hv'] = host
        params['_flows'] = host_view(' AND '.join(where[:ntime]))
        fcols.add('ext_ip')          # no rollup holds both ends: the records are read
    params.update(_filt=' AND '.join(where[ntime:]) or '1', _fcols=fcols, _step=step,
                  _t0=max(t0, params['floor']), _t1=t1 if custom else None)
    return ' AND '.join(where), params, rng, step


DIR_HOST = "Enum8('up' = 1, 'down' = 2, 'internal' = 3, 'transit' = 4, 'internal_in' = 5)"


def host_view(period):
    """The records of the period with the host {hv} on the inside side: a record between two inside hosts in which
    it is the receiver (ext_ip) is turned round — int_ip / int_port = the host, ext_ip / ext_port = the sender — and
    gets dir 'internal_in', which the queries count as received (dir NOT IN ('up', 'internal'))."""
    r = "(dir = 'internal' AND ext_ip = {hv:String} AND int_ip != {hv:String})"
    return (f"(SELECT * REPLACE (if({r}, ext_ip, int_ip) AS int_ip, if({r}, int_ip, ext_ip) AS ext_ip, "
            f"if({r}, ext_port, int_port) AS int_port, if({r}, int_port, ext_port) AS ext_port, "
            f"CAST(if({r}, 'internal_in', toString(dir)) AS {DIR_HOST}) AS dir) "
            f"FROM flows WHERE {period} AND (int_ip = {{hv:String}} OR ext_ip = {{hv:String}}))")


def src(p, cols, t0=None, t1=None, bucketed=False):
    """`FROM … WHERE …` for a query over the scope in `p` (or [t0, t1)) that groups by / shows `cols`: whole 5-minute
    buckets from the pre-aggregated tables when one holds all the columns (and for a time series only when its step
    is a multiple of 5 minutes), the rest from the records. Rows have `flows` (records): sum(flows) counts them."""
    t0 = p['_t0'] if t0 is None else t0
    t1 = p['_t1'] if t1 is None and t0 == p['_t0'] else t1
    sql, _ = rollups.source(cols, t0, t1, p['_fcols'], use=USE_ROLLUPS, step=p['_step'] if bucketed else None, table=p.get('_flows', 'flows'))
    return f"{sql} WHERE {p['_filt']}"


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


# Distinct addresses are counted by their 64-bit hash: the same result (a collision among a million addresses has a
# chance of about 1 in 30 million) at less than half the cost of comparing the address strings themselves.
def api_summary(q):
    where, p, rng, step = scope(q)
    # the current and the previous window (each from its own source: a 5-minute total must not straddle them)
    cur0, prev0 = p['_t0'], max(p['t0'] - rng, p['floor'])
    both = lambda cols: (f"(SELECT {cols}, 1 AS cur FROM {src(p, cols.split(', '))} UNION ALL "   # noqa: E731
                         f"SELECT {cols}, 0 AS cur FROM {src(p, cols.split(', '), prev0, cur0)})")
    r = ch(f"""SELECT
        sumIf(bytes, cur) AS s_bytes, sumIf(bytes, cur AND dir IN ('up', 'internal')) AS s_up, sumIf(bytes, cur AND dir NOT IN ('up', 'internal')) AS s_down,
        sumIf(flows, cur) AS s_flows, sumIf(packets, cur) AS s_packets,
        sumIf(bytes, NOT cur) AS s_p_bytes, sumIf(flows, NOT cur) AS s_p_flows, toUnixTimestamp(min(ts)) AS s_oldest
      FROM {both('ts, dir, bytes, packets, flows')}""", p, fmt='JSON')[0]
    r = {k[2:]: int(v) for k, v in r.items()}
    # distinct inside and outside addresses, from the per-host and per-address totals
    h = ch(f"SELECT uniqExactIf(cityHash64(int_ip), cur) AS c, uniqExactIf(cityHash64(int_ip), NOT cur) AS p FROM {both('int_ip')}", p, fmt='JSON')[0]
    e = ch(f"SELECT uniqExactIf(cityHash64(ext_ip), cur) AS c, uniqExactIf(cityHash64(ext_ip), NOT cur) AS p FROM {both('ext_ip')}", p, fmt='JSON')[0]
    r.update(hosts=int(h['c']), p_hosts=int(h['p']), ips=int(h['c']) + int(e['c']), p_ips=int(h['p']) + int(e['p']))
    if r['oldest'] and r['oldest'] % rollups.BUCKET == 0:    # a rollup's bucket: the first record in it
        p['ob'] = r['oldest']
        first = ch(f"SELECT toUnixTimestamp(min(ts)) AS t, count() AS n FROM flows WHERE {where.replace('ts >= toDateTime({t0:UInt32})', 'ts >= toDateTime({ob:UInt32})', 1)} "
                   f"AND ts < toDateTime({{ob:UInt32}}) + {rollups.CUT}", p, fmt='JSON')
        if first and int(first[0]['n']):
            r['oldest'] = int(first[0]['t'])
    top = ch(f"SELECT service AS k, sum(bytes) AS b FROM {src(p, ['service'])} GROUP BY k ORDER BY b DESC LIMIT 1", p, fmt='JSON')
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
        s = src(p, [col], bucketed=True)
        rows = ch(f"""WITH (SELECT groupArray(k) FROM (SELECT toString({col}) AS k FROM {s} GROUP BY k ORDER BY sum(bytes) DESC, k LIMIT {{top:UInt8}})) AS tops
            SELECT {bucket} AS t, if(has(tops, toString({col})), toString({col}), '__other') AS k, sum(bytes) AS b
            FROM {s} GROUP BY t, k ORDER BY t, k""", p, fmt='JSON')
        return {'step': step, 'range': rng, 'from': p['t0'], 'to': p['t1'], 'rows': [[int(r['t']), r['k'], int(r['b'])] for r in rows]}
    rows = ch(f"""SELECT {bucket} AS t, sumIf(bytes, toString(dir) IN ('down', 'internal_in')) AS dn, sumIf(bytes, dir IN ('up', 'internal')) AS up,
            sumIf(bytes, dir NOT IN ('up', 'down')) AS other, sum(flows) AS fl
        FROM {src(p, [], bucketed=True)} GROUP BY t ORDER BY t""", p, fmt='JSON')
    return {'step': step, 'range': rng, 'from': p['t0'], 'to': p['t1'], 'rows': [[int(r['t']), int(r['dn']), int(r['up']), int(r['other']), int(r['fl'])] for r in rows]}


# a query that groups by something with millions of values (conversations) may use this much memory; the rest is
# left to the other widgets of the page, which load at the same time
CH_QUERY_MEMORY = int(os.environ.get('FT_CH_MEMORY_MB', '1024')) * 1024 * 1024 * 2 // 5


def ch_totals(query, params, settings=None):
    """A GROUP BY … WITH TOTALS query -> (rows, the totals row of all groups, unaffected by LIMIT)."""
    out = json.loads(ch(query, params, fmt='JSON', raw=True, settings=settings))
    return out['data'], out.get('totals') or {}


def attrs(rows, keys, what, where, p, cols=None):
    """Add per-key attributes (`service, country, …`: the same for every record of a key, or any one of them) to the
    top rows only: computing them for every group of a busy day (hundreds of thousands of outside addresses) cost
    more than the top list itself. The top keys are frequent, so a few of their records are found after reading a
    small part of the period (the query stops at its LIMIT); keys not met there are aggregated."""
    if not rows:
        return
    cols = cols or keys
    p = dict(p, **{f'a{i}': [r[k] for r in rows] for i, k in enumerate(keys)})
    cond = ' AND '.join(f'{c} IN {{a{i}:Array(String)}}' for i, c in enumerate(cols))
    s = src(p, list(cols) + what.split(', '))       # the per-address totals hold the attributes too
    got = {}
    for x in ch(f"SELECT {', '.join(cols)}, {what} FROM {s} AND {cond} LIMIT {20 * len(rows)}", p, fmt='JSON'):
        got.setdefault(tuple(x[c] for c in cols), x)
    if len(got) < len({tuple(r[k] for k in keys) for r in rows}):
        agg = ', '.join(f'any({w}) AS {w}' for w in what.split(', '))
        for x in ch(f"SELECT {', '.join(cols)}, {agg} FROM {s} AND {cond} GROUP BY {', '.join(cols)}", p, fmt='JSON'):
            got.setdefault(tuple(x[c] for c in cols), x)
    for r in rows:
        for k, v in got.get(tuple(r[k] for k in keys), {}).items():
            if k not in cols:
                r[k] = v


def api_top(q):
    where, p, rng, step = scope(q)
    totals = {}
    dim = q1(q, 'dim', 'int_ip')
    p['lim'] = max(1, min(q1(q, 'limit', '10', int), 500))
    if dim == 'conv':
        # a busy day has millions of host-peer pairs: they are grouped by the pair's 64-bit hash (8 bytes instead of
        # two address strings; a collision among 10 million pairs has a chance of about 1 in 300,000), then the pairs
        # shown are read exactly with what they are
        sums = """sumIf(bytes, dir IN ('up', 'internal')) AS up, sumIf(bytes, dir NOT IN ('up', 'internal')) AS dn, count() AS fl, sum(packets) AS pk"""
        try:
            top, tb = ch_totals(f"""SELECT cityHash64(int_ip, ext_ip) AS h, sum(bytes) AS b FROM {p['_flows']} WHERE {where}
                GROUP BY h WITH TOTALS ORDER BY b DESC LIMIT {{lim:UInt16}}""", p,      # beyond its memory share: on disk
                settings={'max_memory_usage': CH_QUERY_MEMORY, 'max_bytes_before_external_group_by': CH_QUERY_MEMORY * 2 // 5})
            p['hs'], totals = [int(r['h']) for r in top], {'up': tb.get('b', 0), 'dn': 0}
        except CHError as ex:
            if 'Code: 241' not in str(ex):
                raise
            # still out of memory (other panels loading at the same time): the heaviest candidates by a bounded-memory
            # count (Space-Saving), many times the rows asked for, so the order of those shown is right
            p['k'] = min(max(200, p['lim'] * 20), 5000)
            cand = ch(f"SELECT topKWeighted({{k:UInt16}})(cityHash64(int_ip, ext_ip), bytes) AS t, sum(bytes) AS b FROM {p['_flows']} WHERE {where}", p, fmt='JSON')[0]
            p['hs'], totals = [int(h) for h in cand['t']], {'up': cand['b'], 'dn': 0}
        rows = ch(f"""SELECT int_ip, ext_ip, {sums}, any(service) AS service, any(country) AS country, any(city) AS city FROM {p['_flows']}
            WHERE {where} AND cityHash64(int_ip, ext_ip) IN {{hs:Array(UInt64)}}
            GROUP BY int_ip, ext_ip ORDER BY up + dn DESC LIMIT {{lim:UInt16}}""", p, fmt='JSON') if p['hs'] else []
        for r in rows:
            r['name'] = NAMES.get(r['int_ip'])
    elif dim == 'host_svc':     # each inside host with its main service and L7 protocol
        rows, totals = ch_totals(f"""SELECT int_ip AS k, sumIf(bytes, dir IN ('up', 'internal')) AS up, sumIf(bytes, dir NOT IN ('up', 'internal')) AS dn,
                sum(flows) AS fl, 0 AS pk
            FROM {src(p, ['int_ip'])} GROUP BY k WITH TOTALS ORDER BY up + dn DESC LIMIT {{lim:UInt16}}""", p)
        if rows:                # the main service / L7 / protocol of the hosts shown (per host x service of a whole day
            p['hs'] = [r['k'] for r in rows]                                   # did not fit into memory)
            main = {x['k']: x for x in ch(f"""SELECT k, argMax(service, b) AS service, argMax(l7, b) AS l7, argMax(proto, b) AS proto
                FROM (SELECT int_ip AS k, service, l7, proto, sum(bytes) AS b FROM {src(p, ['int_ip', 'service', 'l7', 'proto'])} AND int_ip IN {{hs:Array(String)}}
                      GROUP BY k, service, l7, proto) GROUP BY k""", p, fmt='JSON')}
            for r in rows:
                r.update({c: main.get(r['k'], {}).get(c, d) for c, d in (('service', ''), ('l7', ''), ('proto', 0))})
        for r in rows:
            r['name'] = NAMES.get(r['k'])
            r['proto'] = int(r['proto'])
    elif dim == 'int_ip' and q1(q, 't', 'internet') == 'internal':
        # inside <-> inside: a host is both the source (int_ip) and the destination (ext_ip) of records;
        # count what it sent (up) and what it received (dn)
        rows = ch(f"""SELECT k, sum(u) AS up, sum(d) AS dn, sum(f) AS fl, sum(pk_) AS pk FROM (
                SELECT if(toString(dir) = 'internal_in', ext_ip, int_ip) AS k, bytes AS u, 0 AS d, 1 AS f, packets AS pk_ FROM {p['_flows']} WHERE {where}
                UNION ALL SELECT if(toString(dir) = 'internal_in', int_ip, ext_ip) AS k, 0 AS u, bytes AS d, 1 AS f, packets AS pk_ FROM {p['_flows']} WHERE {where})
            GROUP BY k ORDER BY up + dn DESC LIMIT {{lim:UInt16}}""", p, fmt='JSON')
        for r in rows:
            r['name'] = NAMES.get(r['k'])
    elif dim in DIMS:
        col = DIMS[dim]
        extra, cols = '', [col]
        if dim == 'asn':
            extra, cols = ', any(as_org) AS as_org, any(country) AS country', [col, 'as_org', 'country']
        elif dim == 'service':
            extra, cols = ', uniqExact(cityHash64(int_ip)) AS hosts, any(l7) AS l7', [col, 'int_ip', 'l7']
        elif dim == 'city':
            extra, cols = ', any(country) AS country, any(lat) AS la, any(lon) AS lo', [col, 'country', 'lat', 'lon']
        elif dim == 'ext_port':     # its hosts and peers: below, for the ports shown
            extra, cols = ', any(l7) AS l7, any(proto) AS proto_n, any(service) AS service', [col, 'l7', 'proto', 'service']
        rows, totals = ch_totals(f"""SELECT toString({col}) AS k, sumIf(bytes, dir IN ('up', 'internal')) AS up, sumIf(bytes, dir NOT IN ('up', 'internal')) AS dn,
                sum(flows) AS fl, sum(packets) AS pk {extra}
            FROM {src(p, cols)} GROUP BY k WITH TOTALS ORDER BY up + dn DESC LIMIT {{lim:UInt16}}""", p)
        if dim == 'ext_port' and rows:
            p['ports'] = [int(r['k']) for r in rows]
            hp = {str(x['k']): x for x in ch(f"""SELECT ext_port AS k, uniqExact(cityHash64(int_ip)) AS hosts, uniqExact(cityHash64(ext_ip)) AS peers
                FROM {p['_flows']} WHERE {where} AND ext_port IN {{ports:Array(UInt64)}} GROUP BY k""", p, fmt='JSON')}
            for r in rows:
                r.update(hosts=int(hp.get(r['k'], {}).get('hosts', 0)), peers=int(hp.get(r['k'], {}).get('peers', 0)))
        if dim == 'ext_ip':     # 200k+ outside addresses a day: what each one is, only for those shown
            attrs(rows, ('k',), 'service, country, city, asn, as_org', where, p, cols=('ext_ip',))
        if dim == 'int_ip':
            for r in rows:
                r['name'] = NAMES.get(r['k'])
    else:
        raise BadRequest('bad dim')
    if dim == 'int_ip' and q1(q, 't', 'internet') == 'internal':     # there every record counts for two hosts
        tot = ch(f"SELECT sum(bytes) AS b FROM {p['_flows']} WHERE {where}", p, fmt='JSON')[0]['b']
    else:                       # up + dn of all groups, computed in the same pass (WITH TOTALS; no 2nd scan)
        tot = int(totals.get('up') or 0) + int(totals.get('dn') or 0)
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
            (SELECT groupArray(k) FROM (SELECT int_ip AS k FROM {p['_flows']} WHERE {where} GROUP BY k ORDER BY sum({metric}) DESC LIMIT {{n:UInt8}})) AS l,
            (SELECT groupArray(k) FROM (SELECT ext_ip AS k FROM {p['_flows']} WHERE {where} GROUP BY k ORDER BY sum({metric}) DESC LIMIT {{n:UInt8}})) AS r,
            (SELECT uniqExact(cityHash64(int_ip)) FROM {p['_flows']} WHERE {where}) AS nl, (SELECT uniqExact(cityHash64(ext_ip)) FROM {p['_flows']} WHERE {where}) AS nr""", p, fmt='JSON')[0]
    left, right = tops['l'], tops['r']
    p['L'], p['R'] = left, right
    links = ch(f"""SELECT if(has({{L:Array(String)}}, int_ip), int_ip, '__other') AS l, if(has({{R:Array(String)}}, ext_ip), ext_ip, '__other') AS r,
            sumIf({metric}, dir IN ('up', 'internal')) AS up, sumIf({metric}, dir NOT IN ('up', 'internal')) AS dn, toUnixTimestamp(max(ts)) AS t
        FROM {p['_flows']} WHERE {where} GROUP BY l, r""", p, fmt='JSON')
    info = {}
    if right:
        for r in ch(f"SELECT ext_ip, any(service) AS service, any(country) AS country, any(city) AS city FROM {p['_flows']} WHERE {where} AND has({{R:Array(String)}}, ext_ip) GROUP BY ext_ip", p, fmt='JSON'):
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
            uniqExact(cityHash64(int_ip)) AS hosts, topKWeighted(3)(service, bytes) AS services,
            sumIf(bytes, dir IN ('up', 'down')) AS internet, sumIf(bytes, toString(dir) IN ('internal', 'internal_in')) AS internal
        FROM {p['_flows']} WHERE {where} GROUP BY in_if, out_if ORDER BY v DESC LIMIT 80""", p, fmt='JSON')
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
            sumIf({metric}, dir NOT IN ('up', 'down')) AS other, count() AS fl, uniqExact(cityHash64(int_ip)) AS hosts,
            topKWeighted(3)(service, toUInt64({metric})) AS services
        FROM {p['_flows']} WHERE {where} GROUP BY in_if, out_if ORDER BY v DESC LIMIT 60""", p, fmt='JSON')
    # an inside host enters the box through: in_if when it sends (up, or the source of an internal record),
    # out_if when it receives (down, or the destination of an internal record; internal_in = a record turned round
    # for a chosen host, which received it: int_ip is the destination, ext_ip the source)
    inside = ch(f"""SELECT host, iface, sum(u) AS up, sum(d) AS dn, sum(u) + sum(d) AS v FROM (
            SELECT int_ip AS host, if(toString(dir) IN ('down', 'internal_in'), out_if, in_if) AS iface, if(toString(dir) IN ('down', 'internal_in'), 0, {metric}) AS u,
                   if(toString(dir) IN ('down', 'internal_in'), {metric}, 0) AS d
                FROM {p['_flows']} WHERE {where} AND toString(dir) IN ('up', 'down', 'internal', 'internal_in')
            UNION ALL SELECT ext_ip, if(dir = 'internal', out_if, in_if), if(dir = 'internal', 0, {metric}), if(dir = 'internal', {metric}, 0)
                FROM {p['_flows']} WHERE {where} AND toString(dir) IN ('internal', 'internal_in'))
        GROUP BY host, iface ORDER BY v DESC LIMIT {{n:UInt8}} BY iface LIMIT 60""", p, fmt='JSON')
    outside = ch(f"""SELECT ext_ip AS host, if(dir = 'up', out_if, in_if) AS iface, sumIf({metric}, dir = 'up') AS up, sumIf({metric}, dir = 'down') AS dn,
            sum({metric}) AS v, any(service) AS service, any(country) AS country, any(city) AS city
        FROM {p['_flows']} WHERE {where} AND dir IN ('up', 'down') GROUP BY host, iface ORDER BY v DESC LIMIT {{n:UInt8}}""", p, fmt='JSON')
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


def network_q(q):
    """Path analysis looks at every device and all traffic: device filters are dropped (the Point of View is chosen
    instead), the traffic scope defaults to all, and a host filter (ip / dst) takes the host's packets in both
    directions — in an internal record int_ip is the sender, so `ip` alone would keep only what the host sent."""
    q = dict(q)
    try:
        flt = json.loads(q.get('f', ['[]'])[0])
    except ValueError:
        raise BadRequest('bad filter JSON')
    flt = [f for f in (flt if isinstance(flt, list) else []) if isinstance(f, dict) and f.get('k') != 'device']
    q['f'] = [json.dumps([{**f, 'k': 'host'} if f.get('k') in ('ip', 'dst') else f for f in flt])]
    q.setdefault('t', ['all'])
    return q


def network_topology(q):
    where, p, rng, step = scope(network_q(q))
    where, live = live_window(q, where, p, default='0')
    cfg = exporters_cfg()
    known = {a.split('/')[0] for c in cfg.values() for v in c.get('if_addrs', {}).values() for a in v} | set(cfg) | \
        {a for c in cfg.values() for a in c.get('public_ips', [])}
    topo = topology.build(cfg, *topology.query(ch, where, p, known))
    for lk in topo['links']:
        for e in ('a', 'b'):
            i = lk[e + '_if']
            lk[e + '_name'] = (cfg.get(lk[e], {}).get('if_names', {}).get(str(i)) or f'if {i}') if i is not None else ''
    return topo, cfg, where, p, live, rng


def api_topology(q):
    """Path analysis: the devices that are layer-3 neighbours of the Point of View (`pov`), `depth` links deep, with
    the traffic of every link as each end recorded it. `devices` lists them all for the selector."""
    topo, cfg, where, p, live, rng = network_topology(q)
    devs = sorted(d for d in topo['nodes'] if d != topology.INTERNET)
    pov = q1(q, 'pov', '')
    if pov not in topo['nodes']:
        pov = max(devs, key=lambda d: sum(1 for lk in topo['links'] if d in (lk['a'], lk['b']))) if devs else ''
    depth = max(1, min(q1(q, 'depth', '1', int), 6))
    part = topology.around(topo, pov, depth) if pov else {'nodes': [], 'links': []}
    degree = {d: len({lk['b'] if lk['a'] == d else lk['a'] for lk in topo['links'] if d in (lk['a'], lk['b']) and topology.INTERNET not in (lk['a'], lk['b'])})
              for d in devs}
    devices = [{**topo['nodes'][d], 'neighbours': degree[d]} for d in devs]
    return {'pov': pov, 'depth': depth, 'devices': devices, **part, 'live': live, 'window': p.get('win', rng),
            'window_end': p.get('wend'), 'range': rng}


def api_path(q):
    """Path analysis: the hops of the traffic from `src` to `dst` (an address or a network each) across the
    exporting devices, in order, with gaps where a device on the way recorded none of it."""
    def net(k):
        v = q1(q, k, '').strip()
        try:
            return str(ipaddress.ip_network(v, strict=False))
        except ValueError:
            raise BadRequest(f'bad {k}')
    s, d = net('src'), net('dst')
    topo, cfg, where, p, live, rng = network_topology(q)
    rows = topology.path_query(ch, where, p, s, d)
    out = topology.path(topo, cfg, rows)
    return {'src': s, 'dst': d, **out, 'live': live, 'window': p.get('win', rng), 'window_end': p.get('wend'), 'range': rng}


def api_flows(q):
    where, p, rng, step = scope(q)
    p['lim'] = max(1, min(q1(q, 'limit', '50', int), 1000))
    rows = ch(f"""SELECT toUnixTimestamp(ts) AS t, toFloat64(ts_start) AS t0, exporter, in_if, out_if, toString(dir) AS dir, int_ip, int_port, ext_ip, ext_port,
            proto, nat_ip, nat_port, bytes, packets, l7, service, country, city, asn, as_org, sampling
        FROM {p['_flows']} WHERE {where} ORDER BY ts DESC LIMIT {{lim:UInt16}}""", p, fmt='JSON')
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
        FROM {p['_flows']} WHERE {where} AND ts > toDateTime({{since:UInt32}}) AND lat != 0 ORDER BY ts LIMIT 300""", p, fmt='JSON')
    for r in rows:
        r['t'], r['bytes'], r['ext_port'] = int(r['t']), int(r['bytes']), int(r['ext_port'])
        r['name'] = NAMES.get(r['int_ip'])
    return {'rows': rows, 'now': int(time.time())}


def api_geo(q):
    where, p, rng, step = scope(q)
    where, live = live_window(q, where, p, default='0')
    # the live window is 2 minutes of records; a period comes from the per-city totals (has_ll = has coordinates)
    frm = f"{p['_flows']} WHERE {where} AND lat != 0" if live else f"{src(p, ['exporter', 'country', 'city', 'has_ll', 'lat', 'lon'])} AND has_ll"
    rows = ch(f"""SELECT exporter, country, city, any(lat) AS la, any(lon) AS lo, sumIf(bytes, dir IN ('up', 'internal')) AS up, sumIf(bytes, dir NOT IN ('up', 'internal')) AS dn,
            {'count()' if live else 'sum(flows)'} AS fl
        FROM {frm} GROUP BY exporter, country, city ORDER BY up + dn DESC, exporter, country, city LIMIT 300""", p, fmt='JSON')
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


class Cache:
    """Answers over long periods (6 hours or more, or a custom period that has ended) for 60 s: a page asks several
    of them at once, other users and reloads ask the same, and over a day of a busy network each one reads tens of
    millions of records. Live windows and everything else are always fresh; the minute is short against the 5-minute
    steps of a day's charts."""
    TTL, SIZE = 60, 300
    PATHS = {'/api/summary', '/api/series', '/api/top', '/api/geo', '/api/river', '/api/paths', '/api/devmap', '/api/host', '/api/topology', '/api/path'}
    LIVE_BY_DEFAULT = {'/api/river'}

    def __init__(self):
        self.lock, self.items = threading.Lock(), {}

    def key(self, path, q):
        if path not in self.PATHS or q.get('live', ['1' if path in self.LIVE_BY_DEFAULT else '0'])[0] == '1':
            return None
        try:
            if q.get('from') and q.get('to'):
                if int(q['to'][0]) > time.time() - 60:       # a custom period still running
                    return None
            elif RANGES.get(q.get('range', ['24h'])[0], 86400) < 6 * 3600:
                return None
        except ValueError:
            return None
        return path + '?' + '&'.join(f'{k}={v}' for k, v in sorted((k, tuple(v)) for k, v in q.items()))

    def clear(self):
        with self.lock:
            self.items.clear()

    def get(self, path, q):
        k = self.key(path, q)
        with self.lock:
            hit = self.items.get(k) if k else None
            return hit[1] if hit and time.time() - hit[0] < self.TTL else None

    def put(self, path, q, body):
        k = self.key(path, q)
        if not k:
            return
        with self.lock:
            now = time.time()
            if len(self.items) >= self.SIZE:
                for x in [x for x, v in self.items.items() if now - v[0] >= self.TTL] or sorted(self.items, key=lambda x: self.items[x][0])[:self.SIZE // 4]:
                    del self.items[x]
            self.items[k] = (now, body)


CACHE = Cache()
ROUTES = {'/api/meta': api_meta, '/api/summary': api_summary, '/api/series': api_series, '/api/top': api_top, '/api/river': api_river,
          '/api/flows': api_flows, '/api/paths': api_paths, '/api/devmap': api_devmap, '/api/topology': api_topology, '/api/path': api_path, '/api/live': api_live, '/api/geo': api_geo, '/api/devices': api_devices, '/api/host': api_host,
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
                q = parse_qs(u.query)
                body = CACHE.get(u.path, q)
                if body is None:
                    body = json.dumps(fn(q), default=str).encode()
                    CACHE.put(u.path, q, body)
                return self.send(200, body, 'application/json')
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
        CACHE.clear()            # names of hosts and devices, exporters' settings… may change: answer fresh
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
