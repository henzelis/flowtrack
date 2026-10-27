#!/usr/bin/env python3
"""FlowSphera API + web UI server (stdlib HTTP server, ClickHouse over HTTP).

All user input reaches ClickHouse only as bound query parameters ({name:Type}),
never by string interpolation; dimension names come from fixed whitelists.
"""
import hashlib
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
import detect  # noqa: E402
import directory  # noqa: E402
import reports  # noqa: E402
import notify  # noqa: E402
import reputation  # noqa: E402
import capacity  # noqa: E402
import ifcounters  # noqa: E402
import common  # noqa: E402
import licensing  # noqa: E402
import rollups  # noqa: E402
import snmp  # noqa: E402
import topology  # noqa: E402
from common import (web_query, COMMUNITY, STATE_DIR, VERSION, CHError, ch, describe_listeners, edition, exporters_mtime, save_license, deactivate_license, license_checkin, license_refresh, iface_addrs, is_private, listen_signature,  # noqa: E402
                    listen_label, load_exporters, load_json, load_ui_exporter, open_listeners, save_ui_exporter, set_lang, tr,
                    trn, N_, get_lang, languages)

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
LONG = 86400            # (1.17.0) from a day on a period is answered from the rollups only (see scope)
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
                # (1.17.0) every 5-minute total keeps the longest days of its records: the small table answers once
                # its history is in (reading every record took seconds on a month of a busy network)
                tbl = 'agg_traffic' if rollups.ready_from('agg_traffic') == 0 else 'flows'
                _stored['days'] = int(ch(f"SELECT max(keep_days) AS d FROM {tbl}", fmt='JSON')[0]['d'])
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
DIR_VALUES = ('up', 'down', 'internal', 'transit', 'internal_back')
DIMS = {'int_ip': 'int_ip', 'ext_ip': 'ext_ip', 'service': 'service', 'l7': 'l7', 'country': 'country', 'city': 'city',
        'asn': 'asn', 'ext_port': 'ext_port', 'exporter': 'exporter', 'dir': 'dir', 'proto': 'proto'}


# (1.16.0) DSCP classes (RFC 4594 names); 255 = the exporter did not send the marking
DSCP_NAMES = {0: 'CS0', 8: 'CS1', 10: 'AF11', 12: 'AF12', 14: 'AF13', 16: 'CS2', 18: 'AF21', 20: 'AF22', 22: 'AF23', 24: 'CS3',
              26: 'AF31', 28: 'AF32', 30: 'AF33', 32: 'CS4', 34: 'AF41', 36: 'AF42', 38: 'AF43', 40: 'CS5', 44: 'VA', 46: 'EF',
              48: 'CS6', 56: 'CS7', 255: '?'}
DSCP_BY_NAME = {v: k for k, v in DSCP_NAMES.items() if v != '?'} | {'BE': 0, 'DEFAULT': 0}


def dscp_value(v):
    """'46', 'EF', 'af41', 'BE' -> the number, None when it is neither."""
    v = str(v).strip().upper()
    if v.isdigit():
        n = int(v)
        return n if n < 64 or n == 255 else None
    return DSCP_BY_NAME.get(v)

# ------------------------------------------------------------------ names

class Names:
    """Inside host names: hosts.json (manual) > exporter self IPs > reverse DNS (cached, async)."""

    def __init__(self):
        self.pool = ThreadPoolExecutor(max_workers=4)
        self.cache, self.pending = {}, set()
        self.lock = threading.Lock()
        self.reload()

    def reload(self):
        self.manual = common.load_host_names()
        self.raw = load_exporters()                 # as configured (the settings forms edit this)
        self.exporters = snmp.merge(self.raw)       # + interface names / addresses from SNMP where none were entered
        self.mtime = (exporters_mtime(), snmp.data_mtime())
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

    def get(self, ip, lookup=True):
        """lookup=False (1.14.1): only names known already — an export of 100,000 hosts must not queue as many
        reverse DNS lookups"""
        if ip in self.manual:
            return self.manual[ip]
        if ip in self.self_ips:
            return self.self_ips[ip]
        with self.lock:
            hit = self.cache.get(ip)
            if lookup and (hit is None or time.time() - hit[1] > 3600) and ip not in self.pending and is_private(ip):
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
    nominal = t1 - t0           # a preset's own length picks its chart step
    if t1 - t0 >= LONG:
        # (1.17.0) a period of a day or more starts (and a chosen one ends) on a whole hour: every table answers it
        # from whole buckets — the hourly ones too — without a raw edge, and all panels cover the same span
        t0 = t0 // 3600 * 3600
        if custom:
            t1 = -(-t1 // 3600) * 3600
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
    # hosts chosen (positive `ip` filters): the records are read from their point of view (host_view), so the
    # sessions in which one of them is the server count too
    # (1.8.6) `ip` and `dst` take a network too (172.16.0.0/24): its addresses, any of them
    for f in flt:
        if isinstance(f, dict) and f.get('k') in ('ip', 'dst', 'host') and '/' in str(f.get('v', '')):
            f['v'] = net_value(f['v'])
    host = sorted({str(f.get('v', '')) for f in flt if isinstance(f, dict) and f.get('k') == 'ip' and not f.get('neg') and f.get('v')})
    hnets = [h for h in host if '/' in h]
    host = [h for h in host if '/' not in h]
    traffic = q.get('t', ['internet'])[0]
    # (1.8.7) net:NAME — the addresses whose narrowest named network is NAME; inside <-> inside its hosts are read
    # from their point of view like ip: (between inside and outside the inside side is int_ip already: the rollups do)
    nets = common.load_networks()
    for f in flt:
        if isinstance(f, dict) and f.get('k') == 'net':
            v = str(f.get('v', '')).strip().lower()
            hit = [x for x in nets if x['name'].lower() == v]
            if not hit:
                raise BadRequest(tr('no network named {name}', name=str(f.get('v', ''))[:50]))
            f['v'] = hit[0]['name']
            if not f.get('neg') and traffic != 'internet':
                hnets += [x['net'] for x in hit if x['net'] not in hnets]
    internal = "dir IN ('internal', 'internal_back')"
    # traffic scope: internet (inside <-> outside, default), internal (inside <-> inside) or all
    if traffic == 'internet':
        where.append("dir IN ('up', 'down')")
        fcols.add('dir')
    elif traffic == 'internal':
        where.append(internal)
        fcols.add('dir')
    anyof = {}          # (1.8.3) several positive filters of one key: any of them (device A or device B)
    for i, f in enumerate(flt):
        if not isinstance(f, dict):
            continue
        k, v, neg = f.get('k'), str(f.get('v', '')), bool(f.get('neg'))
        if k in ('ip', 'dst', 'host') and '/' in v:      # a network: its addresses (at either end for -ip and host)
            one = lambda col: f'isIPAddressInRange({col}, {{f{i}:String}})'      # noqa: E731
            cond = one('ext_ip') if k == 'dst' else f"({one('int_ip')} OR {one('ext_ip')})" if (neg or k == 'host') else one('int_ip')
            fcols |= {'ext_ip'} if k == 'dst' else {'int_ip', 'ext_ip'} if (neg or k == 'host') else {'int_ip'}
        elif k == 'net':
            ne = net_expr('int_ip', params)
            cond = f"({ne} = {{f{i}:String}} OR {net_expr('ext_ip', params)} = {{f{i}:String}})" if neg else f'{ne} = {{f{i}:String}}'
            fcols |= {'int_ip', 'ext_ip'} if neg else {'int_ip'}
        elif k == 'ip' and neg:      # leave a host out: at either end
            cond = f'(int_ip = {{f{i}:String}} OR ext_ip = {{f{i}:String}})'
            fcols |= {'int_ip', 'ext_ip'}
        elif k == 'dir' and v == 'internal':
            cond = internal
            fcols.add('dir')
        elif k == 'asn':
            if v.upper().startswith('AS'):
                v = v[2:]
            if v.isascii() and v.isdigit():
                cond = f'asn = {{f{i}:UInt32}}'
                fcols.add('asn')
            else:
                cond = f'positionCaseInsensitive(as_org, {{f{i}:String}}) > 0'
                fcols.add('as_org')
        elif k == 'host':         # either end (Path analysis: a host's conversations in both directions)
            cond = f'(int_ip = {{f{i}:String}} OR ext_ip = {{f{i}:String}})'
            fcols |= {'int_ip', 'ext_ip'}
        elif k == 'dscp':         # (1.16.0) a DSCP class by number (46) or name (EF, AF41, CS1, BE); 255 = not sent
            n = dscp_value(v)
            if n is None:
                raise BadRequest(tr('Unknown DSCP class: {v}', v=v[:20]))
            params[f'f{i}n'] = n
            cond = f'dscp = {{f{i}n:UInt8}}'
            fcols.add('dscp')
        elif k == 'iface':
            if v.isascii() and v.isdigit():
                cond = f'(in_if = {{f{i}:UInt32}} OR out_if = {{f{i}:UInt32}})'
                fcols |= {'in_if', 'out_if'}
            else:                 # (1.13.0) by name (wan, port1, ether1): that interface on each device that has one
                hits = ifaces_named(v)
                if not hits:
                    raise BadRequest(tr('no interface named {name}', name=v[:50]))
                for n, (dev, idx) in enumerate(hits):
                    params[f'f{i}d{n}'], params[f'f{i}i{n}'] = dev, idx
                cond = '(' + ' OR '.join(f'(exporter = {{f{i}d{n}:String}} AND (in_if = {{f{i}i{n}:UInt32}} OR out_if = {{f{i}i{n}:UInt32}}))'
                                         for n in range(len(hits))) + ')'
                fcols |= {'exporter', 'in_if', 'out_if'}
        elif k in FILTERS:
            col, typ = FILTERS[k]
            if typ != 'String' and not (v.isascii() and v.isdigit()) or k == 'dir' and v not in DIR_VALUES:
                raise BadRequest(f'bad value for {k}')
            cond = f'{col} = {{f{i}:{typ}}}'
            fcols.add(col)
        else:
            continue
        if neg:
            where.append(f'NOT ({cond})')
        else:
            anyof.setdefault(k, []).append(cond)
        params[f'f{i}'] = v
    for conds in anyof.values():
        where.append(conds[0] if len(conds) == 1 else '(' + ' OR '.join(conds) + ')')
    step = STEP.get(nominal) if not custom else None
    if not step:    # custom: the smallest round step that keeps the chart within ~300 points
        step = next((x for x in NICE_STEPS if rng / x <= 300), NICE_STEPS[-1])
    # for src(): the filters alone, the columns they use and the period ("_" params are not sent to ClickHouse)
    params['_flows'] = 'flows'
    # (1.17.0) between inside and outside the inside host is int_ip already (nothing is turned): the rollups that hold
    # int_ip answer, only inside <-> inside needs the records turned to the host
    if (host or hnets) and traffic != 'internet':
        params['hv'] = host
        params.update({f'hn{j}': n for j, n in enumerate(hnets)})
        # (1.17.0) not the window's own start: summary compares with the window before it, which then had no records
        # (ClickHouse moves each query's own period into the view: the same parts are read)
        params['_flows'] = host_view(' AND '.join(['ts >= toDateTime({floor:UInt32})'] + where[2:ntime]), len(hnets))
        params['_turn'] = turn_cond(len(hnets))     # (1.17.0) the rollups answer too: rollups.source(turn=…)
    params.update(_filt=' AND '.join(where[ntime:]) or '1', _fcols=fcols, _step=step,
                  _t0=max(t0, params['floor']), _t1=t1 if custom else None)
    return ' AND '.join(where), params, rng, step


DIR_HOST = rollups.DIR


def net_expr(col, p):
    """(1.8.7) SQL: the name of the narrowest named network holding the address in `col`, or ''; the networks go to
    the params `p` (nc0, nn0, …)."""
    nets = common.load_networks()
    if not nets:
        return "''"
    for j, x in enumerate(nets):
        p[f'nc{j}'], p[f'nn{j}'] = x['net'], x['name']
    return 'multiIf(' + ', '.join(f'isIPAddressInRange({col}, {{nc{j}:String}}), {{nn{j}:String}}' for j in range(len(nets))) + ", '')"


def net_value(v):
    """A network as typed (172.16.0.5/24 -> 172.16.0.0/24); BadRequest for one that is not."""
    try:
        return str(ipaddress.ip_network(str(v).strip(), strict=False))
    except ValueError:
        raise BadRequest(tr('not a network: {value}', value=str(v)[:50])) from None


def host_of(nets=0):
    """SQL over a column: one of the chosen hosts {hv}, or (1.8.6) an address in one of the networks {hn0} …"""
    return lambda x: '(' + ' OR '.join([f'{x} IN {{hv:Array(String)}}'] + [f'isIPAddressInRange({x}, {{hn{j}:String}})' for j in range(nets)]) + ')'


def turn_cond(nets=0):
    """SQL over a record: a chosen host was the server of this inside session (and the client was not one of them —
    a session inside a network keeps its sides): host_view turns it round, and (1.17.0) rollups.source over agg_conv"""
    of = host_of(nets)
    return f"(dir IN ('internal', 'internal_back') AND {of('ext_ip')} AND NOT {of('int_ip')})"


def host_view(period, nets=0):
    """The records of the period with the hosts {hv} (a list) on the inside side. Between inside hosts int_ip is the client:
    a session in which the host is the server (ext_ip) is turned round — int_ip / int_port = the host, ext_ip /
    ext_port = its client — and its directions swapped, so for the host too 'internal' = sent, 'internal_back' =
    received (the queries count dir IN ('up', 'internal') as sent). `turned` = 1 on those records."""
    of, r = host_of(nets), turn_cond(nets)
    return (f"(SELECT * REPLACE (if({r}, ext_ip, int_ip) AS int_ip, if({r}, int_ip, ext_ip) AS ext_ip, "
            f"if({r}, ext_port, int_port) AS int_port, if({r}, int_port, ext_port) AS ext_port, "
            f"CAST(if({r}, if(dir = 'internal', 'internal_back', 'internal'), toString(dir)) AS {DIR_HOST}) AS dir), toUInt8({r}) AS turned "
            f"FROM flows WHERE {period} AND ({of('int_ip')} OR {of('ext_ip')}))")     # IN: the index is used


def src(p, cols, t0=None, t1=None, bucketed=False):
    """`FROM … WHERE …` for a query over the scope in `p` (or [t0, t1)) that groups by / shows `cols`: whole 5-minute
    buckets from the pre-aggregated tables when one holds all the columns (and for a time series only when its step
    is a multiple of 5 minutes), the rest from the records. Rows have `flows` (records): sum(flows) counts them."""
    t0 = p['_t0'] if t0 is None else t0
    t1 = p['_t1'] if t1 is None and t0 == p['_t0'] else t1
    sql, _ = rollups.source(cols, t0, t1, p['_fcols'], use=USE_ROLLUPS, step=p['_step'] if bucketed else None, table=p.get('_flows', 'flows'), turn=p.get('_turn'))
    return f"{sql} WHERE {p['_filt']}"


def q1(q, key, default, cast=str):
    try:
        return cast(q.get(key, [default])[0])
    except (TypeError, ValueError):
        raise BadRequest(f'bad {key}')


def host_obj(ip):
    return {'ip': ip, 'name': NAMES.get(ip), 'private': is_private(ip), 'net': common.network_of(ip)}


def exporters_cfg(raw=False):
    """The devices; with SNMP names and addresses filled in, or raw=True: only what was configured."""
    if (exporters_mtime(), snmp.data_mtime()) != NAMES.mtime:
        NAMES.reload()
    return NAMES.raw if raw else NAMES.exporters


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
        netflow = {'port': int(st['port']), 'sflow_port': int(st.get('sflow_port') or 0), 'listen': live(st.get('listen') or [])}
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
    # (1.17.0) the first record in time order (min() under a WHERE read every record of the period)
    oldest = ch("SELECT toUnixTimestamp(ts) AS t FROM flows WHERE ts >= now() - toIntervalDay({d:UInt16}) ORDER BY ts LIMIT 1", {'d': view_days()}, fmt='JSON')
    return {'devices': devices, 'now': int(time.time()), 'oldest': int(oldest[0]['t']) if oldest else 0, 'listen': listen_info(),
            'ranges': list(RANGES), 'geo_attribution': 'IP Geolocation by DB-IP (db-ip.com), CC BY 4.0', 'edition': edition_info(), 'version': VERSION,
            'langs': languages(), 'networks': [{'net': x['net'], 'name': x['name']} for x in common.load_networks()],
            'l7': common.l7_names()}


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


# Licensing messages come in English from the core and the license server; in another UI language they are shown by
# these English texts of the dictionaries (N_ marks a text for them), in English as they came.
_LICENSE_MSGS = {
    N_('this is not a FlowSphera license code'), N_('the license code was mistyped or cut short'),
    N_('this license is for another FlowSphera version'), N_('this license is for another FlowSphera edition'),
    N_('the license was not issued by FlowSphera or was altered'), N_('this license was deactivated on this server to move it elsewhere'),
    N_('the system clock is behind — set the correct date and time (NTP)'), N_('no license is installed')}


_SERVER_MSGS = {
    'unknown': N_('this license key is not known to the license server'),
    'revoked': N_('this license key was revoked'),
    'expired': N_('this license key has expired'),
    'returned': N_('this license was deactivated or released and no longer works here'),
    'unreachable': N_('the license server is unreachable — check the internet connection (or enter an FTL-… license from the vendor)'),
    'busy': N_('too many requests to the license server — try again in a minute'),
    'error': N_('license server error — try again later'),
}


def license_message(code, msg, lic=None):
    """A licensing message in the UI language."""
    lic = lic or {}
    # (1.18.0) the compiled core and the license server still say «FlowTrack» (the product's former name)
    msg = (msg or '').replace('FlowTrack', 'FlowSphera')
    if get_lang() == 'en':
        return msg or ''
    if code == 'in_use':
        inst = re.search(r'installation (\S+)', msg)
        return tr('this key is already active on installation {inst} — deactivate it there first (Settings → License) '
                  'or ask the vendor to release it', inst=inst.group(1) if inst else '?')
    if code == 'unconfirmed':
        when = re.search(r'since (\d{4}-\d{2}-\d{2})', msg)
        return (tr('the license server has not confirmed this license since {date} — check the connection to it', date=when.group(1))
                if when else tr('the license server has not confirmed this online license yet'))
    if code == 'unknown' and 'license key' not in msg:
        return tr('this license was not issued by the license server')
    if code == 'invalid' and 'license key' in msg:
        return tr('this is not a FlowSphera license key') if 'not a' in msg else tr('the license key was mistyped or cut short')
    if code in _SERVER_MSGS and msg not in _LICENSE_MSGS and (code != 'expired' or 'license key' in msg):
        return tr(_SERVER_MSGS[code])        # from the license server
    if code == 'expired' and lic.get('expires'):
        return tr('the license ended on {date}', date=time.strftime('%Y-%m-%d', time.gmtime(lic['expires'])))
    if code == 'other_instance':
        return tr('this license was issued for installation {inst}, not for this one ({this})',
                  inst=lic.get('instance'), this=licensing.instance_id())
    return (tr(msg) if msg in _LICENSE_MSGS else msg) if msg else ''


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
    """Check for renewal now (any installed license; the daily check-in covers online ones by itself)."""
    try:
        _, renewed = license_refresh()
    except ValueError as ex:
        raise BadRequest(license_message(getattr(ex, 'code', 'error'), str(ex))) from None
    out = edition_info(admin=True)
    lic = out.get('license') or {}
    until = time.strftime('%Y-%m-%d', time.gmtime(lic['expires'])) if lic.get('expires') else ''
    out['checked'] = {'renewed': renewed, 'note': tr('Renewed: the license is valid until {date}', date=until) if renewed
                      else tr('The license server has no renewal for this license')}
    return out


# Distinct addresses are counted by their 64-bit hash: the same result (a collision among a million addresses has a
# chance of about 1 in 30 million) at less than half the cost of comparing the address strings themselves.
def api_summary(q):
    where, p, rng, step = scope(q)
    # the current and the previous window (each from its own source: a 5-minute total must not straddle them)
    cur0, prev0 = p['_t0'], max(p['t0'] - rng, p['floor'])
    # (1.17.0) only the columns a rollup groups by choose it: ts, dir and the sums are in every row (before, the totals
    # asked for them as columns, so no rollup matched and both windows were read from the records)
    dims = lambda cols: [c for c in cols.split(', ') if c not in ('ts', 'dir', 'bytes', 'packets', 'flows')]   # noqa: E731
    both = lambda cols: (f"(SELECT {cols}, 1 AS cur FROM {src(p, dims(cols))} UNION ALL "   # noqa: E731
                         f"SELECT {cols}, 0 AS cur FROM {src(p, dims(cols), prev0, cur0)})")
    r = ch(f"""SELECT
        sumIf(bytes, cur) AS s_bytes, sumIf(bytes, cur AND dir IN ('up', 'internal')) AS s_up, sumIf(bytes, cur AND dir NOT IN ('up', 'internal')) AS s_down,
        sumIf(flows, cur) AS s_flows, sumIf(packets, cur) AS s_packets,
        sumIf(bytes, NOT cur) AS s_p_bytes, sumIf(flows, NOT cur) AS s_p_flows, toUnixTimestamp(min(ts)) AS s_oldest
      FROM {both('ts, dir, bytes, packets, flows')}""", p, fmt='JSON')[0]
    r = {k[2:]: int(v) for k, v in r.items()}
    # distinct inside and outside addresses, from the per-host and per-address totals
    if q1(q, 't', 'internet') == 'internal':     # between inside hosts both ends are inside hosts
        h = ch(f"SELECT uniqExactIf(cityHash64(x), cur) AS c, uniqExactIf(cityHash64(x), NOT cur) AS p FROM "
               f"(SELECT arrayJoin([int_ip, ext_ip]) AS x, cur FROM {both('int_ip, ext_ip')})", p, fmt='JSON')[0]
    else:
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
    if by in DIMS or by == 'net':
        top = q1(q, 'top', '7', int)
        p['top'] = max(1, min(top, 20))
        col = net_expr('int_ip', p) if by == 'net' else DIMS[by]        # (1.8.7) by named network: of the inside address
        both = by in ('int_ip', 'net') and q1(q, 't', 'internet') == 'internal'     # a host is the client or the server
        dim = ['int_ip', 'ext_ip'] if both else ['int_ip' if by == 'net' else col]
        # (1.17.0) a day or more of what only hourly tables hold (outside addresses, both ends): hourly points, from them
        has = lambda st: rollups.source(dim, p['_t0'], p['_t1'], p['_fcols'], use=USE_ROLLUPS, step=st, table=p['_flows'], turn=p.get('_turn'))[1]  # noqa: E731
        if rng >= LONG and step % 3600 and not has(step) and has(-(-step // 3600) * 3600):
            step = p['_step'] = p['step'] = -(-step // 3600) * 3600
        s = src(p, dim[:1], bucketed=True)
        if both:
            # (1.17.0) both ends from the conversations per hour (agg_conv), a chosen host's turned to it too
            pairs = src(p, ['int_ip', 'ext_ip'], bucketed=True)
            s = (f"(SELECT ts, int_ip, bytes FROM {pairs} UNION ALL "
                 f"SELECT ts, ext_ip AS int_ip, bytes FROM {pairs})")
        rows = ch(f"""WITH (SELECT groupArray(k) FROM (SELECT toString({col}) AS k FROM {s} GROUP BY k ORDER BY sum(bytes) DESC, k LIMIT {{top:UInt8}})) AS tops
            SELECT {bucket} AS t, if(has(tops, toString({col})), toString({col}), '__other') AS k, sum(bytes) AS b
            FROM {s} GROUP BY t, k ORDER BY t, k""", p, fmt='JSON')
        return {'step': step, 'range': rng, 'from': p['t0'], 'to': p['t1'], 'rows': [[int(r['t']), r['k'], int(r['b'])] for r in rows]}
    rows = ch(f"""SELECT {bucket} AS t, sumIf(bytes, dir IN ('down', 'internal_back')) AS dn, sumIf(bytes, dir IN ('up', 'internal')) AS up,
            sumIf(bytes, dir = 'transit') AS other, sum(flows) AS fl
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
    if not rollups.source(list(cols) + what.split(', '), p['_t0'], p['_t1'], p['_fcols'], use=USE_ROLLUPS, table=p.get('_flows', 'flows'), turn=p.get('_turn'))[1]:
        # (1.17.0) what an address is does not depend on the filters: without them the per-address totals answer
        # instead of every record of the period (a host's outside addresses: a filter no per-address table holds)
        s = src(dict(p, _filt='1', _fcols=set(), _flows='flows'), list(cols) + what.split(', '))
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


TOP_ALL = 100_000      # (1.14.1) rows of /api/top?limit=all at most


def api_top(q):
    where, p, rng, step = scope(q)
    totals = {}
    dim = q1(q, 'dim', 'int_ip')
    # (1.14.1) limit=all: every row under the filters (scripts, billing, CSV), up to TOP_ALL — one more is asked for to
    # tell a cut list ('truncated'); a number keeps to 1–500 as before (0 or -1 meant 1 and nobody was told)
    every = q1(q, 'limit', '10') == 'all'
    if every and dim == 'conv':
        raise BadRequest(tr('limit=all is not available for conversations: use a number up to 500'))
    p['lim'] = TOP_ALL + 1 if every else max(1, min(q1(q, 'limit', '10', int), 500))
    name_of = (lambda ip: NAMES.get(ip, lookup=False)) if every else NAMES.get      # noqa: E731
    if dim == 'conv':
        # a busy day has millions of host-peer pairs: they are grouped by the pair's 64-bit hash (8 bytes instead of
        # two address strings; a collision among 10 million pairs has a chance of about 1 in 300,000), then the pairs
        # shown are read exactly with what they are
        # (1.16.2) whole hours from the conversations per hour (agg_conv), the edges from the records
        sums = """sumIf(bytes, dir IN ('up', 'internal')) AS up, sumIf(bytes, dir NOT IN ('up', 'internal')) AS dn, sum(flows) AS fl, sum(packets) AS pk"""
        pairs = src(p, ['int_ip', 'ext_ip', 'service', 'country', 'city'])
        try:
            top, tb = ch_totals(f"""SELECT cityHash64(int_ip, ext_ip) AS h, sum(bytes) AS b FROM {pairs}
                GROUP BY h WITH TOTALS ORDER BY b DESC LIMIT {{lim:UInt32}}""", p,      # beyond its memory share: on disk
                settings={'max_memory_usage': CH_QUERY_MEMORY, 'max_bytes_before_external_group_by': CH_QUERY_MEMORY * 2 // 5})
            p['hs'], totals = [int(r['h']) for r in top], {'up': tb.get('b', 0), 'dn': 0}
        except CHError as ex:
            if 'Code: 241' not in str(ex):
                raise
            # still out of memory (other panels loading at the same time): the heaviest candidates by a bounded-memory
            # count (Space-Saving), many times the rows asked for, so the order of those shown is right
            p['k'] = min(max(200, p['lim'] * 20), 5000)
            cand = ch(f"SELECT topKWeighted({{k:UInt16}})(cityHash64(int_ip, ext_ip), bytes) AS t, sum(bytes) AS b FROM {pairs}", p, fmt='JSON')[0]
            p['hs'], totals = [int(h) for h in cand['t']], {'up': cand['b'], 'dn': 0}
        rows = ch(f"""SELECT int_ip, ext_ip, {sums}, any(service) AS service, any(country) AS country, any(city) AS city FROM {pairs}
            AND cityHash64(int_ip, ext_ip) IN {{hs:Array(UInt64)}}
            GROUP BY int_ip, ext_ip ORDER BY up + dn DESC LIMIT {{lim:UInt32}}""", p, fmt='JSON') if p['hs'] else []
        for r in rows:
            r['name'] = name_of(r['int_ip'])
    elif dim == 'host_svc':     # each inside host with its main service and L7 protocol
        rows, totals = ch_totals(f"""SELECT int_ip AS k, sumIf(bytes, dir IN ('up', 'internal')) AS up, sumIf(bytes, dir NOT IN ('up', 'internal')) AS dn,
                sum(flows) AS fl, 0 AS pk
            FROM {src(p, ['int_ip'])} GROUP BY k WITH TOTALS ORDER BY up + dn DESC LIMIT {{lim:UInt32}}""", p)
        if rows:                # the main service / L7 / protocol of the hosts shown (per host x service of a whole day
            p['hs'] = [r['k'] for r in rows]                                   # did not fit into memory)
            main = {x['k']: x for x in ch(f"""SELECT k, argMax(service, b) AS service, argMax(l7, b) AS l7, argMax(proto, b) AS proto
                FROM (SELECT int_ip AS k, service, l7, proto, sum(bytes) AS b FROM {src(p, ['int_ip', 'service', 'l7', 'proto'])} AND int_ip IN {{hs:Array(String)}}
                      GROUP BY k, service, l7, proto) GROUP BY k""", p, fmt='JSON')}
            for r in rows:
                r.update({c: main.get(r['k'], {}).get(c, d) for c, d in (('service', ''), ('l7', ''), ('proto', 0))})
        for r in rows:
            r['name'] = name_of(r['k'])
            r['proto'] = int(r['proto'])
    elif dim in ('net', 'net_svc') and q1(q, 't', 'internet') == 'internal':
        # (1.8.7) inside <-> inside: a network sends from its client hosts and from its servers
        nl, nr = net_expr('int_ip', p), net_expr('ext_ip', p)
        pairs = src(p, ['int_ip', 'ext_ip'])     # (1.17.0) see int_ip below
        flows = 'flows'
        rows = ch(f"""SELECT k, sum(u) AS up, sum(d) AS dn, sum(f) AS fl, 0 AS pk, uniqExact(h) AS hosts FROM (
                SELECT {nl} AS k, cityHash64(int_ip) AS h, if(dir = 'internal', bytes, 0) AS u, if(dir = 'internal', 0, bytes) AS d, {flows} AS f FROM {pairs}
                UNION ALL SELECT {nr}, cityHash64(ext_ip), if(dir = 'internal', 0, bytes), if(dir = 'internal', bytes, 0), {flows} FROM {pairs})
            GROUP BY k ORDER BY up + dn DESC LIMIT {{lim:UInt32}}""", p, fmt='JSON')
        net_rows(rows, p, where, src(p, ['int_ip', 'service', 'l7', 'proto']) if dim == 'net_svc' else None)
    elif dim in ('net', 'net_svc'):      # (1.8.7) traffic of each named network (by the inside address), '' = no network
        rows, totals = ch_totals(f"""SELECT {net_expr('int_ip', p)} AS k, sumIf(bytes, dir IN ('up', 'internal')) AS up,
                sumIf(bytes, dir NOT IN ('up', 'internal')) AS dn, sum(flows) AS fl, 0 AS pk, uniqExact(cityHash64(int_ip)) AS hosts
            FROM {src(p, ['int_ip'])} GROUP BY k WITH TOTALS ORDER BY up + dn DESC LIMIT {{lim:UInt32}}""", p)
        net_rows(rows, p, where, src(p, ['int_ip', 'service', 'l7', 'proto']) if dim == 'net_svc' else None)
    elif dim == 'int_ip' and q1(q, 't', 'internet') == 'internal':
        # inside <-> inside: a host is the client (int_ip) of some sessions and the server (ext_ip) of others; count
        # what it sent (up) and received (dn), how many hosts it connected to (calls) and how many connected to it
        # (callers). For a chosen host the records are turned to it (host_view): `turned` = it was the server.
        # (1.17.0) both ends come from the conversations per hour (agg_conv), a chosen host's turned to it too
        turned = 'turned' if 'hv' in p else '0'
        pairs = src(p, ['int_ip', 'ext_ip'] + (['turned'] if 'hv' in p else []))
        flows = 'flows'
        rows = ch(f"""SELECT k, sum(u) AS up, sum(d) AS dn, sum(f) AS fl, sum(pk_) AS pk,
                uniqExactIf(peer, NOT srv) AS calls, uniqExactIf(peer, srv) AS callers FROM (
                SELECT int_ip AS k, ext_ip AS peer, toUInt8({turned}) AS srv, if(dir = 'internal', bytes, 0) AS u, if(dir = 'internal', 0, bytes) AS d, {flows} AS f, packets AS pk_
                    FROM {pairs}
                UNION ALL SELECT ext_ip, int_ip, toUInt8(1 - {turned}), if(dir = 'internal', 0, bytes), if(dir = 'internal', bytes, 0), {flows}, packets FROM {pairs})
            GROUP BY k ORDER BY up + dn DESC LIMIT {{lim:UInt32}}""", p, fmt='JSON')
        for r in rows:
            r['name'] = name_of(r['k'])
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
            FROM {src(p, cols)} GROUP BY k WITH TOTALS ORDER BY up + dn DESC LIMIT {{lim:UInt32}}""", p)
        if dim == 'ext_port' and rows:
            p['ports'] = [int(r['k']) for r in rows]
            # (1.17.0) exact, from the hosts and the addresses of each port per hour (agg_port_host / agg_port_peer);
            # when neither rollup serves (a chosen host, rollups off) both counts in one pass over the records, not two
            hp, one = {}, [('int_ip', 'hosts'), ('ext_ip', 'peers')]
            raw = not any(rollups.source(['ext_port', 'proto', c], p['_t0'], p['_t1'], p['_fcols'], use=USE_ROLLUPS,
                                         table=p.get('_flows', 'flows'), turn=p.get('_turn'))[1] for c, _ in one)
            for part in ([one] if raw else [[x] for x in one]):
                for x in ch(f"""SELECT ext_port AS k, {', '.join(f'uniqExact(cityHash64({c})) AS {out}' for c, out in part)}
                        FROM {src(p, ['ext_port', 'proto'] + [c for c, _ in part])} AND ext_port IN {{ports:Array(UInt64)}} GROUP BY k""", p, fmt='JSON'):
                    hp.setdefault(str(x['k']), {}).update({out: int(x[out]) for _, out in part})
            for r in rows:
                r.update(hosts=hp.get(r['k'], {}).get('hosts', 0), peers=hp.get(r['k'], {}).get('peers', 0))
        if dim == 'ext_ip':     # 200k+ outside addresses a day: what each one is, only for those shown
            attrs(rows, ('k',), 'service, country, city, asn, as_org', where, p, cols=('ext_ip',))
        if dim == 'int_ip':
            for r in rows:
                r['name'] = name_of(r['k'])
    else:
        raise BadRequest('bad dim')
    if dim in ('int_ip', 'net', 'net_svc') and q1(q, 't', 'internet') == 'internal':     # there every record counts for two hosts
        tot = ch(f"SELECT sum(bytes) AS b FROM {src(p, [])}", p, fmt='JSON')[0]['b']
    else:                       # up + dn of all groups, computed in the same pass (WITH TOTALS; no 2nd scan)
        tot = int(totals.get('up') or 0) + int(totals.get('dn') or 0)
    for r in rows:
        for k in ('up', 'dn', 'fl', 'pk', 'hosts', 'asn', 'peers', 'proto_n', 'calls', 'callers'):
            if k in r:
                r[k] = int(r[k])
    out = {'total': int(tot), 'rows': rows}
    if every:
        out['truncated'] = len(rows) > TOP_ALL
        out['rows'] = rows[:TOP_ALL]
    return out


CSV_ROUTES = {'/api/top'}
CSV_COLS = {'k': None, 'name': 'name', 'up': 'upload_bytes', 'dn': 'download_bytes', 'fl': 'flows', 'pk': 'packets', 'hosts': 'hosts',
            'peers': 'peers', 'service': 'service', 'l7': 'l7', 'country': 'country', 'city': 'city', 'as_org': 'as_org', 'asn': 'asn',
            'calls': 'calls', 'callers': 'callers', 'networks': 'networks', 'int_ip': 'int_ip', 'ext_ip': 'ext_ip'}


def top_csv(dim, res):
    """(1.14.1) /api/top as CSV (UTF-8 with a BOM, so Excel reads names right): the key column is named by the dim
    (int_ip → host), then the columns the rows have, plus total_bytes; a cut list ends with a '# truncated' line."""
    import csv
    import io
    rows = res.get('rows') or []
    keys = [k for k in CSV_COLS if any(k in r for r in rows)] or ['k', 'up', 'dn']
    head = [{'int_ip': 'host', 'ext_ip': 'outside_ip', 'net': 'network'}.get(dim, dim) if k == 'k' else CSV_COLS[k] for k in keys]
    f = io.StringIO()
    w = csv.writer(f, lineterminator='\r\n')
    w.writerow(head + ['total_bytes'])
    for r in rows:
        w.writerow([', '.join(map(str, v)) if isinstance(v, list) else ('' if v is None else v) for v in (r.get(k) for k in keys)]
                   + [int(r.get('up') or 0) + int(r.get('dn') or 0)])
    if res.get('truncated'):
        w.writerow([f'# truncated: more than {TOP_ALL} rows, narrow the filters'])
    return ('\ufeff' + f.getvalue()).encode()

def net_rows(rows, p, where, svc_src=None):
    """(1.8.7) The networks of each named-network row; with `svc_src` also its main service, L7 protocol and protocol."""
    by = {}
    for x in common.load_networks():
        by.setdefault(x['name'], []).append(x['net'])
    for r in rows:
        r['nets'] = by.get(r['k'], [])
    if svc_src and rows:
        e = net_expr('int_ip', p)
        main = {x['k']: x for x in ch(f"""SELECT k, argMax(service, b) AS service, argMax(l7, b) AS l7, argMax(proto, b) AS proto
            FROM (SELECT {e} AS k, service, l7, proto, sum(bytes) AS b FROM {svc_src} GROUP BY k, service, l7, proto) GROUP BY k""", p, fmt='JSON')}
        for r in rows:
            r.update({c: main.get(r['k'], {}).get(c, d) for c, d in (('service', ''), ('l7', ''), ('proto', 0))})
            r['proto'] = int(r['proto'])


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
    # (1.16.2) a whole period reads the rollups (inside hosts, outside addresses, their pairs per hour) for its whole
    # buckets; the live window (minutes) the records
    if live:
        metric = metric.replace('flows', '1')
        F_l = F_r = F_lr = F_info = f"{p['_flows']} WHERE {where}"
    else:
        metric = {'1': 'flows'}.get(metric, metric)
        F_l, F_r, F_lr = src(p, ['int_ip']), src(p, ['ext_ip']), src(p, ['int_ip', 'ext_ip', 'service', 'country', 'city'])
        F_info = src(p, ['ext_ip', 'service', 'country', 'city'])
    tops = ch(f"""SELECT
            (SELECT groupArray(k) FROM (SELECT int_ip AS k FROM {F_l} GROUP BY k ORDER BY sum({metric}) DESC LIMIT {{n:UInt8}})) AS l,
            (SELECT groupArray(k) FROM (SELECT ext_ip AS k FROM {F_r} GROUP BY k ORDER BY sum({metric}) DESC LIMIT {{n:UInt8}})) AS r,
            (SELECT uniqExact(cityHash64(int_ip)) FROM {F_l}) AS nl, (SELECT uniqExact(cityHash64(ext_ip)) FROM {F_r}) AS nr""", p, fmt='JSON')[0]
    left, right = tops['l'], tops['r']
    p['L'], p['R'] = left, right
    links = ch(f"""SELECT if(has({{L:Array(String)}}, int_ip), int_ip, '__other') AS l, if(has({{R:Array(String)}}, ext_ip), ext_ip, '__other') AS r,
            sumIf({metric}, dir IN ('up', 'internal')) AS up, sumIf({metric}, dir NOT IN ('up', 'internal')) AS dn, toUnixTimestamp(max(ts)) AS t
        FROM {F_lr} GROUP BY l, r""", p, fmt='JSON')
    info = {}
    if right:
        for r in ch(f"SELECT ext_ip, any(service) AS service, any(country) AS country, any(city) AS city FROM {F_info} AND has({{R:Array(String)}}, ext_ip) GROUP BY ext_ip", p, fmt='JSON'):
            info[r['ext_ip']] = r
    more_l, more_r = int(tops['nl']) > len(left), int(tops['nr']) > len(right)
    out = [{'l': x['l'], 'r': x['r'], 'up': float(x['up']), 'dn': float(x['dn']), 't': int(x['t'])} for x in links
           if (x['l'] != '__other' or more_l) and (x['r'] != '__other' or more_r)]
    return {'left': [host_obj(ip) for ip in left], 'right': [{'ip': ip, 'name': NAMES.get(ip) if is_private(ip) else '', **{k: info.get(ip, {}).get(k, '') for k in ('service', 'country', 'city')}} for ip in right],
            'more_left': more_l, 'more_right': more_r, 'links': out, 'window_end': p.get('wend'), 'window': win if live else rng, 'live': live, 'range': rng}


def iface_from(p, where, live, cols):
    """`FROM … WHERE …` of Through device / Path analysis (a caller may add `AND …`): the pre-aggregated totals per
    interface pair (agg_iface*) over a period, or the records of a live window (cheap: two minutes). Rows have
    `flows` (records)."""
    if not live:
        return src(p, cols)
    rc = ', '.join(f'{rollups.RAW_EXPR[c]} AS {c}' if c in rollups.RAW_EXPR else c for c in cols)
    return f"(SELECT ts, exporter, dir, {rc}, bytes, packets, toUInt64(1) AS flows FROM {p['_flows']} WHERE {where}) WHERE 1"


def _live_window(q, where, p):
    live = q1(q, 'live', '0') == '1' and not p['custom']
    win = max(60, min(q1(q, 'win', '120', int), 900))
    wend = None
    if live:
        wend = live_end(q)
        p['wend'], p['win'] = wend, win
        where += ' AND ts > toDateTime({wend:UInt32}) - toIntervalSecond({win:UInt32}) AND ts <= toDateTime({wend:UInt32})'
    return where, live, win, wend


def _path_hosts(p, where, live):
    """{(in_if, out_if): inside hosts on the path}"""
    rows = ch(f"SELECT in_if, out_if, uniqExact(int_ip) AS h FROM {iface_from(p, where, live, ['in_if', 'out_if', 'int_ip'])} GROUP BY in_if, out_if", p, fmt='JSON')
    return {(int(r['in_if']), int(r['out_if'])): int(r['h']) for r in rows}


METRIC = {'bytes': 'bytes', 'packets': 'packets', 'flows': 'flows'}


def api_paths(q):
    """Traffic through an exporter: (input interface -> output interface) pairs with volume, hosts and services.
    The device comes from the 'device' filter; live = the last `win` seconds of data, otherwise the range."""
    where, p, rng, step = scope(q)
    metric = METRIC.get(q1(q, 'metric', 'bytes'), 'bytes')
    where, live, win, wend = _live_window(q, where, p)
    rows = ch(f"""SELECT in_if, out_if, sum({metric}) AS v, sum(bytes) AS b, sum(packets) AS pk, sum(flows) AS fl,
            topKWeighted(3)(service, bytes) AS services,
            sumIf(bytes, dir IN ('up', 'down')) AS internet, sumIf(bytes, dir IN ('internal', 'internal_back')) AS internal
        FROM {iface_from(p, where, live, ['in_if', 'out_if', 'service'])} GROUP BY in_if, out_if ORDER BY v DESC LIMIT 80""", p, fmt='JSON')
    hosts = _path_hosts(p, where, live) if rows else {}
    for r in rows:
        for k in ('in_if', 'out_if', 'b', 'pk', 'fl', 'internet', 'internal'):
            r[k] = int(r[k])
        r['v'] = float(r['v'])
        r['hosts'] = hosts.get((r['in_if'], r['out_if']), 0)
    return {'rows': rows, 'live': live, 'window_end': wend, 'window': win if live else rng, 'range': rng}


def api_devmap(q):
    """One exporter as a box with ports: interface pairs (paths through the box; the 20 biggest by the chosen
    metric), the inside hosts behind each inside interface and the outside addresses behind each WAN interface. Same
    time window rules as api_paths."""
    where, p, rng, step = scope(q)
    metric = METRIC.get(q1(q, 'metric', 'bytes'), 'bytes')
    where, live, win, wend = _live_window(q, where, p)
    p['n'] = max(3, min(q1(q, 'top', '10', int), 20))
    paths = ch(f"""SELECT in_if, out_if, sum({metric}) AS v, sumIf({metric}, dir = 'up') AS up, sumIf({metric}, dir = 'down') AS dn,
            sumIf({metric}, dir NOT IN ('up', 'down')) AS other, sum(flows) AS fl, topKWeighted(3)(service, toUInt64({metric})) AS services
        FROM {iface_from(p, where, live, ['in_if', 'out_if', 'service'])} GROUP BY in_if, out_if ORDER BY v DESC LIMIT 20""", p, fmt='JSON')
    hosts = _path_hosts(p, where, live) if paths else {}
    # an inside host enters the box through: in_if when it sends (up; between inside hosts 'internal' = int_ip sends,
    # 'internal_back' = ext_ip (peer_ip) sends), out_if when it receives (down; the other end of an inside record)
    hs = lambda: iface_from(p, where, live, ['in_if', 'out_if', 'int_ip', 'peer_ip'])      # noqa: E731
    inside = ch(f"""SELECT host, iface, sum(u) AS up, sum(d) AS dn, sum(u) + sum(d) AS v FROM (
            SELECT int_ip AS host, if(dir IN ('down', 'internal_back'), out_if, in_if) AS iface, if(dir IN ('down', 'internal_back'), 0, {metric}) AS u,
                   if(dir IN ('down', 'internal_back'), {metric}, 0) AS d
                FROM {hs()} AND dir IN ('up', 'down', 'internal', 'internal_back')
            UNION ALL SELECT peer_ip, if(dir = 'internal', out_if, in_if), if(dir = 'internal', 0, {metric}), if(dir = 'internal', {metric}, 0)
                FROM {hs()} AND dir IN ('internal', 'internal_back'))
        GROUP BY host, iface ORDER BY v DESC LIMIT {{n:UInt8}} BY iface LIMIT 60""", p, fmt='JSON')
    # the outside addresses beyond the WAN ports: a busy network has hundreds of thousands a day — the biggest few per
    # port are found approximately (constant memory; grouping them all with their names took 1.5 GiB on a day of
    # 2,400 records/s), then counted exactly
    ext = lambda: iface_from(p, where, live, ['in_if', 'out_if', 'out_ip', 'service', 'country', 'city'])      # noqa: E731
    cand = ch(f"""SELECT if(dir = 'up', out_if, in_if) AS iface, topKWeighted({{k:UInt8}})(out_ip, toUInt64({metric})) AS top
        FROM {ext()} AND dir IN ('up', 'down') GROUP BY iface""", {**p, 'k': 3 * p['n']}, fmt='JSON')
    p['cand'] = sorted({h for r in cand for h in r['top']})
    outside = ch(f"""SELECT out_ip AS host, if(dir = 'up', out_if, in_if) AS iface, sumIf({metric}, dir = 'up') AS up, sumIf({metric}, dir = 'down') AS dn,
            sum({metric}) AS v, any(service) AS service, any(country) AS country, any(city) AS city
        FROM {ext()} AND dir IN ('up', 'down') AND has({{cand:Array(String)}}, out_ip)
        GROUP BY host, iface ORDER BY v DESC LIMIT {{n:UInt8}}""", p, fmt='JSON') if p['cand'] else []
    num = ('in_if', 'out_if', 'iface', 'fl', 'hosts')
    for rows in (paths, inside, outside):
        for r in rows:
            for k, val in list(r.items()):
                if k in num:
                    r[k] = int(val)
                elif k in ('v', 'up', 'dn', 'other'):
                    r[k] = float(val)
    for r in paths:
        r['hosts'] = hosts.get((r['in_if'], r['out_if']), 0)
    for r in inside:
        r['name'] = NAMES.get(r['host'])
    return {'paths': paths, 'inside': inside, 'outside': outside, 'live': live, 'window_end': wend, 'window': win if live else rng, 'range': rng}


def network_q(q):
    """Path analysis looks at every device and all traffic: device filters are dropped (the Point of View is chosen
    instead), the traffic scope follows the selector (all when not given), and a host filter (ip / dst) takes the host's packets in both
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


# Path analysis (1.8.1): which devices are neighbours changes rarely, and finding it is the heaviest query FlowSphera
# has (every conversation of the period, grouped by the devices that saw it). It is worked out in the background from
# the last hour every 10 minutes (and when the devices' settings or SNMP data change); a page over a period then adds
# only the volumes of its links, from the 5-minute totals per interface pair.
# (1.8.2) A page never waits for it once there is one: an outdated structure is shown while a new one is worked out
# in the background — on a busy network that takes 20 s, and SNMP data changing every few minutes made every visit wait.
TOPO_EVERY, TOPO_SPAN = 600, 3600
_topo = {'key': None, 't': 0, 'data': None}
_topo_lock = threading.Lock()          # one build at a time
_topo_bg = threading.Event()           # a background build is running


def _known(cfg):
    return {a.split('/')[0] for c in cfg.values() for v in c.get('if_addrs', {}).values() for a in v} | set(cfg) | \
        {a for c in cfg.values() for a in c.get('public_ips', [])}


def _topo_build(cfg):
    key = (exporters_mtime(), snmp.data_mtime())
    with _topo_lock:
        p = {'span': TOPO_SPAN}
        near, _, exporting, pairs = topology.query(ch, 'ts >= now() - toIntervalSecond({span:UInt32})', p, _known(cfg), volumes=False)
        _topo.update(key=key, t=time.time(), data=(near, exporting, pairs))
        return _topo['data']


def _topo_build_bg(cfg):
    """Work the structure out in a thread of its own (no web request's query tag: leaving the page does not cancel it)."""
    if _topo_bg.is_set():
        return
    _topo_bg.set()
    def run():
        try:
            _topo_build(cfg)
        except (CHError, OSError) as e:
            print(f'[flowtrack-api] path analysis structure: {e}', flush=True)
        finally:
            _topo_bg.clear()
    threading.Thread(target=run, daemon=True).start()


def topo_structure(cfg, wait=True):
    """(near, exporting, pairs) of the last hour, as topology.build() takes them. A page gets the one there is at once
    (an outdated one starts a background build); only the very first one is waited for. wait=False (the background
    refresh) always works it out."""
    if not wait:
        return _topo_build(cfg)
    data = _topo['data']
    if data is None:
        with _topo_lock:                   # a build already running (the start of the web): wait for it, not twice
            data = _topo['data']
        return data if data is not None else _topo_build(cfg)
    if _topo['key'] != (exporters_mtime(), snmp.data_mtime()) or time.time() - _topo['t'] >= TOPO_EVERY * 1.5:
        _topo_build_bg(cfg)
    return data


def topo_refresher(stop):
    while not stop.wait(TOPO_EVERY):
        try:
            topo_structure(exporters_cfg(), wait=False)
        except (CHError, OSError) as e:
            print(f'[flowtrack-api] path analysis structure: {e}', flush=True)


def network_topology(q):
    """Neighbours, link states and the hops of a path come from all the traffic; the traffic selector (t) narrows
    only the volumes on the links (topology.set_volumes)."""
    nq = network_q(q)
    narrow = {'internet': "dir IN ('up', 'down')", 'internal': "dir IN ('internal', 'internal_back')"}.get(q1(nq, 't', 'all'))
    where, p, rng, step = scope({**nq, 't': ['all']})
    where, live = live_window(q, where, p, default='0')
    cfg = exporters_cfg()
    if live:                         # two minutes of records: everything from them, as it is now
        topo = topology.build(cfg, *topology.query(ch, where, p, _known(cfg)))
        if narrow:
            topology.set_volumes(topo, topology.iface_volumes(ch, f'{where} AND {narrow}', p))
    else:                            # the neighbours of the last hour, the volumes of the period from the totals
        near, exp_h, pairs = topo_structure(cfg)
        tot, _ = rollups.source(['in_if', 'out_if'], p['_t0'], p['_t1'], p['_fcols'], use=USE_ROLLUPS, table=p.get('_flows', 'flows'), turn=p.get('_turn'))
        ifaces = topology.iface_volumes(ch, p['_filt'], p, table=tot)
        topo = topology.build(cfg, near, ifaces, {r['exporter'] for r in ifaces} | set(exp_h), pairs)
        if narrow:
            topology.set_volumes(topo, topology.iface_volumes(ch, f"{p['_filt']} AND {narrow}", p, table=tot))
    hints = iface_hints()
    for lk in topo['links']:
        seen = {}
        for e in ('a', 'b'):
            i = lk[e + '_if']
            lk[e + '_name'] = (cfg.get(lk[e], {}).get('if_names', {}).get(str(i)) or f'if {i}') if i is not None else ''
            seen[e] = hints.get(lk[e], {}).get(i, []) if i is not None else []
        # the address of each end: from the settings or SNMP, else (like Through device) what the records show on
        # that interface — a network both ends share first (the link's own subnet)
        common = [x for x in seen['a'] if x in seen['b']]
        for e in ('a', 'b'):
            i = lk[e + '_if']
            lk[e + '_seen'] = False
            if lk[e + '_addr'] or i is None:
                continue
            own = cfg.get(lk[e], {}).get('if_addrs', {}).get(str(i)) or []
            if own:
                lk[e + '_addr'] = own[0]
            elif common or seen[e]:
                lk[e + '_addr'], lk[e + '_seen'] = (common or seen[e])[0], True
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
    if live:
        rows = topology.path_query(ch, where, p, s, d)
    else:        # (1.17.0) a period: the conversations per hour (whole hours), the records only at its edges
        tbl, _ = rollups.source(['in_if', 'out_if', 'int_ip', 'ext_ip', 'nat_ip'], p['_t0'], p['_t1'], p['_fcols'], use=USE_ROLLUPS,
                                table=p.get('_flows', 'flows'), turn=p.get('_turn'))
        rows = topology.path_query(ch, p['_filt'], p, s, d, table=tbl)
    out = topology.path(topo, cfg, rows)
    return {'src': s, 'dst': d, **out, 'live': live, 'window': p.get('win', rng), 'window_end': p.get('wend'), 'range': rng}


def api_flows(q):
    where, p, rng, step = scope(q)
    p['lim'] = max(1, min(q1(q, 'limit', '50', int), 1000))
    rows = ch(f"""SELECT toUnixTimestamp(ts) AS t, toFloat64(ts_start) AS t0, exporter, in_if, out_if, toString(dir) AS dir, int_ip, int_port, ext_ip, ext_port,
            proto, nat_ip, nat_port, bytes, packets, l7, service, country, city, asn, as_org, sampling, dscp, dscp_out
        FROM {p['_flows']} WHERE {where} ORDER BY ts DESC LIMIT {{lim:UInt16}}""", p, fmt='JSON')
    for r in rows:
        r['name'] = NAMES.get(r['int_ip'])
        for k in ('t', 'in_if', 'out_if', 'int_port', 'ext_port', 'proto', 'nat_port', 'bytes', 'packets', 'asn', 'sampling'):
            r[k] = int(r[k])
    return {'rows': rows}


LIVE_TOP, LIVE_BACK = 20, 20


def api_live(q):
    """The newest flows with a location after `since` (unix s), for the map's arcs and Live connections: the
    LIVE_TOP biggest of the last LIVE_BACK seconds of data, one per device x direction x place (1.8.1: before, the
    oldest 300 records after `since` — thousands of records a second left the map ever further behind). `upto`:
    the newest second read, the next `since`."""
    where, p, rng, step = scope(q)
    p['since'] = max(0, q1(q, 'since', str(int(time.time()) - 90), int))
    last = ch(f"SELECT toUnixTimestamp(max(ts)) AS t FROM flows WHERE {where} AND ts > toDateTime({{since:UInt32}}) AND lat != 0", p, fmt='JSON')
    upto = int(last[0]['t']) if last and int(last[0]['t'] or 0) else 0
    if not upto:
        return {'rows': [], 'now': int(time.time()), 'upto': p['since']}
    p['lo'], p['upto'], p['n'] = max(p['since'], upto - LIVE_BACK), upto, LIVE_TOP
    rows = ch(f"""SELECT toUnixTimestamp(max(ts)) AS t, exporter, toString(dir) AS dir, argMax(int_ip, bytes) AS int_ip, argMax(ext_ip, bytes) AS ext_ip,
            argMax(ext_port, bytes) AS ext_port, argMax(service, bytes) AS service, country, city, lat, lon, sum(bytes) AS b, count() AS n
        FROM flows WHERE {where} AND ts > toDateTime({{lo:UInt32}}) AND ts <= toDateTime({{upto:UInt32}}) AND lat != 0
        GROUP BY exporter, dir, country, city, lat, lon ORDER BY b DESC LIMIT {{n:UInt8}}""", p, fmt='JSON')
    for r in rows:
        r['t'], r['bytes'], r['ext_port'], r['n'] = int(r['t']), int(r.pop('b')), int(r['ext_port']), int(r['n'])
        r['name'] = NAMES.get(r['int_ip'])
    rows.sort(key=lambda r: r['t'])
    return {'rows': rows, 'now': int(time.time()), 'upto': upto}


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


def iface(c, idx, nbytes, ext, seen=(), sn=None):
    """c: the configured device (raw); sn: what SNMP found on it (or None)"""
    names = c.get('if_names', {})
    role = 'wan' if idx in c.get('wan_ifs', []) else 'local' if c.get('local_if') == idx and c.get('local_if') is not None else 'lan'
    custom = names.get(str(idx), '')
    si = (sn or {}).get('ifs', {}).get(str(idx), {})
    return {'index': idx, 'name': custom or si.get('name') or ('local' if role == 'local' else f'if {idx}'), 'custom_name': custom,
            'role': role, 'wan': role == 'wan', 'bytes': nbytes, 'ext_share': round(ext / nbytes, 3) if nbytes else 0,
            'addrs': c.get('if_addrs', {}).get(str(idx), []), 'seen_addrs': list(seen),
            'snmp_name': si.get('name', ''), 'snmp_alias': si.get('alias', ''), 'snmp_up': si.get('oper') == 1 if si else None,
            'snmp_speed': si.get('speed') or 0, 'snmp_addrs': (sn or {}).get('addrs', {}).get(str(idx), []),
            **if_capacity(c, idx, si.get('speed') or 0)}


def ifaces_named(name):
    """(1.13.0) [(device, index)] of the interfaces called `name` (any case): your own name, else the SNMP one."""
    name = name.strip().lower()
    sset, sdata = snmp.load_settings(), snmp.load_data()
    out = []
    for dev, c in exporters_cfg(raw=True).items():
        sn = sdata.get(dev) if sset.get(dev, {}).get('enabled') else None
        idxs = {int(k) for key in ('if_names', 'if_addrs', 'if_caps') for k in (c.get(key) or {}) if str(k).isdigit()}
        idxs |= {int(k) for k in (sn or {}).get('ifs', {}) if str(k).isdigit()} | set(c.get('wan_ifs', []))
        for idx in sorted(idxs):
            info = iface(c, idx, 0, 0, (), sn)
            if name in (info['name'].lower(), info['snmp_name'].lower()):
                out.append((dev, idx))
    return out

def if_capacity(c, idx, auto_mbps):
    """(1.12.0) What an interface can carry, Mbit/s in and out: the operator's own figures (an ISP contract of 300 / 50
    on a 1 Gbit/s port) or the port's speed (SNMP ifHighSpeed, else the sFlow counters' ifSpeed); 0 = unknown."""
    own = (c.get('if_caps') or {}).get(str(idx))
    if own:
        return {'cap_in': own[0], 'cap_out': own[1], 'cap_own': True, 'cap_auto': auto_mbps}
    return {'cap_in': auto_mbps, 'cap_out': auto_mbps, 'cap_own': False, 'cap_auto': auto_mbps}


def interfaces_of(c, rows, seen_addrs, sn=None, cnt=None):
    """Interfaces seen in the data, those the sFlow counters report (a switch port without sampled traffic), plus those
    only mentioned in the settings (so a WAN index that never shows up in the data is visible and can be corrected)."""
    cnt = cnt or {}
    out = [iface(c, int(r['i']), int(r['bytes']), int(r['ext']), seen_addrs.get(int(r['i']), ()), sn) for r in rows]
    out += [iface(c, idx, 0, 0, (), sn) for idx in sorted(set(cnt) - {i['index'] for i in out})]
    for i in out:
        i['counters'] = cnt.get(i['index'])
        sp = int((i['counters'] or {}).get('speed') or 0) // 1_000_000     # sFlow ifSpeed (bit/s) when SNMP knows none
        if sp and not i['cap_auto']:
            i.update(cap_auto=sp, **({} if i['cap_own'] else {'cap_in': sp, 'cap_out': sp}))
    seen = {i['index'] for i in out}
    configured = set(c.get('wan_ifs', [])) | {int(k) for key in ('if_names', 'if_addrs') for k in c.get(key, {}) if str(k).isdigit()}
    if c.get('local_if') is not None:
        configured.add(int(c['local_if']))
    for idx in sorted(configured - seen):
        out.append({**iface(c, idx, 0, 0, (), sn), 'unseen': True})
    return sorted(out, key=lambda i: i['index'])


def sflow_counters():
    """exporter -> ifIndex -> what the interface counters of the last 10 minutes say (sFlow counter samples, or since
    1.14.0 the SNMP reads — `src`): speed, state, average in / out bit/s, errors and discards (a counter that went
    back, e.g. after a reboot, is skipped for that step)."""
    try:
        # (1.14.0) the SNMP reads go to the same table: one source per interface (SNMP before sFlow), never both mixed
        rows = ch("""SELECT exporter, if_index, src, groupArray((toUInt32(ts), speed, status, in_octets, out_octets, in_errors + out_errors,
                in_discards + out_discards)) AS a FROM if_counters WHERE ts >= now() - INTERVAL 10 MINUTE GROUP BY exporter, if_index, src
            ORDER BY src = 'snmp'""", fmt='JSON')
    except CHError:                    # the table appears when the collector of 1.7.0 starts
        return {}
    out = {}
    for r in rows:
        a = sorted(([int(v) for v in x] for x in r['a']), key=lambda x: x[0])
        span = a[-1][0] - a[0][0]
        step = lambda k: sum(b[k] - x[k] for x, b in zip(a, a[1:]) if b[k] >= x[k])
        out.setdefault(r['exporter'], {})[int(r['if_index'])] = {
            'speed': a[-1][1], 'up': bool(a[-1][2] & 2), 'admin_up': bool(a[-1][2] & 1), 'last': a[-1][0],
            'in_bps': round(step(3) * 8 / span) if span else None, 'out_bps': round(step(4) * 8 / span) if span else None,
            'errors': step(5), 'discards': step(6), 'minutes': round(span / 60, 1), 'src': r.get('src') or 'sflow'}
    return out


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


_hints = [0, {}]


def iface_hints():
    """exporter -> interface -> addresses the records of 24 h show on it (kept 5 minutes)."""
    if time.time() - _hints[0] < 300:
        return _hints[1]
    # NetFlow does not carry interface addresses; show what the data reveals so the user can recognise ports:
    # the source NAT address used when leaving an interface (the uplink's public IP) and the private /24
    # networks that send traffic into it (LAN segments). Only addresses with at least 10 % of the interface's flows.
    # (1.8.1) the networks from the hourly totals of inside hosts per interface pair; the NAT address of an uplink
    # does not change within the hour, so the last hour of records shows it
    hosts, _ = rollups.source(['in_if', 'out_if', 'int_ip'], int(time.time()) - 86400, None, set(), use=USE_ROLLUPS)
    rows = ch(f"""SELECT exporter, i, a FROM (
            SELECT exporter, i, a, c, sum(c) OVER (PARTITION BY exporter, i) AS t FROM (
                SELECT exporter, out_if AS i, nat_ip AS a, count() AS c FROM flows
                WHERE ts >= now() - INTERVAL 1 HOUR AND dir = 'up' AND nat_ip != '' AND nat_ip != int_ip GROUP BY exporter, i, a
                UNION ALL
                SELECT exporter, in_if AS i, concat(IPv4NumToString(bitAnd(IPv4StringToNumOrDefault(int_ip), 4294967040)), '/24') AS a, sum(flows) AS c FROM {hosts}
                WHERE dir IN ('up', 'internal') AND int_ip != exporter AND isIPv4String(int_ip)
                  AND (isIPAddressInRange(int_ip, '10.0.0.0/8') OR isIPAddressInRange(int_ip, '172.16.0.0/12') OR isIPAddressInRange(int_ip, '192.168.0.0/16'))
                GROUP BY exporter, i, a))
        WHERE c >= 0.1 * t ORDER BY exporter, i, c DESC LIMIT 3 BY exporter, i""", fmt='JSON')
    seen = {}
    for h in rows:
        seen.setdefault(h['exporter'], {}).setdefault(int(h['i']), []).append(h['a'])
    _hints[:] = [time.time(), seen]
    return seen


def snmp_status(ip, settings, data):
    """The device's SNMP settings (no secrets) and how the last poll went."""
    e = settings.get(ip)
    if not e:
        return {'enabled': False}
    out = snmp.public(e)
    d = data.get(ip) if e.get('enabled') else None
    if d:
        out.update({'polled': d.get('t', 0), 'ok': d.get('ok', False), 'last_ok': d.get('t_ok', 0), 'sys': d.get('sys', {}),
                    'ifs': snmp_ifs(d), 'interfaces': len(d.get('ifs', {})), 'addresses': sum(len(v) for v in d.get('addrs', {}).values())})
        if not d.get('ok'):
            out.update({'error': d.get('error'), 'error_text': snmp_error_text(d.get('error'), e, ip), 'detail': d.get('detail', '')})
        c = ifcounters.load_status().get(ip) if e.get('enabled') else None     # (1.14.0) the collector's minute reads
        if c:
            out['counters'] = {'t': c.get('t', 0), 'ok': c.get('ok', False), 'interfaces': c.get('interfaces', 0), 'error': c.get('error')}
    return out


def snmp_error_text(code, e, ip):
    where = f"{e.get('host') or ip}:{e.get('port', 161)}"
    v3 = e.get('version') == '3'
    return {
        'timeout': tr('No answer from {where}. Check that SNMP is on, that the device lets this server in (trusted hosts / allowed addresses, '
                      'SNMP access on the interface), UDP {port} on the way, and the privacy password and protocol — with wrong ones the '
                      'device does not answer.', where=where, port=e.get('port', 161)) if v3 else
                   tr('No answer from {where}. Check that SNMP is on, that the device lets this server in (trusted hosts / allowed addresses, '
                      'SNMP access on the interface), UDP {port} on the way, and the community — with a wrong one the device does not answer.',
                      where=where, port=e.get('port', 161)),
        'user': tr('The device does not know the SNMPv3 user «{user}».', user=e.get('user', '')),
        'auth': tr('Wrong authentication password or protocol.'),
        'priv': tr('Wrong privacy (encryption) password or protocol.'),
        'level': tr('The device does not allow this security level for the user.'),
        'host': tr('Unknown host {host}.', host=e.get('host')),
        'tool': tr('The net-snmp tools are not installed on the server (package snmp): run sudo flowtrack upgrade.'),
    }.get(code, tr('The device answered with an error.'))


def api_devices(q):
    exp = exporters_cfg(raw=True)
    sset, sdata = snmp.load_settings(), snmp.load_data()
    cnt = sflow_counters()
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
    del pub, selfs
    # the collector already sorted every record by its ends (dir): the sender is public on 'down' and 'transit'
    # records, the receiver on 'up' and 'transit' — so the 5-minute totals per interface pair answer it (1.8.1;
    # before, two passes over a day of records, address by address)
    day, _ = rollups.source(['in_if', 'out_if'], int(time.time()) - 86400, None, set(), use=USE_ROLLUPS)
    ifs = ch(f"""SELECT exporter, i, sum(b) AS bytes, sum(e) AS ext FROM (
            SELECT exporter, in_if AS i, bytes AS b, if(dir IN ('down', 'transit'), bytes, 0) AS e FROM {day}
            UNION ALL SELECT exporter, out_if AS i, bytes AS b, if(dir IN ('up', 'transit'), bytes, 0) AS e FROM {day})
        GROUP BY exporter, i ORDER BY exporter, i""", fmt='JSON')
    seen_addrs = iface_hints()
    # records reported twice although the exporter sends no direction field (both directions monitored on
    # several interfaces): identical flow, interfaces, start time and size
    dups = {r['exporter']: r for r in ch("""SELECT exporter, count() AS n, uniqExact(cityHash64(int_ip, ext_ip, int_port, ext_port, proto, in_if, out_if, ts_start, bytes)) AS u,
            countIf(obs != 255) AS with_dir FROM flows WHERE ts >= now() - INTERVAL 5 MINUTE GROUP BY exporter""", fmt='JSON')}
    # the latest minute's sampling, unless the devices were edited since: the collector applies a new ratio within
    # about a minute, so until its stats cover that time show the configured one (changed in the UI -> shown at once)
    cfg_changed = max(exporters_mtime())
    out = []
    seen = {s['exporter'] for s in stats}
    for ip in exp:
        if ip not in seen:
            stats.append({'exporter': ip, 'version': 0, 'packets': 0, 'records': 0, 'lost': 0, 'no_template': 0, 'errors': 0, 'templates': 0, 'last': 0, 'span': 60, 'sampling_n': 0, 'dup_dropped': 0, 'dup_packets': 0})
    try:                   # exporters the collector found to send running totals of long sessions (core 1.4.1)
        with open(os.path.join(STATE_DIR, 'running.json')) as f:
            running = set(json.load(f))
    except (OSError, ValueError, TypeError):
        running = set()
    for s in stats:
        c = exp.get(s['exporter'], {})
        names = c.get('if_names', {})
        recs, span = int(s['records']), max(60, int(s['span']))
        out.append({'ip': s['exporter'], 'name': c.get('name', s['exporter']), 'vendor': c.get('vendor', ''), 'model': c.get('model', ''),
                    'site': ', '.join(x for x in (c.get('city', ''), c.get('country', '')) if x), 'proto': PROTO_LABEL.get(PROTOCOLS.get(int(s['version'])), f"v{s['version']}"),
                    'detected': PROTOCOLS.get(int(s['version']), '') if int(s['last']) else '',
                    'rps': round(recs / span, 1), 'packets': int(s['packets']), 'records': recs, 'lost': int(s['lost']),
                    'loss_pct': round(100 * int(s['lost']) / max(1, int(s['packets']) + int(s['lost'])), 2), 'no_template': int(s['no_template']),
                    'errors': int(s['errors']), 'templates': int(s['templates']), 'last': int(s['last']),
                    'dup_dropped': int(s.get('dup_dropped') or 0), 'dup_packets': int(s.get('dup_packets') or 0),
                    'dup_pct': round(100 * (int(dups[s['exporter']]['n']) - int(dups[s['exporter']]['u'])) / max(1, int(dups[s['exporter']]['n'])), 2) if s['exporter'] in dups else 0,
                    'direction_field': bool(s['exporter'] in dups and int(dups[s['exporter']]['with_dir'])),
                    'running_totals': s['exporter'] in running,
                    'sampling': f"1:{int(s['sampling_n'])}" if int(s.get('sampling_n') or 0) > 1 and int(s['last']) > cfg_changed + 120 else c.get('sampling', '1:1'),
                    'wan_ifs': c.get('wan_ifs', []), 'configured': s['exporter'] in exp,
                    'config': {k: c.get(k) for k in ('name', 'vendor', 'protocol', 'model', 'wan_ifs', 'local_if', 'public_ips', 'city', 'country', 'lat', 'lon', 'sampling', 'export_ifs')},
                    'snmp': snmp_status(s['exporter'], sset, sdata),
                    'interfaces': interfaces_of(c, [r for r in ifs if r['exporter'] == s['exporter']], seen_addrs.get(s['exporter'], {}),
                                                sdata.get(s['exporter']) if sset.get(s['exporter'], {}).get('enabled') else None,
                                                cnt.get(s['exporter'], {}))})
    return {'devices': out, 'collector': collector_health(), 'listen': listen_info(), 'snmp_tools': snmp.available()}


def api_ifload(q):
    """(1.12.0) The load of each interface of a device: bit/s entering it (as the input interface) and leaving it (as
    the output one) per 5 minutes — all the traffic through the device, whatever the traffic selector and the filters —
    with the average, the 95th percentile and the peak against its capacity. Buckets without records count as 0."""
    try:
        dev = str(ipaddress.ip_address(q1(q, 'device', '').strip()))
    except ValueError:
        raise BadRequest(tr('Invalid device IP address'))
    qq = {k: q[k] for k in ('range', 'from', 'to') if k in q}
    qq.update(f=[json.dumps([{'k': 'device', 'v': dev}])], t=['all'])
    where, p, rng, step = scope(qq)
    p['_step'] = 300
    # (1.17.0) each record goes to its two interfaces in ClickHouse: grouped by the PAIR, a firewall with 250 VLANs
    # (63,000 pairs) sent 6.4 M rows a day for Python to add up — 20 s against 1 s of the query
    sql, _ = rollups.source(['in_if', 'out_if'], p['_t0'], p['_t1'], p['_fcols'], use=USE_ROLLUPS, step=300, table=p.get('_flows', 'flows'), turn=p.get('_turn'))
    rows = ch(f"""SELECT toUnixTimestamp(toStartOfInterval(ts, INTERVAL 300 SECOND)) AS t, x.1 AS i, x.2 AS d, sum(bytes) AS b
        FROM {sql} ARRAY JOIN [(in_if, 0), (out_if, 1)] AS x WHERE ({p['_filt']}) AND x.1 != 0 GROUP BY t, i, d""", p, fmt='JSON')
    t0 = p['_t0'] // 300 * 300
    n = max(1, (p['t1'] - t0 + 299) // 300)
    acc = {}
    for r in rows:
        k = (int(r['t']) - t0) // 300
        if 0 <= k < n:
            acc.setdefault(int(r['i']), [[0] * n, [0] * n])[int(r['d'])][k] += int(r['b'])
    c = exporters_cfg(raw=True).get(dev, {})
    sset, sdata = snmp.load_settings(), snmp.load_data()
    sn = sdata.get(dev) if sset.get(dev, {}).get('enabled') else None
    cnt = sflow_counters().get(dev, {})
    chunk = max(1, -(-n // 300))           # the chart: at most 300 points (a day stays at 5 minutes), each the busiest 5 minutes in it
    out = []
    for idx in sorted(set(acc) | {int(k) for k in (c.get('if_caps') or {})}):
        info = if_info(c, idx, sn, cnt)
        series = acc.get(idx, [[0] * n, [0] * n])
        d = {}
        for name, b, cap in (('in', series[0], info['cap_in']), ('out', series[1], info['cap_out'])):
            bps = [x * 8 / 300 for x in b]
            srt = sorted(bps)
            st = {'avg': sum(bps) / n, 'p95': srt[min(n - 1, int(0.95 * n))], 'peak': srt[-1], 'bytes': sum(b)}
            st.update({f'{k}_pct': round(100 * st[k] / (cap * 1e6), 1) if cap else None for k in ('avg', 'p95', 'peak')})
            d[name] = st
        pts = [[t0 + i * 300, max(series[0][i:i + chunk]) * 8 / 300, max(series[1][i:i + chunk]) * 8 / 300] for i in range(0, n, chunk)]
        out.append({'index': idx, 'name': info['name'], 'role': info['role'], 'cap_in': info['cap_in'], 'cap_out': info['cap_out'],
                    'cap_own': info['cap_own'], 'cap_auto': info['cap_auto'], 'in': d['in'], 'out': d['out'], 'series': pts})
    # the fullest first (by peak share of capacity), then the busiest of those without a known capacity
    out.sort(key=lambda i: (-max(i['in']['peak_pct'] or -1, i['out']['peak_pct'] or -1), -(i['in']['bytes'] + i['out']['bytes'])))
    return {'device': dev, 'from': t0, 'to': p['t1'], 'step': 300, 'chart_step': 300 * chunk, 'interfaces': out}



def if_info(c, idx, sn, cnt):
    """An interface's name, role and capacity, with the sFlow counters' ifSpeed when SNMP knows no speed."""
    info = iface(c, idx, 0, 0, (), sn)
    sp = int((cnt.get(idx) or {}).get('speed') or 0) // 1_000_000
    if sp and not info['cap_auto']:
        info.update(cap_auto=sp, **({} if info['cap_own'] else {'cap_in': sp, 'cap_out': sp}))
    return info


CAP_DAYS = (7, 30, 90, 180, 365)
P95_SKIP = 300 * 5 // 100           # 288 five-minute buckets a day: the 95th percentile is the 15th busiest (14 above it)


TZ_OLD = {'Europe/Kyiv': 'Europe/Kiev', 'Europe/Kiev': 'Europe/Kyiv'}     # renamed in tzdata 2022b: one side may lack either


def _tz(q):
    """The browser's time zone for whole local days; its old / new name when the server's tzdata has only that, else
    the server's own zone (days a few hours off are better than no page)."""
    tz = q1(q, 'tz', '')
    for name in (tz, TZ_OLD.get(tz)):
        if not name:
            continue
        try:
            reports.ZoneInfo(name)
            return name
        except (reports.ZoneInfoNotFoundError, ValueError):
            pass
    return reports.system_tz()


def _five_min(p):
    """5-minute totals per device, interface and direction (0 = into it, as the input interface; 1 = out of it).
    (1.14.0) Each record goes to its two interfaces as it is read: grouping by the PAIR of interfaces first ran out of
    memory on a busy firewall (thousands of VLAN / tunnel pairs × 8,640 buckets in 30 days, a customer on 1.13.1)."""
    sql, _ = rollups.source(['in_if', 'out_if'], p['_t0'], p['_t1'], p['_fcols'], use=USE_ROLLUPS, step=p['_step'], table=p.get('_flows', 'flows'), turn=p.get('_turn'))
    return f"""SELECT exporter, x.1 AS i, x.2 AS d, toStartOfInterval(ts, INTERVAL 300 SECOND) AS t, sum(bytes) AS v
        FROM {sql} ARRAY JOIN [(in_if, 0), (out_if, 1)] AS x WHERE ({p['_filt']}) AND x.1 != 0 GROUP BY exporter, i, d, t"""


# (1.14.0) the Capacity queries spill their grouping to disk rather than fail on a big network
CAP_SETTINGS = {'max_bytes_before_external_group_by': CH_QUERY_MEMORY * 2 // 5, 'max_bytes_before_external_sort': CH_QUERY_MEMORY * 2 // 5}


def _cap_scope(q, extra_f=()):
    """(days, tz, where, p): whole local days back from today (today so far included), all traffic, no filters."""
    days = q1(q, 'days', '30', int)
    days = max(d for d in CAP_DAYS if d <= max(days, CAP_DAYS[0]))
    days = min(days, view_days())
    tz = _tz(q)
    now = int(time.time())
    today = int(ch("SELECT toUnixTimestamp(toStartOfDay(now(), {tz:String})) AS d", {'tz': tz}, fmt='JSON')[0]['d'])
    t0 = today - (days - 1) * 86400
    qq = {'from': [str(t0)], 'to': [str(now)], 't': ['all'], 'f': [json.dumps(list(extra_f))]}
    where, p, _, _ = scope(qq)
    p.update(_step=300, tz=tz, k=P95_SKIP)
    return days, tz, today, p


def _cap_filter(q):
    """(1.13.0) Capacity follows the device and interface filters (an interface by number or by name; several of one
    key: any of them; '-' leaves out) -> (keep(dev, idx, info), the keys of the other filters, which do not apply:
    a link is full or not whatever part of its traffic one looks at)."""
    try:
        flt = json.loads(q.get('f', ['[]'])[0])
    except ValueError:
        raise BadRequest('bad filter JSON')
    flt = [f for f in flt if isinstance(f, dict)] if isinstance(flt, list) else []
    cfg = exporters_cfg(raw=True)

    def hit(f, dev, idx, info):
        v = str(f.get('v', '')).strip()
        if f['k'] == 'device':
            return v == dev or v.lower() == str(cfg.get(dev, {}).get('name', '')).lower()
        return str(idx) == v if v.isdigit() else v.lower() in (info['name'].lower(), info['snmp_name'].lower())
    use = [f for f in flt if f.get('k') in ('device', 'iface')]

    def keep(dev, idx, info):
        for k in ('device', 'iface'):
            pos = [f for f in use if f['k'] == k and not f.get('neg')]
            if pos and not any(hit(f, dev, idx, info) for f in pos):
                return False
        return not any(hit(f, dev, idx, info) for f in use if f.get('neg'))
    return keep, sorted({str(f.get('k')) for f in flt if f.get('k') not in ('device', 'iface')})


def counter_days(p, where=''):
    """-> ({(dev, idx, src, d, day): {...}}, {(dev, idx, src, d): {...}}): per local day and over the period — the
    95th percentile of the 5-minute rates, the busiest minute (one read to the next), the bytes and the 5-minute
    buckets seen (m)."""
    p['c0'] = p['_t0'] - 300          # the read before the period: the first rate inside it
    rs = ifcounters.rates_state()
    if rs and rs[1] <= p['_t0'] < rs[0] and not where:
        # (1.16.2) the rates made in 5-minute buckets (ifcounters.Rates), the last minutes since then from the reads: before,
        # every read of the period went through a window function at once — a FortiGate with hundreds of interfaces had
        # 21 M reads in a month, ~250 bytes each: «Not enough memory» on Capacity
        p.update(rdn=rs[0], rc0=rs[0] - ifcounters.MAX_GAP)
        five = f"""SELECT exporter, i, src, d, toUnixTimestamp(toStartOfDay(t5, {{tz:String}})) AS day, t5, b, sdt, pk FROM (
                SELECT t5, exporter, i, src, d, b, sdt, pk FROM if_rate5 FINAL WHERE t5 >= toDateTime({{t0:UInt32}}) AND t5 < toDateTime({{rdn:UInt32}})
                UNION ALL {ifcounters.five_sql(t0='rdn', c0='rc0')})"""
    else:
        five = f"""SELECT exporter, i, src, d, toUnixTimestamp(toStartOfDay(ts, {{tz:String}})) AS day, toStartOfInterval(ts, INTERVAL 300 SECOND) AS t5,
                sum(delta) AS b, sum(dt) AS sdt, max(delta * 8 / dt) AS pk FROM ({ifcounters.rates_sql(where)}) WHERE ts >= toDateTime({{t0:UInt32}})
                GROUP BY exporter, i, src, d, day, t5"""
    keys = ('exporter', 'i', 'src', 'd')
    day = {}
    for r in ch(f"""SELECT exporter, i, src, d, day, sum(b) AS bytes, count() AS m, max(pk) AS peak, quantileExact(0.95)(b * 8 / sdt) AS p95
            FROM ({five}) GROUP BY exporter, i, src, d, day""", dict(p, t0=p['_t0']), fmt='JSON', timeout=120):
        day[(r['exporter'], int(r['i']), r['src'], int(r['d']), int(r['day']))] = {'bytes': int(r['bytes']), 'm': int(r['m']), 'peak': float(r['peak']), 'p95': float(r['p95'])}
    per = {}
    for r in ch(f"""SELECT exporter, i, src, d, sum(b) AS bytes, count() AS m, sum(sdt) AS secs, max(pk) AS peak, quantileExact(0.95)(b * 8 / sdt) AS p95,
                toUnixTimestamp(min(t5)) AS first
            FROM ({five}) GROUP BY exporter, i, src, d""", dict(p, t0=p['_t0']), fmt='JSON', timeout=120):
        per[tuple(r[k] if k in ('exporter', 'src') else int(r[k]) for k in keys)] = {'bytes': int(r['bytes']), 'm': int(r['m']), 'secs': int(r['secs']),
                                                                                    'peak': float(r['peak']), 'p95': float(r['p95']), 'first': int(r['first'])}
    return day, per


SEEN_MIN = 3 * 3600      # (1.15.1) hours of counters before «what the flows see»: long sessions report every 30 minutes
SEEN_DAYS = 3            # (1.15.2) over the last days only


def flows_seen(p, cper):
    """(1.15.1) {(dev, idx, d): % of the counted bytes the flows carry} over the time both have — from a device's first
    counter read (+ 10 minutes, the first read gives no rate) to 10 minutes ago (the flows of the last minutes are still
    coming) — as soon as that is SEEN_MIN long; before, it waited for whole days (a new SNMP device showed nothing)."""
    end = int(time.time()) // 300 * 300 - 600
    starts = {}
    for (dev, idx, src, d), v in cper.items():
        starts[dev] = min(starts.get(dev, v['first']), v['first'])
    # (1.15.2) at most the last SEEN_DAYS: the share follows a change of the export (a sampler switched on) within days,
    # and records stored before a fix of the collector do not weigh on it for the whole period
    # (1.16.2) whole 5-minute buckets, as the flows side always was (its buckets from the start on)
    starts = {dev: -(-max(t + 600, p['_t0'], end - SEEN_DAYS * 86400) // 300) * 300 for dev, t in starts.items()}
    starts = {dev: t for dev, t in starts.items() if end - t >= SEEN_MIN}
    if not starts:
        return {}
    q = dict(p, cE=end)
    conds = []
    for n, (dev, t) in enumerate(sorted(starts.items())):
        q[f'cx{n}'], q[f'ct{n}'] = dev, t
        conds.append(f'(exporter = {{cx{n}:String}} AND {{col}} >= toDateTime({{ct{n}:UInt32}}))')
    cond = lambda col: '(' + ' OR '.join(c.replace('{col}', col) for c in conds) + ')'      # noqa: E731
    flows = {(r['exporter'], int(r['i']), int(r['d'])): int(r['b']) for r in ch(f"""SELECT exporter, i, d, sum(v) AS b FROM ({_five_min(p)})
        WHERE {cond('t')} AND t < toDateTime({{cE:UInt32}}) GROUP BY exporter, i, d""", q, fmt='JSON', timeout=120, settings=CAP_SETTINGS)}
    ctr = {}
    rs = ifcounters.rates_state()
    if rs and rs[1] <= min(starts.values()) and end <= rs[0]:     # (1.16.2) from the 5-minute rates (the starts are buckets)
        sql = f"SELECT exporter, i, src, d, sum(b) AS b FROM if_rate5 FINAL WHERE {cond('t5')} AND t5 < toDateTime({{cE:UInt32}}) GROUP BY exporter, i, src, d"
    else:
        q['c0'] = q.get('c0', p['_t0'] - 300)
        sql = f"""SELECT exporter, i, src, d, sum(delta) AS b FROM ({ifcounters.rates_sql()}) WHERE {cond('ts')} AND ts < toDateTime({{cE:UInt32}})
            GROUP BY exporter, i, src, d"""
    for r in ch(sql, q, fmt='JSON', timeout=120):
        key = (r['exporter'], int(r['i']), int(r['d']))
        if r['src'] == 'snmp' or key not in ctr:
            ctr[key] = int(r['b'])
    return {k: round(100 * flows.get(k, 0) / b, 1) for k, b in ctr.items() if b > 10_000_000}

def api_capacity(q):
    """(1.13.0) Capacity planning: every interface of every device, day by day over whole local days — the busiest 5
    minutes, the 95th percentile of the 5-minute load (empty ones count as 0) and the bytes, into and out of it — with
    the trend, the forecast (capacity.py) and one status, the fullest first."""
    days, tz, today, p = _cap_scope(q)
    rows = ch(f"""SELECT exporter, i, d, toUnixTimestamp(toStartOfDay(t, {{tz:String}})) AS day, sum(v) AS bytes, max(v) AS peak, count() AS m,
            if(count() > {{k:UInt32}}, arrayElement(arraySort(groupArray(v)), toUInt32(count() - {{k:UInt32}})), 0) AS p95
        FROM ({_five_min(p)}) GROUP BY exporter, i, d, day""", p, fmt='JSON', timeout=120, settings=CAP_SETTINGS)
    # the period's own 95th percentile: over its 5-minute buckets from the interface's first record on (a device added
    # last week is not diluted by the weeks before it), the empty ones as 0; `span` = those seconds, for the average
    per = {(r['exporter'], int(r['i']), int(r['d'])): (int(r['p95']), int(r['span'])) for r in ch(f"""SELECT exporter, i, d,
            intDiv({{t1:UInt32}} - toUnixTimestamp(min(t)) + 299, 300) AS n, n * 300 AS span,
            if(count() > intDiv(n * 5, 100), arrayElement(arraySort(groupArray(v)), toUInt32(count() - intDiv(n * 5, 100))), 0) AS p95
        FROM ({_five_min(p)}) GROUP BY exporter, i, d""", p, fmt='JSON', timeout=120, settings=CAP_SETTINGS)}
    by = {}
    for r in rows:
        by.setdefault((r['exporter'], int(r['i'])), []).append(r)
    # (1.14.0) the interfaces' own counters where a device has them: SNMP before sFlow; also links without any flows
    cday, cper = counter_days(p)
    csrc = {}
    for dev, idx, src, d in cper:
        if csrc.get((dev, idx)) != 'snmp':
            csrc[(dev, idx)] = src
    for key in csrc:
        by.setdefault(key, [])
    seen_all = flows_seen(p, cper) if cper else {}
    keep, skipped = _cap_filter(q)
    cfg = exporters_cfg(raw=True)
    sset, sdata = snmp.load_settings(), snmp.load_data()
    cnts = sflow_counters()
    out = []
    for (dev, idx), rs in by.items():
        src = csrc.get((dev, idx))
        total = max(sum(int(r['bytes']) for r in rs), sum(v['bytes'] for k, v in cper.items() if k[:3] == (dev, idx, src)))
        c = cfg.get(dev, {})
        own = str(idx) in (c.get('if_caps') or {})
        if total < 1_000_000 and not own:
            continue
        info = if_info(c, idx, sdata.get(dev) if sset.get(dev, {}).get('enabled') else None, cnts.get(dev, {}))
        if not keep(dev, idx, info):
            continue
        series = {}
        for r in rs:
            e = series.setdefault(int(r['day']), [int(r['day']), 0, 0, 0, 0, 0, 0, 0])
            d = int(r['d'])
            e[1 + d], e[3 + d] = int(r['p95']) * 8 / 300, int(r['peak']) * 8 / 300
            e[5] = max(e[5], int(r['m']))
            e[6] += int(r['bytes'])
        # a day with counters for at least half of it takes their figures (every octet, the busiest minute); what the
        # flows see: flows_seen, over the hours both have
        seen = {}
        # (1.15.1) a link no flow describes has the counters as its only source: their days count from the first read
        only_ctr = bool(src) and not any(int(r['bytes']) for r in rs)
        for d in (0, 1):
            cdays = {k[4]: v for k, v in cday.items() if k[:4] == (dev, idx, src, d) and (v['m'] >= 144 or only_ctr and v['m'] > 0)}
            for dy, v in cdays.items():
                e = series.setdefault(dy, [dy, 0, 0, 0, 0, 0, 0, 0])
                e.extend([0] * (8 - len(e)))
                e[1 + d], e[3 + d], e[5], e[7] = v['p95'], v['peak'], max(e[5], v['m']), 1
            seen['in' if d == 0 else 'out'] = seen_all.get((dev, idx, d))
        days_l = [series[k] + [0] * (8 - len(series[k])) for k in sorted(series)]
        first = days_l[0][0] if days_l else today
        ctr = bool(src) and (only_ctr or sum(1 for e in days_l if e[7]) * 2 >= max(1, len(days_l)))     # counters for most days
        dirs = {}
        for name, d, cap in (('in', 0, info['cap_in']), ('out', 1, info['cap_out'])):
            pts = [(round((e[0] - first) / 86400), e[1 + d]) for e in days_l if e[0] < today and e[5] >= 144]
            tr_ = capacity.trend(pts)
            fc = capacity.forecast(tr_, cap * 1e6)
            peak = max((e[3 + d] for e in days_l), default=0)
            if ctr and (dev, idx, src, d) in cper:
                cp = cper[(dev, idx, src, d)]
                p95, span, byts = cp['p95'], cp['secs'], cp['bytes']
            else:
                p95, span = per.get((dev, idx, d), (0, 0))
                p95 = p95 * 8 / 300
                byts = sum(int(r['bytes']) for r in rs if int(r['d']) == d)
            pct = (lambda v: round(100 * v / (cap * 1e6), 1) if cap else None)
            dirs[name] = {'peak': peak, 'p95': p95, 'avg': byts * 8 / max(300, span), 'bytes': byts, 'since': p['t1'] - span if span else None,
                          'peak_pct': pct(peak), 'p95_pct': pct(p95), 'trend': tr_ and {**{k: tr_[k] for k in ('slope', 'level', 'busy', 'days')}, 'last_day': first + tr_['last'] * 86400},
                          'forecast': fc, 'status': capacity.status(pct(peak), pct(p95), fc)}
        worst = min(('in', 'out'), key=lambda k: (capacity.RANK[dirs[k]['status']], -(dirs[k]['p95_pct'] or 0), -dirs[k]['p95']))
        out.append({'device': dev, 'device_name': c.get('name') or dev, 'index': idx, 'name': info['name'], 'role': info['role'],
                    'cap_in': info['cap_in'], 'cap_out': info['cap_out'], 'cap_own': info['cap_own'], 'cap_auto': info['cap_auto'],
                    'in': dirs['in'], 'out': dirs['out'], 'worst': worst, 'status': dirs[worst]['status'],
                    'source': src if ctr else 'flows', 'seen_pct': seen if src else None, 'counters': src,
                    'counters_since': min((v['first'] for k, v in cper.items() if k[:3] == (dev, idx, src)), default=None) if src else None,
                    'days': [e[:5] + [e[7]] for e in days_l]})
    out.sort(key=lambda x: (capacity.RANK[x['status']], -(x[x['worst']]['p95_pct'] or -1), -(x['in']['bytes'] + x['out']['bytes'])))
    counts = {k: sum(1 for x in out if x['status'] == k) for k in capacity.RANK}
    return {'unfiltered': skipped, 'days': days, 'max_days': view_days(), 'choices': [d for d in CAP_DAYS if d <= max(view_days(), CAP_DAYS[0])], 'tz': tz,
            'from': p['_t0'], 'to': p['t1'], 'today': today, 'forecast_days': capacity.FORECAST_DAYS,
            'watch_pct': capacity.WATCH_PCT, 'full_pct': capacity.FULL_PCT, 'counts': counts, 'interfaces': out}


def api_capacity_iface(q):
    """(1.13.0) One interface in depth: the load by weekday and hour (the busiest 5 minutes of each hour, averaged over
    the weeks) and what drives it — the inside hosts and the services on it, the recent half of the period against the
    earlier one."""
    try:
        dev = str(ipaddress.ip_address(q1(q, 'device', '').strip()))
    except ValueError:
        raise BadRequest(tr('Invalid device IP address'))
    idx = q1(q, 'if', '0', int)
    days, tz, today, p = _cap_scope(q, [{'k': 'device', 'v': dev}, {'k': 'iface', 'v': str(idx)}])
    p['idx'] = idx
    heat = ch(f"""SELECT d, w, h, avg(mx) AS v FROM (
            SELECT d, toDayOfWeek(t, 0, {{tz:String}}) AS w, toHour(t, {{tz:String}}) AS h, toStartOfHour(t) AS hr, max(v) AS mx
            FROM ({_five_min(p)}) WHERE i = {{idx:UInt32}} GROUP BY d, w, h, hr)
        GROUP BY d, w, h""", p, fmt='JSON', timeout=120, settings=CAP_SETTINGS)
    grid = {'in': [[0] * 24 for _ in range(7)], 'out': [[0] * 24 for _ in range(7)]}
    for r in heat:
        grid['in' if int(r['d']) == 0 else 'out'][int(r['w']) - 1][int(r['h'])] = float(r['v']) * 8 / 300
    # the recent half of the interface's history in the period against the earlier one (whole hours: the per-host
    # table sums hours)
    first = int(ch(f"SELECT toUnixTimestamp(min(t)) AS f FROM ({_five_min(p)}) WHERE i = {{idx:UInt32}}", p, fmt='JSON', timeout=120, settings=CAP_SETTINGS)[0]['f'] or p['_t0'])
    first = max(first, p['_t0'])
    p['mid'] = (first + (p['t1'] - first) // 2) // 3600 * 3600
    drivers = {}
    for key, col in (('hosts', 'int_ip'), ('services', 'service')):
        rows = ch(f"""SELECT {col} AS k, sumIf(bytes, ts >= toDateTime({{mid:UInt32}})) AS b2, sumIf(bytes, ts < toDateTime({{mid:UInt32}})) AS b1
            FROM {src(p, ['in_if', 'out_if', col])} AND {col} != '' GROUP BY k ORDER BY b1 + b2 DESC LIMIT 10""", p, fmt='JSON', timeout=120)
        drivers[key] = [{'k': r['k'], 'name': NAMES.get(r['k']) if col == 'int_ip' else None, 'recent': int(r['b2']), 'earlier': int(r['b1'])} for r in rows]
    return {'device': dev, 'index': idx, 'days': days, 'tz': tz, 'mid': p['mid'], 'from': first, 'to': p['t1'],
            'heat': grid, **drivers}


USAGE_PERIODS = ('month', 'prev_month', '7', '30', '90', '180', '365')
USAGE_ROWS = 500
UP_SQL, DN_SQL = "sumIf(bytes, dir IN ('up', 'internal'))", "sumIf(bytes, dir NOT IN ('up', 'internal'))"


def _usage_period(q, tz):
    """(1.15.0) -> (t0, t1, kind, label key): this month so far, last month, or the last N whole local days (today so
    far included); never older than the edition keeps."""
    import datetime as _dt
    floor = int(time.time()) - view_days() * 86400
    if not q.get('period'):
        # (1.18.0) the page's own period (the shared one at the top: a preset that ends now or chosen dates), as on
        # every other page — Usage no longer has a period switch of its own (Yegor)
        t0, t1, custom = period(q)
        if t1 - t0 >= LONG:
            t0 = t0 // 3600 * 3600
        return max(t0, floor), t1, 'range', floor
    per = q1(q, 'period', '30')
    if per not in USAGE_PERIODS:
        raise BadRequest('bad period')
    z = reports.ZoneInfo(tz)
    now = _dt.datetime.now(z)
    day0 = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if per == 'month':
        t0, t1 = day0.replace(day=1), now
    elif per == 'prev_month':
        t1 = day0.replace(day=1)
        t0 = (t1 - _dt.timedelta(days=1)).replace(day=1)
    else:
        t0, t1 = day0 - _dt.timedelta(days=int(per) - 1), now
    return max(int(t0.timestamp()), floor), int(t1.timestamp()), per, floor


def api_usage(q):
    """(1.15.0) Usage by host: what each inside host downloaded and uploaded over a period (since 1.18.0 the page's
    shared period; `period` = this month, last month or the last 7 – 365 days stays for other callers), against the same length of time before it; the totals
    day by day (month by month over 92 days) and the hosts, the busiest first (USAGE_ROWS; all of them:
    /api/top?dim=int_ip&limit=all, also as CSV). The filters and the traffic selector apply as on every page."""
    tz = _tz(q)
    t0, t1, per, floor = _usage_period(q, tz)
    if t1 - t0 < 60:
        raise BadRequest(tr('No data for this period yet'))
    qq = {k: v for k, v in q.items() if k in ('f', 't')}
    qq.update({'from': [str(t0)], 'to': [str(t1)]})
    where, p, _, _ = scope(qq)
    p['tz'] = tz
    span = t1 - t0
    pt0, pt1 = t0 - span, t0
    bucket = 'hour' if span <= 2 * 86400 else 'day' if span <= 92 * 86400 else 'month'
    bexpr = {'hour': "toUnixTimestamp(toStartOfHour(ts))", 'day': "toUnixTimestamp(toStartOfDay(ts, {tz:String}))",
             'month': "toUnixTimestamp(toDateTime(toStartOfMonth(ts, {tz:String}), {tz:String}))"}[bucket]
    cur, prev = src(p, ['int_ip'], t0, t1), src(p, ['int_ip'], pt0, pt1)
    series = ch(f"""SELECT {bexpr} AS t, {UP_SQL} AS up, {DN_SQL} AS dn, uniqExact(cityHash64(int_ip)) AS hosts
        FROM {cur} AND ts < toDateTime({{t1:UInt32}}) GROUP BY t ORDER BY t""", dict(p, t1=t1), fmt='JSON', timeout=120, settings=CAP_SETTINGS)
    tot = ch(f"""SELECT {UP_SQL} AS up, {DN_SQL} AS dn, uniqExact(cityHash64(int_ip)) AS hosts FROM {cur} AND ts < toDateTime({{t1:UInt32}})""",
             dict(p, t1=t1), fmt='JSON', timeout=120)[0]
    # the period before is compared only when the data reach back to its start: on a new installation the days
    # before the first record are no «zero» to grow from (every host would look new)
    oldest = int(ch("SELECT toUnixTimestamp(min(ts)) AS t FROM flows", fmt='JSON')[0]['t'] or 0)
    ptot = ch(f"""SELECT {UP_SQL} AS up, {DN_SQL} AS dn, uniqExact(cityHash64(int_ip)) AS hosts FROM {prev} AND ts < toDateTime({{t1:UInt32}})""",
              dict(p, t1=pt1), fmt='JSON', timeout=120)[0] if pt0 >= floor and 0 < oldest <= pt0 + 3600 else None
    p['lim'] = USAGE_ROWS
    rows = ch(f"""SELECT int_ip AS k, {UP_SQL} AS up, {DN_SQL} AS dn, uniqExact(toDate(ts, {{tz:String}})) AS days
        FROM {cur} AND ts < toDateTime({{t1:UInt32}}) GROUP BY k ORDER BY up + dn DESC LIMIT {{lim:UInt32}}""",
              dict(p, t1=t1), fmt='JSON', timeout=120, settings=CAP_SETTINGS)
    before = {}
    if rows and ptot is not None:
        p['hs'] = [r['k'] for r in rows]
        before = {r['k']: (int(r['up']), int(r['dn'])) for r in ch(f"""SELECT int_ip AS k, {UP_SQL} AS up, {DN_SQL} AS dn
            FROM {prev} AND ts < toDateTime({{t1:UInt32}}) AND int_ip IN {{hs:Array(String)}} GROUP BY k""", dict(p, t1=pt1), fmt='JSON', timeout=120)}
    hosts = [{'k': r['k'], 'name': NAMES.get(r['k'], lookup=False), 'net': common.network_of(r['k']), 'up': int(r['up']), 'dn': int(r['dn']),
              'days': int(r['days']), **({'prev_up': before.get(r['k'], (0, 0))[0], 'prev_dn': before.get(r['k'], (0, 0))[1]} if ptot is not None else {})}
             for r in rows]
    num = lambda d: {k: int(d[k]) for k in ('up', 'dn', 'hosts')} if d else None      # noqa: E731
    return {'period': per, 'periods': list(USAGE_PERIODS), 'max_days': view_days(), 'tz': tz, 'from': t0, 'to': t1,
            'prev_from': pt0, 'prev_to': pt1, 'bucket': bucket, 'cut': t0 == floor, 'since': oldest,
            'total': num(tot), 'prev': num(ptot), 'series': [[int(r['t']), int(r['up']), int(r['dn']), int(r['hosts'])] for r in series],
            'hosts': hosts, 'more': max(0, int(tot['hosts']) - len(hosts))}


CONV_NEW_DAYS = 7          # (1.18.0) a conversation is new when it was not seen in this many days before the period
CONV_RIGHT = {'owner': (['asn', 'as_org'], 'toString(asn)', 'any(as_org)'), 'country': (['country'], 'country', "''"),
              'addr': (['ext_ip'], 'ext_ip', "''")}
# (1.18.0) whom a pair talks to: the owner (AS) of the address, or the address itself when it has none
CONV_OWNER = "cityHash64(int_ip, if(asn != 0, toString(asn), ext_ip))"


def api_conversations(q):
    """(1.18.0) Conversations: who talks to whom over the period (inside host x outside address, or two inside hosts),
    from the conversations per hour (agg_conv). The cards (pairs, the biggest, the new ones, countries), the graph
    hosts -> services -> owners / countries / addresses (`right`) with the rest as '__other', the biggest pairs over
    time, and the pairs themselves, the biggest first, with the new ones apart. A pair is new when its inside host
    never talked to that owner (AS) in the CONV_NEW_DAYS days before the period (or the period before, if longer) — as
    far as the data reach back. CDNs and clouds change addresses every day: «host x address» was new for half of the
    pairs on our own network (7,797 of 15,027 a day), «host x owner» for 126 of 734."""
    where, p, rng, step = scope(q)
    internal = q1(q, 't', 'internet') == 'internal'
    right = 'addr' if internal else q1(q, 'right', 'owner')
    if right not in CONV_RIGHT:
        raise BadRequest('bad right')
    n, m, ns = (max(3, min(q1(q, k, d, int), 20)) for k, d in (('hosts', '8'), ('peers', '8'), ('services', '6')))
    p['lim'] = max(1, min(q1(q, 'limit', '50', int), 500))
    t0, floor = p['t0'], p['floor']
    pt0 = max(t0 - rng, floor)                                # the period before, for the change of each pair
    lt0 = max(min(t0 - CONV_NEW_DAYS * 86400, pt0), floor)    # how far back «talked before» looks
    oldest = int(ch("SELECT toUnixTimestamp(min(ts)) AS t FROM flows", fmt='JSON')[0]['t'] or 0)
    has_prev = pt0 < t0 and 0 < oldest <= pt0 + 3600
    looks = 0 < oldest < t0 - 3600 and lt0 < t0               # without an hour of history before, every pair would be «new»
    PC = ['int_ip', 'ext_ip', 'asn']
    parts = [f"SELECT int_ip, ext_ip, asn, ts, bytes, flows, 0 AS w FROM {src(p, PC)}"]
    before = []
    if looks:
        parts.append(f"SELECT int_ip, ext_ip, asn, ts, bytes, flows, 1 AS w FROM {src(p, PC, pt0, t0)}")
        before.append(f"SELECT int_ip, ext_ip, asn FROM {src(p, PC, pt0, t0)}")
        if lt0 < pt0:
            before.append(f"SELECT int_ip, ext_ip, asn FROM {src(p, PC, lt0, pt0)}")
    # a pair is its 64-bit hash (see api_top) with its owner's (o); w: 0 the period, 1 the period before
    old = f"o IN (SELECT {CONV_OWNER} FROM ({' UNION ALL '.join(before)}))" if before else '0'
    pairs = f"""SELECT h, o, b, f, pb, pf, {old} AS old FROM (
        SELECT cityHash64(int_ip, ext_ip) AS h, any({CONV_OWNER}) AS o, sumIf(bytes, w = 0) AS b, sumIf(flows, w = 0) AS f,
            sumIf(bytes, w = 1) AS pb, sumIf(flows, w = 1) AS pf FROM ({' UNION ALL '.join(parts)}) GROUP BY h)"""
    st = dict(CAP_SETTINGS, max_memory_usage=CH_QUERY_MEMORY)
    tot = ch(f"""SELECT countIf(f > 0) AS pairs, uniqExactIf(o, f > 0 AND NOT old) AS new_owners, countIf(f > 0 AND NOT old) AS new_pairs,
            sumIf(b, f > 0 AND NOT old) AS new_bytes, sum(b) AS bytes, countIf(pf > 0) AS prev_pairs FROM ({pairs})""",
             p, fmt='JSON', timeout=120, settings=st)[0]
    top = ch(f"SELECT h, b, pb, old FROM ({pairs}) WHERE f > 0 ORDER BY b DESC LIMIT {{lim:UInt32}} BY old",
             p, fmt='JSON', timeout=120, settings=st)
    info = {int(r['h']): r for r in top}
    rows = []
    if info:
        p['hs'] = list(info)
        rows = ch(f"""SELECT cityHash64(int_ip, ext_ip) AS h, int_ip, ext_ip, {UP_SQL} AS up, {DN_SQL} AS dn, sum(flows) AS fl,
                argMax(service, bytes) AS service, any(country) AS country, any(asn) AS asn, any(as_org) AS as_org,
                toUnixTimestamp(min(ts)) AS first, toUnixTimestamp(max(ts)) AS last
            FROM {src(p, PC + ['service', 'country', 'as_org'])} AND cityHash64(int_ip, ext_ip) IN {{hs:Array(UInt64)}}
            GROUP BY int_ip, ext_ip""", p, fmt='JSON', timeout=120)
    out = []
    for r in rows:
        x = info.get(int(r['h']))
        if x:
            out.append({'int_ip': r['int_ip'], 'ext_ip': r['ext_ip'], 'name': NAMES.get(r['int_ip']),
                        'ext_name': NAMES.get(r['ext_ip'], lookup=False), 'service': r['service'], 'country': r['country'],
                        'asn': int(r['asn']), 'owner': common.clean_org(r['as_org']) if r['as_org'] else '',
                        'up': int(r['up']), 'dn': int(r['dn']), 'fl': int(r['fl']), 'first': int(r['first']), 'last': int(r['last']),
                        'prev': int(x['pb']) if has_prev else None, 'new': bool(looks and not int(x['old']))})
    out.sort(key=lambda r: r['up'] + r['dn'], reverse=True)
    # the graph: the busiest hosts, services and peers, the rest of each as '__other'
    rcols, rkey, rlab = CONV_RIGHT[right]
    p.update(n=n + 1, m=m + 1, ns=ns + 1)
    hosts = ch(f"SELECT int_ip AS k, sum(bytes) AS b FROM {src(p, ['int_ip'])} GROUP BY k ORDER BY b DESC LIMIT {{n:UInt8}}", p, fmt='JSON', timeout=120)
    svcs = ch(f"SELECT service AS k, sum(bytes) AS b FROM {src(p, ['service'])} GROUP BY k ORDER BY b DESC LIMIT {{ns:UInt8}}", p, fmt='JSON', timeout=120)
    peers = ch(f"SELECT {rkey} AS k, {rlab} AS lab, sum(bytes) AS b FROM {src(p, rcols)} GROUP BY k ORDER BY b DESC LIMIT {{m:UInt8}}",
               p, fmt='JSON', timeout=120)
    more = {'hosts': len(hosts) > n, 'services': len(svcs) > ns, 'peers': len(peers) > m}
    hosts, svcs, peers = hosts[:n], svcs[:ns], peers[:m]
    p.update(L=[r['k'] for r in hosts], S=[r['k'] for r in svcs], R=[r['k'] for r in peers])
    links = ch(f"""SELECT if(has({{L:Array(String)}}, int_ip), int_ip, '__other') AS l, if(has({{S:Array(String)}}, service), service, '__other') AS s,
            if(has({{R:Array(String)}}, {rkey}), {rkey}, '__other') AS r, {UP_SQL} AS up, {DN_SQL} AS dn
        FROM {src(p, ['int_ip', 'service'] + rcols)} GROUP BY l, s, r HAVING up + dn > 0""", p, fmt='JSON', timeout=120, settings=st) if hosts else []
    peer_out = []
    for r in peers:
        lab = common.clean_org(r['lab']) if right == 'owner' and r['lab'] else ('' if right == 'owner' else r['k'])
        peer_out.append({'k': r['k'], 'label': lab, 'b': int(r['b']), **({'name': NAMES.get(r['k'], lookup=False)} if right == 'addr' else {})})
    # the biggest pairs over time (whole hours over a day or more: the conversations are kept per hour)
    sstep = step if rng < LONG else -(-max(step, 3600) // 3600) * 3600
    top5 = [h for h, x in sorted(info.items(), key=lambda kv: -int(kv[1]['b']))][:5]
    series = []
    if top5:
        ps = dict(p, _step=sstep, ss=sstep, h5=top5)
        series = [[int(r['t']), str(r['h']), int(r['b'])] for r in ch(f"""SELECT toUnixTimestamp(toStartOfInterval(ts, toIntervalSecond({{ss:UInt32}}))) AS t,
                cityHash64(int_ip, ext_ip) AS h, sum(bytes) AS b FROM {src(ps, PC, bucketed=True)} AND cityHash64(int_ip, ext_ip) IN {{h5:Array(UInt64)}}
            GROUP BY t, h ORDER BY t""", ps, fmt='JSON', timeout=120)]
    keys = {str(r['h']): f"{r['int_ip']}|{r['ext_ip']}" for r in rows if int(r['h']) in top5}
    countries = [] if internal else ch(f"""SELECT country AS k, sum(bytes) AS b FROM {src(p, ['country'])} AND country != ''
        GROUP BY k ORDER BY b DESC""", p, fmt='JSON', timeout=120)
    new = (lambda k: int(tot[k]) if looks else None)      # noqa: E731
    return {'from': p['t0'], 'to': p['t1'], 'range': rng, 'right': right, 'internal': internal, 'since': oldest,
            'new_from': lt0 if looks else None, 'new_days': round((t0 - max(lt0, oldest)) / 86400, 1) if looks else None,
            'prev_from': pt0 if has_prev else None,
            'total': {'pairs': int(tot['pairs']), 'bytes': int(tot['bytes']), 'prev_pairs': int(tot['prev_pairs']) if has_prev else None,
                      'new_owners': new('new_owners'), 'new_pairs': new('new_pairs'), 'new_bytes': new('new_bytes'),
                      'countries': len(countries), 'top_countries': [r['k'] for r in countries[:3]]},
            'pairs': out[:p['lim']], 'new': [r for r in out if r['new']][:p['lim']],
            'graph': {'hosts': [{'k': r['k'], 'name': NAMES.get(r['k']), 'b': int(r['b'])} for r in hosts],
                      'services': [{'k': r['k'], 'b': int(r['b'])} for r in svcs], 'peers': peer_out, 'more': more,
                      'links': [[r['l'], r['s'], r['r'], int(r['up']), int(r['dn'])] for r in links]},
            'series': {'step': sstep, 'keys': keys, 'rows': series}}


def api_qos(q):
    """(1.16.0) QoS marking under the period and the filters: the traffic of each DSCP class (on the way in), over time,
    through each interface of each device, the services of each class, and what the devices re-marked (class in ->
    class out, where the exporter sends both). 255 = the exporter did not send the marking."""
    where, p, rng, step = scope(q)
    p['step'] = step
    settings = CAP_SETTINGS
    classes = ch(f"""SELECT dscp AS k, sum(bytes) AS b, sum(packets) AS pk, sum(flows) AS fl FROM {src(p, ['dscp'])}
        GROUP BY k ORDER BY b DESC""", p, fmt='JSON', timeout=120, settings=settings)
    bucket = 'toUnixTimestamp(toStartOfInterval(ts, toIntervalSecond({step:UInt32})))'
    series = ch(f"""SELECT {bucket} AS t, dscp AS k, sum(bytes) AS b FROM {src(p, ['dscp'], bucketed=True)} GROUP BY t, k ORDER BY t""",
                p, fmt='JSON', timeout=120, settings=settings)
    ifs = ch(f"""SELECT exporter, in_if AS i, dscp AS k, sum(bytes) AS b FROM {src(p, ['in_if', 'out_if', 'dscp'])}
        GROUP BY exporter, i, k HAVING b > 0 ORDER BY b DESC LIMIT 2000""", p, fmt='JSON', timeout=120, settings=settings)
    remark = ch(f"""SELECT exporter, dscp AS a, dscp_out AS z, sum(bytes) AS b FROM {src(p, ['in_if', 'out_if', 'dscp', 'dscp_out'])}
        AND dscp_out != 255 AND dscp != 255 AND dscp_out != dscp GROUP BY exporter, a, z ORDER BY b DESC LIMIT 50""", p, fmt='JSON', timeout=120)
    both = ch(f"""SELECT sumIf(bytes, dscp_out != 255 AND dscp != 255) AS b FROM {src(p, ['in_if', 'out_if', 'dscp', 'dscp_out'])}""",
              p, fmt='JSON', timeout=120)[0]
    svc = ch(f"""SELECT dscp AS k, service AS s, sum(bytes) AS b FROM {src(p, ['dscp', 'service'])} AND service != ''
        GROUP BY k, s ORDER BY b DESC LIMIT 5 BY k""", p, fmt='JSON', timeout=120, settings=settings)
    cfg = exporters_cfg()
    names = {}
    for dev, c in cfg.items():
        for k, v in (c.get('if_names') or {}).items():
            names[(dev, int(k))] = v
    out_ifs = {}
    for r in ifs:
        key = (r['exporter'], int(r['i']))
        e = out_ifs.setdefault(key, {'device': r['exporter'], 'device_name': (cfg.get(r['exporter']) or {}).get('name') or r['exporter'],
                                     'index': key[1], 'name': names.get(key) or ('local' if key[1] == 0 else f'if {key[1]}'), 'classes': {}, 'bytes': 0})
        e['classes'][int(r['k'])] = int(r['b'])
        e['bytes'] += int(r['b'])
    return {'step': step, 'range': rng, 'from': p['t0'], 'to': p['t1'], 'names': {str(k): v for k, v in DSCP_NAMES.items()},
            'classes': [{'k': int(r['k']), 'bytes': int(r['b']), 'packets': int(r['pk']), 'flows': int(r['fl'])} for r in classes],
            'series': [[int(r['t']), int(r['k']), int(r['b'])] for r in series],
            'interfaces': sorted(out_ifs.values(), key=lambda x: -x['bytes'])[:40],
            'remarked': [{'device': r['exporter'], 'device_name': (cfg.get(r['exporter']) or {}).get('name') or r['exporter'], 'from': int(r['a']),
                          'to': int(r['z']), 'bytes': int(r['b'])} for r in remark],
            'both_known': int(both['b'] or 0),
            'services': [{'k': int(r['k']), 'service': r['s'], 'bytes': int(r['b'])} for r in svc]}

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


_NOW_CACHE, _NOW_LOCK = {}, threading.Lock()


def _alerts_now_cached(kinds, ttl=60):
    """(1.17.0) _alerts_now() once a minute for everybody: every open tab's bell asks every minute, and each asking read
    hours of records; one at a time, so tabs that ask together wait for the one answer"""
    key = (json.dumps(kinds, sort_keys=True), common.get_lang())
    with _NOW_LOCK:
        hit = _NOW_CACHE.get(key)
        if hit and time.time() - hit[0] < ttl:
            return [dict(x) for x in hit[1]]
        out = _alerts_now(kinds)
        if len(_NOW_CACHE) > 20:
            _NOW_CACHE.clear()
        _NOW_CACHE[key] = (time.time(), out)
        return [dict(x) for x in out]


def _alerts_now(kinds):
    """Anomalies computed from the latest flows (sustained upload, bursts, new countries) and the health of export,
    collector and license — all about now."""
    out = []
    # (1.17.0) the busy minutes the detector kept (ev_upload) and, after its last window, the records: before, 3 hours of
    # records were read every minute (at 5,000 records/s 54 M)
    done = detect.kept_until()
    if done and done > time.time() - 3 * 3600:
        busy = f"""SELECT int_ip, ext_ip, service, ext_port, m, b FROM ev_upload FINAL WHERE m >= now() - INTERVAL 3 HOUR AND m < toDateTime({done})
            UNION ALL {detect.upload_sql(f'toDateTime({done})', 'now()')}"""
    else:
        busy = detect.upload_sql('now() - INTERVAL 3 HOUR', 'now()')
    for r in ch(f"""SELECT int_ip, ext_ip, any(service) AS service, any(ext_port) AS port, count() AS mins, sum(b) * 8 / (count() * 60) AS bps, min(m) AS since
            FROM ({busy}) GROUP BY int_ip, ext_ip HAVING mins >= 45 ORDER BY bps DESC LIMIT 5""", fmt='JSON') if kinds['sustained_upload']['on'] else []:
        out.append({'sev': kinds['sustained_upload']['sev'], 'kind': 'sustained_upload', 'ip': r['int_ip'], 'name': NAMES.get(r['int_ip']),
                    'src': r['int_ip'], 'dst': r['ext_ip'], 'port': int(r['port']),
                    'title': tr('Sustained upload'),
                    'text': tr('{host} → {dst} ({service}) — {mbps} Mbit/s for {mins} min in the last 3 h.', host=NAMES.get(r['int_ip']) or r['int_ip'],
                               dst=f"{r['ext_ip']}:{r['port']}", service=r['service'], mbps=f"{float(r['bps']) / 1e6:.1f}", mins=r['mins']),
                    'when': r['since']})
    for r in ch("""SELECT exporter, sum(lost) AS lost_n, sum(packets) AS packets_n FROM exporter_stats WHERE ts >= now() - INTERVAL 1 HOUR GROUP BY exporter HAVING lost_n > 0""", fmt='JSON'):
        r['lost'], r['packets'] = r['lost_n'], r['packets_n']
        pct = 100 * int(r['lost']) / max(1, int(r['packets']) + int(r['lost']))
        out.append({'sev': 'warn' if pct < 2 else 'crit', 'kind': 'export_loss', 'device': r['exporter'], 'title': tr('Export loss'),
                    'text': tr('{device}: {lost} packets ({pct}%) lost in the last hour. Check the path to the collector.',
                               device=exporters_cfg().get(r['exporter'], {}).get('name', r['exporter']), lost=r['lost'], pct=f'{pct:.2f}'),
                    'when': tr('last hour')})
    # (1.10.0) scheduled reports that cannot go out (no mail server, nobody to send to) or whose last sending failed
    st = reports.status()
    for r in reports.load():
        x = st.get(r['id'], {})
        if not r['on']:
            continue
        if x.get('blocked'):
            out.append({'sev': 'warn', 'kind': 'report', 'title': tr('Report not sent'), 'when': tr('now'),
                        'text': tr('{name}: {why}', name=r['name'], why=x['blocked'])})
        elif x.get('error') and x.get('error_at', 0) > x.get('sent', 0) and time.time() - x['error_at'] < 3 * 86400:
            out.append({'sev': 'warn', 'kind': 'report', 'title': tr('Report not sent'),
                        'when': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(x['error_at'])),
                        'text': tr('{name}: the last sending failed — {error}', name=r['name'], error=x['error'])})
    col = collector_health(60)
    if col and col['socket_drops'] + col['queue_drops']:
        lost = col['socket_drops'] + col['queue_drops']
        pct = 100 * lost / max(1, col['packets'] + lost)
        out.append({'sev': 'warn' if pct < 1 else 'crit', 'kind': 'collector_drops', 'title': tr('Collector falling behind'),
                    'text': tr('{lost} packets ({pct}%) dropped in the last hour: socket buffer {sock}, worker queues {queue}. '
                               'Raise FT_WORKERS in /etc/flowtrack/env (now {workers}) or net.core.rmem_max.', lost=lost, pct=f'{pct:.2f}',
                               sock=col['socket_drops'], queue=col['queue_drops'], workers=col['workers']), 'when': tr('last hour')})
    ed = edition()
    lic = ed['license'] or {}
    if ed['status'] == 'expired':
        out.append({'sev': 'crit', 'kind': 'license_expired', 'title': tr('FlowSphera Pro license expired'),
                    'text': tr('{msg}. The Community limits apply again ({rps} records/s, {days} days); stored data is kept, records older than '
                               '{days} days show again with a renewed key. Enter it in Settings → License.',
                               msg=license_message(ed['status'], ed['message'], lic).capitalize(), rps=f"{COMMUNITY['rps']:,}", days=COMMUNITY['retention_days']),
                    'when': time.strftime('%Y-%m-%d', time.gmtime(lic.get('expires') or 0))})
    elif ed['status'] in ('invalid', 'other_instance', 'returned', 'clock'):
        out.append({'sev': 'crit', 'kind': 'license_invalid', 'title': tr('The license does not work on this server'),
                    'text': tr('{msg}. The Community limits apply ({rps} records/s, {days} days); stored data is kept. See Settings → License.',
                               msg=license_message(ed['status'], ed['message'], lic).capitalize(), rps=f"{COMMUNITY['rps']:,}", days=COMMUNITY['retention_days']),
                    'when': tr('now')})
    elif ed['status'] == 'active' and lic.get('days_left', 99) < 14:
        out.append({'sev': 'warn', 'kind': 'license_expiring', 'title': tr('FlowSphera Pro license ends soon'),
                    'text': trn(lic['days_left'], 'The license ends on {date} ({n} day left). After that the Community limits apply.',
                                'The license ends on {date} ({n} days left). After that the Community limits apply.',
                                date=time.strftime('%Y-%m-%d', time.gmtime(lic['expires']))),
                    'when': trn(lic['days_left'], '{n} day left', '{n} days left')})
    if col and col.get('license_drops'):
        out.append({'sev': 'warn', 'kind': 'license_limit', 'title': tr('Edition limit reached'),
                    'text': tr('{n} records were not stored in the last hour: the traffic exceeds {rps} records/s, the limit of FlowSphera Community. '
                               'FlowSphera Pro has no limit.', n=col['license_drops'], rps=f"{ed['rps']:,}"), 'when': tr('last hour')})
    if col and col['dropped_rows']:
        out.append({'sev': 'crit', 'kind': 'rows_dropped', 'title': tr('Records not stored'),
                    'text': tr('{n} records did not reach the database in the last hour: ClickHouse was unavailable longer than the collector buffer lasts.',
                               n=col['dropped_rows']), 'when': tr('last hour')})
    # (1.17.0) the host x country pairs of the day and of the week before from the conversations per hour (agg_conv);
    # the exact first record only inside the hour it is in
    now = int(time.time())
    day, week = (rollups.source(['int_ip', 'country'], a, b, [])[0] for a, b in ((now - 86400, None), (now - 7 * 86400, now - 86400)))
    new = ch(f"""SELECT int_ip, country, min(ts) AS hour FROM {day} WHERE country != '' GROUP BY int_ip, country
            HAVING (int_ip, country) NOT IN (SELECT int_ip, country FROM {week} GROUP BY int_ip, country)
               AND (SELECT min(ts) FROM flows) < now() - INTERVAL 2 DAY
            ORDER BY hour DESC LIMIT 5 WITH TIES""", fmt='JSON') if kinds['new_country']['on'] else []
    if new:     # the newest five by their exact first record (pairs of one hour tie on it above): only those hours are read
        hours = sorted({r['hour'] for r in new})
        win = ' OR '.join(f'(ts >= toDateTime({{h{i}:String}}) AND ts < toDateTime({{h{i}:String}}) + 3600)' for i in range(len(hours)))
        new = ch(f"""SELECT int_ip, country, min(ts) AS first FROM flows
            WHERE ({win}) AND ts >= now() - INTERVAL 1 DAY AND concat(int_ip, '|', country) IN {{pairs:Array(String)}}
            GROUP BY int_ip, country ORDER BY first DESC LIMIT 5""",
            {**{f'h{i}': h for i, h in enumerate(hours)}, 'pairs': [f"{r['int_ip']}|{r['country']}" for r in new]}, fmt='JSON')
    for r in new:
        out.append({'sev': kinds['new_country']['sev'], 'kind': 'new_country', 'ip': r['int_ip'], 'name': NAMES.get(r['int_ip']), 'title': tr('New destination'),
                    'text': tr('{host} contacted {country} for the first time this week.', host=NAMES.get(r['int_ip']) or r['int_ip'], country=r['country']),
                    'when': r['first']})
    # (1.17.0) the 5-minute totals per host are agg_host's own rows (summed over devices and directions)
    per = rollups.source(['int_ip'], now // 300 * 300 - 86400, None, [])[0]
    for r in ch(f"""WITH per AS (SELECT int_ip, toStartOfFiveMinutes(ts) AS m, sum(bytes) AS b FROM {per} WHERE ts >= now() - INTERVAL 1 DAY GROUP BY int_ip, m)
            SELECT int_ip, max(b) AS peak, quantile(0.5)(b) AS med, argMax(m, b) AS at FROM per GROUP BY int_ip
            HAVING count() > 24 AND peak > 100000000 AND peak > 8 * med AND at >= now() - INTERVAL 3 HOUR ORDER BY peak DESC LIMIT 5""", fmt='JSON') if kinds['burst']['on'] else []:
        out.append({'sev': kinds['burst']['sev'], 'kind': 'burst', 'ip': r['int_ip'], 'name': NAMES.get(r['int_ip']), 'title': tr('Traffic burst'),
                    'text': tr('{host}: {mb} MB in 5 min — {times}× the daily median.', host=NAMES.get(r['int_ip']) or r['int_ip'],
                               mb=f"{int(r['peak']) / 1e6:.0f}", times=f"{float(r['peak']) / max(1.0, float(r['med'])):.0f}"), 'when': r['at']})
    return out


# filter keys the events answer to; the others (service, protocol, interfaces ...) do not apply to them
EVENT_FILTERS = ('ip', 'net', 'dst', 'host', 'device', 'country', 'asn', 'port')


def _in_net(addr, net):
    try:
        return ipaddress.ip_address(str(addr).split('/')[0]) in net
    except ValueError:
        return False


def _event_match(a, f):
    """Does the event `a` answer to the filter {k, v} (the negation is the caller's)? Addresses: the source, the
    target and the addresses an event lists (ports scanned on, probing sources) — `ip` and `dst` alike, because an
    event's source may be inside or outside."""
    k, v = f.get('k'), str(f.get('v', ''))
    if k in ('ip', 'dst', 'host'):
        addrs = {a.get('ip'), a.get('src'), a.get('dst')} | set(a.get('addrs') or ())
        if '/' in v:            # (1.8.6) a network: any of the event's addresses in it
            try:
                net = ipaddress.ip_network(v, strict=False)
            except ValueError:
                return False
            return any(_in_net(x, net) for x in addrs if x)
        return v in addrs
    if k == 'net':              # (1.8.7) any of the event's addresses in the named network
        addrs = {a.get('ip'), a.get('src'), a.get('dst')} | set(a.get('addrs') or ())
        return any(common.network_of(x).lower() == v.lower() for x in addrs if x)
    if k == 'device':
        return v == (a.get('exporter') or a.get('device'))
    if k == 'country':
        return v == a.get('country')
    if k == 'asn':
        w = v[2:] if v.upper().startswith('AS') else v
        return (w.isdigit() and int(w) == int(a.get('asn') or 0)) or (not w.isdigit() and w.lower() in str(a.get('org', '')).lower())
    if k == 'port':
        return v.isdigit() and (int(v) == int(a.get('port') or 0) or int(v) in (a.get('ports') or ()))
    return True


def api_alerts(q):
    """Events of the chosen period that answer to the filters: detections stored by the collector (detect.py) and,
    when the period reaches now, the anomalies and health computed here. Kinds switched off in Settings -> Events
    and ignored sources are left out."""
    cfg = detect.load_config()
    kinds, ign = cfg['kinds'], detect.Ignore(cfg['ignore'])
    t0, t1, custom = period(q)
    try:
        flt = [f for f in json.loads(q.get('f', ['[]'])[0]) if isinstance(f, dict)]
    except (ValueError, TypeError):
        raise BadRequest('bad filter JSON')
    out = _alerts_now_cached(kinds) if t1 >= time.time() - 600 else []
    exc = detect.Exclude(cfg.get('exclude'))
    out = [a for a in out if (not a.get('ip') or (a['ip'], 0) not in ign) and not exc(a['kind'], a.get('src') or a.get('ip'), a.get('dst', ''), a.get('port', 0))]
    meta = {}
    try:
        out += detect.recent(cfg, t0, t1, meta)
    except CHError as e:           # before the collector of 1.6 created the table
        if 'UNKNOWN_TABLE' not in str(e):
            raise
    # exclusions each; positive filters of one key: any of them (1.8.3)
    pos = {}
    for f in flt:
        if f.get('k') not in EVENT_FILTERS:
            continue
        if f.get('neg'):
            out = [a for a in out if not _event_match(a, f)]
        else:
            pos.setdefault(f.get('k'), []).append(f)
    for fs in pos.values():
        out = [a for a in out if any(_event_match(a, f) for f in fs)]
    rank = {'crit': 0, 'warn': 1, 'info': 2}
    out.sort(key=lambda a: rank.get(a['sev'], 3))       # stable: the order within a priority stays
    for a in out:
        a.pop('addrs', None)
        a.pop('ports', None)
    res = {'watch': {k: v for k, v in kinds.items()}, 'unfiltered': sorted({f.get('k') for f in flt if f.get('k') not in EVENT_FILTERS}),
           'stats': {**detect.stats(out, t0, t1, _tz(q)), 'truncated': meta.get('truncated', False)}}
    # (1.17.0) the page asks for a part: the newest first, of one priority / kind, matching a text; without `limit`
    # every event as before (reports, older clients)
    if 'limit' not in q:
        res['alerts'] = out
        return res
    sev, kind, text = q1(q, 'sev', ''), q1(q, 'kind', ''), q1(q, 'q', '').strip().lower()
    sel = [a for a in out if (not sev or a['sev'] == sev) and (not kind or a['kind'] == kind)
           and (not text or text in f"{a.get('title', '')} {a.get('text', '')} {a.get('src', '')} {a.get('dst', '')} {a.get('ip', '')}".lower())]
    sel.sort(key=lambda a: detect.ev_time(a.get('last') or a.get('when')) or t1, reverse=True)
    try:
        limit, offset = max(0, min(int(q1(q, 'limit', '30')), 500)), max(0, int(q1(q, 'offset', '0')))
    except ValueError:
        raise BadRequest('bad limit / offset')
    res.update(alerts=sel[offset:offset + limit], matched=len(sel), offset=offset)
    return res


def get_events_config():
    cfg = detect.load_config()
    try:
        svcs = detect.services(cfg)
    except CHError:
        svcs = []
    m, keys = reputation.meta(), reputation.load_keys()
    # (1.16.2) key_set: a key is saved (the key itself never leaves the server); key_need: no download without one
    lists = [{'name': n, 'title': reputation.TITLES[n], 'category': c, 'link': link, 'on': cfg['lists'].get(n, True),
              'count': m.get(n, {}).get('count', 0), 'updated': m.get(n, {}).get('updated', 0), 'error': m.get(n, {}).get('error', ''),
              'key_set': n in keys, 'key_need': bool(reputation.AUTH.get(n, {}).get('need')), 'key_link': reputation.AUTH.get(n, {}).get('signup', '')}
             for n, (c, _, _, _, link) in reputation.LISTS.items()]
    return {'config': cfg, 'defaults': detect.defaults(), 'services': svcs, 'lists': lists}


# (1.8.4) the roles of our services and the sensitive / public ports are set in Settings → Flow configuration:
# saving (or resetting) the Events tab keeps them, and that tab saves only them
SERVICE_KEYS = ('roles', 'sensitive', 'public')
# the exceptions (addresses to ignore, connections excluded) are a table saved row by row (Events → Exceptions)
EXCEPTION_KEYS = ('ignore', 'exclude')


def post_events_config(body):
    cur = detect.load_config()
    try:
        detect.save_config(detect.validate({**{k: cur[k] for k in SERVICE_KEYS + EXCEPTION_KEYS}, **body}))
        # (1.16.2) list keys: {list: key} sets, clear_keys: [list] removes; an empty field keeps the saved key
        keys = {n: v for n, v in (body.get('list_keys') or {}).items() if isinstance(v, str) and v.strip()}
        keys.update({n: '' for n in body.get('clear_keys') or [] if isinstance(n, str)})
        if keys:
            reputation.save_keys(keys)
    except ValueError as e:
        raise BadRequest(str(e)) from None
    return get_events_config()


def post_events_exceptions(body):
    """Only the addresses to ignore and the excluded connections (each list replaced when given)."""
    cur = detect.load_config()
    try:
        detect.save_config(detect.validate({**cur, **{k: body[k] for k in EXCEPTION_KEYS if k in body}}))
    except ValueError as e:
        raise BadRequest(str(e)) from None
    cfg = detect.load_config()
    return {k: cfg[k] for k in EXCEPTION_KEYS}


def api_host_names(q):
    """(1.8.4) The names of inside hosts set by people: {items: [{ip, name}]}."""
    names = common.load_host_names()
    return {'items': [{'ip': ip, 'name': n} for ip, n in sorted(names.items(), key=lambda x: _ip_key(x[0]))]}


def _ip_key(ip):
    try:
        a = ipaddress.ip_address(ip)
        return (a.version, int(a))
    except ValueError:
        return (9, 0)


def post_host_names(body):
    """The whole table: [{ip, name}] -> STATE_DIR/hosts.json (over /etc hosts.json; one removed there = null)."""
    items = body.get('items')
    if not isinstance(items, list):
        raise BadRequest('items')
    out = {}
    for it in items:
        if not isinstance(it, dict):
            raise BadRequest('items')
        try:
            ip = str(ipaddress.ip_address(str(it.get('ip', '')).strip()))
        except ValueError:
            raise BadRequest(tr('not an IP address: {value}', value=str(it.get('ip', ''))[:60])) from None
        name = ' '.join(str(it.get('name', '')).split())
        if not name:
            raise BadRequest(tr('host name: give a name for {ip}', ip=ip))
        if len(name) > 64:
            raise BadRequest(tr('host name: at most 64 characters: {name}', name=name[:64] + '…'))
        out[ip] = name
    if len(out) > 5000:
        raise BadRequest(tr('at most 5000 host names'))
    base = {str(k): v for k, v in (load_json('hosts.json', {}) or {}).items() if v}
    ui = {ip: n for ip, n in out.items() if base.get(ip) != n}
    ui.update({ip: None for ip in base if ip not in out})
    tmp = common.UI_HOSTS + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(ui, f, ensure_ascii=False, indent=1)
    os.replace(tmp, common.UI_HOSTS)
    NAMES.reload()
    return api_host_names({})


def api_networks(q):
    """(1.8.7) The named networks, as the user ordered them."""
    try:
        with open(common.UI_NETWORKS) as f:
            raw = json.load(f)
    except (OSError, ValueError):
        raw = []
    return {'items': [{'net': str(x.get('net', '')), 'name': str(x.get('name', ''))} for x in raw if isinstance(x, dict)] if isinstance(raw, list) else []}


def post_networks(body):
    """The whole table: [{net, name}] -> STATE_DIR/networks.json."""
    items = body.get('items')
    if not isinstance(items, list):
        raise BadRequest('items')
    out, seen = [], set()
    for it in items:
        if not isinstance(it, dict):
            raise BadRequest('items')
        net = net_value(it.get('net', ''))
        name = ' '.join(str(it.get('name', '')).split())
        if not name:
            raise BadRequest(tr('network name: give a name for {net}', net=net))
        if len(name) > 40:
            raise BadRequest(tr('network name: at most 40 characters: {name}', name=name[:40] + '…'))
        if net in seen:
            raise BadRequest(tr('{net} is listed twice', net=net))
        seen.add(net)
        out.append({'net': net, 'name': name})
    if len(out) > 500:
        raise BadRequest(tr('at most 500 named networks'))
    tmp = common.UI_NETWORKS + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    os.replace(tmp, common.UI_NETWORKS)
    return api_networks({})


def post_events_services(body):
    """Only the roles of our services and the sensitive / public ports; {'reset': true} = the defaults."""
    if body.get('reset'):
        d = detect.defaults()
        body = {k: d[k] for k in SERVICE_KEYS}
    cur = detect.load_config()
    try:
        detect.save_config(detect.validate({**cur, **{k: body[k] for k in SERVICE_KEYS if k in body}}))
    except ValueError as e:
        raise BadRequest(str(e)) from None
    return get_events_config()


def post_notify(body):
    try:
        cfg = notify.validate(body, notify.load())
    except ValueError as e:
        raise BadRequest(str(e)) from None
    notify.save(cfg)
    return notify.public(cfg)


def _notify_form(body):
    """The typed settings (not saved) over the stored ones: for Test and Find chat before saving."""
    form = dict(body, telegram=dict(body.get('telegram') or {}, on=False))
    if 'email' in body:
        form['email'] = dict(body.get('email') or {}, on=False)
    if 'webhook' in body:
        form['webhook'] = dict(body.get('webhook') or {}, on=False)
    if 'siem' in body:
        form['siem'] = dict(body.get('siem') or {}, on=False)
    try:
        return notify.validate(form, notify.load())
    except ValueError as e:
        raise BadRequest(str(e)) from None


def post_notify_test(body):
    """A test message on one channel: 'telegram' (default), 'email' or 'webhook' (1.11.0)."""
    cfg = _notify_form(body)
    try:
        {'email': notify.test_mail, 'webhook': notify.test_webhook, 'siem': notify.test_siem}.get(body.get('channel'), notify.test)(cfg)
    except ValueError as e:
        raise BadRequest(str(e)) from None
    return {'ok': True}


def post_notify_chats(body):
    """Chats that wrote to the bot lately, and the entered chat ID checked with Telegram (when there is one)."""
    cfg = _notify_form(body)
    try:
        out = {'chats': notify.chats(cfg), 'checked': None, 'check_error': ''}
    except ValueError as e:
        raise BadRequest(str(e)) from None
    if cfg['telegram']['chat']:
        try:
            out['checked'] = notify.check_chat(cfg)
        except ValueError as e:
            out['check_error'] = str(e)
    return out


def post_events_ignore(body):
    try:
        detect.add_ignore(body.get('value', ''))
    except ValueError as e:
        raise BadRequest(str(e)) from None
    return {'ok': True}


PROTO_BY_NAME = {'tcp': 6, 'udp': 17, 'sctp': 132}


def api_ports(q):
    """(1.8.3) The user's own names of ports, as 'tcp/8443 HTTPS management' lines."""
    names = common.load_port_names()
    rev = {v: k for k, v in PROTO_BY_NAME.items()}
    return {'lines': [f"{rev.get(p, p)}/{n} {v}" for (p, n), v in sorted(names.items())],
            # (1.8.4) the table in Settings → Flow configuration: each name with what FlowSphera calls the port without it
            'items': [{'proto': rev.get(p, str(p)), 'port': n, 'name': v, 'default': common.default_l7(p, n)}
                      for (p, n), v in sorted(names.items(), key=lambda x: (x[0][1], x[0][0]))],
            'known': {f"{rev.get(p, p)}/{n}": v[0] for (p, n), v in common.PORTS.items()},
            'applied': _ports_pending() is None}


def _ports_pending():
    try:
        with open(os.path.join(STATE_DIR, 'ports_applied.json')) as f:
            return json.load(f).get('pending')
    except (OSError, ValueError, AttributeError):
        return None


def post_ports(body):
    """'tcp/8443 HTTPS management' per line (also tcp:8443, 8443/tcp; a port alone = TCP) -> ports.json; the collector
    names new records at once and renames the stored ones."""
    out = {}
    if isinstance(body.get('items'), list):     # (1.8.4) the table: [{proto: tcp|udp, port, name}]
        lines = []
        for it in body['items']:
            if not isinstance(it, dict):
                raise BadRequest('items')
            name = ' '.join(str(it.get('name', '')).split())
            pr = str(it.get('proto', '')).lower()
            if pr not in PROTO_BY_NAME:
                raise BadRequest(tr('port name: the protocol must be TCP or UDP'))
            lines.append(f"{pr}/{it.get('port')} {name}")
        body = {'text': '\n'.join(lines)}
    for line in str(body.get('text', '')).splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        spec, _, name = line.partition(' ')
        name = name.strip()
        m = re.fullmatch(r'(?:(tcp|udp|sctp)[/:])?(\d{1,5})(?:/(tcp|udp|sctp))?', spec.lower())
        if not m or not name:
            raise BadRequest(tr('port name: write it as «tcp/8443 HTTPS management»: {line}', line=line))
        port = int(m.group(2))
        if not 1 <= port <= 65535:
            raise BadRequest(tr('not a port: {port}', port=port))
        if len(name) > 40:
            raise BadRequest(tr('port name: at most 40 characters: {line}', line=line))
        out[f"{PROTO_BY_NAME[m.group(1) or m.group(3) or 'tcp']}/{port}"] = name
    if len(out) > 500:
        raise BadRequest(tr('at most 500 port names'))
    tmp = common.PORT_NAMES_FILE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    os.replace(tmp, common.PORT_NAMES_FILE)
    return api_ports({})


def post_events_exclude(body):
    try:
        detect.add_exclusion({k: body.get(k) for k in ('src', 'dst', 'port', 'dir')})
    except ValueError as e:
        raise BadRequest(str(e)) from None
    return {'ok': True}


def _str(v, n, field):
    if v is None or v == '':
        return ''
    if not isinstance(v, str) or len(v) > n:
        raise BadRequest(tr('{field}: up to {n} characters', field=field, n=n))
    return v.strip()


PROTOCOLS = {5: 'netflow5', 9: 'netflow9', 10: 'ipfix', 105: 'sflow'}    # export version (105 = sFlow v5) -> protocol
PROTO_LABEL = {'netflow5': 'NetFlow v5', 'netflow9': 'NetFlow v9', 'ipfix': 'IPFIX', 'sflow': 'sFlow v5'}


def device_from_body(b):
    try:
        ip = str(ipaddress.ip_address(str(b.get('ip', '')).strip()))
    except ValueError:
        raise BadRequest(tr('Invalid exporter IP address'))
    cfg = {'name': _str(b.get('name'), 64, tr('name')) or ip, 'vendor': _str(b.get('vendor'), 64, tr('vendor')), 'model': _str(b.get('model'), 64, tr('model')),
           'city': _str(b.get('city'), 64, tr('city')), 'sampling': _str(b.get('sampling'), 16, tr('sampling')) or '1:1'}
    proto = b.get('protocol') or ''
    if proto not in ('', *PROTOCOLS.values()):
        raise BadRequest(tr('Unknown export protocol'))
    cfg['protocol'] = proto
    cc = _str(b.get('country'), 2, tr('country')).upper()
    if cc and not cc.isalpha():
        raise BadRequest(tr('Country code: two Latin letters'))
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
        raise BadRequest(tr('Interfaces are whole numbers; latitude/longitude are numbers within ±90/±180'))
    pubs = []
    for x in (b.get('public_ips') or [])[:16]:
        try:
            pubs.append(str(ipaddress.ip_address(str(x).strip())))
        except ValueError:
            raise BadRequest(tr('Invalid public IP: {ip}', ip=x))
    cfg['public_ips'] = pubs
    cfg['export_ifs'] = export_ifs(b.get('export_ifs'))
    old = exporters_cfg(raw=True).get(ip, {})
    for k in ('if_names', 'if_addrs'):
        if old.get(k):
            cfg[k] = old[k]
    return ip, cfg


def export_ifs(v):
    """Interface names for the device configuration of the form (chosen from SNMP or typed): they go into commands
    in quotes on some devices, so no quotes, spaces at the ends or control characters."""
    out = []
    for x in (v or [])[:64]:
        x = str(x).strip() if isinstance(x, (str, int)) else ''
        if not x or len(x) > 64 or any(ch in x for ch in '"\'`\\') or any(ord(ch) < 32 or ord(ch) == 127 for ch in x):
            raise BadRequest(tr('Interface names: up to 64, each up to 64 characters, no quotes'))
        if x not in out:
            out.append(x)
    return out


def snmp_ifs(d):
    """The interfaces an SNMP poll found, for choosing those the device configuration names."""
    addrs = d.get('addrs', {})
    return [{'index': int(k), 'name': v.get('name') or v.get('descr') or '', 'alias': v.get('alias', ''), 'up': v.get('oper') == 1,
             'addrs': addrs.get(k, [])} for k, v in sorted(d.get('ifs', {}).items(), key=lambda kv: int(kv[0]))[:500]
            if v.get('name') or v.get('descr')]


SNMP_FIELDS = {'version': N_('SNMP version'), 'host': N_('SNMP address'), 'port': N_('SNMP port'),
               'community': N_('Community: 1–64 characters'), 'user': N_('SNMPv3 user: 1–32 characters'),
               'level': N_('Security level'), 'auth_proto': N_('Authentication protocol'),
               'auth_pass': N_('Authentication password: 8–64 characters'), 'priv_proto': N_('Privacy protocol'),
               'priv_pass': N_('Privacy password: 8–64 characters')}


def snmp_from_body(ip, b):
    try:
        return snmp.settings_from(b, snmp.load_settings().get(ip))
    except ValueError as e:
        field = tr(SNMP_FIELDS[str(e)]) if str(e) in SNMP_FIELDS else str(e)
        raise BadRequest(tr('{field}: invalid value (no spaces at the ends, no quotes at the start, no control characters)', field=field))


def post_device_save(body, user):
    ip, cfg = device_from_body(body)
    sn = snmp_from_body(ip, body['snmp']) if isinstance(body.get('snmp'), dict) else None
    save_ui_exporter(ip, cfg)
    if sn is not None and (sn.get('enabled') or ip in snmp.load_settings()):
        snmp.save_settings(ip, sn)
        if sn.get('enabled'):
            POLLER.kick(ip)
    NAMES.reload()
    return {'ok': True, 'ip': ip}


def device_ip(body):
    try:
        return str(ipaddress.ip_address(str(body.get('ip', '')).strip()))
    except ValueError:
        raise BadRequest(tr('Invalid device IP address'))


def post_snmp_test(body, user):
    """Poll with the settings in the form (not saved; empty secrets = the stored ones)."""
    ip = device_ip(body)
    e = snmp_from_body(ip, {**(body.get('snmp') or {}), 'enabled': True})
    try:
        found = snmp.poll(ip, e)
        return {'ok': True, **snmp.summary(found), 'ifs': snmp_ifs(found)}
    except snmp.SnmpError as x:
        return {'ok': False, 'error': x.code, 'error_text': snmp_error_text(x.code, e, ip), 'detail': x.detail[:300]}


def post_snmp_poll(body, user):
    """Poll a device now with its stored settings."""
    ip = device_ip(body)
    if not snmp.load_settings().get(ip, {}).get('enabled'):
        raise BadRequest(tr('SNMP is off for this device'))
    snmp.poll_and_store(ip)
    NAMES.reload()
    return {'ok': True, 'snmp': snmp_status(ip, snmp.load_settings(), snmp.load_data())}


def post_device_interfaces(body, user):
    try:
        ip = str(ipaddress.ip_address(str(body.get('ip', '')).strip()))
    except ValueError:
        raise BadRequest(tr('Invalid device IP address'))
    items = body.get('interfaces')
    if not isinstance(items, list) or len(items) > 1024:
        raise BadRequest(tr('A list of interfaces is expected'))
    names, addrs, wan, local, caps = {}, {}, [], None, {}
    for it in items:
        try:
            idx = int(it.get('index'))
        except (TypeError, ValueError, AttributeError):
            raise BadRequest(tr('The interface index must be a number'))
        if not 0 <= idx < 2**32:
            raise BadRequest(tr('Interface index out of range'))
        name = str(it.get('name') or '').strip()
        if len(name) > 32 or any(ord(ch_) < 32 for ch_ in name):
            raise BadRequest(tr('Interface {idx} name: up to 32 characters, no control characters', idx=idx))
        if name:
            names[str(idx)] = name
        raw = it.get('addrs') or []
        if isinstance(raw, str):
            raw = raw.replace(',', ' ').split()
        if not isinstance(raw, list) or len(raw) > 8:
            raise BadRequest(tr('Interface {idx}: up to 8 addresses', idx=idx))
        try:
            # 'a.b.c.d/nn' keeps its prefix (interface address with mask), a bare address stays bare
            ok = [str(ipaddress.ip_interface(a) if '/' in a else ipaddress.ip_address(a)) for a in (str(x).strip() for x in raw) if a]
        except ValueError as e:
            raise BadRequest(tr('Interface {idx}: invalid address ({error})', idx=idx, error=e))
        if ok:
            addrs[str(idx)] = ok
        # (1.12.0) own capacity, Mbit/s in / out (empty: the port's speed); one figure given = both directions
        cin, cout = it.get('cap_in'), it.get('cap_out')
        if cin not in (None, '') or cout not in (None, ''):
            try:
                cin = float(cin if cin not in (None, '') else cout)
                cout = float(cout if cout not in (None, '') else cin)
                assert 0 < cin <= 1e6 and 0 < cout <= 1e6
            except (TypeError, ValueError, AssertionError):
                raise BadRequest(tr('Interface {idx}: capacity is Mbit/s, more than 0', idx=idx)) from None
            caps[str(idx)] = [round(cin, 3), round(cout, 3)]
        role = it.get('role', 'lan')
        if role == 'wan':
            wan.append(idx)
        elif role == 'local':
            if local is not None:
                raise BadRequest(tr('Only one interface can have the role «the device itself»'))
            local = idx
        elif role != 'lan':
            raise BadRequest(tr('Role: lan, wan or local'))
    merged = exporters_cfg(raw=True).get(ip, {})
    entry = load_ui_exporter(ip)
    entry.update({'if_names': names, 'if_addrs': addrs, 'wan_ifs': sorted(set(wan)), 'local_if': local, 'if_caps': caps})
    entry.setdefault('name', merged.get('name', ip))
    save_ui_exporter(ip, entry)
    NAMES.reload()
    return {'ok': True}


def post_device_delete(body, user):
    ip = str(body.get('ip', ''))
    if ip not in exporters_cfg():
        raise BadRequest(tr('The device is not configured'))
    save_ui_exporter(ip, None)
    snmp.save_settings(ip, None)
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
          '/api/flows': api_flows, '/api/paths': api_paths, '/api/devmap': api_devmap, '/api/topology': api_topology, '/api/path': api_path, '/api/live': api_live, '/api/ports': api_ports, '/api/hosts/names': api_host_names, '/api/networks': api_networks, '/api/geo': api_geo, '/api/devices': api_devices, '/api/host': api_host,
          '/api/alerts': api_alerts, '/api/ifload': api_ifload,
          '/api/capacity': api_capacity, '/api/capacity/iface': api_capacity_iface, '/api/usage': api_usage, '/api/qos': api_qos, '/api/conversations': api_conversations}
STATIC = {'.html': 'text/html; charset=utf-8', '.js': 'application/javascript', '.json': 'application/json; charset=utf-8', '.css': 'text/css', '.svg': 'image/svg+xml', '.woff2': 'font/woff2'}


AUTH = None
POLLER = snmp.Poller()
ADMIN_GET = {'/api/users', '/api/events/config', '/api/notify', '/api/backups', '/api/reports', '/api/reports/pdf', '/api/mail', '/api/tokens', '/api/ldap'}
# (1.11.0) what an API token can never do, whatever its scope: people's accounts, the tokens themselves, the license,
# deleting backups, and what only a browser session has
TOKEN_DENY = {'/api/users', '/api/users/update', '/api/users/delete', '/api/tokens', '/api/tokens/delete', '/api/ldap', '/api/ldap/test', '/api/mail/delete', '/api/license',
              '/api/license/deactivate', '/api/license/checkin', '/api/backups/delete', '/api/me/password', '/api/me/prefs',
              '/api/logout', '/api/cancel'}
COOKIE = 'ft_session'


# the page runs only its own script files: even text that slipped into the HTML unescaped could not run code
# ('unsafe-eval': the 3D globe library builds functions from strings of its own; inline scripts stay blocked)
CSP = ("default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; "
       "font-src 'self' data:; img-src 'self' data: blob:; connect-src 'self'; worker-src 'self' blob:; "
       "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")


class H(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version, sys_version = 'FlowTrack', ''      # no Python version in the Server header
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

    def who(self):
        """(user, role, api token or None) of the request: a browser session, else `Authorization: Bearer ftapi_…`
        (1.11.0: a 'write' token acts as an administrator, a 'read' one as a viewer). AuthError for a wrong token."""
        user = AUTH.session_user(self.token())
        if user:
            return user, AUTH.users[user]['role'], None
        h = self.headers.get('Authorization') or ''
        if h[:7].lower() == 'bearer ' and h[7:].strip():
            t = AUTH.token_user(h[7:].strip(), self.client_ip())
            return f"token:{t['name']}", 'admin' if t['scope'] == 'write' else 'viewer', t
        return None, None, None

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
        self.send_header('Content-Security-Policy', CSP)
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', cache)
        if getattr(self, '_disposition', None):
            self.send_header('Content-Disposition', self._disposition)
            self._disposition = None
        self.send_header('X-Content-Type-Options', 'nosniff')
        try:
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionError, ssl.SSLError):
            # (1.16.2) the browser left (page closed or changed) while its answer was on the way: nothing to answer any
            # more. Before, the error reached do_GET's «database error» branch, was logged as one, and a 502 was
            # written into the closed connection — a second error with a traceback
            self.close_connection = True

    def do_GET(self):
        u = urlparse(self.path)
        if u.path.startswith('/api/'):
            if u.path == '/api/login/methods':     # (1.12.0) the sign-in page: local, and the directory when it is on
                m = directory.method(directory.load())
                return self.json(200, {'methods': [{'id': 'local'}] + ([m] if m else [])})
            try:
                user, role, tok = self.who()
            except AuthError as e:
                return self.json(e.status, {'error': str(e)})
            if not user:
                return self.json(401, {'error': 'login required'})
            if tok and u.path in TOKEN_DENY:
                return self.json(403, {'error': tr('An API token cannot do this: sign in as an administrator.')})
            if u.path == '/api/me':
                return self.json(200, AUTH.public(user) if not tok else {'name': user, 'role': role, 'token': tok['scope']})
            if u.path == '/api/edition':
                return self.json(200, edition_info(admin=role == 'admin'))
            if u.path == '/api/progress':      # not a page query itself: it neither cancels nor counts in what it reports
                return self.json(200, page_progress(self.token(), self.headers.get('X-FT-Tab'), self.headers.get('X-FT-Page')))
            if u.path == '/api/report/pdf':        # (1.10.0) a report of any period: any user, it shows what the pages show
                try:
                    name, pdf = get_report_once_pdf(parse_qs(u.query))
                except BadRequest as e:
                    return self.json(400, {'error': str(e)})
                self._disposition = f'attachment; filename="{name}"'
                return self.send(200, pdf, 'application/pdf')
            if u.path in ADMIN_GET:
                if role != 'admin':
                    return self.json(403, {'error': tr('Administrator rights required')})
                if u.path == '/api/events/config':
                    return self.json(200, get_events_config())
                if u.path == '/api/notify':
                    return self.json(200, notify.public(notify.load()))
                if u.path == '/api/backups':
                    return self.json(200, get_backups())
                if u.path == '/api/reports':
                    return self.json(200, get_reports())
                if u.path == '/api/mail':
                    return self.json(200, get_mail())
                if u.path == '/api/tokens':
                    return self.json(200, {'tokens': AUTH.list_tokens()})
                if u.path == '/api/ldap':
                    return self.json(200, directory.public(directory.load()))
                if u.path == '/api/reports/pdf':
                    try:
                        name, pdf = get_report_pdf(parse_qs(u.query))
                    except BadRequest as e:
                        return self.json(400, {'error': str(e)})
                    self._disposition = f'attachment; filename="{name}"'
                    return self.send(200, pdf, 'application/pdf')
                return self.json(200, {'users': AUTH.list_users()})
        fn = ROUTES.get(u.path)
        if fn:
            try:
                q = parse_qs(u.query)
                if u.path in CSV_ROUTES and q1(q, 'format', 'json') == 'csv':      # (1.14.1) a table as CSV
                    tag = web_tag(self.token(), self.headers.get('X-FT-Tab'), self.headers.get('X-FT-Page'))
                    with web_query(tag, web_settings(u.path, q)):
                        res = fn(q)
                    self._disposition = f'attachment; filename="flowsphera-{q1(q, "dim", "int_ip")}.csv"'
                    return self.send(200, top_csv(q1(q, 'dim', 'int_ip'), res), 'text/csv; charset=utf-8')
                body = CACHE.get(u.path, q)
                if body is None:
                    tag = web_tag(self.token(), self.headers.get('X-FT-Tab'), self.headers.get('X-FT-Page'))
                    with web_query(tag, web_settings(u.path, q)):
                        body = json.dumps(fn(q), default=str).encode()
                    CACHE.put(u.path, q, body)
                return self.send(200, body, 'application/json')
            except BadRequest as e:
                return self.send(400, json.dumps({'error': str(e)}).encode(), 'application/json')
            except CHError as e:
                code, msg = ch_error_answer(e)
                if code == 502:
                    print(f'[flowtrack-api] {u.path}: {e}', flush=True)
                return self.send(code, json.dumps({'error': msg}).encode(), 'application/json')
            except OSError as e:
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
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            n = -1
        if n < 0:
            return self.json(400, {'error': 'bad Content-Length'})
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
                token = AUTH.login(body.get('username'), body.get('password'), self.client_ip(), body.get('method') or 'local')
                self.set_cookie(token, 7 * 86400)
                return self.json(200, AUTH.public(AUTH.session_user(token)))      # a directory user: the directory's name
            user, role, api = self.who()
            tok = self.token()
            if not user:
                return self.json(401, {'error': 'login required'})
            if api and (u.path in TOKEN_DENY or role != 'admin'):        # (1.11.0) a 'read' token changes nothing
                return self.json(403, {'error': tr('An API token cannot do this: sign in as an administrator.') if u.path in TOKEN_DENY
                                       else tr('This API token can only read: create one with changes allowed.')})
            if u.path == '/api/cancel':
                return self.json(200, cancel_page(tok, self.headers.get('X-FT-Tab'), self.headers.get('X-FT-Page')))
            if u.path == '/api/logout':
                AUTH.logout(tok)
                self.set_cookie('', 0)
                return self.json(200, {'ok': True})
            if u.path == '/api/me/prefs':        # (1.9.0) any user: their own choices
                return self.json(200, AUTH.set_prefs(user, body.get('prefs')))
            if u.path == '/api/me/password':
                AUTH.change_own_password(user, body.get('current'), body.get('new'), tok, self.client_ip())
                return self.json(200, AUTH.public(user))
            admin_routes = {
                '/api/users': lambda: AUTH.create_user(body.get('name'), body.get('role'), body.get('password')),
                '/api/users/update': lambda: AUTH.update_user(user, body.get('name'), body.get('role'), body.get('password')),
                '/api/users/delete': lambda: AUTH.delete_user(user, body.get('name')),
                '/api/tokens': lambda: post_token_create(body, user),
                '/api/ldap': lambda: post_ldap(body),
                '/api/ldap/test': lambda: post_ldap_test(body),
                '/api/tokens/delete': lambda: (AUTH.delete_token(body.get('id')), {'tokens': AUTH.list_tokens()})[1],
                '/api/devices/save': lambda: post_device_save(body, user),
                '/api/devices/delete': lambda: post_device_delete(body, user),
                '/api/devices/interfaces': lambda: post_device_interfaces(body, user),
                '/api/devices/snmp_test': lambda: post_snmp_test(body, user),
                '/api/devices/snmp_poll': lambda: post_snmp_poll(body, user),
                '/api/license': lambda: post_license(body),
                '/api/license/deactivate': post_license_deactivate,
                '/api/license/checkin': post_license_checkin,
                '/api/events/config': lambda: post_events_config(body),
                '/api/events/ignore': lambda: post_events_ignore(body),
                '/api/events/exclude': lambda: post_events_exclude(body),
                '/api/events/services': lambda: post_events_services(body),
                '/api/events/exceptions': lambda: post_events_exceptions(body),
                '/api/hosts/names': lambda: post_host_names(body),
                '/api/networks': lambda: post_networks(body),
                '/api/ports': lambda: post_ports(body),
                '/api/notify': lambda: post_notify(body),
                '/api/notify/test': lambda: post_notify_test(body),
                '/api/notify/chats': lambda: post_notify_chats(body),
                '/api/backups/config': lambda: post_backups_config(body),
                '/api/backups/run': lambda: post_backups_run(body),
                '/api/backups/verify': lambda: post_backups_verify(body),
                '/api/backups/delete': lambda: post_backups_delete(body, user, self.client_ip()),
                '/api/backups/test': lambda: post_backups_test(body),
                '/api/reports/save': lambda: post_report_save(body),
                '/api/reports/delete': lambda: post_report_delete(body),
                '/api/reports/send': lambda: post_report_send(body),
                '/api/reports/send_once': lambda: post_report_send_once(body),
                '/api/mail': lambda: post_mail(body),
                '/api/mail/test': lambda: post_mail_test(body),
                '/api/mail/delete': lambda: post_mail_delete(),
            }
            if u.path not in admin_routes:
                return self.json(404, {'error': 'not found'})
            if role != 'admin':
                return self.json(403, {'error': tr('Administrator rights required')})
            res = admin_routes[u.path]()
            return self.json(200, res if isinstance(res, dict) else {'ok': True})
        except AuthError as e:
            return self.json(e.status, {'error': str(e)})
        except BadRequest as e:
            return self.json(400, {'error': str(e)})
        except OSError as e:
            print(f'[flowtrack-api] POST {u.path}: {e}', flush=True)
            return self.json(500, {'error': tr('could not save')})


# ---------------------------------------------------------------- web queries: limits, priority, cancelling (1.8.1)
# A page asks several queries; on a busy network (thousands of records/s) one may run for a long time. When the
# browser has moved on to another page (or filters), the queries of the page it left are cancelled, so they do not
# hold up the ones it asks now. Every web query has a time and memory limit, and live views go first.
WEB_SECONDS = int(os.environ.get('FT_WEB_QUERY_SECONDS', '120'))
WEB_MEMORY = int(os.environ.get('FT_CH_MEMORY_MB', '2048')) * (1 << 20) // 2
_PAGES, _PAGES_LOCK = {}, threading.Lock()
_TAG_RE = re.compile(r'^[A-Za-z0-9]{1,16}$')


def _is_live(path, q):
    return path == '/api/live' or q1(q, 'live', '0') == '1'


def web_tag(token, tab, page):
    """The query_id prefix of this request; cancels the queries of the page this browser tab showed before."""
    if not (token and _TAG_RE.match(tab or '') and _TAG_RE.match(page or '')):
        return None
    sid = hashlib.sha256(token.encode()).hexdigest()[:10]
    key, tag = (sid, tab), f'ftw-{sid}-{tab}-{page}'
    with _PAGES_LOCK:
        old = _PAGES.get(key)
        _PAGES[key] = page
        if len(_PAGES) > 5000:
            _PAGES.pop(next(iter(_PAGES)))
    if old and old != page:
        threading.Thread(target=_cancel, args=(f'ftw-{sid}-{tab}-{old}-',), daemon=True).start()
    return tag


def _page_prefix(token, tab, page):
    if not (token and _TAG_RE.match(tab or '') and _TAG_RE.match(page or '')):
        return None
    return f"ftw-{hashlib.sha256(token.encode()).hexdigest()[:10]}-{tab}-{page}-"


def page_progress(token, tab, page):
    """(1.8.5) How far the queries of this page are: rows read, rows to read (ClickHouse's estimate, 0 = unknown),
    seconds — for the waiting animations and the progress line."""
    prefix = _page_prefix(token, tab, page)
    if not prefix:
        return {'n': 0}
    try:
        r = ch("SELECT count() AS n, sum(read_rows) AS rows, sum(total_rows_approx) AS total, max(elapsed) AS secs "
               "FROM system.processes WHERE startsWith(query_id, {p:String})", {'p': prefix}, fmt='JSON', timeout=5)[0]
    except (CHError, OSError, IndexError):
        return {'n': 0}
    return {'n': int(r['n']), 'rows': int(r['rows'] or 0), 'total': int(r['total'] or 0), 'secs': round(float(r['secs'] or 0), 1)}


def cancel_page(token, tab, page):
    """(1.8.5) The Cancel button: stop what this page still asks the database."""
    prefix = _page_prefix(token, tab, page)
    if prefix:
        _cancel(prefix)
    return {'ok': bool(prefix)}


def _cancel(prefix):
    try:
        ch("KILL QUERY WHERE startsWith(query_id, {p:String}) ASYNC", {'p': prefix}, timeout=10)
    except (CHError, OSError):
        pass


def web_settings(path, q):
    # (1.16.2) a query whose caller is gone (the browser left, the API gave up) stops instead of running on
    return {'max_execution_time': WEB_SECONDS, 'timeout_overflow_mode': 'throw', 'max_memory_usage': WEB_MEMORY,
            'priority': 1 if _is_live(path, q) else 5, 'cancel_http_readonly_queries_on_client_close': 1}


def ch_error_answer(e):
    """(status, message) for a failed query: the limits and a cancelled page in words people understand."""
    s = str(e)
    if 'Code: 159' in s or 'TIMEOUT_EXCEEDED' in s:
        return 503, tr('Too much data for this period: choose a shorter period or add a filter.')
    if 'Code: 241' in s or 'MEMORY_LIMIT_EXCEEDED' in s:
        return 503, tr('Not enough memory for this period: choose a shorter period or add a filter.')
    if 'Code: 394' in s or 'QUERY_WAS_CANCELLED' in s:
        return 409, 'cancelled'
    return 502, 'database error'


# ---------------------------------------------------------------- backups (1.8.0): the work is done by root (backup.py)
SECRETS = {'s3': ('secret',), 'sftp': ('password', 'key'), 'ftp': ('password',)}


# ---------------------------------------------------------------- scheduled reports (1.10.0)

def report_call(path, q):
    """The pages' own queries for a report (reports.collect): as a page asks them, with a longer time limit and
    below the pages in priority (a month on a busy network). A month of 31 days + the hour of a clock change is
    trimmed to the longest period the edition shows."""
    if q.get('from') and q.get('to') and int(q['to'][0]) - int(q['from'][0]) > (view_days() + 1) * 86400:
        q = dict(q, **{'from': [str(int(q['to'][0]) - (view_days() + 1) * 86400)]})
    with web_query(f'ftr-{os.urandom(3).hex()}', dict(web_settings(path, q), max_execution_time=max(WEB_SECONDS, 600), priority=8)):
        return ROUTES[path](q)


def get_reports():
    cfg = notify.load()
    return {'reports': reports.load(), 'status': reports.status(), 'blank': reports.blank(), 'sections': list(reports.SECTIONS),
            'mail': notify.server_public(cfg), 'mail_ready': bool(cfg['email']['host'] and cfg['email']['sender']), 'mail_to': cfg['email']['to'],
            'timezones': sorted(reports.available_timezones())}


def _report_of(body):
    """The stored report of body['id'], or the typed one (not saved: Download / Send before saving)."""
    if body.get('form'):
        try:
            return reports.validate(body['form'])
        except ValueError as e:
            raise BadRequest(str(e)) from None
    r = next((x for x in reports.load() if x['id'] == body.get('id')), None)
    if not r:
        raise BadRequest(tr('There is no such report any more.'))
    return r


def _report_period(r, back):
    t0, t1 = reports.period(r, time.time(), back)      # older records than the edition keeps: the report says so itself
    if t1 <= int(time.time()) - (view_days() + 1) * 86400:
        raise BadRequest(tr('This period is older than the records FlowSphera keeps.'))
    return t0, t1


def get_report_pdf(q):
    """The PDF of a report's last period (back=1: the one before) for the browser to save."""
    try:
        body = {'id': q1(q, 'id', ''), 'form': json.loads(q1(q, 'form', '')) if q.get('form') else None}
    except ValueError:
        raise BadRequest('bad form') from None
    r = _report_of(body)
    t0, t1 = _report_period(r, max(0, min(q1(q, 'back', '0', int), 12)))
    try:
        pdf, _ = reports.make(r, t0, t1, report_call, VERSION)
    except CHError as e:
        raise BadRequest(ch_error_answer(e)[1]) from None
    return reports.file_name(r, t0), pdf


def _report_once(body):
    """(report, t0, t1) of a report of any period: body {form: the report's settings, from, to}."""
    try:
        t0, t1 = int(body.get('from')), int(body.get('to'))
    except (TypeError, ValueError):
        raise BadRequest(tr('The period of the report must be at least 5 minutes long.')) from None
    t1 = min(t1, int(time.time()))
    if t1 <= int(time.time()) - (view_days() + 1) * 86400:
        raise BadRequest(tr('This period is older than the records FlowSphera keeps.'))
    try:
        return reports.once(body.get('form') or {}, t0, t1), t0, t1
    except ValueError as e:
        raise BadRequest(str(e)) from None


def get_report_once_pdf(q):
    try:
        body = {'form': json.loads(q1(q, 'form', '{}')), 'from': q1(q, 'from', ''), 'to': q1(q, 'to', '')}
    except ValueError:
        raise BadRequest('bad form') from None
    r, t0, t1 = _report_once(body)
    try:
        pdf, _ = reports.make(r, t0, t1, report_call, VERSION)
    except CHError as e:
        raise BadRequest(ch_error_answer(e)[1]) from None
    return reports.file_name(r, t0), pdf


def post_report_send_once(body):
    """A report of any period by e-mail now, to the addresses given (administrators)."""
    r, t0, t1 = _report_once(body)
    if not r['to']:
        raise BadRequest(tr('Enter at least one recipient.'))
    try:
        n, label = reports.send(r, t0, t1, report_call, VERSION)
    except ValueError as e:
        raise BadRequest(str(e)) from None
    except CHError as e:
        raise BadRequest(ch_error_answer(e)[1]) from None
    return {'ok': True, 'sent': n, 'period': label}


def post_report_save(body):
    try:
        r = reports.upsert(body)
    except ValueError as e:
        raise BadRequest(str(e)) from None
    return dict(get_reports(), saved=r['id'])


def post_report_delete(body):
    try:
        reports.remove(str(body.get('id') or ''))
    except ValueError as e:
        raise BadRequest(str(e)) from None
    return get_reports()


def post_ldap(body):
    """(1.12.0) Sign-in through Active Directory / LDAP."""
    try:
        cfg = directory.validate(body, directory.load())
    except ValueError as e:
        raise BadRequest(str(e)) from None
    directory.save(cfg)
    return directory.public(cfg)


def post_ldap_test(body):
    """The typed (not saved) settings against the server: the service account, the base DN and, with a name, the user,
    their groups and the role FlowSphera would give (with a password also that)."""
    try:
        cfg = directory.validate(dict(body, on=False), directory.load())
        return directory.test(cfg, str(body.get('test_user') or '').strip(), str(body.get('test_password') or ''))
    except (ValueError, directory.DirectoryError) as e:
        raise BadRequest(str(e)) from None


def post_token_create(body, user):
    """(1.11.0) A new API token: shown once, in this answer only."""
    token, row = AUTH.create_token(user, body.get('name'), body.get('scope'), body.get('days'))
    return {'token': token, 'row': row, 'tokens': AUTH.list_tokens()}


def get_mail():
    """(1.10.0) The mail server of Settings → General (the password only as set or not)."""
    cfg = notify.load()
    return {'mail': notify.server_public(cfg), 'to': cfg['email']['to']}


def post_mail(body):
    try:
        cfg = notify.validate_server(body, notify.load())
    except ValueError as e:
        raise BadRequest(str(e)) from None
    notify.save(cfg)
    return get_mail()


def post_mail_delete():
    """(1.12.1) Settings → General → Mail server → Delete (confirmed in the browser)."""
    cfg = notify.clear_server(notify.load())
    notify.save(cfg)
    return get_mail()


def post_mail_test(body):
    """A test letter through the typed (not saved) mail server to the address given."""
    try:
        notify.test_server(notify.validate_server(body, notify.load()), str(body.get('to') or '').strip(), body.get('lang'))
    except ValueError as e:
        raise BadRequest(str(e)) from None
    return {'ok': True}


def post_report_send(body):
    """Send the last period now (the schedule is not changed)."""
    r = _report_of(body)
    t0, t1 = _report_period(r, 0)
    try:
        n, label = reports.send(r, t0, t1, report_call, VERSION)
        reports.note_sent(r, label, n)
    except ValueError as e:
        raise BadRequest(str(e)) from None
    except CHError as e:
        raise BadRequest(ch_error_answer(e)[1]) from None
    return {'ok': True, 'sent': n, 'period': label}


def get_backups():
    """Settings → Backups: the settings without secrets, the state of the running / last backup, the backups."""
    import backup
    cfg = backup.load()
    try:
        with open(backup.INDEX) as f:
            idx = json.load(f)
    except (OSError, ValueError):
        idx = {}
    st = backup.read_status()
    return {'config': backup.public(cfg), 'running': st.get('running'), 'last': st.get('last'), 'deleted': st.get('deleted'), 'next': backup.next_run(cfg),
            'pending': os.path.exists(backup.REQUEST), 'dir': idx.get('dir') or backup.DIR, 'free': idx.get('free', 0),
            'used': idx.get('used', 0), 'backups': idx.get('backups', []), 'index_t': idx.get('t', 0),
            'tz_offset': time.localtime().tm_gmtoff}


def post_backups_config(body):
    import backup
    try:
        cfg = backup.validate(body, backup.load())
    except ValueError as e:
        raise BadRequest(str(e)) from None
    backup.save(cfg)
    return {'config': backup.public(cfg), 'next': backup.next_run(cfg)}


def _backup_request(req):
    """Ask root's flowtrack-backup.service (started by its .path unit when the file appears) to do something."""
    import backup
    if os.path.exists(backup.REQUEST):
        raise BadRequest(tr('A backup task is already waiting to start.'))
    tmp = backup.REQUEST + '.tmp'
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w') as f:
        json.dump({**req, 't': int(time.time())}, f)
    os.replace(tmp, backup.REQUEST)
    return {'ok': True}


def post_backups_run(body):
    return _backup_request({'do': 'backup', 'full': bool(body.get('full'))})


def post_backups_delete(body, user, ip):
    """(1.8.8) Delete backups by hand; confirmed with the signed-in admin's own password (no slip of the mouse deletes
    one). A full backup takes its changes with it; copies on the places only when asked."""
    import backup
    ids = body.get('ids')
    if not isinstance(ids, list) or not ids or len(ids) > 100 or not all(backup.ID_RE.match(str(x)) for x in ids):
        raise BadRequest('bad ids')
    AUTH.check_password(user, str(body.get('password') or ''), ip)
    return _backup_request({'do': 'delete', 'ids': [str(x) for x in ids], 'copies': bool(body.get('copies'))})


def post_backups_verify(body):
    import backup
    bid = str(body.get('id') or '')
    if not backup.ID_RE.match(bid):
        raise BadRequest('bad id')
    return _backup_request({'do': 'verify', 'id': bid, 'deep': bool(body.get('deep'))})


def post_backups_test(body):
    """Test a place with the typed settings; an empty secret is the stored one."""
    import backup
    kind = body.get('kind')
    if kind not in SECRETS:
        raise BadRequest('bad kind')
    c = dict(backup.load()[kind])
    for k, v in (body.get(kind) or {}).items():
        if k in c and not (k in SECRETS[kind] and v in ('', None)):
            c[k] = v
    if kind == 'sftp' and 'fingerprint' not in (body.get(kind) or {}):
        c['fingerprint'] = ''
    if not str(c.get('host' if kind != 's3' else 'bucket') or '').strip():
        raise BadRequest(tr('Fill in the server first.') if kind != 's3' else tr('Fill in the bucket first.'))
    try:
        c['port'] = int(c.get('port') or (22 if kind == 'sftp' else 21))
    except (TypeError, ValueError):
        raise BadRequest(tr('The port is a number from 1 to 65535.')) from None
    return backup.test_dest(kind, c)


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

    def handle_error(self, request, client_address):
        # (1.16.2) a browser that closed the page while its answer was being sent is no error of ours (a traceback in
        # the log for every closed tab before); anything else is still logged in full
        if isinstance(sys.exc_info()[1], (ConnectionError, ssl.SSLEOFError, ssl.SSLZeroReturnError)):
            return
        super().handle_error(request, client_address)

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
        low = ' — a port below 1024 needs CAP_NET_BIND_SERVICE in flowtrack-web.service (sudo flowtrack upgrade puts it there) or a port from 1024' \
            if getattr(e, 'errno', None) == 13 and int(PORT) < 1024 else ''     # (1.18.0)
        print(f'[flowtrack-api] cannot listen on FT_WEB_BIND={BIND!r} port {PORT}: {e}{low}', flush=True)
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
    POLLER.start()
    # Path analysis: the neighbours worked out in the background (at once, then every 10 minutes)
    def _topo_warm():
        try:
            topo_structure(exporters_cfg(), wait=False)
        except (CHError, OSError) as e:
            print(f'[flowtrack-api] path analysis structure: {e}', flush=True)
        topo_refresher(threading.Event())
    threading.Thread(target=_topo_warm, daemon=True).start()
    threading.Thread(target=reports.scheduler, args=(report_call, VERSION), daemon=True).start()      # (1.10.0)
    for srv in servers[1:]:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    servers[0].serve_forever()
