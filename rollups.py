"""Pre-aggregated flow tables (FlowTrack 1.3.3): 5-minute totals per exporter x direction x a few dimensions, kept
like the records they come from. A day of a busy network (tens of millions of records) becomes a few hundred
thousand rows, so pages over hours and days read 10-100x less.

Answers stay exact: a period is read from the rollups only for the 5-minute buckets that lie wholly inside it and
that the rollups hold completely; its edges (and anything older than the rollups) come from the records themselves.
A query whose dimension or filters are not in a rollup reads the records, as before.

The collector creates the tables and their materialized views (which fill them from the moment they exist) and then
fills the history in the background, newest day first; `ready_from()` tells the API from when on each is complete.
Each table starts at its own next bucket boundary: the 5-minute ones are in use minutes after an upgrade, not only
after the next full hour."""
import threading
import time

from common import CHError, ch, classify_l7_sql, port_service_sql, server_is_src_sql, sql_str

BUCKET = 300        # the finest bucket (5 minutes); charts use rollups only with steps that are multiples of a table's own
VERSION = 1          # bump when a definition below changes: the tables are then built again

DIR = "Enum8('up' = 1, 'down' = 2, 'internal' = 3, 'transit' = 4, 'internal_back' = 5)"     # as flows.dir
_COMMON = [('exporter', 'LowCardinality(String)'), ('dir', DIR)]
# name -> bucket (seconds), key columns (name, type, expression over `flows`) and attributes (any(...): the same for
# every record of a key, or any one of them, exactly like any() over the records). Measured on 40 M records a day
# where attributes follow the destination (as in real data): traffic 1/29, ports 1/35, geo 1/25 of the records.
ROLLUPS = {
    'agg_traffic': {'bucket': 300, 'keys': [('service', 'LowCardinality(String)', 'service'), ('l7', 'LowCardinality(String)', 'l7'),
                    ('proto', 'UInt8', 'proto'), ('country', 'LowCardinality(String)', 'country'), ('asn', 'UInt32', 'asn')],
                    'attrs': [('as_org', 'LowCardinality(String)')]},
    'agg_ports': {'bucket': 300, 'keys': [('ext_port', 'UInt16', 'ext_port'), ('proto', 'UInt8', 'proto'), ('l7', 'LowCardinality(String)', 'l7'),
                  ('service', 'LowCardinality(String)', 'service')],
                  'attrs': []},
    'agg_geo': {'bucket': 300, 'keys': [('country', 'LowCardinality(String)', 'country'), ('city', 'LowCardinality(String)', 'city'),
                ('has_ll', 'UInt8', 'lat != 0')],
                'attrs': [('lat', 'Float32'), ('lon', 'Float32')]},
    'agg_host': {'bucket': 300, 'keys': [('int_ip', 'String', 'int_ip')], 'attrs': []},
    # a host talks to many services: per hour the combinations repeat, per 5 minutes hardly
    'agg_host_svc': {'bucket': 3600, 'keys': [('int_ip', 'String', 'int_ip'), ('service', 'LowCardinality(String)', 'service'),
                     ('l7', 'LowCardinality(String)', 'l7'), ('proto', 'UInt8', 'proto')],
                     'attrs': []},
    # hundreds of thousands of outside addresses a day: they repeat within an hour, hardly within 5 minutes
    'agg_ext': {'bucket': 3600, 'keys': [('ext_ip', 'String', 'ext_ip')],
                'attrs': [('service', 'LowCardinality(String)'), ('country', 'LowCardinality(String)'), ('city', 'LowCardinality(String)'),
                          ('asn', 'UInt32'), ('as_org', 'LowCardinality(String)')]},
    # Through device and Path analysis (1.8.1): the paths through each device (input -> output interface); per hour the
    # inside hosts on them (and, between inside hosts, the other end) and the outside addresses beyond them
    # (1.16.0) QoS: traffic per DSCP class through each device (in -> out interface, the marking in and out), and per
    # hour the services of each class
    'agg_dscp': {'bucket': 300, 'keys': [('in_if', 'UInt32', 'in_if'), ('out_if', 'UInt32', 'out_if'), ('dscp', 'UInt8', 'dscp'),
                 ('dscp_out', 'UInt8', 'dscp_out')], 'attrs': []},
    'agg_dscp_svc': {'bucket': 3600, 'keys': [('dscp', 'UInt8', 'dscp'), ('service', 'LowCardinality(String)', 'service'),
                     ('l7', 'LowCardinality(String)', 'l7'), ('int_ip', 'String', 'int_ip')], 'attrs': []},
    # (1.16.2) Flows: the conversations (inside host x outside address) per hour, for Top conversations and the river of
    # a whole period — a busy network repeats its pairs within the hour (200F: ~8 M records, ~130 k pairs an hour)
    'agg_conv': {'bucket': 3600, 'keys': [('int_ip', 'String', 'int_ip'), ('ext_ip', 'String', 'ext_ip')],
                 'attrs': [('service', 'LowCardinality(String)'), ('country', 'LowCardinality(String)'), ('city', 'LowCardinality(String)')]},
    'agg_iface': {'bucket': 300, 'keys': [('in_if', 'UInt32', 'in_if'), ('out_if', 'UInt32', 'out_if'), ('service', 'LowCardinality(String)', 'service')],
                  'attrs': []},
    'agg_iface_host': {'bucket': 3600, 'keys': [('in_if', 'UInt32', 'in_if'), ('out_if', 'UInt32', 'out_if'), ('int_ip', 'String', 'int_ip'),
                       ('peer_ip', 'String', "if(dir IN ('internal', 'internal_back'), ext_ip, '')")],
                       'attrs': []},
    'agg_iface_ext': {'bucket': 3600, 'keys': [('in_if', 'UInt32', 'in_if'), ('out_if', 'UInt32', 'out_if'), ('out_ip', 'String', "if(dir IN ('up', 'down'), ext_ip, '')")],
                      'attrs': [('service', 'LowCardinality(String)'), ('country', 'LowCardinality(String)'), ('city', 'LowCardinality(String)')]},
}
CUT = max(r['bucket'] for r in ROLLUPS.values())    # the longest bucket (a day is a multiple of every bucket)
LATE = 2 * 3600     # records may reach the collector this late (a multiple of every bucket): see _late()
# columns a query may filter or group by in each rollup (besides ts, exporter, dir); attributes may only be shown
COLUMNS = {name: {'exporter', 'dir'} | {k[0] for k in r['keys']} for name, r in ROLLUPS.items()}
ATTRS = {name: {a[0] for a in r['attrs']} for name, r in ROLLUPS.items()}


def _ddl(name, r):
    cols = [('ts', 'DateTime')] + _COMMON + [(k[0], k[1]) for k in r['keys']]
    cols += [(a[0], f'SimpleAggregateFunction(any, {a[1]})') for a in r['attrs']]
    cols += [('keep_days', 'SimpleAggregateFunction(max, UInt16)')] + [(c, 'SimpleAggregateFunction(sum, UInt64)') for c in ('bytes', 'packets', 'flows')]
    order = ', '.join(['ts', 'exporter', 'dir'] + [k[0] for k in r['keys']])
    return (f"CREATE TABLE IF NOT EXISTS {name} ({', '.join(f'{c} {t}' for c, t in cols)}) ENGINE = AggregatingMergeTree "
            f"PARTITION BY toYYYYMMDD(ts) ORDER BY ({order}) TTL ts + toIntervalDay(keep_days)")


def _select(r, where):
    keys = ', '.join(f'{k[2]} AS {k[0]}' for k in r['keys'])
    attrs = ''.join(f', any({a[0]}) AS {a[0]}' for a in r['attrs'])
    group = ', '.join(['ts', 'exporter', 'dir'] + [k[0] for k in r['keys']])
    return (f"SELECT toStartOfInterval(ts, toIntervalSecond({r['bucket']})) AS ts, exporter, dir, {keys}{attrs}, max(keep_days) AS keep_days, "
            f"sum(bytes) AS bytes, sum(packets) AS packets, count() AS flows FROM flows WHERE {where} GROUP BY {group}")


def _get_state():
    try:
        rows = ch("SELECT k, argMax(v, t) AS v FROM agg_state GROUP BY k", fmt='JSON')
    except CHError:
        return {}
    return {r['k']: int(r['v']) for r in rows}


def _set(k, v):
    ch(f"INSERT INTO agg_state (k, v) VALUES ('{k}', {int(v)})")


def widen_dir():
    """Tables from before 1.7.0: the direction of a server's answer between inside hosts ('internal_back'). Runs
    before anything is received — the materialized views would refuse such a record otherwise. Only metadata."""
    have = {r['name'] for r in ch("SELECT name FROM system.tables WHERE database = currentDatabase()", fmt='JSON')}
    for name in ROLLUPS:
        if name in have:
            ch(f'ALTER TABLE {name} MODIFY COLUMN dir {DIR}')


def ensure(log=print):
    """Create the rollups and start filling them (at the next 5-minute boundary). Returns the state. Rebuilds them
    when VERSION changed."""
    ch("CREATE TABLE IF NOT EXISTS agg_state (k String, v Int64, t DateTime64(3) DEFAULT now64(3)) ENGINE = ReplacingMergeTree(t) ORDER BY k")
    st = _get_state()
    if st.get('version') not in (None, VERSION):
        log(f'rollups: definitions changed ({st.get("version")} -> {VERSION}), building them again')
        for name in ROLLUPS:
            ch(f'DROP VIEW IF EXISTS {name}_mv')
            ch(f'DROP TABLE IF EXISTS {name}')
        ch('TRUNCATE TABLE agg_state')
        st = {}
    if st.get('version') == VERSION and all(f'cutover:{name}' in st for name in ROLLUPS):
        for name, r in ROLLUPS.items():          # a table lost by hand: recreated (its history is filled again)
            ch(_ddl(name, r))
        return st
    now = int(time.time())
    for name, r in ROLLUPS.items():
        if f'cutover:{name}' in st:
            continue
        cut = (now // r['bucket'] + 1) * r['bucket']    # the table's own next bucket boundary
        ch(f'DROP VIEW IF EXISTS {name}_mv')
        ch(f'DROP TABLE IF EXISTS {name}')       # left by an interrupted first start: its rows would be counted twice
        ch(_ddl(name, r))
        ch(f'CREATE MATERIALIZED VIEW {name}_mv TO {name} AS ' + _select(r, f'ts >= toDateTime({cut})'))
        _set(f'cutover:{name}', cut)
        _set(f'ready_from:{name}', cut)        # complete from the cutover on; history is filled by backfill()
    _set('version', VERSION)
    cut = min(v for k, v in _get_state().items() if k.startswith('cutover:'))
    log(f"rollups: created, filled from {time.strftime('%Y-%m-%d %H:%M', time.gmtime(cut))} UTC on")
    return _get_state()


def _wait(until, stop):
    """sleep until the unix time `until`; False when `stop` was set meanwhile"""
    while time.time() < until:
        if stop and stop.wait(10):
            return False
        if not stop:
            time.sleep(10)
    return not (stop and stop.is_set())


def backfill(log=print, settle=600, stop=None, late=LATE):
    """Fill the rollups with the records from before their cutover, newest day first (the API uses each day as soon as
    it is in). Tables with the same cutover are filled together, the earliest first: the 5-minute ones do not wait
    for the hourly ones. Waits `settle` seconds after a cutover first: records of the last minutes before it may
    still arrive (exporters send flows a little late), and they must not be missed. The few that come later still
    are taken in by _late() (late=None: not, for checks in a scratch DB that gets no new records)."""
    st = _get_state()
    todo = {name: st[f'ready_from:{name}'] for name in ROLLUPS if st.get(f'ready_from:{name}', 0) > 0}
    mutations_checked = False
    for cut in sorted({st[f'cutover:{name}'] for name in todo}):
        if not _wait(cut + settle, stop):
            return
        # the records' days may still be changing (an upgrade from before 1.3.1 raises them with an asynchronous
        # mutation): the rollups take the days over, so they wait for it (or they could expire before their records)
        for _ in range(0 if mutations_checked else 720):
            if not int(ch("SELECT count() AS n FROM system.mutations WHERE database = currentDatabase() AND table = 'flows' AND NOT is_done", fmt='JSON')[0]['n']):
                break
            if not _wait(time.time() + 10, stop):
                return
        mutations_checked = True
        if not _fill({name: v for name, v in todo.items() if st[f'cutover:{name}'] == cut}, log, stop):
            return
    if late is not None:
        _late(log, stop, late)


def _late(log, stop, late):
    """A record that ends before a table's cutover but reaches the collector after its history was filled is in
    neither (the view takes only records from the cutover on): seen once on 2026-10-08, a record 20 minutes late.
    `late` seconds after the cutover the buckets of the last `late` seconds before it are summed up again when they
    differ from the records. Once per table — installs that filled their history before 1.7.1 get it at the next
    start."""
    st = _get_state()
    for cut in sorted({st[f'cutover:{name}'] for name in ROLLUPS if not st.get(f'late:{name}')}):
        if not _wait(cut + late, stop):
            return
        part = f'ts >= toDateTime({cut - late}) AND ts < toDateTime({cut})'
        for name in ROLLUPS:
            if st[f'cutover:{name}'] != cut or st.get(f'late:{name}'):
                continue
            n = int(ch(f'SELECT count() AS n FROM flows WHERE {part}', fmt='JSON')[0]['n'])
            have = int(ch(f'SELECT sum(flows) AS n FROM {name} WHERE {part}', fmt='JSON')[0]['n'])
            if n != have:
                ch(f'ALTER TABLE {name} DELETE WHERE {part}', timeout=3600, settings={'mutations_sync': 2})
                ch(f'INSERT INTO {name} ' + _select(ROLLUPS[name], part), timeout=3600,
                   settings={'max_threads': 2, 'max_bytes_before_external_group_by': 200_000_000})
                log(f'rollups: {name}: {n - have:,} records that came after the history was filled added')
            _set(f'late:{name}', 1)


def _fill(ready, log, stop):
    """backfill() of the tables in `ready` (name -> complete from); False when stopped"""
    oldest = ch("SELECT toUnixTimestamp(min(ts)) AS t, count() AS n FROM flows WHERE ts < toDateTime({c:UInt32})", {'c': max(ready.values())}, fmt='JSON')
    if not oldest or not int(oldest[0]['n']):
        for name in ready:
            _set(f'ready_from:{name}', 0)
        log(f"rollups: {', '.join(ready)}: no older records, complete")
        return True
    # a backfill INSERT of a stopped collector goes on inside ClickHouse: stop it before its day is cleared and redone
    for name in ready:
        ch(f"KILL QUERY WHERE current_database = currentDatabase() AND query LIKE 'INSERT INTO {name} SELECT%' SYNC")
    first, t0, n = int(oldest[0]['t']) // 86400 * 86400, time.time(), 0
    hi, fresh = max(ready.values()), set(ready)
    while hi > first:
        lo = max(first, (hi - 1) // 86400 * 86400)      # a day boundary is a boundary of every bucket
        for name, at in ready.items():
            if at <= lo:
                continue
            if name in fresh:            # the first day of this run: a stop in the middle of it may have left part of it
                fresh.discard(name)
                part = f'ts >= toDateTime({lo}) AND ts < toDateTime({min(hi, at)})'
                if int(ch(f'SELECT count() AS n FROM {name} WHERE {part}', fmt='JSON')[0]['n']):
                    ch(f'ALTER TABLE {name} DELETE WHERE {part}', timeout=3600, settings={'mutations_sync': 2})
            # an hourly table holds many more keys (outside addresses, hosts x services): a day of a busy network in one
            # query needed ~3 GiB (seen with 2,400 records/s on 8 GB of RAM: refused, tried again every minute) —
            # it is filled an hour at a time, newest first, and its progress kept after each
            step = 86400 if ROLLUPS[name]['bucket'] < 3600 else ROLLUPS[name]['bucket']
            end = min(hi, at)
            while end > lo:
                beg = max(lo, (end - 1) // step * step)
                ch(f'INSERT INTO {name} ' + _select(ROLLUPS[name], f'ts >= toDateTime({beg}) AND ts < toDateTime({end})'), timeout=3600,
                   settings={'max_threads': 2, 'max_bytes_before_external_group_by': 200_000_000})
                _set(f'ready_from:{name}', beg)
                end = beg
                if stop and stop.is_set():
                    return False
        hi, n = lo, n + 1
        if stop and stop.is_set():
            return False
    for name in ready:
        _set(f'ready_from:{name}', 0)
    log(f"rollups: {', '.join(ready)}: history filled ({n} days, {time.time() - t0:.0f} s)")
    return True


_PRIVATE = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', 'fc00::/7', 'fe80::/10', '::1/128')
REORIENT_TMP = 'flows_reorient'


def reorient_internal(log=print, stop=None, settle=600):
    """Records between inside hosts stored before 1.7.0 run source -> destination; since 1.7.0 int_* is the client
    and ext_* the server (common.server_is_src). The stored server answers are turned round once: int/ext swapped,
    dir 'internal_back', the L7 protocol and service from the server's port. Everything received from the hour after
    the upgrade on is new already; that hour boundary (+ `settle` for late exports) is waited for, so no old record
    arrives after it. Steps are recorded in agg_state: a restart goes on where it stopped. Then the per-hour usage and
    the rollups are summed again for the inside traffic of that period. -> False when stopped."""
    st = _get_state()
    if st.get('reorient:done'):
        return True
    cond = f"dir = 'internal' AND {server_is_src_sql()}"
    t2 = st.get('reorient:t2')
    if not t2:
        if not int(ch(f"SELECT count() AS n FROM flows WHERE {cond}", fmt='JSON')[0]['n']):
            _set('reorient:done', 1)
            return True
        t2 = (int(time.time()) // 3600 + 1) * 3600
        _set('reorient:t2', t2)
    log(f"inside traffic: turning stored server answers round (client -> server) at {time.strftime('%H:%M', time.gmtime(t2 + settle))} UTC")
    if not _wait(t2 + settle, stop):
        return False
    phase, sync = st.get('reorient:phase', 0), {'mutations_sync': 2}
    old = f'ts < toDateTime({t2}) AND {cond}'
    if phase < 1:
        new_ext = 'int_ip'
        private = f"arrayExists(n -> isIPAddressInRange({new_ext}, n), [{', '.join(repr(n) for n in _PRIVATE)}])"
        ps = port_service_sql('proto', 'int_port')
        ch(f'DROP TABLE IF EXISTS {REORIENT_TMP}')
        ch(f'CREATE TABLE {REORIENT_TMP} AS flows')
        ch(f"""INSERT INTO {REORIENT_TMP} SELECT * REPLACE (ext_ip AS int_ip, int_ip AS ext_ip, ext_port AS int_port, int_port AS ext_port,
                CAST('internal_back' AS {DIR}) AS dir, {classify_l7_sql('proto', 'int_port')} AS l7,
                if({ps} != '', {ps}, if({private}, 'Local network', service)) AS service)
            FROM flows WHERE {old}""", timeout=3600)
        _set('reorient:phase', 1)
    if phase < 2:
        ch(f'ALTER TABLE flows DELETE WHERE {old}', timeout=3600, settings=sync)
        _set('reorient:phase', 2)
    if phase < 3:
        key = 'cityHash64(ts, ts_start, exporter, int_ip, ext_ip, int_port, ext_port, proto, bytes, packets)'
        if phase == 2:           # stopped while moving them back: what arrived of it is removed first
            ch(f"ALTER TABLE flows DELETE WHERE ts < toDateTime({t2}) AND dir = 'internal_back' AND {key} IN (SELECT {key} FROM {REORIENT_TMP})",
               timeout=3600, settings=sync)
        ch(f'INSERT INTO flows SELECT * FROM {REORIENT_TMP}', timeout=3600)
        _set('reorient:phase', 3)
    if phase < 4:
        inside = "dir IN ('internal', 'internal_back')"
        first = int(ch("SELECT toUnixTimestamp(min(ts)) AS t FROM flows", fmt='JSON')[0]['t'])
        st = _get_state()
        for name, r in ROLLUPS.items():
            if f'ready_from:{name}' not in st:
                continue
            B = r['bucket']
            a = max(first // B * B, st[f'ready_from:{name}'])     # what the table holds (the rest: backfill)
            if a >= t2:
                continue
            part = f'ts >= toDateTime({a}) AND ts < toDateTime({t2})'
            ch(f'ALTER TABLE {name} DELETE WHERE {part} AND {inside}', timeout=3600, settings=sync)
            ch(f'INSERT INTO {name} ' + _select(r, f'{part} AND {inside}'), timeout=3600)
        _set('reorient:phase', 4)
    ch(f'DROP TABLE IF EXISTS {REORIENT_TMP}')
    n = int(ch(f"SELECT count() AS n FROM flows WHERE ts < toDateTime({t2}) AND dir = 'internal_back'", fmt='JSON')[0]['n'])
    _set('reorient:done', 1)
    log(f'inside traffic: {n:,} stored server answers turned round (client -> server)')
    return True


def raise_keep_days(days):
    """A new license keeps the stored records longer: the rollups too (never shortened)."""
    for name in ROLLUPS:
        if int(ch(f'SELECT count() AS n FROM {name} WHERE keep_days < {int(days)}', fmt='JSON')[0]['n']):
            ch(f'ALTER TABLE {name} UPDATE keep_days = {int(days)} WHERE keep_days < {int(days)}')


_cache = {'t': 0, 'st': {}}
_lock = threading.Lock()


# (1.8.3) the user renamed ports: the L7 protocol is a key of these rollups
L7_TABLES = [n for n, r in ROLLUPS.items() if any(k[0] == 'l7' for k in r['keys'])]


def relabel_records(names):
    """{(proto, port): l7}: the stored records of those ports get these L7 names (the rollups follow later)."""
    if not names:
        return
    arms = ', '.join(f"(proto, ext_port) = ({int(p)}, {int(n)}), '{sql_str(v)}'" for (p, n), v in sorted(names.items()))
    keys = ', '.join(f'({int(p)}, {int(n)})' for p, n in sorted(names))
    ch(f"ALTER TABLE flows UPDATE l7 = multiIf({arms}, l7) WHERE (proto, ext_port) IN ({keys})", timeout=3600,
       settings={'mutations_sync': 2})


def relabel_rollups(protos, labels, until, at=None, log=print, stop=None):
    """Sum the rollup buckets before `until` (a full hour) that hold these L7 names (old and new) again from the
    records, newest day first — a day per DELETE, an hour per INSERT (bounded memory). -> where it stopped (unix s,
    to go on from), 0 when done. Buckets older than the records keep their names."""
    if not protos or not labels:        # nothing to sum again (an empty IN () is an SQL error)
        return 0
    old = ch("SELECT toUnixTimestamp(min(ts)) AS t, count() AS n FROM flows", fmt='JSON')
    if not old or not int(old[0]['n']):
        return 0
    # from the first whole hour that still has records: the totals of older hours are all that is left of them
    first = -(-int(old[0]['t']) // 3600) * 3600
    cond = (f"proto IN ({', '.join(str(int(p)) for p in sorted(protos))}) AND "
            f"l7 IN ({', '.join(chr(39) + sql_str(x) + chr(39) for x in sorted(labels))})")
    hi = min(until, at) if at else until
    while hi > first:
        if stop and stop.is_set():
            return hi
        lo = max(first, (hi - 1) // 86400 * 86400)
        for name in L7_TABLES:
            ch(f'ALTER TABLE {name} DELETE WHERE ts >= toDateTime({lo}) AND ts < toDateTime({hi}) AND {cond}', timeout=3600,
               settings={'mutations_sync': 2})
            for h in range(lo, hi, 3600):
                ch(f'INSERT INTO {name} ' + _select(ROLLUPS[name], f'ts >= toDateTime({h}) AND ts < toDateTime({min(h + 3600, hi)}) AND {cond}'),
                   timeout=3600, settings={'max_threads': 2, 'max_bytes_before_external_group_by': 200_000_000})
        hi = lo
    return 0


def ready_from(name=None):
    """From when on (unix time, a bucket boundary) rollup `name` is complete (no name: all of them); None = not in
    use. Re-read every 30 s."""
    with _lock:
        if time.time() - _cache['t'] > 30:
            _cache['st'], _cache['t'] = _get_state(), time.time()
        st = _cache['st']
    if st.get('version') != VERSION:
        return None
    got = [st.get(f'ready_from:{n}') for n in ([name] if name else ROLLUPS)]
    return None if None in got else max(got)


# smallest first; a table added later goes after those that hold the same columns, so their queries stay where they are
PREFER = ['agg_geo', 'agg_traffic', 'agg_ports', 'agg_iface', 'agg_host', 'agg_host_svc', 'agg_iface_host', 'agg_ext', 'agg_iface_ext', 'agg_conv']
# (1.16.2) only for a query that groups by the pair, or by its key columns alone (exact) — never for an attribute (a
# service per pair and hour is any() of them) because a filter needs both ends
PAIR_ONLY = {'agg_conv'}
RAW_EXPR = {'has_ll': 'lat != 0', 'peer_ip': "if(dir IN ('internal', 'internal_back'), ext_ip, '')",
            'out_ip': "if(dir IN ('up', 'down'), ext_ip, '')"}       # rollup key columns that are expressions over the records
_TYPES = {c: t for r in ROLLUPS.values() for c, t, *_ in r['keys'] + r['attrs']}


def source(cols, t0, t1, flt_cols, use=True, step=None, table='flows'):
    """FROM-expression for a query over [t0, t1) (t1 None = up to now) that groups by or shows `cols` (a rollup's
    attributes only through any()) and filters on `flt_cols`; `step`: a time series' step (a rollup only when its
    bucket divides it). -> (sql, rollup name or None). Rows have ts, exporter, dir, `cols`, the filter columns,
    bytes, packets and flows (records), so a query sums `flows` instead of count(). The period is inside; the
    filters stay with the caller. `table`: what the records are read from (api.host_view for a chosen host)."""
    asked = set(cols)
    cols = list(dict.fromkeys(list(cols) + [c for c in flt_cols]))
    rcols = ', '.join(['ts', 'exporter', 'dir'] + [f'{RAW_EXPR[c]} AS {c}' if c in RAW_EXPR else c for c in cols if c not in ('exporter', 'dir')])
    raw = lambda cond: f"SELECT {rcols}, bytes, packets, toUInt64(1) AS flows FROM {table} WHERE {cond}"   # noqa: E731
    end = f' AND ts < toDateTime({int(t1)})' if t1 else ''
    whole = '(' + raw(f'ts >= toDateTime({int(t0)}){end}') + ')'
    if not use or table != 'flows':      # (1.16.2) a chosen host's turned records (api.host_view) are not in any rollup
        return whole, None
    need = set(flt_cols) | {'exporter', 'dir'}
    name = next((n for n in PREFER if set(cols) <= COLUMNS[n] | ATTRS[n] and need <= COLUMNS[n]
                 and (n not in PAIR_ONLY or {'int_ip', 'ext_ip'} <= asked or asked <= COLUMNS[n])
                 and not (step and step % ROLLUPS[n]['bucket'])), None)
    rf = ready_from(name) if name else None
    if rf is None:
        return whole, None
    B = ROLLUPS[name]['bucket']
    a = max(-(-int(t0) // B) * B, rf)                         # first whole bucket the rollup holds
    b = (int(t1) if t1 else int(time.time())) // B * B       # end of the last whole bucket (the current one is raw)
    if b - a < B:
        return whole, None
    # the rollup's columns as plain types (SimpleAggregateFunction(...) would not unite with the records' columns)
    acols = ', '.join(['ts', 'exporter', 'dir'] + [f"CAST({c}, '{_TYPES[c]}') AS {c}" for c in cols if c not in ('exporter', 'dir')])
    parts = [f"SELECT {acols}, toUInt64(bytes) AS bytes, toUInt64(packets) AS packets, toUInt64(flows) AS flows FROM {name} "
             f"WHERE ts >= toDateTime({a}) AND ts < toDateTime({b})",
             raw(f'ts >= toDateTime({int(t0)}) AND ts < toDateTime({a})'),
             raw(f'ts >= toDateTime({b}){end}')]
    return '(' + ' UNION ALL '.join(parts) + ')', name
