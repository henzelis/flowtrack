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

from common import CHError, ch

BUCKET = 300        # the finest bucket (5 minutes); charts use rollups only with steps that are multiples of a table's own
VERSION = 1          # bump when a definition below changes: the tables are then built again

_COMMON = [('exporter', 'LowCardinality(String)'), ('dir', "Enum8('up' = 1, 'down' = 2, 'internal' = 3, 'transit' = 4)")]
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
}
CUT = max(r['bucket'] for r in ROLLUPS.values())    # the longest bucket (a day is a multiple of every bucket)
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


def backfill(log=print, settle=600, stop=None):
    """Fill the rollups with the records from before their cutover, newest day first (the API uses each day as soon as
    it is in). Tables with the same cutover are filled together, the earliest first: the 5-minute ones do not wait
    for the hourly ones. Waits `settle` seconds after a cutover first: records of the last minutes before it may
    still arrive (exporters send flows a little late), and they must not be missed."""
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
            ch(f'INSERT INTO {name} ' + _select(ROLLUPS[name], f'ts >= toDateTime({lo}) AND ts < toDateTime({min(hi, at)})'), timeout=3600,
               settings={'max_threads': 2, 'max_bytes_before_external_group_by': 200_000_000})
            _set(f'ready_from:{name}', lo)
        hi, n = lo, n + 1
        if stop and stop.is_set():
            return False
    for name in ready:
        _set(f'ready_from:{name}', 0)
    log(f"rollups: {', '.join(ready)}: history filled ({n} days, {time.time() - t0:.0f} s)")
    return True


def raise_keep_days(days):
    """A new license keeps the stored records longer: the rollups too (never shortened)."""
    for name in ROLLUPS:
        if int(ch(f'SELECT count() AS n FROM {name} WHERE keep_days < {int(days)}', fmt='JSON')[0]['n']):
            ch(f'ALTER TABLE {name} UPDATE keep_days = {int(days)} WHERE keep_days < {int(days)}')


_cache = {'t': 0, 'st': {}}
_lock = threading.Lock()


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


PREFER = ['agg_geo', 'agg_traffic', 'agg_ports', 'agg_host', 'agg_host_svc', 'agg_ext']    # smallest first
RAW_EXPR = {'has_ll': 'lat != 0'}       # rollup key columns that are expressions over the records
_TYPES = {c: t for r in ROLLUPS.values() for c, t, *_ in r['keys'] + r['attrs']}


def source(cols, t0, t1, flt_cols, use=True, step=None, table='flows'):
    """FROM-expression for a query over [t0, t1) (t1 None = up to now) that groups by or shows `cols` (a rollup's
    attributes only through any()) and filters on `flt_cols`; `step`: a time series' step (a rollup only when its
    bucket divides it). -> (sql, rollup name or None). Rows have ts, exporter, dir, `cols`, the filter columns,
    bytes, packets and flows (records), so a query sums `flows` instead of count(). The period is inside; the
    filters stay with the caller. `table`: what the records are read from (api.host_view for a chosen host)."""
    cols = list(dict.fromkeys(list(cols) + [c for c in flt_cols]))
    rcols = ', '.join(['ts', 'exporter', 'dir'] + [f'{RAW_EXPR[c]} AS {c}' if c in RAW_EXPR else c for c in cols if c not in ('exporter', 'dir')])
    raw = lambda cond: f"SELECT {rcols}, bytes, packets, toUInt64(1) AS flows FROM {table} WHERE {cond}"   # noqa: E731
    end = f' AND ts < toDateTime({int(t1)})' if t1 else ''
    whole = '(' + raw(f'ts >= toDateTime({int(t0)}){end}') + ')'
    if not use:
        return whole, None
    need = set(flt_cols) | {'exporter', 'dir'}
    name = next((n for n in PREFER if set(cols) <= COLUMNS[n] | ATTRS[n] and need <= COLUMNS[n]
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
