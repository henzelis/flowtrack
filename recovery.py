"""(2.0.0 build 3) The database after an unclean stop (a power cut, a hard reset).

ClickHouse writes a part's files and renames the part into place; what the kernel had not yet written to the disk is
lost with the power. At the next start such parts are empty or cut short: ClickHouse sets them aside into the table's
detached/ folder (reason broken-on-start) and goes on — unless more than max_suspicious_broken_parts of one table are
broken, then the table stays offline and the collector waits for it for ever (the Optiplex, 2026-10-30: 106 broken
parts of flows, 18 hours without records). deploy/clickhouse-flowsphera.xml now lets any number of broken parts be
set aside (with FT_CH_FSYNC=1 durable() has the parts of flows and the state written to the disk before they count),
and this module tells the people what happened:

- once per start of ClickHouse it looks for parts set aside since the last look (system.detached_parts);
- the rollups that lost parts — all of them when the records did — are summed again from the records from the first
  day the lost parts belonged to (rollups.remake), so long periods and the records agree again;
- an event «Database recovered after an unclean stop» (detect kind db_recovered) says when the server stopped, what
  was set aside, which records are missing and what was summed again, on the Events page and on every notification
  channel;
- broken parts set aside more than KEEP_DAYS ago are removed (they are kept that long for a look by hand).
State: STATE_DIR/recovery.json (the ClickHouse start already looked at)."""
import datetime
import json
import os
import time

import detect
import notify
import rollups
from common import STATE_DIR, CHError, ch, sql_str

STATE = os.path.join(STATE_DIR, 'recovery.json')
# (FT_CH_FSYNC=1 in the env) the tables nothing can sum again get their parts written to the disk (fsync) before they
# count. Off by default (Yegor, 2026-10-31): in the Lab it made inserts of flows 10x slower (868 vs 79 ms, p99 8 s at
# 5,000 records/s) and it saves only the last seconds before a power cut — the collector loses what it holds then
# anyway, and the database recovers by itself without it
FSYNC_ON = os.environ.get('FT_CH_FSYNC', '0') == '1'
DURABLE = ('flows', 'agg_state', 'events')
FSYNC = {'fsync_after_insert': 1, 'fsync_part_directory': 1, 'min_rows_to_fsync_after_merge': 1}
KEEP_DAYS = 30
DROP_PER_RUN = 500       # removing a detached part is one query each: thousands after many power cuts, a few at a time
BROKEN = ('broken-on-start',)


def _load():
    try:
        with open(STATE) as f:
            v = json.load(f)
        return v if isinstance(v, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(st):
    tmp = STATE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(st, f)
    os.replace(tmp, STATE)


def durable(on=None):
    """fsync of the DURABLE tables as FT_CH_FSYNC says (the collector at its start; a setting of the table, kept in its
    metadata): switched on, or off again"""
    v = int(FSYNC_ON if on is None else on)
    want = {k: v for k in FSYNC}
    have = {r['name']: r['q'] for r in ch("SELECT name, create_table_query AS q FROM system.tables WHERE database = currentDatabase() "
                                          "AND name IN {t:Array(String)}", {'t': list(DURABLE)}, fmt='JSON')}
    for t, q in have.items():
        # a table never switched on has none of them: off already
        if all(f'{k} = {x}' in q for k, x in want.items()) or (not v and not any(f'{k} = 1' in q for k in FSYNC)):
            continue
        ch(f"ALTER TABLE {t} MODIFY SETTING {', '.join(f'{k} = {x}' for k, x in want.items())}")


def ch_started():
    """unix time ClickHouse started at"""
    return int(ch('SELECT toUnixTimestamp(now() - uptime()) AS t', fmt='JSON')[0]['t'])


def broken_parts(since):
    """parts of this database ClickHouse set aside as broken since the unix time `since`"""
    return ch("""SELECT table, partition_id, name, level, bytes_on_disk AS bytes, toUnixTimestamp(modification_time) AS t
            FROM system.detached_parts WHERE database = currentDatabase() AND reason IN {r:Array(String)} AND modification_time >= toDateTime({s:UInt32})""",
              {'r': list(BROKEN), 's': int(since)}, fmt='JSON')


def _day(partition_id):
    """start of the UTC day of a partition of a table partitioned by toYYYYMMDD(ts); None for other partitions"""
    try:
        return int(datetime.datetime.strptime(str(partition_id), '%Y%m%d').replace(tzinfo=datetime.timezone.utc).timestamp())
    except ValueError:
        return None


def summary(parts, started, stopped):
    """what the event says, from the parts set aside at one start: tables, sizes, the newest inserts lost (level 0 of
    flows: the records of the last moments before the stop never reached the disk), and which rollups are summed again
    from when"""
    tables, size, inserts = {}, 0, 0
    first = {}
    for p in parts:
        tables[p['table']] = tables.get(p['table'], 0) + 1
        size += int(p['bytes'])
        if p['table'] == 'flows' and not int(p['level']):
            inserts += 1
        day = _day(p['partition_id'])
        if day is not None:
            first[p['table']] = min(first.get(p['table'], day), day)
    # lost records: every rollup is summed again (it still counts them, the records do not); a rollup's own lost parts:
    # that rollup. From the first day a lost part belonged to (a merged part may hold the whole day), at least
    # from LATE before the stop
    floor = (stopped or started) - rollups.LATE
    resum = {}
    for name in rollups.ROLLUPS:
        if name in tables or 'flows' in tables:
            resum[name] = min([first[t] for t in (name, 'flows') if t in first] + [floor])
    return {'tables': dict(sorted(tables.items(), key=lambda kv: -kv[1])), 'parts': len(parts), 'bytes': size,
            'inserts': inserts, 'stopped': stopped, 'started': started, 'resum': resum,
            'since': min(resum.values()) if resum else 0}


class Recovery:
    def __init__(self, log=print):
        self.log, self.notifier = log, None

    def check(self):
        """Look at the parts set aside since the last look, once per start of ClickHouse. Returns the summary when
        something was set aside (the rollups to sum again are made again here: run rollups.backfill() after it)."""
        started, st = ch_started(), _load()
        if st.get('ch_started') == started:
            return None
        # the first look of this version: only the parts of this start (the older ones were reported by nobody, and
        # there may be thousands from before)
        parts = broken_parts(st.get('seen') or started - 60)
        st.update(ch_started=started, seen=int(time.time()))
        if not parts:
            _save(st)
            return None
        stopped = ch('SELECT toUnixTimestamp(max(ts)) AS t FROM flows WHERE ts < toDateTime({s:UInt32})', {'s': started}, fmt='JSON')
        stopped = int(stopped[0]['t']) if stopped and int(stopped[0]['t']) > 0 else 0
        s = summary(parts, started, stopped)
        self.log(f"ClickHouse set aside {s['parts']} broken parts at its start "
                 f"{time.strftime('%Y-%m-%d %H:%M', time.gmtime(started))} UTC (an unclean stop): "
                 + ', '.join(f'{t} {n}' for t, n in s['tables'].items()))
        known = rollups._get_state()
        todo = {name: v for name, v in s['resum'].items() if f'cutover:{name}' in known}
        if todo:
            rollups.remake(todo, self.log, {name: 'parts lost at an unclean stop' for name in todo})
        self._event(s)
        _save(st)       # after the event: a failure above looks again at the next start
        return s

    def _event(self, s):
        info = {k: s[k] for k in ('tables', 'parts', 'bytes', 'inserts', 'stopped', 'started', 'since')}
        now = int(time.time())
        hit = {'kind': 'db_recovered', 'key': str(s['started']), 'exporter': '', 'src': '', 'dst': '', 'port': 0, 'proto': 0,
               'value': float(s['parts']), 'info': info}
        new = []
        detect.store([hit], s['started'], now, new)
        cfg = detect.load_config()
        if not cfg['kinds'].get('db_recovered', {}).get('on', True):
            return
        if self.notifier is None:
            self.notifier = notify.Notifier(self.log)
        self.notifier.push([{'kind': r['kind'], 'row': r} for r in new], cfg['kinds'], now)

    def cleanup(self):
        """remove broken parts set aside more than KEEP_DAYS ago, DROP_PER_RUN at a time -> how many"""
        old = ch("""SELECT table, name FROM system.detached_parts WHERE database = currentDatabase() AND reason IN {r:Array(String)}
                AND modification_time < now() - INTERVAL {d:UInt16} DAY LIMIT {n:UInt32}""",
                 {'r': list(BROKEN), 'd': KEEP_DAYS, 'n': DROP_PER_RUN}, fmt='JSON')
        for p in old:
            ch(f"ALTER TABLE `{p['table']}` DROP DETACHED PART '{sql_str(p['name'])}'", settings={'allow_drop_detached': 1})
        return len(old)

    def watch(self, lock, stop=None, every=300):
        """the collector's thread: ClickHouse may start again on its own (a restart of its container, a crash), then
        its new broken parts are looked at here; once a day the old ones are removed"""
        cleaned = 0
        while not (stop and stop.is_set()):
            time.sleep(every)
            try:
                with lock:
                    if self.check():
                        rollups.backfill(self.log)
                if time.time() - cleaned >= 86400:
                    n = self.cleanup()
                    if n:
                        self.log(f'removed {n} broken parts set aside more than {KEEP_DAYS} days ago')
                    cleaned = time.time()
            except (CHError, OSError) as ex:
                self.log(f'WARN recovery check: {str(ex)[:200]}')
