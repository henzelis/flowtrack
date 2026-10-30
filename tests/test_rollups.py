"""Which rollup a query reads (rollups.source): each table from its own cutover on, whole buckets only, edges from
the records; the state as the collector writes it (no ClickHouse needed)."""
import os
import sys
import tempfile
import time
import unittest

TMP = tempfile.mkdtemp()
os.makedirs(TMP + '/cfg'), os.makedirs(TMP + '/state')
open(TMP + '/cfg/exporters.json', 'w').write('{}')
os.environ.update(FT_CONFIG_DIR=TMP + '/cfg', FT_STATE_DIR=TMP + '/state')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import rollups  # noqa: E402

DAY = 86400
NOW = 1791446400 + 3 * 3600 + 7 * 60       # 03:07 UTC: the 5-minute tables start at 03:10, the hourly ones at 04:00


class Source(unittest.TestCase):
    def state(self, **ready):
        st = {'version': rollups.VERSION}
        for name, r in rollups.ROLLUPS.items():
            cut = (NOW // r['bucket'] + 1) * r['bucket']
            st[f'cutover:{name}'] = cut
            st[f'ready_from:{name}'] = ready.get(name, cut)
        rollups._cache.update(st=st, t=float('inf'))

    def setUp(self):
        rollups.time = type('Clock', (), {'time': staticmethod(lambda: NOW)})

    def tearDown(self):
        rollups.time = time
        rollups._cache.update(st={}, t=0)

    def test_each_table_from_its_own_cutover(self):
        self.state(agg_traffic=0, agg_ext=NOW // 3600 * 3600 + 3600)   # traffic complete; ext not until its cutover
        sql, name = rollups.source(['service'], NOW - DAY, None, [])
        self.assertEqual(name, 'agg_traffic')
        sql, name = rollups.source(['ext_ip'], NOW - DAY, None, [])
        self.assertIsNone(name)                     # the hourly table holds nothing whole yet: records only
        self.assertNotIn('agg_ext', sql)

    def test_whole_buckets_from_the_rollup_edges_from_the_records(self):
        self.state(agg_geo=0)
        t0, t1 = NOW - DAY + 137, NOW - 3600 + 41
        sql, name = rollups.source([], t0, t1, [])
        self.assertEqual(name, 'agg_geo')
        a, b = -(-t0 // 300) * 300, t1 // 300 * 300
        self.assertIn(f'FROM agg_geo WHERE ts >= toDateTime({a}) AND ts < toDateTime({b})', sql)
        self.assertIn(f'ts >= toDateTime({t0}) AND ts < toDateTime({a})', sql)
        self.assertIn(f'ts >= toDateTime({b}) AND ts < toDateTime({t1})', sql)

    def test_port_filter_tables_1170(self):
        """(1.17.0) under a port filter the conversations come from agg_conv_port and the AS from agg_ports; without
        one agg_conv stays the table (agg_conv_port is never chosen for it)"""
        self.state(**{n: 0 for n in rollups.ROLLUPS})
        pair = ['int_ip', 'ext_ip', 'service', 'country', 'city']
        self.assertEqual(rollups.source(pair, NOW - DAY, None, [])[1], 'agg_conv')
        self.assertEqual(rollups.source(pair, NOW - DAY, None, ['ext_port'])[1], 'agg_conv_port')
        self.assertEqual(rollups.source(pair, NOW - DAY, None, ['ext_port', 'proto'])[1], 'agg_conv_port')
        path = ['in_if', 'out_if', 'int_ip', 'ext_ip', 'nat_ip']
        self.assertEqual(rollups.source(path, NOW - DAY, None, [])[1], 'agg_conv')
        self.assertEqual(rollups.source(path, NOW - DAY, None, ['ext_port'])[1], 'agg_conv_port')
        self.assertEqual(rollups.source(['asn', 'as_org', 'country'], NOW - DAY, None, ['ext_port'])[1], 'agg_ports')
        self.assertEqual(rollups.source(['ext_port'], NOW - DAY, None, [])[1], 'agg_ports')
        for cols, flt in ((['int_ip'], []), (['ext_ip'], []), (['service'], []), (['int_ip'], ['ext_port'])):
            self.assertNotEqual(rollups.source(cols, NOW - DAY, None, flt)[1], 'agg_conv_port', (cols, flt))

    def test_whole_buckets_read_no_records_1170(self):
        """(1.17.0) a period of whole buckets has no edges: the records are not in the query at all"""
        self.state(agg_geo=0)
        t0 = (NOW - DAY) // 3600 * 3600
        sql, name = rollups.source([], t0, t0 + 6 * 3600, [])
        self.assertEqual(name, 'agg_geo')
        self.assertNotIn('FROM flows', sql)
        sql, _ = rollups.source([], t0 + 7, t0 + 6 * 3600, [])           # only the left edge
        self.assertEqual(sql.count('FROM flows'), 1)
        self.assertIn(f'ts >= toDateTime({t0 + 7}) AND ts < toDateTime({t0 + 300})', sql)

    def test_history_not_filled_yet_comes_from_the_records(self):
        rf = NOW // DAY * DAY                        # backfill got down to midnight
        self.state(agg_traffic=rf)
        sql, name = rollups.source(['service'], NOW - DAY, None, [])
        self.assertEqual(name, 'agg_traffic')
        self.assertIn(f'FROM agg_traffic WHERE ts >= toDateTime({rf})', sql)
        self.assertIn(f'ts >= toDateTime({NOW - DAY}) AND ts < toDateTime({rf})', sql)

    def test_columns_filters_and_steps_the_rollup_lacks(self):
        self.state(**{n: 0 for n in rollups.ROLLUPS})
        self.assertIsNone(rollups.source(['int_ip', 'ext_ip'], NOW - DAY, None, ['dscp'])[1])  # a filter no conversations table has
        self.assertEqual(rollups.source(['int_ip', 'ext_ip'], NOW - DAY, None, ['l7'])[1], 'agg_conv_port')     # (1.17.0) L7 there
        self.assertEqual(rollups.source(['service'], NOW - DAY, None, ['ext_port', 'int_ip'])[1], 'agg_conv_port')   # (1.17.0)
        self.assertEqual(rollups.source(['l7'], NOW - DAY, None, ['ext_port', 'int_ip'])[1], 'agg_conv_port')
        self.assertIsNone(rollups.source(['l7'], NOW - DAY, None, ['ext_port', 'int_ip', 'dscp'])[1])
        self.assertEqual(rollups.source(['service'], NOW - DAY, None, ['ext_port'])[1], 'agg_ports')
        self.assertEqual(rollups.source(['int_ip'], NOW - DAY, None, [], step=300)[1], 'agg_host')
        self.assertIsNone(rollups.source(['ext_ip'], NOW - DAY, None, [], step=300)[1])     # hourly table, 5-min step
        self.assertEqual(rollups.source(['ext_ip'], NOW - DAY, None, [], step=3600)[1], 'agg_ext')
        self.assertIsNone(rollups.source(['service'], NOW - DAY, None, [], use=False)[1])

    def test_conversations_1162(self):
        """(1.16.2) agg_conv serves the pairs (Top conversations, the river of a period) and key-only queries with a
        filter on either end; never an attribute grouped under a host filter (service per pair and hour is any()) nor
        a chosen host's turned records"""
        self.state(**{n: 0 for n in rollups.ROLLUPS})
        self.assertEqual(rollups.source(['int_ip', 'ext_ip'], NOW - DAY, None, [])[1], 'agg_conv')
        self.assertEqual(rollups.source(['int_ip', 'ext_ip', 'service', 'country', 'city'], NOW - DAY, None, [])[1], 'agg_conv')
        self.assertEqual(rollups.source(['int_ip'], NOW - DAY, None, ['ext_ip'])[1], 'agg_conv')
        self.assertEqual(rollups.source(['int_ip'], NOW - DAY, None, [])[1], 'agg_host')        # the smaller table first
        # (1.17.0) service / country / city are keys of agg_conv: exact under a filter on both ends too
        self.assertEqual(rollups.source(['service'], NOW - DAY, None, ['int_ip', 'ext_ip'])[1], 'agg_conv')
        self.assertIsNone(rollups.source(['int_ip', 'ext_ip'], NOW - DAY, None, [], table='(SELECT * FROM flows)')[1])

    def test_chosen_host_turned_from_the_conversations_1170(self):
        """(1.17.0) a chosen host over inside traffic (api.host_view): its sessions as the client from the table that
        answers without one, those as the server from agg_conv turned round to it; the records when either has none"""
        self.state(**{n: 0 for n in rollups.ROLLUPS})
        turn = "(dir IN ('internal', 'internal_back') AND ext_ip = 'h' AND NOT int_ip = 'h')"
        sql, name = rollups.source(['service'], NOW - DAY, NOW, {'dir', 'int_ip'}, table='(host view)', turn=turn)
        self.assertEqual(name, 'agg_host_svc+agg_conv')
        a, b = sql.split(' UNION ALL SELECT ts, exporter, CAST(', 1)
        self.assertIn('toUInt8(0) AS turned', a)
        self.assertIn('ext_ip AS int_ip', b)                                    # the host, the server, is int_ip now
        self.assertIn("if(dir = 'internal', 'internal_back', 'internal')", b)  # its sent / received swapped
        self.assertIn('toUInt8(1) AS turned', b)
        self.assertIn(f'WHERE {turn}', b)                                      # over the record's own ends
        self.assertNotIn('host view', sql)
        # the both ends of each row, swapped where turned (Top hosts inside: who called whom)
        sql, name = rollups.source(['int_ip', 'ext_ip', 'turned'], NOW - DAY, NOW, {'int_ip'}, table='(host view)', turn=turn)
        self.assertEqual(name, 'agg_conv+agg_conv')
        self.assertIn('ext_ip AS int_ip, int_ip AS ext_ip', sql)
        # a port of a turned session is its int_port, which no rollup holds; a rollup not ready yet: the records
        # its protocols and services (with their L7 name) from agg_conv_port, which holds the L7 name too
        self.assertEqual(rollups.source(['l7'], NOW - DAY, NOW, {'int_ip'}, table='(host view)', turn=turn)[1], 'agg_host_svc+agg_conv_port')
        self.assertEqual(rollups.source(['service', 'l7', 'proto'], NOW - DAY, NOW, {'int_ip'}, table='(host view)', turn=turn)[1],
                         'agg_host_svc+agg_conv_port')
        sql, name = rollups.source(['ext_port'], NOW - DAY, NOW, {'int_ip'}, table='(host view)', turn=turn)
        self.assertIsNone(name)
        self.assertIn('FROM (host view)', sql)
        self.state(**{n: 0 for n in rollups.ROLLUPS if n != 'agg_conv'})
        self.assertIsNone(rollups.source(['service'], NOW - DAY, NOW, {'int_ip'}, table='(host view)', turn=turn)[1])

    def test_qos_ports_and_keys_1170(self):
        """(1.17.0) the QoS tables are read (they were built but never chosen); hosts / addresses of a port come from
        the per-port tables; what an address is (service, country) filters the per-address tables exactly"""
        self.state(**{n: 0 for n in rollups.ROLLUPS})
        self.assertEqual(rollups.source(['dscp'], NOW - DAY, None, [])[1], 'agg_dscp')
        self.assertEqual(rollups.source(['in_if', 'out_if', 'dscp', 'dscp_out'], NOW - DAY, None, [])[1], 'agg_dscp')
        self.assertEqual(rollups.source(['dscp', 'service'], NOW - DAY, None, [])[1], 'agg_dscp_svc')
        self.assertEqual(rollups.source(['int_ip'], NOW - DAY, None, ['dscp'])[1], 'agg_dscp_svc')
        self.assertEqual(rollups.source(['in_if', 'out_if'], NOW - DAY, None, [])[1], 'agg_iface')      # not the QoS one
        self.assertEqual(rollups.source(['ext_port', 'proto', 'int_ip'], NOW - DAY, None, [])[1], 'agg_port_host')
        self.assertEqual(rollups.source(['ext_port', 'proto', 'ext_ip'], NOW - DAY, None, [])[1], 'agg_port_peer')
        self.assertEqual(rollups.source(['int_ip'], NOW - DAY, None, ['ext_port'])[1], 'agg_port_host')
        self.assertEqual(rollups.source(['ext_port'], NOW - DAY, None, [])[1], 'agg_ports')            # the small one first
        self.assertEqual(rollups.source(['ext_ip'], NOW - DAY, None, ['service'])[1], 'agg_ext')
        self.assertEqual(rollups.source(['in_if', 'out_if', 'out_ip'], NOW - DAY, None, ['country'])[1], 'agg_iface_ext')
        self.assertIsNone(rollups.source(['int_ip', 'ext_ip'], NOW - DAY, None, [], step=300)[1])  # hourly table
        # (1.17.0) Path analysis over a period: the conversations per hour carry the interfaces and the NAT address
        self.assertEqual(rollups.source(['in_if', 'out_if', 'int_ip', 'ext_ip', 'nat_ip'], NOW - DAY, None, [])[1], 'agg_conv')
        self.assertEqual(rollups.source(['in_if', 'out_if'], NOW - DAY, None, [])[1], 'agg_iface')      # still the small one

    def test_old_or_missing_state_means_records_only(self):
        rollups._cache.update(st={}, t=float('inf'))
        self.assertIsNone(rollups.source(['service'], NOW - DAY, None, [])[1])
        self.assertIsNone(rollups.ready_from())
        rollups._cache.update(st={'version': rollups.VERSION - 1, **{f'ready_from:{n}': 0 for n in rollups.ROLLUPS}}, t=float('inf'))
        self.assertIsNone(rollups.source(['service'], NOW - DAY, None, [])[1])

    def test_ready_from_of_all_is_the_latest(self):
        self.state(agg_traffic=0)
        self.assertEqual(rollups.ready_from('agg_traffic'), 0)
        self.assertEqual(rollups.ready_from(), (NOW // 3600 + 1) * 3600)


class Select(unittest.TestCase):
    def test_grouped_by_the_bucket_not_the_second_1170(self):
        """(1.17.0) ch() sends prefer_column_name_to_alias: `GROUP BY ts` would group the history's INSERT ... SELECT by
        each record's own second (every number right, the tables many times bigger)"""
        for name, r in rollups.ROLLUPS.items():
            bucket = f"toStartOfInterval(ts, toIntervalSecond({r['bucket']}))"
            group = rollups._select(r, '1').split(' GROUP BY ')[1]
            self.assertTrue(group.startswith(bucket + ', '), name)
            self.assertNotIn('ts', group[len(bucket):].split(', '), name)


class Fill(unittest.TestCase):
    """(1.17.0) the history is filled several tables at a time: every hour of every table exactly once, newest first,
    the progress of each table kept after each of its steps (no ClickHouse: ch() recorded)"""
    def run_fill(self, ready, oldest, stop=None):
        import re
        import threading
        calls, lock = [], threading.Lock()

        def ch(q, params=None, fmt=None, **kw):
            with lock:
                calls.append(q)
            if q.startswith('SELECT toUnixTimestamp(min(ts))'):
                return [{'t': oldest, 'n': 1}]
            if q.startswith('SELECT count()'):
                return [{'n': 0}]
            if q.startswith('INSERT INTO') and stop:
                stop.set()
            return []
        old = rollups.ch
        rollups.ch = ch
        try:
            res = rollups._fill(dict(ready), lambda *a: None, stop)
        finally:
            rollups.ch = old
        ins = [(m[1], int(m[2]), int(m[3])) for q in calls
               if (m := re.match(r'INSERT INTO (agg_\w+) SELECT .* ts >= toDateTime\((\d+)\) AND ts < toDateTime\((\d+)\)', q))]
        prog = [(m[1], int(m[2])) for q in calls if (m := re.match(r"INSERT INTO agg_state \(k, v\) VALUES \('ready_from:(\w+)', (\d+)\)", q))]
        return res, ins, prog

    def test_every_hour_of_every_table_once(self):
        end = NOW // 3600 * 3600
        ready = {n: end for n in rollups.ROLLUPS}
        ready['agg_geo'] = end - 3 * DAY // 2                  # one table further on already
        oldest = end - 2 * DAY - 1234
        res, ins, prog = self.run_fill(ready, oldest)
        self.assertTrue(res)
        first = oldest // DAY * DAY
        for name, at in ready.items():
            spans = sorted((b, e) for n, b, e in ins if n == name)
            self.assertEqual(spans[0][0], first, name)
            self.assertEqual(spans[-1][1], at, name)
            self.assertTrue(all(a[1] == b[0] for a, b in zip(spans, spans[1:])), name)     # no gap, no overlap
            steps = [b for n, b, e in ins if n == name]
            self.assertEqual(steps, sorted(steps, reverse=True), name)                    # newest first
            mine = [v for n, v in prog if n == name]
            self.assertEqual(mine[-1], 0, name)                                           # complete
            self.assertEqual(mine[:-1], steps, name)                                      # progress after each step

    def test_stop_keeps_what_was_done(self):
        import threading
        end = NOW // 3600 * 3600
        stop = threading.Event()
        res, ins, prog = self.run_fill({n: end for n in rollups.ROLLUPS}, end - 3 * DAY, stop)
        self.assertFalse(res)
        self.assertLessEqual(len(ins), rollups.FILL_WORKERS)          # each running table stops after its step
        self.assertEqual(sorted((n, b) for n, b, e in ins), sorted(prog))
        self.assertNotIn(0, [v for n, v in prog])

    def test_since_fills_only_the_hole_2_0_0(self):
        end = NOW // 3600 * 3600
        ready = {n: end for n in rollups.ROLLUPS}
        since = {n: end - DAY - 2 * 3600 for n in rollups.ROLLUPS}         # the tables hold what is before it
        old = rollups._fill
        rollups._fill = lambda r, log, stop, s=None: old(r, log, stop, since)
        try:
            res, ins, prog = self.run_fill(ready, end - 20 * DAY)
        finally:
            rollups._fill = old
        self.assertTrue(res)
        for name in ready:
            spans = sorted((b, e) for n, b, e in ins if n == name)
            self.assertEqual((spans[0][0], spans[-1][1]), (since[name], end), name)
            self.assertTrue(all(a[1] == b[0] for a, b in zip(spans, spans[1:])), name)
            self.assertEqual([v for n, v in prog if n == name][-1], 0, name)


class Relink(unittest.TestCase):
    """(2.0.0) the upgrade renamed the database flowtrack to flowsphera: the views still read flowtrack.flows and
    write flowtrack.agg_* — nothing reached the rollups any more. ensure() makes them again and sums the hole."""
    def run_relink(self, mv_db, deps, ready=0):
        calls = []
        st = {'version': rollups.VERSION}
        for name, r in rollups.ROLLUPS.items():
            st.update({f'cutover:{name}': 1791000000, f'ready_from:{name}': ready, f'def:{name}': r.get('v', 1)})

        def ch(q, params=None, fmt=None, **kw):
            calls.append(q)
            if q.startswith('SELECT currentDatabase()'):
                return [{'d': 'flowsphera'}]
            if q.startswith('SELECT dependencies_table'):
                return [{'d': deps}]
            if q.startswith('SELECT name, extract('):
                return [{'name': f'{n}_mv', 't': f'{mv_db}.{n}'} for n in rollups.ROLLUPS]
            if q.startswith('SELECT toUnixTimestamp(max(ts))'):
                return [{'t': NOW - 7 * 3600, 'n': 5}]
            if q.startswith('SELECT k, argMax'):
                return [{'k': k, 'v': v} for k, v in st.items()]
            if m := re.match(r"INSERT INTO agg_state \(k, v\) VALUES \('(.+)', (-?\d+)\)", q):
                st[m[1]] = int(m[2])
            return []
        import re
        old = rollups.ch
        rollups.ch, rollups.time = ch, type('Clock', (), {'time': staticmethod(lambda: NOW), 'strftime': staticmethod(time.strftime), 'gmtime': staticmethod(time.gmtime)})
        try:
            rollups.ensure(lambda *a: None)
        finally:
            rollups.ch, rollups.time = old, time
        return calls, st

    def test_views_of_the_old_database_made_again(self):
        calls, st = self.run_relink('flowtrack', [])
        for name, r in rollups.ROLLUPS.items():
            cut = (NOW // r['bucket'] + 1) * r['bucket']
            self.assertIn(f'DROP VIEW IF EXISTS {name}_mv', calls)
            since = (NOW - 7 * 3600) // r['bucket'] * r['bucket'] - rollups.LATE      # records late after the view stopped
            self.assertIn(f'ALTER TABLE {name} DELETE WHERE ts >= toDateTime({since})', calls)
            mv = next(q for q in calls if q.startswith(f'CREATE MATERIALIZED VIEW {name}_mv TO {name} AS'))
            self.assertIn(f'FROM flows WHERE ts >= toDateTime({cut})', mv)
            self.assertEqual((st[f'cutover:{name}'], st[f'ready_from:{name}'], st[f'since:{name}'], st[f'late:{name}']),
                             (cut, cut, since, 0))

    def test_working_views_left_alone(self):
        calls, st = self.run_relink('flowsphera', [f'{n}_mv' for n in rollups.ROLLUPS])
        self.assertFalse([q for q in calls if q.startswith(('DROP', 'CREATE MATERIALIZED', 'ALTER', 'TRUNCATE'))])

    def test_history_still_filling_is_filled_again_whole(self):
        calls, st = self.run_relink('flowtrack', [], ready=1791003600)
        self.assertIn('TRUNCATE TABLE agg_traffic', calls)
        self.assertEqual(st['since:agg_traffic'], 0)


if __name__ == '__main__':
    unittest.main()
