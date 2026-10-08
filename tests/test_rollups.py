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

    def test_history_not_filled_yet_comes_from_the_records(self):
        rf = NOW // DAY * DAY                        # backfill got down to midnight
        self.state(agg_traffic=rf)
        sql, name = rollups.source(['service'], NOW - DAY, None, [])
        self.assertEqual(name, 'agg_traffic')
        self.assertIn(f'FROM agg_traffic WHERE ts >= toDateTime({rf})', sql)
        self.assertIn(f'ts >= toDateTime({NOW - DAY}) AND ts < toDateTime({rf})', sql)

    def test_columns_filters_and_steps_the_rollup_lacks(self):
        self.state(**{n: 0 for n in rollups.ROLLUPS})
        self.assertIsNone(rollups.source(['int_ip', 'ext_ip'], NOW - DAY, None, [])[1])    # conversations
        self.assertIsNone(rollups.source(['service'], NOW - DAY, None, ['ext_port', 'int_ip'])[1])
        self.assertEqual(rollups.source(['service'], NOW - DAY, None, ['ext_port'])[1], 'agg_ports')
        self.assertEqual(rollups.source(['int_ip'], NOW - DAY, None, [], step=300)[1], 'agg_host')
        self.assertIsNone(rollups.source(['ext_ip'], NOW - DAY, None, [], step=300)[1])     # hourly table, 5-min step
        self.assertEqual(rollups.source(['ext_ip'], NOW - DAY, None, [], step=3600)[1], 'agg_ext')
        self.assertIsNone(rollups.source(['service'], NOW - DAY, None, [], use=False)[1])

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


if __name__ == '__main__':
    unittest.main()
