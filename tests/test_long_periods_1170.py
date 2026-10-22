"""(1.17.0) a day or more: the period snaps to whole hours (every rollup answers it without raw edges) and a preset
keeps its own chart step; shorter periods are left as they are"""
import os
import sys
import tempfile
import time
import unittest

TMP = tempfile.mkdtemp()
os.makedirs(TMP + '/cfg')
os.makedirs(TMP + '/state')
open(TMP + '/cfg/exporters.json', 'w').write('{}')
os.environ.update(FT_CONFIG_DIR=TMP + '/cfg', FT_STATE_DIR=TMP + '/state')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import api  # noqa: E402
import rollups  # noqa: E402


class LongPeriods(unittest.TestCase):
    def test_preset_week_starts_on_the_hour_and_keeps_its_step(self):
        _, p, rng, step = api.scope({'range': ['7d']})
        self.assertEqual(p['t0'] % 3600, 0)
        self.assertLess(time.time() - 7 * 86400 - p['t0'], 3600)
        self.assertGreaterEqual(rng, 7 * 86400)
        self.assertEqual(step, 3600)
        self.assertEqual(api.scope({'range': ['24h']})[3], 300)

    def test_custom_days_snap_both_ends_short_ones_do_not(self):
        t0 = 1791446400 + 1234
        _, p, rng, _ = api.scope({'from': [str(t0)], 'to': [str(t0 + 2 * 86400)]})
        self.assertEqual((p['t0'], p['t1']), (1791446400, 1791446400 + 2 * 86400 + 3600))
        _, p, _, _ = api.scope({'from': [str(t0)], 'to': [str(t0 + 6 * 3600)]})
        self.assertEqual((p['t0'], p['t1']), (t0, t0 + 6 * 3600))
        _, p, rng, _ = api.scope({'range': ['6h']})
        self.assertEqual(rng, 6 * 3600)                     # a preset under a day: not snapped

    def test_a_period_ending_now_takes_the_current_bucket_from_the_rollup(self):
        rollups._cache.update(st={'version': rollups.VERSION, **{f'ready_from:{n}': 0 for n in rollups.ROLLUPS}}, t=float('inf'))
        now = int(time.time())
        sql, name = rollups.source(['ext_ip'], now // 3600 * 3600 - 86400, None, [])
        self.assertEqual(name, 'agg_ext')
        self.assertIn(f'ts < toDateTime({-(-now // 3600) * 3600})', sql.split('UNION ALL')[0])
        rollups._cache.update(st={}, t=0)


if __name__ == '__main__':
    unittest.main()
