"""(1.13.0) Capacity planning: the trend ignores the weekly rhythm and single odd days, the forecast says when a link
gets full and refuses to reach beyond twice its history."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import capacity  # noqa: E402

M = 1e6


def week_shape(n, base, growth_per_day=0.0, weekend=0.4):
    """n days of a daily 95th percentile: workdays at `base` (+ growth), Saturday and Sunday at `weekend` of it."""
    return [(x, (base + growth_per_day * x) * (weekend if x % 7 in (5, 6) else 1.0)) for x in range(n)]


class Trend(unittest.TestCase):
    def test_too_little_history(self):
        self.assertIsNone(capacity.trend(week_shape(capacity.FORECAST_DAYS - 1, 50 * M)))
        self.assertIsNone(capacity.forecast(None, 100 * M))

    def test_weekly_rhythm_is_no_trend(self):
        # quiet weekends: a naive line through the last days would tilt; whole weeks apart it is flat
        tr = capacity.trend(week_shape(30, 60 * M)[2:])           # starts on a Wednesday, ends on a Friday
        self.assertAlmostEqual(tr['slope'], 0, delta=1)
        fc = capacity.forecast(tr, 100 * M)
        self.assertEqual(fc['direction'], 'stable')
        self.assertIsNone(fc['full_in'])
        # the busy level is the workdays', not the average with the weekends
        self.assertAlmostEqual(tr['busy'], 60 * M, delta=1 * M)

    def test_growth_and_dates(self):
        tr = capacity.trend(week_shape(56, 40 * M, 0.5 * M))       # +0.5 Mbit/s a day from 40, 8 weeks
        self.assertAlmostEqual(tr['slope'], 0.5 * M, delta=0.01 * M)
        fc = capacity.forecast(tr, 100 * M)
        self.assertEqual(fc['direction'], 'up')
        self.assertTrue(fc['clear'])
        # busy level on day 55 ≈ 67.5: 85 Mbit/s in ≈ 35 days, 100 in ≈ 65
        self.assertTrue(30 <= fc['full_in'] <= 40, fc)
        self.assertTrue(60 <= fc['over_in'] <= 70, fc)
        self.assertGreater(fc['growth_pct_month'], 15)

    def test_horizon_twice_the_history(self):
        tr = capacity.trend(week_shape(14, 20 * M, 0.1 * M))       # 14 days: no date further than 28 days
        fc = capacity.forecast(tr, 100 * M)
        self.assertEqual(fc['horizon'], 28)
        self.assertIsNone(fc['full_in'])

    def test_already_full_and_odd_day(self):
        pts = week_shape(28, 90 * M, weekend=1.0)
        pts[10] = (10, 5 * M)                                       # one quiet day (holiday) changes nothing
        tr = capacity.trend(pts)
        self.assertAlmostEqual(tr['slope'], 0, delta=0.01 * M)
        fc = capacity.forecast(tr, 100 * M)
        self.assertEqual(fc['full_in'], 0)
        self.assertIsNone(fc['over_in'])
        self.assertEqual(capacity.status(95, 90, fc), 'full')

    def test_declining_never_gets_a_date(self):
        fc = capacity.forecast(capacity.trend(week_shape(42, 80 * M, -0.5 * M)), 100 * M)
        self.assertEqual(fc['direction'], 'down')
        self.assertIsNone(fc['full_in'])

    def test_no_capacity(self):
        fc = capacity.forecast(capacity.trend(week_shape(28, 10 * M, 0.2 * M)), 0)
        self.assertEqual(fc['direction'], 'up')
        self.assertIsNone(fc['busy_pct'])
        self.assertEqual(capacity.status(None, None, fc), 'unknown')

    def test_status_order(self):
        self.assertEqual(capacity.status(50, 40, None), 'ok')
        self.assertEqual(capacity.status(90, 40, None), 'watch')
        self.assertEqual(capacity.status(80, 72, None), 'watch')
        self.assertEqual(capacity.status(99, 101, None), 'over')
        self.assertEqual(capacity.status(60, 50, {'full_in': 60, 'over_in': None}), 'soon')
        self.assertEqual(capacity.status(60, 50, {'full_in': 20, 'over_in': None}), 'full')


if __name__ == '__main__':
    unittest.main()
