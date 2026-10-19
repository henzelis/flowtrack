"""(1.15.0) Usage by host: the periods (this month, last month, N whole local days) never older than the edition keeps,
and the period before is compared only when the data reach back to its start. Run: python -m unittest discover -s tests"""
import datetime
import json
import os
import sys
import tempfile
import unittest
from unittest import mock
from zoneinfo import ZoneInfo

TMP = tempfile.mkdtemp()
os.makedirs(TMP + '/cfg', exist_ok=True), os.makedirs(TMP + '/state', exist_ok=True)
open(TMP + '/cfg/exporters.json', 'w').write('{}')
os.environ.update(FT_CONFIG_DIR=TMP + '/cfg', FT_STATE_DIR=TMP + '/state')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import api  # noqa: E402

KYIV = ZoneInfo('Europe/Kyiv')
NOW = datetime.datetime(2026, 10, 19, 14, 30, tzinfo=KYIV)


class FrozenDT(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW.astimezone(tz)


def period(per, days=30):
    with mock.patch('datetime.datetime', FrozenDT), mock.patch.object(api, 'view_days', lambda: days), \
            mock.patch('time.time', lambda: NOW.timestamp()):
        return api._usage_period({'period': [per]}, 'Europe/Kyiv')


class Periods(unittest.TestCase):
    def test_this_month(self):
        t0, t1, per, _ = period('month')
        self.assertEqual(datetime.datetime.fromtimestamp(t0, KYIV), datetime.datetime(2026, 10, 1, tzinfo=KYIV))
        self.assertEqual(t1, int(NOW.timestamp()))

    def test_last_month_is_whole(self):
        t0, t1, _, _ = period('prev_month', days=365)
        self.assertEqual((datetime.datetime.fromtimestamp(t0, KYIV), datetime.datetime.fromtimestamp(t1, KYIV)),
                         (datetime.datetime(2026, 9, 1, tzinfo=KYIV), datetime.datetime(2026, 10, 1, tzinfo=KYIV)))

    def test_whole_days(self):
        t0, _, _, _ = period('7')
        self.assertEqual(datetime.datetime.fromtimestamp(t0, KYIV), datetime.datetime(2026, 10, 13, tzinfo=KYIV))

    def test_never_older_than_the_edition(self):
        t0, _, _, floor = period('365', days=30)
        self.assertEqual(t0, floor)
        self.assertEqual(floor, int(NOW.timestamp()) - 30 * 86400)

    def test_bad(self):
        with self.assertRaises(api.BadRequest):
            period('42')


class Compare(unittest.TestCase):
    """api_usage with the database faked: the totals of the period before are asked for only when the data reach back."""
    def run_usage(self, oldest):
        asked = []

        def ch(sql, params=None, **kw):
            asked.append(sql)
            if 'min(ts)' in sql:
                return [{'t': oldest}]
            if 'GROUP BY k' in sql:
                return [{'k': '10.0.0.5', 'up': 10, 'dn': 90, 'days': 3}]
            if 'GROUP BY t' in sql:
                return []
            return [{'up': 10, 'dn': 90, 'hosts': 1}]
        with mock.patch.object(api, 'ch', ch), mock.patch('datetime.datetime', FrozenDT), mock.patch('time.time', lambda: NOW.timestamp()), \
                mock.patch.object(api.NAMES, 'get', lambda ip, lookup=True: ''):
            return api.api_usage({'period': ['7'], 'tz': ['Europe/Kyiv'], 'f': [json.dumps([])]}), asked

    def test_new_installation_has_nothing_to_compare(self):
        d, _ = self.run_usage(int(NOW.timestamp()) - 3 * 86400)      # data since 3 days
        self.assertIsNone(d['prev'])
        self.assertNotIn('prev_up', d['hosts'][0])

    def test_with_history(self):
        d, _ = self.run_usage(int(NOW.timestamp()) - 20 * 86400)
        self.assertEqual(d['prev'], {'up': 10, 'dn': 90, 'hosts': 1})
        self.assertIn('prev_up', d['hosts'][0])


if __name__ == '__main__':
    unittest.main()
