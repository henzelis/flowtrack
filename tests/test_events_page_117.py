"""1.17.0: the Events page's numbers — events by priority and kind, how many began in each step (the chart), and the
list a part at a time (the newest first, of one priority / kind / text). Run: python -m unittest discover -s tests"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

TMP = tempfile.mkdtemp()
os.makedirs(TMP + '/cfg', exist_ok=True), os.makedirs(TMP + '/state', exist_ok=True)
open(TMP + '/cfg/exporters.json', 'w').write('{}')
os.environ.update(FT_CONFIG_DIR=TMP + '/cfg', FT_STATE_DIR=TMP + '/state')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import api  # noqa: E402
import detect  # noqa: E402

T0 = 1792800000                     # 2026-10-23 00:00 UTC
utc = lambda t: __import__('datetime').datetime.fromtimestamp(t, __import__('datetime').timezone.utc).strftime('%Y-%m-%d %H:%M:%S')  # noqa: E731


def ev(kind, sev, first, last=None, src='203.0.113.5', text=''):
    return {'kind': kind, 'sev': sev, 'title': kind, 'text': text or f'{kind} from {src}', 'first': utc(first), 'last': utc(last or first),
            'when': utc(last or first), 'src': src, 'dst': '', 'ip': src, 'stored': True}


class Stats(unittest.TestCase):
    def test_counts_by_priority_kind_and_step(self):
        out = [ev('port_scan', 'warn', T0 + 600), ev('port_scan', 'warn', T0 + 700), ev('brute_force', 'crit', T0 + 4000),
               ev('probes', 'info', T0 - 3600, T0 + 100)]                       # began before the period
        st = detect.stats(out, T0, T0 + 86400, 'UTC')
        self.assertEqual((st['total'], st['sev'], st['before']), (4, {'crit': 1, 'warn': 2, 'info': 1}, 1))
        self.assertEqual({k: v['n'] for k, v in st['kinds'].items()}, {'port_scan': 2, 'brute_force': 1, 'probes': 1})
        s = st['series']
        self.assertEqual((s['step'], s['from']), (1800, T0))            # 24 h: 48 steps of half an hour
        self.assertEqual(s['rows'], [[T0, 'port_scan', 2], [T0 + 3600, 'brute_force', 1]])
        self.assertEqual(sum(r[2] for r in s['rows']) + st['before'], st['total'])

    def test_a_kind_takes_its_highest_priority_and_live_ones_go_to_the_end(self):
        out = [ev('burst', 'info', T0 + 60), ev('burst', 'crit', T0 + 120),
               {'kind': 'export_loss', 'sev': 'warn', 'title': 'Lost packets', 'text': '', 'when': 'last hour'}]
        st = detect.stats(out, T0, T0 + 3600, 'UTC')
        self.assertEqual(st['kinds']['burst']['sev'], 'crit')
        self.assertEqual(st['kinds']['export_loss']['title'], 'Lost packets')
        self.assertIn([T0 + 3300, 'export_loss', 1], st['series']['rows'])  # 1 h: steps of 5 minutes, the last one

    def test_long_periods_count_whole_local_days(self):
        st = detect.stats([ev('ddos', 'crit', T0 + 86400 * 3 + 3600)], T0, T0 + 30 * 86400, 'Europe/Kyiv')
        s = st['series']
        self.assertEqual(s['step'], 86400)
        b = s['rows'][0][0]
        self.assertEqual((b + 2 * 3600) % 86400, 0)                     # local midnight (Kyiv is UTC+2 from 25 October)


class Paged(unittest.TestCase):
    def call(self, events, **q):
        with mock.patch.object(api, '_alerts_now', return_value=[]), mock.patch.object(detect, 'recent', return_value=events), \
                mock.patch.object(api, 'period', return_value=(T0, T0 + 86400, True)):
            return api.api_alerts({'f': ['[]'], 'tz': ['UTC'], **{k: [str(v)] for k, v in q.items()}})

    def events(self):
        return [ev('port_scan', 'warn', T0 + i * 600, src=f'203.0.113.{i}') for i in range(40)] + [ev('brute_force', 'crit', T0 + 100, src='198.51.100.7')]

    def test_without_limit_every_event_as_before(self):
        r = self.call(self.events())
        self.assertEqual(len(r['alerts']), 41)
        self.assertEqual(r['alerts'][0]['sev'], 'crit')                 # the old order: the priority first
        self.assertEqual(r['stats']['total'], 41)

    def test_the_newest_part_of_one_priority_kind_or_text(self):
        r = self.call(self.events(), limit=30)
        self.assertEqual((len(r['alerts']), r['matched'], r['stats']['total']), (30, 41, 41))
        self.assertEqual(r['alerts'][0]['src'], '203.0.113.39')         # the newest first
        r = self.call(self.events(), limit=30, offset=30)
        self.assertEqual((len(r['alerts']), r['offset']), (11, 30))
        r = self.call(self.events(), limit=30, sev='crit')
        self.assertEqual([a['src'] for a in r['alerts']], ['198.51.100.7'])
        self.assertEqual(r['stats']['total'], 41)                       # the cards and charts keep every event
        self.assertEqual(self.call(self.events(), limit=30, kind='port_scan')['matched'], 40)
        self.assertEqual(self.call(self.events(), limit=30, q='198.51.100')['matched'], 1)
        self.assertEqual(self.call(self.events(), limit=0)['alerts'], [])

    def test_bad_limit(self):
        with self.assertRaises(api.BadRequest):
            self.call(self.events(), limit='x')


if __name__ == '__main__':
    unittest.main()
