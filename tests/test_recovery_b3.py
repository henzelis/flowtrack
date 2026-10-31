"""(2.0.0 build 3) the database after an unclean stop: ClickHouse sets broken parts aside however many there are,
recovery.py sums the rollups again and stores an event that says what happened (the Optiplex, 2026-10-30: 106 broken
parts of flows kept the table offline for 18 hours)."""
import os
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = os.path.join(os.path.dirname(__file__), '..')
sys.path.insert(0, ROOT)

import detect  # noqa: E402
import recovery  # noqa: E402
import rollups  # noqa: E402
from common import set_lang  # noqa: E402

DAY = 1793318400            # 2026-10-30 00:00 UTC
STOP = DAY + 13 * 3600 + 540
START = DAY + 14 * 3600 + 2040


def part(table, name, level=0, size=0, pid='20261030'):
    return {'table': table, 'partition_id': pid, 'name': name, 'level': level, 'bytes': size, 't': START}


class Summary(unittest.TestCase):
    def test_lost_records_sum_every_rollup_again_from_their_day(self):
        s = recovery.summary([part('flows', '20261030_1767308_1767308_0'), part('flows', '20261030_1765026_1767308_1297', 1297),
                              part('agg_conv', '20261029_10_900_80', 80, pid='20261029')], START, STOP)
        self.assertEqual(s['tables'], {'flows': 2, 'agg_conv': 1})
        self.assertEqual((s['parts'], s['inserts']), (3, 1))
        self.assertEqual(set(s['resum']), set(rollups.ROLLUPS))
        self.assertEqual(s['resum']['agg_traffic'], DAY)              # the day of the lost parts of flows
        self.assertEqual(s['resum']['agg_conv'], DAY - 86400)         # its own lost part was of the day before
        self.assertEqual(s['since'], DAY - 86400)

    def test_a_rollup_alone_is_summed_again_alone(self):
        s = recovery.summary([part('agg_geo', '20261030_5_9_2', 2), part('exporter_stats', 'x_1_1_0')], START, STOP)
        self.assertEqual(set(s['resum']), {'agg_geo'})
        self.assertEqual(s['inserts'], 0)

    def test_nothing_to_sum_again(self):
        self.assertEqual(recovery.summary([part('events', 'all_1_1_0', pid='all')], START, STOP)['resum'], {})

    def test_other_partitions_reach_back_late_before_the_stop(self):
        s = recovery.summary([part('agg_host', 'all_1_1_0', pid='all')], START, STOP)
        self.assertEqual(s['resum']['agg_host'], STOP - rollups.LATE)


class Check(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.old = (recovery.STATE, recovery.ch, recovery.rollups.remake, recovery.rollups._get_state, recovery.detect.store,
                    recovery.detect.load_config, recovery.notify.Notifier)
        recovery.STATE = os.path.join(self.dir, 'recovery.json')
        self.parts, self.since, self.remade, self.stored, self.pushed = [], [], [], [], []

        def ch(q, params=None, fmt=None, **kw):
            if 'uptime()' in q:
                return [{'t': START}]
            if 'system.detached_parts' in q:
                self.since.append(params['s'])
                return list(self.parts)
            if 'max(ts)' in q:
                return [{'t': STOP}]
            return []
        recovery.ch = ch
        recovery.rollups.remake = lambda since_of, log, why: self.remade.append(since_of)
        recovery.rollups._get_state = lambda: {f'cutover:{n}': 1 for n in rollups.ROLLUPS}

        def store(hits, t0, t1, new=None):
            self.stored.append((hits, t0))
            new += [dict(h, first_seen=t0, hits=1) for h in hits]
        recovery.detect.store = store
        recovery.detect.load_config = detect.defaults
        test = self

        class Notifier:
            def __init__(self, log):
                pass

            def push(self, events, kinds, t1):
                test.pushed.append(events)
        recovery.notify.Notifier = Notifier

    def tearDown(self):
        (recovery.STATE, recovery.ch, recovery.rollups.remake, recovery.rollups._get_state, recovery.detect.store,
         recovery.detect.load_config, recovery.notify.Notifier) = self.old

    def test_broken_parts_sum_again_store_and_notify_once(self):
        self.parts = [part('flows', '20261030_1767308_1767308_0')]
        r = recovery.Recovery(lambda *a: None)
        s = r.check()
        self.assertEqual(self.since, [START - 60])                   # the first look: only the parts of this start
        self.assertEqual(set(self.remade[0]), set(rollups.ROLLUPS))
        hits, t0 = self.stored[0]
        self.assertEqual((hits[0]['kind'], hits[0]['key'], t0), ('db_recovered', str(START), START))
        self.assertEqual((hits[0]['info']['stopped'], hits[0]['info']['inserts']), (STOP, 1))
        self.assertEqual(self.pushed[0][0]['kind'], 'db_recovered')
        self.assertEqual(s['parts'], 1)
        self.assertIsNone(r.check())                                   # the same start of ClickHouse: looked at
        self.assertEqual(len(self.stored), 1)

    def test_a_clean_start_says_nothing(self):
        self.assertIsNone(recovery.Recovery(lambda *a: None).check())
        self.assertEqual((self.stored, self.remade, self.pushed), ([], [], []))

    def test_switched_off_kind_is_stored_not_sent(self):
        self.parts = [part('agg_geo', '20261030_5_9_2', 2)]
        recovery.detect.load_config = lambda: {**detect.defaults(), 'kinds': {**detect.defaults()['kinds'], 'db_recovered': {'on': False, 'sev': 'warn'}}}
        recovery.Recovery(lambda *a: None).check()
        self.assertEqual((len(self.stored), self.pushed), (1, []))


class Text(unittest.TestCase):
    def test_cause_and_consequences(self):
        set_lang('en')
        info = recovery.summary([part('flows', '20261030_1767308_1767308_0'), part('agg_conv', 'a_1_1_3', 3)], START, STOP)
        title, text = detect.describe({'kind': 'db_recovered', 'port': 0, 'dst': '', 'src': '', 'hits': 1, 'info': info})
        self.assertEqual(title, 'Database recovered after an unclean stop')
        self.assertIn('power cut', text)
        self.assertIn('flows (1), agg_conv (1)', text)
        self.assertIn('are missing', text)
        self.assertIn('from 2026-10-30 13:09 UTC to 2026-10-30 14:34 UTC (1 hour)', text)
        self.assertIn('summed again from the records since 2026-10-30 00:00 UTC', text)
        self.assertIn('UPS', text)

    def test_nothing_lost_says_so(self):
        set_lang('en')
        info = recovery.summary([part('agg_geo', '20261030_5_9_2', 2)], START, STOP)
        _, text = detect.describe({'kind': 'db_recovered', 'port': 0, 'dst': '', 'src': '', 'hits': 1, 'info': info})
        self.assertIn('complete up to the stop', text)

    def test_ukrainian(self):
        set_lang('uk')
        try:
            info = recovery.summary([part('flows', 'f_1_1_0')], START, STOP)
            title, text = detect.describe({'kind': 'db_recovered', 'port': 0, 'dst': '', 'src': '', 'hits': 1, 'info': info})
        finally:
            set_lang('en')
        self.assertEqual(title, 'Базу даних відновлено після неакуратного вимкнення')
        self.assertIn('ДБЖ', text)
        self.assertIn('1 година', text)


class Cleanup(unittest.TestCase):
    def test_old_broken_parts_removed_quoted(self):
        calls, old = [], recovery.ch

        def ch(q, params=None, fmt=None, settings=None, **kw):
            calls.append((q, settings))
            return [{'table': 'flows', 'name': "20261001_1_1_0"}] if q.startswith('SELECT') else []
        recovery.ch = ch
        try:
            self.assertEqual(recovery.Recovery().cleanup(), 1)
        finally:
            recovery.ch = old
        self.assertIn("reason IN {r:Array(String)}", calls[0][0])
        self.assertEqual(calls[1], ("ALTER TABLE `flows` DROP DETACHED PART '20261001_1_1_0'", {'allow_drop_detached': 1}))


class Remake(unittest.TestCase):
    def test_since_aligned_and_whole_history_while_filling(self):
        calls, st, old = [], {'ready_from:agg_conv': 5}, (rollups.ch, rollups._get_state, rollups._set)
        rollups.ch = lambda q, *a, **kw: calls.append(q) or []
        rollups._get_state = lambda: st
        rollups._set = lambda k, v: st.__setitem__(k, v)
        try:
            rollups.remake({'agg_traffic': STOP, 'agg_conv': STOP}, lambda *a: None, {'agg_traffic': 'x', 'agg_conv': 'x'})
        finally:
            rollups.ch, rollups._get_state, rollups._set = old
        self.assertIn(f'ALTER TABLE agg_traffic DELETE WHERE ts >= toDateTime({STOP // 300 * 300})', calls)
        self.assertIn('TRUNCATE TABLE agg_conv', calls)
        self.assertEqual(st['since:agg_traffic'], STOP // 300 * 300)


class Config(unittest.TestCase):
    def test_clickhouse_writes_to_disk_and_sets_any_number_aside(self):
        mt = ET.parse(os.path.join(ROOT, 'deploy', 'clickhouse-flowsphera.xml')).getroot().find('merge_tree')
        self.assertIsNotNone(mt)
        self.assertEqual((mt.findtext('fsync_after_insert'), mt.findtext('fsync_part_directory')), ('1', '1'))
        self.assertGreaterEqual(int(mt.findtext('max_suspicious_broken_parts')), 100000)


if __name__ == '__main__':
    unittest.main()
