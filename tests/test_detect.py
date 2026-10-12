"""Detections (1.6): settings checks, the ignore list, event merging and texts — no database needed (the rules
themselves run against ClickHouse: flowtrack-verify detect_check.py). Run: python -m unittest discover -s tests"""
import os
import sys
import tempfile
import unittest

os.environ['FT_STATE_DIR'] = tempfile.mkdtemp(prefix='ft-detect-test-')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import detect as D  # noqa: E402


class Settings(unittest.TestCase):
    def setUp(self):
        for f in (D.CONFIG,):
            if os.path.exists(f):
                os.remove(f)

    def test_defaults_without_a_file(self):
        c = D.load_config()
        self.assertEqual(c['kinds']['brute_force']['sessions'], 30)
        self.assertEqual(c['kinds']['ddos']['sev'], 'crit')
        self.assertIn(22, c['sensitive'])
        self.assertEqual(c['public'], [80, 443, 8080])

    def test_validate_and_round_trip(self):
        c = D.validate({'kinds': {'brute_force': {'on': False, 'sev': 'crit', 'sessions': '40'}, 'nonsense': {'on': True}},
                        'ignore': ['203.0.113.7', '198.51.100.9/24', 'as64500', ' '], 'sensitive': '22, 2222 22',
                        'public': [443], 'roles': {'192.0.2.10:8743/6': 'public', '[2001:db8::1]:22/6': 'sensitive'}})
        self.assertEqual(c['kinds']['brute_force'], {'on': False, 'sev': 'crit', 'sessions': 40})
        self.assertNotIn('nonsense', c['kinds'])
        self.assertEqual(c['ignore'], ['198.51.100.0/24', '203.0.113.7', 'AS64500'])
        self.assertEqual(c['sensitive'], [22, 2222])
        D.save_config(c)
        self.assertEqual(D.load_config(), c)
        self.assertEqual(D.role_of(c, '192.0.2.10:8743/6', 8743), 'public')
        self.assertEqual(D.role_of(c, '192.0.2.10:2222/6', 2222), 'sensitive')
        self.assertEqual(D.role_of(c, '192.0.2.10:443/6', 443), 'public')
        self.assertEqual(D.role_of(c, '192.0.2.10:5000/6', 5000), 'normal')

    def test_lists_and_own_list(self):
        c = D.validate({'lists': {'tor_exit': False, 'nonsense': True}, 'own_list': '203.0.113.9, 198.51.100.0/24'})
        self.assertFalse(c['lists']['tor_exit'])
        self.assertTrue(c['lists']['feodo'])
        self.assertNotIn('nonsense', c['lists'])
        self.assertEqual(c['own_list'], ['198.51.100.0/24', '203.0.113.9'])
        with self.assertRaises(ValueError):
            D.validate({'own_list': ['example.com']})
        D.save_config(c)
        self.assertEqual(D.load_config()['lists']['tor_exit'], False)

    def test_validate_refuses(self):
        for body in ({'kinds': {'brute_force': {'sessions': 1}}}, {'kinds': {'ddos': {'factor': 'x'}}},
                     {'ignore': ['example.com']}, {'sensitive': '22 70000'}, {'roles': {'nope': 'public'}},
                     {'roles': {'192.0.2.1:22/6': 'secret'}}):
            with self.assertRaises(ValueError, msg=body):
                D.validate(body)

    def test_add_ignore_keeps_the_rest(self):
        D.save_config(D.validate({'kinds': {'probes': {'on': False}}}))
        D.add_ignore('192.0.2.5')
        D.add_ignore('192.0.2.5')
        c = D.load_config()
        self.assertEqual(c['ignore'], ['192.0.2.5'])
        self.assertFalse(c['kinds']['probes']['on'])


class IgnoreList(unittest.TestCase):
    def test_match(self):
        ig = D.Ignore(['203.0.113.7', '10.0.0.0/8', '2001:db8::/32', 'AS64500'])
        self.assertIn(('203.0.113.7', 0), ig)
        self.assertIn(('10.1.2.3', 0), ig)
        self.assertIn(('2001:db8::5', None), ig)
        self.assertIn(('198.51.100.1', 64500), ig)
        self.assertNotIn(('198.51.100.1', 64501), ig)
        self.assertNotIn(('', 0), ig)
        self.assertNotIn(('not-an-ip', 0), ig)
        self.assertEqual(ig.params(), {'ign_ips': ['203.0.113.7'], 'ign_nets': ['10.0.0.0/8', '2001:db8::/32'], 'ign_asns': [64500]})


class Events(unittest.TestCase):
    def test_endpoint(self):
        self.assertEqual(D.endpoint('192.0.2.1', 22, 6), '192.0.2.1:22/6')
        self.assertEqual(D.endpoint('2001:db8::1', 443, 17), '[2001:db8::1]:443/17')
        self.assertEqual(D._endpoint('[2001:db8::1]:443/17'), ('2001:db8::1', 443, 17))
        self.assertIsNone(D._endpoint('192.0.2.1:22'))

    def test_merge_info(self):
        m = D.merge_info({'ports': [22, 23], 'sessions': 5, 'sources': ['a'], 'bps': 10.0, 'srcs': 3, 'country': 'CN'},
                         {'ports': [23, 80], 'sessions': 7, 'sources': ['b', 'a'], 'bps': 4.0, 'srcs': 9, 'country': 'HK'})
        self.assertEqual(m['ports'], [22, 23, 80])
        self.assertEqual(m['sessions'], 12)
        self.assertEqual(m['sources'], ['a', 'b'])
        self.assertEqual((m['bps'], m['srcs'], m['country']), (10.0, 9, 'HK'))

    def test_ts_is_utc(self):
        self.assertEqual(D._ts('2026-10-12 00:00:00'), 1791763200)
        self.assertEqual(D._ts(5), 5)

    def test_every_kind_has_a_text(self):
        info = {'ports': [22, 80], 'targets': ['192.0.2.9'], 'sessions': 40, 'sources': ['198.51.100.1'], 'countries': ['CN'],
                'how': 'ports', 'per_minute': 3000, 'srcs': 900, 'minutes': 4, 'baseline': 12.5, 'bps': 3e8, 'country': 'CN', 'org': 'X'}
        info['lists'] = ['feodo', 'cins']
        info['hosts'] = ['10.0.0.5', '10.0.0.6']
        info['srcmap'] = {'5.6.7.8': ['cins'], '5.6.7.9': ['cins', 'spamhaus_drop']}
        for kind in ('port_scan', 'brute_force', 'probes', 'heavy_client', 'ddos', 'inside_scan', 'lateral_scan',
                     'malware_contact', 'listed_contact', 'listed_inbound'):
            for how in ('ports', 'hosts', 'services', 'sessions', 'volume', 'reflection'):
                r = {'kind': kind, 'info': dict(info, how=how), 'src': '198.51.100.1', 'dst': '192.0.2.9', 'port': 22, 'hits': 2,
                     'value': 40, 'exporter': '192.0.2.254'}
                title, text = D.describe(r)
                self.assertTrue(title and text and '{' not in text, (kind, how, text))
        self.assertEqual(set(D.NAMES), set(D.KINDS))
        r = {'kind': 'brute_force', 'info': {'sessions': 40, 'lists': ['cins']}, 'src': '5.6.7.8', 'dst': '192.0.2.9', 'port': 22, 'hits': 1, 'value': 40, 'exporter': ''}
        self.assertIn('CINS Army', D.describe(r)[1])
        r = {'kind': 'listed_inbound', 'info': info, 'src': '', 'dst': '', 'port': 0, 'hits': 3, 'value': 2, 'exporter': ''}
        self.assertIn('CINS Army 2', D.describe(r)[1])

    def test_merge_reputation_info(self):
        m = D.merge_info({'srcmap': {'a': ['x']}, 'hosts': ['h1'], 'sent': 5}, {'srcmap': {'a': ['y'], 'b': ['x']}, 'hosts': ['h2', 'h1'], 'sent': 7})
        self.assertEqual(m['srcmap'], {'a': ['x', 'y'], 'b': ['x']})
        self.assertEqual((m['hosts'], m['sent']), (['h1', 'h2'], 12))


if __name__ == '__main__':
    unittest.main()
