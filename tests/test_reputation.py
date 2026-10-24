"""IP reputation (1.6.1): list parsing, the merged lookup table, downloads that fail keep the old copy — no network
or database needed. Run: python -m unittest discover -s tests"""
import os
import sys
import tempfile
import unittest

os.environ['FT_STATE_DIR'] = tempfile.mkdtemp(prefix='ft-rep-test-')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import reputation as R  # noqa: E402


class Parsers(unittest.TestCase):
    def test_formats(self):
        self.assertEqual(list(R._lines('# c\n; x\n5.6.7.8\n\n9.9.9.0/24 ; SBL1\n')), ['5.6.7.8', '9.9.9.0/24'])
        self.assertEqual(list(R._drop('{"cidr":"5.6.0.0/16","sblid":"SBL1"}\n{"type":"metadata"}\nnot json\n')), ['5.6.0.0/16'])
        tf = {'query_status': 'ok', 'data': [{'ioc': '5.6.7.8:36511', 'ioc_type': 'ip:port'}, {'ioc': '[2a00::1]:443', 'ioc_type': 'ip:port'},
                                             {'ioc': 'evil.example', 'ioc_type': 'domain'}]}
        self.assertEqual(list(R._threatfox_api(__import__('json').dumps(tf))), ['5.6.7.8', '2a00::1'])     # (1.16.2) the API
        with self.assertRaisesRegex(ValueError, 'the key was refused'):
            list(R._threatfox_api('{"query_status": "unknown_auth_key"}'))
        self.assertEqual(list(R._dshield('Start\tEnd\tNetblock\n5.6.7.0\t5.6.7.255\t24\t345\n#x\n')), ['5.6.7.0/24'])

    def test_special_ranges_never_listed(self):
        nets = R.networks(['10.0.0.0/8', '192.168.1.1', '127.0.0.1', '0.0.0.0/0', '224.0.0.1', 'fe80::1', 'junk', '5.6.7.8', '2a00::/16'])
        self.assertEqual([str(n) for n in nets], ['5.6.7.8/32', '2a00::/16'])


class Lookup(unittest.TestCase):
    def setUp(self):
        os.makedirs(R.DIR, exist_ok=True)
        for name, body in (('spamhaus_drop', '5.6.0.0/16\n2a00::/16\n'), ('cins', '5.6.7.8\n5.6.7.9\n'),
                           ('feodo', '5.6.7.8\n'), ('tor_exit', '7.7.7.7\n')):
            with open(os.path.join(R.DIR, name + '.txt'), 'w') as f:
                f.write(body)

    def test_nested_and_overlapping(self):
        ix = R.Index(['spamhaus_drop', 'cins', 'feodo'], ['8.8.4.0/24'])
        self.assertEqual(ix.lookup('5.6.7.8'), {'spamhaus_drop', 'cins', 'feodo'})
        self.assertEqual(ix.lookup('5.6.7.9'), {'spamhaus_drop', 'cins'})
        self.assertEqual(ix.lookup('5.6.7.10'), {'spamhaus_drop'})
        self.assertEqual(ix.lookup('5.6.0.0'), {'spamhaus_drop'})
        self.assertEqual(ix.lookup('5.6.255.255'), {'spamhaus_drop'})
        self.assertEqual(ix.lookup('5.7.0.0'), frozenset())
        self.assertEqual(ix.lookup('5.5.255.255'), frozenset())
        self.assertEqual(ix.lookup('2a00:1450::1'), {'spamhaus_drop'})
        self.assertEqual(ix.lookup('8.8.4.4'), {'custom'})
        self.assertEqual(ix.lookup('7.7.7.7'), frozenset())          # tor_exit not enabled
        self.assertEqual(ix.lookup('not an ip'), frozenset())
        self.assertEqual(ix.size, 6)

    def test_rebuild_only_on_change(self):
        ix = R.Index(['cins'])
        self.assertFalse(ix.build(['cins'], []))
        self.assertTrue(ix.build(['cins', 'tor_exit'], []))
        self.assertEqual(ix.lookup('7.7.7.7'), {'tor_exit'})

    def test_segments_agree_with_brute_force(self):
        import random
        rnd = random.Random(3)
        ranges = []
        for i in range(300):
            s = rnd.randrange(0, 5000)
            ranges.append((s, s + rnd.choice((0, 0, 3, 50, 700)), f'l{i % 7}'))
        starts, ends, names = R._segments(ranges)
        self.assertTrue(all(a <= b for a, b in zip(starts, ends)) and all(e < s for e, s in zip(ends, starts[1:])))
        for x in range(0, 6000, 7):
            want = {n for s, e, n in ranges if s <= x <= e}
            import bisect
            i = bisect.bisect_right(starts, x) - 1
            got = set(names[i]) if i >= 0 and x <= ends[i] else set()
            self.assertEqual(got, want, x)

    def test_category(self):
        self.assertEqual(R.category(['cins', 'feodo']), 'malware')
        self.assertEqual(R.category(['spamhaus_drop', 'tor_exit']), 'drop')
        self.assertEqual(R.category(['custom']), 'attack')
        self.assertEqual(R.category(['tor_exit']), 'anon')


class Update(unittest.TestCase):
    def test_failure_keeps_the_old_copy(self):
        os.makedirs(R.DIR, exist_ok=True)
        path = os.path.join(R.DIR, 'et_compromised.txt')
        with open(path, 'w') as f:
            f.write('5.6.7.8/32\n')
        saved = R._get
        try:
            R._get = lambda url, *a: '<html>rate limited</html>'
            self.assertEqual(R.update(['et_compromised'], log=lambda *_: None, now=1e9), [])
            self.assertEqual(open(path).read(), '5.6.7.8/32\n')
            st = R.meta()['et_compromised']
            self.assertFalse(st['ok'])
            self.assertIn('no addresses', st['error'])
            # not again before RETRY; then a good answer replaces the file
            R._get = lambda url, *a: '5.6.7.9\n10.0.0.1\n'
            self.assertEqual(R.update(['et_compromised'], log=lambda *_: None, now=1e9 + 60), [])
            self.assertEqual(R.update(['et_compromised'], log=lambda *_: None, now=1e9 + R.RETRY), ['et_compromised'])
            self.assertEqual(open(path).read(), '5.6.7.9/32\n')
            self.assertEqual(R.meta()['et_compromised']['count'], 1)
            # fresh: not downloaded again within a day
            self.assertEqual(R.update(['et_compromised'], log=lambda *_: None, now=1e9 + R.RETRY + 3600), [])
        finally:
            R._get = saved



class Keys(unittest.TestCase):
    """(1.16.2) a key per list: kept 0600 apart from the settings, sent as Auth-Key, a list that needs one says so"""
    def setUp(self):
        for f in (R.KEYS, R.META):
            if os.path.exists(f):
                os.remove(f)
        self.saved = R._get
        self.calls = []
        R._get = lambda url, key=None, body=None: self.calls.append((url, key, body)) or '{"query_status": "ok", "data": [{"ioc": "5.6.7.8:80", "ioc_type": "ip:port"}]}'

    def tearDown(self):
        R._get = self.saved

    def test_needs_a_key_then_downloads_with_it(self):
        self.assertEqual(R.update(['threatfox'], log=lambda *a: None, now=1792400000), [])
        self.assertEqual(self.calls, [])                                      # nothing asked without the key
        self.assertEqual(R.meta()['threatfox']['error'], R.NO_KEY)
        R.save_keys({'threatfox': 'k123'})
        self.assertEqual(os.stat(R.KEYS).st_mode & 0o777, 0o600)
        self.assertEqual(R.update(['threatfox'], log=lambda *a: None, now=1792400060), ['threatfox'])   # at once, not in an hour
        self.assertEqual(self.calls[0][1:], ('k123', R.AUTH['threatfox']['body']))
        self.assertEqual(R.meta()['threatfox']['count'], 1)

    def test_any_list_may_have_a_key_and_lose_it(self):
        R.save_keys({'cins': 'abc', 'nonsense': 'x'})
        self.assertEqual(R.load_keys(), {'cins': 'abc'})
        R.update(['cins'], log=lambda *a: None, now=1792400000)
        self.assertEqual(self.calls[0][1:], ('abc', None))                  # a plain download with the Auth-Key header
        R.save_keys({'cins': ''})
        self.assertEqual(R.load_keys(), {})
        with self.assertRaises(ValueError):
            R.save_keys({'cins': 'two words'})

    def test_the_browser_never_gets_a_key(self):
        from unittest import mock
        import api
        with mock.patch.object(api.detect, 'services', lambda cfg: []):
            api.post_events_config({'list_keys': {'threatfox': 'secret-1'}})
            out = api.get_events_config()
            api.post_events_config({'list_keys': {'threatfox': ''}})          # an empty field keeps it
            kept = R.load_keys()
            api.post_events_config({'clear_keys': ['threatfox']})
        tf = next(x for x in out['lists'] if x['name'] == 'threatfox')
        self.assertEqual((tf['key_set'], tf['key_need'], tf['key_link']), (True, True, 'https://auth.abuse.ch/'))
        self.assertNotIn('secret-1', __import__('json').dumps(out))
        self.assertEqual(kept, {'threatfox': 'secret-1'})
        self.assertEqual(R.load_keys(), {})

    def test_refused_key_said_plainly(self):
        import urllib.error
        from unittest import mock
        R._get = self.saved
        err = urllib.error.HTTPError('u', 401, 'Unauthorized', {}, None)
        with mock.patch('urllib.request.urlopen', side_effect=err):
            with self.assertRaisesRegex(ValueError, 'refused'):
                R._get('https://x', 'bad')


if __name__ == '__main__':
    unittest.main()
