"""The web API's 60-second cache: only long, finished periods; never live windows; a POST clears it."""
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
import api  # noqa: E402


class Cache(unittest.TestCase):
    def setUp(self):
        self.c = api.Cache()

    def test_long_ranges_are_cached(self):
        for path, q in (('/api/top', {'range': ['24h'], 'dim': ['service']}), ('/api/summary', {'range': ['6h']}),
                        ('/api/geo', {'range': ['7d'], 'live': ['0']}), ('/api/series', {})):        # no range = 24h
            self.c.put(path, q, b'x')
            self.assertEqual(self.c.get(path, q), b'x', (path, q))

    def test_short_live_running_or_other_paths_are_not(self):
        now = int(time.time())
        for path, q in (('/api/top', {'range': ['1h']}), ('/api/geo', {'range': ['24h'], 'live': ['1']}),
                        ('/api/river', {'range': ['24h']}),                                     # live unless live=0
                        ('/api/top', {'from': [str(now - 86400)], 'to': [str(now)]}),            # still running
                        ('/api/flows', {'range': ['24h']}), ('/api/alerts', {}), ('/api/devices', {}), ('/api/meta', {}),
                        ('/api/top', {'from': ['x'], 'to': ['y']})):
            self.c.put(path, q, b'x')
            self.assertIsNone(self.c.get(path, q), (path, q))

    def test_finished_custom_period_and_parameters_matter(self):
        now = int(time.time())
        q = {'from': [str(now - 7200)], 'to': [str(now - 3600)], 'dim': ['l7']}
        self.c.put('/api/top', q, b'a')
        self.assertEqual(self.c.get('/api/top', dict(reversed(list(q.items())))), b'a')        # order does not matter
        self.assertIsNone(self.c.get('/api/top', dict(q, dim=['service'])))
        self.assertIsNone(self.c.get('/api/top', dict(q, f=['[{"k":"l7","v":"DNS"}]'])))

    def test_expires_and_clears(self):
        q = {'range': ['24h']}
        self.c.put('/api/top', q, b'x')
        self.c.items[self.c.key('/api/top', q)] = (time.time() - api.Cache.TTL - 1, b'x')
        self.assertIsNone(self.c.get('/api/top', q))
        self.c.put('/api/top', q, b'y')
        self.c.clear()
        self.assertIsNone(self.c.get('/api/top', q))

    def test_bounded(self):
        for i in range(api.Cache.SIZE * 2):
            self.c.put('/api/top', {'range': ['24h'], 'limit': [str(i)]}, b'x')
        self.assertLessEqual(len(self.c.items), api.Cache.SIZE)


if __name__ == '__main__':
    unittest.main()
