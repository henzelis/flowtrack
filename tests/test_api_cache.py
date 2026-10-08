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


class NetworkScope(unittest.TestCase):
    """Path analysis: no device filter, all traffic, a host filter matches the host at either end (internal records
    carry the sender in int_ip, so `ip` alone would drop the replies)."""

    def test_host_both_directions(self):
        flt = '[{"k":"ip","v":"10.20.0.5"},{"k":"device","v":"192.0.2.1"},{"k":"port","v":"22"}]'
        where, p, _, _ = api.scope(api.network_q({'range': ['1h'], 'f': [flt]}))
        self.assertIn('(int_ip = {f0:String} OR ext_ip = {f0:String})', where)
        self.assertEqual(p['f0'], '10.20.0.5')
        self.assertNotIn('exporter', where)
        self.assertNotIn('dir', where)
        self.assertIn('ext_port = {f1:UInt16}', where)

    def test_other_pages_keep_the_inside_host(self):
        where, _, _, _ = api.scope({'range': ['1h'], 'f': ['[{"k":"ip","v":"10.20.0.5"}]']})
        self.assertIn('int_ip = {f0:String}', where)
        self.assertNotIn('ext_ip', where)
