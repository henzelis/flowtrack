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


class TopoStructure(unittest.TestCase):
    """Path analysis (1.8.2): a page never waits for the neighbours once there are some; outdated ones are shown while
    new ones are worked out in the background."""
    def setUp(self):
        self.calls, self.orig = [], api.topology.query
        def slow(ch, where, p, known):
            self.calls.append(time.time()); time.sleep(.5)
            return ['near%d' % len(self.calls)], [], {'1.2.3.4'}, []
        api.topology.query = slow
        api._topo.update(key=None, t=0, data=None)

    def tearDown(self):
        api.topology.query = self.orig
        for _ in range(50):                 # let a background build finish
            if not api._topo_bg.is_set():
                break
            time.sleep(.05)

    def test_first_is_waited_for_then_outdated_is_served_at_once(self):
        self.assertEqual(api.topo_structure({})[0], ['near1'])
        self.assertEqual(api.topo_structure({})[0], ['near1'])         # fresh: no build
        self.assertEqual(len(self.calls), 1)
        api._topo['t'] = 0                                              # outdated (or SNMP data changed)
        t = time.time(); got = api.topo_structure({}); self.assertLess(time.time() - t, .2)
        self.assertEqual(got[0], ['near1'])                             # the old one, at once
        api.topo_structure({})                                          # a second page: no second build
        time.sleep(.8)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(api.topo_structure({})[0], ['near2'])

    def test_snmp_data_change_does_not_block(self):
        api.topo_structure({})
        api._topo['key'] = ('other',)
        t = time.time(); api.topo_structure({}); self.assertLess(time.time() - t, .2)
