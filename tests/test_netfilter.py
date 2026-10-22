"""1.8.6: filters by network — ip / dst / -ip / host with 172.16.0.0/24, events too. Run: python -m unittest discover -s tests"""
import json
import os
import sys
import tempfile
import unittest

TMP = tempfile.mkdtemp()
os.makedirs(TMP + '/cfg', exist_ok=True), os.makedirs(TMP + '/state', exist_ok=True)
open(TMP + '/cfg/exporters.json', 'w').write('{}')
os.environ.update(FT_CONFIG_DIR=TMP + '/cfg', FT_STATE_DIR=TMP + '/state')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import api  # noqa: E402


def scope(flt, t='all'):
    return api.scope({'f': [json.dumps(flt)], 'range': ['24h'], 't': [t]})


class Networks(unittest.TestCase):
    def test_inside_network_reads_the_host_view(self):
        where, p, _, _ = scope([{'k': 'ip', 'v': '172.16.0.77/24'}, {'k': 'ip', 'v': '10.0.0.5'}])
        self.assertEqual((p['hv'], p['hn0']), (['10.0.0.5'], '172.16.0.0/24'))       # normalised
        self.assertIn("isIPAddressInRange(int_ip, {hn0:String})", p['_flows'])
        self.assertIn('isIPAddressInRange(int_ip, {f0:String})', where)
        self.assertIn(' OR ', where)                                                  # either of them

    def test_internet_reads_int_ip_without_the_host_view(self):
        """(1.17.0) between inside and outside the host is int_ip of every record: no turned records, the rollups
        that hold int_ip answer"""
        where, p, _, _ = scope([{'k': 'ip', 'v': '172.16.0.77/24'}, {'k': 'ip', 'v': '10.0.0.5'}], t='internet')
        self.assertNotIn('hv', p)
        self.assertEqual(p['_flows'], 'flows')
        self.assertIn('int_ip', p['_fcols'])
        self.assertNotIn('ext_ip', p['_fcols'])
        self.assertIn('isIPAddressInRange(int_ip, {f0:String})', where)

    def test_outside_and_excluded(self):
        where, p, _, _ = scope([{'k': 'dst', 'v': '203.0.113.0/24'}, {'k': 'ip', 'v': '10.0.0.0/8', 'neg': True}])
        self.assertIn('isIPAddressInRange(ext_ip, {f0:String})', where)
        self.assertIn('NOT ((isIPAddressInRange(int_ip, {f1:String}) OR isIPAddressInRange(ext_ip, {f1:String})))', where)
        self.assertNotIn('hv', p)

    def test_ipv6_and_bad(self):
        _, p, _, _ = scope([{'k': 'ip', 'v': '2001:db8:1::5/64'}])
        self.assertEqual(p['hn0'], '2001:db8:1::/64')
        for bad in ('10.0.0.0/33', '10.0.0.300/24', 'x/8'):
            with self.assertRaises(api.BadRequest):
                scope([{'k': 'ip', 'v': bad}])

    def test_events(self):
        a = {'ip': '10.0.2.5', 'src': '10.0.2.5', 'dst': '8.8.8.8'}
        self.assertTrue(api._event_match(a, {'k': 'ip', 'v': '10.0.2.0/24'}))
        self.assertTrue(api._event_match(a, {'k': 'dst', 'v': '8.8.0.0/16'}))
        self.assertFalse(api._event_match(a, {'k': 'ip', 'v': '10.0.3.0/24'}))


if __name__ == '__main__':
    unittest.main()
