"""1.8.7: named networks — Settings table, net:NAME filter, traffic by network. Run: python -m unittest discover -s tests"""
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
import common  # noqa: E402


def scope(flt, t='internet'):
    return api.scope({'f': [json.dumps(flt)], 'range': ['24h'], 't': [t]})


def save(items):
    common._networks[0] = None          # the same second as the last write: read again
    out = api.post_networks({'items': items})
    common._networks[0] = None
    return out


class Networks(unittest.TestCase):
    def setUp(self):
        save([{'net': '10.0.0.0/8', 'name': 'All'}, {'net': '10.1.0.77/24', 'name': ' Office  A '},
              {'net': '172.16.5.0/24', 'name': 'Office A'}, {'net': '2001:db8::/48', 'name': 'V6'}])

    def test_saved_normalised_and_narrowest_first(self):
        self.assertEqual(api.api_networks({})['items'][1], {'net': '10.1.0.0/24', 'name': 'Office A'})
        self.assertEqual(common.load_networks()[0]['net'], '10.1.0.0/24')
        self.assertEqual(common.network_of('10.1.0.9'), 'Office A')         # the narrowest wins
        self.assertEqual(common.network_of('10.2.0.9'), 'All')
        self.assertEqual(common.network_of('2001:db8::5'), 'V6')
        self.assertEqual(common.network_of('8.8.8.8'), '')

    def test_bad_tables(self):
        for items in ([{'net': '10.0.0.0/33', 'name': 'x'}], [{'net': '10.0.0.0/8', 'name': ' '}],
                      [{'net': '10.0.0.0/8', 'name': 'a'}, {'net': '10.0.0.5/8', 'name': 'b'}], [{'net': '10.0.0.0/8', 'name': 'x' * 41}]):
            with self.assertRaises(api.BadRequest):
                api.post_networks({'items': items})

    def test_filter(self):
        where, p, _, _ = scope([{'k': 'net', 'v': 'office a'}])     # any case
        self.assertIn('multiIf(isIPAddressInRange(int_ip, {nc0:String}), {nn0:String}', where)
        self.assertEqual(p['f0'], 'Office A')
        self.assertNotIn('hv', p)                                 # inside <-> outside: the rollups
        _, p, _, _ = scope([{'k': 'net', 'v': 'Office A'}], t='internal')
        self.assertEqual(sorted(v for k, v in p.items() if k.startswith('hn')), ['10.1.0.0/24', '172.16.5.0/24'])
        where, p, _, _ = scope([{'k': 'net', 'v': 'All', 'neg': True}])
        self.assertIn('isIPAddressInRange(ext_ip, {nc0:String})', where)
        self.assertIn('NOT (', where)
        with self.assertRaises(api.BadRequest):
            scope([{'k': 'net', 'v': 'Nowhere'}])

    def test_events_and_host(self):
        self.assertTrue(api._event_match({'src': '8.8.8.8', 'dst': '172.16.5.3'}, {'k': 'net', 'v': 'Office A'}))
        self.assertFalse(api._event_match({'src': '10.9.0.1'}, {'k': 'net', 'v': 'Office A'}))
        self.assertEqual(api.host_obj('10.1.0.3')['net'], 'Office A')

    def test_no_networks(self):
        save([])
        self.assertEqual(api.net_expr('int_ip', {}), "''")


if __name__ == '__main__':
    unittest.main()
