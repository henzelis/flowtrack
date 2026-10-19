"""(1.13.0) The interface filter takes a name (iface:wan — that interface on each device that has one), and Capacity
follows the device and interface filters. Run: python -m unittest discover -s tests"""
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

DEVS = {'192.0.2.1': {'name': 'fw-main', 'wan_ifs': [1], 'if_names': {'1': 'wan', '5': 'lan'}},
        '192.0.2.2': {'name': 'branch', 'wan_ifs': [3], 'if_names': {'3': 'WAN'}},
        '192.0.2.3': {'name': 'sw', 'if_names': {}}}
SNMP = {'192.0.2.3': {'ifs': {'7': {'name': 'ether1'}}}}


def patched():
    return [mock.patch.object(api, 'exporters_cfg', lambda raw=False: DEVS),
            mock.patch.object(api.snmp, 'load_settings', lambda: {'192.0.2.3': {'enabled': True}}),
            mock.patch.object(api.snmp, 'load_data', lambda: SNMP)]


class Names(unittest.TestCase):
    def setUp(self):
        self.p = patched()
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()

    def test_lookup_any_case_and_snmp(self):
        self.assertEqual(api.ifaces_named('wan'), [('192.0.2.1', 1), ('192.0.2.2', 3)])
        self.assertEqual(api.ifaces_named('ETHER1'), [('192.0.2.3', 7)])
        self.assertEqual(api.ifaces_named('nope'), [])

    def test_scope_by_name(self):
        where, p, _, _ = api.scope({'f': [json.dumps([{'k': 'iface', 'v': 'wan'}])], 'range': ['24h']})
        self.assertIn('(exporter = {f0d0:String} AND (in_if = {f0i0:UInt32} OR out_if = {f0i0:UInt32}))', where)
        self.assertEqual((p['f0d0'], p['f0i0'], p['f0d1'], p['f0i1']), ('192.0.2.1', 1, '192.0.2.2', 3))
        self.assertIn('exporter', p['_fcols'])
        where, p, _, _ = api.scope({'f': [json.dumps([{'k': 'iface', 'v': '5'}])], 'range': ['24h']})
        self.assertIn('(in_if = {f0:UInt32} OR out_if = {f0:UInt32})', where)         # a number as before
        with self.assertRaises(api.BadRequest):
            api.scope({'f': [json.dumps([{'k': 'iface', 'v': 'nope'}])], 'range': ['24h']})

    def test_capacity_filters(self):
        info = lambda name: {'name': name, 'snmp_name': ''}      # noqa: E731
        links = [('192.0.2.1', 1, info('wan')), ('192.0.2.1', 5, info('lan')), ('192.0.2.2', 3, info('WAN'))]
        pick = lambda flt: [(d, i) for d, i, inf in links if api._cap_filter({'f': [json.dumps(flt)]})[0](d, i, inf)]   # noqa: E731
        self.assertEqual(pick([{'k': 'device', 'v': '192.0.2.1'}]), [('192.0.2.1', 1), ('192.0.2.1', 5)])
        self.assertEqual(pick([{'k': 'device', 'v': 'branch'}]), [('192.0.2.2', 3)])                 # by name too
        self.assertEqual(pick([{'k': 'iface', 'v': 'wan'}]), [('192.0.2.1', 1), ('192.0.2.2', 3)])
        self.assertEqual(pick([{'k': 'iface', 'v': '1'}, {'k': 'device', 'v': '192.0.2.1'}]), [('192.0.2.1', 1)])
        self.assertEqual(pick([{'k': 'iface', 'v': 'wan', 'neg': True}]), [('192.0.2.1', 5)])
        self.assertEqual(api._cap_filter({'f': [json.dumps([{'k': 'service', 'v': 'Zoom'}, {'k': 'iface', 'v': 'wan'}])]})[1], ['service'])


if __name__ == '__main__':
    unittest.main()


class CapacityMemory(unittest.TestCase):
    """(1.14.0) A customer's 200F on 1.13.1: «Not enough memory» on Capacity. The 5-minute totals were grouped by the
    PAIR of interfaces first (thousands of VLAN / tunnel pairs × 8,640 buckets); measured on 20 M synthetic rows with
    3,600 pairs: 1.75 GiB and out of memory, against 182 MiB when each record goes to its two interfaces as it is read."""
    def test_no_pair_grouping(self):
        _, p, _, _ = api.scope({'f': ['[]'], 'range': ['24h'], 't': ['all']})
        p['_step'] = 300
        q = api._five_min(p)
        self.assertNotIn('GROUP BY exporter, in_if, out_if', q)
        self.assertIn('ARRAY JOIN [(in_if, 0), (out_if, 1)] AS x WHERE', q)
        self.assertEqual(q.count('GROUP BY'), 1)
