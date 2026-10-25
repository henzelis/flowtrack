"""1.12.0: interface load — own capacities (in / out) saved with the interfaces, the capacity an interface gets (own,
else SNMP speed), the 5-minute load with average / p95 / peak and shares (/api/ifload), and the "Link near capacity"
rule (every 5 minutes of the span above the threshold). Run: python -m unittest discover -s tests"""
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

TMP = tempfile.mkdtemp()
os.makedirs(TMP + '/cfg', exist_ok=True), os.makedirs(TMP + '/state', exist_ok=True)
open(TMP + '/cfg/exporters.json', 'w').write('{}')
os.environ.update(FT_CONFIG_DIR=TMP + '/cfg', FT_STATE_DIR=TMP + '/state')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import api  # noqa: E402
import common  # noqa: E402
import detect  # noqa: E402

DEV = '192.0.2.1'


class Capacity(unittest.TestCase):
    def test_own_figures_win_over_the_port_speed(self):
        c = {'if_caps': {'1': [300, 50]}}
        self.assertEqual(api.if_capacity(c, 1, 1000), {'cap_in': 300, 'cap_out': 50, 'cap_own': True, 'cap_auto': 1000})
        self.assertEqual(api.if_capacity(c, 2, 1000), {'cap_in': 1000, 'cap_out': 1000, 'cap_own': False, 'cap_auto': 1000})
        self.assertEqual(api.if_capacity({}, 3, 0)['cap_in'], 0)                 # unknown

    def test_saved_with_the_interfaces(self):
        own = os.path.join(tempfile.mkdtemp(), 'exporters.json')                # not the shared state: other tests use this device
        with mock.patch.object(api, 'exporters_cfg', lambda raw=False: {}), mock.patch.object(api.NAMES, 'reload', lambda: None), \
             mock.patch.object(common, 'UI_EXPORTERS', own):
            api.post_device_interfaces({'ip': DEV, 'interfaces': [{'index': 1, 'role': 'wan', 'cap_in': '300', 'cap_out': '50'},
                                                                  {'index': 2, 'cap_in': '1000'}, {'index': 3, 'cap_in': '', 'cap_out': ''}]}, 'admin')
            e = common.load_ui_exporter(DEV)
        self.assertEqual(e['if_caps'], {'1': [300.0, 50.0], '2': [1000.0, 1000.0]})     # one figure = both directions; empty = port speed
        for bad in ({'cap_in': '0'}, {'cap_in': '-5'}, {'cap_in': 'fast'}, {'cap_out': '2000000'}):
            with self.subTest(bad), self.assertRaises(api.BadRequest):
                api.post_device_interfaces({'ip': DEV, 'interfaces': [dict({'index': 1}, **bad)]}, 'admin')


class Load(unittest.TestCase):
    def test_average_p95_peak_and_shares(self):
        t1 = int(time.time()) // 300 * 300
        t0 = t1 - 7200
        # 2 Gbit/s once, 100 Mbit/s otherwise, in through interface 1 and out through 2 (one row per interface and way, 1.17.0)
        rows = [{'t': t0 + k * 300, 'i': i, 'd': d, 'b': 75_000_000_000 if k == 3 else 3_750_000_000} for k in range(24) for i, d in ((1, 0), (2, 1))]
        c = {'if_caps': {'1': [1000, 1000]}, 'if_names': {'1': 'wan'}}
        sent = []
        with mock.patch.object(api, 'ch', lambda q, *a, **k: sent.append(q) or rows), mock.patch.object(api, 'exporters_cfg', lambda raw=False: {DEV: c}), \
             mock.patch.object(api, 'sflow_counters', lambda: {}), mock.patch.object(api.snmp, 'load_settings', lambda: {}), \
             mock.patch.object(api, 'view_days', lambda: 30):
            d = api.api_ifload({'device': [DEV], 'from': [str(t0)], 'to': [str(t1)]})
        # (1.17.0) the split into interfaces is ClickHouse's, before the scope's WHERE (after it is a syntax error)
        self.assertRegex(sent[-1], r'ARRAY JOIN \[\(in_if, 0\), \(out_if, 1\)\] AS x WHERE \(')
        wan = next(i for i in d['interfaces'] if i['index'] == 1)
        self.assertEqual((wan['name'], wan['cap_in']), ('wan', 1000))
        self.assertAlmostEqual(wan['in']['peak'], 2e9)
        self.assertEqual(wan['in']['peak_pct'], 200.0)
        self.assertAlmostEqual(wan['in']['p95'], 1e8)                            # one busy 5 minutes in 24 (4 %): above the p95
        self.assertAlmostEqual(wan['in']['avg'], (23 * 1e8 + 2e9) / 24)
        self.assertEqual(wan['out']['bytes'], 0)
        other = next(i for i in d['interfaces'] if i['index'] == 2)
        self.assertIsNone(other['out']['peak_pct'])                              # no capacity known: no share
        self.assertEqual(d['interfaces'][0]['index'], 1)                         # the fullest first


class Rule(unittest.TestCase):
    def run_rule(self, levels, pct=85, span=15):
        t1 = 1_800_000_000
        end = t1 // 300 * 300
        rows = [{'exporter': DEV, 't': end - (i + 1) * 300, 'in_if': 1, 'out_if': 9, 'b': int(lv / 100 * 100e6 * 300 / 8)} for i, lv in enumerate(levels)]
        caps = {DEV: ('fw', {1: ('wan', 100.0, 20.0)})}
        with mock.patch.object(detect, 'capacities', lambda: caps), mock.patch.object(detect, 'ch', lambda *a, **k: rows):
            return detect.link_load({'pct': pct, 'span': span}, t1)

    def test_every_5_minutes_above_the_threshold(self):
        h = self.run_rule([90, 95, 88])
        self.assertEqual(len(h), 1)
        self.assertEqual((h[0]['key'], h[0]['port'], h[0]['info']['dir'], h[0]['info']['pct'], h[0]['info']['min_pct']), (f'{DEV}/1/in', 1, 'in', 95.0, 88.0))
        self.assertEqual(self.run_rule([90, 50, 95]), [])                        # one quiet 5 minutes: no event
        self.assertEqual(self.run_rule([90, 95]), [])                            # a missing 5 minutes counts as 0

    def test_described(self):
        common.set_lang('en')
        h = self.run_rule([90, 95, 88])[0]
        title, text = detect.describe(dict(h, first_seen=0, last_seen=0, hits=1))
        self.assertEqual(title, 'Link near capacity: wan')
        self.assertIn('fw · wan: incoming traffic up to 95 of 100 Mbit/s (95%), above 85% for 15 min.', text)

    def test_capacities_from_settings_and_snmp(self):
        with mock.patch.object(common, 'load_exporters', lambda: {DEV: {'name': 'fw', 'if_caps': {'5': [300, 50]}, 'if_names': {'5': 'isp'}}}), \
             mock.patch('snmp.load_settings', lambda: {DEV: {'enabled': True}}), \
             mock.patch('snmp.load_data', lambda: {DEV: {'ifs': {'1': {'name': 'wan', 'speed': 100}, '2': {'name': 'vlan', 'speed': 0}}}}):
            caps = detect.capacities()
        self.assertEqual(caps[DEV][1], {1: ('wan', 100.0, 100.0), 5: ('isp', 300.0, 50.0)})


if __name__ == '__main__':
    unittest.main()
