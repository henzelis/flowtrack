"""(1.14.0) Interface counters over SNMP: one read of a device becomes if_counters rows (64-bit where the device has
ifXTable, 32-bit otherwise, loopbacks left out), a device that stops answering is logged once an hour, not every
minute. Run: python -m unittest discover -s tests"""
import os
import sys
import tempfile
import unittest
from unittest import mock

TMP = tempfile.mkdtemp()
os.makedirs(TMP + '/cfg', exist_ok=True), os.makedirs(TMP + '/state', exist_ok=True)
os.environ.update(FT_CONFIG_DIR=TMP + '/cfg', FT_STATE_DIR=TMP + '/state')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ifcounters  # noqa: E402
import snmp  # noqa: E402

WALKS = {  # the columns a FortiGate answers (two interfaces + a loopback)
    ifcounters.HC['in_octets']: {'1': 29464436863, '5': 1200, '24': 9},
    ifcounters.HC['out_octets']: {'1': 2673075888, '5': 3400, '24': 9},
    ifcounters.HC['in_ucast']: {'1': 10, '5': 2}, ifcounters.HC['out_ucast']: {'1': 11, '5': 3},
    ifcounters.COMMON['in_errors']: {'1': 4}, ifcounters.COMMON['if_type']: {'1': 6, '5': 6, '24': 24},
    ifcounters.COMMON['admin']: {'1': 1, '5': 1, '24': 1}, ifcounters.COMMON['oper']: {'1': 1, '5': 2, '24': 1},
    ifcounters.COMMON['speed_m']: {'1': 1000, '5': 100},
}


class FakeSession:
    def __init__(self, walks):
        self.walks = walks

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def walk(self, col):
        return [(f'{col}.{i}', 'Counter64', v) for i, v in self.walks.get(col, {}).items()]


class Read(unittest.TestCase):
    def test_wide_counters_to_rows(self):
        with mock.patch.object(snmp, 'Session', lambda ip, e: FakeSession(WALKS)):
            found = ifcounters.read('192.0.2.1', {})
        r = ifcounters.rows('192.0.2.1', found, 1792399330)
        self.assertEqual([x['if_index'] for x in r], [1, 5])                  # the loopback left out
        w = r[0]
        self.assertEqual((w['in_octets'], w['out_octets'], w['speed'], w['status'], w['in_errors'], w['wide'], w['src']),
                         (29464436863, 2673075888, 1_000_000_000, 3, 4, 1, 'snmp'))
        self.assertEqual(r[1]['status'], 1)                                   # admin up, oper down
        self.assertEqual(w['ts'], '2026-10-19 08:42:10')

    def test_32_bit_device(self):
        low = {ifcounters.LOW['in_octets']: {'3': 4294967000}, ifcounters.LOW['out_octets']: {'3': 77}, ifcounters.COMMON['if_type']: {'3': 6}}
        with mock.patch.object(snmp, 'Session', lambda ip, e: FakeSession(low)):
            r = ifcounters.rows('192.0.2.2', ifcounters.read('192.0.2.2', {}), 1792399330)
        self.assertEqual((r[0]['in_octets'], r[0]['wide']), (4294967000, 0))

    def test_silent_device_logged_once_an_hour(self):
        said = []
        p = ifcounters.Poller(said.append)

        def boom(ip, e):
            raise snmp.SnmpError('timeout', 'no answer')
        with mock.patch.object(snmp, 'load_settings', lambda: {'192.0.2.1': {'enabled': True}}), mock.patch.object(ifcounters, 'read', boom):
            p.once(1000)
            p.once(1060)
            p.once(1000 + 3700)
        self.assertEqual(len(said), 2)
        self.assertFalse(ifcounters.load_status()['192.0.2.1']['ok'])


if __name__ == '__main__':
    unittest.main()


class FlowsSeen(unittest.TestCase):
    """(1.15.1) «What the flows see» over the hours both sources have, from 3 hours of counters on (it waited for whole
    days: a device with SNMP switched on today showed nothing for a day, the counters' label for half the period)."""
    def seen(self, hours, flows_b, ctr_b):
        import api
        now = 1792400000
        cper = {('192.0.2.1', 1, 'snmp', 0): {'first': now - hours * 3600, 'bytes': 1, 'm': 1, 'secs': 1, 'peak': 0, 'p95': 0}}
        asked = []

        def ch(sql, params=None, **kw):
            asked.append(params)
            return [{'exporter': '192.0.2.1', 'i': 1, 'd': 0, 'b': flows_b}] if 'delta' not in sql else \
                [{'exporter': '192.0.2.1', 'i': 1, 'src': 'snmp', 'd': 0, 'b': ctr_b}]
        with mock.patch.object(api, 'ch', ch), mock.patch('time.time', lambda: now):
            p = {'_t0': now - 30 * 86400, '_t1': None, '_fcols': set(), '_filt': '1', '_step': 300}
            return api.flows_seen(p, cper), asked

    def test_two_hours_is_too_early(self):
        r, asked = self.seen(2, 50_000_000, 100_000_000)
        self.assertEqual((r, asked), ({}, []))

    def test_after_three_hours(self):
        r, asked = self.seen(4, 48_000_000, 100_000_000)
        self.assertEqual(r, {('192.0.2.1', 1, 0): 48.0})
        self.assertEqual(asked[0]['ct0'], 1792400000 - 4 * 3600 + 600)            # from the first read + 10 minutes
