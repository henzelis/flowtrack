"""(1.16.0) QoS marking: the core hands DSCP in / out with each record (core 1.6.0), the collector stores them (255 when
the exporter does not send it), the filter takes a class name or number. Run: python -m unittest discover -s tests"""
import json
import os
import sys
import tempfile
import unittest

TMP = tempfile.mkdtemp()
os.makedirs(TMP + '/cfg', exist_ok=True), os.makedirs(TMP + '/state', exist_ok=True)
open(TMP + '/cfg/exporters.json', 'w').write('{}')
os.environ.update(FT_CONFIG_DIR=TMP + '/cfg', FT_STATE_DIR=TMP + '/state')
os.environ['FT_GEOIP_DIR'] = tempfile.mkdtemp()
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import api  # noqa: E402
import collector as C  # noqa: E402


class Names(unittest.TestCase):
    def test_values(self):
        for v, n in (('EF', 46), ('ef', 46), ('46', 46), ('AF41', 34), ('BE', 0), ('cs1', 8), ('255', 255)):
            self.assertEqual(api.dscp_value(v), n, v)
        for v in ('XX', '64', '-1', 'AF5'):
            self.assertIsNone(api.dscp_value(v), v)

    def test_filter(self):
        where, p, _, _ = api.scope({'f': [json.dumps([{'k': 'dscp', 'v': 'EF'}])], 'range': ['24h']})
        self.assertIn('dscp = {f0n:UInt8}', where)
        self.assertEqual(p['f0n'], 46)
        self.assertIn('dscp', p['_fcols'])
        with self.assertRaises(api.BadRequest):
            api.scope({'f': [json.dumps([{'k': 'dscp', 'v': 'nonsense'}])], 'range': ['24h']})


class Store(unittest.TestCase):
    def row(self, f):
        c = C.Collector(accounting=False, rate_limit=False)
        e = C.Exporter('192.0.2.1', {'wan_ifs': [2]})
        c.buf = []
        c.store(e, f)
        return c.buf[0]['dscp'], c.buf[0]['dscp_out']

    def test_from_the_core(self):
        base = ('10.0.0.5', '198.51.100.7', 1000, 2, 17, 5060, 5060, 7, 2, 0, '0.0.0.0', 0, '0.0.0.0', 0, 1.7e9, 1.7e9 + 1, 0, 1)
        self.assertEqual(self.row(base + (46, 34)), (46, 34))             # EF in, re-marked to AF41 on the way out
        self.assertEqual(self.row(base + (255, 255)), (255, 255))         # the exporter sent no marking
        self.assertEqual(self.row(base), (255, 255))                      # an older core: no marking either


if __name__ == '__main__':
    unittest.main()
