"""Template persistence and sampling detection. Run: python -m unittest discover -s tests"""
import json
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
os.environ.setdefault('FT_STATE_DIR', tempfile.mkdtemp())
os.environ.setdefault('FT_CONFIG_DIR', tempfile.mkdtemp())
import collector as C  # noqa: E402
import ftcore  # noqa: E402

NOW, UP = 1_700_000_000, 100_000_000


def v9(*flowsets, seq=1):
    return struct.pack('!HHIIII', 9, 1, UP, NOW, seq, 0) + b''.join(flowsets)


def fs(fid, payload):
    pad = (-(len(payload) + 4)) % 4
    return struct.pack('!HH', fid, len(payload) + 4 + pad) + payload + b'\0' * pad


# FortiOS-like options template: field order is NOT ascending (40, 41, 42, 36, 37, 34, 35)
OPT_FIELDS = [(40, 8), (41, 8), (42, 8), (36, 2), (37, 2), (34, 4), (35, 1)]
OPT_TPL = fs(1, struct.pack('!HHH', 256, 4, 4 * len(OPT_FIELDS)) + struct.pack('!HH', 1, 2)
             + b''.join(struct.pack('!HH', t, ln) for t, ln in OPT_FIELDS))
OPT_DATA = fs(256, struct.pack('!H', 1) + struct.pack('!QQQHHIB', 59_031_927_932, 6_574_000, 196_606, 60, 15, 1, 1))


# a flow template and one record: src, dst, bytes, packets, proto, sport, dport, in_if, out_if, first, last
FLOW_FIELDS = [(8, 4), (12, 4), (1, 4), (2, 4), (4, 1), (7, 2), (11, 2), (10, 2), (14, 2), (22, 4), (21, 4)]
FLOW_TPL = fs(0, struct.pack('!HH', 300, len(FLOW_FIELDS)) + b''.join(struct.pack('!HH', t, ln) for t, ln in FLOW_FIELDS))
FLOW = fs(300, bytes([10, 0, 0, 5, 198, 51, 100, 7]) + struct.pack('!IIBHHHHII', 1000, 10, 6, 40000, 443, 2, 1, UP - 30000, UP - 1000))


def decoder():
    return ftcore.Decoder(rate=0) if ftcore.TESTING else ftcore.Decoder()


class TemplatePersistence(unittest.TestCase):
    def test_options_field_order_survives_save_and_restore(self):
        d = decoder()
        d.packet('x', v9(OPT_TPL, FLOW_TPL), NOW)
        saved = json.loads(d.templates_json())['x']
        self.assertEqual(saved['v9']['256']['o'], [list(f) for f in OPT_FIELDS])     # in the exporter's order
        r = decoder()
        self.assertEqual(r.load_templates('x', json.dumps(saved)), 2)
        r.packet('x', v9(OPT_DATA, seq=2), NOW)                         # the options record still reads as rate 1
        f = r.packet('x', v9(FLOW, seq=3), NOW)
        self.assertEqual([(x[0], x[1], x[2], x[17]) for x in f], [('10.0.0.5', '198.51.100.7', 1000, 0)])

    def test_unordered_legacy_options_entry_is_skipped(self):
        legacy = {'v9': {'256': {'s': {'1': 2}, 'o': {str(t): ln for t, ln in OPT_FIELDS}}}}
        self.assertEqual(decoder().load_templates('x', json.dumps(legacy)), 0)

    def test_sampling_not_inferred_from_rate_one(self):
        d = decoder()
        d.packet('x', v9(OPT_TPL, OPT_DATA, FLOW_TPL, FLOW), NOW)
        stats, _ = d.take_stats()
        self.assertEqual((stats['x']['opt_sampling'], stats['x']['sampling']), (0, 0))


class Helpers(unittest.TestCase):
    def test_norm_addr(self):
        self.assertEqual(C.norm_addr('::ffff:192.0.2.1'), '192.0.2.1')
        self.assertEqual(C.norm_addr('2001:db8::1%eth0'), '2001:db8::1')

    def test_parse_ratio(self):
        self.assertEqual(C.parse_ratio('1:1000'), 1000)
        self.assertEqual(C.parse_ratio('bogus'), 1)


if __name__ == '__main__':
    unittest.main()
