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
from netflow import parse_packet  # noqa: E402

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


class TemplatePersistence(unittest.TestCase):
    def roundtrip(self, templates):
        # same path as the collector: the text written to templates.json, then read back
        return C.templates_from_json(json.loads(C.templates_file_text({'x': templates}))['x'])

    def test_options_field_order_survives_save_and_restore(self):
        fresh = {'netflow': {}, 'ipfix': {}}
        parse_packet(v9(OPT_TPL), fresh)
        restored = self.roundtrip(fresh)
        a = parse_packet(v9(OPT_DATA, seq=2), fresh).options[0].data
        b = parse_packet(v9(OPT_DATA, seq=2), restored).options[0].data
        self.assertEqual(a, b)
        self.assertEqual(b['SAMPLING_INTERVAL'], 1)
        self.assertEqual(b['FLOW_ACTIVE_TIMEOUT'], 60)

    def test_unordered_legacy_options_entry_is_skipped(self):
        legacy = {'v9': {'256': {'s': {'1': 2}, 'o': {str(t): ln for t, ln in OPT_FIELDS}}}}
        self.assertEqual(C.templates_from_json(legacy)['netflow'], {})

    def test_sampling_not_inferred_from_rate_one(self):
        fresh = {'netflow': {}, 'ipfix': {}}
        opts = parse_packet(v9(OPT_TPL, OPT_DATA), fresh).options
        self.assertEqual(C.sampling_of(opts[0].data), 0)


class Helpers(unittest.TestCase):
    def test_norm_addr(self):
        self.assertEqual(C.norm_addr('::ffff:192.0.2.1'), '192.0.2.1')
        self.assertEqual(C.norm_addr('2001:db8::1%eth0'), '2001:db8::1')

    def test_parse_ratio(self):
        self.assertEqual(C.parse_ratio('1:1000'), 1000)
        self.assertEqual(C.parse_ratio('bogus'), 1)


if __name__ == '__main__':
    unittest.main()
