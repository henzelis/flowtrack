"""Exporters that monitor ingress and egress on several interfaces: each routed packet is reported twice.
With the direction field the egress copy must be dropped when its input interface already reports
ingress. Run: python -m unittest discover -s tests"""
import os
import socket
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
os.environ.setdefault('FT_STATE_DIR', tempfile.mkdtemp())
os.environ.setdefault('FT_CONFIG_DIR', tempfile.mkdtemp())
os.environ['FT_GEOIP_DIR'] = tempfile.mkdtemp()          # no GeoIP needed here
import collector as C  # noqa: E402

UP = 100_000_000
ip4 = socket.inet_aton
EXP = ('192.0.2.1', 2055)


def v9(*flowsets, seq=1):
    return struct.pack('!HHIIII', 9, 1, UP, 1_700_000_000, seq, 0) + b''.join(flowsets)


def fs(fid, payload):
    pad = (-(len(payload) + 4)) % 4
    return struct.pack('!HH', fid, len(payload) + 4 + pad) + payload + b'\0' * pad


# src, dst, bytes, pkts, proto, sport, dport, in_if, out_if, first, last, direction
FIELDS = [(8, 4), (12, 4), (1, 4), (2, 4), (4, 1), (7, 2), (11, 2), (10, 2), (14, 2), (22, 4), (21, 4), (61, 1)]
TPL = fs(0, struct.pack('!HH', 300, len(FIELDS)) + b''.join(struct.pack('!HH', t, ln) for t, ln in FIELDS))


def rec(src, dst, nbytes, in_if, out_if, direction, sport=40000):
    return ip4(src) + ip4(dst) + struct.pack('!IIBHHHHIIB', nbytes, 10, 6, sport, 443, in_if, out_if, UP - 30000, UP - 1000, direction)


class Dedup(unittest.TestCase):
    def setUp(self):
        self.c = C.Collector(accounting=False)

    def stored(self):
        return [(r['int_ip'], r['ext_ip'], r['bytes'], r['in_if'], r['out_if'], r['obs']) for r in self.c.buf]

    def test_egress_copy_of_an_ingress_observed_flow_is_dropped(self):
        # LAN (if 2) -> WAN (if 1): seen on ingress of 2 and on egress of 1
        self.c.handle_packet(v9(TPL, fs(300, rec('10.0.0.5', '198.51.100.7', 1000, 2, 1, 0) + rec('10.0.0.5', '198.51.100.7', 1000, 2, 1, 1))), EXP)
        self.assertEqual(self.stored(), [('10.0.0.5', '198.51.100.7', 1000, 2, 1, 0)])
        self.assertEqual(self.c.exporters['192.0.2.1'].dup_dropped, 1)

    def test_both_directions_of_a_session_are_kept(self):
        # the reply WAN (1) -> LAN (2) is another flow, seen on ingress of 1 and egress of 2
        self.c.handle_packet(v9(TPL, fs(300, rec('10.0.0.5', '198.51.100.7', 1000, 2, 1, 0) + rec('198.51.100.7', '10.0.0.5', 5000, 1, 2, 0)
                                       + rec('10.0.0.5', '198.51.100.7', 1000, 2, 1, 1) + rec('198.51.100.7', '10.0.0.5', 5000, 1, 2, 1))), EXP)
        self.assertEqual(sorted(r[2] for r in self.stored()), [1000, 5000])

    def test_egress_only_interface_keeps_its_records(self):
        # if 7 is monitored on egress only: traffic entering through it has no ingress copy
        self.c.handle_packet(v9(TPL, fs(300, rec('10.0.0.5', '198.51.100.7', 1000, 2, 1, 0) + rec('10.9.0.9', '198.51.100.8', 700, 7, 1, 1))), EXP)
        self.assertEqual(sorted(r[2] for r in self.stored()), [700, 1000])
        self.assertEqual(self.c.exporters['192.0.2.1'].dup_dropped, 0)

    def test_without_direction_field_nothing_is_dropped(self):
        fields = FIELDS[:-1]
        tpl = fs(0, struct.pack('!HH', 301, len(fields)) + b''.join(struct.pack('!HH', t, ln) for t, ln in fields))
        r = rec('10.0.0.5', '198.51.100.7', 1000, 2, 1, 0)[:-1]
        self.c.handle_packet(v9(tpl, fs(301, r + r)), EXP)
        self.assertEqual([x[5] for x in self.stored()], [255, 255])


if __name__ == '__main__':
    unittest.main()
