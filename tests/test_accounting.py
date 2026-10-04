"""Receiver-side packet accounting: lost packets from sequence numbers, and which packets every worker
must see. Run: python -m unittest discover -s tests"""
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
os.environ.setdefault('FT_STATE_DIR', tempfile.mkdtemp())
os.environ.setdefault('FT_CONFIG_DIR', tempfile.mkdtemp())
import collector as C  # noqa: E402

IP = '192.0.2.1'


def v9(*flowsets, seq=1, src=0, up=None):
    return struct.pack('!HHIIII', 9, 1, seq * 10 if up is None else up, 0, seq, src) + b''.join(flowsets)


def fs(fid, payload):
    pad = (-(len(payload) + 4)) % 4
    return struct.pack('!HH', fid, len(payload) + 4 + pad) + payload + b'\0' * pad


def ipfix(*sets, seq=1, dom=7):
    body = b''.join(sets)
    return struct.pack('!HHIII', 10, 16 + len(body), seq, seq, dom) + body


def iset(sid, payload):
    return struct.pack('!HH', sid, len(payload) + 4) + payload


def v5(seq, count):
    return struct.pack('!HHIIIIBBH', 5, count, seq, 0, 0, seq, 0, 0, 0) + b'\0' * 48 * count


V9_TPL = fs(0, struct.pack('!HH', 256, 2) + struct.pack('!HHHH', 8, 4, 1, 4))           # 8-byte records
V9_OPT_TPL = fs(1, struct.pack('!HHH', 257, 4, 4) + struct.pack('!HHHH', 1, 4, 34, 4))
IPFIX_TPL = iset(2, struct.pack('!HH', 300, 2) + struct.pack('!HHHH', 8, 4, 1, 8))      # 12-byte records
IPFIX_VAR_TPL = iset(2, struct.pack('!HH', 302, 1) + struct.pack('!HH', 82, 0xFFFF))    # variable length
IPFIX_OPT_TPL = iset(3, struct.pack('!HHH', 301, 2, 1) + struct.pack('!HHHH', 143, 4, 305, 4))


class Peek(unittest.TestCase):
    def test_v9_templates_and_options_are_shared(self):
        a = C.Accounting()
        self.assertTrue(a.account(IP, v9(V9_TPL, V9_OPT_TPL, seq=1)))
        self.assertFalse(a.account(IP, v9(fs(256, b'\0' * 24), seq=2)))     # plain data: one worker
        self.assertTrue(a.account(IP, v9(fs(257, b'\0' * 8), seq=3)))       # options data: every worker

    def test_v9_loss_counts_packets(self):
        a = C.Accounting()
        for seq in (10, 11, 14, 15):                                       # 12 and 13 missing
            a.account(IP, v9(fs(256, b'\0' * 8), seq=seq))
        self.assertEqual(a.take()[IP], {'packets': 4, 'lost': 2, 'version': 9, 'dup_packets': 0})
        self.assertEqual(a.take(), {})                                      # counters reset

    def test_v9_sequence_per_source_id(self):
        a = C.Accounting()
        for seq, src in ((1, 1), (100, 2), (2, 1), (101, 2)):
            a.account(IP, v9(seq=seq, src=src))
        self.assertEqual(a.take()[IP]['lost'], 0)

    def test_ipfix_loss_counts_records(self):
        a = C.Accounting()
        a.account(IP, ipfix(IPFIX_TPL, seq=0))
        a.account(IP, ipfix(iset(300, b'\0' * 36), seq=0))                   # 3 records
        a.account(IP, ipfix(iset(300, b'\0' * 24), seq=3))                   # next: ok, 2 records
        a.account(IP, ipfix(iset(300, b'\0' * 12), seq=9))                   # expected 5 -> 4 records lost
        self.assertEqual(a.take()[IP]['lost'], 4)

    def test_ipfix_unknown_length_skips_one_check(self):
        a = C.Accounting()
        a.account(IP, ipfix(IPFIX_VAR_TPL, seq=0))
        a.account(IP, ipfix(iset(302, b'\x03abc'), seq=0))                  # record count unknown
        a.account(IP, ipfix(iset(302, b'\x03abc'), seq=50))                 # cannot judge: no loss
        self.assertEqual(a.take()[IP]['lost'], 0)

    def test_ipfix_options(self):
        a = C.Accounting()
        self.assertTrue(a.account(IP, ipfix(IPFIX_OPT_TPL)))
        self.assertTrue(a.account(IP, ipfix(iset(301, b'\0' * 8), seq=1)))

    def test_v5_loss_counts_flows(self):
        a = C.Accounting()
        a.account(IP, v5(0, 2))
        a.account(IP, v5(2, 3))
        a.account(IP, v5(10, 1))                                            # expected 5 -> 5 flows lost
        self.assertEqual(a.take()[IP], {'packets': 3, 'lost': 5, 'version': 5, 'dup_packets': 0})

    def test_reordering_is_not_negative_loss(self):
        a = C.Accounting()
        a.account(IP, v5(10, 5))
        a.account(IP, v5(12, 1))                                            # older than expected 15
        self.assertEqual(a.take()[IP]['lost'], 0)

    def test_garbage_goes_to_a_worker(self):
        a = C.Accounting()
        self.assertTrue(a.account(IP, b'\x00'))
        self.assertTrue(a.account(IP, v9(struct.pack('!HH', 0, 40) + b'\0' * 3)))    # truncated set


class RepeatedPackets(unittest.TestCase):
    def test_copies_with_own_sequence_counters_are_dropped(self):
        # RouterOS 7 after a traffic-flow change: every export sent 4x, same content, 4 sequence counters
        a = C.Accounting()
        data = fs(256, b'\1' * 8)
        for rnd in range(3):
            results = [a.account(IP, v9(data, seq=base + rnd, up=1000 + rnd), now=10.0 + rnd) for base in (52, 130, 154, 68193)]
            self.assertIsNotNone(results[0])                            # the first copy is taken
            self.assertEqual(results[1:], [None, None, None])           # the others are dropped
        self.assertEqual(a.take()[IP], {'packets': 3, 'lost': 0, 'version': 9, 'dup_packets': 9})

    def test_same_content_later_or_from_another_exporter_is_kept(self):
        a = C.Accounting()
        p = v9(fs(256, b'\1' * 8), seq=1, up=5)
        self.assertIsNotNone(a.account(IP, p, now=0.0))
        self.assertIsNotNone(a.account('192.0.2.2', p, now=0.1))         # another exporter
        self.assertIsNotNone(a.account(IP, p, now=0.0 + C.DUP_WINDOW + 0.5))   # outside the window
        self.assertEqual(a.take()[IP]['dup_packets'], 0)

    def test_templates_repeated_are_dropped_once_and_still_shared(self):
        a = C.Accounting()
        self.assertTrue(a.account(IP, v9(V9_TPL, seq=1, up=7), now=0.0))
        self.assertIsNone(a.account(IP, v9(V9_TPL, seq=900, up=7), now=0.001))

    def test_ipfix_and_v5_copies(self):
        a = C.Accounting()
        self.assertIsNotNone(a.account(IP, ipfix(IPFIX_TPL, seq=0), now=0.0))
        body = iset(300, b'\0' * 12)
        self.assertIsNotNone(a.account(IP, struct.pack('!HHIII', 10, 16 + len(body), 50, 0, 7) + body, now=0.1))
        self.assertIsNone(a.account(IP, struct.pack('!HHIII', 10, 16 + len(body), 50, 77, 7) + body, now=0.2))
        self.assertIsNotNone(a.account('192.0.2.5', v5(10, 1), now=0.0))
        p = bytearray(v5(10, 1)); p[16:20] = struct.pack('!I', 999)
        self.assertIsNone(a.account('192.0.2.5', bytes(p), now=0.1))
        self.assertEqual(a.take()[IP], {'packets': 2, 'lost': 0, 'version': 10, 'dup_packets': 1})

    def test_window_is_pruned(self):
        a = C.Accounting()
        for i in range(1000):
            a.account(IP, v9(seq=i), now=i * 0.01)
        self.assertLessEqual(len(a.ex[IP]['recent']), C.DUP_WINDOW / 0.01 + 2)


class Workers(unittest.TestCase):
    def test_setting(self):
        self.assertEqual(C.workers_setting('3'), 3)
        self.assertEqual(C.workers_setting('0'), 1)
        self.assertEqual(C.workers_setting('x'), 1)
        self.assertTrue(1 <= C.workers_setting('auto') <= 4)


if __name__ == '__main__':
    unittest.main()
