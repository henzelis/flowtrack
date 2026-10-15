"""Exporters that send running totals of long sessions (core 1.4.1, a FortiGate 200F): every export carries the
session's bytes since its start, so stored as they come a tunnel counted 16 TiB every 30 minutes. Once found, only
the growth is stored, the exporter is remembered (running.json) and its packets go to one worker.
Run: python -m unittest discover -s tests"""
import os
import struct
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
os.environ.setdefault('FT_STATE_DIR', tempfile.mkdtemp())
os.environ.setdefault('FT_CONFIG_DIR', tempfile.mkdtemp())
os.environ['FT_GEOIP_DIR'] = tempfile.mkdtemp()          # no GeoIP needed here
import collector as C  # noqa: E402

FW = '198.51.100.98'
# IPV4_SRC, IPV4_DST, L4_SRC_PORT, L4_DST_PORT, PROTOCOL, INPUT_SNMP, OUTPUT_SNMP, IN_BYTES (8), IN_PKTS, FIRST, LAST
FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (10, 2), (14, 2), (1, 8), (2, 4), (22, 4), (21, 4)]


def v9(uptime, export, recs, first):
    tpl = struct.pack('!HH', 256, len(FIELDS)) + b''.join(struct.pack('!HH', i, n) for i, n in FIELDS)
    data = b''.join(struct.pack('!4s4sHHBHHQIII', bytes([192, 0, 2, 47]), bytes([203, 0, 113, 7]), port, port, 17, 38, 39,
                                b, p, first, uptime - 500) for port, b, p in recs)
    data += b'\0' * (-len(data) % 4)
    sets = b''.join(struct.pack('!HH', sid, len(body) + 4) + body for sid, body in ((0, tpl), (256, data)))
    return struct.pack('!HHIIII', 9, 2, uptime, export, 1, 0) + sets


class RunningTotals(unittest.TestCase):
    def setUp(self):
        if not hasattr(C.ftcore.Decoder(1, rate=0), 'set_running'):
            self.skipTest('core older than 1.4.1')
        self.c = C.Collector(rate_limit=False)
        self.c.flush = lambda: None
        try:
            os.remove(C.RUNNING_FILE)
        except OSError:
            pass

    def feed(self, k, now0, up0, first):
        now, up = now0 + 1800 * k, up0 + 1_800_000 * k
        recs = [(65000 + t, 17_000_000_000_000 + 1_000_000 * k, 4_000_000 + 1_000 * k) for t in range(12)]
        n = len(self.c.buf)
        self.c.handle_packet(v9(up, now, recs, first), (FW, 2055))
        return self.c.buf[n:]

    def test_tunnels_three_days_old(self):
        now0 = int(time.time()) - 4 * 1800
        up0 = 400_000_000
        first = up0 - 3 * 86_400_000
        rows = [self.feed(k, now0, up0, first) for k in range(4)]
        st = self.c.take_stats()['exp'][FW]
        self.assertTrue(st['running'])
        self.assertGreater(st['running_fixed'], 0)
        self.assertEqual(len(rows[3]), 12)
        b = [r['bytes'] for r in rows[3]] if isinstance(rows[3][0], dict) else None
        self.assertIsNotNone(b, rows[3][0])
        self.assertEqual(set(b), {1_000_000})

    def test_remembered_exporter_is_corrected_from_its_first_repeat(self):
        C.save_running({FW: 1})
        self.c.load_running()
        now0 = int(time.time()) - 4 * 1800
        up0 = 400_000_000
        first = up0 - 3 * 86_400_000
        rows = [self.feed(k, now0, up0, first) for k in range(2)]
        self.assertEqual(rows[0], [])                     # old sessions first seen: only remembered
        self.assertEqual({r['bytes'] for r in rows[1]}, {1_000_000})


class Routing(unittest.TestCase):
    def test_saved_and_loaded(self):
        C.save_running({FW: 123})
        self.assertEqual(C.load_running(), {FW: 123})


if __name__ == '__main__':
    unittest.main()
