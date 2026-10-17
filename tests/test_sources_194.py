"""1.9.4: packets with forged source addresses cannot fill the memory. The receiver tracks at most MAX_NEW sources
that are not configured (an idle one makes room); a worker forgets an idle unconfigured exporter in the core too;
the core keeps a bounded number of templates and exporters; the receiver's accounting of one source stays bounded.
Run: python -m unittest discover -s tests"""
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
os.environ.setdefault('FT_STATE_DIR', tempfile.mkdtemp())
os.environ.setdefault('FT_CONFIG_DIR', tempfile.mkdtemp())
os.environ['FT_GEOIP_DIR'] = tempfile.mkdtemp()          # no GeoIP needed here
import collector as C  # noqa: E402
import ftcore  # noqa: E402

NOW = 1_790_000_000


def ipfix(*sets, dom=1, seq=1):
    body = b''.join(sets)
    return struct.pack('!HHIII', 10, 16 + len(body), NOW, seq, dom) + body


def template(tid, n):
    payload = struct.pack('!HH', tid, n) + b''.join(struct.pack('!HH', 1 + k % 200, 4) for k in range(n))
    return struct.pack('!HH', 2, len(payload) + 4) + payload


class NewSources(unittest.TestCase):
    def test_limit_and_idle(self):
        g = C.NewSources(limit=2, idle=100)
        self.assertTrue(g.admit('a', 0) and g.admit('b', 1) and g.admit('a', 50))
        self.assertFalse(g.admit('c', 60))                  # full, nobody idle
        self.assertTrue(g.admit('c', 102))                 # b idle 101 s: makes room
        self.assertEqual(sorted(g.seen), ['a', 'c'])
        self.assertEqual(g.take_ignored(), (1, 1))
        self.assertEqual(g.take_ignored(), (0, 0))
        self.assertEqual(sorted(g.expire(300)), ['a', 'c'])

    def test_receiver_gate(self):
        r = C.Receiver(1)
        r.cfg = {'192.0.2.1': {}}
        r.new = C.NewSources(limit=1)
        self.assertTrue(r.new.admit('198.51.100.1'))
        self.assertFalse(r.new.admit('198.51.100.2'))


class WorkerForgets(unittest.TestCase):
    def test_idle_unconfigured_is_forgotten_in_the_core(self):
        c = C.Collector(accounting=False, rate_limit=False)
        c.cfg = {'192.0.2.1': {}}
        for ip in ('192.0.2.1', '203.0.113.9'):
            c.handle_packet(ipfix(template(300, 3)), (ip, 2055))
        self.assertEqual(set(c.exporters), {'192.0.2.1', '203.0.113.9'})
        for e in c.exporters.values():
            e.seen -= C.NEW_IDLE + 1
        c.forget_idle()
        self.assertEqual(set(c.exporters), {'192.0.2.1'})          # a configured one stays however quiet
        self.assertFalse(c.dec.forget('203.0.113.9'))              # already gone from the core
        self.assertTrue(c.dec.forget('192.0.2.1'))


class CoreBounds(unittest.TestCase):
    def test_templates(self):
        d = ftcore.Decoder(rate=0)
        d.packet('192.0.2.1', ipfix(template(300, 513)), NOW, False)          # more fields than any real template
        for tid in range(256, 3000):
            d.packet('192.0.2.1', ipfix(template(tid, 500)), NOW, False)
        n = d.take_stats()[0]['192.0.2.1']['templates']
        self.assertLessEqual(n * 500, 50_000)

    def test_exporters(self):
        d = ftcore.Decoder(rate=0)
        for i in range(1100):
            d.packet(f'10.{i // 256}.{i % 256}.1', ipfix(template(300, 3)), NOW, False)
        self.assertEqual(d.take_refused(), 1100 - 1024)


class Accounting(unittest.TestCase):
    def test_one_source_stays_bounded(self):
        a = C.Accounting()
        for i in range(5000):
            a.account('192.0.2.1', ipfix(template(256 + i % 60000, 2), dom=i, seq=i))
        x = a.ex['192.0.2.1']
        self.assertLessEqual(len(x['tpl']), 4096)
        self.assertLessEqual(len(x['seq']), 256)


if __name__ == '__main__':
    unittest.main()
