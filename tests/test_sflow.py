"""sFlow v5 (1.7.0): the compiled decoder sums flow samples per minute and keeps interface counters; the collector
scales by the sampling rate, decides the direction like for NetFlow, counts lost datagrams by their sequence numbers.
Run: python -m unittest discover -s tests"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))
os.environ.setdefault('FT_STATE_DIR', tempfile.mkdtemp())
os.environ.setdefault('FT_CONFIG_DIR', tempfile.mkdtemp())
import ftcore  # noqa: E402
import collector  # noqa: E402
from sflowgen import counter_sample, datagram, flow_sample  # noqa: E402

IP, NOW = '192.0.2.1', 1_790_000_000 - 1_790_000_000 % 60 + 5      # 5 s into a minute


@unittest.skipUnless(ftcore.TESTING, 'needs a testing build of ftcore (cargo build --features testing)')
class Decoder(unittest.TestCase):
    def test_samples_summed_per_minute(self):
        d = ftcore.Decoder(rate=0)
        s = flow_sample('10.0.0.5', '93.184.216.34', sport=50000, dport=443, length=1500, rate=512, vlan=10)
        self.assertEqual(d.packet(IP, datagram([s, s, s]), NOW), [])
        self.assertEqual(d.flush(NOW + 10), [])                    # the minute is still open
        out = d.flush(NOW + 60)
        self.assertEqual(len(out), 1)
        ip, f = out[0]
        self.assertEqual((ip, f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[17]),
                         (IP, '10.0.0.5', '93.184.216.34', 4500, 3, 6, 50000, 443, 1, 2, 512))
        st = d.take_stats()[0][IP]
        self.assertEqual((st['records'], st['sampling'], st['agent'], st['decode_errors']), (3, 512, IP, 0))

    def test_ipv6_udp_and_counters(self):
        d = ftcore.Decoder(rate=0)
        d.packet(IP, datagram([flow_sample('2001:db8::5', '2001:db8:1::53', proto=17, sport=5353, dport=53, length=120),
                               counter_sample(7, 10_000, 20_000, in_errors=3)]), NOW)
        (_, f), = d.flush(NOW, all=True)
        self.assertEqual((f[0], f[4], f[6], f[2]), ('2001:db8::5', 17, 53, 120))
        (c,) = d.counters()
        self.assertEqual((c[0], c[2], c[4], c[6], c[7], c[12], c[14]), (IP, 7, 1_000_000_000, 3, 10_000, 3, 20_000))
        self.assertEqual(d.counters(), [])                          # taken once

    def test_garbage_is_a_decode_error(self):
        d = ftcore.Decoder(rate=0)
        good = datagram([flow_sample('10.0.0.1', '10.0.0.2')])
        for cut in (29, 40, len(good) - 3):
            d.packet(IP, good[:cut], NOW)
        self.assertGreaterEqual(d.take_stats()[0][IP]['decode_errors'], 2)


@unittest.skipUnless(ftcore.TESTING, 'needs a testing build of ftcore (cargo build --features testing)')
class Collector(unittest.TestCase):
    def test_scaled_direction_and_counters(self):
        c = collector.Collector(accounting=True, rate_limit=False)
        c.handle_packet(datagram([flow_sample('10.0.0.5', '8.8.8.8', rate=100, length=1000),
                                  flow_sample('8.8.8.8', '10.0.0.5', sport=443, dport=50000, rate=100, length=600),
                                  counter_sample(1, 5, 6)]), (IP, 0))
        c.sflow_tick(NOW + 3600, all=True)
        rows = sorted(c.buf, key=lambda r: r['dir'])
        self.assertEqual([(r['dir'], r['int_ip'], r['ext_ip'], r['bytes'], r['packets'], r['sampling']) for r in rows],
                         [('down', '10.0.0.5', '8.8.8.8', 60_000, 100, 100), ('up', '10.0.0.5', '8.8.8.8', 100_000, 100, 100)])
        self.assertEqual([(r['exporter'], r['if_index'], r['in_octets'], r['out_octets']) for r in c.cbuf], [(IP, 1, 5, 6)])

    def test_lost_datagrams_and_version(self):
        a = collector.Accounting()
        for seq in (1, 2, 5, 6):                      # 3 and 4 lost
            a.account(IP, datagram([flow_sample('10.0.0.1', '1.1.1.1', seq=seq)], seq=seq), now=seq * 10)
        a.account(IP, datagram([flow_sample('10.0.0.1', '1.1.1.1')], seq=1, sub_agent=1), now=100)   # another sub-agent
        st = a.take()[IP]
        self.assertEqual((st['packets'], st['lost'], st['version']), (5, 2, collector.SFLOW))

    def test_repeated_datagram_is_a_copy(self):
        a = collector.Accounting()
        d = datagram([flow_sample('10.0.0.1', '1.1.1.1')], seq=7)
        self.assertIsNotNone(a.account(IP, d, now=1))
        self.assertIsNone(a.account(IP, datagram([flow_sample('10.0.0.1', '1.1.1.1')], seq=8), now=1.5))
        self.assertEqual(a.take()[IP]['dup_packets'], 1)

    def test_netflow_v5_is_not_taken_for_sflow(self):
        self.assertIsNone(collector.sflow_seq_at(b'\x00\x05' + b'\x00' * 70))


if __name__ == '__main__':
    unittest.main()
