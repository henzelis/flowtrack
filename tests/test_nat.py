"""Records arriving through destination NAT: the inside host is the translated destination (MikroTik's replies to
masqueraded hosts, a FortiGate VIP), the public address goes to nat_ip — as for outgoing records.
Run: python -m unittest discover -s tests"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
os.environ.setdefault('FT_STATE_DIR', tempfile.mkdtemp())
os.environ.setdefault('FT_CONFIG_DIR', tempfile.mkdtemp())
os.environ['FT_GEOIP_DIR'] = tempfile.mkdtemp()          # no GeoIP needed here
import collector as C  # noqa: E402

PUB, HOST, PEER = '81.20.30.5', '10.20.0.5', '198.51.100.7'


def rec(src, dst, in_if, out_if, nat_src='0.0.0.0', nat_sport=0, nat_dst='0.0.0.0', nat_dport=0):
    # (src, dst, bytes, packets, proto, sport, dport, in_if, out_if, obs, nat_src, nat_sport, nat_dst, nat_dport, start, end, app_tag, rate)
    return (src, dst, 1000, 2, 6, 443 if src == PEER else 50000, 50000 if src == PEER else 443, in_if, out_if, 0,
            nat_src, nat_sport, nat_dst, nat_dport, 1_700_000_000, 1_700_000_001, 0, 1)


class DestinationNat(unittest.TestCase):
    def setUp(self):
        self.c = C.Collector(accounting=False, rate_limit=False)
        self.e = C.Exporter('192.0.2.1', {'wan_ifs': [2], 'public_ips': [PUB]})

    def row(self, f):
        self.c.buf = []
        self.c.store(self.e, f)
        r = self.c.buf[0]
        return r['dir'], r['int_ip'], r['int_port'], r['ext_ip'], r['nat_ip'], r['nat_port']

    def test_reply_to_masqueraded_host(self):
        # in on WAN to the router's public address, translated to the inside host
        self.assertEqual(self.row(rec(PEER, PUB, 2, 7, nat_dst=HOST, nat_dport=50001)), ('down', HOST, 50001, PEER, PUB, 50000))

    def test_outgoing_unchanged(self):
        self.assertEqual(self.row(rec(HOST, PEER, 7, 2, nat_src=PUB, nat_sport=50000)), ('up', HOST, 50000, PEER, PUB, 50000))

    def test_already_inside_destination_unchanged(self):
        # FortiGate style: the reply's destination is the inside host already, the public one in the NAT field
        self.assertEqual(self.row(rec(PEER, HOST, 2, 7, nat_dst=PUB, nat_dport=50000)), ('down', HOST, 50000, PEER, PUB, 50000))

    def test_traffic_to_the_router_itself(self):
        self.assertEqual(self.row(rec(PEER, PUB, 2, 0, nat_dst=PUB, nat_dport=50000)), ('down', PUB, 50000, PEER, PUB, 50000))


if __name__ == '__main__':
    unittest.main()
