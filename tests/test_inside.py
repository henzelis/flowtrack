"""Traffic between inside hosts (1.7.0): every record is stored client -> server — int_* = who started the session,
ext_* = the server and its service port; dir 'internal' = the client's packets, 'internal_back' = the server's
answer — so both directions of a session form one conversation and the service is named from the server's port.
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
from common import server_is_src  # noqa: E402

A, B = '10.20.0.5', '10.20.0.9'


def rec(src, dst, sport, dport, proto=6):
    # (src, dst, bytes, packets, proto, sport, dport, in_if, out_if, obs, nat_src, nat_sport, nat_dst, nat_dport, start, end, app_tag, rate)
    return (src, dst, 1000, 2, proto, sport, dport, 7, 8, 0, '0.0.0.0', 0, '0.0.0.0', 0, 1_700_000_000, 1_700_000_001, 0, 1)


class ServerSide(unittest.TestCase):
    def test_rules(self):
        self.assertFalse(server_is_src(6, 42724, 22))       # to a well-known port: the source is the client
        self.assertTrue(server_is_src(6, 22, 42724))        # from it: the server's answer
        self.assertTrue(server_is_src(17, 53, 1078))        # DNS answer to a client port above 1023
        self.assertTrue(server_is_src(6, 3030, 50973))      # neither port known: the lower one is the server
        self.assertFalse(server_is_src(6, 29129, 3030))
        self.assertTrue(server_is_src(17, 5247, 43353))     # CAPWAP data from the FortiGate to an access point
        self.assertFalse(server_is_src(17, 2055, 2055))     # equal ports: the source started it
        self.assertFalse(server_is_src(17, 123, 53))        # both well-known: the lower port is the server
        self.assertFalse(server_is_src(1, 0, 0))            # ICMP: no ports
        self.assertFalse(server_is_src(47, 1000, 22))       # GRE and other protocols without ports


class Orientation(unittest.TestCase):
    def setUp(self):
        self.c = C.Collector(accounting=False, rate_limit=False)
        self.e = C.Exporter('192.0.2.1', {})

    def row(self, f):
        self.c.buf = []
        self.c.store(self.e, f)
        r = self.c.buf[0]
        return r['dir'], r['int_ip'], r['int_port'], r['ext_ip'], r['ext_port'], r['l7'], r['service']

    def test_client_request(self):
        self.assertEqual(self.row(rec(A, B, 42724, 22)), ('internal', A, 42724, B, 22, 'SSH', 'Local network'))

    def test_server_answer_turned_round(self):
        # the answer keeps the client as int_ip and the server's port as the service (was "TCP other" before 1.7.0)
        self.assertEqual(self.row(rec(B, A, 22, 42724)), ('internal_back', A, 42724, B, 22, 'SSH', 'Local network'))

    def test_dns_answer(self):
        self.assertEqual(self.row(rec('10.20.0.1', B, 53, 1078, proto=17)), ('internal_back', B, 1078, '10.20.0.1', 53, 'DNS', 'DNS'))

    def test_internet_unchanged(self):
        self.assertEqual(self.row(rec('8.8.8.8', A, 443, 50000))[:3], ('down', A, 50000))


if __name__ == '__main__':
    unittest.main()
