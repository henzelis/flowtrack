"""The compiled decoder on IPFIX the Python netflow library (FlowTrack <= 1.1) could not read, and the records/s
limit inside it. Run: python -m unittest discover -s tests"""
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
os.environ.setdefault('FT_STATE_DIR', tempfile.mkdtemp())
os.environ.setdefault('FT_CONFIG_DIR', tempfile.mkdtemp())
import ftcore  # noqa: E402

NOW = 1_790_000_000
IP = '192.0.2.9'


def ipfix(*sets, seq=1):
    body = b''.join(sets)
    return struct.pack('!HHIII', 10, 16 + len(body), NOW, seq, 0) + body


def iset(sid, payload):
    return struct.pack('!HH', sid, len(payload) + 4) + payload


def tpl(tid, fields, sid=2):
    """fields: (id, length) or (id, length, enterprise)"""
    out = struct.pack('!HH', tid, len(fields))
    for f in fields:
        out += struct.pack('!HH', f[0] | (0x8000 if len(f) == 3 else 0), f[1]) + (struct.pack('!I', f[2]) if len(f) == 3 else b'')
    return iset(sid, out)


SRC, DST = bytes([10, 0, 0, 5]), bytes([198, 51, 100, 7])


def decoder():
    return ftcore.Decoder(rate=0)


@unittest.skipUnless(ftcore.TESTING, 'needs a testing build of ftcore (cargo build --features testing)')
class Ipfix(unittest.TestCase):
    def flows(self, *packets):
        d = decoder()
        out = []
        for p in packets:
            out += d.packet(IP, p, NOW + 1)
        self.stats = d.take_stats()[0].get(IP, {})
        return [(f[0], f[1], f[2], f[3]) for f in out]

    def test_variable_length_and_enterprise_fields(self):
        # src, an enterprise field numbered like octetDeltaCount, a variable-length string, dst, bytes, packets
        t = tpl(400, [(8, 4), (1, 8, 12356), (82, 0xFFFF), (12, 4), (1, 4), (2, 4)])
        rec = SRC + struct.pack('!Q', 999_999) + bytes([5]) + b'wan1\x00' + DST + struct.pack('!II', 1500, 3)
        long_name = SRC + struct.pack('!Q', 1) + bytes([255]) + struct.pack('!H', 300) + b'x' * 300 + DST + struct.pack('!II', 40, 1)
        self.assertEqual(self.flows(ipfix(t, iset(400, rec + long_name))),
                         [('10.0.0.5', '198.51.100.7', 1500, 3), ('10.0.0.5', '198.51.100.7', 40, 1)])

    def test_reduced_size_counters_and_unknown_fields(self):
        # bytes in 3 octets, packets in 6 octets, a field number no registry knows, padding at the end of the set
        t = tpl(401, [(8, 4), (12, 4), (1, 3), (2, 6), (31999, 2)])
        rec = SRC + DST + (70000).to_bytes(3, 'big') + (5).to_bytes(6, 'big') + b'\x00\x01'
        self.assertEqual(self.flows(ipfix(t, iset(401, rec + b'\x00\x00\x00'))), [('10.0.0.5', '198.51.100.7', 70000, 5)])
        self.assertEqual(self.stats['decode_errors'], 0)

    def test_unknown_template_keeps_the_known_records(self):
        t = tpl(402, [(8, 4), (12, 4), (1, 4)])
        p = ipfix(t, iset(999, b'\x00' * 12), iset(402, SRC + DST + struct.pack('!I', 77)))
        self.assertEqual(self.flows(p), [('10.0.0.5', '198.51.100.7', 77, 0)])
        self.assertEqual(self.stats['no_template'], 1)

    def test_reserved_set_ids_are_skipped(self):
        t = tpl(403, [(8, 4), (12, 4), (1, 4)])
        self.assertEqual(self.flows(ipfix(t, iset(7, b'\x00' * 4), iset(403, SRC + DST + struct.pack('!I', 9)))),
                         [('10.0.0.5', '198.51.100.7', 9, 0)])

    def test_template_withdrawal(self):
        t = tpl(404, [(8, 4), (12, 4), (1, 4)])
        withdraw = iset(2, struct.pack('!HH', 404, 0))
        data = iset(404, SRC + DST + struct.pack('!I', 9))
        self.assertEqual(self.flows(ipfix(t), ipfix(withdraw, seq=2), ipfix(data, seq=3)), [])
        self.assertEqual((self.stats['no_template'], self.stats['templates']), (1, 0))

    def test_truncated_packet_is_a_decode_error(self):
        t = tpl(405, [(8, 4), (12, 4), (1, 4)])
        p = ipfix(t, iset(405, SRC + DST + struct.pack('!I', 9)))
        self.assertEqual(self.flows(p[:-6]), [])
        self.assertEqual(self.stats['decode_errors'], 1)
        self.assertTrue(self.stats['last_error'])

    def test_ipfix_options_set_the_sampling_rate(self):
        opt = iset(3, struct.pack('!HHH', 406, 2, 1) + struct.pack('!HHHH', 143, 4, 305, 4))
        t = tpl(407, [(8, 4), (12, 4), (1, 4)])
        d = decoder()
        f = d.packet(IP, ipfix(opt, iset(406, struct.pack('!II', 1, 512)), t, iset(407, SRC + DST + struct.pack('!I', 10))), NOW)
        self.assertEqual(f[0][17], 512)                             # the exporter's own rate; Python scales by it


class Limit(unittest.TestCase):
    def test_decoder_follows_the_edition(self):
        ftcore.edition(tempfile.mkdtemp())                         # no license: Community
        d = ftcore.Decoder(2)
        self.assertEqual(d.rate, ftcore.COMMUNITY_RPS / 2)

    @unittest.skipUnless(ftcore.TESTING, 'needs a testing build of ftcore')
    def test_records_over_the_limit_are_counted_not_returned(self):
        t = tpl(410, [(8, 4), (12, 4), (1, 4)])
        rec = SRC + DST + struct.pack('!I', 100)
        d = ftcore.Decoder(rate=1)                                 # 1 record/s, a 60 s window: 60 at once
        got = sum(len(d.packet(IP, ipfix(t, iset(410, rec * 10), seq=i), NOW)) for i in range(10))
        stats, over = d.take_stats()
        self.assertEqual((got, over, stats[IP]['records']), (60, 40, 100))


if __name__ == '__main__':
    unittest.main()
