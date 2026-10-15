"""1.8.3: several values of one filter (any of them), exclusions of events by connection and direction, the user's
own names of ports. Run: python -m unittest discover -s tests"""
import json
import os
import sys
import tempfile
import unittest

TMP = tempfile.mkdtemp()
os.makedirs(TMP + '/cfg', exist_ok=True), os.makedirs(TMP + '/state', exist_ok=True)
open(TMP + '/cfg/exporters.json', 'w').write('{}')
os.environ.update(FT_CONFIG_DIR=TMP + '/cfg', FT_STATE_DIR=TMP + '/state')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import api  # noqa: E402
import common  # noqa: E402
import detect  # noqa: E402


def scope(flt, **q):
    return api.scope({'f': [json.dumps(flt)], **{k: [v] for k, v in q.items()}})


class AnyOf(unittest.TestCase):
    def test_two_devices_are_either(self):
        where, p, _, _ = scope([{'k': 'device', 'v': '10.0.0.1'}, {'k': 'device', 'v': '10.0.0.2'}])
        self.assertIn('(exporter = {f0:String} OR exporter = {f1:String})', where)
        self.assertEqual((p['f0'], p['f1']), ('10.0.0.1', '10.0.0.2'))

    def test_other_keys_and_exclusions_still_narrow(self):
        where, _, _, _ = scope([{'k': 'device', 'v': 'a'}, {'k': 'country', 'v': 'UA'}, {'k': 'device', 'v': 'b', 'neg': True}])
        self.assertIn('exporter = {f0:String}', where)
        self.assertIn('country = {f1:String}', where)
        self.assertIn('NOT (exporter = {f2:String})', where)
        self.assertNotIn(' OR exporter', where)

    def test_two_hosts_are_read_from_their_point_of_view(self):
        where, p, _, _ = scope([{'k': 'ip', 'v': '10.0.0.5'}, {'k': 'ip', 'v': '10.0.0.6'}])
        self.assertEqual(p['hv'], ['10.0.0.5', '10.0.0.6'])
        self.assertIn('int_ip IN {hv:Array(String)}', p['_flows'])
        self.assertIn('(int_ip = {f0:String} OR int_ip = {f1:String})', where)

    def test_events_any_of_one_key(self):
        evs = [{'kind': 'port_scan', 'src': '1.1.1.1', 'dst': '10.0.0.5', 'ip': '1.1.1.1', 'exporter': 'A'},
               {'kind': 'port_scan', 'src': '2.2.2.2', 'dst': '10.0.0.6', 'ip': '2.2.2.2', 'exporter': 'B'},
               {'kind': 'port_scan', 'src': '3.3.3.3', 'dst': '10.0.0.7', 'ip': '3.3.3.3', 'exporter': 'C'}]
        fs = [{'k': 'device', 'v': 'A'}, {'k': 'device', 'v': 'B'}]
        got = [e for e in evs if any(api._event_match(e, f) for f in fs)]
        self.assertEqual([e['exporter'] for e in got], ['A', 'B'])


class Exclusions(unittest.TestCase):
    def test_rules_are_checked(self):
        r = detect.exclusions([{'src': '10.0.0.5', 'dst': '203.0.113.7', 'port': '443', 'dir': 'up'},
                               {'src': '', 'dst': '10.0.0.0/24', 'port': 0, 'dir': 'down'}])
        self.assertEqual(r[0], {'src': '10.0.0.5', 'dst': '203.0.113.7', 'port': 443, 'dir': 'up'})
        self.assertEqual(r[1]['dst'], '10.0.0.0/24')
        for bad in ({'src': 'x', 'dir': 'up'}, {'dir': 'up', 'port': 80}, {'src': '10.0.0.1', 'port': 70000}, {'src': '10.0.0.1', 'dir': 'side'}):
            with self.assertRaises(ValueError):
                detect.exclusions([bad])

    def test_direction_target_and_port(self):
        ex = detect.Exclude(detect.exclusions([{'src': '10.0.0.5', 'dst': '203.0.113.7', 'port': 443, 'dir': 'up'},
                                               {'src': '', 'dst': '10.0.9.0/24', 'port': 8443, 'dir': 'down'}]))
        self.assertTrue(ex('sustained_upload', '10.0.0.5', '203.0.113.7', 443))
        self.assertFalse(ex('sustained_upload', '10.0.0.5', '203.0.113.7', 22))        # another port
        self.assertFalse(ex('brute_force', '10.0.0.5', '203.0.113.7', 443))            # the other direction
        self.assertTrue(ex('brute_force', '198.51.100.9', '10.0.9.4', 8443))           # anyone -> our network:8443
        self.assertFalse(ex('brute_force', '198.51.100.9', '10.0.8.4', 8443))
        self.assertFalse(detect.Exclude([])('port_scan', '1.1.1.1', '10.0.0.1', 22))

    def test_saved_with_the_settings(self):
        cfg = detect.validate({'exclude': [{'src': '10.0.0.5', 'dst': '', 'port': 0, 'dir': 'any'}]})
        self.assertEqual(cfg['exclude'], [{'src': '10.0.0.5', 'dst': '', 'port': 0, 'dir': 'any'}])


class PortNames(unittest.TestCase):
    def tearDown(self):
        common.PORT_NAMES.clear()

    def test_parsed_saved_and_used(self):
        out = api.post_ports({'text': 'tcp/8443 HTTPS management\n5000/udp Camera stream\n9000 Admin\n# a comment\n'})
        self.assertEqual(out['lines'], ['tcp/8443 HTTPS management', 'tcp/9000 Admin', 'udp/5000 Camera stream'])
        self.assertTrue(common.reload_port_names())
        self.assertEqual(common.classify_l7(6, 8443), ('HTTPS management', None))
        self.assertEqual(common.classify_l7(17, 5000)[0], 'Camera stream')
        self.assertEqual(common.classify_l7(6, 8444), ('TCP other', None))
        self.assertEqual(common.default_l7(6, 8443), 'TCP other')
        self.assertEqual(common.default_l7(6, 443), 'HTTPS')
        self.assertIn("'HTTPS management'", common.classify_l7_sql())
        self.assertFalse(common.server_is_src(6, 50000, 8443))            # a named port is the server side
        self.assertTrue(common.server_is_src(6, 8443, 50000))

    def test_bad_lines(self):
        for bad in ('tcp/8443', 'icmp/1 Ping', 'tcp/70000 Big', 'tcp/80 ' + 'x' * 41):
            with self.assertRaises(api.BadRequest):
                api.post_ports({'text': bad})


if __name__ == '__main__':
    unittest.main()
