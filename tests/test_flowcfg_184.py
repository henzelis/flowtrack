"""1.8.4: Settings → Flow configuration — port names as a table, the roles of our services saved apart from the
rest of the event settings. Run: python -m unittest discover -s tests"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

TMP = tempfile.mkdtemp()
os.makedirs(TMP + '/cfg', exist_ok=True), os.makedirs(TMP + '/state', exist_ok=True)
open(TMP + '/cfg/exporters.json', 'w').write('{}')
os.environ.update(FT_CONFIG_DIR=TMP + '/cfg', FT_STATE_DIR=TMP + '/state')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import api  # noqa: E402
import common  # noqa: E402
import detect  # noqa: E402


class PortTable(unittest.TestCase):
    def tearDown(self):
        common.PORT_NAMES.clear()

    def test_items_saved_and_listed_with_the_default_name(self):
        out = api.post_ports({'items': [{'proto': 'udp', 'port': 5000, 'name': ' Camera   stream '},
                                        {'proto': 'tcp', 'port': 8443, 'name': 'HTTPS management'},
                                        {'proto': 'tcp', 'port': 443, 'name': 'Web'}]})
        self.assertEqual(out['items'], [{'proto': 'tcp', 'port': 443, 'name': 'Web', 'default': 'HTTPS'},
                                        {'proto': 'udp', 'port': 5000, 'name': 'Camera stream', 'default': 'UDP other'},
                                        {'proto': 'tcp', 'port': 8443, 'name': 'HTTPS management', 'default': 'TCP other'}])
        self.assertEqual(out['known']['tcp/443'], 'HTTPS')
        self.assertEqual(api.post_ports({'items': []})['items'], [])        # the last one deleted

    def test_bad_items(self):
        for bad in ({'proto': 'icmp', 'port': 1, 'name': 'x'}, {'proto': 'tcp', 'port': 0, 'name': 'x'},
                    {'proto': 'tcp', 'port': '8443\nudp/53', 'name': 'x'}, {'proto': 'tcp', 'port': 80, 'name': ''},
                    {'proto': 'tcp', 'port': 80, 'name': 'x' * 41}, 'tcp/80 x'):
            with self.assertRaises(api.BadRequest):
                api.post_ports({'items': [bad]})


@mock.patch.object(api, 'get_events_config', lambda: {})
class ServiceRoles(unittest.TestCase):
    def tearDown(self):
        if os.path.exists(detect.CONFIG):
            os.remove(detect.CONFIG)

    def test_saved_apart_from_the_events_tab(self):
        api.post_events_config({'ignore': ['203.0.113.7'], 'kinds': {'port_scan': {'on': False}}})
        api.post_events_services({'roles': {'10.0.0.5:8443/6': 'sensitive'}, 'sensitive': '22, 8443', 'public': [80]})
        cfg = detect.load_config()
        self.assertEqual((cfg['ignore'], cfg['kinds']['port_scan']['on']), (['203.0.113.7'], False))   # kept
        self.assertEqual((cfg['roles'], cfg['sensitive'], cfg['public']), ({'10.0.0.5:8443/6': 'sensitive'}, [22, 8443], [80]))
        # the Events tab (save without them, or restore its defaults) keeps the roles
        api.post_events_config({'ignore': []})
        api.post_events_config({})
        cfg = detect.load_config()
        self.assertEqual((cfg['roles'], cfg['sensitive'], cfg['ignore']), ({'10.0.0.5:8443/6': 'sensitive'}, [22, 8443], []))
        self.assertTrue(cfg['kinds']['port_scan']['on'])
        api.post_events_services({'reset': True})
        cfg, d = detect.load_config(), detect.defaults()
        self.assertEqual((cfg['roles'], cfg['sensitive'], cfg['public']), ({}, d['sensitive'], d['public']))

    def test_bad_port(self):
        with self.assertRaises(api.BadRequest):
            api.post_events_services({'sensitive': '22, 70000'})


@mock.patch.object(api, 'get_events_config', lambda: {})
class Exceptions(unittest.TestCase):
    def tearDown(self):
        if os.path.exists(detect.CONFIG):
            os.remove(detect.CONFIG)

    def test_saved_row_by_row_and_kept_by_the_events_tab(self):
        out = api.post_events_exceptions({'ignore': ['203.0.113.7', 'as40934'],
                                          'exclude': [{'dir': 'up', 'src': '10.0.0.5', 'dst': '', 'port': 0}]})
        self.assertEqual(out['ignore'], ['203.0.113.7', 'AS40934'])
        self.assertEqual(out['exclude'], [{'src': '10.0.0.5', 'dst': '', 'port': 0, 'dir': 'up'}])
        api.post_events_exceptions({'ignore': []})                          # one list replaced, the other kept
        api.post_events_config({'kinds': {}})                                # Save / Restore defaults on Events
        cfg = detect.load_config()
        self.assertEqual((cfg['ignore'], len(cfg['exclude'])), ([], 1))
        for bad in ({'ignore': ['not-an-ip']}, {'exclude': [{'dir': 'up', 'src': '', 'dst': '', 'port': 0}]},
                    {'exclude': [{'dir': 'up', 'src': '10.0.0.0/33', 'dst': '', 'port': 0}]}):
            with self.assertRaises(api.BadRequest):
                api.post_events_exceptions(bad)


class HostNames(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(common.CONFIG_DIR, 'hosts.json'), 'w') as f:
            f.write('{"10.0.0.1": "router", "10.0.0.2": "old"}')

    def tearDown(self):
        for p in (common.UI_HOSTS, os.path.join(common.CONFIG_DIR, 'hosts.json')):
            if os.path.exists(p):
                os.remove(p)

    def test_over_the_deployment_file(self):
        self.assertEqual(api.api_host_names({})['items'], [{'ip': '10.0.0.1', 'name': 'router'}, {'ip': '10.0.0.2', 'name': 'old'}])
        out = api.post_host_names({'items': [{'ip': '10.0.0.1', 'name': 'router'}, {'ip': '10.0.0.10', 'name': '  NAS   office '},
                                             {'ip': '2001:db8::1', 'name': 'v6 box'}]})
        self.assertEqual(out['items'], [{'ip': '10.0.0.1', 'name': 'router'}, {'ip': '10.0.0.10', 'name': 'NAS office'},
                                        {'ip': '2001:db8::1', 'name': 'v6 box'}])
        with open(common.UI_HOSTS) as f:            # only the differences are stored; 10.0.0.2 removed = null
            self.assertEqual(json.load(f), {'10.0.0.10': 'NAS office', '2001:db8::1': 'v6 box', '10.0.0.2': None})
        self.assertEqual(api.NAMES.get('10.0.0.10'), 'NAS office')
        self.assertNotIn('10.0.0.2', api.NAMES.manual)

    def test_bad_rows(self):
        for bad in ({'ip': '10.0.0.0/24', 'name': 'x'}, {'ip': '10.0.0.300', 'name': 'x'}, {'ip': '10.0.0.1', 'name': ' '},
                    {'ip': '10.0.0.1', 'name': 'x' * 65}):
            with self.assertRaises(api.BadRequest):
                api.post_host_names({'items': [bad]})


if __name__ == '__main__':
    unittest.main()
