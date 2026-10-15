"""1.8.4: Settings → Flow configuration — port names as a table, the roles of our services saved apart from the
rest of the event settings. Run: python -m unittest discover -s tests"""
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


if __name__ == '__main__':
    unittest.main()
