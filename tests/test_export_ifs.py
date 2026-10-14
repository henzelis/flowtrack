"""Interface names for the device configuration (1.7.1): what the form may store (they go into commands, some in
quotes) and the list of interfaces an SNMP poll offers to choose from."""
import os
import sys
import tempfile
import unittest

TMP = tempfile.mkdtemp()
os.makedirs(TMP + '/cfg'), os.makedirs(TMP + '/state')
open(TMP + '/cfg/exporters.json', 'w').write('{}')
os.environ.update(FT_CONFIG_DIR=TMP + '/cfg', FT_STATE_DIR=TMP + '/state')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import api  # noqa: E402


class ExportIfs(unittest.TestCase):
    def test_names_kept_in_order_without_repeats(self):
        self.assertEqual(api.export_ifs([' wan ', 'internal', 'wan', 'GigabitEthernet0/0/1', 'ge-0/0/0.0', 'Branch-GRE Тунель']),
                         ['wan', 'internal', 'GigabitEthernet0/0/1', 'ge-0/0/0.0', 'Branch-GRE Тунель'])
        self.assertEqual(api.export_ifs(None), [])
        self.assertEqual(api.export_ifs([]), [])

    def test_quotes_control_characters_and_long_names_refused(self):
        for bad in (['wan"'], ["a'b"], ['a`b'], ['a\\b'], ['a\nb'], ['x' * 65], [''], ['  '], [None]):
            with self.assertRaises(api.BadRequest, msg=bad):
                api.export_ifs(bad)

    def test_at_most_64(self):
        self.assertEqual(len(api.export_ifs([f'eth{i}' for i in range(100)])), 64)


class SnmpIfs(unittest.TestCase):
    def test_list_by_index_with_addresses(self):
        d = {'ifs': {'11': {'name': 'lan1', 'alias': 'office', 'oper': 1}, '2': {'name': '', 'descr': 'ether2', 'oper': 2},
                     '3': {'name': '', 'descr': ''}},
             'addrs': {'11': ['10.0.1.1/24']}}
        self.assertEqual(api.snmp_ifs(d), [
            {'index': 2, 'name': 'ether2', 'alias': '', 'up': False, 'addrs': []},
            {'index': 11, 'name': 'lan1', 'alias': 'office', 'up': True, 'addrs': ['10.0.1.1/24']}])     # nameless one left out
        self.assertEqual(api.snmp_ifs({}), [])


if __name__ == '__main__':
    unittest.main()
