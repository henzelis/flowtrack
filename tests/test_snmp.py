"""SNMP (1.5): net-snmp output parsing, settings validation (the secrets end up in snmp.conf lines), the private config
and how SNMP names / addresses fill in what was not entered by hand. Run: python -m unittest discover -s tests"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import snmp  # noqa: E402

WALK = """.1.3.6.1.2.1.31.1.1.1.1.1 = Hex-STRING: 77 61 6E 31
.1.3.6.1.2.1.31.1.1.1.1.21 = Hex-STRING: 42 72 61 6E 63 68 2D 47 52 45 20 D0 A2 D1 83 D0 BD D0 B5 D0 BB
D1 8C
.1.3.6.1.2.1.31.1.1.1.1.22 = ""
.1.3.6.1.2.1.2.2.1.8.1 = INTEGER: 1
.1.3.6.1.2.1.4.20.1.3.10.255.0.2 = IpAddress: 255.255.255.252
.1.3.6.1.2.1.4.34.1.5.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1 = OID: .1.3.6.1.2.1.4.32.1.5.7.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.0.64
.1.3.6.1.2.1.1.5.0 = STRING: "fw \\"main\\""
.1.3.6.1.2.1.31.1.1.1.18 = No Such Object available on this agent at this OID
"""


class Parse(unittest.TestCase):
    def test_rows(self):
        rows = {o: v for o, _, v in snmp.parse(WALK)}
        self.assertEqual(rows['1.3.6.1.2.1.31.1.1.1.1.1'], 'wan1')
        self.assertEqual(rows['1.3.6.1.2.1.31.1.1.1.1.21'], 'Branch-GRE Тунель')   # hex continued on the next line, UTF-8
        self.assertEqual(rows['1.3.6.1.2.1.31.1.1.1.1.22'], '')
        self.assertEqual(rows['1.3.6.1.2.1.2.2.1.8.1'], 1)
        self.assertEqual(rows['1.3.6.1.2.1.4.20.1.3.10.255.0.2'], '255.255.255.252')
        self.assertTrue(rows['1.3.6.1.2.1.4.34.1.5.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1'].endswith('.64'))
        self.assertEqual(rows['1.3.6.1.2.1.1.5.0'], 'fw "main"')
        self.assertNotIn('1.3.6.1.2.1.31.1.1.1.18', rows)

    def test_inet_index(self):
        self.assertEqual(str(snmp._inet([1, 4, 10, 0, 0, 1])), '10.0.0.1')
        self.assertEqual(str(snmp._inet([2, 16, 32, 1, 13, 184] + [0] * 11 + [1])), '2001:db8::1')
        self.assertIsNone(snmp._inet([4, 20] + [0] * 20))           # zone-scoped: skipped

    def test_appended_index(self):            # FortiOS `set append-index enable`: 10.0.1.1 + .1
        self.assertEqual(snmp._v4('10.0.1.1.1'), '10.0.1.1')
        self.assertEqual(snmp._v4('192.168.1.103'), '192.168.1.103')
        self.assertIsNone(snmp._v4('10.0.1'))
        self.assertEqual(str(snmp._inet([1, 4, 10, 0, 1, 1, 11])), '10.0.1.1')    # ipAddressTable + ifIndex

    def test_errors(self):
        self.assertEqual(snmp.classify('Timeout: No Response from udp:192.0.2.1:161.'), 'timeout')
        self.assertEqual(snmp.classify('snmpget: Unknown user name'), 'user')
        self.assertEqual(snmp.classify('snmpget: Authentication failure (incorrect password, community or key)'), 'auth')
        self.assertEqual(snmp.classify('snmpget: Decryption error'), 'priv')


class Settings(unittest.TestCase):
    V3 = {'enabled': True, 'version': '3', 'user': 'flowtrack', 'level': 'authPriv', 'auth_proto': 'SHA-256', 'auth_pass': 'pa ss#w"rd1',
          'priv_proto': 'AES', 'priv_pass': 'privpass123'}

    def test_v3_and_conf(self):
        e = snmp.settings_from(self.V3, None)
        self.assertEqual(e['port'], 161)
        conf = snmp._conf(e)
        self.assertIn('defAuthPassphrase pa ss#w"rd1\n', conf)       # rest of the line: spaces, # and quotes inside are fine
        self.assertIn('defPrivType AES\n', conf)
        self.assertEqual(snmp.public(e)['has_auth_pass'], True)
        self.assertNotIn('auth_pass', snmp.public(e))

    def test_rejects_what_breaks_snmp_conf(self):
        for k, v in (('auth_pass', 'short'), ('auth_pass', 'line\ndefVersion 1'), ('auth_pass', ' spaced pass '), ('priv_pass', '"quoted1"'),
                     ('auth_proto', 'SHA-1024'), ('level', 'all'), ('user', ''), ('version', '1')):
            with self.assertRaises(ValueError, msg=(k, v)):
                snmp.settings_from({**self.V3, k: v}, None)
        with self.assertRaises(ValueError):
            snmp.settings_from({'enabled': True, 'version': '2c', 'community': 'pub\nlic'}, None)
        with self.assertRaises(ValueError):
            snmp.settings_from({'enabled': True, 'version': '2c', 'port': 70000, 'community': 'x'}, None)

    def test_empty_secret_keeps_stored(self):
        old = snmp.settings_from(self.V3, None)
        e = snmp.settings_from({**self.V3, 'auth_pass': '', 'priv_pass': ''}, old)
        self.assertEqual((e['auth_pass'], e['priv_pass']), (old['auth_pass'], old['priv_pass']))
        with self.assertRaises(ValueError):                           # nothing stored: a password is needed
            snmp.settings_from({**self.V3, 'auth_pass': ''}, None)
        off = snmp.settings_from({'enabled': False}, old)             # switched off: kept for later, not used
        self.assertFalse(off['enabled'])
        self.assertEqual(off['priv_pass'], old['priv_pass'])

    def test_v2c_target(self):
        e = snmp.settings_from({'enabled': True, 'version': '2c', 'community': 'public', 'port': '1161'}, None)
        self.assertEqual(snmp._conf(e), 'defVersion 2c\ndefCommunity public\n')
        self.assertEqual(snmp._target('192.0.2.1', e), 'udp:192.0.2.1:1161')
        self.assertEqual(snmp._target('2001:db8::1', e), 'udp6:[2001:db8::1]:1161')

    def test_session_conf_is_private(self):
        if not snmp.available():
            self.skipTest('net-snmp tools not installed')
        s = snmp.Session('192.0.2.1', snmp.settings_from(self.V3, None))
        try:
            st = os.stat(os.path.join(s.dir, 'snmp.conf'))
            self.assertEqual(st.st_mode & 0o777, 0o600)
        finally:
            s.close()
        self.assertFalse(os.path.exists(s.dir))


class Merge(unittest.TestCase):
    def test_hand_entered_wins(self):
        exp = {'192.0.2.1': {'name': 'fw', 'if_names': {'1': 'wan'}, 'if_addrs': {'5': ['10.9.9.1/24']}},
               '192.0.2.2': {'name': 'other'}}
        data = {'192.0.2.1': {'ok': True, 'ifs': {'1': {'name': 'wan1'}, '21': {'name': 'Branch-GRE'}, '22': {'name': ''}},
                              'addrs': {'1': ['198.51.100.2/29'], '5': ['10.0.0.1/24'], '21': ['10.255.0.2/32']}},
                '192.0.2.2': {'ok': True, 'ifs': {'1': {'name': 'ether1'}}}}
        on = {'192.0.2.1': {'enabled': True}, '192.0.2.2': {'enabled': False}}
        m = snmp.merge(exp, data, on)
        self.assertEqual(m['192.0.2.1']['if_names'], {'1': 'wan', '21': 'Branch-GRE'})
        self.assertEqual(m['192.0.2.1']['if_addrs'], {'1': ['198.51.100.2/29'], '5': ['10.9.9.1/24'], '21': ['10.255.0.2/32']})
        self.assertIs(m['192.0.2.2'], exp['192.0.2.2'])               # SNMP off: data ignored
        self.assertEqual(exp['192.0.2.1']['if_names'], {'1': 'wan'})   # the configured entry is not changed

    def test_store_keeps_last_good_on_failure(self):
        with tempfile.TemporaryDirectory() as d:
            old = (snmp.SETTINGS, snmp.DATA, snmp.poll)
            snmp.SETTINGS, snmp.DATA = os.path.join(d, 's.json'), os.path.join(d, 'd.json')
            try:
                snmp.save_settings('192.0.2.1', {'enabled': True, 'version': '2c', 'community': 'x'})
                snmp.poll = lambda ip, e: {'sys': {'name': 'fw'}, 'ifs': {'1': {'name': 'wan1'}}, 'addrs': {}}
                snmp.poll_and_store('192.0.2.1')

                def fail(ip, e):
                    raise snmp.SnmpError('timeout', 'Timeout: No Response')
                snmp.poll = fail
                r = snmp.poll_and_store('192.0.2.1')
                self.assertFalse(r['ok'])
                self.assertEqual(r['ifs'], {'1': {'name': 'wan1'}})
                self.assertTrue(r['t_ok'])
                self.assertEqual(os.stat(snmp.SETTINGS).st_mode & 0o777, 0o600)
                self.assertEqual(snmp.due(r['t'] + 60), [])
                self.assertEqual(snmp.due(r['t'] + snmp.RETRY), ['192.0.2.1'])
                snmp.save_settings('192.0.2.1', {'enabled': False})   # off: what was polled is dropped
                self.assertEqual(snmp.load_data(), {})
            finally:
                snmp.SETTINGS, snmp.DATA, snmp.poll = old


if __name__ == '__main__':
    unittest.main()
