"""1.12.0: sign-in through Active Directory / LDAP — the settings checks, group matching and roles, and the sign-in flow
of auth.py with the directory answered by a stand-in (the real servers — Samba AD with nested groups, OpenLDAP with
LDAPS / STARTTLS and its own CA — are checked on stage, see flowsphera-verify). Run: python -m unittest discover -s tests"""
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

TMP = tempfile.mkdtemp()
os.environ.setdefault('FT_STATE_DIR', TMP)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import auth  # noqa: E402
import directory  # noqa: E402
from auth import Auth, AuthError  # noqa: E402

ON = {'on': True, 'kind': 'ad', 'host': 'dc1.corp.example.com', 'security': 'ldaps', 'bind_dn': 'svc@corp.example.com',
      'bind_password': 'secret', 'base_dn': 'DC=corp,DC=example,DC=com', 'admin_groups': 'FT-Admins', 'viewer_groups': ['FT-Viewers']}


class Settings(unittest.TestCase):
    def test_checks(self):
        c = directory.validate(ON, directory.defaults())
        self.assertEqual((c['port'], c['admin_groups'], c['viewer_groups']), (636, ['FT-Admins'], ['FT-Viewers']))
        self.assertEqual(directory.validate(dict(ON, security='starttls', port=''), directory.defaults())['port'], 389)
        kept = directory.validate(dict(ON, bind_password=''), c)
        self.assertEqual(kept['bind_password'], 'secret')                     # an empty field keeps the saved password
        self.assertNotIn('secret', str(directory.public(c)))
        for bad in ({'host': ''}, {'base_dn': ''}, {'admin_groups': '', 'viewer_groups': []}, {'user_filter': '(uid=x)'},
                    {'ca': 'not a pem'}, {'host': 'bad host!'}, {'port': 0}, {'label': 'x' * 41}):
            with self.subTest(bad), self.assertRaises(ValueError):
                directory.validate(dict(ON, **bad), directory.defaults())
        self.assertTrue(directory.validate(dict(ON, admin_groups='', viewer_groups=[], everyone_viewer=True), directory.defaults())['on'])

    def test_sign_in_page_method(self):
        self.assertIsNone(directory.method(directory.defaults()))
        self.assertEqual(directory.method(directory.validate(ON, directory.defaults())), {'id': 'ldap', 'label': 'Active Directory'})
        self.assertEqual(directory.method(directory.validate(dict(ON, label='CORP'), directory.defaults()))['label'], 'CORP')

    def test_groups_and_roles(self):
        c = directory.validate(dict(ON, admin_groups='FT-Admins\nCN=Ops,OU=G,DC=corp,DC=example,DC=com'), directory.defaults())
        dns = ['CN=ft-admins,CN=Users,DC=corp,DC=example,DC=com', 'CN=Other,CN=Users,DC=corp,DC=example,DC=com']
        self.assertEqual(directory.role_of(c, dns), 'admin')                  # by name, case-insensitive
        self.assertEqual(directory.role_of(c, ['cn=ops,ou=g,dc=corp,dc=example,dc=com']), 'admin')     # by full DN
        self.assertEqual(directory.role_of(c, ['CN=FT-Viewers,CN=Users,DC=corp,DC=example,DC=com']), 'viewer')
        self.assertEqual(directory.role_of(c, ['CN=FT-Viewers,CN=Users,DC=x', 'CN=FT-Admins,CN=Users,DC=x']), 'admin')   # admin wins
        self.assertIsNone(directory.role_of(c, ['CN=Nobody,DC=x']))
        self.assertEqual(directory.role_of(dict(c, everyone_viewer=True), []), 'viewer')

    def test_names_cannot_inject_into_the_filter(self):
        for name in ('*', 'a*', 'x)(uid=*', 'a(b', 'bob\\00', 'a b', ''):
            with self.subTest(name):
                self.assertIsNone(directory.authenticate(directory.validate(ON, directory.defaults()), name, 'pw'))     # refused before any query
        self.assertTrue(directory.USER_RE.match('anna@corp.example.com'))


class SignIn(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.p = [mock.patch.object(auth, 'USERS_FILE', os.path.join(d, 'u.json')), mock.patch.object(auth, 'SESSIONS_FILE', os.path.join(d, 's.json')),
                  mock.patch.object(auth, 'TOKENS_FILE', os.path.join(d, 't.json')),
                  mock.patch.object(directory, 'load', lambda: directory.validate(dict(ON, label='CORP'), directory.defaults()))]
        for p in self.p:
            p.start()
        self.a = Auth()                                 # admin / flowsphera, local
        self.answers = {('anna', 'pw'): {'name': 'anna', 'role': 'admin', 'dn': 'CN=anna,DC=x', 'groups': []},
                        ('admin', 'pw'): {'name': 'admin', 'role': 'viewer', 'dn': 'CN=admin,DC=x', 'groups': []},
                        ('carl', 'pw'): {'name': 'carl', 'role': None, 'dn': 'CN=carl,DC=x', 'groups': []}}
        self.d = mock.patch.object(directory, 'authenticate', lambda cfg, u, p: self.answers.get((u, p)))
        self.d.start()

    def tearDown(self):
        self.d.stop()
        for p in self.p:
            p.stop()

    def test_directory_user(self):
        tok = self.a.login('anna', 'pw', '10.0.0.1', 'ldap')
        self.assertEqual(self.a.session_user(tok), 'ldap:anna')
        pub = self.a.public('ldap:anna')
        self.assertEqual((pub['role'], pub['source'], pub['display']), ('admin', 'ldap', 'anna'))
        self.assertNotIn('hash', self.a.users['ldap:anna'])
        s = self.a.sessions[auth._tok_id(tok)]
        self.assertTrue(s['fixed'] and round((s['exp'] - s['created']) / 3600) == 12)
        s['exp'] = time.time() + 3600                    # no sliding for a directory session
        self.a.session_user(tok)
        self.assertLess(s['exp'], time.time() + 3601)

    def test_same_name_two_accounts(self):
        self.assertEqual(self.a.session_user(self.a.login('admin', 'pw', '10.0.0.2', 'ldap')), 'ldap:admin')
        self.assertEqual(self.a.session_user(self.a.login('admin', 'flowsphera', '10.0.0.2', 'local')), 'admin')
        self.assertEqual((self.a.users['admin']['role'], self.a.users['ldap:admin']['role']), ('admin', 'viewer'))
        with self.assertRaises(AuthError):              # the directory password does not open the local account
            self.a.login('admin', 'pw', '10.0.0.2', 'local')

    def test_refusals(self):
        with self.assertRaises(AuthError) as e:
            self.a.login('carl', 'pw', '10.0.0.3', 'ldap')
        self.assertEqual(e.exception.status, 403)
        for _ in range(5):                               # wrong ones count with the failed logins
            with self.assertRaises(AuthError):
                self.a.login('anna', 'nope', '10.0.0.4', 'ldap')
        with self.assertRaises(AuthError) as e:
            self.a.login('anna', 'pw', '10.0.0.4', 'ldap')
        self.assertEqual(e.exception.status, 429)
        with mock.patch.object(directory, 'authenticate', side_effect=directory.DirectoryError('down')):
            with self.assertRaises(AuthError) as e:
                self.a.login('anna', 'pw', '10.0.0.5', 'ldap')
        self.assertEqual(e.exception.status, 503)
        self.assertEqual(len(self.a.fails['10.0.0.5']), 0)                    # a server problem is not a wrong password
        with mock.patch.object(directory, 'load', directory.defaults):
            with self.assertRaises(AuthError):
                self.a.login('anna', 'pw', '10.0.0.6', 'ldap')

    def test_what_a_directory_user_cannot_do_here(self):
        tok = self.a.login('anna', 'pw', '10.0.0.7', 'ldap')
        with self.assertRaises(AuthError):
            self.a.change_own_password('ldap:anna', 'pw', 'Another-pass-1', tok, '10.0.0.7')
        for kw in ({'role': 'viewer'}, {'password': 'Another-pass-1'}):
            with self.subTest(kw), self.assertRaises(AuthError):
                self.a.update_user('admin', 'ldap:anna', **kw)
        self.a.check_password('ldap:anna', 'pw', '10.0.0.7')                 # confirmed by the directory
        with self.assertRaises(AuthError):
            self.a.check_password('ldap:anna', 'nope', '10.0.0.7')
        self.a.delete_user('admin', 'ldap:anna')                              # removed; comes back at the next sign-in
        self.assertNotIn('ldap:anna', self.a.users)

    def test_a_local_administrator_always_remains(self):
        self.a.login('anna', 'pw', '10.0.0.8', 'ldap')                        # a directory admin does not count
        self.a._set_password('second', 'Second-pass-1', role='viewer')
        with self.assertRaises(AuthError):
            self.a.update_user('second', 'admin', role='viewer')
        with self.assertRaises(AuthError):
            self.a.delete_user('second', 'admin')

    def test_local_sign_in_unchanged(self):
        self.assertEqual(self.a.session_user(self.a.login('admin', 'flowsphera', '10.0.0.9')), 'admin')     # no method = local
        with self.assertRaises(AuthError):
            self.a.login('anna', 'pw', '10.0.0.9')                             # a directory user does not sign in locally


if __name__ == '__main__':
    unittest.main()
