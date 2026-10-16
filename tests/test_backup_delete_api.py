"""1.8.8: POST /api/backups/delete asks root's backup service only after the signed-in admin's own password; wrong
ones count with the failed logins. Run: python -m unittest discover -s tests"""
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
import backup  # noqa: E402
from auth import Auth, AuthError  # noqa: E402


class DeleteApi(unittest.TestCase):
    def setUp(self):
        api.AUTH = Auth()
        api.AUTH._set_password('boss', 'right-password-1', role='admin')
        backup.REQUEST = os.path.join(TMP, 'state', 'backup.request')
        if os.path.exists(backup.REQUEST):
            os.remove(backup.REQUEST)

    def test_right_password_asks_the_service(self):
        api.post_backups_delete({'ids': ['20261008-030000'], 'password': 'right-password-1', 'copies': True}, 'boss', '10.0.0.9')
        with open(backup.REQUEST) as f:
            req = json.load(f)
        self.assertEqual((req['do'], req['ids'], req['copies']), ('delete', ['20261008-030000'], True))

    def test_wrong_password_asks_nothing_and_counts(self):
        for _ in range(5):
            with self.assertRaises(AuthError) as c:
                api.post_backups_delete({'ids': ['20261008-030000'], 'password': 'nope'}, 'boss', '10.0.0.8')
            self.assertEqual(c.exception.status, 400)        # 401 would sign the admin out
        self.assertFalse(os.path.exists(backup.REQUEST))
        with self.assertRaises(AuthError) as c:              # then even the right one waits
            api.post_backups_delete({'ids': ['20261008-030000'], 'password': 'right-password-1'}, 'boss', '10.0.0.8')
        self.assertEqual(c.exception.status, 429)

    def test_login_still_works_and_shares_the_count(self):
        tok = api.AUTH.login('boss', 'right-password-1', '10.0.0.6')
        self.assertEqual(api.AUTH.session_user(tok), 'boss')
        self.assertTrue(api.AUTH.users['boss']['last_login'])
        with self.assertRaises(AuthError):
            api.AUTH.login('boss', 'nope', '10.0.0.6')
        api.AUTH.check_password('boss', 'right-password-1', '10.0.0.6')      # a right one clears the count

    def test_own_map_view(self):                 # (1.9.0) each user's default Path analysis view, kept with the account
        self.assertEqual(api.AUTH.public('boss')['prefs'], {})
        self.assertEqual(api.AUTH.set_prefs('boss', {'path_view': 'metro'})['prefs'], {'path_view': 'metro'})
        self.assertEqual(Auth().public('boss')['prefs'], {'path_view': 'metro'})          # saved: a new instance reads it
        for bad in ({'path_view': 'nope'}, {'colour': 'red'}, 'x'):
            with self.assertRaises(AuthError):
                api.AUTH.set_prefs('boss', bad)

    def test_bad_ids(self):
        for ids in ([], ['../etc'], 'x', ['20261008-030000'] * 101):
            with self.assertRaises(api.BadRequest):
                api.post_backups_delete({'ids': ids, 'password': 'right-password-1'}, 'boss', '10.0.0.7')


if __name__ == '__main__':
    unittest.main()
