"""1.9.4 security review: root's backup service never follows a link the flowsphera user left in its folder; a restore
of the settings neither writes through links nor sets setuid bits; a copy's manifest cannot name a folder elsewhere;
wrong current passwords count as failed logins; bad filter values are a 400, not a database error.
Run: python -m unittest discover -s tests"""
import io
import json
import os
import shutil
import stat
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

TMP = tempfile.mkdtemp()
os.makedirs(TMP + '/cfg', exist_ok=True), os.makedirs(TMP + '/state', exist_ok=True)
open(TMP + '/cfg/exporters.json', 'w').write('{}')
os.environ.update(FT_CONFIG_DIR=TMP + '/cfg', FT_STATE_DIR=TMP + '/state', FT_BACKUP_DIR=tempfile.mkdtemp())
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import api  # noqa: E402
import backup  # noqa: E402
from auth import Auth, AuthError  # noqa: E402


class NoLinks(unittest.TestCase):
    def test_write_json_does_not_follow_a_link(self):
        d = tempfile.mkdtemp()
        victim = os.path.join(d, 'victim')
        with open(victim, 'w') as f:
            f.write('SECRET')
        os.chmod(victim, 0o600)
        path = os.path.join(d, 'status.json')
        os.symlink(victim, path + '.tmp')
        backup._write_json(path, {'ok': 1})
        with open(victim) as f:
            self.assertEqual(f.read(), 'SECRET')
        self.assertEqual(stat.S_IMODE(os.stat(victim).st_mode), 0o600)
        self.assertFalse(os.path.islink(path))
        with open(path) as f:
            self.assertEqual(json.load(f), {'ok': 1})
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o644)

    def _tar(self, files, mode=0o644):
        tp = os.path.join(tempfile.mkdtemp(), 's.tar.gz')
        with tarfile.open(tp, 'w:gz') as t:
            for n, v in files.items():
                ti = tarfile.TarInfo(n)
                ti.size, ti.mode = len(v), mode
                t.addfile(ti, io.BytesIO(v.encode()))
        return tp

    def test_restore_settings_replaces_a_link(self):
        state = backup.STATE_DIR.lstrip('/')
        tp = self._tar({f'{state}/users.json': 'U'}, mode=0o4755)
        root, outside = tempfile.mkdtemp(), tempfile.mkdtemp()
        victim = os.path.join(outside, 'victim')
        with open(victim, 'w') as f:
            f.write('SECRET')
        os.makedirs(os.path.join(root, state))
        os.symlink(victim, os.path.join(root, state, 'users.json'))
        backup._restore_settings(tp, False, root=root)
        with open(victim) as f:
            self.assertEqual(f.read(), 'SECRET')
        got = os.path.join(root, state, 'users.json')
        self.assertFalse(os.path.islink(got))
        self.assertEqual(stat.S_IMODE(os.stat(got).st_mode), 0o755)          # no setuid

    def test_restore_settings_stops_at_a_linked_folder(self):
        state = backup.STATE_DIR.lstrip('/')
        tp = self._tar({f'{state}/reports/x.json': 'X'})
        root, outside = tempfile.mkdtemp(), tempfile.mkdtemp()
        os.makedirs(os.path.join(root, state))
        os.symlink(outside, os.path.join(root, state, 'reports'))
        with self.assertRaises(backup.BackupError):
            backup._restore_settings(tp, False, root=root)
        self.assertEqual(os.listdir(outside), [])

    def test_prefix_is_a_folder(self):
        cfgd = backup.CONFIG_DIR.lstrip('/')
        tp = self._tar({f'{cfgd}-evil/x': 'X', f'{cfgd}/exporters.json': '{}'})
        root = tempfile.mkdtemp()
        backup._restore_settings(tp, False, root=root)
        self.assertFalse(os.path.exists(os.path.join(root, f'{cfgd}-evil')))
        self.assertTrue(os.path.exists(os.path.join(root, cfgd, 'exporters.json')))

    def test_fetch_refuses_a_base_outside(self):
        src = tempfile.mkdtemp()
        with open(os.path.join(src, '20261017-030000.json'), 'w') as f:
            json.dump({'id': '20261017-030000', 'base': '../../etc'}, f)
        open(os.path.join(src, '20261017-030000.ftbk'), 'w').close()
        with mock.patch.object(backup, '_ensure_dir'), self.assertRaises(backup.BackupError):
            backup.fetch(src, '20261017-030000', backup.defaults(), log=lambda *a: None)


class EncryptedOnly(unittest.TestCase):
    def _place(self, encrypted):
        src = tempfile.mkdtemp()
        bid = '20261017-040000'
        with open(os.path.join(src, bid + '.json'), 'w') as f:
            json.dump({'id': bid}, f)
        tp = os.path.join(src, 'x.tar')
        with tarfile.open(tp, 'w') as t:
            ti = tarfile.TarInfo('manifest.json')
            body = json.dumps({'id': bid, 't': 0, 'version': '1.9.4', 'tables': {}}).encode()
            ti.size = len(body)
            t.addfile(ti, io.BytesIO(body))
        with open(tp, 'rb') as fi, open(os.path.join(src, bid + '.ftbk'), 'wb') as fo:
            if encrypted:
                backup.encrypt_stream(fi, fo, 'the right passphrase')
            else:
                fo.write(fi.read())
        return src, bid

    def test_plain_copy_refused_while_encrypting(self):
        cfg = backup.defaults()
        cfg['encrypt'] = {'on': True, 'passphrase': 'the right passphrase'}
        src, bid = self._place(False)
        with mock.patch.object(backup, '_ensure_dir'), self.assertRaises(backup.BackupError) as e:
            backup.fetch(src, bid, cfg, log=lambda *a: None)
        self.assertIn('--unencrypted', str(e.exception))
        self.assertFalse(os.path.exists(os.path.join(backup.DIR, bid)))
        with mock.patch.object(backup, '_ensure_dir'), mock.patch.object(os, 'chown'):
            self.assertEqual(backup.fetch(src, bid, cfg, log=lambda *a: None, unencrypted=True)['id'], bid)
        src, bid2 = self._place(True)                                  # an encrypted one is fine
        shutil.rmtree(os.path.join(backup.DIR, bid2))
        with mock.patch.object(backup, '_ensure_dir'), mock.patch.object(os, 'chown'):
            self.assertEqual(backup.fetch(src, bid2, cfg, log=lambda *a: None)['id'], bid2)

    def test_hostile_header(self):
        enc = io.BytesIO()
        backup.encrypt_stream(io.BytesIO(b'x' * 100), enc, 'pp-pp-pp-pp')
        raw = bytearray(enc.getvalue())
        bad = raw[:]
        bad[len(backup.MAGIC) + 16] = 40                             # scrypt cost 2^40
        with self.assertRaises(backup.BackupError):
            backup.decrypt_stream(io.BytesIO(bytes(bad)), io.BytesIO(), 'pp-pp-pp-pp')
        bad = raw[:len(backup.MAGIC) + 24] + struct.pack('>I', 0xFFFFFFF0)    # a 4 GB chunk
        with self.assertRaises(backup.BackupError):
            backup.decrypt_stream(io.BytesIO(bytes(bad)), io.BytesIO(), 'pp-pp-pp-pp')


class OwnPassword(unittest.TestCase):
    def test_wrong_current_passwords_count(self):
        a = Auth()
        a._set_password('ann', 'right-password-1', role='viewer')
        for _ in range(5):
            with self.assertRaises(AuthError):
                a.change_own_password('ann', 'wrong', 'new-password-12', None, '10.0.0.7')
        with self.assertRaises(AuthError) as e:
            a.change_own_password('ann', 'right-password-1', 'new-password-12', None, '10.0.0.7')
        self.assertEqual(e.exception.status, 429)


class Filters(unittest.TestCase):
    def test_bad_values_are_400(self):
        for f in ({'k': 'dir', 'v': "'"}, {'k': 'port', 'v': '٣'}, {'k': 'iface', 'v': '١'}):
            with self.assertRaises(api.BadRequest, msg=f):
                api.scope({'f': [json.dumps([f])], 'range': ['1h']})
        api.scope({'f': [json.dumps([{'k': 'dir', 'v': 'up'}])], 'range': ['1h']})


if __name__ == '__main__':
    unittest.main()
