"""Backups (backup.py): the encryption of copies survives every size and refuses a wrong passphrase, a cut or
tampered file; chains and keeping; the schedule picks full or the changes; settings from the UI are checked and
secrets never go back to the browser; the files of a ClickHouse backup are checked against its list; a restore of the
settings leaves out what belongs to this server. Run: python -m unittest discover -s tests"""
import io
import json
import os
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
os.environ.setdefault('FT_STATE_DIR', tempfile.mkdtemp())
os.environ.setdefault('FT_CONFIG_DIR', tempfile.mkdtemp())
os.environ['FT_BACKUP_DIR'] = tempfile.mkdtemp()
import backup  # noqa: E402


def roundtrip(data, pp='correct horse battery'):
    enc = io.BytesIO()
    backup.encrypt_stream(io.BytesIO(data), enc, pp)
    out = io.BytesIO()
    backup.decrypt_stream(io.BytesIO(enc.getvalue()), out, pp)
    return enc.getvalue(), out.getvalue()


class Encryption(unittest.TestCase):
    def test_sizes(self):
        for n in (0, 1, backup.CHUNK - 1, backup.CHUNK, backup.CHUNK + 1, 3 * backup.CHUNK):
            data = os.urandom(n)
            enc, out = roundtrip(data)
            self.assertEqual(out, data, n)
            self.assertTrue(enc.startswith(backup.MAGIC))
            if n >= 64:
                self.assertNotIn(data[:64], enc)                      # nothing of the plain text shows

    def test_wrong_passphrase(self):
        enc, _ = roundtrip(b'secret settings')
        with self.assertRaises(backup.BackupError) as e:
            backup.decrypt_stream(io.BytesIO(enc), io.BytesIO(), 'another passphrase')
        self.assertIn('passphrase', str(e.exception))

    def test_cut_or_tampered(self):
        enc, _ = roundtrip(os.urandom(2 * backup.CHUNK + 10))
        one = len(backup.MAGIC) + 24 + 4 + backup.CHUNK + 16          # the header and the first chunk
        for bad in (enc[:one],                                        # a whole chunk and the last one dropped
                    enc[:-5],                                         # cut inside the last chunk
                    enc[:one + 100] + bytes([enc[one + 100] ^ 1]) + enc[one + 101:],   # one bit flipped
                    enc + b'x'):                                      # bytes after the end
            with self.assertRaises(backup.BackupError):
                backup.decrypt_stream(io.BytesIO(bad), io.BytesIO(), 'correct horse battery')

    def test_not_ours(self):
        with self.assertRaises(backup.BackupError):
            backup.decrypt_stream(io.BytesIO(b'PK\x03\x04 a zip'), io.BytesIO(), 'x' * 10)


def man(bid, kind='full', base=None, t=None, **kw):
    return {'id': bid, 'kind': kind, 'base': base, 't': t or 0, 'size': 1, 'places': {'local': 'ok'}, 'errors': {}, **kw}


class Chains(unittest.TestCase):
    def test_chains_newest_first(self):
        ms = [man('20261001-030000'), man('20261002-030000', 'diff', '20261001-030000'), man('20261008-030000'),
              man('20261009-030000', 'diff', '20261008-030000'), man('20261010-030000', 'diff', '20261008-030000')]
        c = backup.chains(ms)
        self.assertEqual([[m['id'] for m in x] for x in c],
                         [['20261010-030000', '20261009-030000', '20261008-030000'], ['20261002-030000', '20261001-030000']])

    def test_orphan_diff_is_its_own_chain(self):
        c = backup.chains([man('20261009-030000', 'diff', '20261001-000000'), man('20261008-030000')])
        self.assertEqual(len(c), 2)

    def test_prune_keeps_newest_chains(self):
        d = tempfile.mkdtemp()
        ms = [man('20261001-030000'), man('20261002-030000', 'diff', '20261001-030000'), man('20261008-030000'), man('20261015-030000')]
        for m in ms:
            os.makedirs(os.path.join(d, m['id']))
            with open(os.path.join(d, m['id'], 'manifest.json'), 'w') as f:
                json.dump(m, f)
        with mock.patch.object(backup, 'DIR', d):
            cfg = backup.defaults()
            cfg['keep_full'] = 2
            gone = backup.prune(cfg, log=lambda *a: None)
            self.assertEqual(gone, {'20261001-030000', '20261002-030000'})
            self.assertEqual(sorted(os.listdir(d)), ['20261008-030000', '20261015-030000'])


class PruneErrors(unittest.TestCase):
    """1.8.8: what keeping could not delete is said (log, status, exit code), never passed over in silence."""
    def folder(self, ids):
        d = tempfile.mkdtemp()
        for bid in ids:
            os.makedirs(os.path.join(d, bid))
            with open(os.path.join(d, bid, 'manifest.json'), 'w') as f:
                json.dump(man(bid), f)
        return d

    def test_a_folder_that_cannot_go_is_reported_and_the_rest_go(self):
        d = self.folder(['20261001-030000', '20261008-030000', '20261015-030000'])
        real = backup.shutil.rmtree
        def rmtree(p, *a, **k):
            if p.endswith('20261001-030000'):
                raise PermissionError(13, 'Permission denied', p)
            return real(p, *a, **k)
        cfg, errs, logged = backup.defaults(), [], []
        cfg['keep_full'] = 1
        with mock.patch.object(backup, 'DIR', d), mock.patch.object(backup.shutil, 'rmtree', rmtree):
            gone = backup.prune(cfg, log=logged.append, errors=errs)
        self.assertEqual(gone, {'20261008-030000'})
        self.assertEqual(len(errs), 1)
        self.assertIn('20261001-030000', errs[0])
        self.assertFalse(any('Deleted' in x and '20261001' in x for x in logged))

    def test_a_place_that_refuses_is_reported(self):
        d = self.folder(['20261008-030000', '20261015-030000'])
        place = mock.Mock()
        place.list.return_value = ['20261008-030000.ftbk', '20261008-030000.json', '20261015-030000.ftbk', '20261015-030000.json']
        place.delete.side_effect = backup.BackupError('SFTP: refused')
        cfg, errs = backup.defaults(), []
        cfg['keep_full'], cfg['sftp']['on'] = 1, True
        with mock.patch.object(backup, 'DIR', d), mock.patch.object(backup, 'open_dest', return_value=place):
            backup.prune(cfg, log=lambda *a: None, errors=errs)
        self.assertTrue(errs and 'SFTP' in errs[0], errs)

    def test_run_records_it_and_the_slot_is_done(self):
        st = {}
        with mock.patch.object(backup, 'make', return_value=man('20261015-030000')), \
                mock.patch.object(backup, 'copy_out', return_value={}), \
                mock.patch.object(backup, 'prune', side_effect=RuntimeError('boom')), \
                mock.patch.object(backup, 'status', side_effect=lambda **kw: st.update(kw)), \
                mock.patch.object(backup, 'write_index'):
            backup.run(slot=123, log=lambda *a: None)
        self.assertEqual(st['last_slot'], 123)                 # no new backup every 5 minutes
        self.assertTrue(st['last']['ok'])
        self.assertIn('boom', st['last']['prune_error'])


class DeleteByHand(unittest.TestCase):
    """1.8.8: Settings → Backups → Delete…: a full backup takes its changes; the admin's own password confirms it."""
    def folder(self, ms):
        d = tempfile.mkdtemp()
        for m in ms:
            os.makedirs(os.path.join(d, m['id']))
            with open(os.path.join(d, m['id'], 'manifest.json'), 'w') as f:
                json.dump(m, f)
        return d

    def test_full_takes_its_changes_and_unknown_is_said(self):
        d = self.folder([man('20261001-030000'), man('20261002-030000', 'diff', '20261001-030000'), man('20261008-030000'),
                         man('20261009-030000', 'diff', '20261008-030000')])
        errs = []
        with mock.patch.object(backup, 'DIR', d):
            gone = backup.delete(['20261001-030000', '20261020-030000'], log=lambda *a: None, errors=errs)
        self.assertEqual(gone, {'20261001-030000', '20261002-030000'})
        self.assertEqual(sorted(os.listdir(d)), ['20261008-030000', '20261009-030000'])
        self.assertEqual(len(errs), 1)
        self.assertIn('20261020-030000', errs[0])

    def test_a_change_alone(self):
        d = self.folder([man('20261008-030000'), man('20261009-030000', 'diff', '20261008-030000')])
        with mock.patch.object(backup, 'DIR', d):
            self.assertEqual(backup.delete(['20261009-030000'], log=lambda *a: None), {'20261009-030000'})
        self.assertEqual(os.listdir(d), ['20261008-030000'])

    def test_copies_only_when_asked(self):
        d = self.folder([man('20261008-030000')])
        place = mock.Mock()
        place.list.return_value = ['20261008-030000.ftbk', '20261008-030000.json']
        cfg = backup.defaults()
        cfg['sftp']['on'] = True
        with mock.patch.object(backup, 'DIR', d), mock.patch.object(backup, 'open_dest', return_value=place), mock.patch.object(backup, 'load', return_value=cfg):
            backup.delete(['20261008-030000'], log=lambda *a: None)
            place.delete.assert_not_called()
        d = self.folder([man('20261008-030000')])
        with mock.patch.object(backup, 'DIR', d), mock.patch.object(backup, 'open_dest', return_value=place), mock.patch.object(backup, 'load', return_value=cfg):
            backup.delete(['20261008-030000'], copies=True, log=lambda *a: None)
        self.assertEqual(sorted(c.args[0] for c in place.delete.call_args_list), ['20261008-030000.ftbk', '20261008-030000.json'])


class Schedule(unittest.TestCase):
    def cfg(self, **s):
        c = backup.defaults()
        c['schedule'].update(s)
        return c

    def at(self, y, mo, day, h, mi=0):
        return time.mktime((y, mo, day, h, mi, 0, 0, 0, -1))

    def test_slot(self):
        c = self.cfg(time='03:00')
        self.assertEqual(backup._slot(c, self.at(2026, 10, 14, 2, 59)), self.at(2026, 10, 13, 3))
        self.assertEqual(backup._slot(c, self.at(2026, 10, 14, 3, 0)), self.at(2026, 10, 14, 3))
        self.assertEqual(backup.next_run(c, self.at(2026, 10, 14, 12)), self.at(2026, 10, 15, 3))
        self.assertIsNone(backup.next_run(self.cfg(on=False)))

    def test_due(self):
        wed = self.at(2026, 10, 14, 3, 5)                 # a Wednesday
        c = self.cfg(time='03:00', full='week', weekday=0)
        with mock.patch.object(backup, 'manifests', return_value=[]):
            self.assertEqual(backup.due(c, {}, wed), 'full')                       # nothing yet: full
        recent = [man('20261011-030000', t=self.at(2026, 10, 11, 3))]             # last Sunday's full one
        with mock.patch.object(backup, 'manifests', return_value=recent):
            self.assertEqual(backup.due(c, {}, wed), 'diff')
            self.assertIsNone(backup.due(c, {'last_slot': backup._slot(c, wed)}, wed))   # done for today
            self.assertIsNone(backup.due(self.cfg(on=False), {}, wed))
            self.assertEqual(backup.due(self.cfg(full='day'), {}, wed), 'full')
            self.assertEqual(backup.due(self.cfg(weekday=3), {}, wed), 'full')         # Wednesday is the full day
        old = [man('20261001-030000', t=self.at(2026, 10, 1, 3))]                 # the Sunday was missed
        with mock.patch.object(backup, 'manifests', return_value=old):
            self.assertEqual(backup.due(c, {}, wed), 'full')


class Settings(unittest.TestCase):
    def body(self, **kw):
        b = {'schedule': {'on': True, 'time': '02:30', 'full': 'week', 'weekday': 6}, 'keep_full': 3,
             'encrypt': {'on': True, 'passphrase': 'a long passphrase'},
             's3': {'on': True, 'endpoint': 'https://s3.example.com', 'bucket': 'b', 'key_id': 'AK', 'secret': 'SK'},
             'sftp': {'on': True, 'host': 'nas.lan', 'port': 22, 'user': 'u', 'auth': 'key', 'key': 'KEY', 'fingerprint': 'SHA256:x'},
             'ftp': {'on': True, 'host': 'ftp.lan', 'user': 'u', 'password': 'PW'}}
        b.update(kw)
        return b

    def test_public_hides_secrets(self):
        cfg = backup.validate(self.body(), backup.defaults())
        pub = json.dumps(backup.public(cfg))
        for secret in ('SK', 'KEY', 'PW', 'a long passphrase'):
            self.assertNotIn(f'"{secret}"', pub)
        p = backup.public(cfg)
        self.assertTrue(p['s3']['secret_set'] and p['sftp']['key_set'] and p['ftp']['password_set'] and p['encrypt']['set'])

    def test_empty_secret_keeps_stored(self):
        old = backup.validate(self.body(), backup.defaults())
        b = self.body()
        b['s3'] = dict(b['s3'], secret='')
        b['encrypt'] = {'on': True, 'passphrase': ''}
        b['ftp'] = dict(b['ftp'], password='')
        cfg = backup.validate(b, old)
        self.assertEqual((cfg['s3']['secret'], cfg['encrypt']['passphrase'], cfg['ftp']['password']), ('SK', 'a long passphrase', 'PW'))

    def test_new_sftp_server_needs_its_key_again(self):
        old = backup.validate(self.body(), backup.defaults())
        b = self.body()
        b['sftp'] = dict(b['sftp'], host='other.lan')
        del b['sftp']['fingerprint']
        with self.assertRaises(ValueError):
            backup.validate(b, old)

    def test_refused(self):
        for kw in ({'keep_full': 0}, {'keep_full': 61}, {'schedule': {'time': '3:00 PM'}}, {'encrypt': {'on': True, 'passphrase': 'short'}},
                   {'s3': {'on': True, 'bucket': ''}}, {'ftp': {'on': True, 'host': 'bad host!'}}, {'sftp': {'on': True, 'host': 'h', 'user': 'u', 'port': 70000}}):
            with self.assertRaises(ValueError, msg=kw):
                backup.validate(self.body(**kw), backup.defaults())


class Files(unittest.TestCase):
    def test_check_files(self):
        d = tempfile.mkdtemp()
        data = os.path.join(d, 'B', 'data')
        os.makedirs(os.path.join(data, 'data', 't', 'p1'))
        with open(os.path.join(data, 'data', 't', 'p1', 'data.bin'), 'wb') as f:
            f.write(b'x' * 100)
        meta = os.path.join(data, '.backup')
        with open(meta, 'w') as f:
            f.write('<config><contents>'
                    '<file><name>data/t/p1/data.bin</name><size>100</size></file>'
                    '<file><name>data/t/p0/data.bin</name><size>50</size><use_base>true</use_base></file>'    # in the base backup
                    '<file><name>data/t/p1/empty.txt</name><size>0</size></file>'
                    '</contents></config>')
        with mock.patch.object(backup, 'DIR', d):
            self.assertEqual(backup._check_files('B', meta), [])
            with open(os.path.join(data, 'data', 't', 'p1', 'data.bin'), 'wb') as f:
                f.write(b'x' * 99)
            self.assertEqual(len(backup._check_files('B', meta)), 1)
            os.remove(os.path.join(data, 'data', 't', 'p1', 'data.bin'))
            self.assertIn('missing', backup._check_files('B', meta)[0])


class RestoreSettings(unittest.TestCase):
    def test_what_is_left_out(self):
        src = tempfile.mkdtemp()
        cfgd, state = backup.CONFIG_DIR.lstrip('/'), backup.STATE_DIR.lstrip('/')
        files = {f'{cfgd}/exporters.json': '{}', f'{cfgd}/env': 'FT_CH_PASSWORD=old', f'{cfgd}/tls/cert.pem': 'C',
                 f'{state}/users.json': 'U', f'{state}/license.key': 'L', f'{state}/hw.board': 'H', f'{state}/sessions.json': 'S',
                 f'{state}/backup.json': 'B', f'{state}/backup_status.json': 'X', 'etc/passwd': 'evil'}
        tp = os.path.join(src, 's.tar.gz')
        with tarfile.open(tp, 'w:gz') as t:
            for n, v in files.items():
                ti = tarfile.TarInfo(n)
                ti.size = len(v)
                t.addfile(ti, io.BytesIO(v.encode()))
        for with_license, lic in ((False, False), (True, True)):
            root = tempfile.mkdtemp()
            backup._restore_settings(tp, with_license, root=root)
            have = {os.path.relpath(os.path.join(r, n), root) for r, _, fs in os.walk(root) for n in fs}
            self.assertEqual(have, {f'{cfgd}/exporters.json', f'{cfgd}/tls/cert.pem', f'{state}/users.json', f'{state}/backup.json'}
                             | ({f'{state}/license.key'} if lic else set()))


if __name__ == '__main__':
    unittest.main()
