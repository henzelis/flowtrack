#!/usr/bin/env python3
"""Backups (1.8.0): the flow data and every setting, on a schedule, in a folder on this server and as copies on S3,
SFTP or FTP; restore from any of them.

A backup is a folder <DIR>/<id>/ (id = UTC time, YYYYMMDD-HHMMSS):
  data/             ClickHouse BACKUP DATABASE of the flow data (the container sees DIR as /backups)
  settings.tar.gz   /etc/flowtrack and /var/lib/flowtrack
  manifest.json     what it is: kind, base, version, tables, sizes, where the copies went
A full backup stands alone; a differential one (kind 'diff') holds what changed since the full backup it names in
`base` (ClickHouse base_backup) — a restore needs that full one too, nothing else. A full backup with its
differential ones is a chain; keeping counts chains.

A copy off the server is two files: <id>.json (the manifest, no secrets) and <id>.ftbk (a tar of the folder,
encrypted with the passphrase when it is set — AES-256-GCM in 1 MiB chunks, key from scrypt). The folder here is not
encrypted: only root (and ClickHouse) can read it, and ClickHouse needs it as it is for the next differential backup.

Runs as root: flowtrack-backup.service (started every 5 minutes by its timer — the schedule itself is in the
settings — and at once when the web interface asks for a backup through STATE_DIR/backup.request), and
`sudo flowtrack backup …` / `sudo flowtrack restore …`. The web interface reads STATE_DIR/backup_index.json and
backup_status.json and writes the settings (STATE_DIR/backup.json, 0600: S3 / SFTP / FTP secrets, the passphrase)."""
import argparse
import contextlib
import fcntl
import getpass
import hashlib
import io
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import time


def _load_env(path='/etc/flowtrack/env'):
    """The CLI runs outside the services: take the database address and password from the install's env file."""
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except OSError:
        pass


_load_env(os.path.join(os.environ.get('FT_CONFIG_DIR', '/etc/flowtrack'), 'env'))

import common  # noqa: E402
from common import CONFIG_DIR, STATE_DIR, VERSION, CHError, ch, set_lang, tr  # noqa: E402

DIR = os.environ.get('FT_BACKUP_DIR', '/var/backups/flowtrack')       # on the host
CH_DIR = os.environ.get('FT_BACKUP_CH_DIR', '/backups')              # the same folder inside the ClickHouse container
CH_UID = int(os.environ.get('FT_BACKUP_CH_UID', '101'))              # the clickhouse user of the official image
DB = common.CH_DB
CONFIG = os.path.join(STATE_DIR, 'backup.json')
STATUS = os.path.join(STATE_DIR, 'backup_status.json')
INDEX = os.path.join(STATE_DIR, 'backup_index.json')
REQUEST = os.path.join(STATE_DIR, 'backup.request')
SERVICES = ('flowtrack-collector', 'flowtrack-web')
ID_RE = re.compile(r'^\d{8}-\d{6}$')
DESTS = ('s3', 'sftp', 'ftp')
# never restored: what the installer made for this server, the license bound to it, the state of backups themselves
_C, _S = CONFIG_DIR.strip('/'), STATE_DIR.strip('/')
SKIP_RESTORE = (f'{_C}/env', f'{_C}/clickhouse', f'{_C}/install-lang', f'{_S}/hw.board', f'{_S}/sessions.json',
                f'{_S}/backup_status.json', f'{_S}/backup_index.json', f'{_S}/backup.request', f'{_S}/backup.lock', f'{_S}/reputation')
LICENSE_FILES = (f'{_S}/license.',)


# the members are checked here (paths, kinds, modes, links on the way); owners stay as stored (the flowtrack user's
# files stay its own) — Python 3.14's default filter would make them root's
TAR_AS_CHECKED = {'filter': 'fully_trusted'} if hasattr(tarfile, 'fully_trusted_filter') else {}


class BackupError(Exception):
    pass


def _sys(q, **kw):
    """DDL on whole databases runs in the `system` database: common.ch() names the flow database for every query,
    and that one does not exist while a restore has set it aside."""
    return ch(q, settings={'database': 'system'}, **kw)


def _db_exists(name):
    return bool(int(_sys("SELECT count() AS n FROM system.databases WHERE name = {db:String}", params={'db': name}, fmt='JSON')[0]['n']))


# ---------------------------------------------------------------- settings

def defaults():
    return {'schedule': {'on': True, 'time': '03:00', 'full': 'week', 'weekday': 0}, 'keep_full': 4,
            'encrypt': {'on': False, 'passphrase': ''},
            's3': {'on': False, 'endpoint': '', 'region': '', 'bucket': '', 'prefix': '', 'key_id': '', 'secret': ''},
            'sftp': {'on': False, 'host': '', 'port': 22, 'user': '', 'auth': 'key', 'password': '', 'key': '', 'path': '', 'fingerprint': ''},
            'ftp': {'on': False, 'host': '', 'port': 21, 'tls': True, 'verify': True, 'user': '', 'password': '', 'path': ''}}


def load():
    cfg = defaults()
    try:
        with open(CONFIG) as f:
            saved = json.load(f)
    except (OSError, ValueError):
        return cfg
    for k, v in saved.items():
        if isinstance(cfg.get(k), dict) and isinstance(v, dict):
            cfg[k].update(v)
        elif k in cfg:
            cfg[k] = v
    return cfg


def save(cfg):
    _write_json(CONFIG, cfg, 0o600)


def _write_json(path, obj, mode=0o644):
    # the service runs as root and writes into STATE_DIR, which the flowtrack user owns: a link left there in place of
    # the temporary file must never be followed (it would overwrite and chmod any file of the system)
    tmp = path + '.tmp'
    with contextlib.suppress(FileNotFoundError):
        os.unlink(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'w') as f:
        os.fchmod(f.fileno(), mode)
        json.dump(obj, f, indent=1, ensure_ascii=False)
    os.replace(tmp, path)


def public(cfg):
    """The settings for the browser: every secret only as 'set or not'."""
    out = json.loads(json.dumps(cfg))
    out['encrypt'] = {'on': cfg['encrypt']['on'], 'set': bool(cfg['encrypt']['passphrase'])}
    out['s3'].update(secret='', secret_set=bool(cfg['s3']['secret']))
    out['sftp'].update(password='', key='', password_set=bool(cfg['sftp']['password']), key_set=bool(cfg['sftp']['key']))
    out['ftp'].update(password='', password_set=bool(cfg['ftp']['password']))
    return out


HOST_RE = re.compile(r'^([A-Za-z0-9_-]{1,63}\.)*[A-Za-z0-9_-]{1,63}$|^[0-9a-fA-F:]{2,39}$')


def validate(body, old):
    """The settings from the UI, checked; an empty secret keeps the stored one. Raises ValueError for people."""
    cfg = defaults()
    s, src = cfg['schedule'], body.get('schedule') or {}
    s['on'] = bool(src.get('on'))
    t = str(src.get('time') or '03:00')
    if not re.fullmatch(r'([01]\d|2[0-3]):[0-5]\d', t):
        raise ValueError(tr('The time looks wrong: HH:MM, e.g. 03:00.'))
    s['time'] = t
    s['full'] = 'day' if src.get('full') == 'day' else 'week'
    try:
        s['weekday'] = min(6, max(0, int(src.get('weekday') or 0)))
        cfg['keep_full'] = int(body['keep_full'] if body.get('keep_full') not in (None, '') else 4)
    except (TypeError, ValueError):
        raise ValueError(tr('A number is expected.')) from None
    if not 1 <= cfg['keep_full'] <= 60:
        raise ValueError(tr('Keep from 1 to 60 full backups.'))
    e, src = cfg['encrypt'], body.get('encrypt') or {}
    e['on'] = bool(src.get('on'))
    p = str(src.get('passphrase') or '')
    if p and len(p) < 10:
        raise ValueError(tr('A passphrase needs at least 10 characters'))
    e['passphrase'] = p or old['encrypt']['passphrase']
    if e['on'] and not e['passphrase']:
        raise ValueError(tr('Enter a passphrase to encrypt the backups.'))

    def text(d, k, n=1000):
        v = str(d.get(k) or '').strip()
        if len(v) > n:
            raise ValueError(tr('{field} is too long.', field=k))
        return v

    def port(d, default):
        try:
            v = int(d.get('port') or default)
        except (TypeError, ValueError):
            raise ValueError(tr('The port is a number from 1 to 65535.')) from None
        if not 1 <= v <= 65535:
            raise ValueError(tr('The port is a number from 1 to 65535.'))
        return v

    def host(d, label):
        h = text(d, 'host', 253)
        if h and not HOST_RE.match(h):
            raise ValueError(tr('{what}: the server name looks wrong.', what=label))
        return h

    x, src = cfg['s3'], body.get('s3') or {}
    x.update(on=bool(src.get('on')), endpoint=text(src, 'endpoint', 300), region=text(src, 'region', 50), bucket=text(src, 'bucket', 63),
             prefix=text(src, 'prefix', 300).lstrip('/'), key_id=text(src, 'key_id', 200), secret=text(src, 'secret', 500) or old['s3']['secret'])
    if x['endpoint'] and not re.match(r'^https?://[^\s/]+', x['endpoint']):
        raise ValueError(tr('S3: the endpoint is an address like https://s3.eu-central-1.amazonaws.com.'))
    if x['on'] and not (x['bucket'] and x['key_id'] and x['secret']):
        raise ValueError(tr('S3: the bucket, the access key ID and the secret key are needed.'))
    x, src = cfg['sftp'], body.get('sftp') or {}
    x.update(on=bool(src.get('on')), host=host(src, 'SFTP'), port=port(src, 22), user=text(src, 'user', 100),
             auth='password' if src.get('auth') == 'password' else 'key', path=text(src, 'path', 500),
             password=text(src, 'password', 500) or old['sftp']['password'], key=str(src.get('key') or '').strip() or old['sftp']['key'],
             fingerprint=text(src, 'fingerprint', 200) if 'fingerprint' in src else old['sftp']['fingerprint'])
    if x['host'] != old['sftp']['host'] or x['port'] != old['sftp']['port']:
        x['fingerprint'] = text(src, 'fingerprint', 200)            # another server: its key is accepted anew
    if x['on'] and not (x['host'] and x['user'] and (x['key'] if x['auth'] == 'key' else x['password'])):
        raise ValueError(tr('SFTP: the server, the user and the key or the password are needed.'))
    if x['on'] and not x['fingerprint']:
        raise ValueError(tr('SFTP: press Test and accept the key of the server first.'))
    x, src = cfg['ftp'], body.get('ftp') or {}
    x.update(on=bool(src.get('on')), host=host(src, 'FTP'), port=port(src, 21), tls=src.get('tls', True) is not False, verify=src.get('verify', True) is not False,
             user=text(src, 'user', 100), path=text(src, 'path', 500), password=text(src, 'password', 500) or old['ftp']['password'])
    if x['on'] and not x['host']:
        raise ValueError(tr('FTP: the server is needed.'))
    return cfg


# ---------------------------------------------------------------- encryption of the copies

MAGIC = b'FTBK1\n'
CHUNK = 1 << 20


def _key(passphrase, salt, log_n=15):
    return hashlib.scrypt(passphrase.encode(), salt=salt, n=1 << log_n, r=8, p=1, maxmem=128 << 20, dklen=32)


def encrypt_stream(src, dst, passphrase):
    """src (file) -> dst (file): header (magic, salt, scrypt cost, nonce prefix) + chunks of [4-byte length][AES-GCM].
    The nonce of a chunk is the prefix, its number and a last-chunk flag: chunks cannot be reordered, dropped or cut."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, prefix, log_n = os.urandom(16), os.urandom(7), 15
    head = MAGIC + salt + bytes([log_n]) + prefix
    aes = AESGCM(_key(passphrase, salt, log_n))
    dst.write(head)
    i, cur = 0, src.read(CHUNK)
    while True:
        nxt = src.read(CHUNK) if cur else b''
        last = not nxt
        ct = aes.encrypt(prefix + struct.pack('>I', i) + (b'\x01' if last else b'\x00'), cur, head)
        dst.write(struct.pack('>I', len(ct)) + ct)
        if last:
            return
        i, cur = i + 1, nxt


def decrypt_stream(src, dst, passphrase):
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    head = src.read(len(MAGIC) + 24)
    if not head.startswith(MAGIC) or len(head) != len(MAGIC) + 24:
        raise BackupError(tr('Not an encrypted FlowSphera backup.'))
    salt, log_n, prefix = head[len(MAGIC):len(MAGIC) + 16], head[len(MAGIC) + 16], head[len(MAGIC) + 17:]
    if not 10 <= log_n <= 20:                  # the file is not trusted: a huge scrypt cost would never finish
        raise BackupError(tr('The backup file is damaged.'))
    aes = AESGCM(_key(passphrase, salt, log_n))
    i = 0
    while True:
        n = src.read(4)
        if len(n) != 4:
            raise BackupError(tr('The backup file is cut short.'))
        size = struct.unpack('>I', n)[0]
        if size > CHUNK + 16:                  # a chunk and its tag: never read gigabytes into memory
            raise BackupError(tr('The backup file is damaged.'))
        ct = src.read(size)
        for last in (False, True):
            try:
                pt = aes.decrypt(prefix + struct.pack('>I', i) + (b'\x01' if last else b'\x00'), ct, head)
                break
            except InvalidTag:
                pt = None
        if pt is None:
            raise BackupError(tr('Wrong passphrase, or the backup file is damaged.') if i == 0 else tr('The backup file is damaged.'))
        dst.write(pt)
        if last:
            if src.read(1):
                raise BackupError(tr('The backup file is damaged.'))
            return
        i += 1


def is_encrypted(path):
    with open(path, 'rb') as f:
        return f.read(len(MAGIC)) == MAGIC


# ---------------------------------------------------------------- places for the copies

class Dest:
    """A place for copies: put / get / list / delete files by name in one folder."""
    name = ''

    def __init__(self, c):
        self.c = c

    def close(self):
        pass

    def test(self):
        """Write, read back and delete a small file. -> a message for people (raises BackupError)."""
        data = b'FlowTrack backup test ' + str(time.time()).encode()
        nm = f'.flowtrack-test-{os.getpid()}'
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 't')
            with open(p, 'wb') as f:
                f.write(data)
            self.put(p, nm)
            self.get(nm, p + '.back')
            with open(p + '.back', 'rb') as f:
                if f.read() != data:
                    raise BackupError(tr('The file read back differs from the one written.'))
            self.delete(nm)
        return tr('OK — wrote, read and deleted a test file.')


class S3(Dest):
    name = 's3'

    def __init__(self, c):
        super().__init__(c)
        import boto3
        from botocore.config import Config
        self.cli = boto3.client('s3', endpoint_url=c['endpoint'] or None, region_name=c['region'] or None,
                                aws_access_key_id=c['key_id'], aws_secret_access_key=c['secret'],
                                config=Config(connect_timeout=10, read_timeout=60, retries={'max_attempts': 3}, s3={'addressing_style': 'auto'}))
        self.pre = (c['prefix'].strip('/') + '/') if c['prefix'].strip('/') else ''

    def _err(self, e):
        from botocore.exceptions import BotoCoreError, ClientError
        if isinstance(e, ClientError):
            err = e.response.get('Error', {})
            return BackupError(f"S3: {err.get('Code', '')} {err.get('Message', '')}".strip())
        if isinstance(e, BotoCoreError):
            return BackupError(f'S3: {e}')
        return e

    def put(self, path, name, progress=None):
        try:
            self.cli.upload_file(path, self.c['bucket'], self.pre + name, Callback=progress)
        except Exception as e:
            raise self._err(e) from None

    def get(self, name, path, progress=None):
        try:
            self.cli.download_file(self.c['bucket'], self.pre + name, path, Callback=progress)
        except Exception as e:
            raise self._err(e) from None

    def list(self):
        try:
            out, tok = [], None
            while True:
                kw = {'Bucket': self.c['bucket'], 'Prefix': self.pre}
                if tok:
                    kw['ContinuationToken'] = tok
                r = self.cli.list_objects_v2(**kw)
                out += [o['Key'][len(self.pre):] for o in r.get('Contents', []) if '/' not in o['Key'][len(self.pre):]]
                if not r.get('IsTruncated'):
                    return out
                tok = r['NextContinuationToken']
        except Exception as e:
            raise self._err(e) from None

    def delete(self, name):
        try:
            self.cli.delete_object(Bucket=self.c['bucket'], Key=self.pre + name)
        except Exception as e:
            raise self._err(e) from None


def sftp_fingerprint(key):
    import base64
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


class SFTP(Dest):
    name = 'sftp'

    def __init__(self, c, accept_any=False):
        super().__init__(c)
        import paramiko
        self.paramiko = paramiko
        try:
            sock = socket.create_connection((c['host'], int(c['port'])), timeout=10)
        except OSError as e:
            raise BackupError(tr('No answer from {host}:{port}: {err}', host=c['host'], port=c['port'], err=e)) from None
        # never SHA-1 RSA signatures (ssh-rsa; CVE-2026-44405): RSA keys still work with rsa-sha2-256/512
        self.t = paramiko.Transport(sock, disabled_algorithms={'keys': ['ssh-rsa'], 'pubkeys': ['ssh-rsa']})
        try:
            self.t.start_client(timeout=15)
            self.fingerprint = sftp_fingerprint(self.t.get_remote_server_key())
            if not accept_any and self.fingerprint != c['fingerprint']:
                raise BackupError(tr('SFTP: the key of the server changed ({fp}) — copies stop until you test and accept it.', fp=self.fingerprint)
                                  if c['fingerprint'] else tr('SFTP: press Test and accept the key of the server first.'))
            if c['auth'] == 'key':
                self.t.auth_publickey(c['user'], self._pkey(c['key']))
            else:
                self.t.auth_password(c['user'], c['password'])
            self.s = paramiko.SFTPClient.from_transport(self.t)
            self.s.get_channel().settimeout(60)
        except paramiko.AuthenticationException:
            self.t.close()
            raise BackupError(tr('SFTP: the server did not accept the user and the key or the password.')) from None
        except paramiko.SSHException as e:
            self.t.close()
            raise BackupError(f'SFTP: {e}') from None
        except BackupError:
            self.t.close()
            raise
        self.dir = c['path'].rstrip('/') or '.'
        self._mkdirs()

    def _pkey(self, text):
        p = self.paramiko
        for cls in (p.Ed25519Key, p.ECDSAKey, p.RSAKey):
            try:
                return cls.from_private_key(io.StringIO(text))
            except (p.SSHException, ValueError):
                continue
        raise BackupError(tr('SFTP: the private key is not an OpenSSH key FlowSphera can read (without a passphrase).'))

    def _mkdirs(self):
        if self.dir in ('.', '/'):
            return
        cur = '/' if self.dir.startswith('/') else ''
        for part in self.dir.strip('/').split('/'):
            cur = f'{cur}{part}/'
            try:
                self.s.stat(cur)
            except OSError:
                try:
                    self.s.mkdir(cur)
                except OSError as e:
                    raise BackupError(tr('SFTP: cannot create the folder {path}: {err}', path=cur, err=e)) from None

    def close(self):
        with contextlib.suppress(Exception):
            self.t.close()

    def _p(self, name):
        return f'{self.dir}/{name}'

    def put(self, path, name, progress=None):
        try:
            self.s.put(path, self._p(name) + '.part', callback=(lambda a, b: progress(a)) if progress else None)
            with contextlib.suppress(OSError):
                self.s.remove(self._p(name))
            self.s.rename(self._p(name) + '.part', self._p(name))
        except (OSError, self.paramiko.SSHException) as e:
            raise BackupError(f'SFTP: {e}') from None

    def get(self, name, path, progress=None):
        try:
            self.s.get(self._p(name), path, callback=(lambda a, b: progress(a)) if progress else None)
        except (OSError, self.paramiko.SSHException) as e:
            raise BackupError(f'SFTP: {e}') from None

    def list(self):
        try:
            return self.s.listdir(self.dir)
        except (OSError, self.paramiko.SSHException) as e:
            raise BackupError(f'SFTP: {e}') from None

    def delete(self, name):
        try:
            self.s.remove(self._p(name))
        except (OSError, self.paramiko.SSHException) as e:
            raise BackupError(f'SFTP: {e}') from None


class FTP(Dest):
    name = 'ftp'

    def __init__(self, c):
        super().__init__(c)
        import ftplib
        import ssl
        self.ftplib = ftplib
        try:
            if c['tls']:
                ctx = ssl.create_default_context()
                if not c['verify']:
                    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                self.f = ftplib.FTP_TLS(context=ctx, timeout=30)
            else:
                self.f = ftplib.FTP(timeout=30)
            self.f.connect(c['host'], int(c['port']))
            self.f.login(c['user'] or 'anonymous', c['password'])
            if c['tls']:
                self.f.prot_p()
            self.f.set_pasv(True)
        except (OSError, EOFError, ftplib.Error) as e:
            with contextlib.suppress(Exception):
                self.f.close()
            raise BackupError(tr('FTP: {err}', err=self._why(e))) from None
        self.dir = c['path'].rstrip('/')
        if self.dir:
            self._mkdirs()

    @staticmethod
    def _why(e):
        import ssl
        if isinstance(e, ssl.SSLCertVerificationError):
            return tr('the certificate of the server is not trusted ({err}) — or untick “Verify the certificate”', err=e.verify_message)
        return str(e) or e.__class__.__name__

    def _mkdirs(self):
        cur = '/' if self.dir.startswith('/') else ''
        for part in self.dir.strip('/').split('/'):
            cur = f'{cur}{part}/'
            try:
                self.f.cwd(cur)
            except self.ftplib.error_perm:
                try:
                    self.f.mkd(cur)
                except self.ftplib.Error as e:
                    raise BackupError(tr('FTP: cannot create the folder {path}: {err}', path=cur, err=e)) from None
        self.f.cwd(self.dir or '/')

    def close(self):
        with contextlib.suppress(Exception):
            self.f.quit()

    def put(self, path, name, progress=None):
        try:
            with open(path, 'rb') as fh:
                self.f.storbinary(f'STOR {name}.part', fh, blocksize=1 << 16, callback=(lambda b: progress(len(b))) if progress else None)
            with contextlib.suppress(self.ftplib.error_perm):
                self.f.delete(name)
            self.f.rename(f'{name}.part', name)
        except (OSError, EOFError, self.ftplib.Error) as e:
            raise BackupError(tr('FTP: {err}', err=self._why(e))) from None

    def get(self, name, path, progress=None):
        try:
            with open(path, 'wb') as fh:
                def w(b):
                    fh.write(b)
                    if progress:
                        progress(len(b))
                self.f.retrbinary(f'RETR {name}', w, blocksize=1 << 16)
        except (OSError, EOFError, self.ftplib.Error) as e:
            raise BackupError(tr('FTP: {err}', err=self._why(e))) from None

    def list(self):
        try:
            return [n.rsplit('/', 1)[-1] for n in self.f.nlst()]
        except self.ftplib.error_perm as e:            # an empty folder answers 550 on some servers
            if str(e).startswith('550'):
                return []
            raise BackupError(tr('FTP: {err}', err=e)) from None
        except (OSError, EOFError, self.ftplib.Error) as e:
            raise BackupError(tr('FTP: {err}', err=self._why(e))) from None

    def delete(self, name):
        try:
            self.f.delete(name)
        except (OSError, EOFError, self.ftplib.Error) as e:
            raise BackupError(tr('FTP: {err}', err=self._why(e))) from None


def open_dest(kind, c, **kw):
    return {'s3': S3, 'sftp': SFTP, 'ftp': FTP}[kind](c, **kw)


def test_dest(kind, c):
    """For the web interface: -> {'ok', 'message', 'fingerprint'?}. A new SFTP server answers with its key to accept."""
    d = None
    try:
        if kind == 'sftp' and not c.get('fingerprint'):
            d = SFTP(c, accept_any=True)
            return {'ok': True, 'fingerprint': d.fingerprint, 'message': tr('The server answered with the key {fp}. Accept it if it is the key of your server.', fp=d.fingerprint)}
        d = open_dest(kind, c)
        return {'ok': True, 'message': d.test()}
    except BackupError as e:
        return {'ok': False, 'message': str(e)}
    except Exception as e:                       # a library error we do not know: still an answer for people
        return {'ok': False, 'message': f'{kind.upper()}: {e.__class__.__name__}: {e}'}
    finally:
        if d:
            d.close()


# ---------------------------------------------------------------- status for the web interface

def status(**kw):
    try:
        with open(STATUS) as f:
            st = json.load(f)
    except (OSError, ValueError):
        st = {}
    st.update(kw)
    _write_json(STATUS, st)
    return st


def read_status():
    try:
        with open(STATUS) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def manifests():
    """Backups in the folder here, newest first (only complete ones: those with a manifest)."""
    out = []
    for n in os.listdir(DIR) if os.path.isdir(DIR) else []:
        p = os.path.join(DIR, n, 'manifest.json')
        if ID_RE.match(n) and os.path.isfile(p):
            try:
                with open(p) as f:
                    out.append(json.load(f))
            except (OSError, ValueError):
                continue
    return sorted(out, key=lambda m: m['id'], reverse=True)


def write_index():
    du = shutil.disk_usage(DIR) if os.path.isdir(DIR) else None
    ms = manifests()
    _write_json(INDEX, {'dir': DIR, 'free': du.free if du else 0, 'used': sum(m.get('size', 0) for m in ms), 'backups': ms, 't': int(time.time())})


def _save_manifest(m):
    _write_json(os.path.join(DIR, m['id'], 'manifest.json'), m, 0o600)


# ---------------------------------------------------------------- making a backup

def _db_size():
    r = ch(f"SELECT sum(bytes_on_disk) AS b FROM system.parts WHERE active AND database = {{db:String}}", {'db': DB}, fmt='JSON')
    return int(r[0]['b'] or 0)


def _tables():
    rows = ch("SELECT name, engine, toUInt64(ifNull(total_rows, 0)) AS rows FROM system.tables WHERE database = {db:String} AND engine LIKE '%MergeTree'",
              {'db': DB}, fmt='JSON')
    return {r['name']: int(r['rows']) for r in rows}


def _settings_tar(path):
    """/etc/flowtrack and /var/lib/flowtrack as they are now (the backups' own state left out)."""
    skip = {STATUS, INDEX, REQUEST, CONFIG + '.tmp', STATUS + '.tmp', INDEX + '.tmp'}
    with tarfile.open(path, 'w:gz') as t:
        for root in (CONFIG_DIR, STATE_DIR):
            if os.path.isdir(root):
                t.add(root, arcname=root.lstrip('/'), filter=lambda ti: None if '/' + ti.name in skip or ti.name.endswith('/reputation') else ti)


def _sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def _du(path):
    total = 0
    for root, _, files in os.walk(path):
        for n in files:
            with contextlib.suppress(OSError):
                total += os.lstat(os.path.join(root, n)).st_size
    return total


def _ensure_dir():
    os.makedirs(DIR, exist_ok=True)
    os.chown(DIR, CH_UID, CH_UID)
    os.chmod(DIR, 0o700)


def _edition():
    with contextlib.suppress(Exception):
        return common.edition()['name']
    return ''


def make(full=False, log=print):
    """A backup now: -> its manifest. full=False makes a differential one on the newest full backup (a full one when
    there is none)."""
    _ensure_dir()
    ms = manifests()
    base = next((m for m in ms if m['kind'] == 'full'), None)
    if base and not os.path.isfile(os.path.join(DIR, base['id'], 'data', '.backup')):
        base = None
    kind = 'full' if full or not base else 'diff'
    size = _db_size()
    need = size if kind == 'full' else size // 4
    free = shutil.disk_usage(DIR).free
    if free < need + (256 << 20):
        raise BackupError(tr('Not enough space in {dir}: {free} free, about {need} needed.', dir=DIR, free=_fmt(free), need=_fmt(need)))
    bid = time.strftime('%Y%m%d-%H%M%S', time.gmtime())
    while os.path.exists(os.path.join(DIR, bid)):
        time.sleep(1)
        bid = time.strftime('%Y%m%d-%H%M%S', time.gmtime())
    folder = os.path.join(DIR, bid)
    os.mkdir(folder, 0o700)
    os.chown(folder, CH_UID, CH_UID)
    t0 = time.time()
    try:
        status(running={'id': bid, 'kind': kind, 'stage': 'data', 'started': int(t0), 'done': 0, 'total': 0})
        log(tr('Backing up the flow data ({kind})…', kind=tr('full') if kind == 'full' else tr('changes')))
        rows_before = _tables()
        q = f"BACKUP DATABASE {DB} TO File('{bid}/data')"
        if kind == 'diff':
            q += f" SETTINGS base_backup = File('{base['id']}/data')"
        ch(q, timeout=24 * 3600)
        rows_after = _tables()
        status(running={'id': bid, 'kind': kind, 'stage': 'settings', 'started': int(t0), 'done': 0, 'total': 0})
        st = os.path.join(folder, 'settings.tar.gz')
        _settings_tar(st)
        os.chmod(st, 0o600)
        m = {'format': 1, 'id': bid, 't': int(t0), 'kind': kind, 'base': base['id'] if kind == 'diff' else None, 'version': VERSION,
             'edition': _edition(), 'host': socket.gethostname(), 'took': round(time.time() - t0, 1),
             'tables': {k: [rows_before.get(k, 0), rows_after.get(k, 0)] for k in rows_after},
             'data_size': _du(os.path.join(folder, 'data')), 'settings_sha256': _sha256(st), 'settings_size': os.path.getsize(st),
             'places': {'local': 'ok'}, 'errors': {}, 'encrypted': False}
        m['size'] = m['data_size'] + m['settings_size']
        _save_manifest(m)
        log(tr('Backup {id} made: {size} in {s} s.', id=bid, size=_fmt(m['size']), s=round(m['took'])))
        return m
    except BaseException:
        shutil.rmtree(folder, ignore_errors=True)          # a failed backup leaves nothing half-made
        raise
    finally:
        status(running=None)


def _fmt(b):
    b = float(b)
    for u in ('B', 'KB', 'MB', 'GB', 'TB'):
        if b < 1000 or u == 'TB':
            return f'{b:.0f} {u}' if u in ('B', 'KB') else f'{b:.2f} {u}'
        b /= 1000


def _pack(m, passphrase, out):
    """The backup folder as one file for a copy: a tar (data/, settings.tar.gz, manifest.json), encrypted when a
    passphrase is given."""
    folder = os.path.join(DIR, m['id'])
    if not passphrase:
        with tarfile.open(out, 'w') as t:
            for n in ('data', 'settings.tar.gz', 'manifest.json'):
                t.add(os.path.join(folder, n), arcname=n)
        return
    import threading
    r, w = os.pipe()
    failed = []

    def writer():                                  # the tar goes into a pipe in a thread; this one encrypts it
        try:
            with os.fdopen(w, 'wb') as pw, tarfile.open(fileobj=pw, mode='w|') as t:
                for n in ('data', 'settings.tar.gz', 'manifest.json'):
                    t.add(os.path.join(folder, n), arcname=n)
        except BaseException as e:                 # noqa: B902 — reported below
            failed.append(e)
    th = threading.Thread(target=writer, daemon=True)
    th.start()
    with os.fdopen(r, 'rb') as pr, open(out, 'wb') as fo:
        encrypt_stream(pr, fo, passphrase)
    th.join()
    if failed:
        raise BackupError(tr('Could not pack the backup {id}: {err}', id=m['id'], err=failed[0]))


def copy_out(cfg, log=print, only=None):
    """Copy every kept backup that a place has not got yet (or got with an error) to S3 / SFTP / FTP. -> errors."""
    errors = {}
    ms = manifests()
    want = [k for k in DESTS if cfg[k]['on'] and (only is None or k in only)]
    for kind in want:
        todo = [m for m in reversed(ms) if m['places'].get(kind) != 'ok']
        if not todo:
            continue
        try:
            d = open_dest(kind, cfg[kind])
        except BackupError as e:
            errors[kind] = str(e)
            for m in todo:
                m['places'][kind], m['errors'][kind] = 'error', str(e)
                _save_manifest(m)
            continue
        try:
            there = set(d.list())
        except BackupError:
            there = set()
        try:
            for m in todo:
                if {m['id'] + '.ftbk', m['id'] + '.json'} <= there:      # already there (e.g. it was restored from there)
                    m['places'][kind] = 'ok'
                    m['errors'].pop(kind, None)
                    _save_manifest(m)
                    continue
                status(running={'id': m['id'], 'kind': m['kind'], 'stage': kind, 'started': int(time.time()), 'done': 0, 'total': m['size']})
                log(tr('Copying {id} to {where}…', id=m['id'], where=kind.upper()))
                try:
                    with tempfile.TemporaryDirectory(dir=DIR) as tmp:
                        f = os.path.join(tmp, m['id'] + '.ftbk')
                        pp = cfg['encrypt']['passphrase'] if cfg['encrypt']['on'] else ''
                        _pack(m, pp, f)
                        done = [0]

                        def prog(n, m=m, kind=kind, f=f):
                            done[0] += n
                            if done[0] % (32 << 20) < n:
                                status(running={'id': m['id'], 'kind': m['kind'], 'stage': kind, 'started': int(time.time()), 'done': done[0], 'total': os.path.getsize(f)})
                        d.put(f, m['id'] + '.ftbk', prog)
                        mj = os.path.join(tmp, m['id'] + '.json')
                        info = {k: v for k, v in m.items() if k not in ('places', 'errors')}
                        info['encrypted'] = bool(pp)
                        with open(mj, 'w') as fh:
                            json.dump(info, fh, indent=1)
                        d.put(mj, m['id'] + '.json')
                    m['places'][kind] = 'ok'
                    m['errors'].pop(kind, None)
                    m['encrypted'] = bool(pp) or m.get('encrypted', False)
                except (BackupError, OSError) as e:
                    m['places'][kind], m['errors'][kind] = 'error', str(e)
                    errors[kind] = str(e)
                    log(f'  {e}')
                _save_manifest(m)
        finally:
            d.close()
            status(running=None)
    return errors


def chains(ms):
    """[[full, diff, diff…], …] newest first; a differential backup whose full one is gone is a chain of its own."""
    by = {m['id']: m for m in ms}
    out, seen = [], {}
    for m in sorted(ms, key=lambda m: m['id'], reverse=True):
        root = m['id'] if m['kind'] == 'full' or m.get('base') not in by else m['base']
        if root not in seen:
            seen[root] = len(out)
            out.append([])
        out[seen[root]].append(m)
    out.sort(key=lambda c: max(x['id'] for x in c), reverse=True)
    return out


def _remove(bid):
    """Delete one backup folder here: the manifest first, so a half-deleted folder is no longer taken for a backup."""
    folder = os.path.join(DIR, bid)
    with contextlib.suppress(FileNotFoundError):
        os.remove(os.path.join(folder, 'manifest.json'))
    shutil.rmtree(folder)


def delete(ids, copies=False, log=print, errors=None):
    """(1.8.8) Backups deleted by hand (Settings → Backups, `flowtrack backup delete`): a full one takes its changes
    with it — they cannot be restored without it. copies: also on every place that is on. -> the ids deleted here."""
    errors = [] if errors is None else errors
    ms = manifests()
    by = {m['id']: m for m in ms}
    for bid in ids:
        if bid not in by:
            errors.append(tr('No backup {id}.', id=bid))
    want = {bid for bid in ids if bid in by}
    want |= {m['id'] for m in ms if m.get('base') in want}
    gone = set()
    for bid in sorted(want, reverse=True):          # the changes before their full one
        try:
            _remove(bid)
        except OSError as e:
            errors.append(tr('Could not delete the backup {id}: {err}', id=bid, err=e))
            log(errors[-1])
            continue
        gone.add(bid)
        log(tr('Deleted the backup {id}.', id=bid))
    if copies and gone:
        cfg = load()
        for kind in DESTS:
            if not cfg[kind]['on']:
                continue
            try:
                d = open_dest(kind, cfg[kind])
            except BackupError as e:
                errors.append(tr('Old copies on {where} were not deleted: {err}', where=kind.upper(), err=e))
                continue
            try:
                names = set(d.list())
                for bid in sorted(gone):
                    for n in (bid + '.ftbk', bid + '.json'):
                        if n in names:
                            d.delete(n)
                    log(tr('Deleted the old copy {id} on {where}.', id=bid, where=kind.upper()))
            except BackupError as e:
                errors.append(tr('Old copies on {where} were not deleted: {err}', where=kind.upper(), err=e))
            finally:
                d.close()
    return gone


def prune(cfg, log=print, errors=None):
    """Keep the newest `keep_full` chains here and on every place; older ones go (and their copies). What could not
    be deleted is logged and added to `errors` (a list), never passed over in silence (1.8.8)."""
    ms = manifests()
    keep = cfg['keep_full']
    old = [m for c in chains(ms)[keep:] for m in c]
    gone = set()
    errors = [] if errors is None else errors

    def failed(text):
        errors.append(text)
        log(text)
    for m in old:
        try:
            _remove(m['id'])
        except OSError as e:
            failed(tr('Could not delete the old backup {id}: {err}', id=m['id'], err=e))
            continue
        gone.add(m['id'])
        log(tr('Deleted the old backup {id}.', id=m['id']))
    # the copies: also those of backups the folder here no longer has
    keep_ids = {m['id'] for c in chains(manifests())[:keep] for m in c}
    for kind in DESTS:
        if not cfg[kind]['on']:
            continue
        try:
            d = open_dest(kind, cfg[kind])
        except BackupError as e:
            failed(tr('Old copies on {where} were not deleted: {err}', where=kind.upper(), err=e))
            continue
        try:
            names = d.list()
            ids = {n.split('.')[0] for n in names if ID_RE.match(n.split('.')[0])}
            if not ids & keep_ids and keep_ids:        # nothing kept is there yet: never empty a place
                continue
            for bid in sorted(ids - keep_ids):
                if bid > min(keep_ids, default='9'):   # newer than the kept ones (another server's?): leave it
                    continue
                try:
                    for n in (bid + '.ftbk', bid + '.json'):
                        if n in names:
                            d.delete(n)
                except BackupError as e:
                    failed(tr('Could not delete the old copy {id} on {where}: {err}', id=bid, where=kind.upper(), err=e))
                    continue
                log(tr('Deleted the old copy {id} on {where}.', id=bid, where=kind.upper()))
        except BackupError as e:
            failed(tr('Old copies on {where} were not deleted: {err}', where=kind.upper(), err=e))
        finally:
            d.close()
    return gone


# ---------------------------------------------------------------- schedule

def _slot(cfg, now=None):
    """The most recent scheduled moment (local time of the server) at or before now."""
    import datetime
    now = datetime.datetime.fromtimestamp(now or time.time())
    h, mi = map(int, cfg['schedule']['time'].split(':'))
    t = now.replace(hour=h, minute=mi, second=0, microsecond=0)
    if t > now:
        t = (t - datetime.timedelta(days=1)).replace(hour=h, minute=mi)
    return t.timestamp()


def due(cfg, st, now=None):
    """-> None, 'full' or 'diff': the backup the schedule wants now. A missed one (the server was off) runs late."""
    if not cfg['schedule']['on']:
        return None
    slot = _slot(cfg, now)
    if st.get('last_slot', 0) >= slot:
        return None
    ms = manifests()
    full = next((m for m in ms if m['kind'] == 'full'), None)
    if cfg['schedule']['full'] == 'day' or not full:
        return 'full'
    # the weekly full one on its day, or when the newest full one is older than a week (that day was missed)
    wd = (time.localtime(slot).tm_wday + 1) % 7             # 0 = Sunday, as in the UI
    if (wd == cfg['schedule']['weekday'] and full['t'] < slot) or full['t'] < slot - 7 * 86400 + 3600:
        return 'full'
    return 'diff'


def next_run(cfg, now=None):
    if not cfg['schedule']['on']:
        return None
    return int(_slot(cfg, now) + 86400)


# ---------------------------------------------------------------- verify

def verify(bid, deep=False, log=print, settings=True):
    """Check a backup here: every file ClickHouse listed has its size, the settings their checksum, the full backup a
    differential one needs is there. deep: restore the data into a scratch database and count the rows."""
    m = _manifest(bid)
    folder = os.path.join(DIR, bid)
    problems = []
    for b in [m] + ([_manifest(m['base'])] if m.get('base') else []):
        meta = os.path.join(DIR, b['id'], 'data', '.backup')
        if not os.path.isfile(meta):
            problems.append(tr('{id}: the data of the backup is missing.', id=b['id']))
            continue
        problems += _check_files(b['id'], meta)
    if os.path.isfile(os.path.join(folder, 'settings.tar.gz')):
        if _sha256(os.path.join(folder, 'settings.tar.gz')) != m['settings_sha256']:
            problems.append(tr('{id}: the settings archive is damaged.', id=bid))
    elif settings:               # a backup of the data alone (its settings left out on purpose) restores --only-data
        problems.append(tr('{id}: the settings archive is missing.', id=bid))
    if deep and not problems:
        scratch = f'{DB}_verify'
        log(tr('Restoring {id} into a scratch database to count the rows…', id=bid))
        _sys(f'DROP DATABASE IF EXISTS {scratch} SYNC')
        try:
            _sys(f"RESTORE DATABASE {DB} AS {scratch} FROM File('{bid}/data')", timeout=24 * 3600)
            rows = {r['name']: int(r['rows']) for r in ch("SELECT name, toUInt64(ifNull(total_rows, 0)) AS rows FROM system.tables WHERE database = {db:String} AND engine LIKE '%MergeTree'",
                                                      {'db': scratch}, fmt='JSON')}
            for t, (lo, hi) in m['tables'].items():
                n = rows.get(t)
                if n is None:
                    problems.append(tr('{id}: the table {t} is missing.', id=bid, t=t))
                elif not min(lo, hi) <= n <= max(lo, hi) and not (n and lo == hi == 0):
                    problems.append(tr('{id}: {t} has {n} rows, {lo}–{hi} expected.', id=bid, t=t, n=n, lo=lo, hi=hi))
        finally:
            _sys(f'DROP DATABASE IF EXISTS {scratch} SYNC')
    m['verified'] = {'t': int(time.time()), 'ok': not problems, 'deep': deep, 'problems': problems[:5]}
    _save_manifest(m)
    return problems


def _check_files(bid, meta):
    """The .backup file of ClickHouse lists every file with its size; one kept whole in the base backup (use_base,
    base_size = size) is not in this folder."""
    import xml.etree.ElementTree as ET
    problems = []
    try:
        root = ET.parse(meta).getroot()
    except ET.ParseError:
        return [tr('{id}: the list of files of the backup is damaged.', id=bid)]
    data = os.path.join(DIR, bid, 'data')
    for f in root.iter('file'):
        name, size = f.findtext('name'), int(f.findtext('size') or 0)
        use_base = f.findtext('use_base') == 'true'
        base_size = int(f.findtext('base_size') or (size if use_base else 0))
        if not name or size == 0 or base_size >= size:
            continue
        dn = f.findtext('data_file') or name
        p = os.path.join(data, dn.lstrip('/'))
        if not os.path.isfile(p):
            problems.append(tr('{id}: the file {f} is missing.', id=bid, f=dn))
        elif os.path.getsize(p) not in (size, size - base_size):
            problems.append(tr('{id}: the file {f} has the wrong size.', id=bid, f=dn))
        if len(problems) >= 5:
            break
    return problems


def _manifest(bid):
    if not ID_RE.match(bid or ''):
        raise BackupError(tr('No backup {id}.', id=bid))
    try:
        with open(os.path.join(DIR, bid, 'manifest.json')) as f:
            return json.load(f)
    except (OSError, ValueError):
        raise BackupError(tr('No backup {id} in {dir}.', id=bid, dir=DIR)) from None


# ---------------------------------------------------------------- restore

def _ver(v):
    return tuple(int(x) for x in re.findall(r'\d+', v)[:3]) if v else (0,)


def fetch(source, bid, cfg, passphrase=None, log=print, unencrypted=False):
    """Bring a backup (and the full one it needs) from S3 / SFTP / FTP or a folder of .ftbk files into the folder
    here. -> the manifest. While this server encrypts its copies, a copy that is not encrypted is refused unless
    `unencrypted` (whoever can write to the place could have put it there; it is restored as root)."""
    _ensure_dir()
    if os.path.isdir(source):
        names = os.listdir(source)
        get = lambda n, p: shutil.copyfile(os.path.join(source, n), p)           # noqa: E731
        d = None
    else:
        d = open_dest(source, cfg[source])
        names, get = d.list(), d.get
    try:
        todo, cur = [], bid
        while cur:
            if os.path.isfile(os.path.join(DIR, cur, 'manifest.json')):
                break
            if cur + '.ftbk' not in names:
                raise BackupError(tr('{id} is not there.', id=cur))
            todo.append(cur)
            with tempfile.TemporaryDirectory(dir=DIR) as tmp:
                get(cur + '.json', os.path.join(tmp, 'm.json'))
                with open(os.path.join(tmp, 'm.json')) as fh:
                    cur = json.load(fh).get('base')
            if cur and not ID_RE.match(str(cur)):            # the copy is not trusted: its base names a folder here
                raise BackupError(tr('The backup file holds an unsafe path: {p}', p=str(cur)[:60]))
        for b in reversed(todo):
            log(tr('Downloading {id}…', id=b))
            with tempfile.TemporaryDirectory(dir=DIR) as tmp:
                f = os.path.join(tmp, b + '.ftbk')
                get(b + '.ftbk', f)
                tarp = f
                if not is_encrypted(f) and cfg['encrypt']['on'] and not unencrypted:
                    raise BackupError(tr('{id} is not encrypted, while this server encrypts its copies: whoever can write to '
                                         '{place} could have put it there. If you made it yourself before encryption was '
                                         'turned on, add --unencrypted.', id=b, place=source))
                if is_encrypted(f):
                    if passphrase is None:
                        passphrase = cfg['encrypt']['passphrase'] or getpass.getpass(tr('Passphrase of the backups: '))
                    tarp = f + '.tar'
                    with open(f, 'rb') as src, open(tarp, 'wb') as dst:
                        decrypt_stream(src, dst, passphrase)
                    os.remove(f)
                dest = os.path.join(DIR, b)
                os.mkdir(dest, 0o700)
                with tarfile.open(tarp) as t:
                    for ti in t.getmembers():
                        if ti.name.startswith('/') or '..' in ti.name.split('/') or not (ti.isfile() or ti.isdir()):
                            raise BackupError(tr('The backup file holds an unsafe path: {p}', p=ti.name))
                        ti.mode &= 0o777
                    t.extractall(dest, **TAR_AS_CHECKED)
                for root, dirs, files in os.walk(dest):
                    for n in dirs + files:
                        os.chown(os.path.join(root, n), CH_UID, CH_UID)
                os.chown(dest, CH_UID, CH_UID)
                with open(os.path.join(dest, 'manifest.json')) as fh:
                    m = json.load(fh)
                m['places'] = {'local': 'ok', **({source: 'ok'} if source in DESTS else {})}
                m['errors'] = {}
                _save_manifest(m)
        return _manifest(bid)
    finally:
        if d:
            d.close()


def remote_list(source, cfg):
    """[manifest…] of the copies on a place or in a folder of .ftbk files, newest first."""
    out = []
    if os.path.isdir(source):
        for n in sorted(os.listdir(source)):
            if n.endswith('.json') and ID_RE.match(n[:-5]) and os.path.isfile(os.path.join(source, n[:-5] + '.ftbk')):
                with open(os.path.join(source, n)) as f:
                    out.append(json.load(f))
    else:
        d = open_dest(source, cfg[source])
        try:
            names = set(d.list())
            with tempfile.TemporaryDirectory() as tmp:
                for n in sorted(names):
                    if n.endswith('.json') and ID_RE.match(n[:-5]) and n[:-5] + '.ftbk' in names:
                        d.get(n, os.path.join(tmp, n))
                        with open(os.path.join(tmp, n)) as f:
                            out.append(json.load(f))
        finally:
            d.close()
    return sorted(out, key=lambda m: m['id'], reverse=True)


def _systemctl(*a):
    subprocess.run(['systemctl', *a], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


ASIDE = f'{DB}_before_restore'


def restore(bid, data=True, settings=True, with_license=False, force=False, log=print):
    """Restore a backup from the folder here. The services stop; the current flow data is set aside under another
    name until the backup is in place, and comes back if the restore fails."""
    m = _manifest(bid)
    if _ver(m['version']) > _ver(VERSION) and not force:
        raise BackupError(tr('The backup is from FlowSphera {v}, newer than this {cur}: upgrade first (sudo flowtrack upgrade).', v=m['version'], cur=VERSION))
    if data and _db_exists(ASIDE):
        raise BackupError(tr('An earlier restore did not finish: the flow data from before it is kept as {aside}. Run sudo flowtrack restore --undo to put it back, then try again.', aside=ASIDE))
    problems = verify(bid, log=log, settings=settings)
    if problems:
        raise BackupError(tr('The backup is not intact:') + '\n  ' + '\n  '.join(problems))
    log(tr('Stopping FlowSphera…'))
    _systemctl('stop', *SERVICES)
    try:
        if data:
            log(tr('Restoring the flow data of {id}…', id=bid))
            have = _db_exists(DB)
            if have:
                _sys(f'RENAME DATABASE {DB} TO {ASIDE}')
            try:
                _sys(f"RESTORE DATABASE {DB} FROM File('{bid}/data')", timeout=24 * 3600)
            except BaseException as e:
                log(tr('The restore failed ({err}): putting the flow data back as it was.', err=str(e)[:300]))
                if have:
                    _put_back(log)
                raise
            if have:
                _sys(f'DROP DATABASE IF EXISTS {ASIDE} SYNC')
        if settings:
            log(tr('Restoring the settings…'))
            _restore_settings(os.path.join(DIR, bid, 'settings.tar.gz'), with_license)
    finally:
        log(tr('Starting FlowSphera…'))
        _systemctl('start', *SERVICES)
    log(tr('Restored {id} ({when}).', id=bid, when=time.strftime('%Y-%m-%d %H:%M', time.localtime(m['t']))))


def _put_back(log=print):
    """The flow data set aside by a restore back in its place (whatever is under the real name goes)."""
    try:
        _sys(f'DROP DATABASE IF EXISTS {DB} SYNC')
        _sys(f'RENAME DATABASE {ASIDE} TO {DB}')
        log(tr('The flow data is as it was before the restore.'))
    except CHError as e:
        log(tr('Could not put the flow data back ({err}); it is kept as {aside}: run sudo flowtrack restore --undo.', err=str(e)[:300], aside=ASIDE))
        raise


def undo(log=print):
    """After a restore that did not finish: the flow data from before it back in its place."""
    if not _db_exists(ASIDE):
        raise BackupError(tr('Nothing to undo: no flow data was set aside by a restore.'))
    log(tr('Stopping FlowSphera…'))
    _systemctl('stop', *SERVICES)
    try:
        _put_back(log)
    finally:
        log(tr('Starting FlowSphera…'))
        _systemctl('start', *SERVICES)


def _restore_settings(path, with_license, root='/'):
    def skip(name):
        if any(name == s or name.startswith(s + '/') for s in SKIP_RESTORE):
            return True
        return not with_license and any(name.startswith(s) for s in LICENSE_FILES)
    def inside(name, d):
        d = d.strip('/')
        return name == d or name.startswith(d + '/')

    with tarfile.open(path) as t:
        members = []
        for ti in t.getmembers():
            if ti.name.startswith('/') or '..' in ti.name.split('/') or not (ti.isfile() or ti.isdir()):
                continue
            if not (inside(ti.name, CONFIG_DIR) or inside(ti.name, STATE_DIR)) or skip(ti.name):
                continue
            ti.mode &= 0o777                      # never setuid / setgid / sticky
            members.append(ti)
        # STATE_DIR belongs to the flowtrack user: a link it left in place of a file or folder would make this (root)
        # write elsewhere. Links are removed before; a folder on the way that is a link stops the restore.
        for ti in members:
            parts, cur = ti.name.split('/'), root
            for i, part in enumerate(parts):
                cur = os.path.join(cur, part)
                if not os.path.islink(cur):
                    continue
                if i < len(parts) - 1:
                    raise BackupError(tr('The settings cannot be restored: {p} is a link.', p=cur))
                os.unlink(cur)
        t.extractall(root, members=members, **TAR_AS_CHECKED)


# ---------------------------------------------------------------- the service and the command line

@contextlib.contextmanager
def lock(wait=False):
    """One backup or restore at a time. wait: the service waits for the running one (a request file it left would
    start it again at once, over and over); the command line says so instead."""
    os.makedirs(STATE_DIR, exist_ok=True)
    fd = os.open(os.path.join(STATE_DIR, 'backup.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
    except BlockingIOError:
        os.close(fd)
        raise BackupError(tr('Another backup or restore is running.')) from None
    try:
        yield
    finally:
        os.close(fd)


def run(full=False, slot=None, log=print):
    """A backup with everything after it: copies, keeping, the index. -> the manifest."""
    cfg = load()
    try:
        m = make(full, log=log)
    except (BackupError, CHError, OSError) as e:
        status(last={'t': int(time.time()), 'ok': False, 'error': str(e)[:500]}, **({'last_slot': slot} if slot else {}))
        write_index()
        raise
    # the backup is made: whatever goes wrong after it is recorded with it (and the slot counts as done), never lost
    try:
        errs = copy_out(cfg, log=log)
    except Exception as e:                     # noqa: BLE001 — a library error we do not know
        errs = {'copy': str(e)}
        log(f'ERROR copies: {e}')
    perrs = []
    try:
        prune(cfg, log=log, errors=perrs)
    except Exception as e:                     # noqa: BLE001
        perrs.append(tr('Old backups were not deleted: {err}', err=e))
        log(perrs[-1])
    status(last={'t': int(time.time()), 'ok': not errs, 'id': m['id'], 'error': '; '.join(f'{k.upper()}: {v}' for k, v in errs.items())[:500],
                 'prune_error': '; '.join(perrs)[:500]},
           next=next_run(cfg), **({'last_slot': slot} if slot else {}))
    write_index()
    return m


def service():
    """flowtrack-backup.service: what the web interface asked for, else the scheduled backup when it is due."""
    with contextlib.suppress(OSError):
        with open(os.path.join(CONFIG_DIR, 'install-lang')) as f:
            set_lang(f.read().strip())
    cfg = load()
    held = lock(wait=True)
    held.__enter__()
    try:
        req = None
        if os.path.exists(REQUEST):            # taken only under the lock, so it is never lost
            try:
                with open(REQUEST) as f:
                    req = json.load(f)
            except (OSError, ValueError):
                req = {'do': 'backup'}
            with contextlib.suppress(OSError):
                os.remove(REQUEST)
        if req:
            if req.get('do') == 'verify' and ID_RE.match(str(req.get('id'))):
                with contextlib.suppress(BackupError, CHError):
                    verify(req['id'], deep=bool(req.get('deep')))
            elif req.get('do') == 'copy':
                copy_out(cfg)
            elif req.get('do') == 'delete':
                ids = [str(x) for x in req.get('ids') or [] if ID_RE.match(str(x))]
                errs = []
                gone = delete(ids, copies=bool(req.get('copies')), errors=errs)
                status(deleted={'t': int(time.time()), 'ids': sorted(gone), 'error': '; '.join(errs)[:500]})
                for e in errs:
                    print(f'ERROR: {e}', flush=True)
            else:
                try:
                    run(full=bool(req.get('full')))
                except (BackupError, CHError, OSError) as e:      # in the status already; the journal says it too
                    print(f'ERROR: {e}', flush=True)
            write_index()
            return
        st = read_status()
        if 'last_slot' not in st:              # just installed or upgraded: the first backup waits for the schedule
            status(last_slot=int(_slot(cfg)), next=next_run(cfg))
            write_index()
            return
        kind = due(cfg, st)
        if kind:
            try:
                run(full=kind == 'full', slot=int(_slot(cfg)))
            except (BackupError, CHError, OSError) as e:
                print(f'ERROR: {e}', flush=True)
        elif st.get('next') != next_run(cfg):
            status(next=next_run(cfg))
        write_index()                          # also after backups were deleted or copied in by hand
    finally:
        held.__exit__(None, None, None)


def _table(ms, extra=''):
    if not ms:
        print(tr('No backups.'))
        return
    for m in ms:
        places = ' '.join(k for k, v in (m.get('places') or {}).items() if v == 'ok')
        bad = ' '.join(f'{k}✕' for k, v in (m.get('places') or {}).items() if v == 'error')
        print(f"{m['id']}  {time.strftime('%Y-%m-%d %H:%M', time.localtime(m['t']))}  {(tr('full') if m['kind'] == 'full' else tr('changes')):<14} "
              f"{_fmt(m.get('size', 0)):>10}  {m.get('version', '?'):<7} {places} {bad}{extra}")


def main(argv=None):
    with contextlib.suppress(OSError):
        with open(os.path.join(CONFIG_DIR, 'install-lang')) as f:
            set_lang(f.read().strip())
    ap = argparse.ArgumentParser(prog='flowtrack', description=tr('FlowSphera backups'))
    sub = ap.add_subparsers(dest='cmd')
    b = sub.add_parser('backup')
    b.add_argument('what', nargs='?', default='now', choices=('now', 'list', 'verify', 'prune', 'copy', 'delete', 'service'))
    b.add_argument('id', nargs='?')
    b.add_argument('--full', action='store_true')
    b.add_argument('--deep', action='store_true')
    b.add_argument('--from', dest='source')
    b.add_argument('--copies', action='store_true')
    b.add_argument('--yes', action='store_true')
    r = sub.add_parser('restore')
    r.add_argument('id', nargs='?')
    r.add_argument('--from', dest='source')
    r.add_argument('--only-settings', action='store_true')
    r.add_argument('--only-data', action='store_true')
    r.add_argument('--with-license', action='store_true')
    r.add_argument('--passphrase-file')
    r.add_argument('--unencrypted', action='store_true')
    r.add_argument('--yes', action='store_true')
    r.add_argument('--force', action='store_true')
    r.add_argument('--undo', action='store_true')
    a = ap.parse_args(argv)
    if os.geteuid() != 0:
        print(tr('Run it as root: sudo flowtrack {cmd} …', cmd=a.cmd or 'backup'), file=sys.stderr)
        return 1
    try:
        if a.cmd == 'backup':
            if a.what == 'service':
                service()
            elif a.what == 'list':
                _table(remote_list(a.source, load()) if a.source else manifests())
            elif a.what == 'verify':
                bid = a.id or (manifests() or [{}])[0].get('id')
                with lock():
                    problems = verify(bid, deep=a.deep)
                    write_index()
                print('\n'.join(problems) if problems else tr('{id}: intact.', id=bid))
                return 1 if problems else 0
            elif a.what == 'delete':
                if not a.id or not ID_RE.match(a.id):
                    print(tr('Which backup? flowtrack backup delete ID [--copies]'), file=sys.stderr)
                    return 1
                if not a.yes:
                    ans = input(tr('Delete {id} (a full backup also takes its changes){c}? Type yes: ', id=a.id,
                                   c=tr(' and its copies') if a.copies else ''))
                    if ans.strip().lower() not in ('yes', 'y', tr('yes').lower()):
                        return 1
                with lock():
                    errs = []
                    delete([a.id], copies=a.copies, errors=errs)
                    write_index()
                if errs:
                    print('\n'.join(errs), file=sys.stderr)
                return 1 if errs else 0
            elif a.what == 'prune':
                with lock():
                    perrs = []
                    prune(load(), errors=perrs)
                    write_index()
                if perrs:
                    return 1
            elif a.what == 'copy':
                with lock():
                    errs = copy_out(load())
                    write_index()
                return 1 if errs else 0
            else:
                with lock():
                    run(full=a.full)
            return 0
        if a.cmd == 'restore' and a.undo:
            with lock():
                undo()
            return 0
        if a.cmd == 'restore':
            cfg = load()
            if a.only_settings and a.only_data:
                raise BackupError(tr('--only-settings and --only-data exclude each other.'))
            pp = None
            if a.passphrase_file:
                with open(a.passphrase_file) as f:
                    pp = f.read().strip()
            src = a.source
            if src and src not in DESTS and not os.path.isdir(src):
                raise BackupError(tr('--from: s3, sftp, ftp or a folder with .ftbk files.'))
            ms = remote_list(src, cfg) if src else manifests()
            if not a.id:
                _table(ms)
                if not ms:
                    return 1
                a.id = input(tr('Which backup (id, Enter = the newest)? ')).strip() or ms[0]['id']
            if not any(m['id'] == a.id for m in ms):
                raise BackupError(tr('No backup {id}.', id=a.id))
            m = next(m for m in ms if m['id'] == a.id)
            what = tr('the settings') if a.only_settings else tr('the flow data') if a.only_data else tr('the flow data and the settings')
            print(tr('Restore {id} ({when}, FlowSphera {v}): {what} of this server are replaced; collecting stops for the time of it.',
                     id=a.id, when=time.strftime('%Y-%m-%d %H:%M', time.localtime(m['t'])), v=m.get('version', '?'), what=what))
            if not a.yes and input(tr('Type yes to go on: ')).strip().lower() not in ('yes', 'y', tr('yes').lower()):
                print(tr('Nothing changed.'))
                return 1
            with lock():
                if src:
                    fetch(src, a.id, cfg, passphrase=pp, unencrypted=a.unencrypted)
                restore(a.id, data=not a.only_settings, settings=not a.only_data, with_license=a.with_license, force=a.force)
                write_index()
            return 0
        ap.print_help()
        return 2
    except (BackupError, CHError) as e:
        print(str(e), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == '__main__':
    sys.exit(main())
