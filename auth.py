"""FlowTrack users and sessions (stdlib only).

- Passwords: scrypt (n=2^14, r=8, p=1) with a per-user random salt; compared in constant time.
- Sessions: random 256-bit tokens; only their SHA-256 is stored on disk, so a leaked
  sessions file cannot be replayed. Sliding expiry of 7 days.
- Roles: 'admin' (everything, incl. users and devices) and 'viewer' (read-only).
- On first start, when no users exist, creates admin / flowtrack and flags the password as default.
- API tokens (1.11.0): for scripts and monitoring, sent as `Authorization: Bearer ftapi_…`. They belong to the
  installation (not to a user), carry a scope — 'read' (what a viewer sees) or 'write' (also the administrator's
  changes, without users, tokens, the license and deleting backups) — and an optional end date. Only their SHA-256 is
  stored (api_tokens.json); the token itself is shown once. Wrong tokens count with the failed logins of the address.
- Directory users (1.12.0, directory.py): the sign-in page offers "Local account" or the directory (Active Directory /
  LDAP) when that is on — the person chooses, nothing is guessed. Directory users are kept here as "ldap:<name>"
  (local names cannot hold ':', so a local "admin" and the directory's "admin" are two accounts), without a password,
  the role from their groups at every sign-in, sessions of 12 hours without sliding. At least one LOCAL administrator
  always remains: the way in when the directory is unreachable.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque

import directory
from common import tr

STATE_DIR = os.environ.get('FT_STATE_DIR', '/var/lib/flowtrack')
USERS_FILE = os.path.join(STATE_DIR, 'users.json')
SESSIONS_FILE = os.path.join(STATE_DIR, 'sessions.json')
SESSION_TTL = 7 * 86400
DIRECTORY_TTL = 12 * 3600               # (1.12.0) a directory user's session: their groups are checked again after it
LDAP_PREFIX = 'ldap:'                   # a directory user's key in users.json (local names cannot contain ':')
ROLES = ('admin', 'viewer')
NAME_RE = re.compile(r'^[A-Za-z0-9._-]{2,32}$')
MIN_PASSWORD = 8
TOKENS_FILE = os.path.join(STATE_DIR, 'api_tokens.json')
TOKEN_PREFIX = 'ftapi_'
SCOPES = ('read', 'write')
TOKEN_DAYS = (0, 30, 90, 365)            # 0 = no end date
MAX_TOKENS = 50
DEFAULT_USER, DEFAULT_PASSWORD = 'admin', 'flowtrack'


class AuthError(Exception):
    """Message is safe to show to the user; status is the HTTP status for it."""
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


def _write_json(path, obj):
    tmp = path + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(obj, f, indent=1)
    os.replace(tmp, path)


def _read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def _hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32).hex()


def _tok_id(token):
    return hashlib.sha256(token.encode()).hexdigest()


class Auth:
    def __init__(self):
        self.lock = threading.Lock()
        os.makedirs(STATE_DIR, exist_ok=True)
        self.users = _read_json(USERS_FILE, {})
        self.sessions = _read_json(SESSIONS_FILE, {})
        self.tokens = _read_json(TOKENS_FILE, {})
        self.fails = defaultdict(deque)          # ip -> timestamps of failed logins
        if not self.users:
            self._set_password(DEFAULT_USER, DEFAULT_PASSWORD, role='admin', default=True)
            print(f'[flowtrack-api] created default user {DEFAULT_USER!r} — change its password', flush=True)
        now = time.time()
        self.sessions = {k: v for k, v in self.sessions.items() if v.get('exp', 0) > now and v.get('user') in self.users}

    # ------------------------------------------------------------ storage
    def _save_users(self):
        _write_json(USERS_FILE, self.users)

    def _save_sessions(self):
        _write_json(SESSIONS_FILE, self.sessions)

    def _save_tokens(self):
        _write_json(TOKENS_FILE, self.tokens)

    def _set_password(self, name, password, role=None, default=False):
        salt = secrets.token_bytes(16)
        u = self.users.get(name) or {'created': int(time.time()), 'last_login': 0}
        u.update({'salt': salt.hex(), 'hash': _hash(password, salt), 'default': default})
        if role:
            u['role'] = role
        self.users[name] = u
        self._save_users()

    @staticmethod
    def _check_new_password(password):
        if not isinstance(password, str) or len(password) < MIN_PASSWORD:
            raise AuthError(tr('The password must be at least {n} characters long', n=MIN_PASSWORD))
        if len(password) > 256:
            raise AuthError(tr('The password is too long'))

    def public(self, name):
        u = self.users[name]
        return {'name': name, 'role': u['role'], 'created': u.get('created', 0), 'last_login': u.get('last_login', 0),
                'default_password': bool(u.get('default')), 'prefs': dict(u.get('prefs') or {}), 'source': u.get('source', 'local'),
                'display': name[len(LDAP_PREFIX):] if u.get('source') == 'ldap' else name}

    # (1.9.0) what a user chose for themself, kept with the account (any browser): the Path analysis map view
    PREFS = {'path_view': ('classic', 'lines', 'stars', 'metro', 'river'), 'conv_view': ('flow', 'chord', 'matrix')}

    def set_prefs(self, name, prefs):
        if not isinstance(prefs, dict):
            raise AuthError('bad prefs')
        with self.lock:
            u = self.users[name]
            cur = dict(u.get('prefs') or {})
            for k, v in prefs.items():
                if k not in self.PREFS or v not in self.PREFS[k]:
                    raise AuthError(f'bad value for {k}'[:60])
                cur[k] = v
            u['prefs'] = cur
            self._save_users()
        return self.public(name)

    # ------------------------------------------------------------ login / sessions
    def _verify(self, name, password, ip, wrong):
        """The password of `name`, under the lock; 5 wrong ones from one address in 5 minutes -> 429 for a while."""
        now = time.time()
        q = self._too_many(ip, now)
        u = self._local(name)              # a directory user has no local password (1.12.0)
        # always run scrypt so response time does not reveal whether the user exists
        calc = _hash(password if isinstance(password, str) else '', bytes.fromhex(u['salt']) if u else b'0' * 16)
        if not u or not hmac.compare_digest(calc, u['hash']):
            q.append(now)
            raise AuthError(wrong)
        q.clear()
        return u

    def check_password(self, name, password, ip):
        """(1.8.8) Confirm a dangerous action with the signed-in user's own password (no new session); wrong ones
        count with the failed logins. A directory user's password is checked by the directory (1.12.0)."""
        if self.users.get(name, {}).get('source') == 'ldap':
            now = time.time()
            with self.lock:
                q = self._too_many(ip, now)
            try:
                r = directory.authenticate(directory.load(), name[len(LDAP_PREFIX):], password)
            except directory.DirectoryError:
                raise AuthError(tr('The directory cannot be reached now to check your password.'), 503) from None
            if not r or LDAP_PREFIX + r['name'] != name:
                with self.lock:
                    q.append(now)
                raise AuthError(tr('Wrong password'))
            return
        with self.lock:
            self._verify(name, password, ip, tr('Wrong password'))

    def _local(self, name):
        u = self.users.get(name) if isinstance(name, str) else None
        return u if u and u.get('source') != 'ldap' else None

    def login(self, name, password, ip, method='local'):
        now = time.time()
        with self.lock:
            q = self._too_many(ip, now)
        if method != 'ldap':
            with self.lock:
                u = self._verify(name, password, ip, tr('Wrong username or password'))
                return self._open_session(name, u, now, SESSION_TTL)
        # (1.12.0) through the directory — outside the lock: it talks to the network
        cfg = directory.load()
        if not cfg['on']:
            raise AuthError(tr('Sign-in through the directory is off: choose «Local account».'))
        try:
            r = directory.authenticate(cfg, name, password)
        except directory.DirectoryError as e:
            print(f'[flowtrack-api] directory sign-in of {str(name)[:64]!r}: {e}', flush=True)
            raise AuthError(tr('The directory cannot be reached now (local users can still sign in). Ask an administrator.'), 503) from None
        with self.lock:
            if r is None:
                q.append(now)
                raise AuthError(tr('Wrong username or password'))
            if not r['role']:
                raise AuthError(tr('Your directory account is not in a FlowTrack group: ask an administrator to add you.'), 403)
            q.clear()
            key = LDAP_PREFIX + r['name']
            u = self.users.get(key) or {'created': int(now), 'source': 'ldap'}
            u.update(source='ldap', role=r['role'], dn=r['dn'])
            self.users[key] = u
            return self._open_session(key, u, now, DIRECTORY_TTL, fixed=True)

    def _open_session(self, name, u, now, ttl, fixed=False):
        token = secrets.token_urlsafe(32)
        self.sessions[_tok_id(token)] = {'user': name, 'exp': now + ttl, 'created': int(now), **({'fixed': True} if fixed else {})}
        u['last_login'] = int(now)
        self._save_users()
        self._save_sessions()
        return token

    def session_user(self, token):
        if not token:
            return None
        now = time.time()
        with self.lock:
            tid = _tok_id(token)
            s = self.sessions.get(tid)
            if not s or s['exp'] < now or s['user'] not in self.users:
                return None
            if not s.get('fixed') and s['exp'] - now < SESSION_TTL - 86400:      # sliding expiry, written at most once a day
                s['exp'] = now + SESSION_TTL
                self._save_sessions()
            return s['user']

    def _too_many(self, ip, now):
        q = self.fails[ip]
        while q and now - q[0] > 300:
            q.popleft()
        if len(q) >= 5:
            raise AuthError(tr('Too many failed attempts. Try again in a few minutes.'), 429)
        return q

    def token_user(self, token, ip):
        """(1.11.0) The API token of a request -> {'name', 'scope'}; AuthError 401 (unknown, ended) or 429."""
        now = time.time()
        with self.lock:
            q = self._too_many(ip, now)
            t = self.tokens.get(_tok_id(token)) if isinstance(token, str) and token.startswith(TOKEN_PREFIX) else None
            if not t or (t.get('expires') and t['expires'] < now):
                q.append(now)
                raise AuthError(tr('Invalid or expired API token'), 401)
            if now - t.get('last_used', 0) > 60 or t.get('last_ip') != ip:      # written at most once a minute
                t['last_used'], t['last_ip'] = int(now), ip
                self._save_tokens()
            return {'name': t['name'], 'scope': t['scope']}

    def list_tokens(self):
        with self.lock:
            return sorted(({'id': k[:16], **{f: v.get(f) for f in ('name', 'scope', 'hint', 'created', 'by', 'expires', 'last_used', 'last_ip')}}
                           for k, v in self.tokens.items()), key=lambda x: -x['created'])

    def create_token(self, actor, name, scope, days):
        """-> (the token, shown once; its public row)."""
        name = str(name or '').strip()
        if not name or len(name) > 48 or any(ord(c) < 32 for c in name):
            raise AuthError(tr('Give the token a name (up to 48 characters).'))
        if scope not in SCOPES:
            raise AuthError(tr('Unknown access level'))
        try:
            days = int(days or 0)
        except (TypeError, ValueError):
            days = -1
        if days not in TOKEN_DAYS:
            raise AuthError(tr('Unknown validity'))
        now = int(time.time())
        with self.lock:
            if any(t['name'].lower() == name.lower() for t in self.tokens.values()):
                raise AuthError(tr('A token with this name already exists'))
            if len(self.tokens) >= MAX_TOKENS:
                raise AuthError(tr('At most {n} tokens.', n=MAX_TOKENS))
            token = TOKEN_PREFIX + secrets.token_urlsafe(32)
            self.tokens[_tok_id(token)] = {'name': name, 'scope': scope, 'hint': token[:10] + '…', 'created': now, 'by': actor,
                                           'expires': now + days * 86400 if days else 0, 'last_used': 0, 'last_ip': ''}
            self._save_tokens()
        return token, next(t for t in self.list_tokens() if t['name'] == name)

    def delete_token(self, tid):
        with self.lock:
            k = next((k for k in self.tokens if k[:16] == tid and isinstance(tid, str) and len(tid) == 16), None)
            if not k:
                raise AuthError(tr('There is no such token any more.'))
            del self.tokens[k]
            self._save_tokens()

    def logout(self, token):
        with self.lock:
            if self.sessions.pop(_tok_id(token or ''), None):
                self._save_sessions()

    def _drop_sessions(self, name, keep=None):
        self.sessions = {k: v for k, v in self.sessions.items() if v['user'] != name or k == keep}
        self._save_sessions()

    # ------------------------------------------------------------ self-service
    def change_own_password(self, name, current, new, token, ip):
        if self.users.get(name, {}).get('source') == 'ldap':
            raise AuthError(tr('Your password belongs to the directory: change it there (e.g. Ctrl+Alt+Del in Windows).'))
        with self.lock:
            self._verify(name, current, ip, tr('The current password is wrong'))     # wrong ones count as failed logins
            self._check_new_password(new)
            if new == current:
                raise AuthError(tr('The new password is the same as the current one'))
            self._set_password(name, new)
            self._drop_sessions(name, keep=_tok_id(token))   # sign out other devices

    # ------------------------------------------------------------ admin
    def list_users(self):
        with self.lock:
            return [self.public(n) for n in sorted(self.users)]

    def create_user(self, name, role, password):
        with self.lock:
            if not isinstance(name, str) or not NAME_RE.match(name):
                raise AuthError(tr('Username: 2–32 characters: Latin letters, digits, dot, hyphen, underscore'))
            if name in self.users:
                raise AuthError(tr('This user already exists'))
            if role not in ROLES:
                raise AuthError(tr('Unknown role'))
            self._check_new_password(password)
            self._set_password(name, password, role=role)

    def _admins(self):
        """The LOCAL administrators: one always remains, a way in when the directory is unreachable (1.12.0)."""
        return [n for n, u in self.users.items() if u['role'] == 'admin' and u.get('source') != 'ldap']

    def update_user(self, actor, name, role=None, password=None):
        with self.lock:
            if name not in self.users:
                raise AuthError(tr('User not found'))
            if self.users[name].get('source') == 'ldap' and (role not in (None, self.users[name]['role']) or password is not None):
                raise AuthError(tr('A directory user\'s role comes from their groups and the password from the directory.'))
            if role is not None:
                if role not in ROLES:
                    raise AuthError(tr('Unknown role'))
                if role != 'admin' and self.users[name]['role'] == 'admin' and len(self._admins()) == 1:
                    raise AuthError(tr('At least one administrator must remain'))
                if name == actor and role != 'admin':
                    raise AuthError(tr('You cannot remove your own administrator rights'))
                self.users[name]['role'] = role
                self._save_users()
            if password is not None:
                self._check_new_password(password)
                self._set_password(name, password)
                if name != actor:
                    self._drop_sessions(name)

    def delete_user(self, actor, name):
        with self.lock:
            if name not in self.users:
                raise AuthError(tr('User not found'))
            if name == actor:
                raise AuthError(tr('You cannot delete yourself'))
            if self.users[name]['role'] == 'admin' and self.users[name].get('source') != 'ldap' and len(self._admins()) == 1:
                raise AuthError(tr('At least one administrator must remain'))
            del self.users[name]
            self._save_users()
            self._drop_sessions(name)
