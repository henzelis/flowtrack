"""FlowTrack users and sessions (stdlib only).

- Passwords: scrypt (n=2^14, r=8, p=1) with a per-user random salt; compared in constant time.
- Sessions: random 256-bit tokens; only their SHA-256 is stored on disk, so a leaked
  sessions file cannot be replayed. Sliding expiry of 7 days.
- Roles: 'admin' (everything, incl. users and devices) and 'viewer' (read-only).
- On first start, when no users exist, creates admin / flowtrack and flags the password as default.
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

STATE_DIR = os.environ.get('FT_STATE_DIR', '/var/lib/flowtrack')
USERS_FILE = os.path.join(STATE_DIR, 'users.json')
SESSIONS_FILE = os.path.join(STATE_DIR, 'sessions.json')
SESSION_TTL = 7 * 86400
ROLES = ('admin', 'viewer')
NAME_RE = re.compile(r'^[A-Za-z0-9._-]{2,32}$')
MIN_PASSWORD = 8
DEFAULT_USER, DEFAULT_PASSWORD = 'admin', 'flowtrack'


class AuthError(Exception):
    """Message is safe to show to the user."""


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
            raise AuthError(f'Пароль має містити щонайменше {MIN_PASSWORD} символів')
        if len(password) > 256:
            raise AuthError('Пароль задовгий')

    def public(self, name):
        u = self.users[name]
        return {'name': name, 'role': u['role'], 'created': u.get('created', 0), 'last_login': u.get('last_login', 0),
                'default_password': bool(u.get('default'))}

    # ------------------------------------------------------------ login / sessions
    def login(self, name, password, ip):
        now = time.time()
        with self.lock:
            q = self.fails[ip]
            while q and now - q[0] > 300:
                q.popleft()
            if len(q) >= 5:
                raise AuthError('Забагато невдалих спроб. Спробуйте за кілька хвилин.')
            u = self.users.get(name) if isinstance(name, str) else None
            # always run scrypt so response time does not reveal whether the user exists
            calc = _hash(password if isinstance(password, str) else '', bytes.fromhex(u['salt']) if u else b'0' * 16)
            if not u or not hmac.compare_digest(calc, u['hash']):
                q.append(now)
                raise AuthError('Невірний логін або пароль')
            q.clear()
            token = secrets.token_urlsafe(32)
            self.sessions[_tok_id(token)] = {'user': name, 'exp': now + SESSION_TTL, 'created': int(now)}
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
            if s['exp'] - now < SESSION_TTL - 86400:      # sliding expiry, written at most once a day
                s['exp'] = now + SESSION_TTL
                self._save_sessions()
            return s['user']

    def logout(self, token):
        with self.lock:
            if self.sessions.pop(_tok_id(token or ''), None):
                self._save_sessions()

    def _drop_sessions(self, name, keep=None):
        self.sessions = {k: v for k, v in self.sessions.items() if v['user'] != name or k == keep}
        self._save_sessions()

    # ------------------------------------------------------------ self-service
    def change_own_password(self, name, current, new, token):
        with self.lock:
            u = self.users[name]
            if not hmac.compare_digest(_hash(current or '', bytes.fromhex(u['salt'])), u['hash']):
                raise AuthError('Поточний пароль невірний')
            self._check_new_password(new)
            if new == current:
                raise AuthError('Новий пароль збігається з поточним')
            self._set_password(name, new)
            self._drop_sessions(name, keep=_tok_id(token))   # sign out other devices

    # ------------------------------------------------------------ admin
    def list_users(self):
        with self.lock:
            return [self.public(n) for n in sorted(self.users)]

    def create_user(self, name, role, password):
        with self.lock:
            if not isinstance(name, str) or not NAME_RE.match(name):
                raise AuthError('Логін: 2–32 символи, латиниця, цифри, крапка, дефіс, підкреслення')
            if name in self.users:
                raise AuthError('Такий користувач уже існує')
            if role not in ROLES:
                raise AuthError('Невідома роль')
            self._check_new_password(password)
            self._set_password(name, password, role=role)

    def _admins(self):
        return [n for n, u in self.users.items() if u['role'] == 'admin']

    def update_user(self, actor, name, role=None, password=None):
        with self.lock:
            if name not in self.users:
                raise AuthError('Користувача не знайдено')
            if role is not None:
                if role not in ROLES:
                    raise AuthError('Невідома роль')
                if role != 'admin' and self.users[name]['role'] == 'admin' and len(self._admins()) == 1:
                    raise AuthError('Має лишитися хоча б один адміністратор')
                if name == actor and role != 'admin':
                    raise AuthError('Не можна зняти права адміністратора із самого себе')
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
                raise AuthError('Користувача не знайдено')
            if name == actor:
                raise AuthError('Не можна видалити самого себе')
            if self.users[name]['role'] == 'admin' and len(self._admins()) == 1:
                raise AuthError('Має лишитися хоча б один адміністратор')
            del self.users[name]
            self._save_users()
            self._drop_sessions(name)
