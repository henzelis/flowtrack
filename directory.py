"""Sign-in through a directory (1.12.0): Active Directory or any LDAP server.

FlowSphera looks the user up with a service account (bind DN + password), checks the password by binding as the user
found, and gives the role of the user's groups: one of the administrator groups -> admin, one of the viewer groups ->
viewer (or anyone who signs in, when that is ticked); nobody else gets in. Active Directory groups count nested (the
LDAP_MATCHING_RULE_IN_CHAIN rule), other servers by memberOf or by the groups' member / uniqueMember / memberUid.

Local users always come first: a name that exists locally signs in with its local password only, so an administrator
keeps a way in when the directory is unreachable. Directory users are kept in users.json without a password (source
'ldap') — their role is worked out again at every sign-in, and their sessions end after 12 hours.

The settings live in STATE_DIR/ldap.json (0600, the service user only); the service account's password never goes to
the browser or the log."""
import hashlib
import json
import os
import re
import ssl
import tempfile

from common import STATE_DIR, tr

CONFIG = os.path.join(STATE_DIR, 'ldap.json')
KINDS = ('ad', 'ldap')
SECURITY = ('ldaps', 'starttls', 'none')
HOST_RE = re.compile(r'^([A-Za-z0-9_-]{1,63}\.)*[A-Za-z0-9_-]{1,63}$|^[0-9a-fA-F:.]{2,39}$')
USER_RE = re.compile(r'^[A-Za-z0-9._@-]{1,128}$')
NAME_RE = re.compile(r'^[A-Za-z0-9._-]{1,64}$')         # what a directory user is called in FlowSphera
FILTERS = {'ad': '(&(objectCategory=person)(objectClass=user)(|(sAMAccountName={u})(userPrincipalName={u})))',
           'ldap': '(&(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=person))(uid={u}))'}
NAME_ATTR = {'ad': 'sAMAccountName', 'ldap': 'uid'}
IN_CHAIN = '1.2.840.113556.1.4.1941'                     # AD: membership through nested groups


class DirectoryError(Exception):
    """Something to tell people (never with the password)."""


def defaults():
    return {'on': False, 'label': '', 'kind': 'ad', 'host': '', 'port': 636, 'security': 'ldaps', 'verify': True, 'ca': '',
            'bind_dn': '', 'bind_password': '', 'base_dn': '', 'user_filter': '', 'admin_groups': [], 'viewer_groups': [],
            'everyone_viewer': False, 'timeout': 8}


def load():
    cfg = defaults()
    try:
        with open(CONFIG) as f:
            saved = json.load(f)
        cfg.update({k: v for k, v in saved.items() if k in cfg})
    except (FileNotFoundError, ValueError):
        pass
    return cfg


def save(cfg):
    tmp = CONFIG + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(cfg, f, indent=1, ensure_ascii=False)
    os.replace(tmp, CONFIG)


def public(cfg):
    return dict(cfg, bind_password='', bind_password_set=bool(cfg['bind_password']),
                default_filter=FILTERS[cfg['kind']], default_filters=FILTERS)


def method(cfg):
    """What the sign-in page offers besides the local account (no secrets: anyone may ask)."""
    if not cfg['on']:
        return None
    return {'id': 'ldap', 'label': cfg['label'] or ('Active Directory' if cfg['kind'] == 'ad' else 'LDAP')}


def _groups(v):
    v = v if isinstance(v, list) else re.split(r'[\n;]+', str(v or ''))
    out = [str(x).strip() for x in v if str(x).strip()]
    if len(out) > 50 or any(len(x) > 500 for x in out):
        raise ValueError(tr('At most 50 groups, each up to 500 characters.'))
    return out


def validate(body, old):
    """The settings from the UI, checked; an empty password keeps the stored one. ValueError for people."""
    c = defaults()
    c['on'] = bool(body.get('on'))
    label = str(body.get('label') or '').strip()
    if len(label) > 40 or any(ord(ch) < 32 for ch in label):
        raise ValueError(tr('The name on the sign-in page: up to 40 characters.'))
    c['label'] = label
    if body.get('kind') in KINDS:
        c['kind'] = body['kind']
    host = str(body.get('host') or '').strip()
    if host and not HOST_RE.match(host):
        raise ValueError(tr('The directory server is a host name or an IP address, e.g. dc1.example.com.'))
    c['host'] = host
    if body.get('security') in SECURITY:
        c['security'] = body['security']
    try:
        c['port'] = (636 if c['security'] == 'ldaps' else 389) if body.get('port') in (None, '') else int(body['port'])
        assert 1 <= c['port'] <= 65535
    except (TypeError, ValueError, AssertionError):
        raise ValueError(tr('The port is a number 1–65535.')) from None
    c['verify'] = bool(body.get('verify', True))
    ca = str(body.get('ca') or '').strip()
    if ca and ('-----BEGIN CERTIFICATE-----' not in ca or len(ca) > 20000):
        raise ValueError(tr('The CA certificate is PEM text starting with -----BEGIN CERTIFICATE-----.'))
    c['ca'] = ca
    for k, n in (('bind_dn', 500), ('base_dn', 500), ('user_filter', 500)):
        v = str(body.get(k) or '').strip()
        if len(v) > n or any(ord(ch) < 32 for ch in v):
            raise ValueError(tr('{field}: up to {n} characters, one line.', field=k, n=n))
        c[k] = v
    if c['user_filter'] and '{u}' not in c['user_filter']:
        raise ValueError(tr('The user filter must contain {u} where the typed name goes.'))
    pw = str(body.get('bind_password') or '')
    if len(pw) > 256 or any(ord(ch) < 32 for ch in pw):
        raise ValueError(tr('The password: up to 256 characters, no control characters.'))
    c['bind_password'] = pw or old['bind_password']
    c['admin_groups'], c['viewer_groups'] = _groups(body.get('admin_groups')), _groups(body.get('viewer_groups'))
    c['everyone_viewer'] = bool(body.get('everyone_viewer'))
    if c['on']:
        if not (c['host'] and c['base_dn']):
            raise ValueError(tr('Enter the directory server and the base DN to switch sign-in through the directory on.'))
        if not (c['admin_groups'] or c['viewer_groups'] or c['everyone_viewer']):
            raise ValueError(tr('Name at least one group (or let everyone in as a viewer): otherwise nobody can sign in.'))
    return c


# ------------------------------------------------------------------ talking to the server

_TLS = []


def _tls_class():
    """ldap3's Tls with Python's own certificate and host-name check: ldap3 falls back to an old match_hostname that
    does not know IP addresses in certificates (Python 3.12 removed ssl.match_hostname), so a directory reached by its IP
    was refused even with the right CA. TLS 1.2 at least."""
    if not _TLS:
        import ldap3

        class Tls(ldap3.Tls):
            def wrap_socket(self, connection, do_handshake=False):
                if self.validate == ssl.CERT_NONE:
                    ctx = ssl._create_unverified_context()
                else:
                    ctx = ssl.create_default_context(cafile=self.ca_certs_file)      # system CAs when none is given
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                connection.socket = ctx.wrap_socket(connection.socket, server_side=False, do_handshake_on_connect=do_handshake,
                                                    server_hostname=connection.server.host)
        _TLS.append(Tls)
    return _TLS[0]


def _server(cfg):
    import ldap3
    tls = None
    if cfg['security'] != 'none':
        ca_file = None
        if cfg['ca']:              # written once per certificate (the services have a private /tmp)
            ca_file = os.path.join(tempfile.gettempdir(), f"ft-ldap-ca-{hashlib.sha256(cfg['ca'].encode()).hexdigest()[:16]}.pem")
            if not os.path.exists(ca_file):
                with open(ca_file, 'w') as f:
                    f.write(cfg['ca'])
        tls = _tls_class()(validate=ssl.CERT_REQUIRED if cfg['verify'] else ssl.CERT_NONE, ca_certs_file=ca_file,
                           version=ssl.PROTOCOL_TLS_CLIENT)
    return ldap3.Server(cfg['host'], port=cfg['port'], use_ssl=cfg['security'] == 'ldaps', tls=tls,
                        connect_timeout=cfg['timeout'], get_info=ldap3.NONE)


def _bind(cfg, dn, password):
    """A bound connection, or DirectoryError: server problems explained, wrong credentials -> None."""
    import ldap3
    from ldap3.core import exceptions as X
    where = f"{cfg['host']}:{cfg['port']}"
    try:
        conn = ldap3.Connection(_server(cfg), user=dn or None, password=password or None, receive_timeout=cfg['timeout'],
                                raise_exceptions=False, auto_bind=ldap3.AUTO_BIND_NONE, read_only=True)
        conn.open()
        if cfg['security'] == 'starttls' and not conn.start_tls():
            raise DirectoryError(tr('{where} refused STARTTLS — choose LDAPS (usually port 636) or no encryption.', where=where))
        if not conn.bind():
            if conn.result.get('result') == 49:            # invalidCredentials
                conn.unbind()
                return None
            raise DirectoryError(tr('{where} refused the sign-in: {text}', where=where,
                                    text=(conn.result.get('description') or '') + ' ' + (conn.result.get('message') or '')[:150]))
        return conn
    except DirectoryError:
        raise
    except X.LDAPSocketOpenError as e:
        s = str(e)
        if 'CERTIFICATE_VERIFY_FAILED' in s or 'certificate verify failed' in s:
            why = re.search(r'certificate verify failed: ([^(\'"]+)', s)        # expired, wrong address, unknown issuer…
            raise DirectoryError(tr('The certificate of {where} is not trusted ({why}). Paste the CA certificate of your directory, or untick "Verify the certificate" only for a test server.',
                                    where=where, why=why.group(1).strip() if why else 'verify failed')) from None
        raise DirectoryError(tr('No connection to {where} ({error}).', where=where, error=s[:160])) from None
    except X.LDAPStartTLSError as e:
        why = re.search(r'certificate verify failed: ([^(\'"]+)', str(e))
        if why:
            raise DirectoryError(tr('The certificate of {where} is not trusted ({why}). Paste the CA certificate of your directory, or untick "Verify the certificate" only for a test server.',
                                    where=where, why=why.group(1).strip())) from None
        raise DirectoryError(tr('STARTTLS with {where} failed ({error}).', where=where, error=str(e)[:160])) from None
    except (X.LDAPException, OSError, ssl.SSLError) as e:
        raise DirectoryError(tr('The directory {where} answered with an error: {error}', where=where, error=str(e)[:200])) from None


def _service(cfg):
    conn = _bind(cfg, cfg['bind_dn'], cfg['bind_password'])
    if conn is None:
        raise DirectoryError(tr('The directory did not accept the service account (bind DN or its password is wrong).'))
    return conn


def _find(cfg, conn, username):
    """-> (dn, name in FlowSphera, memberOf list) of the one entry the filter finds, or None."""
    from ldap3.utils.conv import escape_filter_chars
    flt = (cfg['user_filter'] or FILTERS[cfg['kind']]).replace('{u}', escape_filter_chars(username))
    attr = NAME_ATTR[cfg['kind']]
    if not conn.search(cfg['base_dn'], flt, attributes=[attr, 'memberOf', 'uid', 'sAMAccountName', 'cn'], size_limit=2):
        if conn.result.get('result') not in (0, 4, 32):       # success / size limit / no such object
            raise DirectoryError(tr('The search in {base} failed: {text}', base=cfg['base_dn'], text=conn.result.get('description') or ''))
    hits = [e for e in conn.response or [] if e.get('type') == 'searchResEntry']
    if len(hits) != 1:
        return None if not hits else 'many'
    e = hits[0]
    a = e.get('attributes') or {}
    val = lambda k: (a.get(k)[0] if isinstance(a.get(k), list) and a.get(k) else a.get(k)) or ''    # noqa: E731
    name = str(val(attr) or val('uid') or val('sAMAccountName') or username)
    return e['dn'], name, [str(x) for x in (a.get('memberOf') or [])]


def _member_of(cfg, conn, dn, name, direct):
    """Every group DN of the user: AD through nested groups, others by memberOf or by the groups' member attributes."""
    from ldap3.utils.conv import escape_filter_chars
    groups = set(direct)
    if cfg['kind'] == 'ad':
        flt = f'(member:{IN_CHAIN}:={escape_filter_chars(dn)})'
    else:
        flt = f'(|(member={escape_filter_chars(dn)})(uniqueMember={escape_filter_chars(dn)})(memberUid={escape_filter_chars(name)}))'
    if conn.search(cfg['base_dn'], flt, attributes=['cn'], size_limit=500):
        groups |= {e['dn'] for e in conn.response or [] if e.get('type') == 'searchResEntry'}
    return sorted(groups)


def _matches(group_dns, wanted):
    """A configured group is a full DN or just its name (the CN); case does not matter."""
    have = {g.lower() for g in group_dns} | {g.split(',', 1)[0].split('=', 1)[-1].lower() for g in group_dns}
    return [w for w in wanted if w.lower() in have]


def role_of(cfg, group_dns):
    if _matches(group_dns, cfg['admin_groups']):
        return 'admin'
    if _matches(group_dns, cfg['viewer_groups']) or cfg['everyone_viewer']:
        return 'viewer'
    return None


def authenticate(cfg, username, password):
    """-> {'name', 'role', 'dn', 'groups'}; DirectoryError with the reason, or None for a wrong name / password
    (the caller counts it as a failed sign-in and says only "wrong username or password")."""
    if not isinstance(username, str) or not USER_RE.match(username) or not isinstance(password, str) or not password or len(password) > 256:
        return None
    conn = _service(cfg)
    try:
        hit = _find(cfg, conn, username)
        if hit is None:
            return None
        if hit == 'many':
            raise DirectoryError(tr('The user filter finds more than one entry for {u}: make it narrower.', u=username))
        dn, name, direct = hit
        groups = _member_of(cfg, conn, dn, name, direct)
    finally:
        conn.unbind()
    user = _bind(cfg, dn, password)
    if user is None:
        return None
    user.unbind()
    if not NAME_RE.match(name):
        raise DirectoryError(tr('The directory name {name} cannot be used in FlowSphera (letters, digits, dot, hyphen, underscore).', name=name[:80]))
    return {'name': name, 'role': role_of(cfg, groups), 'dn': dn, 'groups': groups}


def test(cfg, username='', password=''):
    """Settings check for the UI: the service account, the base DN, and — with a name — the user, groups and role
    (with a password also the password itself)."""
    out = {'service': False, 'user': None}
    conn = _service(cfg)
    try:
        out['service'] = True
        if not conn.search(cfg['base_dn'], '(objectClass=*)', search_scope='BASE', attributes=['objectClass']):
            raise DirectoryError(tr('The base DN {base} was not found in the directory.', base=cfg['base_dn']))
        if username:
            if not USER_RE.match(username):
                raise DirectoryError(tr('Not a user name: {u}', u=username[:80]))
            hit = _find(cfg, conn, username)
            if hit is None:
                out['user'] = {'found': False}
                return out
            if hit == 'many':
                raise DirectoryError(tr('The user filter finds more than one entry for {u}: make it narrower.', u=username))
            dn, name, direct = hit
            groups = _member_of(cfg, conn, dn, name, direct)
            out['user'] = {'found': True, 'dn': dn, 'name': name, 'groups': groups, 'role': role_of(cfg, groups),
                           'admin_match': _matches(groups, cfg['admin_groups']), 'viewer_match': _matches(groups, cfg['viewer_groups'])}
    finally:
        conn.unbind()
    if username and password and out['user'] and out['user']['found']:
        u = _bind(cfg, out['user']['dn'], password)
        out['user']['password_ok'] = u is not None
        if u:
            u.unbind()
    return out
