"""FlowTrack licensing: the identity of this installation, activation requests, and licenses bound to it.

Every installation has an Instance ID derived from the machine (/etc/machine-id), so it survives a reinstall on the
same server. A license is issued for one activation request, which carries the Instance ID and salted hashes of the
hardware: the board UUID and up to two network cards. FlowTrack accepts a license only on the installation it was
issued for — a copied disk or a shared key does not work elsewhere. The check needs no network: activation works
the same online and in closed networks, the codes are short enough to type.

Codes are Crockford base32 in groups of five, with a prefix that names them:
  FTR-…  activation request    version, instance (10 B), board, NIC 1, NIC 2 (6 B hashes), checksum
  FTL-…  license               body + Ed25519 signature + checksum; the body is the edition, term and binding
  FTX-…  return code           proof that a license was deactivated here, to move it to another server
  FTK-…  license key           a purchase, activated online: the license server issues the license for this server
  FTS-…  lease                 the license server's signed confirmation that an online license holds until a date

Online licenses (from a license key) need the license server: FlowTrack checks in every day and receives a new
lease; without one for longer than the lease (30 days) the Community limits apply. Offline licenses (FTL-… from the
vendor) need no network.

The work is done by the compiled FlowTrack core (`ftcore`), which also holds the vendor's public key and the
Community limits; this module is its Python face.

Command line (installed as `flowtrack-license`): licensing.py status | request | activate FILE|CODE|KEY|- | checkin | deactivate
"""
import hashlib
import http.client
import json
import os
import ssl
import sys
import time
import urllib.parse

import ftcore

STATE_DIR = os.environ.get('FT_STATE_DIR', '/var/lib/flowtrack')
# The license server and the SHA-256 of its TLS certificate (pinned: the server uses its own certificate, so no
# public CA is involved and nobody in between can read a license key). Responses are signed by the server's key,
# which the compiled core checks.
LICENSE_SERVER = os.environ.get('FT_LICENSE_SERVER', 'https://lic.telesphera.net:8443')
LICENSE_SERVER_PIN = os.environ.get('FT_LICENSE_SERVER_PIN', '6e3498f6c56906fc2f727246cba9a18b4ee32b37e8bcce1729ac7ae92e123eef')
CHECKIN_FILE = 'license.checkin'       # the last check-in: {'ts', 'ok', 'error'}
FEATURES = list(ftcore.FEATURES)       # bit n of a license's feature mask (reserved; every feature is in every edition)
ALPHABET = ftcore.ALPHABET
LicenseError = ftcore.LicenseError     # a ValueError; .code: invalid | expired | other_instance | returned | clock
encode, decode, format_instance, parse_request, verify, normalized, return_tag = (
    ftcore.encode, ftcore.decode, ftcore.format_instance, ftcore.parse_request, ftcore.verify, ftcore.normalized,
    ftcore.return_tag)


def hardware():
    """What binds a license to this server: {'machine', 'board', 'macs'} (empty when unknown)."""
    return ftcore.hardware(STATE_DIR)


def instance_id(hw=None):
    """'XXXX-XXXX-XXXX-XXXX' — the name of this installation in licenses and in the vendor's register."""
    return ftcore.instance_id(STATE_DIR, hw)


def binding(hw=None):
    """-> 28 bytes: instance, board hash, NIC 1 hash, NIC 2 hash (zeros when absent)."""
    return ftcore.binding(STATE_DIR, hw)


def request_code(hw=None):
    """The activation request the customer sends to get a license for this installation."""
    return ftcore.request_code(STATE_DIR, hw)


def bound_here(bind, hw=None):
    return ftcore.bound_here(STATE_DIR, bind, hw)


def check(text, now=None):
    """-> {'name', 'rps', 'retention_days', 'features', 'license'} when the license is valid on this installation
    now; LicenseError (with .code) otherwise. Licenses are always time-limited."""
    return ftcore.check(text, STATE_DIR, now)


def deactivate(text):
    """Refuse this license on this installation from now on -> the return code for the vendor."""
    return ftcore.deactivate(text, STATE_DIR)


def edition():
    """Limits in effect with the installed license (see common.edition)."""
    return ftcore.edition(STATE_DIR)


# ------------------------------------------------------------------ the license server
class ServerError(ValueError):
    """The license server refused (code: invalid | unknown | in_use | revoked | expired | returned | other_instance
    | busy | error) or could not be reached (code: unreachable)."""
    def __init__(self, msg, code='error'):
        super().__init__(msg)
        self.code = code


def _post(path, body, timeout=20):
    from common import VERSION
    u = urllib.parse.urlsplit(LICENSE_SERVER)
    data = json.dumps(dict(body, version=VERSION)).encode()
    conn = None
    try:
        if u.scheme == 'https':
            ctx = ssl.create_default_context()
            if LICENSE_SERVER_PIN:              # the server's own certificate, checked by its fingerprint below
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout, context=ctx)
            conn.connect()
            if LICENSE_SERVER_PIN:
                got = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
                if got != LICENSE_SERVER_PIN.replace(':', '').lower():
                    raise ServerError('the license server presented an unexpected certificate', 'unreachable')
        else:
            conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
        conn.request('POST', path, data, {'Content-Type': 'application/json'})
        r = conn.getresponse()
        out = json.loads(r.read() or b'{}')
    except ServerError:
        raise
    except (OSError, ValueError, http.client.HTTPException) as ex:
        raise ServerError(f'the license server cannot be reached ({LICENSE_SERVER}): {ex}', 'unreachable') from None
    finally:
        if conn:
            conn.close()
    if r.status != 200:
        raise ServerError(out.get('error') or f'license server error {r.status}', out.get('code', 'error'))
    return out


def _record(ok, error=''):
    try:
        with open(os.path.join(STATE_DIR, CHECKIN_FILE + '.tmp'), 'w') as f:
            json.dump({'ts': int(time.time()), 'ok': ok, 'error': error[:300]}, f)
        os.replace(os.path.join(STATE_DIR, CHECKIN_FILE + '.tmp'), os.path.join(STATE_DIR, CHECKIN_FILE))
    except OSError:
        pass


def last_checkin():
    try:
        with open(os.path.join(STATE_DIR, CHECKIN_FILE)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def activate_key(key):
    """License key (FTK-…) -> the online license (FTL-…) for this installation; its lease is stored."""
    r = _post('/v1/activate', {'key': ' '.join(key.split()), 'request': request_code()})
    ftcore.save_lease(r['lease'], STATE_DIR)
    _record(True)
    return r['license']


def checkin(text):
    """Renew the lease of the online license `text` -> a renewed license code when the vendor extended it, else
    None. ServerError(code 'revoked' | 'returned') means the license must be dropped here."""
    try:
        r = _post('/v1/checkin', {'license': text, 'request': request_code()})
        ftcore.save_lease(r['lease'], STATE_DIR)
    except ServerError as ex:
        _record(False, str(ex))
        raise
    _record(True)
    return r.get('license')


def release_online(text):
    """Tell the license server that this installation gave the license up (the key is free for another server)."""
    _post('/v1/deactivate', {'license': text, 'request': request_code()})


# ------------------------------------------------------------------ command line (root)
def _cli(argv):
    import common
    cmd = argv[1] if len(argv) > 1 else 'status'
    if cmd == 'request':
        print('Instance ID:       ', instance_id())
        print('Activation request:', request_code())
    elif cmd == 'status':
        ed = common.edition()
        lic = ed['license'] or {}
        print('Instance ID:', instance_id())
        print('Edition:    ', ed['name'] + ('' if ed['status'] in ('community', 'active') else f" ({ed['status']}: {ed['message']})"))
        if lic:
            print('Licensed to:', lic['customer'], '· until', time.strftime('%Y-%m-%d', time.gmtime(lic['expires'])))
    elif cmd == 'activate' and len(argv) > 2:
        src = argv[2]
        text = sys.stdin.read() if src == '-' else open(src).read() if os.path.exists(src) else src
        ed = common.save_license(text)
        print('Activated:', ed['license']['customer'], '· until', time.strftime('%Y-%m-%d', time.gmtime(ed['license']['expires'])))
    elif cmd == 'checkin':
        ed = common.license_checkin()
        print('Edition:', ed['name'], ed['status'], '· confirmed until', time.strftime('%Y-%m-%d', time.gmtime(ed['lease_until'])) if ed.get('lease_until') else '')
    elif cmd == 'deactivate':
        r = common.deactivate_license(with_code=True)
        if r['released']:
            print('Deactivated: the license key can now be activated on another server.')
        else:
            print('Return code (send it to your FlowTrack vendor):', r['return_code'])
    else:
        sys.exit(__doc__)


if __name__ == '__main__':
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        _cli(sys.argv)
    except (ValueError, OSError) as ex:
        sys.exit(f'error: {ex}')
