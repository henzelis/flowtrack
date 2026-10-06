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

Command line (installed as `flowtrack-license`): licensing.py status | request | activate FILE|CODE|- | deactivate
"""
import hashlib
import json
import os
import secrets
import struct
import sys
import time

STATE_DIR = os.environ.get('FT_STATE_DIR', '/var/lib/flowtrack')
PUBLIC_KEY = bytes.fromhex('19ced3749623110e4b6af8348a0070e1243fed739d062d4e3785411042227af8')
# bit n of the license's feature mask; append only, never reorder
FEATURES = ['alerts', 'reports', 'api_tokens', 'multi_tenant', 'sso', 'threat_intel']
EDITIONS = {1: 'pro'}
CUSTOMER_MAX = 64            # bytes of UTF-8
CLOCK_SLACK = 2 * 86400      # how far the clock may go back before the license is suspended

ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
_TYPOS = str.maketrans({'O': '0', 'I': '1', 'L': '1'})
_BODY = struct.Struct('>BB6sIIIHI10s6s6s6s')          # version, edition, id, issued, expires, rps, retention, features, binding
_ZERO = bytes(6)
_SIGNED = b'FlowTrack license v2\0'


class LicenseError(ValueError):
    """code: invalid | expired | other_instance | returned | clock; license: public details when the key was genuine."""
    def __init__(self, msg, code='invalid', license=None):
        super().__init__(msg)
        self.code, self.license = code, license


# ------------------------------------------------------------------ codes
def b32(data):
    n, bits, out = int.from_bytes(data, 'big'), len(data) * 8, []
    pad = -bits % 5
    n <<= pad
    for i in range((bits + pad) // 5):
        out.append(ALPHABET[(n >> (5 * i)) & 31])
    return ''.join(reversed(out))


def unb32(text, nbytes):
    n = 0
    for c in text:
        n = n * 32 + ALPHABET.index(c)
    pad = len(text) * 5 - nbytes * 8
    if pad < 0 or pad >= 5 or n & ((1 << pad) - 1):
        raise ValueError('length')
    return (n >> pad).to_bytes(nbytes, 'big')


def group(text, size=5):
    return '-'.join(text[i:i + size] for i in range(0, len(text), size))


def _checksum(data):
    return hashlib.sha256(b'FlowTrack check\0' + data).digest()[:2]


def encode(prefix, data):
    """bytes -> 'PFX-XXXXX-…' with a 2-byte checksum (catches typos before anything else is tried)."""
    return prefix + '-' + group(b32(data + _checksum(data)))


def decode(prefix, text):
    """'PFX-XXXXX-…' (any case, spaces, line breaks, # comment lines; O/I/L typed for 0/1/1) -> bytes."""
    lines = [ln for ln in (text or '').splitlines() if not ln.strip().startswith('#')]
    s = ''.join(''.join(lines).split()).upper().replace('-', '')
    if not s.startswith(prefix):
        raise ValueError('prefix')
    s = s[len(prefix):].translate(_TYPOS)
    if not s or any(c not in ALPHABET for c in s):
        raise ValueError('characters')
    raw = unb32(s, len(s) * 5 // 8)
    data, chk = raw[:-2], raw[-2:]
    if _checksum(data) != chk:
        raise ValueError('checksum')
    return data


# ------------------------------------------------------------------ this installation
_JUNK_UUIDS = {'03000200-0400-0500-0006-000700080009', '00020003-0004-0005-0006-000700080009'}


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ''


def hardware():
    """What binds a license to this server: {'machine', 'board', 'macs'} (empty when unknown).
    The board UUID is readable by root only; the services copy it to STATE_DIR/hw.board when they start."""
    machine = _read('/etc/machine-id')
    if not machine:                                   # no machine-id (unusual): a random id kept in the state dir
        path = os.path.join(STATE_DIR, 'instance.id')
        machine = _read(path)
        if not machine:
            machine = secrets.token_hex(16)
            try:
                with open(path, 'w') as f:
                    f.write(machine + '\n')
            except OSError:
                pass
    board = (_read('/sys/class/dmi/id/product_uuid') or _read(os.path.join(STATE_DIR, 'hw.board'))).lower()
    if board in _JUNK_UUIDS or len(set(board.replace('-', ''))) <= 1:
        board = ''
    macs = []
    try:
        names = sorted(os.listdir('/sys/class/net'), key=lambda n: (not n.startswith(('en', 'eth')), n))
    except OSError:
        names = []
    for n in names:                                   # physical cards only: bridges, VPNs, containers come and go
        if not os.path.exists(f'/sys/class/net/{n}/device'):
            continue
        mac = _read(f'/sys/class/net/{n}/address').lower()
        if mac and mac != '00:00:00:00:00:00' and mac not in macs:
            macs.append(mac)
    return {'machine': machine, 'board': board, 'macs': macs}


def instance_bytes(hw):
    return hashlib.sha256(b'FlowTrack instance\0' + hw['machine'].encode()).digest()[:10]


def instance_id(hw=None):
    """'XXXX-XXXX-XXXX-XXXX' — the name of this installation in licenses and in the vendor's register."""
    return format_instance(instance_bytes(hw or hardware()))


def format_instance(b):
    return group(b32(b), 4)


def _factor(inst, kind, value):
    return hashlib.sha256(b'FlowTrack hw\0' + kind + b'\0' + inst + value.encode()).digest()[:6] if value else _ZERO


def binding(hw=None):
    """-> 28 bytes: instance, board hash, NIC 1 hash, NIC 2 hash (zeros when absent)."""
    hw = hw or hardware()
    inst = instance_bytes(hw)
    macs = (hw['macs'] + ['', ''])[:2]
    return inst + _factor(inst, b'board', hw['board']) + _factor(inst, b'mac', macs[0]) + _factor(inst, b'mac', macs[1])


def request_code(hw=None):
    """The activation request the customer sends to get a license for this installation."""
    return encode('FTR', b'\x01' + binding(hw))


def parse_request(text):
    """-> {'instance', 'binding' (28 bytes), 'board', 'nics'} or ValueError."""
    try:
        data = decode('FTR', text)
    except ValueError:
        raise ValueError('this is not a FlowTrack activation request, or it was mistyped') from None
    if len(data) != 29 or data[0] != 1:
        raise ValueError('this activation request is from another FlowTrack version')
    b = data[1:]
    return {'instance': format_instance(b[:10]), 'binding': b, 'board': b[10:16] != _ZERO,
            'nics': sum(b[i:i + 6] != _ZERO for i in (16, 22))}


def bound_here(bind, hw=None):
    """The license's binding matches this server: the same instance, and the board or one of the cards."""
    hw = hw or hardware()
    inst = instance_bytes(hw)
    if bind[:10] != inst:
        return False
    wanted = {bind[i:i + 6] for i in (10, 16, 22)} - {_ZERO}
    if not wanted:
        return True
    have = {_factor(inst, b'board', hw['board'])} | {_factor(inst, b'mac', m) for m in hw['macs']}
    return bool(wanted & (have - {_ZERO}))


# ------------------------------------------------------------------ licenses
def pack(lic):
    """License fields -> body bytes (what is signed). Fields: id (6 bytes), edition, issued, expires, rps (None =
    unlimited), retention_days, features (names), binding (28 bytes), customer."""
    ed = {v: k for k, v in EDITIONS.items()}[lic['edition']]
    mask = sum(1 << FEATURES.index(f) for f in lic.get('features') or [])
    b = lic['binding']
    cust = lic['customer'].encode()
    if len(cust) > CUSTOMER_MAX:
        raise ValueError(f'the customer name is longer than {CUSTOMER_MAX} bytes')
    return _BODY.pack(2, ed, lic['id'], lic['issued'], lic['expires'], lic.get('rps') or 0, lic['retention_days'],
                      mask, b[:10], b[10:16], b[16:22], b[22:28]) + bytes([len(cust)]) + cust


def unpack(body):
    v, ed, lid, issued, expires, rps, ret, mask, inst, board, m1, m2 = _BODY.unpack_from(body)
    n = body[_BODY.size]
    if len(body) != _BODY.size + 1 + n:
        raise ValueError('length')
    return {'v': v, 'edition': EDITIONS.get(ed, f'edition {ed}'), 'id': lid.hex(), 'issued': issued, 'expires': expires,
            'rps': rps or None, 'retention_days': ret,
            'features': [f for i, f in enumerate(FEATURES) if mask >> i & 1], 'binding': inst + board + m1 + m2,
            'instance': format_instance(inst), 'customer': body[_BODY.size + 1:].decode(errors='replace')}


def license_code(body, signature):
    return encode('FTL', body + signature)


def signed_message(body):
    return _SIGNED + body


def verify(text, public_key=None):
    """-> license fields if the code was signed by the FlowTrack vendor (wherever it was issued for)."""
    try:
        data = decode('FTL', text)
    except ValueError as ex:
        msg = 'this is not a FlowTrack license code' if str(ex) in ('prefix', 'characters') else 'the license code was mistyped or cut short'
        raise LicenseError(msg) from None
    if len(data) < _BODY.size + 1 + 64 or data[0] != 2:
        raise LicenseError('this license is for another FlowTrack version')
    body, sig = data[:-64], data[-64:]
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        raise LicenseError('the Python package "cryptography" is missing — run the installer with --upgrade') from None
    try:
        Ed25519PublicKey.from_public_bytes(public_key or PUBLIC_KEY).verify(sig, signed_message(body))
        lic = unpack(body)
    except (InvalidSignature, ValueError, struct.error):
        raise LicenseError('the license was not issued by FlowTrack or was altered') from None
    if lic['edition'] not in EDITIONS.values():
        raise LicenseError('this license is for another FlowTrack edition')
    return lic


def public(lic, now=None):
    out = {k: lic[k] for k in ('id', 'customer', 'edition', 'issued', 'expires', 'instance')}
    out['days_left'] = max(0, int((lic['expires'] - (now or time.time())) // 86400))
    return out


def _state(name, default):
    try:
        with open(os.path.join(STATE_DIR, name)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _save_state(name, value, strict=False):
    path = os.path.join(STATE_DIR, name)
    try:
        with open(path + '.tmp', 'w') as f:
            json.dump(value, f)
        os.replace(path + '.tmp', path)
    except OSError:
        if strict:
            raise


def check(text, now=None, hw=None, public_key=None):
    """-> {'name', 'rps', 'retention_days', 'features', 'license'} when the license is valid on this installation
    now; LicenseError (with .code) otherwise. Licenses are always time-limited."""
    now = int(now or time.time())
    lic = verify(text, public_key)
    info = public(lic, now)
    if not bound_here(lic['binding'], hw):
        raise LicenseError(f"this license was issued for installation {lic['instance']}, not for this one "
                           f"({instance_id(hw)})", 'other_instance', info)
    if lic['id'] in _state('license.returned', []):
        raise LicenseError('this license was deactivated on this server to move it elsewhere', 'returned', info)
    seen = _state('license.clock', {})
    if now < lic['issued'] - 86400 or now < seen.get(lic['id'], 0) - CLOCK_SLACK:
        raise LicenseError('the system clock is behind — set the correct date and time (NTP)', 'clock', info)
    if now > lic['expires']:
        raise LicenseError('the license expired on ' + time.strftime('%Y-%m-%d', time.gmtime(lic['expires'])), 'expired', info)
    if now > seen.get(lic['id'], 0) + 600:            # the latest time seen while the license was valid
        seen[lic['id']] = now
        _save_state('license.clock', seen)
    return {'name': lic['edition'], 'rps': lic['rps'], 'retention_days': lic['retention_days'],
            'features': lic['features'], 'license': info}


def return_tag(lic_id, binding_):
    return hashlib.sha256(b'FlowTrack return\0' + bytes.fromhex(lic_id) + binding_).digest()[:6]


def return_code(lic):
    return encode('FTX', bytes.fromhex(lic['id']) + return_tag(lic['id'], lic['binding']))


def deactivate(text):
    """Refuse this license on this installation from now on -> the return code for the vendor."""
    lic = verify(text)
    returned = _state('license.returned', [])
    if lic['id'] not in returned:
        _save_state('license.returned', returned + [lic['id']], strict=True)
    return return_code(lic)


def normalized(text):
    """The license code as stored: one line, grouped."""
    return encode('FTL', decode('FTL', text))


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
    elif cmd == 'deactivate':
        print('Return code (send it to your FlowTrack vendor):', common.deactivate_license())
    else:
        sys.exit(__doc__)


if __name__ == '__main__':
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        _cli(sys.argv)
    except (ValueError, OSError) as ex:
        sys.exit(f'error: {ex}')
