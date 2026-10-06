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

The work is done by the compiled FlowTrack core (`ftcore`), which also holds the vendor's public key and the
Community limits; this module is its Python face.

Command line (installed as `flowtrack-license`): licensing.py status | request | activate FILE|CODE|- | deactivate
"""
import os
import sys
import time

import ftcore

STATE_DIR = os.environ.get('FT_STATE_DIR', '/var/lib/flowtrack')
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
