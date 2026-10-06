"""Editions and licensing: Community limits by default; a license issued for this installation's activation request
lifts them, on this server only; bad, foreign, expired, returned licenses keep Community; the records/s limit is a
token bucket averaged over a window. Run: python -m unittest discover -s tests"""
import os
import struct
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
os.environ.setdefault('FT_STATE_DIR', tempfile.mkdtemp())
os.environ.setdefault('FT_CONFIG_DIR', tempfile.mkdtemp())
import common  # noqa: E402
import ftcore  # noqa: E402
import licensing  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

SK = Ed25519PrivateKey.generate()                   # the tests' own vendor key
PK = SK.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
OTHER_SK = Ed25519PrivateKey.generate()
ONLINE_SK = Ed25519PrivateKey.generate()            # the license server's key
ONLINE_PK = ONLINE_SK.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
HERE = {'machine': 'a' * 32, 'board': '4c4c4544-0042-3510-8051-b4c04f4e3732', 'macs': ['2c:f0:5d:96:61:98', 'e0:d4:e8:72:34:f9']}
REAL_HW = licensing.hardware
if not ftcore.TESTING:
    raise unittest.SkipTest('needs a testing build of ftcore (cargo build --features testing)')
ftcore._testing(public_key=PK, online_key=ONLINE_PK)


def pack(lic):
    """What the License Manager signs (FlowTrack license v2 body; v3 = online, + lease days)."""
    mask = sum(1 << licensing.FEATURES.index(f) for f in lic.get('features') or [])
    b, cust = lic['binding'], lic['customer'].encode()
    if len(cust) > ftcore.CUSTOMER_MAX:
        raise ValueError(f'the customer name is longer than {ftcore.CUSTOMER_MAX} bytes')
    v3 = lic.get('lease_days') is not None
    body = struct.pack('>BB6sIIIHI10s6s6s6s', 3 if v3 else 2, 1, lic['id'], lic['issued'], lic['expires'], lic.get('rps') or 0,
                       lic['retention_days'], mask, b[:10], b[10:16], b[16:22], b[22:28])
    if v3:
        body += struct.pack('>H', lic['lease_days'])
    return body + bytes([len(cust)]) + cust


def issue(hw=HERE, days=365, sk=SK, **kw):
    now = int(time.time())
    lic = dict(id=os.urandom(6), edition='pro', issued=now, expires=now + days * 86400 + 3600,   # an hour of margin: days_left must not depend on test speed
               rps=None, retention_days=90,
               features=['alerts'], binding=licensing.parse_request(licensing.request_code(hw))['binding'],
               customer='ТОВ «Тест»')
    lic.update(kw)
    body = pack(lic)
    prefix = b'FlowTrack license v3\0' if lic.get('lease_days') is not None else b'FlowTrack license v2\0'
    return licensing.encode('FTL', body + sk.sign(prefix + body))


def lease(code, hw=HERE, until=None, issued=None, sk=ONLINE_SK):
    """A lease from the license server for license `code` on `hw`."""
    lic = licensing.verify(code)
    now = int(time.time())
    body = struct.pack('>B6s10sII', 1, bytes.fromhex(lic['id']), lic['binding'][:10] if hw is HERE else
                       licensing.parse_request(licensing.request_code(hw))['binding'][:10],
                       issued or now, until or now + 30 * 86400)
    return licensing.encode('FTS', body + sk.sign(b'FlowTrack lease v1\0' + body))


class Base(unittest.TestCase):
    def setUp(self):
        state = tempfile.mkdtemp()
        common.LICENSE_FILE = os.path.join(state, 'license.key')
        common._edition.update(key=None, value=None)
        licensing.STATE_DIR = state
        self.hw = dict(HERE)
        ftcore._testing(public_key=PK, online_key=ONLINE_PK, hardware=lambda: self.hw)

    def tearDown(self):
        ftcore._testing(public_key=PK, online_key=ONLINE_PK)


class Codes(unittest.TestCase):
    def test_round_trip_and_typos(self):
        data = os.urandom(29)
        code = licensing.encode('FTR', data)
        self.assertRegex(code, r'^FTR(-[0-9A-Z]{1,5})+$')
        self.assertEqual(licensing.decode('FTR', code), data)
        sloppy = '# a comment line\n' + code.lower().replace('-', ' ').replace('0', 'o').replace('1', 'l') + '\n'
        self.assertEqual(licensing.decode('FTR', sloppy), data)
        for i in (6, 20, len(code) - 2):
            typo = code[:i] + ('A' if code[i] != 'A' else 'B') + code[i + 1:]
            with self.assertRaisesRegex(ValueError, 'checksum'):
                licensing.decode('FTR', typo)
        with self.assertRaises(ValueError):                 # the last character's unused bits must be zero
            licensing.decode('FTR', code[:-1] + licensing.ALPHABET[licensing.ALPHABET.index(code[-1]) ^ 1])

    def test_request(self):
        req = licensing.request_code(HERE)
        self.assertLess(len(req), 70)                       # short enough to read out by phone
        r = licensing.parse_request(req)
        self.assertEqual((r['instance'], r['board'], r['nics']), (licensing.instance_id(HERE), True, 2))
        self.assertRegex(r['instance'], r'^[0-9A-Z]{4}(-[0-9A-Z]{4}){3}$')
        bare = licensing.parse_request(licensing.request_code({'machine': 'b' * 32, 'board': '', 'macs': []}))
        self.assertEqual((bare['board'], bare['nics']), (False, 0))
        with self.assertRaisesRegex(ValueError, 'not a FlowTrack activation request'):
            licensing.parse_request('FTL-' + req[4:])

    def test_real_hardware(self):
        hw = REAL_HW()
        self.assertTrue(hw['machine'])
        self.assertTrue(licensing.bound_here(licensing.binding(hw), hw))


class Edition(Base):
    def test_community_by_default(self):
        ed = common.edition()
        self.assertEqual((ed['name'], ed['status'], ed['rps'], ed['retention_days']), ('community', 'community', 5000, 14))

    def test_license_for_this_server(self):
        ed = common.save_license(issue(rps=20000))
        self.assertEqual((ed['name'], ed['status'], ed['rps'], ed['retention_days'], ed['features']), ('pro', 'active', 20000, 90, ['alerts']))
        self.assertEqual((ed['license']['customer'], ed['license']['days_left'], ed['license']['instance']),
                         ('ТОВ «Тест»', 365, licensing.instance_id(HERE)))
        self.assertEqual(oct(os.stat(common.LICENSE_FILE).st_mode & 0o777), '0o640')
        self.assertTrue(common.read_license().startswith('FTL-'))
        ed = common.save_license('')                        # removing it: Community again
        self.assertEqual((ed['status'], ed['rps']), ('community', 5000))

    def test_typed_license_with_typos(self):
        code = issue()
        ed = common.save_license('\n'.join(code.lower().replace('-', ' ')[i:i + 40] for i in range(0, len(code), 40)))
        self.assertEqual(ed['status'], 'active')

    def test_another_server(self):
        code = issue({'machine': 'b' * 32, 'board': '', 'macs': ['00:11:22:33:44:55']})
        with self.assertRaises(licensing.LicenseError) as cm:
            common.save_license(code)
        self.assertEqual(cm.exception.code, 'other_instance')
        self.assertIn(licensing.instance_id(HERE), str(cm.exception))
        self.assertFalse(os.path.exists(common.LICENSE_FILE))

    def test_cloned_disk(self):
        common.save_license(issue())
        self.hw = dict(HERE, board='11111111-2222-3333-4444-555555555555', macs=['52:54:00:12:34:56'])   # same disk, other box
        common._edition['value'] = None
        ed = common.edition()
        self.assertEqual((ed['status'], ed['rps']), ('other_instance', 5000))
        self.assertEqual(ed['license']['customer'], 'ТОВ «Тест»')

    def test_hardware_changes_on_the_same_server(self):
        code = issue()
        self.hw = dict(HERE, macs=['52:54:00:12:34:56'])                    # both cards replaced, same board
        self.assertEqual(common.save_license(code)['status'], 'active')
        self.hw = dict(HERE, board='', macs=['52:54:00:12:34:56', HERE['macs'][1]])   # board unreadable, one card left
        common._edition['value'] = None
        self.assertEqual(common.edition()['status'], 'active')

    def test_forged_or_altered(self):
        with self.assertRaisesRegex(ValueError, 'not issued by FlowTrack'):
            common.save_license(issue(sk=OTHER_SK))
        data = bytearray(licensing.decode('FTL', issue(rps=5000)))
        data[17] ^= 1                                       # the records/s limit, with a valid checksum
        with self.assertRaisesRegex(ValueError, 'not issued by FlowTrack'):
            common.save_license(licensing.encode('FTL', bytes(data)))
        with self.assertRaisesRegex(ValueError, 'mistyped'):
            common.save_license(issue()[:-7])
        with self.assertRaisesRegex(ValueError, 'not a FlowTrack license'):
            common.save_license('hello')
        self.assertEqual(common.edition()['status'], 'community')
        with open(common.LICENSE_FILE, 'w') as f:            # a license that went bad on disk
            f.write('FTL-XXXXX')
        common._edition['value'] = None
        self.assertEqual((common.edition()['status'], common.edition()['rps']), ('invalid', 5000))

    def test_expired(self):
        code = issue(days=10)
        common.save_license(code)
        with self.assertRaises(licensing.LicenseError) as cm:
            licensing.check(code, now=time.time() + 11 * 86400)
        self.assertEqual(cm.exception.code, 'expired')
        old = issue(issued=int(time.time()) - 100 * 86400, expires=int(time.time()) - 86400)
        with self.assertRaisesRegex(ValueError, 'expired'):           # an expired license cannot be entered
            common.save_license(old)

    def test_clock_turned_back(self):
        code = issue(days=30)
        now = time.time()
        licensing.check(code, now=now + 20 * 86400)                   # seen running on day 20
        licensing.check(code, now=now + 19 * 86400)                   # a day back: NTP slack, fine
        with self.assertRaises(licensing.LicenseError) as cm:
            licensing.check(code, now=now + 5 * 86400)                # two weeks back: suspended
        self.assertEqual(cm.exception.code, 'clock')
        with self.assertRaises(licensing.LicenseError) as cm:
            licensing.check(issue(), now=now - 3 * 86400)             # before the license was issued
        self.assertEqual(cm.exception.code, 'clock')

    def test_deactivate_and_move(self):
        code = issue()
        common.save_license(code)
        ret = common.deactivate_license()
        self.assertFalse(os.path.exists(common.LICENSE_FILE))
        self.assertEqual(common.edition()['status'], 'community')
        lic = licensing.verify(code)
        data = licensing.decode('FTX', ret)                           # what the vendor checks against the register
        self.assertEqual((data[:6].hex(), data[6:]), (lic['id'], licensing.return_tag(lic['id'], lic['binding'])))
        with self.assertRaises(licensing.LicenseError) as cm:         # this server refuses it from now on
            common.save_license(code)
        self.assertEqual(cm.exception.code, 'returned')
        self.assertEqual(common.save_license(issue())['status'], 'active')   # a new license for this server works
        common.save_license('')
        with self.assertRaisesRegex(ValueError, 'no license'):
            common.deactivate_license()

    def test_customer_name_limit(self):
        with self.assertRaisesRegex(ValueError, 'longer than'):
            issue(customer='Я' * 40)


class Online(Base):
    def online(self, **kw):
        return issue(sk=ONLINE_SK, lease_days=30, **kw)

    def test_needs_a_lease(self):
        code = self.online(rps=20000)
        with self.assertRaises(licensing.LicenseError) as cm:
            common.save_license(code)
        self.assertEqual(cm.exception.code, 'unconfirmed')
        ftcore.save_lease(lease(code), licensing.STATE_DIR)
        ed = common.save_license(code)
        self.assertEqual((ed['status'], ed['rps'], ed['license']['online']), ('active', 20000, True))
        self.assertGreater(ed['lease_until'], time.time() + 29 * 86400)

    def test_lease_expiry_and_clock(self):
        code = self.online()
        ftcore.save_lease(lease(code, until=int(time.time()) + 5 * 86400), licensing.STATE_DIR)
        licensing.check(code, now=time.time() + 4 * 86400)
        with self.assertRaises(licensing.LicenseError) as cm:
            licensing.check(code, now=time.time() + 6 * 86400)
        self.assertEqual(cm.exception.code, 'unconfirmed')
        self.assertIn('has not confirmed', str(cm.exception))

    def test_lease_of_another_installation_or_license(self):
        code = self.online()
        other = {'machine': 'b' * 32, 'board': '', 'macs': []}
        with self.assertRaisesRegex(ValueError, 'not for this one'):
            ftcore.save_lease(lease(code, hw=other), licensing.STATE_DIR)
        ftcore.save_lease(lease(self.online()), licensing.STATE_DIR)          # a lease of another license
        with self.assertRaises(licensing.LicenseError) as cm:
            licensing.check(code)
        self.assertEqual(cm.exception.code, 'unconfirmed')

    def test_forged_lease(self):
        code = self.online()
        with self.assertRaisesRegex(ValueError, 'not issued'):
            ftcore.save_lease(lease(code, sk=OTHER_SK), licensing.STATE_DIR)

    def test_online_key_signs_only_online_licenses(self):
        with self.assertRaisesRegex(ValueError, 'not issued by FlowTrack'):
            common.save_license(issue(sk=ONLINE_SK))                     # an offline (v2) license: master key only
        code = issue(lease_days=30)                                        # the master key may sign online ones
        ftcore.save_lease(lease(code, sk=SK), licensing.STATE_DIR)         # and their leases
        self.assertEqual(common.save_license(code)['status'], 'active')

    def test_offline_licenses_need_no_lease(self):
        ed = common.save_license(issue())
        self.assertEqual((ed['status'], ed['license']['online'], ed['lease_until']), ('active', False, None))

    def test_deactivation_drops_the_lease(self):
        code = self.online()
        ftcore.save_lease(lease(code), licensing.STATE_DIR)
        common.save_license(code)
        common.deactivate_license()
        self.assertIsNone(ftcore.lease(licensing.STATE_DIR))


class Limit(Base):
    def test_bucket(self):
        t = [0.0]
        r = ftcore.RateLimit(rate=10, window=5, clock=lambda: t[0])
        self.assertEqual(sum(r.take() for _ in range(80)), 50)     # a burst gets the whole window (10/s x 5 s)
        t[0] += 2
        self.assertEqual(sum(r.take() for _ in range(80)), 20)     # then 10 per second
        t[0] += 100
        self.assertEqual(sum(r.take() for _ in range(80)), 50)     # the bucket never holds more than the window

    def test_unlimited(self):
        r = ftcore.RateLimit(rate=0)
        self.assertTrue(all(r.take() for _ in range(100000)))

    def test_follows_the_edition(self):
        common.edition()
        r = ftcore.RateLimit(4)
        self.assertEqual(r.rate, 1250)                              # Community 5,000/s shared by 4 workers
        common.save_license(issue(rps=20000))
        r.take()
        self.assertEqual(r.rate, 5000)
        common.save_license(issue(rps=None))
        r.take()
        self.assertIsNone(r.rate)
        common.save_license('')
        r.take()
        self.assertEqual(r.rate, 1250)


if __name__ == '__main__':
    unittest.main()
