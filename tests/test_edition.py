"""Editions: Community limits by default, a Pro module + license lifts them, a bad key keeps Community,
and the records/s limit is a token bucket averaged over a window. Run: python -m unittest discover -s tests"""
import os
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
os.environ.setdefault('FT_STATE_DIR', tempfile.mkdtemp())
os.environ.setdefault('FT_CONFIG_DIR', tempfile.mkdtemp())
import common  # noqa: E402

REAL_PRO_DIR = common.PRO_DIR       # a Pro module installed on this machine must not leak into the tests

FAKE_PRO = '''
ROUTES = {'/api/pro/ping': lambda q: {'pong': True}}
UI_SCRIPTS = ['pro.js']
WEB_DIR = '/nonexistent'
class LicenseError(ValueError):
    def __init__(self, msg, code='invalid', license=None):
        super().__init__(msg); self.code, self.license = code, license
def activate(text):
    if text == 'OLD':
        raise LicenseError('the license expired on 2026-01-01', 'expired', {'customer': 'Test', 'expires': 1767225600})
    if text != 'GOOD':
        raise ValueError('the license key is damaged or was not issued by FlowTrack')
    return {'name': 'pro', 'rps': None, 'retention_days': 90, 'features': ['alerts'], 'license': {'customer': 'Test'}}
'''


class Edition(unittest.TestCase):
    used = []

    def setUp(self):
        self.state, self.pro = tempfile.mkdtemp(), tempfile.mkdtemp()
        common.LICENSE_FILE = os.path.join(self.state, 'license.key')
        common.PRO_DIR = self.pro
        common._edition.update(key=None, value=None)
        sys.modules.pop('flowtrack_pro', None)
        for d in Edition.used + [REAL_PRO_DIR]:     # earlier tests' and the installed module must not be importable
            if d in sys.path:
                sys.path.remove(d)
        Edition.used.append(self.pro)

    def install_module(self):
        os.makedirs(os.path.join(self.pro, 'flowtrack_pro'))
        with open(os.path.join(self.pro, 'flowtrack_pro', '__init__.py'), 'w') as f:
            f.write(textwrap.dedent(FAKE_PRO))

    def test_community_by_default(self):
        ed = common.edition()
        self.assertEqual((ed['name'], ed['status'], ed['rps'], ed['retention_days'], ed['module']), ('community', 'community', 5000, 14, False))

    def test_key_without_module(self):
        with open(common.LICENSE_FILE, 'w') as f:
            f.write('GOOD')
        ed = common.edition()
        self.assertEqual((ed['status'], ed['rps']), ('no_module', 5000))
        with self.assertRaisesRegex(ValueError, 'not installed'):
            common.save_license('GOOD')

    def test_pro_license(self):
        self.install_module()
        ed = common.save_license('GOOD')
        self.assertEqual((ed['name'], ed['status'], ed['rps'], ed['retention_days'], ed['license']['customer']), ('pro', 'active', None, 90, 'Test'))
        self.assertEqual(oct(os.stat(common.LICENSE_FILE).st_mode & 0o777), '0o640')
        ed = common.save_license('')                      # removing the key: Community again
        self.assertEqual((ed['status'], ed['rps']), ('community', 5000))

    def test_bad_key_is_refused_and_keeps_community(self):
        self.install_module()
        with self.assertRaisesRegex(ValueError, 'damaged'):
            common.save_license('BAD')
        self.assertFalse(os.path.exists(common.LICENSE_FILE))
        with open(common.LICENSE_FILE, 'w') as f:            # a key that went bad on disk
            f.write('BAD')
        ed = common.edition()
        self.assertEqual((ed['status'], ed['rps']), ('invalid', 5000))


    def test_expired_license(self):
        self.install_module()
        with open(common.LICENSE_FILE, 'w') as f:
            f.write('OLD')
        ed = common.edition()
        self.assertEqual((ed['status'], ed['rps'], ed['retention_days'], ed['license']['customer']), ('expired', 5000, 14, 'Test'))
        with self.assertRaisesRegex(ValueError, 'expired'):     # an expired key cannot be entered
            common.save_license('OLD')


class Limit(unittest.TestCase):
    def test_bucket(self):
        t = [0.0]
        r = common.RateLimit(10, window=5, clock=lambda: t[0])
        self.assertEqual(sum(r.take() for _ in range(80)), 50)     # a burst gets the whole window (10/s x 5 s)
        t[0] += 2
        self.assertEqual(sum(r.take() for _ in range(80)), 20)     # then 10 per second
        t[0] += 100
        self.assertEqual(sum(r.take() for _ in range(80)), 50)     # the bucket never holds more than the window

    def test_unlimited(self):
        r = common.RateLimit(None)
        self.assertTrue(all(r.take() for _ in range(100000)))


if __name__ == '__main__':
    unittest.main()
