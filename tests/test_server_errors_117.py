"""(1.17.0) The web server does not log a browser that closed the connection while its answer was sent; every other
error of a request is still logged with its traceback."""
import contextlib
import io
import os
import ssl
import sys
import tempfile
import unittest

TMP = tempfile.mkdtemp()
os.makedirs(TMP + '/cfg'), os.makedirs(TMP + '/state')
open(TMP + '/cfg/exporters.json', 'w').write('{}')
os.environ.update(FT_CONFIG_DIR=TMP + '/cfg', FT_STATE_DIR=TMP + '/state')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import api  # noqa: E402


class HandleError(unittest.TestCase):
    def logged(self, ex):
        srv, err = api.Server.__new__(api.Server), io.StringIO()
        with contextlib.redirect_stderr(err):
            try:
                raise ex
            except Exception:
                srv.handle_error(None, ('192.0.2.1', 50000))
        return err.getvalue()

    def test_closed_by_the_browser_is_quiet(self):
        for ex in (BrokenPipeError(), ConnectionResetError(), ssl.SSLEOFError(8, 'EOF occurred in violation of protocol')):
            self.assertEqual(self.logged(ex), '', type(ex).__name__)

    def test_a_real_error_is_logged(self):
        self.assertIn('ValueError: boom', self.logged(ValueError('boom')))


if __name__ == '__main__':
    unittest.main()
