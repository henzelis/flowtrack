"""1.11.0: API tokens (scopes, what a token can never do, wrong tokens counted with failed logins, end dates) through
the real HTTP handler, and webhooks (FlowTrack JSON / Slack / Discord, HMAC signature, extra header, errors) against a
local receiver. Run: python -m unittest discover -s tests"""
import hashlib
import hmac
import http.server
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

TMP = tempfile.mkdtemp()
os.makedirs(TMP + '/cfg', exist_ok=True), os.makedirs(TMP + '/state', exist_ok=True)
open(TMP + '/cfg/exporters.json', 'w').write('{}')
os.environ.update(FT_CONFIG_DIR=TMP + '/cfg', FT_STATE_DIR=TMP + '/state')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import api  # noqa: E402
import auth  # noqa: E402
import notify  # noqa: E402
from auth import Auth, AuthError  # noqa: E402


class Tokens(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        auth.TOKENS_FILE = os.path.join(TMP, 'state', 'api_tokens.json')
        api.AUTH = Auth()
        api.AUTH._set_password('boss', 'right-password-1', role='admin')
        cls.srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), api.H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f'http://127.0.0.1:{cls.srv.server_address[1]}'
        cls.read, _ = api.AUTH.create_token('boss', 'grafana', 'read', 0)
        cls.write, _ = api.AUTH.create_token('boss', 'script', 'write', 30)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def call(self, path, token=None, body=None, ip_hdr=None):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode() if body is not None else None,
                                     headers={'Content-Type': 'application/json', **({'Authorization': f'Bearer {token}'} if token else {})})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b'{}')

    def test_scopes(self):
        self.assertEqual(self.call('/api/me', self.read), (200, {'name': 'token:grafana', 'role': 'viewer', 'token': 'read'}))
        self.assertEqual(self.call('/api/me', self.write)[1]['role'], 'admin')
        self.assertEqual(self.call('/api/notify', self.read)[0], 403)              # administrators' settings: not for read
        self.assertEqual(self.call('/api/notify', self.write)[0], 200)
        code, out = self.call('/api/networks', self.read, {'networks': []})       # a read token changes nothing
        self.assertEqual(code, 403)
        self.assertIn('read', out['error'])

    def test_never_for_tokens(self):
        for path, body in (('/api/users', None), ('/api/tokens', None), ('/api/users', {'name': 'x1', 'role': 'admin', 'password': 'p' * 12}),
                           ('/api/tokens', {'name': 'more', 'scope': 'write'}), ('/api/me/password', {'current': 'a', 'new': 'b' * 10}),
                           ('/api/license/deactivate', {}), ('/api/backups/delete', {'ids': ['x']})):
            with self.subTest(path):
                self.assertEqual(self.call(path, self.write, body)[0], 403)
        self.assertNotIn('x1', api.AUTH.users)

    def test_tokens_are_kept_as_fingerprints(self):
        with open(auth.TOKENS_FILE) as f:
            raw = f.read()
        self.assertNotIn(self.read, raw)
        self.assertNotIn(self.write, raw)
        self.assertEqual(oct(os.stat(auth.TOKENS_FILE).st_mode & 0o777), '0o600')
        row = next(t for t in api.AUTH.list_tokens() if t['name'] == 'grafana')
        self.assertTrue(self.read.startswith(row['hint'][:-1]))
        self.assertNotIn('hash', row)

    def test_wrong_tokens_count_with_failed_logins(self):
        ip = '127.0.0.1'
        api.AUTH.fails[ip].clear()
        for _ in range(5):
            self.assertEqual(self.call('/api/me', 'ftapi_wrong')[0], 401)
        self.assertEqual(self.call('/api/me', self.read)[0], 429)                  # then even a right one waits
        api.AUTH.fails[ip].clear()
        self.assertEqual(self.call('/api/me', self.read)[0], 200)

    def test_end_date_and_revoke(self):
        tok, row = api.AUTH.create_token('boss', 'short', 'read', 30)
        self.assertEqual(self.call('/api/me', tok)[0], 200)
        k = next(k for k in api.AUTH.tokens if k[:16] == row['id'])
        api.AUTH.tokens[k]['expires'] = int(time.time()) - 1
        self.assertEqual(self.call('/api/me', tok)[0], 401)
        api.AUTH.fails['127.0.0.1'].clear()
        api.AUTH.delete_token(row['id'])
        with self.assertRaises(AuthError):
            api.AUTH.delete_token(row['id'])

    def test_checks(self):
        for name, scope, days in (('', 'read', 0), ('x' * 49, 'read', 0), ('grafana', 'read', 0), ('ok', 'all', 0), ('ok', 'read', 7)):
            with self.subTest((name, scope, days)), self.assertRaises(AuthError):
                api.AUTH.create_token('boss', name, scope, days)

    def test_last_used(self):
        self.call('/api/me', self.write)
        row = next(t for t in api.AUTH.list_tokens() if t['name'] == 'script')
        self.assertTrue(row['last_used'] and row['last_ip'] == '127.0.0.1')


class Receiver(http.server.BaseHTTPRequestHandler):
    got, status = [], 200

    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        Receiver.got.append((self.headers, body))        # header names: case-insensitive, as HTTP has them
        self.send_response(Receiver.status)
        self.end_headers()
        self.wfile.write(b'nope' if Receiver.status >= 400 else b'ok')

    def log_message(self, *a):
        pass


class Webhooks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Receiver)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f'http://127.0.0.1:{cls.srv.server_address[1]}/hook'

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        Receiver.got.clear()
        Receiver.status = 200

    def cfg(self, **w):
        c = notify.defaults()
        c['webhook'] = notify._validate_webhook(dict({'on': True, 'url': self.url}, **w), c['webhook'])
        c['link'] = 'https://ft.example.com'
        return c

    def test_json_signed(self):
        c = self.cfg(secret='s3cret', header='X-Api-Key: abc123')
        ev = [{'kind': 'port_scan', 'sev': 'warn', 'title': 'Port scan', 'text': '203.0.113.5 tried 9 ports.', 'row': {'src': '203.0.113.5', 'hits': 3, 'addrs': ['x']}}]
        notify.webhook_send(c['webhook'], notify.webhook_body(c['webhook'], ev, 2, c['link']))
        h, body = Receiver.got[0]
        d = json.loads(body)
        self.assertEqual((d['source'], d['more'], d['link']), ('FlowTrack', 2, 'https://ft.example.com'))
        self.assertEqual(d['events'][0]['details'], {'src': '203.0.113.5', 'hits': 3})
        self.assertEqual(d['events'][0]['severity'], 'warn')
        want = hmac.new(b's3cret', h['X-FlowTrack-Timestamp'].encode() + b'.' + body, hashlib.sha256).hexdigest()
        self.assertEqual(h['X-FlowTrack-Signature'], 'sha256=' + want)
        self.assertEqual(h['X-Api-Key'], 'abc123')

    def test_chat_formats(self):
        ev = [{'kind': 'ddos', 'sev': 'crit', 'title': 'DDoS', 'text': 'flood'}]
        for fmt, key, mark in (('slack', 'text', '*DDoS*'), ('discord', 'content', '**DDoS**')):
            c = self.cfg(format=fmt)
            body = notify.webhook_body(c['webhook'], ev, 0, c['link'])
            self.assertEqual(list(body), [key])
            self.assertIn(mark, body[key])
            self.assertIn('https://ft.example.com/#v=threats', body[key])
        self.assertNotIn('X-FlowTrack-Signature', notify.webhook_body(self.cfg()['webhook'], ev, 0, ''))

    def test_errors_for_people(self):
        Receiver.status = 500
        with self.assertRaises(notify.WebhookError) as e:
            notify.webhook_send(self.cfg()['webhook'], {'x': 1})
        self.assertIn('500', str(e.exception))
        with self.assertRaises(notify.WebhookError):
            notify.webhook_send(self.cfg(url='http://127.0.0.1:9/none')['webhook'], {'x': 1})
        with self.assertRaises(ValueError):
            notify.test_webhook(notify.defaults())

    def test_settings(self):
        old = self.cfg(secret='keep', header='X-Api-Key: abc')['webhook']
        w = notify._validate_webhook({'on': True, 'url': self.url, 'secret': '', 'header': ''}, old)
        self.assertEqual((w['secret'], w['header']), ('keep', 'X-Api-Key: abc'))       # empty fields keep the saved ones
        w = notify._validate_webhook({'on': True, 'url': self.url, 'clear_secret': True, 'clear_header': True}, old)
        self.assertEqual((w['secret'], w['header']), ('', ''))
        for bad in ({'url': 'ftp://x'}, {'url': 'javascript:alert(1)'}, {'header': 'no colon'}, {'header': 'X-A: b\r\nX-B: c'}, {'on': True, 'url': ''}):
            with self.subTest(bad), self.assertRaises(ValueError):
                notify._validate_webhook(dict({'url': self.url}, **bad), old)
        pub = notify.public(dict(notify.defaults(), webhook=old))['webhook']
        self.assertEqual((pub['secret'], pub['secret_set'], pub['header'], pub['header_set']), ('', True, 'X-Api-Key', True))

    def test_notifier_sends_through_the_webhook(self):
        c = self.cfg()
        c['webhook_kinds'] = {'probes': False}
        with unittest.mock.patch.object(notify, 'load', lambda: c):
            n = notify.Notifier(log=lambda *a: None)
            sent = n.push([{'kind': 'port_scan', 'title': 'Port scan', 'text': 'x'}, {'kind': 'probes', 'title': 'Probes', 'text': 'y'}],
                          {'port_scan': {'sev': 'warn'}, 'probes': {'sev': 'warn'}}, time.time())
            self.assertEqual(sent, 1)
            for _ in range(50):
                if Receiver.got:
                    break
                time.sleep(0.1)
        d = json.loads(Receiver.got[0][1])
        self.assertEqual([e['kind'] for e in d['events']], ['port_scan'])


import unittest.mock  # noqa: E402

if __name__ == '__main__':
    unittest.main()
