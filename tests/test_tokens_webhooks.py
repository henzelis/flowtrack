"""1.11.0: API tokens (scopes, what a token can never do, wrong tokens counted with failed logins, end dates) through
the real HTTP handler, webhooks (FlowSphera JSON / Slack / Discord, HMAC signature, extra header, errors) against a
local receiver, and the SIEM channel (RFC 5424 + CEF / JSON over UDP, TCP and TLS, no hourly limit).
Run: python -m unittest discover -s tests"""
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
        self.assertEqual((d['source'], d['more'], d['link']), ('FlowTrack', 2, 'https://ft.example.com'))      # a field machines read: the former name stays
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
import datetime  # noqa: E402
import socket  # noqa: E402
import socketserver  # noqa: E402
import ssl  # noqa: E402

ROW = {'kind': 'port_scan', 'key': '203.0.113.5', 'first_seen': '2026-10-18 15:00:00', 'last_seen': '2026-10-18 15:10:00', 'hits': 2,
       'exporter': '192.0.2.1', 'src': '203.0.113.5', 'dst': '198.51.100.1', 'port': 22, 'proto': 6, 'value': 9,
       'info': json.dumps({'country': 'NL', 'org': 'Ex|ample=1', 'asn': 64500, 'ports': list(range(80))})}
EV = [{'kind': 'port_scan', 'sev': 'warn', 'title': 'Port scan', 'text': 'tried a=b\nports', 'row': ROW}]


def self_signed(dirname):
    """A throwaway certificate for 127.0.0.1 (the `cryptography` the installer puts in the venv)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import ipaddress
    k = ec.generate_private_key(ec.SECP256R1())
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'siem.test')])
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(1)
         .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
         .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False).sign(k, hashes.SHA256()))
    cert, key = os.path.join(dirname, 'c.pem'), os.path.join(dirname, 'k.pem')
    with open(cert, 'wb') as f:
        f.write(c.public_bytes(serialization.Encoding.PEM))
    with open(key, 'wb') as f:
        f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert, key


class Siem(unittest.TestCase):
    got = []

    @classmethod
    def setUpClass(cls):
        class Udp(socketserver.BaseRequestHandler):
            def handle(self):
                Siem.got.append(('udp', self.request[0]))

        class Tcp(socketserver.StreamRequestHandler):
            def handle(self):
                for line in self.rfile:
                    Siem.got.append(('tcp', line.rstrip(b'\n')))

        cls.udp = socketserver.ThreadingUDPServer(('127.0.0.1', 0), Udp)
        cls.tcp = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Tcp)
        cert, key = self_signed(TMP)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)

        class TlsServer(socketserver.ThreadingTCPServer):
            def get_request(self):
                s, a = self.socket.accept()
                try:
                    return ctx.wrap_socket(s, server_side=True), a
                except (ssl.SSLError, OSError):
                    s.close()
                    raise OSError('handshake refused')
        cls.tls = TlsServer(('127.0.0.1', 0), Tcp)
        for srv in (cls.udp, cls.tcp, cls.tls):
            threading.Thread(target=srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        for srv in (cls.udp, cls.tcp, cls.tls):
            srv.shutdown()

    def setUp(self):
        Siem.got.clear()

    def m(self, **kw):
        return notify._validate_siem(dict({'on': True, 'host': '127.0.0.1'}, **kw))

    def wait(self, n=1):
        for _ in range(50):
            if len(Siem.got) >= n:
                return
            time.sleep(0.05)

    def test_cef_over_udp(self):
        m = self.m(port=self.udp.server_address[1], transport='udp', facility=17)
        notify.siem_send(m, notify.siem_lines(m, EV))
        self.wait()
        line = Siem.got[0][1].decode()
        self.assertTrue(line.startswith('<140>1 '), line)                 # local1 (17) * 8 + warning (4)
        self.assertIn(' FlowTrack - port_scan - CEF:0|FlowTrack|FlowTrack|', line)
        self.assertIn('|port_scan|Port scan|6|', line)
        for part in ('src=203.0.113.5', 'dst=198.51.100.1', 'dpt=22', 'proto=TCP', 'dvc=192.0.2.1', 'cnt=2', 'cs1=NL',
                     'cs2=Ex|ample\\=1', 'cn1=64500', 'msg=tried a\\=b\\nports', 'start=1792335600000', 'end=1792336200000'):
            self.assertIn(part, line)

    def test_cef_without_country_has_no_empty_labels(self):
        m = self.m(port=self.udp.server_address[1])
        line = notify.siem_lines(m, [{'kind': 'test', 'sev': 'info', 'title': 'FlowSphera', 'text': 'hello'}])[0].decode()
        self.assertNotIn('Label', line)
        self.assertIn('msg=hello', line)

    def test_rows_as_the_detector_hands_them(self):
        # detect.py pushes its rows with info already parsed and the times as unix seconds (found on stage: a test with
        # rows read back from the table, info as JSON text, had hidden that country / org / ASN were lost)
        row = dict(ROW, info=json.loads(ROW['info']), first_seen=1792335600, last_seen=1792336200)
        rec = notify.siem_record({'kind': 'port_scan', 'sev': 'warn', 'row': row})
        self.assertEqual((rec['country'], rec['org'], rec['asn'], rec['first_seen']), ('NL', 'Ex|ample=1', 64500, '2026-10-18T15:00:00+00:00'))
        line = notify.siem_lines(self.m(), [dict(EV[0], row=row)])[0].decode()
        self.assertIn('cs1=NL', line)
        self.assertIn('start=1792335600000', line)
        body = notify.webhook_body({'format': 'json'}, [dict(EV[0], row=row)], 0, '')
        self.assertEqual(body['events'][0]['details']['country'], 'NL')

    def test_json_over_tcp(self):
        m = self.m(port=self.tcp.server_address[1], transport='tcp', format='json')
        notify.siem_send(m, notify.siem_lines(m, EV + [dict(EV[0], sev='crit')]))
        self.wait(2)
        self.assertEqual(len(Siem.got), 2)                                  # one message per line
        head, body = Siem.got[0][1].decode().split(' - port_scan - ', 1)
        d = json.loads(body)
        self.assertEqual((d['src'], d['proto'], d['country'], d['asn'], d['severity']), ('203.0.113.5', 'TCP', 'NL', 64500, 'warn'))
        self.assertEqual(len(d['details']['ports']), 50)                    # long lists cut
        self.assertEqual(d['first_seen'], '2026-10-18T15:00:00+00:00')
        self.assertTrue(Siem.got[1][1].startswith(b'<130>1 '))             # crit -> syslog 2

    def test_tls_verifies_the_certificate(self):
        m = self.m(port=self.tls.server_address[1], transport='tls')
        with self.assertRaises(notify.SiemError) as e:
            notify.siem_send(m, notify.siem_lines(m, EV))
        self.assertIn('not trusted', str(e.exception))
        m['verify'] = False
        notify.siem_send(m, notify.siem_lines(m, EV))
        self.wait()
        self.assertTrue(Siem.got and Siem.got[0][1].startswith(b'<132>1 '))

    def test_closed_port_and_settings(self):
        with self.assertRaises(notify.SiemError):
            notify.siem_send(self.m(port=9, transport='tcp'), [b'x'])
        for bad in ({'host': 'bad host!'}, {'port': 0}, {'facility': 8}, {'host': ''}):
            with self.subTest(bad), self.assertRaises(ValueError):
                notify._validate_siem(dict({'on': True, 'host': '127.0.0.1'}, **bad))
        with self.assertRaises(ValueError):
            notify.test_siem(notify.defaults())

    def test_no_hourly_limit(self):
        c = notify.defaults()
        c['siem'] = self.m(port=self.udp.server_address[1])
        c['per_hour'] = 1
        with unittest.mock.patch.object(notify, 'load', lambda: c):
            n = notify.Notifier(log=lambda *a: None)
            ev = [{'kind': 'port_scan', 'row': ROW}] * 3
            kinds = {'port_scan': {'sev': 'warn'}}
            with unittest.mock.patch.object(notify, 'render', lambda e, lang: dict(e, title='Port scan', text='x')):
                self.assertEqual(n.push(ev, kinds, time.time()) + n.push(ev, kinds, time.time()), 6)
                self.wait(6)
        self.assertEqual(len(Siem.got), 6)

if __name__ == '__main__':
    unittest.main()
