"""Notifications: Telegram (1.6.2) — settings checks, the message (the sending runs against a stand-in Bot API in
flowtrack-verify detect_check.py); e-mail (1.6.4) — settings, the letter, and sending to a small SMTP server on
localhost started here. Run: python -m unittest discover -s tests"""
import email
import email.policy
import os
import socketserver
import sys
import tempfile
import threading
import time
import unittest

os.environ['FT_STATE_DIR'] = tempfile.mkdtemp(prefix='ft-notify-test-')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import notify as N  # noqa: E402

TOK = '123456789:AAbbccddeeffgghhiijjkkllmmnnoopp'


class Settings(unittest.TestCase):
    def test_validate(self):
        c = N.validate({'telegram': {'on': True, 'token': TOK, 'chat': '-1001234567890', 'min_sev': 'crit', 'lang': 'en',
                                     'link': 'https://ft.example/'}, 'kinds': {'probes': False}, 'per_hour': '5000'}, N.defaults())
        self.assertEqual(c['link'], 'https://ft.example')         # shared by the channels since 1.6.4
        self.assertEqual((c['telegram']['min_sev'], c['per_hour'], c['kinds']), ('crit', 600, {'probes': False}))
        for bad in ({'telegram': {'token': '123:short'}}, {'telegram': {'chat': 'not a chat'}}, {'telegram': {'link': 'javascript:x'}},
                    {'telegram': {'on': True}}, {'per_hour': 'x'}):
            with self.assertRaises(ValueError, msg=bad):
                N.validate(bad, N.defaults())
        self.assertTrue(N.validate({'telegram': {'chat': '@my_channel'}}, N.defaults()))

    def test_saved_token_kept_and_hidden(self):
        N.save(N.validate({'telegram': {'token': TOK, 'chat': '42'}}, N.defaults()))
        self.assertEqual(oct(os.stat(N.CONFIG).st_mode & 0o777), '0o600')
        p = N.public(N.load())
        self.assertEqual((p['telegram']['token'], p['telegram']['token_set']), ('', True))
        self.assertEqual(N.validate({'telegram': {'on': True, 'chat': '42'}}, N.load())['telegram']['token'], TOK)


class Chats(unittest.TestCase):
    """Find chat: the entered ID is checked with getChat (works after Telegram dropped the 24-hour getUpdates)."""
    def setUp(self):
        self.calls, self.orig = [], N.call

        def fake(token, method, params=None, timeout=15):
            self.calls.append(method)
            if method == 'getUpdates':
                return []                                   # nothing in the last 24 hours
            if params['chat_id'] == '42':
                return {'id': 42, 'type': 'private', 'first_name': 'Yegor', 'last_name': 'B'}
            raise N.TelegramError('Bad Request: chat not found')
        N.call = fake

    def tearDown(self):
        N.call = self.orig

    def test_entered_id_checked(self):
        cfg = N.validate({'telegram': {'token': TOK, 'chat': '42'}}, N.defaults())
        self.assertEqual(N.chats(cfg), [])
        self.assertEqual(N.check_chat(cfg), {'id': '42', 'type': 'private', 'name': 'Yegor B'})
        with self.assertRaises(ValueError) as e:
            N.check_chat(N.validate({'telegram': {'token': TOK, 'chat': '43'}}, N.defaults()))
        self.assertIn('Chat not found', str(e.exception))
        with self.assertRaises(ValueError):
            N.check_chat(N.validate({'telegram': {'chat': '42'}}, N.defaults()))      # no token


class Message(unittest.TestCase):
    def test_escaped_and_limited(self):
        ev = [{'sev': 'crit', 'title': 'A <b>', 'text': 'x & y'}] + [{'sev': 'warn', 'title': f't{i}', 'text': 'z' * 900} for i in range(10)]
        m = N.format_events(ev, 0, 'en', 'https://ft.example')
        self.assertIn('A &lt;b&gt;', m)
        self.assertIn('x &amp; y', m)
        self.assertLess(len(m), 4096)
        self.assertIn('more events', m)
        self.assertTrue(m.endswith('Open the events in FlowTrack</a>'))
        self.assertEqual(m.count('<b>'), m.count('</b>'))


class Sink(socketserver.ThreadingTCPServer):
    """A minimal SMTP server: EHLO with AUTH, AUTH PLAIN/LOGIN (user / pass), MAIL, RCPT (refuses @bad.example), DATA."""
    allow_reuse_address, daemon_threads = True, True

    def __init__(self):
        self.mails = []
        super().__init__(('127.0.0.1', 0), SinkHandler)
        threading.Thread(target=self.serve_forever, daemon=True).start()


class SinkHandler(socketserver.StreamRequestHandler):
    def say(self, line):
        self.wfile.write(line.encode() + b'\r\n')

    def handle(self):
        import base64
        self.say('220 sink ESMTP')
        mail = {'rcpt': []}
        while True:
            line = self.rfile.readline().decode(errors='replace').rstrip('\r\n')
            if not line:
                return
            cmd = line.split(' ', 1)[0].upper()
            if cmd == 'EHLO':
                self.wfile.write(b'250-sink\r\n250 AUTH PLAIN LOGIN\r\n')
            elif cmd == 'AUTH':
                parts = line.split()
                if parts[1].upper() == 'PLAIN':
                    raw = parts[2] if len(parts) > 2 else (self.say('334 ') or self.rfile.readline().strip())
                    _, u, pw = base64.b64decode(raw).decode().split('\0')
                else:
                    self.say('334 VXNlcm5hbWU6')
                    u = base64.b64decode(self.rfile.readline().strip()).decode()
                    self.say('334 UGFzc3dvcmQ6')
                    pw = base64.b64decode(self.rfile.readline().strip()).decode()
                self.say('235 ok' if (u, pw) == ('user', 'pass') else '535 5.7.8 bad credentials')
            elif cmd == 'MAIL':
                mail = {'from': line, 'rcpt': []}
                self.say('250 ok')
            elif cmd == 'RCPT':
                bad = '@bad.example' in line
                mail['rcpt'].append(line)
                self.say('550 no such user' if bad else '250 ok')
            elif cmd == 'DATA':
                self.say('354 go')
                data = b''
                while True:
                    ln = self.rfile.readline()
                    if ln in (b'.\r\n', b''):
                        break
                    data += ln[1:] if ln.startswith(b'..') else ln
                self.server.mails.append(dict(mail, data=data))
                self.say('250 queued')
            elif cmd == 'QUIT':
                self.say('221 bye')
                return
            else:
                self.say('250 ok')


def mail_cfg(at, **kw):
    return N.validate({'email': dict({'on': True, 'host': '127.0.0.1', 'port': at, 'security': 'none', 'user': 'user', 'password': 'pass',
                                      'sender': 'ft@example.com', 'to': 'a@example.com, b@example.com', 'lang': 'en'}, **kw)}, N.defaults())


class Email(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sink = Sink()
        cls.port = cls.sink.server_address[1]

    def test_validate(self):
        c = mail_cfg(25, to='a@example.com; b@example.com a@example.com', security='ssl', verify=False)
        self.assertEqual(c['email']['to'], ['a@example.com', 'b@example.com'])
        self.assertEqual((c['email']['security'], c['email']['verify'], c['email']['port']), ('ssl', False, 25))
        for bad in ({'host': 'smtp example'}, {'port': 70000}, {'sender': 'not-an-address'}, {'to': 'x@y.z, nope'},
                    {'to': ''}, {'user': 'u\nBcc: x@y.z'}, {'to': ', '.join(f'u{i}@x.y' for i in range(21))}):
            with self.assertRaises(ValueError, msg=bad):
                mail_cfg(25, **bad)

    def test_password_kept_hidden_and_telegram_only_clients(self):
        N.save(mail_cfg(25))
        self.assertEqual(oct(os.stat(N.CONFIG).st_mode & 0o777), '0o600')
        p = N.public(N.load())
        self.assertEqual((p['email']['password'], p['email']['password_set']), ('', True))
        again = N.validate({'email': dict(p['email'], password='')}, N.load())
        self.assertEqual(again['email']['password'], 'pass')
        self.assertEqual(N.validate({'email': dict(p['email'], user='', password='')}, N.load())['email']['password'], '')
        tg_only = N.validate({'telegram': {'chat': '42'}, 'kinds': {}}, N.load())       # 1.6.2 clients and checks
        self.assertEqual(tg_only['email'], N.load()['email'])

    def test_link_moved_out_of_telegram(self):
        with open(N.CONFIG, 'w') as f:
            f.write('{"telegram": {"on": false, "chat": "42", "link": "https://old.example"}, "kinds": {}}')
        self.assertEqual(N.load()['link'], 'https://old.example')
        self.assertEqual(N.validate({'telegram': {'link': 'https://ft.example/'}}, N.load())['link'], 'https://ft.example')

    def test_letter(self):
        ev = [{'sev': 'warn', 'title': 'Port scan', 'text': 'x <b> & y'}, {'sev': 'crit', 'title': 'Flood\r\nBcc: evil@x.y', 'text': 'z'}]
        m = N.format_mail(ev, 3, mail_cfg(25)['email'], 'https://ft.example')
        self.assertEqual(m['Subject'], 'FlowTrack: 🟠 Port scan +4')
        self.assertEqual(m['To'], 'a@example.com, b@example.com')
        self.assertIsNone(m['Bcc'])
        plain, rich = m.get_body(('plain',)).get_content(), m.get_body(('html',)).get_content()
        self.assertIn('x <b> & y', plain)
        self.assertIn('x &lt;b&gt; &amp; y', rich)
        self.assertIn('https://ft.example/#v=threats', plain + rich)
        self.assertIn('3 more events', plain)

    def test_sending(self):
        n = len(self.sink.mails)
        N.test_mail(mail_cfg(self.port))
        self.assertEqual(len(self.sink.mails), n + 1)
        got = email.message_from_bytes(self.sink.mails[-1]['data'], policy=email.policy.default)
        self.assertEqual(got['Subject'], 'FlowTrack: test message')
        self.assertEqual(len(self.sink.mails[-1]['rcpt']), 2)
        for kw, says in (({'password': 'wrong'}, 'login or the password'), ({'to': 'x@bad.example'}, 'refused the recipients'),
                         ({'security': 'starttls'}, 'STARTTLS'), ({'port': 1}, 'No connection')):
            with self.assertRaises(ValueError, msg=kw) as e:
                N.test_mail(mail_cfg(self.port, **kw))
            self.assertIn(says, str(e.exception))
            self.assertNotIn('wrong', str(e.exception))

    def test_notifier_per_channel(self):
        cfg = mail_cfg(self.port)
        cfg['email_kinds'] = {'probes': False}
        N.save(cfg)
        n = len(self.sink.mails)
        nt = N.Notifier(log=lambda m: None)
        kinds = {'port_scan': {'sev': 'warn'}, 'probes': {'sev': 'warn'}, 'burst': {'sev': 'info'}}
        ev = [{'kind': k, 'title': k, 'text': 't'} for k in kinds]
        self.assertEqual(nt.push(ev, kinds, time.time()), 1)              # probes off for e-mail, burst below warn
        for _ in range(50):
            if len(self.sink.mails) > n:
                break
            time.sleep(0.1)
        got = email.message_from_bytes(self.sink.mails[-1]['data'], policy=email.policy.default)
        self.assertEqual(got['Subject'], 'FlowTrack: 🟠 port_scan')


if __name__ == '__main__':
    unittest.main()


class GmailLikeLogin(unittest.TestCase):
    """1.12.0: a server that refuses a login and then drops the line (as Gmail does) — smtplib's login() tried a second
    mechanism and failed with "connection closed"; the reason shown must be the login, not the encryption."""
    def test_refused_login_is_named(self):
        import socket
        import threading
        srv = socket.socket()
        srv.bind(('127.0.0.1', 0))
        srv.listen(1)
        tries = []

        def serve():
            c, _ = srv.accept()
            f = c.makefile('rwb')
            f.write(b'220 fake ESMTP\r\n'); f.flush()
            for line in f:
                cmd = line.decode().strip().upper()
                if cmd.startswith('EHLO'):
                    f.write(b'250-fake\r\n250 AUTH LOGIN PLAIN\r\n')
                elif cmd.startswith('AUTH'):
                    tries.append(cmd.split()[1])
                    f.write(b'535 5.7.8 Username and Password not accepted\r\n'); f.flush()
                    c.close()
                    return
                f.flush()
        threading.Thread(target=serve, daemon=True).start()
        import common
        common.set_lang('en')
        m = dict(N.defaults()['email'], host='127.0.0.1', port=srv.getsockname()[1], security='none', user='u', password='p',
                 sender='a@example.com', to=['b@example.com'])
        msg = N._mail(m, 'subject', 'text', '<p>text</p>')
        with self.assertRaises(N.MailError) as e:
            N.smtp_send(m, msg, timeout=5)
        self.assertIn('did not accept the login or the password', str(e.exception))
        self.assertEqual(tries, ['PLAIN'])                       # one attempt only
        self.assertIn('app password', N._auth_refused(dict(m, host='smtp.gmail.com')))
        srv.close()
