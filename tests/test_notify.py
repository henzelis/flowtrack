"""Telegram notifications (1.6.2): settings checks, the message — no network needed (the sending runs against a
stand-in Bot API in flowtrack-verify detect_check.py). Run: python -m unittest discover -s tests"""
import os
import sys
import tempfile
import unittest

os.environ['FT_STATE_DIR'] = tempfile.mkdtemp(prefix='ft-notify-test-')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import notify as N  # noqa: E402

TOK = '123456789:AAbbccddeeffgghhiijjkkllmmnnoopp'


class Settings(unittest.TestCase):
    def test_validate(self):
        c = N.validate({'telegram': {'on': True, 'token': TOK, 'chat': '-1001234567890', 'min_sev': 'crit', 'lang': 'en',
                                     'link': 'https://ft.example/'}, 'kinds': {'probes': False}, 'per_hour': '5000'}, N.defaults())
        self.assertEqual(c['telegram']['link'], 'https://ft.example')
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


if __name__ == '__main__':
    unittest.main()
