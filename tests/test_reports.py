"""Scheduled reports (1.10.0): periods in the report's time zone, the schedule (due, sent once, retried, given up),
the settings checks and the PDF itself (both languages, an empty period)."""
import datetime
import os
import sys
import tempfile
import unittest
from unittest import mock
from zoneinfo import ZoneInfo

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault('FT_STATE_DIR', tempfile.mkdtemp())

import common  # noqa: E402
import notify  # noqa: E402
import reports  # noqa: E402

KYIV = ZoneInfo('Europe/Kyiv')


def ts(*a):
    return int(datetime.datetime(*a, tzinfo=KYIV).timestamp())


def fake_call(log=None):
    """The API as reports.collect sees it, with made-up numbers (documentation addresses only)."""
    def call(path, q):
        if log is not None:
            log.append((path, q))
        t0, t1 = (int(q['from'][0]), int(q['to'][0])) if q.get('from') else (0, 0)
        if path == '/api/summary':
            return {'bytes': 9_000_000_000, 'up': 1_000_000_000, 'down': 8_000_000_000, 'flows': 123456, 'packets': 1, 'p_bytes': 8_000_000_000,
                    'p_flows': 100000, 'hosts': 12, 'p_hosts': 10, 'ips': 512, 'p_ips': 400, 'has_prev': True, 'oldest': t0}
        if path == '/api/series':
            return {'step': 3600, 'rows': [[t, 2_000_000, 300_000, 0, 10] for t in range(t0, t1, 3600)]}
        if path == '/api/top':
            dim = q['dim'][0]
            row = {'int_ip': {'k': '192.0.2.10', 'name': 'printer'}, 'asn': {'k': '64500', 'as_org': 'Example Net', 'country': 'UA'},
                   'service': {'k': 'Example', 'l7': 'HTTPS'}, 'country': {'k': 'UA'}, 'net': {'k': 'Office', 'hosts': 3}}[dim]
            return {'total': 9_000_000_000, 'rows': [dict(row, up=100_000_000, dn=900_000_000)] * 3}
        if path == '/api/alerts':
            return {'alerts': [{'sev': 'warn', 'kind': 'port_scan', 'title': 'Port scan', 'text': '203.0.113.5 tried 9 ports of ours.',
                                'when': '2026-10-12 10:00:00', 'last': '2026-10-12 10:00:00', 'stored': True}] * 20}
        if path == '/api/devices':
            return {'devices': [{'ip': '192.0.2.1', 'name': 'fw', 'proto': 'IPFIX', 'rps': 12.5, 'loss_pct': 0, 'last': t1}]}
        raise AssertionError(path)
    return call


class Periods(unittest.TestCase):
    def rep(self, every, at='07:00'):
        return reports.validate({'name': 'x', 'every': every, 'at': at, 'tz': 'Europe/Kyiv', 'sections': ['summary']})

    def test_day(self):
        r = self.rep('day')
        self.assertEqual(reports.period(r, ts(2026, 10, 18, 0, 30)), (ts(2026, 10, 17), ts(2026, 10, 18)))
        self.assertEqual(reports.period(r, ts(2026, 10, 18, 0, 30), back=1), (ts(2026, 10, 16), ts(2026, 10, 17)))
        self.assertEqual(reports.send_time(r, ts(2026, 10, 18)), ts(2026, 10, 18, 7, 0))

    def test_week_is_monday_to_sunday(self):
        r = self.rep('week')
        for now in (ts(2026, 10, 19, 0, 1), ts(2026, 10, 21, 12), ts(2026, 10, 25, 23, 59)):
            self.assertEqual(reports.period(r, now), (ts(2026, 10, 12), ts(2026, 10, 19)))
        self.assertEqual(datetime.datetime.fromtimestamp(reports.period(r, ts(2026, 10, 21))[0], KYIV).weekday(), 0)

    def test_week_over_the_clock_change(self):
        r = self.rep('week')      # summer time ends on 25 October 2026: that week is 7 days and an hour long
        t0, t1 = reports.period(r, ts(2026, 10, 27))
        self.assertEqual((t0, t1), (ts(2026, 10, 19), ts(2026, 10, 26)))
        self.assertEqual(t1 - t0, 7 * 86400 + 3600)

    def test_month(self):
        r = self.rep('month')
        self.assertEqual(reports.period(r, ts(2026, 11, 1, 6)), (ts(2026, 10, 1), ts(2026, 11, 1)))
        self.assertEqual(reports.period(r, ts(2026, 3, 15)), (ts(2026, 2, 1), ts(2026, 3, 1)))
        self.assertEqual(reports.period(r, ts(2026, 1, 15), back=1), (ts(2025, 11, 1), ts(2025, 12, 1)))
        common.set_lang('en')
        self.assertEqual(reports.period_label(r, ts(2026, 10, 1), ts(2026, 11, 1)), 'October 2026')

    def test_next_send(self):
        r = self.rep('day', '06:30')
        now = ts(2026, 10, 18, 5)
        self.assertEqual(reports.next_send(r, 0, now), ts(2026, 10, 18, 6, 30))                # yesterday not sent yet
        self.assertEqual(reports.next_send(r, ts(2026, 10, 18), now), ts(2026, 10, 19, 6, 30))  # sent: tomorrow's


class Settings(unittest.TestCase):
    def test_checks(self):
        ok = {'name': 'Weekly', 'every': 'week', 'tz': 'Europe/Kyiv', 'sections': ['summary', 'nonsense']}
        r = reports.validate(dict(ok, to='a@example.com; b@example.com', f=[{'k': 'net', 'v': 'Office'}, {'k': 'evil', 'v': 'x'}]))
        self.assertEqual(r['to'], ['a@example.com', 'b@example.com'])
        self.assertEqual(r['f'], [{'k': 'net', 'v': 'Office', 'neg': False}])
        self.assertEqual(r['sections'], ['summary'])
        self.assertTrue(r['id'])
        for bad in ({'name': ''}, {'every': 'hour'}, {'at': '25:00'}, {'tz': 'Mars/Base'}, {'to': ['not mail']}, {'sections': []}):
            with self.subTest(bad), self.assertRaises(ValueError):
                reports.validate(dict(ok, **bad))


class Schedule(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.p = [mock.patch.object(reports, 'CONFIG', os.path.join(self.dir, 'r.json')),
                  mock.patch.object(reports, 'STATE', os.path.join(self.dir, 's.json')),
                  mock.patch.object(notify, 'load', lambda: dict(notify.defaults(), email=dict(notify.defaults()['email'], host='mail.example.com',
                                                                                               sender='ft@example.com', to=['noc@example.com'])))]
        for p in self.p:
            p.start()
        self.sent = []
        self.smtp = mock.patch.object(notify, 'smtp_send', lambda m, msg, timeout=20: self.sent.append((m, msg)))
        self.smtp.start()

    def tearDown(self):
        self.smtp.stop()
        for p in self.p:
            p.stop()

    def test_a_new_report_waits_for_the_next_period_then_sends_once(self):
        with mock.patch('time.time', return_value=ts(2026, 10, 18, 9)):
            r = reports.upsert({'name': 'Daily', 'every': 'day', 'at': '07:00', 'tz': 'Europe/Kyiv', 'lang': 'uk',
                                'sections': list(reports.SECTIONS)})
        quiet = lambda *a, **k: None      # noqa: E731
        self.assertEqual(reports.tick(fake_call(), now=ts(2026, 10, 18, 9), log=quiet), [])          # yesterday: created after its hour
        self.assertEqual(reports.tick(fake_call(), now=ts(2026, 10, 19, 6, 59), log=quiet), [])      # not its hour yet
        log = []
        self.assertEqual(reports.tick(fake_call(log), now=ts(2026, 10, 19, 7, 0), log=quiet), [r['id']])
        self.assertEqual(reports.tick(fake_call(), now=ts(2026, 10, 19, 7, 5), log=quiet), [])       # once
        m, msg = self.sent[0]
        self.assertEqual(m['to'], ['noc@example.com'])                 # no own recipients: those of the notifications
        pdf = [p for p in msg.iter_attachments()][0]
        self.assertEqual(pdf.get_content_type(), 'application/pdf')
        self.assertTrue(pdf.get_payload(decode=True).startswith(b'%PDF'))
        self.assertIn('2026-10-18', msg['Subject'])
        self.assertEqual({q['from'][0] for p, q in log if 'from' in q}, {str(ts(2026, 10, 18))})
        st = reports.status()[r['id']]
        self.assertEqual(st['sent_period'], '2026-10-18')
        self.assertEqual(st['next'], ts(2026, 10, 20, 7, 0))

    def test_failures_are_retried_then_given_up(self):
        with mock.patch('time.time', return_value=ts(2026, 10, 17, 9)):
            r = reports.upsert({'name': 'D', 'every': 'day', 'tz': 'Europe/Kyiv', 'sections': ['summary'], 'to': ['x@example.com']})
        self.smtp.stop()
        quiet = lambda *a, **k: None      # noqa: E731
        with mock.patch.object(notify, 'smtp_send', side_effect=notify.MailError('No answer from mail.example.com:587.')):
            t = ts(2026, 10, 18, 7)
            self.assertEqual(reports.tick(fake_call(), now=t, log=quiet), [])
            self.assertIn('No answer', reports.status()[r['id']]['error'])
            self.assertEqual(reports.tick(fake_call(), now=t + 60, log=quiet), [])            # waits 15 minutes
            self.assertEqual(reports.load_state()[r['id']]['tries'], 1)
            for i in range(1, reports.TRIES):
                reports.tick(fake_call(), now=t + i * reports.RETRY, log=quiet)
            self.assertEqual(reports.load_state()[r['id']]['done'], ts(2026, 10, 18))        # given up for that day
        self.smtp.start()
        self.assertEqual(reports.tick(fake_call(), now=ts(2026, 10, 18, 23), log=quiet), [])
        self.assertEqual(reports.tick(fake_call(), now=ts(2026, 10, 19, 7, 1), log=quiet), [r['id']])   # the next day goes

    def test_off_and_deleted(self):
        with mock.patch('time.time', return_value=ts(2026, 10, 17, 9)):
            r = reports.upsert({'name': 'D', 'every': 'day', 'tz': 'Europe/Kyiv', 'sections': ['summary']})
            reports.upsert(dict(r, on=False))
        self.assertEqual(reports.tick(fake_call(), now=ts(2026, 10, 18, 8), log=lambda *a: None), [])
        reports.remove(r['id'])
        self.assertEqual(reports.load(), [])
        with self.assertRaises(ValueError):
            reports.remove(r['id'])

    def test_send_now_is_shown_but_keeps_the_schedule(self):
        with mock.patch('time.time', return_value=ts(2026, 10, 18, 9)):
            r = reports.upsert({'name': 'D', 'every': 'day', 'tz': 'Europe/Kyiv', 'sections': ['summary']})
        done = reports.load_state()[r['id']]['done']
        reports.note_sent(r, ts(2026, 10, 17), ts(2026, 10, 18), 2, now=ts(2026, 10, 18, 10))
        s = reports.load_state()[r['id']]
        self.assertEqual((s['done'], s['sent_period'], s['to']), (done, '2026-10-17', 2))

    def test_no_mail_server(self):
        r = reports.validate({'name': 'D', 'every': 'day', 'sections': ['summary']})
        with mock.patch.object(notify, 'load', notify.defaults):
            with self.assertRaises(ValueError):
                reports.send(r, ts(2026, 10, 17), ts(2026, 10, 18), fake_call())


class Pdf(unittest.TestCase):
    def test_both_languages_and_every_part(self):
        for lang in ('en', 'uk'):
            r = reports.validate({'name': 'Звіт / Report', 'every': 'week', 'tz': 'Europe/Kyiv', 'lang': lang,
                                  'sections': list(reports.SECTIONS)})
            t0, t1 = reports.period(r, ts(2026, 10, 20))
            pdf, data = reports.make(r, t0, t1, fake_call(), '1.10.0')
            self.assertTrue(pdf.startswith(b'%PDF') and len(pdf) > 10000, lang)
            self.assertEqual(len(data['events']), 20)
            self.assertIn(b'Manrope-ExtraBold', pdf)

    def test_an_empty_period(self):
        def empty(path, q):
            if path == '/api/summary':
                return {'bytes': 0, 'up': 0, 'down': 0, 'flows': 0, 'hosts': 0, 'ips': 0, 'p_bytes': 0, 'p_flows': 0, 'p_hosts': 0,
                        'p_ips': 0, 'has_prev': False, 'oldest': 0}
            return {'series': {'step': 300, 'rows': []}, 'alerts': [], 'devices': [], 'rows': [], 'total': 0, 'step': 300}
        r = reports.validate({'name': 'Empty', 'every': 'day', 'sections': list(reports.SECTIONS)})
        pdf, _ = reports.make(r, ts(2026, 10, 17), ts(2026, 10, 18), empty)
        self.assertTrue(pdf.startswith(b'%PDF'))

    def test_numbers(self):
        self.assertEqual(reports.fmt_b(9_340_000_000), '9.34 GB')
        self.assertEqual(reports.fmt_b(512), '512 B')
        self.assertEqual(reports.delta(110, 100), '↑ 10%')
        self.assertEqual(reports.delta(90, 100), '↓ 10%')
        self.assertEqual(reports.delta(5, 0), '')
        self.assertEqual(reports.fmt_n(1196826), '1 196 826')


if __name__ == '__main__':
    unittest.main()
