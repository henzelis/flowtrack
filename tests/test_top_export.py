"""(1.14.1) /api/top?limit=all returns every row under the filters (up to TOP_ALL, then 'truncated'); limit=0 / -1 still
mean 1; format=csv gives a table Excel opens. Run: python -m unittest discover -s tests"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

TMP = tempfile.mkdtemp()
os.makedirs(TMP + '/cfg', exist_ok=True), os.makedirs(TMP + '/state', exist_ok=True)
open(TMP + '/cfg/exporters.json', 'w').write('{}')
os.environ.update(FT_CONFIG_DIR=TMP + '/cfg', FT_STATE_DIR=TMP + '/state')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import api  # noqa: E402


def fake(n):
    def ch_totals(sql, p, **kw):
        fake.sql, fake.p = sql, p
        rows = [{'k': f'10.0.{i // 250}.{i % 250 + 1}', 'up': 10 * i, 'dn': 100 * i, 'fl': 1, 'pk': 2} for i in range(min(n, p['lim']))]
        return rows, {'up': 1, 'dn': 2}
    return ch_totals


def top(limit, n, **extra):
    q = {'dim': ['int_ip'], 'limit': [limit], 'range': ['24h'], 'f': [json.dumps([{'k': 'ip', 'v': '10.0.0.0/16'}])], **{k: [v] for k, v in extra.items()}}
    looked = []
    with mock.patch.object(api, 'ch_totals', fake(n)), mock.patch.object(api.NAMES, 'get', lambda ip, lookup=True: looked.append(lookup) or ''):
        r = api.api_top(q)
    top.looked = looked
    return r


class Limit(unittest.TestCase):
    def test_all(self):
        r = top('all', 1234)
        self.assertEqual((len(r['rows']), r['truncated']), (1234, False))
        self.assertIn('{lim:UInt32}', fake.sql)
        self.assertEqual(set(top.looked), {False})            # known names only: no 1,234 reverse DNS lookups

    def test_all_cut(self):
        with mock.patch.object(api, 'TOP_ALL', 1000):
            r = top('all', 5000)
        self.assertEqual((len(r['rows']), r['truncated']), (1000, True))

    def test_numbers_as_before(self):
        for lim, n in (('0', 1), ('-1', 1), ('20', 20), ('9999', 500)):
            r = top(lim, 9999)
            self.assertEqual(len(r['rows']), n, lim)
            self.assertNotIn('truncated', r)

    def test_conv_refuses_all(self):
        with self.assertRaises(api.BadRequest):
            api.api_top({'dim': ['conv'], 'limit': ['all'], 'range': ['24h'], 'f': ['[]']})


class Csv(unittest.TestCase):
    def test_hosts(self):
        body = api.top_csv('int_ip', {'rows': [{'k': '10.0.0.5', 'name': 'nas, office', 'up': 10, 'dn': 90, 'fl': 3, 'pk': 7}], 'truncated': False}).decode()
        self.assertTrue(body.startswith('﻿'))
        lines = body[1:].split('\r\n')
        self.assertEqual(lines[0], 'host,name,upload_bytes,download_bytes,flows,packets,total_bytes')
        self.assertEqual(lines[1], '10.0.0.5,"nas, office",10,90,3,7,100')

    def test_truncated_line(self):
        body = api.top_csv('int_ip', {'rows': [{'k': 'a', 'up': 1, 'dn': 1}], 'truncated': True}).decode()
        self.assertIn('# truncated', body)


if __name__ == '__main__':
    unittest.main()
