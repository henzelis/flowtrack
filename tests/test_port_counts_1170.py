"""(1.17.0) Top ports: the hosts and the outside addresses of each port come from their own rollups (two queries), but
in one pass over the records when no rollup serves them (a chosen host: 1.17.0 first read the records twice).
Run: python -m unittest discover -s tests"""
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


def ports(rollup):
    """/api/top?dim=ext_port with rollups that serve (rollup=True) or not -> (rows, the count queries sent)"""
    sent = []

    def ch(sql, p=None, **kw):
        sent.append(sql)
        return [dict({'k': 443}, **{n: 7 if n == 'hosts' else 9 for n in ('hosts', 'peers') if f'AS {n}' in sql})]

    source = lambda cols, *a, **k: ('(SELECT * FROM flows)', ('agg_port_host' if 'int_ip' in cols else 'agg_port_peer') if rollup else None)  # noqa: E731
    with mock.patch.object(api, 'ch_totals', lambda sql, p, **kw: ([{'k': '443', 'up': 1, 'dn': 2, 'fl': 1, 'pk': 1}], {})), \
         mock.patch.object(api, 'ch', ch), mock.patch.object(api.rollups, 'source', source):
        r = api.api_top({'dim': ['ext_port'], 'limit': ['11'], 'range': ['24h'], 'f': [json.dumps([])]})
    return r['rows'], [s for s in sent if 'uniqExact' in s]


class Counts(unittest.TestCase):
    def test_from_the_two_rollups(self):
        rows, q = ports(True)
        self.assertEqual(len(q), 2)
        self.assertEqual((rows[0]['hosts'], rows[0]['peers']), (7, 9))

    def test_one_pass_over_the_records(self):
        rows, q = ports(False)
        self.assertEqual(len(q), 1)
        self.assertIn('AS hosts', q[0]), self.assertIn('AS peers', q[0])
        self.assertEqual((rows[0]['hosts'], rows[0]['peers']), (7, 9))


if __name__ == '__main__':
    unittest.main()
