"""(1.18.0) Conversations: «new» looks back only as far as the data reach (a fresh installation has nothing new to
show), a pair is new by its inside host x owner, the period before is compared only when the data cover it, inside
traffic is shown by address, the rest of each column of the graph is '__other'. The SQL itself is checked against
the records on stage (flowtrack-verify conv_exact.py)."""
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

TMP = tempfile.mkdtemp()
os.makedirs(TMP + '/cfg', exist_ok=True), os.makedirs(TMP + '/state', exist_ok=True)
open(TMP + '/cfg/exporters.json', 'w').write('{}')
os.environ.update(FT_CONFIG_DIR=TMP + '/cfg', FT_STATE_DIR=TMP + '/state')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import api  # noqa: E402

NOW = 1792944000          # a whole hour


class Conversations(unittest.TestCase):
    def run_api(self, oldest, **q):
        asked = []

        def ch(sql, params=None, **kw):
            asked.append(sql)
            if 'min(ts)' in sql and 'FROM flows' in sql and 'GROUP BY' not in sql:
                return [{'t': oldest}]
            if 'countIf(f > 0) AS pairs' in sql:
                return [{'pairs': 3, 'new_owners': 1, 'new_pairs': 2, 'new_bytes': 70, 'bytes': 100, 'prev_pairs': 2}]
            if 'LIMIT {lim:UInt32} BY old' in sql:
                return [{'h': '1', 'b': 30, 'pb': 10, 'old': 1}, {'h': '2', 'b': 50, 'pb': 0, 'old': 0}, {'h': '3', 'b': 20, 'pb': 0, 'old': 0}]
            if 'argMax(service, bytes)' in sql:
                return [{'h': h, 'int_ip': '10.0.0.' + h, 'ext_ip': '81.20.30.' + h, 'up': up, 'dn': dn, 'fl': 1, 'service': 'HTTPS',
                         'country': 'DE', 'asn': 24940, 'as_org': 'Hetzner Online GmbH', 'first': NOW - 3600, 'last': NOW}
                        for h, up, dn in (('1', 10, 20), ('2', 5, 45), ('3', 10, 10))]
            if 'AS lab' in sql:
                return [{'k': '24940', 'lab': 'Hetzner Online GmbH', 'b': 100}]
            if 'AS l,' in sql:
                return [{'l': '10.0.0.1', 's': 'HTTPS', 'r': '24940', 'up': 10, 'dn': 20}, {'l': '__other', 's': 'HTTPS', 'r': '__other', 'up': 1, 'dn': 1}]
            if 'GROUP BY t, h' in sql:
                return []
            if 'country AS k' in sql:
                return [{'k': 'DE', 'b': 100}]
            return [{'k': '10.0.0.1', 'b': 100}]
        qs = {'range': ['24h'], 'f': [json.dumps([])]}
        qs.update({k: [v] for k, v in q.items()})
        with mock.patch.object(api, 'ch', ch), mock.patch('time.time', lambda: NOW + 600), mock.patch.object(api, 'view_days', lambda: 30), \
                mock.patch.object(api.NAMES, 'get', lambda ip, lookup=True: ''), mock.patch.object(api.rollups, 'ready_from', lambda name: None):
            return api.api_conversations(qs), asked

    def test_fresh_installation_shows_nothing_new(self):
        d, asked = self.run_api(NOW - 1800)          # data only since half an hour before the period
        self.assertIsNone(d['total']['new_owners'])
        self.assertIsNone(d['total']['prev_pairs'])
        self.assertEqual(d['new'], [])
        self.assertFalse(any(p['new'] for p in d['pairs']))
        self.assertFalse(any(' IN (SELECT cityHash64(int_ip, if(asn' in s for s in asked), 'no look back without history')

    def test_new_is_host_by_owner(self):
        d, asked = self.run_api(NOW - 20 * 86400)
        sql = next(s for s in asked if 'countIf(f > 0) AS pairs' in s)
        self.assertIn('cityHash64(int_ip, if(asn != 0, toString(asn), ext_ip))', sql)
        self.assertEqual(d['new_days'], 7.0)
        self.assertEqual(d['total']['new_owners'], 1)
        self.assertEqual([p['ext_ip'] for p in d['new']], ['81.20.30.2', '81.20.30.3'])       # the biggest first
        self.assertEqual([p['ext_ip'] for p in d['pairs']], ['81.20.30.2', '81.20.30.1', '81.20.30.3'])
        self.assertEqual(d['pairs'][1]['prev'], 10)
        self.assertEqual(d['pairs'][0]['owner'], 'Hetzner Online')

    def test_short_history_looks_back_as_far_as_it_goes(self):
        d, _ = self.run_api(NOW - 3 * 86400)
        self.assertEqual(d['new_days'], 2.0)                 # the period is the last day: 2 days before it
        self.assertIsNotNone(d['total']['new_owners'])

    def test_graph_rest_and_owner_names(self):
        d, _ = self.run_api(NOW - 20 * 86400)
        self.assertEqual(d['graph']['peers'], [{'k': '24940', 'label': 'Hetzner Online', 'b': 100}])
        self.assertIn(['__other', 'HTTPS', '__other', 1, 1], d['graph']['links'])

    def test_inside_traffic_by_address(self):
        d, asked = self.run_api(NOW - 20 * 86400, t='internal', right='country')
        self.assertEqual(d['right'], 'addr')
        self.assertTrue(d['internal'])
        self.assertEqual(d['total']['countries'], 0)

    def test_bad_right(self):
        with self.assertRaises(api.BadRequest):
            self.run_api(NOW, right='planet')


if __name__ == '__main__':
    unittest.main()
