"""1.16.2: a page's query waits for ClickHouse as long as ClickHouse is let run it (before: 30 s, then «database error»
while the query ran on), and a query whose caller is gone is cancelled. Run: python -m unittest discover -s tests"""
import io
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
import common  # noqa: E402


class Wait(unittest.TestCase):
    def run_ch(self, **kw):
        seen = {}

        def fake(req, timeout):
            seen['timeout'], seen['url'] = timeout, req.full_url
            return io.BytesIO(json.dumps({'data': []}).encode())
        with mock.patch('urllib.request.urlopen', fake):
            common.ch('SELECT 1', fmt='JSON', **kw)
        return seen

    def test_a_page_query_waits_as_long_as_clickhouse_may_run_it(self):
        with common.web_query('ftw-test', api.web_settings('/api/top', {})):
            seen = self.run_ch()
        self.assertEqual(seen['timeout'], api.WEB_SECONDS + 15)
        self.assertIn('cancel_http_readonly_queries_on_client_close=1', seen['url'])

    def test_other_queries_keep_their_own_wait(self):
        self.assertEqual(self.run_ch()['timeout'], 30)
        self.assertEqual(self.run_ch(timeout=600)['timeout'], 600)
        self.assertEqual(self.run_ch(settings={'max_execution_time': 900})['timeout'], 915)


if __name__ == '__main__':
    unittest.main()
