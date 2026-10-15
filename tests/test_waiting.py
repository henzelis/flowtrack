"""1.8.5: the progress of a page's queries (system.processes by the page's query_id prefix) and Cancel.
Run: python -m unittest discover -s tests"""
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


class Progress(unittest.TestCase):
    def test_reads_the_page_queries_only(self):
        seen = []
        def ch(q, params=None, **kw):
            seen.append(params['p'])
            return [{'n': '2', 'rows': '18331810', 'total': '24783068', 'secs': 3.42}]
        with mock.patch.object(api, 'ch', ch):
            out = api.page_progress('tok', 'tab1', 'page1')
        self.assertEqual(out, {'n': 2, 'rows': 18331810, 'total': 24783068, 'secs': 3.4})
        self.assertTrue(seen[0].startswith('ftw-') and seen[0].endswith('-tab1-page1-'))
        self.assertEqual(seen[0], api.web_tag('tok', 'tab1', 'page1') + '-')      # the same prefix the queries carry

    def test_bad_tags_and_errors(self):
        with mock.patch.object(api, 'ch', side_effect=AssertionError('no query')):
            self.assertEqual(api.page_progress('tok', 'tab-1', 'p'), {'n': 0})
            self.assertEqual(api.page_progress('', 'tab1', 'p'), {'n': 0})
            self.assertEqual(api.cancel_page('tok', 'x' * 17, 'p'), {'ok': False})
        with mock.patch.object(api, 'ch', side_effect=api.CHError('down')):
            self.assertEqual(api.page_progress('tok', 'tab1', 'p'), {'n': 0})

    def test_cancel_kills_this_page(self):
        with mock.patch.object(api, '_cancel') as c:
            self.assertEqual(api.cancel_page('tok', 'tab1', 'page9'), {'ok': True})
        self.assertTrue(c.call_args[0][0].endswith('-tab1-page9-'))


if __name__ == '__main__':
    unittest.main()
