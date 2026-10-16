"""1.8.7: a port name added and taken back within the collector's half minute left an empty rename pending, and
relabel_rollups made `proto IN ()` of it — a ClickHouse error every minute. Run: python -m unittest discover -s tests"""
import os
import sys
import tempfile
import unittest
from unittest import mock

TMP = tempfile.mkdtemp()
os.makedirs(TMP + '/cfg', exist_ok=True), os.makedirs(TMP + '/state', exist_ok=True)
os.environ.update(FT_CONFIG_DIR=TMP + '/cfg', FT_STATE_DIR=TMP + '/state')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import rollups  # noqa: E402


class EmptyPending(unittest.TestCase):
    def test_nothing_to_sum_again_asks_nothing(self):
        with mock.patch.object(rollups, 'ch', side_effect=AssertionError('no query expected')):
            self.assertEqual(rollups.relabel_rollups([], [], 1792065600), 0)
            self.assertEqual(rollups.relabel_rollups([6], [], 1792065600), 0)


if __name__ == '__main__':
    unittest.main()
