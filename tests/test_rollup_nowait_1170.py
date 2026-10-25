"""(1.17.0) FT_ROLLUP_NOWAIT (test VMs only): the history is filled without waiting for the cutover + settle;
without it backfill waits as before"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import rollups  # noqa: E402


class NoWait(unittest.TestCase):
    def run_backfill(self, nowait):
        st = {f'ready_from:{n}': 1792800000 for n in rollups.ROLLUPS}
        st.update({f'cutover:{n}': 1792900800 for n in rollups.ROLLUPS})
        with mock.patch.object(rollups, 'NOWAIT', nowait), mock.patch.object(rollups, '_get_state', return_value=st), \
                mock.patch.object(rollups, '_wait', return_value=False) as wait, \
                mock.patch.object(rollups, 'ch', return_value=[{'n': '0'}]), \
                mock.patch.object(rollups, '_fill', return_value=True) as fill:
            rollups.backfill(log=lambda *_: None, late=None)
        return wait, fill

    def test_default_waits_for_the_cutover_and_settle(self):
        wait, fill = self.run_backfill(False)
        wait.assert_called_once_with(1792900800 + 600, None)
        fill.assert_not_called()

    def test_nowait_fills_at_once(self):
        wait, fill = self.run_backfill(True)
        wait.assert_not_called()
        fill.assert_called_once()

    def test_off_unless_set(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('FT_ROLLUP_NOWAIT', None)
            self.assertNotEqual(os.environ.get('FT_ROLLUP_NOWAIT'), '1')
            self.assertFalse(rollups.NOWAIT)


if __name__ == '__main__':
    unittest.main()
