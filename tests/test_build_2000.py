"""(2.0.0) Fixes are published as builds of the same version (VERSION stays 2.0.0 until the copyright certificate):
the build number comes from the file BUILD next to VERSION; no file (or garbage) = build 1, the release itself."""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class Build(unittest.TestCase):
    def test_build_read_from_its_file(self):
        import common
        with open(os.path.join(ROOT, 'BUILD')) as f:
            self.assertEqual(common.BUILD, int(f.read().strip()))
        self.assertIsInstance(common.BUILD, int)

    def test_no_file_or_garbage_is_build_1(self):
        import shutil
        for content in (None, '', 'x'):
            d = tempfile.mkdtemp()
            shutil.copy(os.path.join(ROOT, 'common.py'), d)
            shutil.copy(os.path.join(ROOT, 'VERSION'), d)
            if content is not None:
                open(os.path.join(d, 'BUILD'), 'w').write(content)
            src = open(os.path.join(d, 'common.py')).read()
            head = src[:src.index('UI_EXPORTERS')]          # only the version part: the rest needs the whole app
            ns = {'__file__': os.path.join(d, 'common.py')}
            exec(compile('import os\n' + head[head.index('STATE_DIR ='):], 'common_head', 'exec'), ns)
            self.assertEqual(ns['BUILD'], 1, content)


if __name__ == '__main__':
    unittest.main()
