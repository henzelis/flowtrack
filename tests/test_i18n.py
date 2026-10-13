"""Language dictionaries web/i18n/<lang>.json against the texts of the code: every T('English') of web/app.js
has a translation in every dictionary, no dictionary keeps texts the code no longer has, and the {placeholders}
of a translation are those of its English text."""
import glob
import json
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# T('text') or T('text', {…}) — not the old two-language form T('English', 'Українська')
CALL = re.compile(r"""\bT\('((?:[^'\\]|\\.)*)'\s*(?:\)|,\s*\{)""")
PLACE = re.compile(r'\{(\w+)\}')


def code_texts():
    with open(os.path.join(ROOT, 'web', 'app.js'), encoding='utf-8') as f:
        code = re.sub(r'^\s*//.*$', '', f.read(), flags=re.M)        # examples in comments are not texts
    return {m.group(1).replace("\\'", "'") for m in CALL.finditer(code)}


class Dictionaries(unittest.TestCase):
    def test_dictionaries(self):
        texts = code_texts()
        self.assertTrue(texts)
        files = glob.glob(os.path.join(ROOT, 'web', 'i18n', '*.json'))
        self.assertTrue(files)
        for path in files:
            with open(path, encoding='utf-8') as f:
                d = json.load(f)
            name = os.path.basename(path)
            with self.subTest(name):
                self.assertEqual(sorted(texts - d.keys()), [], f'{name}: not translated')
                self.assertEqual(sorted(d.keys() - texts), [], f'{name}: no longer in the code')
                bad = [k for k, v in d.items() if set(PLACE.findall(k)) != set(PLACE.findall(v))]
                self.assertEqual(bad, [], f'{name}: placeholders differ')


if __name__ == '__main__':
    unittest.main()
