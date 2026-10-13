"""Language dictionaries web/i18n/<lang>.json against the texts of the code: every text of web/app.js (T, Tn),
web/index.html (data-t, data-t-attr) and the Python modules (tr, trn, N_) has a translation in every dictionary, no
dictionary keeps texts the code no longer has, the {placeholders} of a translation are those of its English text,
and the code itself holds no other language."""
import ast
import glob
import json
import os
import re
import unittest
from html.parser import HTMLParser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STR = r"'((?:[^'\\]|\\.)*)'"
JS_T = re.compile(r"\bT\(" + STR + r"\s*[,)]")
JS_TN = re.compile(r"\bTn\((?:[^'()]|\([^()]*\))*?,\s*" + STR + r",\s*" + STR)
PLACE = re.compile(r'\{(\w+)\}')
OTHER_SCRIPT = re.compile(r'[Ѐ-ӿ]')        # Cyrillic: translations live in the dictionaries only


def read(*p):
    with open(os.path.join(ROOT, *p), encoding='utf-8') as f:
        return f.read()


def js_texts():
    code = re.sub(r'^\s*//.*$', '', read('web', 'app.js'), flags=re.M)        # examples in comments are not texts
    unq = lambda s: s.replace("\\'", "'")
    return {unq(m.group(1)) for m in JS_T.finditer(code)} | {unq(m.group(2)) for m in JS_TN.finditer(code)}


class _Html(HTMLParser):
    def __init__(self):
        super().__init__()
        self.texts, self.open = set(), None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        for name in (a.get('data-t-attr') or '').split():
            self.texts.add(a[name])
        self.open = '' if 'data-t' in a else None

    def handle_data(self, data):
        if self.open is not None:
            self.open += data

    def handle_endtag(self, tag):
        if self.open:
            self.texts.add(self.open)
        self.open = None


def html_texts():
    p = _Html()
    p.feed(read('web', 'index.html'))
    return p.texts


def py_files():
    return sorted(glob.glob(os.path.join(ROOT, '*.py')))


def py_texts():
    out = set()
    for path in py_files():
        with open(path, encoding='utf-8') as f:
            tree = ast.parse(f.read())
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ('tr', 'N_', 'trn'):
                a = n.args[2 if n.func.id == 'trn' else 0] if len(n.args) > (2 if n.func.id == 'trn' else 0) else None
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    out.add(a.value)
    return out


class Dictionaries(unittest.TestCase):
    def test_dictionaries(self):
        texts = js_texts() | html_texts() | py_texts()
        self.assertGreater(len(texts), 500)
        files = glob.glob(os.path.join(ROOT, 'web', 'i18n', '*.json'))
        self.assertTrue(files)
        for path in files:
            with open(path, encoding='utf-8') as f:
                d = json.load(f)
            name = os.path.basename(path)
            with self.subTest(name):
                self.assertTrue(d.get('@name') and d.get('@locale'), f'{name}: "@name" and "@locale" are required')
                keys = {k for k in d if not k.startswith('@')}
                self.assertEqual(sorted(texts - keys), [], f'{name}: not translated')
                self.assertEqual(sorted(keys - texts), [], f'{name}: no longer in the code')
                bad = [k for k in keys for v in (d[k].values() if isinstance(d[k], dict) else [d[k]])
                       if set(PLACE.findall(k)) != set(PLACE.findall(v))]
                self.assertEqual(bad, [], f'{name}: placeholders differ')

    def test_code_is_english(self):
        for path in py_files() + [os.path.join(ROOT, 'web', 'app.js'), os.path.join(ROOT, 'web', 'index.html')]:
            with open(path, encoding='utf-8') as f:
                bad = [f'{i}: {line.strip()[:80]}' for i, line in enumerate(f, 1) if OTHER_SCRIPT.search(line)]
            self.assertEqual(bad, [], os.path.basename(path))


if __name__ == '__main__':
    unittest.main()
