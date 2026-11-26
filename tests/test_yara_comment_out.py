"""YARA attributes that cannot be parsed are exported fully commented out."""

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

YARA = Path(__file__).resolve().parents[1] / 'app' / 'files' / 'scripts' / 'yara'
sys.path.insert(0, str(YARA))

import misp2yara  # noqa: E402


def uncommented(text):
    return re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL).strip()


class YaraCommentOutTest(unittest.TestCase):

    def setUp(self):
        # plyara writes its parser tables next to the parser module
        self._tables = YARA / 'parsetab.py'
        self._had_tables = self._tables.exists()
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()
        if not self._had_tables:
            self._tables.unlink(missing_ok=True)

    def export(self, value):
        attr = {'type': 'yara', 'uuid': '00000000-0000-4000-8000-000000000001',
                'value': value}
        return misp2yara.mispattrs2yara([attr])

    def test_valid_rule_is_unchanged(self):
        generated, valid, broken = self.export(
            'rule ok { condition: true }')
        self.assertEqual((len(valid), broken), (1, []))
        self.assertIn('rule ok', str(valid[0]))

    def test_unparseable_value_is_inside_the_comment(self):
        value = 'this is not a rule at all'
        broken = self.export(value)[2]
        self.assertEqual(len(broken), 1)
        self.assertIn(value, broken[0])
        self.assertEqual(uncommented(broken[0]), '')

    def test_comment_terminator_does_not_escape(self):
        value = 'junk */ rule evil { condition: true } /* x'
        broken = self.export(value)[2]
        self.assertEqual(len(broken), 1)
        self.assertEqual(uncommented(broken[0]), '')
        self.assertEqual(broken[0].count('*/'), 1)
        self.assertIn('rule evil', broken[0])

    def test_repeated_terminators(self):
        value = '**//*/ rule evil { condition: true }'
        broken = self.export(value)[2]
        self.assertEqual(uncommented(broken[0]), '')


if __name__ == '__main__':
    unittest.main()
