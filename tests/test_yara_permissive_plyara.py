"""permissive_plyara repairs a rule body that has no header, and only that."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

YARA = Path(__file__).resolve().parents[1] / 'app' / 'files' / 'scripts' / 'yara'
sys.path.insert(0, str(YARA))

import permissive_plyara  # noqa: E402
from plyara.exceptions import ParseError  # noqa: E402


class PermissivePlyaraNoNameTest(unittest.TestCase):

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

    def parse(self, source):
        return permissive_plyara.PermissivePlyara().parse_string(source)

    def test_headerless_body_is_named(self):
        rules = self.parse('{ condition: true }')
        self.assertEqual(rules[0]['rule_name'], 'UnnamedRule')
        self.assertEqual(rules[0]['permissive_plyara_comment'],
                         'Missing rule name')

    def test_headerless_body_after_comment_is_named(self):
        rules = self.parse('/* c */ { condition: true }')
        self.assertEqual(rules[0]['rule_name'], 'UnnamedRule')

    def test_text_before_the_body_is_not_prefixed(self):
        for source in ('private { condition: true }',
                       'import "pe"\n{ condition: true }'):
            with mock.patch.object(permissive_plyara, '_fix_noname',
                                   wraps=permissive_plyara._fix_noname) as fix:
                with self.assertRaises(ParseError):
                    self.parse(source)
            self.assertFalse(fix.called, source)


if __name__ == '__main__':
    unittest.main()
