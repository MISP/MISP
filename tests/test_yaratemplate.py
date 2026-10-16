#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import unittest
from pathlib import Path

YARA_SCRIPTS_PATH = (Path(__file__).resolve().parents[1]
                    / 'app' / 'files' / 'scripts' / 'yara')
if str(YARA_SCRIPTS_PATH) not in sys.path:
    sys.path.insert(0, str(YARA_SCRIPTS_PATH))

from yaratemplate import YaraRuleTemplate
import plyara

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False


class TestYaraRuleTemplate(unittest.TestCase):

    def test_single_line_named_string(self):
        rule = YaraRuleTemplate("test_single")
        rule.strings_text("alert_msg", "malicious payload detected", nocase=True)
        rule.set_condition("$alert_msg")

        rule_str = str(rule)
        self.assertIn('$alert_msg = "malicious payload detected" nocase ascii wide', rule_str)

        parsed = plyara.Plyara().parse_string(rule_str)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]['rule_name'], "test_single")

    def test_single_line_anonymous_string(self):
        rule = YaraRuleTemplate("test_anonymous")
        rule.strings_text(None, "bad_domain.com")
        rule.set_condition("any of them")

        rule_str = str(rule)
        self.assertIn('$ = "bad_domain.com" nocase ascii wide', rule_str)

        parsed = plyara.Plyara().parse_string(rule_str)
        self.assertEqual(len(parsed), 1)

    def test_multiline_escape_newlines_false_no_duplicate_crash(self):
        # Previously, escape_newlines=False with a name crashed with
        # YaraTemplateException("There is already a string named ...")
        rule = YaraRuleTemplate("test_escape_false")
        content = "line one\nline two\nline three"
        rule.strings_text("sample", content, escape_newlines=False)
        rule.set_condition("all of them")

        rule_str = str(rule)
        self.assertIn('$sample_0 = "line one" nocase ascii wide', rule_str)
        self.assertIn('$sample_1 = "line two" nocase ascii wide', rule_str)
        self.assertIn('$sample_2 = "line three" nocase ascii wide', rule_str)

        parsed = plyara.Plyara().parse_string(rule_str)
        self.assertEqual(len(parsed), 1)

    def test_multiline_escape_newlines_false_skips_blank_lines(self):
        # Blank lines in multiline strings must not generate empty YARA strings ($ = "")
        rule = YaraRuleTemplate("test_blank_lines")
        content = "first line\n\n   \nsecond line\n"
        rule.strings_text("block", content, escape_newlines=False)
        rule.set_condition("all of them")

        rule_str = str(rule)
        self.assertIn('$block_0 = "first line"', rule_str)
        self.assertIn('$block_1 = "second line"', rule_str)
        self.assertNotIn('""', rule_str)

        parsed = plyara.Plyara().parse_string(rule_str)
        self.assertEqual(len(parsed), 1)

    def test_multiline_escape_newlines_false_anonymous(self):
        rule = YaraRuleTemplate("test_anon_multiline")
        rule.strings_text(None, "alpha\nbeta", escape_newlines=False)
        rule.set_condition("any of them")

        rule_str = str(rule)
        self.assertEqual(rule_str.count('$ = "alpha"'), 1)
        self.assertEqual(rule_str.count('$ = "beta"'), 1)

        parsed = plyara.Plyara().parse_string(rule_str)
        self.assertEqual(len(parsed), 1)

    @unittest.skipUnless(HAS_YARA, "yara-python not installed")
    def test_str2yara_regex_matches_windows_crlf(self):
        # Verifies that _str2yara_regex properly matches Windows CRLF (\r\n) linebreaks
        rule = YaraRuleTemplate("test_crlf_match")
        rule.strings_text("http_header", "GET /malware.php HTTP/1.1\nHost: evil.com", escape_newlines=True)
        rule.set_condition("$http_header")

        compiled = yara.compile(source=str(rule))

        # Target containing Windows CRLF
        sample_crlf = b"GET /malware.php HTTP/1.1\r\nHost: evil.com"
        self.assertEqual(len(compiled.match(data=sample_crlf)), 1)

    @unittest.skipUnless(HAS_YARA, "yara-python not installed")
    def test_str2yara_regex_matches_unix_lf_and_mac_cr(self):
        rule = YaraRuleTemplate("test_linebreaks")
        rule.strings_text("header", "Line1\nLine2", escape_newlines=True)
        rule.set_condition("$header")

        compiled = yara.compile(source=str(rule))

        # Unix LF (\n)
        self.assertEqual(len(compiled.match(data=b"Line1\nLine2")), 1)
        # Old Mac CR (\r)
        self.assertEqual(len(compiled.match(data=b"Line1\rLine2")), 1)

    @unittest.skipUnless(HAS_YARA, "yara-python not installed")
    def test_str2yara_regex_enforces_contiguity_and_order(self):
        # Regex mode strictly enforces contiguous sequence
        rule = YaraRuleTemplate("test_contiguity")
        rule.strings_text("seq", "FIRST\nSECOND", escape_newlines=True)
        rule.set_condition("$seq")

        compiled = yara.compile(source=str(rule))

        # Reversed order -> must NOT match
        self.assertEqual(len(compiled.match(data=b"SECOND\r\nFIRST")), 0)

        # Interleaved bytes -> must NOT match
        self.assertEqual(len(compiled.match(data=b"FIRST and other text and SECOND")), 0)


if __name__ == '__main__':
    unittest.main()
