"""Contract of app/files/scripts/stix2/stix2misp.py as MISP's PHP side calls it.

Event::convertStixToMisp() runs the wrapper as a subprocess, JSON-decodes the
last stdout line and shows its ``error`` value to whoever started the import.
That value therefore has to say what went wrong in operator terms, not name a
Python exception class.

Runs against whatever misp-stix the interpreter running the tests can import,
exactly as the real call does.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = (Path(__file__).resolve().parents[1]
          / 'app' / 'files' / 'scripts' / 'stix2' / 'stix2misp.py')
NIL_UUID = '00000000-0000-0000-0000-000000000000'


def run_import(path):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), '-i', str(path),
         '--distribution', '0', '--org-uuid', NIL_UUID],
        capture_output=True, text=True, timeout=300,
    )
    last_line = result.stdout.strip().splitlines()[-1]
    return result.returncode, json.loads(last_line)


class Stix2ImportWrapperContract(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def assert_error(self, path, expected_prefix):
        returncode, payload = run_import(path)
        self.assertEqual(returncode, 1)
        self.assertIn('error', payload)
        self.assertTrue(
            payload['error'].startswith(expected_prefix),
            f'{payload["error"]!r} does not start with {expected_prefix!r}',
        )

    def test_malformed_json_is_reported_as_unparseable(self):
        path = self.dir / 'malformed.json'
        path.write_text('{not json')
        self.assert_error(path, 'The STIX 2 document is not valid JSON: ')

    def test_document_without_stix_content_is_reported_as_unloadable(self):
        path = self.dir / 'empty.json'
        path.write_text('{}')
        self.assert_error(path, 'The STIX 2 document could not be loaded: ')

    def test_oversized_input_is_reported_as_too_large(self):
        # A sparse file: the size check reads stat(), not the content.
        path = self.dir / 'huge.json'
        with open(path, 'wb') as f:
            f.truncate(101 * 1024 * 1024)
        self.assert_error(path, 'The STIX 2 document is too large to import: ')


if __name__ == '__main__':
    unittest.main()
