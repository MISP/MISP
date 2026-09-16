"""Contract of app/files/scripts/stix2misp.py as MISP's PHP side calls it.

Event::convertStixToMisp() runs the wrapper as a subprocess, JSON-decodes the
last stdout line and shows its ``error`` value to whoever started the import.
That value therefore has to say what went wrong in operator terms, not name a
Python exception class. On success the converted event is the ``.out`` file
next to the input, which PHP reads and deletes.

Runs against whatever misp-stix the interpreter running the tests can import,
exactly as the real call does.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'app' / 'files' / 'scripts' / 'stix2misp.py'
SAMPLES = Path(__file__).resolve().parent
# Both samples are vendored rather than fetched: the test suite runs with no
# network. The MISP export is the submodule's `test_event1_stix11.xml` under
# the header MISP's export framing puts on the package it ships - which is
# what marks a document as a MISP export in the first place.
INTERNAL_SAMPLE = SAMPLES / 'stix1_misp_export_sample.xml'
EXTERNAL_SAMPLE = SAMPLES / 'stix1_external_sample.xml'
NIL_UUID = '00000000-0000-0000-0000-000000000000'


def run_import(path, *extra):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), '-i', str(path),
         '--org-uuid', NIL_UUID, *extra],
        capture_output=True, text=True, timeout=300,
    )
    last_line = result.stdout.strip().splitlines()[-1]
    return result.returncode, json.loads(last_line)


class Stix1ImportWrapperContract(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def assert_error(self, path, expected_prefix, *extra):
        returncode, payload = run_import(path, *extra)
        self.assertEqual(returncode, 1)
        self.assertIn('error', payload)
        self.assertTrue(
            payload['error'].startswith(expected_prefix),
            f'{payload["error"]!r} does not start with {expected_prefix!r}',
        )

    def convert(self, sample, *extra):
        """The wrapper writes next to its input, so every conversion runs on a
        copy: nothing is written into the repository."""
        path = self.dir / sample.name
        shutil.copy(sample, path)
        returncode, payload = run_import(path, *extra)
        self.assertEqual(returncode, 0, payload)
        self.assertEqual(payload.get('success'), 1)
        self.assertEqual(payload.get('stix_version'), '1.1.1')
        output = Path(f'{path}.out')
        self.assertTrue(output.is_file())
        event = json.loads(output.read_text(encoding='utf-8'))
        return event.get('Event', event)

    def test_missing_arguments_are_reported_as_an_arguments_error(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True, text=True, timeout=300,
        )
        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertTrue(
            payload['error'].startswith('Arguments error'),
            f'{payload["error"]!r} does not start with "Arguments error"',
        )

    def test_missing_file_is_reported_as_unloadable(self):
        self.assert_error(
            self.dir / 'nothing-here.xml',
            'The STIX 1 document could not be loaded: '
        )

    def test_document_that_is_not_stix_is_reported_as_unloadable(self):
        path = self.dir / 'not-stix.xml'
        path.write_text('<html><body>not a STIX package</body></html>')
        self.assert_error(path, 'The STIX 1 document could not be loaded: ')

    def test_oversized_input_is_reported_as_too_large(self):
        # A sparse file: the size check reads stat(), not the content.
        path = self.dir / 'huge.xml'
        with open(path, 'wb') as f:
            f.truncate(101 * 1024 * 1024)
        self.assert_error(path, 'The STIX 1 document is too large to import: ')

    def test_misp_export_is_converted_with_the_requested_distribution(self):
        event = self.convert(INTERNAL_SAMPLE, '--distribution', '1')
        self.assertEqual(int(event['distribution']), 1)
        # The Internal parser is the one that reads MISP's own export: the
        # External one finds nothing at the package level and returns an
        # event holding nothing at all
        self.assertTrue(event.get('Attribute') or event.get('Object'))

    def test_external_content_is_converted_as_requested(self):
        # Distribution 4 is the level PHP no longer patches into the converted
        # event: the sharing group has to come out of the wrapper itself.
        event = self.convert(
            EXTERNAL_SAMPLE, '--distribution', '4', '--sharing-group-id', '5'
        )
        self.assertEqual(int(event['distribution']), 4)
        self.assertEqual(int(event['sharing_group_id']), 5)
        self.assertTrue(event.get('Attribute'))


if __name__ == '__main__':
    unittest.main()
