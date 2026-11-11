"""Contract of app/files/scripts/misp_framing.py as MISP's PHP side calls it.

StixExport::getFraming() runs the script as a subprocess and JSON-decodes
its stdout, so the only acceptable outputs are a framing document or an
``{"error": ...}`` object. A traceback on stderr with an empty stdout is
what turns a precise upstream message into the opaque
"Could not get results from framing cmd when exporting STIX file."

Runs against whatever misp-stix the interpreter running the tests can
import, exactly as the real call does.
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPT = (Path(__file__).resolve().parents[1]
          / 'app' / 'files' / 'scripts' / 'misp_framing.py')


def run_framing(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, timeout=120,
    )


class Stix1FramingContract(unittest.TestCase):

    def test_invalid_namespace_is_reported_as_json_error(self):
        # An empty namespace has never produced a STIX 1 package: misp-stix
        # 2026.9.8 rejects it up front, earlier releases die inside mixbox.
        result = run_framing(
            'stix1', '-s', 'Event', '-v', '1.1.1',
            '-n', '', '-o', 'MISP', '-f', 'xml',
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertIn('error', payload)
        self.assertTrue(payload['error'].strip(),
                        'error message must not be empty')

    def test_valid_namespace_returns_framing(self):
        result = run_framing(
            'stix1', '-s', 'Event', '-v', '1.1.1',
            '-n', 'https://misp.local', '-o', 'MISP', '-f', 'xml',
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(sorted(payload), ['footer', 'header', 'separator'])
        self.assertIn('xmlns:MISP="https://misp.local"', payload['header'])


if __name__ == '__main__':
    unittest.main()
