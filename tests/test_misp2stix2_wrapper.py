"""Contract of app/files/scripts/stix2/misp2stix2.py as MISP's PHP calls it.

StixExport splits the MISP JSON of a large export into several files and
Stix2Export::__parse_misp_data() runs the wrapper once over all of them.
StixExport::footer() then strips the brackets of every ``<file>.out``, skips
the empty ones and joins the rest inside the bundle framing, so a split export
has to hold the same objects as the same content exported in one file.

Runs against whatever misp-stix the interpreter running the tests can import,
exactly as the real call does.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / 'app' / 'files' / 'scripts'
WRAPPER = SCRIPTS / 'stix2' / 'misp2stix2.py'
FRAMING = SCRIPTS / 'misp_framing.py'
FIXTURES = SCRIPTS / 'misp-stix' / 'tests'
BUNDLE_UUID = '5b2ea4b4-8d8a-4a1d-8b4e-0c1b0d5a6f05'


def load_fixtures(scope):
    return [
        json.loads((FIXTURES / f'test_{scope}_collection_{n}.json').read_text())
        for n in (1, 2)
    ]


def merge_list_responses(first, second):
    return {'response': first['response'] + second['response']}


def merge_attribute_responses(first, second):
    return {
        'response': {
            'Attribute': (first['response']['Attribute']
                          + second['response']['Attribute'])
        }
    }


class SplitExportContract:
    version = None

    @classmethod
    def setUpClass(cls):
        result = subprocess.run(
            [sys.executable, str(FRAMING), 'stix2',
             '-v', cls.version, '--uuid', BUNDLE_UUID],
            capture_output=True, text=True, timeout=120,
        )
        cls.framing = json.loads(result.stdout)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def stage(self, name, content):
        path = self.dir / name
        path.write_text(json.dumps(content))
        return path

    def export(self, *inputs):
        result = subprocess.run(
            [sys.executable, str(WRAPPER), '-v', self.version,
             '-i', *map(str, inputs)],
            capture_output=True, text=True, timeout=300,
        )
        last_line = result.stdout.strip().splitlines()[-1]
        self.assertEqual(json.loads(last_line), {'success': 1}, result.stderr)
        chunks = (
            Path(f'{path}.out').read_text()[1:-1] for path in inputs
        )
        return json.loads(
            self.framing['header']
            + self.framing['separator'].join(filter(None, chunks))
            + self.framing['footer']
        )

    def assert_split_matches_single_file(self, scope, merge):
        first, second = load_fixtures(scope)
        split = self.export(
            self.stage('misp_0.json', first), self.stage('misp_1.json', second)
        )
        single = self.export(
            self.stage('misp_all.json', merge(first, second))
        )
        split_ids = [stix_object['id'] for stix_object in split['objects']]
        duplicates = sorted(
            stix_id for stix_id, count in Counter(split_ids).items()
            if count > 1
        )
        self.assertEqual(duplicates, [])
        self.assertEqual(
            set(split_ids),
            {stix_object['id'] for stix_object in single['objects']}
        )

    def test_split_events_export_matches_single_file(self):
        self.assert_split_matches_single_file('events', merge_list_responses)

    def test_split_attributes_export_matches_single_file(self):
        self.assert_split_matches_single_file(
            'attributes', merge_attribute_responses
        )

    def test_split_objects_export_matches_single_file(self):
        self.assert_split_matches_single_file('objects', merge_list_responses)


class Stix20SplitExportContract(SplitExportContract, unittest.TestCase):
    version = '2.0'


class Stix21SplitExportContract(SplitExportContract, unittest.TestCase):
    version = '2.1'


if __name__ == '__main__':
    unittest.main()
