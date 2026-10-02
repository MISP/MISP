"""What MISP publishes for attributes and proposals: the pubsub, Kafka and
workflow payloads.

None of it is reachable over HTTP, so app/Test/AttributePayloadOracleTest.php
captures it. It boots the application against the instance's database,
swaps the transports for recorders, and runs every write in a rolled-back
transaction. For each sample attribute it records the fetchAttribute()
output, then what an edit and a hard delete publish; attachments are not
deleted, since that would remove their file. For the sample proposal, it
records what saving a copy publishes. One PHPUnit run serves the whole suite.

Timestamps inside the run's own time window and the id of the added proposal
are masked.
"""

import json
import os
import subprocess
import tempfile
import time

from core import Case
from suites.restsearch import load_fixtures

# name, fixture, whether the delete step runs (not for attachments).
ATTRIBUTES = (
    ('composite', 'rest_attribute_composite', True),
    ('object', 'rest_attribute_object', True),
    ('malware', 'rest_attribute_malware', False),
    ('proposed', 'rest_attribute_proposed', True),
    ('deleted', 'rest_attribute_deleted', True),
    ('tagged', 'payload_attribute_tagged', True),
)
PROPOSALS = (('edit', 'rest_proposal'),)
TEST_FILE = 'Test/AttributePayloadOracleTest.php'
OUTPUT_TAIL = 2000


def phpunit(app_dir, request):
    """Runs the capture test; returns (exit code, output, payloads or None,
    started, finished)."""
    with tempfile.TemporaryDirectory() as tmp:
        request = dict(request, out=os.path.join(tmp, 'payloads.json'))
        request_file = os.path.join(tmp, 'request.json')
        with open(request_file, 'w') as f:
            json.dump(request, f)
        started = time.time()
        run = subprocess.run(
            [os.path.join(app_dir, 'Vendor', 'bin', 'phpunit'),
             os.path.join(app_dir, TEST_FILE)],
            env=dict(os.environ, VALUE_ORACLE_PAYLOADS=request_file),
            capture_output=True, text=True)
        finished = time.time()
        payloads = None
        if os.path.exists(request['out']):
            with open(request['out']) as f:
                payloads = json.load(f)
        return (run.returncode, run.stdout + run.stderr, payloads, started,
                finished)


def normalise(value, started, finished, new_ids=(), key=None):
    if isinstance(value, dict):
        return {k: normalise(v, started, finished, new_ids, k)
                for k, v in value.items()}
    if isinstance(value, list):
        return [normalise(v, started, finished, new_ids, key) for v in value]
    if isinstance(value, bool) or value is None:
        return value
    text = str(value)
    if key in ('id', 'new_id') and text in new_ids:
        return '<new>'
    if text.isdigit() and len(text) == 10 and \
            started - 5 <= int(text) <= finished + 5:
        return '<now>'
    return value


class Capture:
    """Runs PHPUnit on first use and hands each case its part."""

    def __init__(self, app_dir, request, runner=phpunit):
        self.app_dir = app_dir
        self.request = request
        self.runner = runner
        self.result = None

    def part(self, group, name, step):
        if self.result is None:
            self.result = self.runner(self.app_dir, self.request)
        code, output, payloads, started, finished = self.result
        if code != 0 or payloads is None:
            return 500, {'phpunit_exit': code,
                         'output_tail': output[-OUTPUT_TAIL:]}
        entry = payloads.get(group, {}).get(name, {})
        if step not in entry:
            return 404, None
        new_ids = ()
        if isinstance(entry[step], dict) and entry[step].get('new_id'):
            new_ids = (str(entry[step]['new_id']),)
        return 200, normalise(entry[step], started, finished, new_ids)


def cases(config):
    fx = load_fixtures(config)
    attributes = {n: int(fx[k]) for n, k, _ in ATTRIBUTES if fx.get(k)}
    deletable = {n for n, _, d in ATTRIBUTES if d}
    proposals = {n: int(fx[k]) for n, k in PROPOSALS if fx.get(k)}
    capture = Capture((config.restore or {}).get('app_dir', ''),
                      {'attributes': attributes, 'proposals': proposals})

    def case(group, name, step, label):
        return Case('payload.%s.%s.%s' % (label, name, step),
                    run=lambda client: capture.part(group, name, step),
                    description='%s %s: %s' % (label, name, step))
    out = []
    for name in attributes:
        steps = ('fetch', 'edit', 'delete') if name in deletable \
            else ('fetch', 'edit')
        for step in steps:
            out.append(case('attributes', name, step, 'attr'))
    for name in proposals:
        out.append(case('proposals', name, 'add', 'proposal'))
    return out
