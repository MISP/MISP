import json
import tempfile
import time
import unittest

import core
from suites import payloads

FIXTURES = {
    'rest_attribute_composite': '930', 'rest_attribute_object': '612',
    'rest_attribute_malware': '938', 'rest_attribute_proposed': '16595',
    'rest_attribute_deleted': '922', 'payload_attribute_tagged': '100010132',
    'rest_proposal': '1',
}


def build(fixtures):
    with tempfile.NamedTemporaryFile('w', suffix='.json') as f:
        json.dump(fixtures, f)
        f.flush()
        config = core.Config('http://x', {}, '/tmp', fixtures=f.name,
                             restore={'app_dir': '/app'})
        return payloads.cases(config)


class CasesTest(unittest.TestCase):
    def test_attachments_are_not_deleted(self):
        names = {c.name for c in build(FIXTURES)}
        self.assertIn('payload.attr.malware.edit', names)
        self.assertNotIn('payload.attr.malware.delete', names)
        self.assertIn('payload.attr.composite.delete', names)
        self.assertIn('payload.proposal.edit.add', names)

    def test_missing_fixture_is_skipped(self):
        names = {c.name for c in build(dict(FIXTURES,
                                            payload_attribute_tagged=None))}
        self.assertFalse(any('.tagged.' in n for n in names))


class CaptureTest(unittest.TestCase):
    def runner(self, result):
        calls = []

        def run(app_dir, request):
            calls.append((app_dir, request))
            return result
        return run, calls

    def test_one_run_serves_every_part(self):
        now = time.time()
        data = {'attributes': {'composite': {
            'fetch': {'Attribute': {'id': '930', 'timestamp': '1618954750'}},
            'edit': {'published': [{'args': [
                {'Attribute': {'timestamp': str(int(now))}}, 'edit']}]}}},
            'proposals': {'edit': {'add': {
                'new_id': '185', 'published': [{'args': [
                    {'ShadowAttribute': {'id': '185',
                                         'old_id': '16595'}}]}]}}}}
        run, calls = self.runner((0, '', data, now - 1, now + 1))
        capture = payloads.Capture('/app', {'attributes': {}}, run)
        self.assertEqual(
            (200, {'Attribute': {'id': '930', 'timestamp': '1618954750'}}),
            capture.part('attributes', 'composite', 'fetch'))
        status, edit = capture.part('attributes', 'composite', 'edit')
        self.assertEqual('<now>',
                         edit['published'][0]['args'][0]['Attribute']
                         ['timestamp'])
        status, add = capture.part('proposals', 'edit', 'add')
        proposal = add['published'][0]['args'][0]['ShadowAttribute']
        self.assertEqual(('<new>', '16595'),
                         (proposal['id'], proposal['old_id']))
        self.assertEqual('<new>', add['new_id'])
        self.assertEqual(1, len(calls))

    def test_failed_run_reports_the_output(self):
        run, _ = self.runner((2, 'Fatal error: x', None, 0, 0))
        capture = payloads.Capture('/app', {}, run)
        status, value = capture.part('attributes', 'composite', 'fetch')
        self.assertEqual(500, status)
        self.assertEqual(2, value['phpunit_exit'])
        self.assertIn('Fatal error', value['output_tail'])

    def test_missing_step_is_404(self):
        run, _ = self.runner((0, '', {'attributes': {}}, 0, 0))
        capture = payloads.Capture('/app', {}, run)
        self.assertEqual((404, None),
                         capture.part('attributes', 'composite', 'fetch'))


if __name__ == '__main__':
    unittest.main()
