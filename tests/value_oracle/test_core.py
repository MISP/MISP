import json
import os
import shutil
import tempfile
import unittest

import core


class FakeClient:
    def __init__(self, responses):
        self.responses = responses

    def request(self, method, path, body=None, user='admin',
                accept='application/json'):
        status, payload = self.responses[(path, user)]
        if not isinstance(payload, (bytes, str)):
            payload = json.dumps(payload)
        if isinstance(payload, str):
            payload = payload.encode()
        return core.Response(status, {}, payload)


class PickTest(unittest.TestCase):
    def test_paths(self):
        obj = {'response': {'Attribute': [{'id': '3'}, {'id': '1'}]}}
        self.assertEqual(['3', '1'], core.pick(obj, 'response.Attribute[].id'))
        self.assertEqual([], core.pick(obj, 'response.Missing[].id'))
        self.assertEqual([obj['response']], core.pick(obj, 'response'))

    def test_nested_lists(self):
        obj = {'Event': [{'Object': [{'Attribute': [{'id': 1}, {'id': 2}]}]},
                         {'Object': [{'Attribute': [{'id': 3}]}]}]}
        self.assertEqual(
            [1, 2, 3], core.pick(obj, 'Event[].Object[].Attribute[].id'))

    def test_ids_keep_duplicates_sorted(self):
        response = core.Response(200, {}, json.dumps(
            {'response': {'Attribute': [{'id': '5'}, {'id': '2'},
                                        {'id': '5'}]}}).encode())
        self.assertEqual(
            [2, 5, 5], core.ids_at('response.Attribute[].id')(response))


class NormaliseTest(unittest.TestCase):
    def test_drop_and_mask(self):
        obj = {'a': 1, 'uuid': 'x', 'n': [{'uuid': 'y', 'timestamp': 9}]}
        self.assertEqual({'a': 1, 'n': [{'timestamp': 9}]},
                         core.drop_keys(obj, ['uuid']))
        self.assertEqual(
            {'a': 1, 'uuid': 'x', 'n': [{'uuid': 'y', 'timestamp': '<m>'}]},
            core.mask_keys(obj, ['timestamp'], '<m>'))

    def test_substitute(self):
        text = 'Generated 2026-10-01 12:00:00\nrow'
        self.assertEqual('Generated <date>\nrow', core.substitute(
            text, [(r'\d{4}-\d\d-\d\d \d\d:\d\d:\d\d', '<date>')]))


class DiffTest(unittest.TestCase):
    def test_equal(self):
        self.assertEqual([], core.diff({'a': [1, 2]}, {'a': [1, 2]}))

    def test_scalar_lists(self):
        lines = core.diff([1, 2, 3], [2, 3, 4])
        self.assertIn('$: 3 items -> 3 (removed 1, added 1)', lines)
        self.assertIn('    removed: 1', lines)
        self.assertIn('    added: 4', lines)

    def test_order_only(self):
        self.assertEqual(['$: same items, different order'],
                         core.diff([1, 2], [2, 1]))

    def test_nested_and_keys(self):
        lines = core.diff({'x': {'y': 1, 'gone': 2}},
                          {'x': {'y': 3, 'new': 4}})
        self.assertIn('$.x.y: 1 -> 3', lines)
        self.assertIn('$.x.gone: removed (was 2)', lines)
        self.assertIn('$.x.new: added (4)', lines)

    def test_type_change(self):
        self.assertTrue(core.diff({'v': '1'}, {'v': 1})[0].startswith(
            '$.v: type str -> int'))

    def test_int_float_same_value_is_equal(self):
        self.assertEqual([], core.diff({'v': 1}, {'v': 1.0}))

    def test_text(self):
        lines = core.diff('a\nb\nc', 'a\nB\nc')
        self.assertTrue(lines[0].startswith('$: text differs'))
        self.assertIn('    -b', lines)
        self.assertIn('    +B', lines)

    def test_limit(self):
        a = {str(i): i for i in range(100)}
        b = {str(i): i + 1 for i in range(100)}
        self.assertEqual(core.DIFF_LIMIT, len(core.diff(a, b)))


class CaseTest(unittest.TestCase):
    def test_invalid_name(self):
        with self.assertRaises(core.OracleError):
            core.Case('bad/name', '/x', core.status_only)

    def test_needs_request_or_runner(self):
        with self.assertRaises(core.OracleError):
            core.Case('nothing')

    def test_extract_error_is_captured(self):
        client = FakeClient({('/x', 'admin'): (500, '<html>boom</html>')})
        result = core.Case('c', '/x', core.json_without()).execute(client)
        self.assertEqual(500, result['status'])
        self.assertIn('extract_error', result['value'])
        self.assertIn('boom', result['value']['body_head'])

    def test_custom_runner(self):
        case = core.Case('c', run=lambda client: (201, {'made': True}))
        result = case.execute(None)
        self.assertEqual((201, {'made': True}),
                         (result['status'], result['value']))


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_round_trip_with_blob(self):
        store = core.Store(self.root, 'baseline')
        big = 'x' * (core.INLINE_LIMIT + 1)
        result = {'case': 'c', 'status': 200,
                  'value': {'small': 'ok', 'big': big}, 'meta': {}}
        store.save('suite', result)
        stored = json.load(open(os.path.join(
            self.root, 'baseline', 'suite', 'c.json')))
        self.assertEqual('c.0.txt.gz', stored['value']['big']['$blob'])
        self.assertEqual(result['value'], store.load('suite', 'c')['value'])
        self.assertEqual(['c'], store.case_names('suite'))
        self.assertIsNone(store.load('suite', 'missing'))

    def test_invalid_label(self):
        with self.assertRaises(core.OracleError):
            core.Store(self.root, '../escape')

    def test_record_then_compare(self):
        client = FakeClient({('/r', 'admin'): (
            200, {'response': {'Attribute': [{'id': 2}, {'id': 1}]}})})
        case = core.Case('ids', '/r', core.ids_at('response.Attribute[].id'))
        store = core.Store(self.root, 'baseline')
        store.save('suite', case.execute(client))
        base = store.load('suite', 'ids')
        self.assertEqual([], core.compare_results(base, case.execute(client)))

        client.responses[('/r', 'admin')] = (
            403, {'response': {'Attribute': [{'id': 1}]}})
        lines = core.compare_results(base, case.execute(client))
        self.assertIn('$status: 200 -> 403', lines)
        self.assertIn('$: 2 items -> 1 (removed 1, added 0)', lines)


if __name__ == '__main__':
    unittest.main()
