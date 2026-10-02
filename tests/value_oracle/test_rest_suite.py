import json
import tempfile
import time
import unittest
from datetime import date

import core
from suites import rest

FIXTURES = {
    'rest_attribute_composite': '930', 'rest_attribute_object': '612',
    'rest_attribute_malware': '938', 'rest_attribute_proposed': '16595',
    'rest_attribute_deleted': '922', 'rest_attribute_org_only': '2408983',
    'rest_object_malware': '86', 'rest_object_org_only': '7445',
    'rest_attachment_event': '7046', 'rest_proposal': '1',
    'export_small': '1275', 'export_object_acl': '5403',
    'export_proposals': '958', 'export_proposal_delete': '1703',
    'domain_common': 'a.com', 'ip_common': '1.2.3.4',
    'composite_full': '1.2.3.4|80', 'substring_term': '%.co%',
    'prefix_term': 'a.co%', 'object_only_ip': '5.6.7.8',
    'proposal_value': 'catalogue (73).zip', 'cross_slot_hash': 'f' * 64,
    'long_shared_prefix': 'http://x/' + 'p' * 70,
}


def build(fixtures):
    with tempfile.NamedTemporaryFile('w', suffix='.json') as f:
        json.dump(fixtures, f)
        f.flush()
        config = core.Config('http://x', {}, '/tmp', fixtures=f.name)
        return rest.cases(config)


class FakeClient:
    def __init__(self, replies):
        self.replies = list(replies)
        self.requests = []

    def request(self, method, path, body=None, user='admin',
                accept='application/json'):
        self.requests.append((method, path, user))
        status, payload = self.replies.pop(0) if self.replies else (200, {})
        return core.Response(status, {}, json.dumps(payload).encode())


class CasesTest(unittest.TestCase):
    def test_names_unique_and_round_trips_last(self):
        cases = build(FIXTURES)
        names = [c.name for c in cases]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(
            ['roundtrip.attributes', 'roundtrip.objects',
             'roundtrip.proposals', 'roundtrip.event_add'], names[-4:])
        self.assertFalse(any(n.startswith('roundtrip') for n in names[:-4]))

    def test_reads_run_for_both_users(self):
        names = {c.name for c in build(FIXTURES)}
        for user in rest.USERS:
            self.assertIn('attributes.view.composite.%s' % user, names)
            self.assertIn('events.attachments.attachments.%s' % user, names)
            self.assertIn('proposals.index.searchall.%s' % user, names)

    def test_index_pages_are_id_ordered(self):
        by_name = {c.name: c for c in build(FIXTURES)}
        body = by_name['attributes.index.value_ip.admin'].body
        self.assertEqual('Attribute.id', body['sort'])
        self.assertEqual(rest.INDEX_PAGE, body['limit'])
        self.assertEqual('Attribute.value',
                         by_name['attributes.index.sort_value.admin']
                         .body['sort'])

    def test_searchall_term_is_the_first_word(self):
        by_name = {c.name: c for c in build(FIXTURES)}
        self.assertEqual('/shadow_attributes/index/searchall:catalogue',
                         by_name['proposals.index.searchall.admin'].path)

    def test_missing_fixture_is_skipped(self):
        names = {c.name for c in build(dict(FIXTURES,
                                            rest_attribute_deleted=None))}
        self.assertNotIn('attributes.view.deleted.admin', names)
        self.assertIn('attributes.view.composite.admin', names)

    def test_warninglist_id_is_numeric(self):
        response = core.Response(
            200, {}, b'{"warninglist_id": "48", "id": "48"}')
        self.assertEqual('{"warninglist_id": 48, "id": "48"}',
                         rest.raw_text(response))

    def test_sorted_by_value(self):
        response = core.Response(200, {}, json.dumps([
            {'id': '9', 'value': 'a'}, {'id': '3', 'value': 'a'},
            {'id': '5', 'value': 'b'}]).encode())
        self.assertEqual({'values': ['a', 'a', 'b'], 'ids': [3, 5, 9]},
                         rest.sorted_by_value(response))


class ScratchTest(unittest.TestCase):
    def event(self, now):
        return {'Event': {
            'id': '8235', 'uuid': 'aaaaaaaa-0000-0000-0000-000000000001',
            'date': date.today().isoformat(), 'timestamp': str(now),
            'Org': {'id': '1', 'uuid': 'bbbbbbbb-0000-0000-0000-000000000001'},
            'Attribute': [], 'RelatedEvent': [{'Event': {
                'id': '36', 'uuid': 'cccccccc-0000-0000-0000-000000000001',
                'date': '2018-03-23', 'timestamp': '1521822464'}}]}}

    def test_created_entities_are_relabelled(self):
        now = int(time.time())
        attributes = {'Attribute': [
            {'id': '100106443', 'event_id': '8235', 'object_id': '0',
             'uuid': 'dddddddd-0000-0000-0000-000000000001',
             'timestamp': str(now), 'value': 'x'},
            {'id': '100106444', 'event_id': '8235', 'object_id': '0',
             'uuid': 'dddddddd-0000-0000-0000-000000000002',
             'timestamp': str(now), 'value': 'y'}]}
        client = FakeClient([
            (200, self.event(now)), (200, attributes),
            (200, {'url': '/events/delete/8235', 'id': '8235'})])
        scratch = rest.Scratch(client)
        scratch.create_event('test')
        scratch.register_created(scratch.call('add', 'POST', '/a', []))
        scratch.delete_event()
        status, steps = scratch.finish()
        self.assertEqual(200, status)
        event = steps[0]['body']['Event']
        self.assertEqual('<event:1>', event['id'])
        self.assertEqual('<uuid:1>', event['uuid'])
        self.assertEqual('<today>', event['date'])
        self.assertEqual('<now>', event['timestamp'])
        self.assertEqual('1', event['Org']['id'])
        related = event['RelatedEvent'][0]['Event']
        self.assertEqual(('36', '2018-03-23', '1521822464'),
                         (related['id'], related['date'],
                          related['timestamp']))
        first = steps[1]['body']['Attribute'][0]
        self.assertEqual(('<attribute:1>', '<event:1>', '0', '<uuid:2>'),
                         (first['id'], first['event_id'], first['object_id'],
                          first['uuid']))
        self.assertEqual('<attribute:2>',
                         steps[1]['body']['Attribute'][1]['id'])
        self.assertEqual({'url': '/events/delete/<event:1>',
                          'id': '<event:1>'}, steps[2]['body'])

    def test_warninglist_id_is_numeric_in_round_trips(self):
        now = int(time.time())
        client = FakeClient([
            (200, self.event(now)),
            (200, {'warnings': [{'warninglist_id': '48'}]}), (200, {})])
        scratch = rest.Scratch(client)
        scratch.create_event('test')
        scratch.call('view', 'GET', '/v')
        scratch.delete_event()
        self.assertEqual([{'warninglist_id': 48}],
                         scratch.finish()[1][1]['body']['warnings'])

    def test_failed_step_sets_the_status(self):
        now = int(time.time())
        client = FakeClient([(200, self.event(now)), (403, {'errors': 'no'}),
                             (200, {})])
        scratch = rest.Scratch(client)
        scratch.create_event('test')
        self.assertIsNone(scratch.call('add', 'POST', '/a', []))
        scratch.delete_event()
        self.assertEqual(403, scratch.finish()[0])

    def test_exception_is_recorded_and_event_deleted(self):
        now = int(time.time())
        client = FakeClient([(200, self.event(now)), (200, {})])

        def steps(s):
            s.create_event('test')
            raise KeyError('Attribute')
        status, recorded = rest.roundtrip(steps)(client)
        self.assertEqual("error", recorded[1]['step'])
        self.assertIn('KeyError', recorded[1]['body'])
        self.assertEqual(('POST', '/events/delete/8235', 'admin'),
                         client.requests[-1])


if __name__ == '__main__':
    unittest.main()
