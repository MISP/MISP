import json
import tempfile
import unittest

import core
from suites import correlation_fixture as cf
from suites import correlations

LONG = 'k' * 120 + 'abcdefghij' + 'XyZ' * 30
FIXTURES = {
    'cf_exact': 'exact.example', 'cf_case': 'Svchost.exe',
    'cf_accent': 'Mise à jour', 'cf_nbsp': 'United States',
    'cross_slot_hash': 'ab' * 32, 'cf_primary_number': '2048',
    'port_value2': '7777', 'cf_excluded': '192.0.2.1',
    'cf_excluded_wildcard': '207.246.77.75', 'cf_excluded_case': '2.txt',
    'cf_over_blocked': 'google.com', 'cf_over_new': 'over.example',
    'cf_disabled_source': 'disabled.example', 'cf_disabled_target': 'Turla',
    'cf_restricted': 'restricted.example', 'cf_long_prefix': LONG,
    'cf_long_191': LONG + 'tail', 'cf_trailing': 'cmd.exe',
    'cf_trailing_alt': 'dispci.exe', 'cf_four_byte': 'http://x/a.php?b=1',
    'plan_ip_in_cidr': '185.193.38.1', 'cf_cidr_v4': '1.117.150.0/24',
    'cf_cidr_v6': '2001:620:20d0::/64',
}


def by_name(fixtures):
    return {name: (kind, value, disabled)
            for name, kind, _, value, disabled in cf.specs(fixtures)}


class Response(core.Response):
    def __init__(self, status, payload):
        super().__init__(status, {}, json.dumps(payload).encode())


class FakeClient:
    def __init__(self, routes):
        self.routes = routes
        self.requests = []

    def request(self, method, path, body=None, user='admin',
                accept='application/json'):
        self.requests.append((method, path, body, user))
        for prefix, payload in self.routes.items():
            if path.startswith(prefix):
                return Response(200, payload(body, user)
                                if callable(payload) else payload)
        return Response(200, {})


class FakeDb:
    def __init__(self, rows='', members=b'', stored=''):
        self.rows = rows
        self.members = members
        self.stored = stored
        self.sql = []
        self.commands = []

    def query(self, sql):
        self.sql.append(sql)
        return self.stored if 'correlation_exclusions' in sql else self.rows

    def redis(self, *args):
        self.commands.append(args)
        return self.members


class SpecsTest(unittest.TestCase):
    def test_variants_are_built_from_the_picks(self):
        specs = by_name(FIXTURES)
        self.assertEqual(('filename', 'SVCHOST.EXE', False),
                         specs['case_variant'])
        self.assertEqual('Mise a jour', specs['accent_variant'][1])
        self.assertEqual('United States', specs['nbsp_variant'][1])
        self.assertEqual('o5f-composite.bin|' + 'ab' * 32,
                         specs['composite_value2'][1])
        self.assertEqual('2.TXT', specs['excluded_case_variant'][1])
        self.assertEqual(('domain', 'disabled.example', True),
                         specs['disabled_source'])
        self.assertEqual(['disabled_source'],
                         [n for n, s in specs.items() if s[2]])
        self.assertTrue(specs['trailing_space'][1].startswith('cmd.exe |'))
        self.assertEqual('dispci.exe ', specs['trailing_nbsp'][1])

    def test_long_variants_split_at_128_characters(self):
        specs = by_name(FIXTURES)
        variant = specs['long_prefix_variant'][1]
        self.assertEqual(LONG[:128], variant[:128])
        self.assertNotEqual(LONG, variant)
        tail = specs['long_case_tail'][1]
        self.assertEqual(FIXTURES['cf_long_191'][:128], tail[:128])
        self.assertNotEqual(FIXTURES['cf_long_191'], tail)
        self.assertEqual(FIXTURES['cf_long_191'].lower(), tail.lower())

    def test_four_byte_variants_differ_only_in_the_character(self):
        specs = by_name(FIXTURES)
        a, b = specs['four_byte'][1], specs['four_byte_alt'][1]
        self.assertNotEqual(a, b)
        for value in (a, b):
            self.assertEqual(1, sum(ord(c) > 0xFFFF for c in value))
            self.assertEqual(FIXTURES['cf_four_byte'],
                             ''.join('?' if ord(c) > 0xFFFF else c
                                     for c in value))

    def test_types_follow_the_values(self):
        specs = by_name(dict(FIXTURES, cf_excluded='not-an-ip'))
        self.assertEqual('text', specs['excluded'][0])
        self.assertEqual('ip-dst', specs['excluded_wildcard'][0])

    def test_missing_picks_are_left_out_and_cidrs_come_last(self):
        names = [s[0] for s in cf.specs(dict(FIXTURES, cf_long_191=None))]
        self.assertNotIn('long_over_191', names)
        self.assertNotIn('long_case_tail', names)
        self.assertEqual(['cidr_member', 'cidr_over_ips', 'cidr6_over_ips'],
                         names[-3:])
        self.assertEqual(len(names), len(set(names)))


class ScratchTest(unittest.TestCase):
    def scratch(self, routes=None):
        scratch = cf.Scratch(FakeClient(routes or {}), [
            ('exact', 'domain', cf.NETWORK, 'exact.example', False),
            ('composite', 'filename|md5', cf.PAYLOAD, 'a b|' + '0' * 32,
             False),
            ('rejected', 'ip-dst', cf.NETWORK, 'nope', False)])
        scratch.event_id = '900'
        scratch.uuids = {'u1': 'exact', 'u2': 'composite'}
        return scratch

    def test_create_records_rejected_attributes(self):
        scratch = self.scratch({
            '/events/add': {'Event': {'id': '900'}},
            '/attributes/add/900': {'Attribute': [], 'errors': {
                'attribute_2': {'value': ['invalid']}}}})
        scratch.event_id = None
        scratch.create()
        self.assertEqual('900', scratch.event_id)
        self.assertEqual({'rejected': {'errors': {'value': ['invalid']}}},
                         scratch.stored)
        posted = scratch.client.requests[1][2]
        self.assertEqual([False, False, False],
                         [a['disable_correlation'] for a in posted])
        self.assertEqual({5}, {a['distribution'] for a in posted})

    def test_rows_are_relabelled(self):
        scratch = self.scratch()
        scratch.names = {'7': 'exact'}
        db = FakeDb(rows='5\t80\t7\t900\t%s\n6\t81\t7\t900\tNULL\n'
                    % 'a\r\nb'.encode().hex())
        rows = scratch.rows(db, 'no_acl_correlations')
        self.assertEqual([
            'attribute_id=5 event_id=80 1_attribute_id=exact '
            '1_event_id=<scratch> value="a\\r\\nb"',
            'attribute_id=6 event_id=81 1_attribute_id=exact '
            '1_event_id=<scratch> value=NULL'], rows)
        self.assertIn('c.event_id = 900 OR c.1_event_id = 900', db.sql[0])

    def test_views_skip_the_appended_event_level_list(self):
        event = {'Event': {
            'RelatedEvent': [{'Event': {'id': '12'}}, {'Event': {'id': '3'}}],
            'Attribute': [
                {'id': '7', 'uuid': 'u1', 'type': 'domain',
                 'value': 'exact.example', 'disable_correlation': False,
                 'RelatedAttribute': [
                     {'id': '55', 'event_id': '12', 'org_id': '1',
                      'value': 'exact.example'},
                     [{'id': '12', 'attribute_id': '55', 'org_id': '1',
                       'value': 'exact.example'}]]},
                {'id': '8', 'uuid': 'u2', 'type': 'filename|md5',
                 'value': 'a b|' + '0' * 32, 'disable_correlation': False,
                 'correlation_exclusion': True}]}}
        search = {'response': {'Attribute': [
            {'id': '7', 'RelatedAttribute': [
                {'id': '56', 'event_id': '3', 'value': 'Exact.example'},
                {'id': '55', 'event_id': '12', 'value': 'exact.example'}]},
            {'id': '8', 'RelatedAttribute': []}]}}
        scratch = self.scratch({'/events/view/900': event,
                                '/attributes/restSearch': search})
        out = scratch.views('admin')
        self.assertEqual([3, 12], out['related_events'])
        self.assertEqual(
            {'exact': ['55 event 12 org 1: "exact.example"']},
            out['related_attributes'])
        self.assertEqual(['composite'], out['exclusion_flagged'])
        self.assertEqual({'exact': ['55 event 12: "exact.example"',
                                    '56 event 3: "Exact.example"']},
                         out['search_related'])
        self.assertEqual('a b|' + '0' * 32,
                         scratch.stored['composite']['value'])
        self.assertEqual(['0' * 32, 'a b', 'exact.example'], scratch.values())
        self.assertEqual(
            '/events/view/900/includeGranularCorrelations:1',
            scratch.client.requests[0][1])

    def test_values_split_only_composite_types(self):
        scratch = self.scratch()
        scratch.stored = {'rule': {'type': 'snort', 'value': 'a|b'},
                          'pair': {'type': 'ip-dst|port', 'value': 'c|'},
                          'bad': {'errors': {}}}
        self.assertEqual(['a|b', 'c'], scratch.values())


class StateTest(unittest.TestCase):
    def setUp(self):
        cf.STATE.update(advanced=None, advanced_changed=False)
        correlations.STATE.update(original=None, current=None)

    def test_exclusions_must_match_the_table(self):
        stored = '%s\n%s\n' % (b'a'.hex(), b'b%'.hex())
        cf.check_exclusions(FakeDb(members=b'b%\na\n', stored=stored))
        with self.assertRaises(core.OracleError):
            cf.check_exclusions(FakeDb(members=b'', stored=stored))

    def test_advanced_correlations_are_enabled_once_and_restored(self):
        client = FakeClient({'/servers/getSetting/': {'value': False}})
        cf.ensure_advanced(client)
        cf.ensure_advanced(client)
        edits = [r for r in client.requests if 'serverSettingsEdit' in r[1]]
        self.assertEqual([{'value': 1}], [r[2] for r in edits])
        original = cf.Client
        cf.Client = lambda config: client
        try:
            cf.teardown(core.Config('http://x', {}, '/tmp'))
        finally:
            cf.Client = original
        edits = [r for r in client.requests if 'serverSettingsEdit' in r[1]]
        self.assertEqual([{'value': 1}, {'value': 0}], [r[2] for r in edits])
        self.assertFalse(cf.STATE['advanced_changed'])

    def test_enabled_advanced_correlations_are_left_alone(self):
        client = FakeClient({'/servers/getSetting/': {'value': True}})
        cf.ensure_advanced(client)
        self.assertFalse([r for r in client.requests
                          if 'serverSettingsEdit' in r[1]])

    def test_over_correlation_lookup_uses_the_table_collation(self):
        db = FakeDb(rows='%s\t0\n' % b'google.com'.hex())
        self.assertEqual(['"google.com" (occurrence 0)'],
                         cf.over_correlating(db, ['GOOGLE.com']))
        self.assertIn("CONVERT(X'%s' USING utf8mb4) COLLATE "
                      "utf8mb4_unicode_ci" % b'GOOGLE.com'.hex(), db.sql[0])
        self.assertEqual([], cf.over_correlating(FakeDb(), []))

    def test_one_case_per_engine(self):
        with tempfile.NamedTemporaryFile('w', suffix='.json') as f:
            json.dump(FIXTURES, f)
            f.flush()
            config = core.Config('http://x', {}, '/tmp', fixtures=f.name)
            names = [c.name for c in cf.cases(config)]
        self.assertEqual(['correlation_fixture.default',
                          'correlation_fixture.noacl',
                          'correlation_fixture.ondemand'], names)


if __name__ == '__main__':
    unittest.main()
