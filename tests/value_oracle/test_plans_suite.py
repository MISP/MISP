import json
import tempfile
import unittest

import core
from suites import plans

FIXTURES = {
    'export_largest': '5386', 'export_small': '1275',
    'domain_common': 'google.com', 'substring_term': '%oogle%',
    'prefix_term': 'goog%', 'composite_full': '179.43.175.26|5301',
    'plan_correlation_event': '7046', 'plan_ip_in_cidr': '185.193.38.1',
}


def build(fixtures):
    with tempfile.NamedTemporaryFile('w', suffix='.json') as f:
        json.dump(fixtures, f)
        f.flush()
        config = core.Config('http://x', {}, '/tmp', fixtures=f.name,
                             restore={'app_dir': '/app'})
        return plans.cases(config)


class FakeClient:
    def __init__(self, ids):
        self.ids = ids
        self.calls = 0

    def request(self, method, path, body=None, user='admin',
                accept='application/json'):
        self.calls += 1
        if user not in self.ids:
            return core.Response(403, {}, b'{}')
        return core.Response(200, {}, json.dumps(
            {'User': {'id': str(self.ids[user])}}).encode())


class CasesTest(unittest.TestCase):
    def test_every_shape_is_covered(self):
        names = {c.name for c in build(FIXTURES)}
        for name in ('plans.a1.fetch_event', 'plans.b.exact.lesser',
                     'plans.b.event_scope.admin', 'plans.c.substring.admin',
                     'plans.d.prefix.lesser', 'plans.e.recorrelate',
                     'plans.e.related.ondemand.lesser',
                     'plans.e.related_small.ondemand.admin',
                     'plans.f.type_export',
                     'plans.g.index_sort', 'plans.h.cidr_wide_save',
                     'plans.h.ip_in_cidr_save', 'plans.j.paginated_search'):
            self.assertIn(name, names)

    def test_missing_fixture_is_skipped(self):
        names = {c.name for c in build(dict(FIXTURES,
                                            plan_correlation_event=None))}
        self.assertEqual({'plans.e.related_small.ondemand.admin'},
                         {n for n in names if n.startswith('plans.e.')})
        self.assertIn('plans.g.index_sort', names)

    def test_saves_go_to_the_small_event(self):
        ops = dict(plans.operations(FIXTURES))
        attribute = ops['h.ip_in_cidr_save']['args']['attribute']
        self.assertEqual((1275, '185.193.38.1'),
                         (attribute['event_id'], attribute['value']))
        self.assertEqual('OnDemand',
                         ops['e.related.ondemand.admin']['engine'])


class RunOperationTest(unittest.TestCase):
    def runner(self, result, code=0):
        calls = []

        def run(app_dir, request):
            calls.append(request)
            return code, 'phpunit output', result, 0, 0
        return run, calls

    def test_value_and_timings_are_separated(self):
        entry = {'value': {'statements': [], 'large_reads': []},
                 'timings': {'value_sql_ms': 12}, 'indexes': [['a PRIMARY']],
                 'error': None}
        run, calls = self.runner({'g.index_sort': entry})
        users = plans.Users()
        client = FakeClient({'admin': 1})
        outcome = plans.run_operation(
            '/app', 'g.index_sort', {'op': 'attributeIndex',
                                     'user': 'admin', 'args': {}},
            users, client, run)
        self.assertEqual((200, entry['value'],
                          {'timings': {'value_sql_ms': 12},
                           'indexes': [['a PRIMARY']]}), outcome)
        self.assertEqual(1, calls[0]['operations']['g.index_sort']['user'])
        plans.run_operation('/app', 'g.index_sort',
                            {'op': 'x', 'user': 'admin'}, users, client, run)
        self.assertEqual(1, client.calls)

    def test_operation_error_is_part_of_the_value(self):
        entry = {'value': {'statements': []}, 'timings': {},
                 'error': 'RuntimeException: Save failed'}
        run, _ = self.runner({'h': entry})
        status, value, _ = plans.run_operation(
            '/app', 'h', {'op': 'saveAttribute', 'user': 'admin'},
            plans.Users(), FakeClient({'admin': 1}), run)
        self.assertEqual(500, status)
        self.assertEqual('RuntimeException: Save failed', value['error'])

    def test_failed_run_reports_the_output(self):
        run, _ = self.runner(None, code=2)
        status, value = plans.run_operation(
            '/app', 'h', {'op': 'x', 'user': 'admin'}, plans.Users(),
            FakeClient({'admin': 1}), run)
        self.assertEqual((500, 2), (status, value['phpunit_exit']))

    def test_unknown_user_is_an_error(self):
        with self.assertRaises(core.OracleError):
            plans.Users().id(FakeClient({}), 'lesser')


if __name__ == '__main__':
    unittest.main()
