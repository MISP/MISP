import json
import tempfile
import unittest

import core
from suites import correlations

FIXTURES = {
    'correlation_event_dense': '11', 'correlation_event_cidr': '12',
    'correlation_event_restricted': '13', 'ip_event': '14',
    'export_composite': '15',
}


def build(fixtures):
    with tempfile.NamedTemporaryFile('w', suffix='.json') as f:
        json.dump(fixtures, f)
        f.flush()
        config = core.Config('http://x', {}, '/tmp', fixtures=f.name,
                             restore={'app_dir': '/app'})
        return correlations.cases(config)


class FakeClient:
    def __init__(self, engine):
        self.engine = engine
        self.requests = []

    def request(self, method, path, body=None, user='admin',
                accept='application/json'):
        self.requests.append((method, path))
        if path.startswith('/servers/getSetting/'):
            payload = {'value': self.engine}
        else:
            self.engine = path.rsplit('/', 1)[1]
            payload = {'saved': True}
        return core.Response(200, {}, json.dumps(payload).encode())


class FakeDb:
    def __init__(self, text):
        self.text = text

    def query(self, sql):
        self.sql = sql
        return self.text


class CasesTest(unittest.TestCase):
    def setUp(self):
        correlations.STATE.update(original=None, current=None)

    def test_each_engine_recorrelates_before_its_views(self):
        names = [c.name for c in build(FIXTURES)]
        self.assertEqual('correlation.default.recorrelated', names[0])
        noacl = names.index('correlation.noacl.recorrelated')
        self.assertTrue(all(n.startswith('correlation.default.')
                            for n in names[:noacl]))
        self.assertFalse(any(n.startswith('correlation.ondemand.recorr')
                             for n in names))
        self.assertIn('correlation.ondemand.view.cidr.lesser', names)
        self.assertEqual(len(names), len(set(names)))

    def test_missing_view_event_is_skipped(self):
        names = {c.name for c in build(dict(FIXTURES,
                                            correlation_event_cidr=None))}
        self.assertFalse(any('.cidr.' in n for n in names))

    def test_pairs_are_unordered_and_sorted(self):
        db = FakeDb('3\t9\n1\t2\n')
        self.assertEqual([[3, 9], [1, 2]],
                         correlations.pairs(db, 'default_correlations'))
        self.assertIn('LEAST(attribute_id, 1_attribute_id)', db.sql)
        self.assertIn('ORDER BY 1, 2', db.sql)

    def test_switch_remembers_the_original_engine(self):
        client = FakeClient('Default')
        correlations.switch_engine(client, 'NoAcl')
        correlations.switch_engine(client, 'NoAcl')
        self.assertEqual('Default', correlations.STATE['original'])
        self.assertEqual(
            [('GET', '/servers/getSetting/MISP.correlation_engine'),
             ('POST', '/correlations/switchEngine/NoAcl')], client.requests)

    def test_teardown_restores_the_original_engine(self):
        client = FakeClient('Default')
        correlations.switch_engine(client, 'OnDemand')
        restored = []
        original = correlations.switch_engine
        correlations.switch_engine = \
            lambda c, engine: restored.append(engine)
        try:
            correlations.teardown(core.Config('http://x', {}, '/tmp'))
        finally:
            correlations.switch_engine = original
        self.assertEqual(['Default'], restored)


if __name__ == '__main__':
    unittest.main()
