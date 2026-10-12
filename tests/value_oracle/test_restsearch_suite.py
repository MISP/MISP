import json
import tempfile
import unittest

import core
from suites import restsearch

FIXTURES = {
    'ip_common': '1.2.3.4', 'ip_hub': '0.0.0.0', 'domain_common': 'a.com',
    'domain_upper': 'A.COM', 'case_variant': 'http://x/A',
    'case_variant_upper': 'HTTP://X/A', 'accent_variant': None,
    'url_common': 'http://u', 'long_shared_prefix': 'p' * 70,
    'long_text': 't' * 400, 'cross_slot_hash': 'f' * 64,
    'port_value2': '8080', 'composite_full': '1.2.3.4|8080',
    'object_only_ip': '5.6.7.8', 'deleted_only': '9.9.9.9',
    'percent_literal': 'http://x/%20', 'proposal_value': 'p.com',
    'substring_term': '%.co%', 'prefix_term': 'a.co%',
    'suffix_term': '%.com', 'ip_event': '42', 'proposal_event': '7',
    'event_sample': ['3', '4', '42'],
}


class SuiteTest(unittest.TestCase):
    def build(self, fixtures):
        with tempfile.NamedTemporaryFile('w', suffix='.json') as f:
            json.dump(fixtures, f)
            f.flush()
            config = core.Config('http://x', {}, '/tmp', fixtures=f.name)
            return restsearch.cases(config)

    def test_names_unique_and_both_users(self):
        cases = self.build(FIXTURES)
        names = [c.name for c in cases]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(len(cases) // 2,
                         len([c for c in cases if c.user == 'lesser']))

    def test_missing_fixture_is_skipped(self):
        names = {c.name for c in self.build(FIXTURES)}
        self.assertNotIn('attr.value_accent_variant.admin', names)
        self.assertIn('attr.value_case_variant.admin', names)

    def test_missing_negated_fixture_is_skipped(self):
        names = {c.name for c in self.build(
            dict(FIXTURES, ip_common=None))}
        self.assertNotIn('attr.value_not_typed.count.admin', names)
        self.assertNotIn('event.sampled_value_not.admin', names)

    def test_page_only_and_sampled_shapes(self):
        by_name = {c.name: c for c in self.build(FIXTURES)}
        self.assertIn('attr.quickfilter.page1.admin', by_name)
        self.assertNotIn('attr.quickfilter.count.admin', by_name)
        self.assertNotIn('attr.quickfilter.admin', by_name)
        self.assertEqual(
            ['3', '4', '42'],
            by_name['event.sampled_quickfilter.lesser'].body['eventid'])

    def test_broad_variant_has_count_and_page(self):
        by_name = {c.name: c for c in self.build(FIXTURES)}
        count = by_name['attr.value_suffix_broad.count.admin']
        page = by_name['attr.value_suffix_broad.page1.admin']
        self.assertEqual('count', count.body['returnFormat'])
        self.assertEqual('Attribute.id asc', page.body['order'])

    def test_value_order_has_tiebreaker(self):
        by_name = {c.name: c for c in self.build(FIXTURES)}
        body = by_name['attr.order_by_value.page2.lesser'].body
        self.assertEqual('Attribute.value asc,Attribute.id asc',
                         body['order'])
        self.assertEqual(2, body['page'])

    def test_requires_fixtures(self):
        with self.assertRaises(core.OracleError):
            restsearch.cases(core.Config('http://x', {}, '/tmp'))


if __name__ == '__main__':
    unittest.main()
