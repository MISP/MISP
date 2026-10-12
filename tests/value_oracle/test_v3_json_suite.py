import base64
import json
import tempfile
import unittest
from urllib.parse import unquote

import core
from suites import v3_json

FIXTURES = {
    'domain_common': 'google.com', 'case_variant': 'http://Example.com/a',
    'accent_variant': 'Café', 'port_value2': '443',
    'composite_full': '179.43.175.26|5301', 'long_text': 'x' * 400,
    'plan_ip_in_cidr': '185.193.38.1', 'ip_hub': '8.8.8.8',
    'correlation_event_dense': '1275', 'correlation_event_cidr': '88',
    'proposal_event': '42', 'plan_correlation_event': '7046',
}


def build(fixtures):
    with tempfile.NamedTemporaryFile('w', suffix='.json') as f:
        json.dump(fixtures, f)
        f.flush()
        config = core.Config('http://x', {}, '/tmp', fixtures=f.name)
        return v3_json.cases(config)


class CasesTest(unittest.TestCase):
    def test_every_endpoint_is_covered_for_both_users(self):
        names = {c.name for c in build(FIXTURES)}
        for user in v3_json.USERS:
            for name in ('value.plain.graph', 'value.accent.occurrences',
                         'value.value2.occurrences_count',
                         'value.long.enrichment_stored',
                         'value.never_recorded.graph',
                         'event.dense.graph_seed', 'event.cidr.graph_count_q',
                         'event.proposal.graph_labels',
                         'event.dense.cards_count_q', 'event.dense.cards_ids',
                         'event.large.timeline_q'):
                self.assertIn('v3_json.%s.%s' % (name, user), names)

    def test_missing_fixture_is_skipped(self):
        names = {c.name for c in build(dict(FIXTURES, ip_hub=None))}
        self.assertFalse(any('.value.hub.' in n for n in names))
        self.assertTrue(any('.value.plain.' in n for n in names))

    def test_an_unheld_value_lands_nothing_and_has_no_store(self):
        names = {c.name for c in build(FIXTURES)
                 if '.never_recorded.' in c.name}
        self.assertEqual({'graph', 'occurrences_count'},
                         {n.split('.')[3] for n in names})

    def test_a_large_event_lands_no_cards(self):
        names = {c.name for c in build(FIXTURES)}
        self.assertNotIn('v3_json.event.large.cards_ids.admin', names)

    def test_the_value_address_decodes_back(self):
        for case in build(FIXTURES):
            if case.name.endswith('.graph.admin') and '.value.' in case.name:
                segment = unquote(case.path.rsplit('/', 1)[1])
                decoded = base64.urlsafe_b64decode(segment).decode()
                self.assertIn(decoded, list(FIXTURES.values())
                              + [v3_json.NEVER_RECORDED])

    def test_rows_compare_unordered(self):
        self.assertTrue(all(c.unordered for c in build(FIXTURES)))


if __name__ == '__main__':
    unittest.main()
