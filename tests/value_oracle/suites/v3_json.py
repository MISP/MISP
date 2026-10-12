"""misp-3-ea's JSON answers that read attribute values: the Pivot Explorer's
graph of an event, the event page's element cards and Timeline tab, and the
value page's graph, occurrences and stored enrichment runs.

Values and events come from the fixtures file (see discover_fixtures.py); a
case whose fixture was not found is skipped. NEVER_RECORDED is a value no
attribute holds, so the unheld path is covered as well. Each case runs as a
site admin and as a lesser org user. Answers compare in their row order.
"""

import base64
from urllib.parse import quote, urlencode

from core import Case, json_without
from suites.restsearch import load_fixtures

USERS = ('admin', 'lesser')
NEVER_RECORDED = 'never-recorded.value-table.invalid'
# Found in most values, so the search boxes' LIKE paths have rows to match
SEARCH_TERM = 'com'

# name, fixture key, the type an enrichment run of it is stored under
VALUES = (
    ('plain', 'domain_common', 'domain'),
    ('case', 'case_variant', 'url'),
    ('accent', 'accent_variant', 'text'),
    ('value2', 'port_value2', 'port'),
    ('composite', 'composite_full', 'ip-dst|port'),
    ('long', 'long_text', 'text'),
    ('in_cidr', 'plan_ip_in_cidr', 'ip-dst'),
    ('hub', 'ip_hub', 'ip-dst'),
)

# name, fixture key, whether the event is small enough to land its cards
EVENTS = (
    ('dense', 'correlation_event_dense', True),
    ('cidr', 'correlation_event_cidr', True),
    ('proposal', 'proposal_event', True),
    ('large', 'plan_correlation_event', False),
)


def b64(value):
    """The value page's address: URL-safe base64 with padding."""
    return base64.urlsafe_b64encode(value.encode()).decode()


def json_case(name, path, user, method='GET', body=None, description=''):
    return Case(name, path, json_without(), method=method, body=body,
                user=user, description=description)


def value_cases(name, value, enrichment_type):
    out = []
    page = '/values/graph/' + quote(b64(value), safe='=')
    for user in USERS:
        prefix = 'v3_json.value.%s.' % name
        out.append(json_case(prefix + 'graph.' + user, page, user,
                             description="the value graph's opening records"))
        out.append(json_case(
            prefix + 'occurrences_count.' + user, '/values/graphOccurrences',
            user, 'POST', {'values': [value], 'count': 1},
            'how many occurrences the graph could land'))
        if enrichment_type is None:
            continue
        out.append(json_case(
            prefix + 'occurrences.' + user, '/values/graphOccurrences',
            user, 'POST', {'values': [value]},
            'the occurrences the graph lands'))
        out.append(json_case(
            prefix + 'enrichment_stored.' + user, '/values/enrichmentStored',
            user, 'POST', {'items': [{'value': value,
                                      'type': enrichment_type}]},
            "the organisation's stored enrichment runs"))
    return out


def event_cases(name, event_id, small):
    out = []
    graph = '/events/graph/%s' % event_id
    cards = '/events/cardElements/%s' % event_id
    timeline = '/events/viewEventTimeline/%s.json' % event_id
    for user in USERS:
        prefix = 'v3_json.event.%s.' % name
        out += [
            json_case(prefix + 'graph_seed.' + user, graph, user,
                      description="the explorer's opening elements"),
            json_case(prefix + 'graph_count.' + user, graph, user, 'POST',
                      {'count': 1}, 'elements the explorer could land'),
            json_case(prefix + 'graph_count_q.' + user, graph, user, 'POST',
                      {'count': 1, 'q': SEARCH_TERM},
                      'elements matching a search term'),
            json_case(prefix + 'graph_labels.' + user, graph, user, 'POST',
                      {'mode': 'labels'}, 'the labels the explorer offers'),
            json_case(prefix + 'cards_count.' + user, cards, user, 'POST',
                      {'count': 1}, 'element cards by type and category'),
            json_case(prefix + 'cards_count_q.' + user, cards, user, 'POST',
                      {'count': 1, 'q': SEARCH_TERM},
                      'element cards matching a search term'),
            json_case(prefix + 'timeline.' + user, timeline, user,
                      description="the Timeline tab's whole span"),
            json_case(prefix + 'timeline_q.' + user,
                      timeline + '?' + urlencode({'q': SEARCH_TERM}), user,
                      description="the Timeline tab's Search values box"),
        ]
        if small:
            out.append(json_case(prefix + 'cards_ids.' + user, cards, user,
                                 'POST', {'slice': 'ids'},
                                 'the IDS slice, landed'))
    return out


def cases(config):
    fx = load_fixtures(config)
    out = []
    for name, key, enrichment_type in VALUES:
        if fx.get(key):
            out += value_cases(name, str(fx[key]), enrichment_type)
    out += value_cases('never_recorded', NEVER_RECORDED, None)
    for name, key, small in EVENTS:
        if fx.get(key):
            out += event_cases(name, fx[key], small)
    return out
