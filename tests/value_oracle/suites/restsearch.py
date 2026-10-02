"""restSearch value-filter matrix across the attribute, event and object
scopes, run as a site admin and as a lesser org user.

Inputs come from the fixtures file (see discover_fixtures.py); a variant whose
fixture was not found is skipped. Broad matches record a count plus an
id-ordered first page instead of the full id list; 'page' variants record
only the page, because their count alone exhausts PHP memory on 2.x. Event
negation and quick-filter variants are bounded to a fixed event sample: on
2.x they exceed the 30 s execution limit for a non-admin user. searchall
takes its term literally, quickFilter wraps it in wildcards.
"""

import json
import os

from core import (Case, OracleError, count_body, ids_at, ids_by_path,
                  ordered_ids_at)

ATTRIBUTES = '/attributes/restSearch'
EVENTS = '/events/restSearch'
OBJECTS = '/objects/restSearch'
USERS = ('admin', 'lesser')
SAMPLE = {'order': 'Attribute.id asc', 'limit': 1000, 'page': 1}

ATTRIBUTE_IDS = 'response.Attribute[].id'
PROPOSAL_IDS = 'response.Attribute[].ShadowAttribute[].id'
EVENT_IDS = 'response[].Event.id'
OBJECT_IDS = 'response[].Object.id'

EXACT_ATTRIBUTE = (
    'ip_common', 'ip_hub', 'domain_common', 'domain_upper', 'case_variant',
    'case_variant_upper', 'accent_variant', 'url_common',
    'long_shared_prefix', 'long_text', 'cross_slot_hash', 'port_value2',
    'composite_full', 'object_only_ip', 'deleted_only', 'percent_literal',
    'proposal_value',
)
EXACT_EVENT = (
    'ip_common', 'domain_upper', 'case_variant', 'cross_slot_hash',
    'port_value2', 'composite_full', 'long_shared_prefix', 'object_only_ip',
    'proposal_value',
)


def load_fixtures(config):
    if not config.fixtures:
        raise OracleError('config has no "fixtures" path; '
                          'run discover_fixtures.py first')
    with open(os.path.expanduser(config.fixtures)) as fh:
        return json.load(fh)


def neg(term):
    return None if term is None else '!' + term


def bare(term):
    return None if term is None else term.strip('%')


def attribute_variants(fx):
    f = fx.get
    v = [('value_' + k, {'value': f(k)}, None) for k in EXACT_ATTRIBUTE]
    v += [
        ('value_list', {'value': [f('ip_common'), f('domain_common')]}, None),
        ('value_substring', {'value': f('substring_term')}, None),
        ('value_prefix', {'value': f('prefix_term')}, None),
        ('value_suffix_broad', {'value': f('suffix_term')}, 'broad'),
        ('value_not_typed',
         {'type': 'ip-dst', 'value': neg(f('ip_common'))}, 'broad'),
        ('value_not_list_typed',
         {'type': 'domain', 'value': [neg(f('domain_common'))]}, 'broad'),
        ('value_in_and_not',
         {'value': [f('substring_term'), neg(f('domain_common'))]}, None),
        ('value1_exact', {'value1': f('ip_common')}, None),
        ('value2_exact', {'value2': f('port_value2')}, None),
        ('value1_prefix', {'value1': f('prefix_term')}, None),
        ('value2_not_typed',
         {'type': 'ip-dst|port', 'value2': neg(f('port_value2'))}, 'broad'),
        ('type_and_value',
         {'type': 'ip-dst', 'value': f('ip_common')}, None),
        ('type_composite_and_value',
         {'type': 'ip-dst|port', 'value': f('ip_common')}, None),
        ('category_and_value',
         {'category': 'Network activity', 'value': f('ip_common')}, None),
        ('to_ids_and_value',
         {'to_ids': 1, 'value': f('substring_term')}, None),
        ('eventid_and_value',
         {'eventid': f('ip_event'), 'value': f('ip_common')}, None),
        ('searchall_wild', {'searchall': f('substring_term')}, None),
        ('searchall_exact', {'searchall': f('domain_common')}, None),
        ('quickfilter', {'quickFilter': bare(f('substring_term'))}, 'page'),
        ('flatten_object_only_ip',
         {'value': f('object_only_ip'), 'flatten': 1}, None),
        ('deleted_included',
         {'value': f('deleted_only'), 'deleted': [0, 1]}, None),
        ('deleted_only_flag',
         {'value': f('deleted_only'), 'deleted': 1}, None),
    ]
    return v


def event_variants(fx):
    f = fx.get
    v = [('value_' + k, {'value': f(k)}) for k in EXACT_EVENT]
    v += [
        ('value_list', {'value': [f('ip_common'), f('domain_common')]}),
        ('value_substring', {'value': f('substring_term')}),
        ('type_and_value', {'type': 'ip-dst', 'value': f('ip_common')}),
    ]
    sample = f('event_sample')
    v += [
        ('sampled_value_not',
         {'value': neg(f('ip_common')), 'eventid': sample}),
        ('sampled_value_in_and_not',
         {'value': [f('substring_term'), neg(f('ip_common'))],
          'eventid': sample}),
        ('sampled_searchall_wild',
         {'searchall': f('substring_term'), 'eventid': sample}),
        ('sampled_searchall_exact',
         {'searchall': f('domain_common'), 'eventid': sample}),
        ('sampled_quickfilter',
         {'quickFilter': bare(f('substring_term')), 'eventid': sample}),
    ]
    return v


def object_variants(fx):
    f = fx.get
    return [
        ('value_object_only_ip', {'value': f('object_only_ip')}),
        ('value_ip_common', {'value': f('ip_common')}),
        ('value_substring', {'value': f('substring_term')}),
        ('value_list', {'value': [f('object_only_ip'), f('ip_common')]}),
        ('quickfilter', {'quickFilter': bare(f('substring_term'))}),
    ]


def usable(filters):
    def has_none(v):
        if isinstance(v, list):
            return any(has_none(x) for x in v)
        return v is None
    return not any(has_none(v) for v in filters.values())


def attribute_cases(fx, user):
    out = []
    for name, filters, shape in attribute_variants(fx):
        if not usable(filters):
            continue
        if shape == 'broad':
            out.append(Case(
                'attr.%s.count.%s' % (name, user), ATTRIBUTES, count_body,
                method='POST', user=user,
                body=dict(filters, returnFormat='count'),
                description='count of ' + name))
        if shape in ('broad', 'page'):
            out.append(Case(
                'attr.%s.page1.%s' % (name, user), ATTRIBUTES,
                ordered_ids_at(ATTRIBUTE_IDS), method='POST', user=user,
                body=dict(filters, returnFormat='json', **SAMPLE),
                description='first id-ordered page of ' + name))
        if shape is None:
            out.append(Case(
                'attr.%s.%s' % (name, user), ATTRIBUTES,
                ids_at(ATTRIBUTE_IDS), method='POST', user=user,
                body=dict(filters, returnFormat='json'),
                description=json.dumps(filters)[:60]))
    if fx.get('prefix_term'):
        for page in (1, 2):
            out.append(Case(
                'attr.order_by_value.page%d.%s' % (page, user), ATTRIBUTES,
                ordered_ids_at(ATTRIBUTE_IDS), method='POST', user=user,
                body={'value': fx['prefix_term'], 'returnFormat': 'json',
                      'order': 'Attribute.value asc,Attribute.id asc',
                      'limit': 50,
                      'page': page},
                description='ordered by value, page %d' % page))
    if fx.get('proposal_event'):
        out.append(Case(
            'attr.include_proposals.%s' % user, ATTRIBUTES,
            ids_by_path({'attributes': ATTRIBUTE_IDS,
                         'proposals': PROPOSAL_IDS}),
            method='POST', user=user,
            body={'eventid': fx['proposal_event'], 'includeProposals': 1,
                  'returnFormat': 'json'},
            description='attributes with their proposals'))
    return out


def scoped_cases(prefix, path, extract_path, variants, user, extra):
    return [
        Case('%s.%s.%s' % (prefix, name, user), path, ids_at(extract_path),
             method='POST', user=user, body=dict(filters, **extra),
             description=json.dumps(filters)[:60])
        for name, filters in variants if usable(filters)
    ]


def cases(config):
    fx = load_fixtures(config)
    out = []
    for user in USERS:
        out += attribute_cases(fx, user)
        out += scoped_cases('event', EVENTS, EVENT_IDS, event_variants(fx),
                            user, {'returnFormat': 'json', 'metadata': 1})
        out += scoped_cases('object', OBJECTS, OBJECT_IDS,
                            object_variants(fx), user,
                            {'returnFormat': 'json'})
    return out
