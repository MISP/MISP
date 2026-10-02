"""Query plans on the value paths: the probe shapes of the exploration (EXP
section 4), run as application operations, with what the database does for
each statement they issue.

None of it is visible over HTTP, so app/Test/AttributePlanOracleTest.php
captures it, one PHPUnit process per case: nothing one operation caches
reaches another, and a --case selection records what a full run does. Every
operation runs in a rolled-back transaction.

Per statement shape that touches a value table (literals removed), a case
records how often it ran and, per table, the access type, key, covering flag
and rows examined (SELECTs are re-run under ANALYZE, writes only EXPLAINed),
then the large reads among them. Kept out of the compared value, in the
case's meta: the timings, which "oracle.py timings" reports, and the index
names. Which of several equivalent indexes serves a lookup follows InnoDB's
sampled statistics and changes from one restore to the next; the key parts
it uses do not.

Restore before recording, and never run it while the correlations suite
runs: that suite switches the engine and rewrites the correlation tables.
"""

import phpunit
from core import Case, OracleError
from suites.restsearch import load_fixtures

TEST_FILE = 'Test/AttributePlanOracleTest.php'
OUTPUT_TAIL = 2000
USERS = ('admin', 'lesser')
# What events/view hands fetchEvent() for a REST request.
REST_VIEW = {
    'includeAnalystData': True, 'includeAttachments': True, 'deleted': 0,
    'excludeLocalTags': False, 'includeWarninglistHits': True,
    'includeFeedCorrelations': 1, 'includeServerCorrelations': 0,
}
# CIDR blocks of EXP section 4 H1 (mask >= 8, so today's code adds a LIKE
# prefix) and H2 (mask < 8, no prefix).
CIDR_WITH_PREFIX = '187.0.0.0/8'
CIDR_WITHOUT_PREFIX = '184.0.0.0/5'


def operations(fx):
    """[(case suffix, operation)], an operation being what
    AttributePlanOracle runs: op, user label, args, optional engine."""
    out = []

    def add(name, op, args, user='admin', engine=None):
        operation = {'op': op, 'user': user, 'args': args}
        if engine:
            operation['engine'] = engine
        out.append((name, operation))

    def search(value):
        return {'format': 'json', 'filters': {'value': value}}

    def save(event_id, value):
        return {'attribute': {
            'event_id': int(event_id), 'type': 'ip-dst',
            'category': 'Network activity', 'value': value, 'to_ids': 0,
            'distribution': 5}}

    if fx.get('export_largest'):
        add('a1.fetch_event', 'fetchEvent', {'options': dict(
            REST_VIEW, eventid=int(fx['export_largest']))})
    for user in USERS:
        if fx.get('domain_common'):
            add('b.exact.' + user, 'attributeRestSearch',
                search(fx['domain_common']), user)
            add('b.event_scope.' + user, 'eventRestSearch', {
                'format': 'json', 'filters': {
                    'value': fx['domain_common'], 'metadata': 1}}, user)
        if fx.get('substring_term'):
            add('c.substring.' + user, 'attributeRestSearch',
                search(fx['substring_term']), user)
        if fx.get('prefix_term'):
            add('d.prefix.' + user, 'attributeRestSearch',
                search(fx['prefix_term']), user)
    if fx.get('composite_full'):
        add('b.composite.admin', 'attributeRestSearch',
            search(fx['composite_full']))
    event = fx.get('plan_correlation_event')
    if event:
        add('e.recorrelate', 'recorrelateEvent', {'event_id': int(event)})
        for engine in ('Default', 'OnDemand'):
            for user in USERS:
                add('e.related.%s.%s' % (engine.lower(), user),
                    'relatedToEvent', {'event_id': int(event)}, user, engine)
    # The large event fills OnDemand's correlation cap before its
    # value2-to-value2 pass, which a small event still reaches.
    if fx.get('export_small'):
        add('e.related_small.ondemand.admin', 'relatedToEvent',
            {'event_id': int(fx['export_small'])}, engine='OnDemand')
    add('f.type_export', 'attributeRestSearch', {
        'format': 'text', 'filters': {'type': 'ip-dst', 'to_ids': 1}})
    add('g.index_sort', 'attributeIndex', {'filters': {}, 'params': {
        'order': 'Attribute.value asc', 'page': 1, 'limit': 60}})
    if fx.get('export_small'):
        small = fx['export_small']
        add('h.cidr_prefix_save', 'saveAttribute',
            save(small, CIDR_WITH_PREFIX))
        add('h.cidr_wide_save', 'saveAttribute',
            save(small, CIDR_WITHOUT_PREFIX))
        if fx.get('plan_ip_in_cidr'):
            add('h.ip_in_cidr_save', 'saveAttribute',
                save(small, fx['plan_ip_in_cidr']))
    if fx.get('export_largest') and fx.get('substring_term'):
        add('j.paginated_search', 'paginatedAttributes', {
            'event_id': int(fx['export_largest']),
            'options': {'searchFor': fx['substring_term'].strip('%')}})
    return out


def capture_plans(app_dir, request):
    return phpunit.run(app_dir, TEST_FILE, 'VALUE_ORACLE_PLANS', request)


class Users:
    """Ids of the configured users, asked of the instance once."""

    def __init__(self):
        self.ids = {}

    def id(self, client, label):
        if label not in self.ids:
            response = client.request('GET', '/users/view/me.json',
                                      user=label)
            if response.status != 200:
                raise OracleError('cannot resolve user %s (HTTP %d)'
                                  % (label, response.status))
            self.ids[label] = int(response.json()['User']['id'])
        return self.ids[label]


def run_operation(app_dir, name, operation, users, client,
                  runner=capture_plans):
    request = {'operations': {name: dict(
        operation, user=users.id(client, operation['user']))}}
    code, output, result, _, _ = runner(app_dir, request)
    if code != 0 or not result or name not in result:
        return 500, {'phpunit_exit': code,
                     'output_tail': output[-OUTPUT_TAIL:]}
    entry = result[name]
    value = entry['value']
    if entry.get('error'):
        value = dict(value, error=entry['error'])
    status = 500 if entry.get('error') else 200
    return status, value, {'timings': entry.get('timings', {}),
                           'indexes': entry.get('indexes', [])}


def cases(config):
    fx = load_fixtures(config)
    app_dir = (config.restore or {}).get('app_dir', '')
    users = Users()

    def case(name, operation):
        return Case('plans.' + name,
                    run=lambda client: run_operation(
                        app_dir, name, operation, users, client),
                    description='%s as %s' % (operation['op'],
                                              operation['user']))
    return [case(name, operation) for name, operation in operations(fx)]
