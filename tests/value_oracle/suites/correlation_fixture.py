"""Correlation fixture: what saving an attribute correlates with, under each
engine, without recorrelating anything.

For Default, NoAcl and OnDemand in turn, a case switches the instance to the
engine, creates a scratch event and adds one attribute per fixture through
attributes/add, so save-time correlation runs. The values are built from
stored ones (the cf_* picks of fixtures.json) to find, or deliberately miss,
known targets in the frozen data: an exact match; case, accent and no-break
space variants; a composite matching on value2; both sides of the
primary-only composite rule; an IP inside a stored CIDR and CIDRs over stored
IPs (advanced correlations on); exact, wildcard and case-variant exclusions;
an over-correlating value, blocked already or not yet; disable_correlation on
either side; a target the lesser user may not see; values sharing their
first 128 characters; a value longer than correlation_values keeps; trailing
spaces; 4-byte characters, which 2.x stores as '?'.

Each case records what 2.x stored for every fixture, the engine table's rows
of the scratch event with their correlation value, the over-correlation
entries of the fixture values (table engines only: OnDemand never blocks),
and for the admin and the lesser user the related events and per-attribute
correlations of events/view (includeGranularCorrelations) and of
attributes/restSearch (includeCorrelations). Then it deletes the event.
Scratch attributes are relabelled with their fixture names and the scratch
event as <scratch>; everything is recorded as sorted sets.

The correlation exclusions must be cached in Redis (oracle.py restore
rebuilds them). Each case clears the Redis CIDR list before and after, since
deleting an event leaves its CIDRs in it. teardown() restores the engine and
MISP.enable_advanced_correlations.
"""

import hashlib
import ipaddress
import json
import unicodedata
import uuid

from core import Case, Client, OracleError
from restore import EXCLUSIONS_KEY, Restorer
from suites import correlations
from suites.restsearch import load_fixtures

USERS = ('admin', 'lesser')
SCRATCH_INFO = 'value oracle scratch: correlation fixture'
ADVANCED = 'MISP.enable_advanced_correlations'
CIDR_CACHE = 'misp:cidr_cache_list'
NETWORK, PAYLOAD, OTHER = 'Network activity', 'Payload delivery', 'Other'
NBSP = ' '
TRAILING_HASH = hashlib.md5(b'o5f trailing space').hexdigest()
COLUMNS = {
    'default_correlations': (
        'attribute_id', 'object_id', 'event_id', 'org_id', 'distribution',
        'object_distribution', 'event_distribution', 'sharing_group_id',
        'object_sharing_group_id', 'event_sharing_group_id',
        '1_attribute_id', '1_object_id', '1_event_id', '1_org_id',
        '1_distribution', '1_object_distribution', '1_event_distribution',
        '1_sharing_group_id', '1_object_sharing_group_id',
        '1_event_sharing_group_id'),
    'no_acl_correlations': (
        'attribute_id', 'event_id', '1_attribute_id', '1_event_id'),
}
STATE = {'advanced': None, 'advanced_changed': False}


def strip_accents(text):
    return unicodedata.normalize('NFC', ''.join(
        c for c in unicodedata.normalize('NFD', text)
        if unicodedata.category(c) != 'Mn'))


def ip_or_text(value):
    try:
        ipaddress.ip_address(value)
        return 'ip-dst'
    except ValueError:
        return 'text'


def specs(fx):
    """[(name, type, category, value, disable_correlation)], leaving out
    fixtures whose pick is missing."""
    def get(key, build=lambda v: v):
        return None if fx.get(key) is None else build(fx[key])

    rows = (
        ('exact', 'domain', NETWORK, get('cf_exact')),
        ('case_variant', 'filename', PAYLOAD, get('cf_case', str.upper)),
        ('accent_variant', 'email-subject', PAYLOAD,
         get('cf_accent', strip_accents)),
        ('nbsp_variant', 'text', OTHER, get('cf_nbsp')),
        ('composite_value2', 'filename|sha256', PAYLOAD,
         get('cross_slot_hash', lambda v: 'o5f-composite.bin|' + v)),
        ('primary_only_source', 'hostname|port', NETWORK,
         get('cf_primary_number', lambda v: 'primary-only.o5f.example|' + v)),
        ('primary_only_target', 'text', OTHER, get('port_value2')),
        ('excluded', ip_or_text(fx.get('cf_excluded') or ''), NETWORK,
         get('cf_excluded')),
        ('excluded_wildcard', ip_or_text(fx.get('cf_excluded_wildcard') or ''),
         NETWORK, get('cf_excluded_wildcard')),
        ('excluded_case_variant', 'filename', PAYLOAD,
         get('cf_excluded_case', str.upper)),
        ('over_correlating', 'domain', NETWORK, get('cf_over_blocked')),
        ('over_correlating_new', 'text', OTHER, get('cf_over_new')),
        ('disabled_source', 'domain', NETWORK, get('cf_disabled_source'),
         True),
        ('disabled_target', 'text', OTHER, get('cf_disabled_target')),
        ('restricted_target', 'domain', NETWORK, get('cf_restricted')),
        ('long_prefix_exact', 'text', OTHER, get('cf_long_prefix')),
        ('long_prefix_variant', 'text', OTHER,
         get('cf_long_prefix', lambda v: v[:128] + '-o5f-variant')),
        ('long_over_191', 'text', OTHER, get('cf_long_191')),
        ('long_case_tail', 'other', OTHER,
         get('cf_long_191', lambda v: v[:128] + v[128:].swapcase())),
        ('trailing_space', 'filename|md5', PAYLOAD,
         get('cf_trailing', lambda v: v + ' |' + TRAILING_HASH)),
        ('trailing_nbsp', 'text', OTHER,
         get('cf_trailing_alt', lambda v: v + NBSP)),
        ('four_byte', 'url', NETWORK,
         get('cf_four_byte', lambda v: v.replace('?', '\U0001F600', 1))),
        ('four_byte_alt', 'text', OTHER,
         get('cf_four_byte', lambda v: v.replace('?', '\U0001F608', 1))),
        # Last, so their CIDRs reach the Redis list after the IPs are saved.
        ('cidr_member', 'ip-dst', NETWORK, get('plan_ip_in_cidr')),
        ('cidr_over_ips', 'ip-dst', NETWORK, get('cf_cidr_v4')),
        ('cidr6_over_ips', 'ip-dst', NETWORK, get('cf_cidr_v6')),
    )
    return [(r[0], r[1], r[2], r[3], len(r) > 4 and r[4])
            for r in rows if r[3] is not None]


def read_setting(client, name):
    response = client.request('GET', '/servers/getSetting/%s' % name)
    if response.status != 200:
        raise OracleError('cannot read %s (HTTP %d)' % (name,
                                                        response.status))
    return response.json().get('value')


def set_advanced(client, enabled):
    response = client.request(
        'POST', '/servers/serverSettingsEdit/%s' % ADVANCED,
        {'value': 1 if enabled else 0})
    if response.status != 200:
        raise OracleError('cannot set %s (HTTP %d): %s' % (
            ADVANCED, response.status, response.text()[:200]))


def ensure_advanced(client):
    if STATE['advanced'] is None:
        STATE['advanced'] = bool(read_setting(client, ADVANCED))
    if not STATE['advanced'] and not STATE['advanced_changed']:
        set_advanced(client, True)
        STATE['advanced_changed'] = True


def check_exclusions(db):
    """Exclusions are read from Redis only and never re-cached lazily: a
    missing set silently changes what correlates."""
    stored = {bytes.fromhex(h) for h in db.query(
        'SELECT HEX(value) FROM correlation_exclusions').split()}
    cached = {m for m in db.redis('SMEMBERS', EXCLUSIONS_KEY).split(b'\n')
              if m}
    if cached != stored:
        raise OracleError(
            'Redis %s holds %d values, the table %d: run oracle.py restore'
            % (EXCLUSIONS_KEY, len(cached), len(stored)))


def literal(value, charset):
    return "CONVERT(X'%s' USING %s) COLLATE %s_unicode_ci" % (
        value.encode().hex(), charset, charset)


class Scratch:
    """The scratch event of one case, with its attributes relabelled."""

    def __init__(self, client, fixtures):
        self.client = client
        self.fixtures = fixtures
        self.statuses = []
        self.event_id = None
        self.names = {}
        self.uuids = {}
        self.stored = {}

    def call(self, method, path, body=None, user='admin'):
        response = self.client.request(method, path, body, user)
        self.statuses.append(response.status)
        return response

    def status(self):
        failed = [s for s in self.statuses if not 200 <= s < 300]
        return failed[0] if failed else 200

    def create(self):
        response = self.call('POST', '/events/add', {'Event': {
            'info': SCRATCH_INFO, 'distribution': 1, 'threat_level_id': 4,
            'analysis': 0}})
        if response.status != 200:
            raise OracleError('scratch event not created (HTTP %d)'
                              % response.status)
        self.event_id = str(response.json()['Event']['id'])
        attributes = []
        for name, kind, category, value, disabled in self.fixtures:
            key = str(uuid.uuid4())
            self.uuids[key] = name
            attributes.append({
                'uuid': key, 'type': kind, 'category': category,
                'value': value, 'distribution': 5,
                'disable_correlation': bool(disabled)})
        response = self.call('POST', '/attributes/add/%s' % self.event_id,
                             attributes)
        body = response.json()
        for key, errors in (body.get('errors') or {}).items():
            index = int(key.rsplit('_', 1)[1])
            self.stored[self.fixtures[index][0]] = {'errors': errors}

    def delete(self):
        if self.event_id is not None:
            self.call('POST', '/events/delete/%s' % self.event_id)

    def label(self, attribute_id):
        return self.names.get(str(attribute_id), int(attribute_id))

    def read_stored(self, event):
        for attribute in event.get('Attribute', []):
            name = self.uuids.get(attribute['uuid'])
            if name is None:
                continue
            self.names[str(attribute['id'])] = name
            self.stored[name] = {
                'type': attribute['type'], 'value': attribute['value'],
                'disable_correlation': bool(attribute['disable_correlation'])}

    def values(self):
        out = set()
        for entry in self.stored.values():
            if 'value' not in entry:
                continue
            parts = (entry['value'].split('|', 1) if '|' in entry['type']
                     else [entry['value']])
            out.update(p for p in parts if p)
        return sorted(out)

    def rows(self, db, table):
        columns = COLUMNS[table]
        found = db.query(
            'SELECT %s, HEX(v.value) FROM %s c '
            'LEFT JOIN attribute_values v ON v.id = c.value_id '
            'WHERE c.event_id = %d OR c.1_event_id = %d' % (
                ', '.join('c.' + c for c in columns), table,
                int(self.event_id), int(self.event_id)))
        out = []
        for line in found.splitlines():
            fields = line.split('\t')
            cells = []
            for column, cell in zip(columns, fields):
                if column.endswith('attribute_id'):
                    cell = self.label(cell)
                elif column.endswith('event_id') and cell == self.event_id:
                    cell = '<scratch>'
                cells.append('%s=%s' % (column, cell))
            value = fields[-1]
            cells.append('value=%s' % (json.dumps(
                bytes.fromhex(value).decode(), ensure_ascii=False)
                if value != 'NULL' else 'NULL'))
            out.append(' '.join(cells))
        return sorted(out)

    def views(self, user):
        out = {}
        view = self.call(
            'GET', '/events/view/%s/includeGranularCorrelations:1'
            % self.event_id, user=user)
        out['view_status'] = view.status
        if view.status == 200:
            event = view.json()['Event']
            if user == 'admin':
                self.read_stored(event)
            out['related_events'] = sorted(
                int(r['Event']['id']) for r in event.get('RelatedEvent', []))
            related, flagged = {}, []
            for attribute in event.get('Attribute', []):
                name = self.label(attribute['id'])
                entries = sorted(
                    '%s event %s org %s: %s' % (
                        self.label(r['id']), r.get('event_id'),
                        r.get('org_id'),
                        json.dumps(r['value'], ensure_ascii=False))
                    for r in flatten(attribute.get('RelatedAttribute'))
                    if 'attribute_id' not in r)
                if entries:
                    related[str(name)] = entries
                if attribute.get('correlation_exclusion'):
                    flagged.append(name)
            out['related_attributes'] = related
            out['exclusion_flagged'] = sorted(str(n) for n in flagged)
        search = self.call('POST', '/attributes/restSearch', {
            'eventid': self.event_id, 'includeCorrelations': 1,
            'returnFormat': 'json'}, user=user)
        out['search_status'] = search.status
        if search.status == 200:
            related = {}
            for attribute in search.json()['response']['Attribute']:
                entries = sorted(
                    '%s event %s: %s' % (
                        self.label(r['id']), r.get('event_id'),
                        json.dumps(r.get('value'), ensure_ascii=False))
                    for r in attribute.get('RelatedAttribute') or [])
                if entries:
                    related[str(self.label(attribute['id']))] = entries
            out['search_related'] = related
        return out


def flatten(entries):
    """The JSON converter gives every attribute its full list. With
    includeGranularCorrelations the REST view also appends the event-level
    list of one parent, nested and with an attribute_id key, to whichever
    attribute the unordered correlation read returns first: views() skips
    those entries."""
    for entry in entries or []:
        if isinstance(entry, list):
            yield from flatten(entry)
        else:
            yield entry


def over_correlating(db, values):
    if not values:
        return []
    found = db.query(
        'SELECT HEX(b.value), o.occurrence FROM over_correlating_values o '
        'JOIN attribute_values b ON b.id = o.value_id '
        'WHERE b.value IN (%s)' % ', '.join(
            literal(v, 'utf8mb4') for v in values))
    return sorted('%s (occurrence %s)' % (
        json.dumps(bytes.fromhex(h).decode(), ensure_ascii=False), n)
        for h, n in (line.split('\t') for line in found.splitlines()))


def engine_case(label, engine, table, config):
    def run(client):
        db = Restorer(config.restore, log=lambda *a: None)
        check_exclusions(db)
        correlations.switch_engine(client, engine)
        ensure_advanced(client)
        value = {'settings': {
            'engine': correlations.current_engine(client),
            'correlation_limit': read_setting(client,
                                              'MISP.correlation_limit'),
            'advanced_correlations': read_setting(client, ADVANCED)}}
        db.redis('UNLINK', CIDR_CACHE)
        scratch = Scratch(client, specs(load_fixtures(config)))
        try:
            scratch.create()
            for user in USERS:
                value[user] = scratch.views(user)
            value['stored'] = scratch.stored
            if table is not None:
                value['rows'] = scratch.rows(db, table)
                value['over_correlating'] = over_correlating(
                    db, scratch.values())
        finally:
            scratch.delete()
            db.redis('UNLINK', CIDR_CACHE)
        return scratch.status(), value
    return Case('correlation_fixture.%s' % label, run=run,
                description='%s engine: save-time correlation of the '
                'fixture values' % engine)


def cases(config):
    return [engine_case(label, engine, table, config)
            for label, engine, table in correlations.ENGINES]


def teardown(config):
    client = Client(config)
    if STATE['advanced_changed']:
        set_advanced(client, STATE['advanced'])
        STATE['advanced_changed'] = False
    correlations.teardown(config)
