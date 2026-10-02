"""REST responses that expose attribute values: reads on the frozen data, then
write round trips in scratch events.

Reads run as the site admin and as the lesser user and record the response
text as served. They cover attributes/view and the REST attributes/index,
objects/view and objects/restSearch, events/view and events/viewAttachments,
restSearch with includeProposals, and the proposal index and view. Pages are
id-ordered; the value-sorted page records its values in order and its ids as
a set, since rows sharing a value have no defined order. warninglist_id is
recorded as a number everywhere: 2.x types it by the state of its cache.

Each round trip creates its own scratch event, writes through one path
(attributes/add and edit, objects/add and edit, proposals and their
acceptance, a nested events/add followed by events/edit), reads the results
back and deletes the event. Ids and uuids of the scratch entities are
relabelled in order of creation, and timestamps inside the case's own time
window are masked. Round trips correlate with the frozen data and leave log
rows behind, so they run last. Proposals make MISP mail an alert to the
scratch event's org members that have contactalert set: run the suite only
where mail cannot leave the host.
"""

import re
import time
from datetime import datetime, timezone

from core import Case
from suites.exports import mask_generated
from suites.restsearch import load_fixtures

USERS = ('admin', 'lesser')
INDEX_PAGE = 50
SCRATCH_INFO = 'value oracle scratch: %s'
ENTITY_KINDS = {
    'Event': 'event', 'Attribute': 'attribute', 'Object': 'object',
    'ShadowAttribute': 'proposal',
}
REFERENCE_KINDS = {
    'event_id': 'event', 'object_id': 'object', 'old_id': 'attribute',
    'attribute_id': 'attribute',
}
# Values and their categories for the attribute round trip; None values are
# filled from the fixtures.
SCRATCH_ATTRIBUTES = (
    ('domain', 'Network activity', 'Scratch.Example.ORG'),
    ('ip-dst', 'Network activity', '2001:DB8::0001'),
    ('ip-dst|port', 'Network activity', None),
    ('sha256', 'Payload delivery', None),
    ('filename|md5', 'Payload delivery',
     'scratch.exe|0cc175b9c0f1b6a831c399e269772661'),
    ('filename|md5', 'Payload delivery', 'scratch.exe|'),
    ('text', 'Other', 'fox \U0001F98A text'),
    ('url', 'Network activity', None),
    ('regkey|value', 'Persistence mechanism',
     'HKLM\\Software\\Scratch|data'),
)
FIXTURE_VALUES = {
    'ip-dst|port': 'composite_full', 'sha256': 'cross_slot_hash',
    'url': 'long_shared_prefix',
}


# A warninglist hit read from the Redis cache carries an int warninglist_id,
# a fresh one the DB string.
WARNINGLIST_ID = re.compile(r'("warninglist_id": )"(\d+)"')


def raw_text(response):
    return WARNINGLIST_ID.sub(r'\1\2', response.text())


def sorted_by_value(response):
    rows = response.json()
    return {'values': [r['value'] for r in rows],
            'ids': sorted(int(r['id']) for r in rows)}


class Scratch:
    """One round trip: records every step and relabels what it created."""

    def __init__(self, client):
        self.client = client
        self.steps = []
        self.ids = {kind: {} for kind in ENTITY_KINDS.values()}
        self.uuids = {}
        self.started = time.time()
        self.event_id = None

    def call(self, step, method, path, body=None, user='admin'):
        response = self.client.request(method, path, body, user)
        try:
            data = response.json()
        except ValueError:
            data = response.text()
        self.steps.append({'step': step, 'status': response.status,
                           'body': data})
        return data if 200 <= response.status < 300 else None

    def register(self, kind, entity):
        if not isinstance(entity, dict):
            return
        if entity.get('id') is not None:
            ids = self.ids[kind]
            ids.setdefault(str(entity['id']),
                           '<%s:%d>' % (kind, len(ids) + 1))
        if entity.get('uuid'):
            self.uuids.setdefault(entity['uuid'],
                                  '<uuid:%d>' % (len(self.uuids) + 1))

    def register_created(self, data):
        """Ids and uuids of the entities a write response returns, without
        the frozen ones it embeds (related events, orgs, tags)."""
        if not isinstance(data, dict):
            return
        event = data.get('Event')
        if isinstance(event, dict):
            self.register('event', event)
            self.register_attributes(event.get('Attribute'))
            for obj in event.get('Object') or []:
                self.register('object', obj)
                self.register_attributes(obj.get('Attribute'))
        obj = data.get('Object')
        if isinstance(obj, dict):
            self.register('object', obj)
            self.register_attributes(obj.get('Attribute'))
        self.register_attributes(data.get('Attribute'))
        self.register('proposal', data.get('ShadowAttribute'))

    def register_attributes(self, attributes):
        if isinstance(attributes, dict):
            attributes = [attributes]
        for attribute in attributes or []:
            self.register('attribute', attribute)

    def create_event(self, name, extra=None):
        body = {'Event': dict({
            'info': SCRATCH_INFO % name, 'distribution': 1,
            'threat_level_id': 4, 'analysis': 0}, **(extra or {}))}
        data = self.call('create event', 'POST', '/events/add', body)
        if data is None:
            raise RuntimeError('scratch event not created')
        self.register_created(data)
        self.event_id = data['Event']['id']
        return data

    def delete_event(self):
        if self.event_id is not None:
            self.call('delete event', 'POST',
                      '/events/delete/%s' % self.event_id)

    def finish(self):
        finished = time.time()
        today = {datetime.fromtimestamp(t, tz).strftime('%Y-%m-%d')
                 for t in (self.started, finished)
                 for tz in (timezone.utc, None)}
        relabelled = [self._relabel(step, None, None, finished, today)
                      for step in self.steps]
        statuses = [s['status'] for s in self.steps]
        failed = [s for s in statuses if not 200 <= s < 300]
        return (failed[0] if failed else 200), relabelled

    @staticmethod
    def _entity(key, current):
        if key in ENTITY_KINDS:
            return ENTITY_KINDS[key]
        # Org, Tag, RelatedEvent, ...: never one of the scratch entities.
        return 'other' if key[:1].isupper() else current

    def _lookup(self, kind, value):
        if kind is not None:
            return self.ids.get(kind, {}).get(str(value))
        found = {ids[str(value)] for ids in self.ids.values()
                 if str(value) in ids}
        return found.pop() if len(found) == 1 else None

    def _relabel_path(self, text):
        def replace(match):
            label = self._lookup(None, match.group(2))
            return match.group(1) + (label or match.group(2))
        return re.sub(r'(/)(\d+)(?=$|/)', replace, text)

    def _relabel(self, value, key, entity, finished, today):
        if isinstance(value, dict):
            return {k: self._relabel(v, k, self._entity(k, entity),
                                     finished, today)
                    for k, v in value.items()}
        if isinstance(value, list):
            return [self._relabel(v, key, entity, finished, today)
                    for v in value]
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, str) and value in self.uuids:
            return self.uuids[value]
        if key == 'id':
            label = self._lookup(entity, value)
            if label is None and isinstance(value, str) and '/' in value:
                return self._relabel_path(value)
            return label or value
        if key in REFERENCE_KINDS:
            return self._lookup(REFERENCE_KINDS[key], value) or value
        if key == 'url' and isinstance(value, str):
            return self._relabel_path(value)
        if key == 'date' and value in today:
            return '<today>'
        if key == 'warninglist_id' and isinstance(value, str) and \
                value.isdigit():
            return int(value)
        text = str(value)
        if text.isdigit() and len(text) == 10 and \
                self.started - 5 <= int(text) <= finished + 5:
            return '<now>'
        if isinstance(value, str):
            return mask_generated(value, self.started, finished)
        return value


def roundtrip(steps):
    def run(client):
        scratch = Scratch(client)
        try:
            steps(scratch)
        except Exception as e:
            scratch.steps.append({'step': 'error', 'status': 0,
                                  'body': '%s: %s' % (type(e).__name__, e)})
        finally:
            scratch.delete_event()
        return scratch.finish()
    return run


def attribute_roundtrip(fixtures):
    def steps(s):
        s.create_event('attributes')
        attributes = []
        for kind, category, value in SCRATCH_ATTRIBUTES:
            if value is None:
                value = fixtures.get(FIXTURE_VALUES[kind])
            if value is not None:
                attributes.append(
                    {'type': kind, 'category': category, 'value': value})
        data = s.call('add attributes', 'POST',
                      '/attributes/add/%s' % s.event_id, attributes)
        s.register_created(data)
        created = [a for a in (data or {}).get('Attribute', [])
                   if isinstance(a, dict)]
        by_type = {}
        for a in created:
            by_type.setdefault(a['type'], a['id'])
            s.call('view %s' % a['type'], 'GET',
                   '/attributes/view/%s' % a['id'])
        edits = (
            ('domain', {'value': 'edited.example.org'}),
            ('ip-dst', {'type': 'ip-src'}),
            ('ip-dst|port', {'type': 'ip-src|port'}),
        )
        for kind, change in edits:
            if kind in by_type:
                s.call('edit %s' % kind, 'POST',
                       '/attributes/edit/%s' % by_type[kind],
                       {'Attribute': change})
                s.call('view edited %s' % kind, 'GET',
                       '/attributes/view/%s' % by_type[kind])
        s.call('search event', 'POST', '/attributes/restSearch',
               {'eventid': s.event_id, 'returnFormat': 'json'})
        s.call('view event', 'GET', '/events/view/%s' % s.event_id)
        if 'url' in by_type:
            s.call('soft delete url', 'POST',
                   '/attributes/delete/%s' % by_type['url'])
            s.call('search with deleted', 'POST', '/attributes/restSearch',
                   {'eventid': s.event_id, 'deleted': [0, 1],
                    'returnFormat': 'json'})
    return steps


def object_roundtrip(fixtures):
    def steps(s):
        s.create_event('objects')
        index = s.call('object templates', 'GET', '/object_templates/index')
        s.steps[-1]['body'] = '<template index>'
        templates = {t['ObjectTemplate']['name']: t['ObjectTemplate']['uuid']
                     for t in index or []}
        objects = (
            ('domain-ip', [
                ('domain', 'domain', 'Object.Example.ORG'),
                ('ip', 'ip-dst', fixtures.get('object_only_ip')),
            ]),
            ('file', [
                ('filename', 'filename', 'scratch.bin'),
                ('sha256', 'sha256', fixtures.get('cross_slot_hash')),
                ('md5', 'md5', '0cc175b9c0f1b6a831c399e269772661'),
            ]),
        )
        created = []
        for name, attributes in objects:
            if name not in templates:
                continue
            body = {'Object': {'Attribute': [
                {'object_relation': r, 'type': t, 'value': v}
                for r, t, v in attributes if v is not None]}}
            data = s.call('add %s' % name, 'POST', '/objects/add/%s/%s' % (
                s.event_id, templates[name]), body)
            s.register_created(data)
            if data:
                created.append(data['Object'])
        for obj in created:
            s.call('view %s' % obj['name'], 'GET',
                   '/objects/view/%s' % obj['id'])
        if created:
            obj = created[-1]
            attributes = [dict(a) for a in obj['Attribute']]
            attributes[0]['value'] = 'edited-' + attributes[0]['value']
            s.call('edit %s' % obj['name'], 'POST',
                   '/objects/edit/%s' % obj['id'],
                   {'Object': {'comment': 'edited', 'Attribute': attributes}})
        s.call('search objects', 'POST', '/objects/restSearch',
               {'eventid': s.event_id})
        s.call('view event', 'GET', '/events/view/%s' % s.event_id)
    return steps


def proposal_roundtrip(fixtures):
    def steps(s):
        s.create_event('proposals')
        data = s.call('add attributes', 'POST',
                      '/attributes/add/%s' % s.event_id, [
                          {'type': 'domain', 'category': 'Network activity',
                           'value': 'proposal.example.org'},
                          {'type': 'ip-dst|port',
                           'category': 'Network activity',
                           'value': '198.51.100.9|443'},
                          {'type': 'url', 'category': 'Network activity',
                           'value': 'http://proposal.example.org/x'},
                      ])
        s.register_created(data)
        ids = {a['type']: a['id'] for a in (data or {}).get('Attribute', [])}
        new = s.call('propose new', 'POST',
                     '/shadow_attributes/add/%s' % s.event_id,
                     {'ShadowAttribute': {'type': 'ip-src',
                                          'category': 'Network activity',
                                          'value': '203.0.113.9'}},
                     user='lesser')
        s.register_created(new)
        edits = {}
        for kind, value in (('domain', 'proposed.example.org'),
                            ('ip-dst|port', '198.51.100.10|8443')):
            if kind in ids:
                edit = s.call('propose edit %s' % kind, 'POST',
                              '/shadow_attributes/edit/%s' % ids[kind],
                              {'ShadowAttribute': {'value': value}},
                              user='lesser')
                s.register_created(edit)
                if edit:
                    edits[kind] = edit['ShadowAttribute']['id']
        if 'url' in ids:
            s.call('propose delete url', 'POST',
                   '/shadow_attributes/delete/%s' % ids['url'], user='lesser')
        index = s.call('proposal index', 'GET',
                       '/shadow_attributes/index/%s' % s.event_id)
        # The deletion proposal is only visible here.
        for row in index or []:
            s.register('proposal', row.get('ShadowAttribute'))
        s.call('search with proposals', 'POST', '/attributes/restSearch',
               {'eventid': s.event_id, 'includeProposals': 1,
                'returnFormat': 'json'})
        s.call('view event', 'GET', '/events/view/%s' % s.event_id)
        for kind, proposal in edits.items():
            s.call('accept %s' % kind, 'POST',
                   '/shadow_attributes/accept/%s' % proposal)
            s.call('view accepted %s' % kind, 'GET',
                   '/attributes/view/%s' % ids[kind])
        if new:
            s.call('discard new', 'POST', '/shadow_attributes/discard/%s'
                   % new['ShadowAttribute']['id'])
        s.call('proposal index after', 'GET',
               '/shadow_attributes/index/%s' % s.event_id)
    return steps


def event_roundtrip(fixtures):
    def steps(s):
        index = s.call('object templates', 'GET', '/object_templates/index')
        s.steps[-1]['body'] = '<template index>'
        templates = {t['ObjectTemplate']['name']: t['ObjectTemplate']['uuid']
                     for t in index or []}
        objects = []
        if 'domain-ip' in templates:
            objects.append({
                'name': 'domain-ip', 'meta-category': 'network',
                'template_uuid': templates['domain-ip'], 'distribution': 5,
                'Attribute': [
                    {'object_relation': 'domain', 'type': 'domain',
                     'value': 'Nested.Object.Example.ORG'},
                    {'object_relation': 'ip', 'type': 'ip-dst',
                     'value': '198.51.100.20'}]})
        attributes = [
            {'type': 'domain', 'category': 'Network activity',
             'value': 'Nested.Example.ORG'},
            {'type': 'filename|md5', 'category': 'Payload delivery',
             'value': 'nested.exe|'},
            {'type': 'ip-dst|port', 'category': 'Network activity',
             'value': fixtures.get('composite_full') or '198.51.100.21|80'},
        ]
        data = s.create_event('nested', {'Attribute': attributes,
                                         'Object': objects})
        s.call('view event', 'GET', '/events/view/%s' % s.event_id)
        created = data['Event'].get('Attribute') or []
        if created:
            first = created[0]
            s.call('edit event', 'POST', '/events/edit/%s' % s.event_id, {
                'Event': {'Attribute': [
                    {'uuid': first['uuid'], 'type': first['type'],
                     'category': first['category'],
                     'value': 'nested-edited.example.org'},
                    {'type': 'hostname|port', 'category': 'Network activity',
                     'value': 'Nested.Example.ORG|8080'},
                ]}})
            s.register_created(s.steps[-1]['body'])
        s.call('view edited event', 'GET', '/events/view/%s' % s.event_id)
    return steps


def read_cases(fx):
    attributes = ('composite', 'object', 'malware', 'proposed', 'deleted',
                  'org_only')
    objects = ('malware', 'org_only')
    index = (
        ('value_exact', {'value': fx.get('domain_common')}),
        ('value_ip', {'value': fx.get('ip_common')}),
        ('value_composite', {'value': fx.get('composite_full')}),
        ('value_wildcard', {'value': fx.get('substring_term')}),
        ('type_composite_page2', {'type': 'ip-dst|port', 'page': 2}),
    )
    out = []
    for user in USERS:
        for shape in attributes:
            pick = fx.get('rest_attribute_' + shape)
            if pick:
                out.append(Case(
                    'attributes.view.%s.%s' % (shape, user),
                    '/attributes/view/%s' % pick, raw_text, user=user,
                    description='attributes/view, %s attribute' % shape))
        for name, filters in index:
            if any(v is None for v in filters.values()):
                continue
            out.append(Case(
                'attributes.index.%s.%s' % (name, user), '/attributes/index',
                raw_text, method='POST', user=user,
                body=dict(filters, limit=INDEX_PAGE, sort='Attribute.id',
                          direction='asc'),
                description='REST attributes/index, ' + name))
        if fx.get('prefix_term'):
            out.append(Case(
                'attributes.index.sort_value.%s' % user, '/attributes/index',
                sorted_by_value, method='POST', user=user,
                body={'value': fx['prefix_term'], 'limit': INDEX_PAGE,
                      'sort': 'Attribute.value', 'direction': 'asc'},
                description='REST attributes/index sorted by value'))
        for shape in objects:
            pick = fx.get('rest_object_' + shape)
            if pick:
                out.append(Case(
                    'objects.view.%s.%s' % (shape, user),
                    '/objects/view/%s' % pick, raw_text, user=user,
                    description='objects/view, %s object' % shape))
        searches = (
            ('small', {'eventid': fx.get('export_small')}),
            ('object_acl', {'eventid': fx.get('export_object_acl')}),
            ('object_only_ip', {'value': fx.get('object_only_ip')}),
        )
        for name, filters in searches:
            if any(v is None for v in filters.values()):
                continue
            out.append(Case(
                'objects.restsearch.%s.%s' % (name, user),
                '/objects/restSearch', raw_text, method='POST', user=user,
                body=filters, description='objects/restSearch, ' + name))
        for name, key in (('attachments', 'rest_attachment_event'),
                          ('small', 'export_small')):
            if fx.get(key):
                out.append(Case(
                    'events.attachments.%s.%s' % (name, user),
                    '/events/viewAttachments/%s' % fx[key], raw_text,
                    user=user, description='events/viewAttachments, ' + name))
        for name in ('small', 'proposals'):
            if fx.get('export_' + name):
                out.append(Case(
                    'events.view.%s.%s' % (name, user),
                    '/events/view/%s' % fx['export_' + name], raw_text,
                    user=user, description='events/view, ' + name))
        for name in ('proposals', 'proposal_delete'):
            if fx.get('export_' + name):
                out.append(Case(
                    'attributes.proposals.%s.%s' % (name, user),
                    '/attributes/restSearch', raw_text, method='POST',
                    user=user, body={'eventid': fx['export_' + name],
                                     'includeProposals': 1,
                                     'returnFormat': 'json'},
                    description='restSearch with includeProposals, ' + name))
        if fx.get('export_proposals'):
            out.append(Case(
                'proposals.index.event.%s' % user,
                '/shadow_attributes/index/%s' % fx['export_proposals'],
                raw_text, user=user, description='proposal index of an event'))
        term = re.match(r'[A-Za-z0-9]+', fx.get('proposal_value') or '')
        if term:
            out.append(Case(
                'proposals.index.searchall.%s' % user,
                '/shadow_attributes/index/searchall:%s' % term.group(0),
                raw_text, user=user, description='proposal index searchall'))
        if fx.get('rest_proposal'):
            out.append(Case(
                'proposals.view.%s' % user,
                '/shadow_attributes/view/%s' % fx['rest_proposal'], raw_text,
                user=user, description='shadow_attributes/view'))
    return out


def cases(config):
    fx = load_fixtures(config)
    trips = (
        ('attributes', attribute_roundtrip),
        ('objects', object_roundtrip),
        ('proposals', proposal_roundtrip),
        ('event_add', event_roundtrip),
    )
    return read_cases(fx) + [
        Case('roundtrip.%s' % name, run=roundtrip(build(fx)),
             description='write round trip: %s' % name)
        for name, build in trips
    ]
