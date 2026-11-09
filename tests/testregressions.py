#!/usr/bin/env python3
"""Regression tests for fixed security findings.

Contract for this file, and the reason it is separate from the testlive_* suites: every
test builds the state it needs under a randomly generated identifier and removes it again
afterwards. Nothing here may reference a fixed organisation name, user email, event uuid or
row id, and no test may depend on what another test or an earlier run left behind. A suite
that needs a freshly seeded database cannot tell a regression from a dirty instance.

Each class covers one fixed finding and states what the defect was, so a failure here says
which protection regressed rather than only which assertion broke.
"""
import os
import sys
import json
import time
import uuid as uuidlib
from urllib.parse import quote
import unittest
import warnings

import requests
import urllib3  # type: ignore

try:
    from pymisp import (PyMISP, MISPEvent, MISPEventReport, MISPObject, MISPUser,
                        MISPOrganisation, MISPSighting)
except ImportError:
    if sys.version_info < (3, 6):
        print('This test suite requires Python 3.6+, breaking.')
        sys.exit(0)
    else:
        raise

urllib3.disable_warnings()

url = "http://" + os.environ["HOST"]
key = os.environ["AUTH"]


def random() -> str:
    return str(uuidlib.uuid4()).split("-")[0]


def check_response(response):
    if isinstance(response, dict) and "errors" in response:
        raise Exception(response["errors"])
    return response


def send(api: PyMISP, request_type: str, url: str, data=None, check_errors: bool = True):
    if data is None:
        data = {}
    response = api._check_response(api._prepare_request(request_type, url, data=data))
    if check_errors:
        check_response(response)
    return response


def least_privileged_role(admin: PyMISP, *required) -> int:
    """The least privileged non-admin, non-sync role holding every named permission.

    Looked up rather than hard-coded, so the suite does not assume a particular role table,
    and so each test runs as the weakest identity that can reach the endpoint at all.
    """
    roles = send(admin, 'GET', 'roles')
    candidates = []
    for entry in roles:
        role = entry['Role'] if 'Role' in entry else entry
        if int(role.get('perm_site_admin', 0)) or int(role.get('perm_sync', 0)):
            continue
        if any(not int(role.get(p, 0) or 0) for p in required):
            continue
        weight = sum(1 for k, v in role.items() if k.startswith('perm_') and int(v or 0))
        candidates.append((weight, int(role['id'])))
    if not candidates:
        raise unittest.SkipTest('no non-admin role with %s on this instance' % ', '.join(required))
    return sorted(candidates)[0][1]


def make_org(admin: PyMISP, label: str):
    org = MISPOrganisation()
    org.name = '%s %s' % (label, random())
    return check_response(admin.add_organisation(org))


def make_user(admin: PyMISP, org_id, role_id):
    user = MISPUser()
    user.email = 'regression-%s@test.local' % random()
    user.org_id = org_id
    user.role_id = role_id
    return check_response(admin.add_user(user))


def make_event(connector: PyMISP, label: str):
    event = MISPEvent()
    event.info = '%s %s' % (label, random())
    event.distribution = 0        # organisation only
    return check_response(connector.add_event(event))


def drop_fixtures(admin: PyMISP, orgs, users):
    """Events first: an organisation that still owns one cannot be deleted."""
    for org in orgs:
        for event in admin.search(controller='events', org=int(org.id),
                                  metadata=True, pythonify=True):
            admin.delete_event(event)
    for user in users:
        admin.delete_user(user)
    for org in orgs:
        admin.delete_organisation(org)


class NestedAliasMassAssignment(unittest.TestCase):
    """A flat, request-derived record that also carries a key equal to the model alias must
    never select the row a save targets.

    Model::set() prefers such a nested dict and drops the outer scalars, so every id strip and
    forced event_id applied to the outer record would be skipped and the save would land on an
    arbitrary row -- including rows in events the caller cannot read.
    """

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        cls.role_id = least_privileged_role(cls.admin, 'perm_add')
        cls.victim_org = make_org(cls.admin, 'regression victim org')
        cls.attacker_org = make_org(cls.admin, 'regression attacker org')
        cls.created_orgs = [cls.victim_org, cls.attacker_org]
        cls.victim_user = make_user(cls.admin, cls.victim_org.id, cls.role_id)
        cls.attacker_user = make_user(cls.admin, cls.attacker_org.id, cls.role_id)
        cls.created_users = [cls.victim_user, cls.attacker_user]
        cls.victim = PyMISP(url, cls.victim_user.authkey)
        cls.victim.global_pythonify = True
        cls.attacker = PyMISP(url, cls.attacker_user.authkey)
        cls.attacker.global_pythonify = True

    @classmethod
    def tearDownClass(cls):
        drop_fixtures(cls.admin, cls.created_orgs, cls.created_users)

    def _victim_attribute(self):
        """An attribute in an organisation-only event of an organisation the attacker is not in."""
        event = make_event(self.victim, 'regression victim event')
        attribute = check_response(self.victim.add_attribute(
            event.id, {'type': 'text', 'category': 'Other',
                       'value': 'victim-value-' + random()}))
        return event, attribute

    def _sightings(self, attribute_id):
        rows = self.admin.search_sightings(context='attribute', context_id=attribute_id)
        normalised = []
        for row in rows:
            if isinstance(row, dict):
                row = row.get('Sighting') or row.get('sighting') or row
            normalised.append(row.to_dict() if hasattr(row, 'to_dict') else row)
        return normalised

    def assertNotStolen(self, attribute, event):
        after = check_response(self.admin.get_attribute(attribute.id))
        self.assertEqual(int(event.id), int(after.event_id),
                         'attribute was re-parented into another event by a nested alias key')
        self.assertEqual(attribute.value, after.value,
                         'attribute value was rewritten by a nested alias key')

    def test_victim_event_is_not_readable(self):
        """Guards the premise of every other test in this class."""
        event, _ = self._victim_attribute()
        response = self.attacker._prepare_request('GET', 'events/view/%s' % event.id)
        self.assertIn(response.status_code, (403, 404),
                      'the attacker can read the victim event, so the other tests prove nothing')

    def test_freetext_import(self):
        victim_event, victim = self._victim_attribute()
        own = make_event(self.attacker, 'regression attacker event')
        payload = [{'type': 'text', 'category': 'Other', 'value': 'outer-decoy',
                    'Attribute': {'id': victim.id, 'event_id': own.id, 'type': 'text',
                                  'category': 'Other', 'value': 'stolen',
                                  'distribution': 5}}]
        send(self.attacker, 'POST', 'events/saveFreeText/%s' % own.id,
             data={'Attribute': {'default_comment': '',
                                 'JsonObject': json.dumps(payload)}},
             check_errors=False)
        self.assertNotStolen(victim, victim_event)

    def test_event_edit(self):
        victim_event, victim = self._victim_attribute()
        own = make_event(self.attacker, 'regression attacker event')
        own_attribute = check_response(self.attacker.add_attribute(
            own.id, {'type': 'text', 'category': 'Other', 'value': 'own-' + random()}))
        future = int(time.time()) + 600
        send(self.attacker, 'POST', 'events/edit/%s' % own.id, data={'Event': {
            'id': own.id, 'timestamp': future,
            'Attribute': [{
                'uuid': own_attribute.uuid, 'type': 'text', 'category': 'Other',
                'value': 'outer-decoy', 'timestamp': future,
                'Attribute': {'id': victim.id, 'uuid': victim.uuid, 'event_id': own.id,
                              'object_id': 0, 'type': 'text', 'category': 'Other',
                              'value': 'stolen', 'distribution': 5,
                              'timestamp': future}}]}}, check_errors=False)
        self.assertNotStolen(victim, victim_event)

    def test_attribute_add_nested_sighting(self):
        victim_event, victim = self._victim_attribute()
        sighting = MISPSighting()
        sighting.from_dict(type='0', source='victim-sighting')
        check_response(self.admin.add_sighting(sighting, victim.id))
        before = self._sightings(victim.id)
        self.assertTrue(before, 'sighting fixture was not created')
        sighting_id = before[0]['id']
        original = before[0]

        own = make_event(self.attacker, 'regression attacker event')
        send(self.attacker, 'POST', 'attributes/add/%s' % own.id, data={'Attribute': {
            'type': 'text', 'category': 'Other', 'value': 'parent-' + random(),
            'distribution': 0,
            'Sighting': [{'type': '0', 'date_sighting': int(time.time()),
                          'Sighting': {'id': sighting_id, 'attribute_id': victim.id,
                                       'event_id': victim_event.id,
                                       'org_id': self.attacker_org.id,
                                       'type': '1', 'source': 'stolen'}}]}},
             check_errors=False)
        # look the row up by id: the attack may add a row, and comparing by position
        # would then silently compare a different sighting
        after = {str(row['id']): row for row in self._sightings(victim.id)}
        self.assertIn(str(sighting_id), after, 'the victim sighting disappeared')
        target = after[str(sighting_id)]
        self.assertEqual(original['source'], target['source'],
                         'sighting was rewritten by a nested alias key')
        self.assertEqual(str(original['org_id']), str(target['org_id']),
                         'sighting was reassigned to another organisation')

    def test_both_request_shapes_still_work(self):
        """The guard must not refuse either supported way of posting a record."""
        flat = send(self.attacker, 'POST', 'events/add',
                    data={'info': 'regression flat form ' + random(), 'distribution': 0})
        self.assertIn('Event', flat)
        wrapped = send(self.attacker, 'POST', 'events/add',
                       data={'Event': {'info': 'regression wrapped form ' + random(),
                                       'distribution': 0}})
        self.assertIn('Event', wrapped)



class DelegationRequestRetargeting(unittest.TestCase):
    """A delegation request must stay bound to the event it was authorised against.

    delegateEvent() authorises only the event named in the URL, and a delegation row also grants
    its organisation read access to the event it names (Event::fetchEvent ORs delegated event ids
    into the read ACL). A row whose event_id or primary key can be chosen by the requester is
    therefore a read grant over any event on the instance, and accepting it transfers ownership
    and deletes the original.
    """

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        if not cls.admin.get_server_setting('MISP.delegation')['value']:
            raise unittest.SkipTest('MISP.delegation is disabled on this instance')
        cls.role_id = least_privileged_role(cls.admin, 'perm_add', 'perm_delegate')
        cls.victim_org = make_org(cls.admin, 'delegation victim org')
        cls.attacker_org = make_org(cls.admin, 'delegation attacker org')
        cls.created_orgs = [cls.victim_org, cls.attacker_org]
        cls.victim_user = make_user(cls.admin, cls.victim_org.id, cls.role_id)
        cls.attacker_user = make_user(cls.admin, cls.attacker_org.id, cls.role_id)
        cls.created_users = [cls.victim_user, cls.attacker_user]
        cls.victim = PyMISP(url, cls.victim_user.authkey)
        cls.victim.global_pythonify = True
        cls.attacker = PyMISP(url, cls.attacker_user.authkey)
        cls.attacker.global_pythonify = True

    @classmethod
    def tearDownClass(cls):
        drop_fixtures(cls.admin, cls.created_orgs, cls.created_users)

    def test_delegation_cannot_be_retargeted(self):
        victim_event = make_event(self.victim, 'delegation victim event')

        probe = self.attacker._prepare_request('GET', 'events/view/%s' % victim_event.id)
        self.assertIn(probe.status_code, (403, 404),
                      'the attacker can already read the victim event, so this proves nothing')

        own = make_event(self.attacker, 'delegation attacker event')
        route = make_event(self.attacker, 'delegation route event')
        created = send(self.attacker, 'POST', 'eventDelegations/delegateEvent/%s' % own.id,
                       data={'EventDelegation': {'org_id': self.attacker_org.id,
                                                 'distribution': 0,
                                                 'message': 'legitimate delegation'}})
        # the create returns the stored row; a missing one means the feature itself broke,
        # which must fail loudly rather than let the assertion below pass vacuously
        self.assertIn('EventDelegation', created,
                      'the legitimate delegation was not created, so the feature is broken')
        delegation_id = created['EventDelegation']['id']
        self.assertEqual(str(own.id), str(created['EventDelegation']['event_id']),
                         'the delegation was not bound to the event it was requested for')

        send(self.attacker, 'POST', 'eventDelegations/delegateEvent/%s' % route.id, data={
            'EventDelegation': {
                'org_id': self.attacker_org.id, 'distribution': 0, 'message': 'outer-decoy',
                'EventDelegation': {'id': delegation_id, 'event_id': victim_event.id,
                                    'org_id': self.attacker_org.id,
                                    'requester_org_id': self.attacker_org.id,
                                    'distribution': 0, 'sharing_group_id': 0,
                                    'message': 'retargeted'}}}, check_errors=False)

        after = self.attacker._prepare_request('GET', 'events/view/%s' % victim_event.id)
        self.assertIn(after.status_code, (403, 404),
                      'a delegation request was retargeted at an event the requester could '
                      'not read, granting their organisation access to it')



class DecayingModelImportOwnership(unittest.TestCase):
    """An imported decaying model belongs to the importer and is never a default model.

    import() strips the id and pins org_id/default on the submitted array and then saves it flat,
    so a nested DecayingModel key supplied its own primary key, organisation and default flag --
    letting any perm_decaying user overwrite another organisation's model in place.
    """

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        cls.role_id = least_privileged_role(cls.admin, 'perm_decaying')
        cls.attacker_org = make_org(cls.admin, 'decaying attacker org')
        cls.created_orgs = [cls.attacker_org]
        cls.attacker_user = make_user(cls.admin, cls.attacker_org.id, cls.role_id)
        cls.created_users = [cls.attacker_user]
        cls.attacker = PyMISP(url, cls.attacker_user.authkey)
        cls.attacker.global_pythonify = True
        cls.created_models = []

    @classmethod
    def tearDownClass(cls):
        for model_id in cls.created_models:
            send(cls.admin, 'POST', 'decayingModel/delete/%s' % model_id, check_errors=False)
        drop_fixtures(cls.admin, cls.created_orgs, cls.created_users)

    def _models(self):
        rows = send(self.admin, 'GET', 'decayingModel/index', check_errors=False)
        out = {}
        for row in (rows if isinstance(rows, list) else []):
            entry = row.get('DecayingModel', row)
            out[str(entry['id'])] = entry
        return out

    def _import(self, payload):
        """import() reads a multipart form field, not a JSON body."""
        return requests.post(
            url + '/decayingModel/import',
            headers={'Authorization': self.attacker.key, 'Accept': 'application/json'},
            files={'data[DecayingModel][json]': (None, json.dumps(payload)),
                   'data[DecayingModel][submittedjson]': ('', b'')},
            allow_redirects=False)

    def test_import_cannot_overwrite_another_orgs_model(self):
        victim = self._models()
        self.assertTrue(victim, 'no decaying model exists to use as a victim')
        target_id, target = sorted(victim.items())[0]
        before = dict(target)

        self._import({
            'name': 'outer-decoy', 'formula': 'polynomial', 'version': '1',
            'parameters': {'threshold': 30, 'lifetime': 30, 'decay_speed': 0.5},
            'DecayingModel': {
                'id': int(target_id), 'name': 'retargeted', 'org_id': int(self.attacker_org.id),
                'default': 1, 'enabled': 1, 'formula': 'polynomial',
                'parameters': {'threshold': 30, 'lifetime': 30, 'decay_speed': 0.5}},
        })

        after = self._models()
        self.assertIn(target_id, after, 'the victim decaying model disappeared')
        self.assertEqual(before['name'], after[target_id]['name'],
                         'an existing decaying model was overwritten by a nested alias key')
        self.assertEqual(str(before['org_id']), str(after[target_id]['org_id']),
                         'an existing decaying model was reassigned to another organisation')
        for model_id, entry in after.items():
            if model_id not in victim:
                self.created_models.append(model_id)
                self.assertEqual(str(self.attacker_org.id), str(entry['org_id']),
                                 'an imported model was created for another organisation')
                self.assertIn(str(entry.get('default', 0)), ('0', 'False', 'None'),
                              'an imported model was flagged as a default model')


class FlattenedObjectAcl(unittest.TestCase):
    """Flattening an event applies the object distribution ACL to the object's attributes,
    and nothing else the dropped Object contain carried.

    fetchEvent() removes the Object contain when flattening, so an object-only attribute would
    otherwise reach everyone who can open the event. Re-applying the whole contain instead of
    its ACL alone is the other half of it: the soft-delete conditions the contain carries say
    which objects are listed, not which of their attributes the owner may see.
    """

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        cls.role_id = least_privileged_role(cls.admin, 'perm_add')
        cls.owner_org = make_org(cls.admin, 'regression flatten owner org')
        cls.outsider_org = make_org(cls.admin, 'regression flatten outsider org')
        cls.created_orgs = [cls.owner_org, cls.outsider_org]
        cls.owner_user = make_user(cls.admin, cls.owner_org.id, cls.role_id)
        cls.outsider_user = make_user(cls.admin, cls.outsider_org.id, cls.role_id)
        cls.created_users = [cls.owner_user, cls.outsider_user]
        cls.owner = PyMISP(url, cls.owner_user.authkey)
        cls.owner.global_pythonify = True
        cls.outsider = PyMISP(url, cls.outsider_user.authkey)
        cls.outsider.global_pythonify = True
        cls._seed()

    @classmethod
    def tearDownClass(cls):
        drop_fixtures(cls.admin, cls.created_orgs, cls.created_users)

    @classmethod
    def _seed(cls):
        """A community event of the owner org holding a shared and an organisation-only
        object, with one attribute of the shared object soft-deleted.

        Attributes are tracked by id: a soft delete may sanitise the value away.
        """
        event = MISPEvent()
        event.info = 'regression flattened object acl %s' % random()
        event.distribution = 1        # community, so the outsider can open it
        cls.event = check_response(cls.owner.add_event(event))

        shared = MISPObject('file')
        shared.distribution = 5       # inherit the event
        shared.add_attribute('filename', value='kept-%s.txt' % random(), distribution=5)
        shared.add_attribute('filename', value='gone-%s.txt' % random(), distribution=5)
        shared = check_response(cls.owner.add_object(cls.event.id, shared))

        private = MISPObject('file')
        private.distribution = 0      # organisation only
        private.add_attribute('filename', value='private-%s.txt' % random(), distribution=5)
        private = check_response(cls.owner.add_object(cls.event.id, private))

        cls.kept_id, cls.deleted_id = (int(a.id) for a in shared.attributes)
        cls.private_id = int(private.attributes[0].id)
        check_response(cls.owner.delete_attribute(cls.deleted_id))

    def _flattened(self, connector, **filters):
        payload = {'eventid': int(self.event.id), 'flatten': 1}
        payload.update(filters)
        response = send(connector, 'POST', 'events/restSearch', payload)
        if isinstance(response, dict):
            response = response.get('response', [])
        ids = []
        for entry in response:
            event = entry['Event'] if 'Event' in entry else entry
            for attribute in event.get('Attribute', []):
                ids.append(int(attribute['id']))
        return ids

    def test_object_distribution_applies_to_flattened_attributes(self):
        seen = self._flattened(self.outsider)
        self.assertIn(self.kept_id, seen,
                      'the outsider cannot read the event at all, so the test proves nothing')
        self.assertNotIn(self.private_id, seen,
                         "an organisation-only object's attribute leaked through flatten")

    def test_owner_keeps_deleted_attributes_of_a_live_object(self):
        seen = self._flattened(self.owner, deleted='only')
        self.assertIn(self.deleted_id, seen,
                      'the owner lost a soft-deleted attribute because its object is not deleted')
        self.assertNotIn(self.kept_id, seen, 'deleted:only returned a live attribute')

    def test_outsider_still_cannot_read_deleted_attributes(self):
        seen = self._flattened(self.outsider, deleted=[0, 1])
        self.assertIn(self.kept_id, seen,
                      'the outsider cannot read the event at all, so the test proves nothing')
        self.assertNotIn(self.deleted_id, seen,
                         "another organisation's soft-deleted attribute was returned")
        self.assertNotIn(self.private_id, seen,
                         "an organisation-only object's attribute leaked through flatten")


class ObjectSearchAcl(unittest.TestCase):
    """The event view's object search matches an object only on the attributes it shows.

    fetchPaginatedObjects() found the objects holding a matching attribute through a subquery
    that carried neither the attribute ACL nor the deleted scope, so whether an object came
    back told the user what its hidden or soft-deleted attributes held. Only the themed event
    view serves the endpoint (MISP.enable_themes), so the class skips where it is off.
    """

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        if not cls.admin.get_server_setting('MISP.enable_themes')['value']:
            raise unittest.SkipTest('events/viewObjects needs MISP.enable_themes')
        cls.role_id = least_privileged_role(cls.admin, 'perm_add')
        cls.owner_org = make_org(cls.admin, 'regression object search owner org')
        cls.outsider_org = make_org(cls.admin, 'regression object search outsider org')
        cls.created_orgs = [cls.owner_org, cls.outsider_org]
        cls.owner_user = make_user(cls.admin, cls.owner_org.id, cls.role_id)
        cls.outsider_user = make_user(cls.admin, cls.outsider_org.id, cls.role_id)
        cls.created_users = [cls.owner_user, cls.outsider_user]
        cls.owner = PyMISP(url, cls.owner_user.authkey)
        cls.owner.global_pythonify = True
        cls.outsider = PyMISP(url, cls.outsider_user.authkey)
        cls.outsider.global_pythonify = True
        cls._seed()

    @classmethod
    def tearDownClass(cls):
        drop_fixtures(cls.admin, cls.created_orgs, cls.created_users)

    @classmethod
    def _seed(cls):
        """A community event of the owner org holding one shared object, with a shared, an
        organisation-only and a soft-deleted attribute."""
        event = MISPEvent()
        event.info = 'regression object search acl %s' % random()
        event.distribution = 1        # community, so the outsider can open it
        cls.event = check_response(cls.owner.add_event(event))

        cls.values = {name: '%s-%s.txt' % (name, random()) for name in ('kept', 'hidden', 'gone')}
        shared = MISPObject('file')
        shared.distribution = 5       # inherit the event
        shared.add_attribute('filename', value=cls.values['kept'], distribution=5)
        shared.add_attribute('filename', value=cls.values['hidden'], distribution=0)
        shared.add_attribute('filename', value=cls.values['gone'], distribution=5)
        shared = check_response(cls.owner.add_object(cls.event.id, shared))
        cls.object_id = int(shared.id)
        gone = next(a for a in shared.attributes if a.value == cls.values['gone'])
        check_response(cls.owner.delete_attribute(int(gone.id)))

    def _found(self, connector, name):
        response = connector._prepare_request(
            'POST', 'events/viewObjects/%d' % int(self.event.id), data={'searchFor': self.values[name]})
        self.assertEqual(200, response.status_code, response.text[:300])
        return [int(o['id']) for o in response.json().get('Object', [])]

    def test_outsider_matches_only_the_attributes_it_sees(self):
        self.assertIn(self.object_id, self._found(self.outsider, 'kept'),
                      'the outsider cannot search the object at all, so the test proves nothing')
        self.assertNotIn(self.object_id, self._found(self.outsider, 'hidden'),
                         "an organisation-only attribute's value matched the outsider's search")
        self.assertNotIn(self.object_id, self._found(self.outsider, 'gone'),
                         "a soft-deleted attribute's value matched the search")

    def test_owner_still_finds_its_own_attribute(self):
        self.assertIn(self.object_id, self._found(self.owner, 'hidden'),
                      'the owner lost the search on its organisation-only attribute')


class SoftDeletedEventTabsAcl(unittest.TestCase):
    """The event view's objects and reports tabs show soft-deleted rows only to the event owner.

    With the Deleted filter on (deleted 1 or 2), fetchPaginatedObjects() and
    fetchPaginatedReports() returned soft-deleted objects, object attributes and reports to
    anyone who could see the event, where fetchEvent() keeps them to the owner org and sync
    users. Only the themed event view serves the endpoints (MISP.enable_themes), so the class
    skips where it is off.
    """

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        if not cls.admin.get_server_setting('MISP.enable_themes')['value']:
            raise unittest.SkipTest('the event view tabs need MISP.enable_themes')
        cls.role_id = least_privileged_role(cls.admin, 'perm_add')
        cls.owner_org = make_org(cls.admin, 'regression deleted tabs owner org')
        cls.outsider_org = make_org(cls.admin, 'regression deleted tabs outsider org')
        cls.created_orgs = [cls.owner_org, cls.outsider_org]
        cls.owner_user = make_user(cls.admin, cls.owner_org.id, cls.role_id)
        cls.outsider_user = make_user(cls.admin, cls.outsider_org.id, cls.role_id)
        cls.created_users = [cls.owner_user, cls.outsider_user]
        cls.owner = PyMISP(url, cls.owner_user.authkey)
        cls.owner.global_pythonify = True
        cls.outsider = PyMISP(url, cls.outsider_user.authkey)
        cls.outsider.global_pythonify = True
        cls._seed()

    @classmethod
    def tearDownClass(cls):
        drop_fixtures(cls.admin, cls.created_orgs, cls.created_users)

    @classmethod
    def _seed(cls):
        """A community event of the owner org with a live object holding a soft-deleted
        attribute, a soft-deleted object, and a live and a soft-deleted report."""
        event = MISPEvent()
        event.info = 'regression deleted tabs %s' % random()
        event.distribution = 1        # community, so the outsider can open it
        cls.event = check_response(cls.owner.add_event(event))

        live = MISPObject('file')
        live.distribution = 5         # inherit the event
        live.add_attribute('filename', value='kept-%s.txt' % random(), distribution=5)
        live.add_attribute('filename', value='gone-%s.txt' % random(), distribution=5)
        live = check_response(cls.owner.add_object(cls.event.id, live))
        cls.live_id = int(live.id)
        cls.kept_id, cls.gone_id = (int(a.id) for a in live.attributes)
        check_response(cls.owner.delete_attribute(cls.gone_id))

        dropped = MISPObject('file')
        dropped.distribution = 5
        dropped.add_attribute('filename', value='dropped-%s.txt' % random(), distribution=5)
        dropped = check_response(cls.owner.add_object(cls.event.id, dropped))
        cls.dropped_id = int(dropped.id)
        check_response(cls.owner.delete_object(cls.dropped_id))

        cls.report_ids = {}
        for name in ('kept', 'gone'):
            report = MISPEventReport()
            report.name = '%s report %s' % (name, random())
            report.content = name
            report.distribution = 5
            report = check_response(cls.owner.add_event_report(cls.event.id, report))
            cls.report_ids[name] = int(report.id)
        check_response(cls.owner.delete_event_report(cls.report_ids['gone']))

    def _tab(self, connector, tab, deleted):
        response = connector._prepare_request(
            'POST', 'events/%s/%d' % (tab, int(self.event.id)), data={'deleted': deleted})
        self.assertEqual(200, response.status_code, response.text[:300])
        return response.json()

    def _objects(self, connector, deleted):
        """Object id -> the ids of the attributes it shows."""
        return {int(o['id']): [int(a['id']) for a in o.get('Attribute', [])]
                for o in self._tab(connector, 'viewObjects', deleted).get('Object', [])}

    def _reports(self, connector, deleted):
        return [int(r['EventReport']['id'])
                for r in self._tab(connector, 'viewEventReports', deleted).get('EventReport', [])]

    def test_outsider_gets_no_soft_deleted_object_data(self):
        objects = self._objects(self.outsider, 1)
        self.assertIn(self.live_id, objects,
                      'the outsider cannot read the objects at all, so the test proves nothing')
        self.assertIn(self.kept_id, objects[self.live_id])
        self.assertNotIn(self.gone_id, objects[self.live_id],
                         "another organisation's soft-deleted attribute was shown")
        self.assertNotIn(self.dropped_id, objects,
                         "another organisation's soft-deleted object was shown")
        self.assertEqual({}, self._objects(self.outsider, 2),
                         'the Deleted filter listed objects to the outsider')

    def test_outsider_gets_no_soft_deleted_report(self):
        self.assertEqual([self.report_ids['kept']], self._reports(self.outsider, 1),
                         "another organisation's soft-deleted report was shown")
        self.assertEqual([], self._reports(self.outsider, 2),
                         "another organisation's soft-deleted report was shown")

    def test_owner_keeps_its_soft_deleted_rows(self):
        objects = self._objects(self.owner, 2)
        self.assertEqual({self.live_id, self.dropped_id}, set(objects))
        self.assertIn(self.gone_id, objects[self.live_id])
        self.assertEqual([self.report_ids['gone']], self._reports(self.owner, 2))


class SoftDeletedReportsAcl(unittest.TestCase):
    """event_reports/view and event_reports/index serve a soft-deleted report only to the event owner.

    Every report read goes through EventReport::buildACLConditions(), which checked the
    distribution alone, so any organisation that could see the event read a retracted report's
    content, where fetchEvent() keeps soft-deleted rows to the owner org and sync users.
    """

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        cls.role_id = least_privileged_role(cls.admin, 'perm_add')
        cls.owner_org = make_org(cls.admin, 'regression deleted reports owner org')
        cls.outsider_org = make_org(cls.admin, 'regression deleted reports outsider org')
        cls.created_orgs = [cls.owner_org, cls.outsider_org]
        cls.owner_user = make_user(cls.admin, cls.owner_org.id, cls.role_id)
        cls.outsider_user = make_user(cls.admin, cls.outsider_org.id, cls.role_id)
        cls.created_users = [cls.owner_user, cls.outsider_user]
        cls.owner = PyMISP(url, cls.owner_user.authkey)
        cls.owner.global_pythonify = True
        cls.outsider = PyMISP(url, cls.outsider_user.authkey)
        cls.outsider.global_pythonify = True

        event = MISPEvent()
        event.info = 'regression deleted reports %s' % random()
        event.distribution = 1        # community, so the outsider can open it
        cls.event = check_response(cls.owner.add_event(event))
        cls.report_ids = {}
        for name in ('kept', 'gone'):
            report = MISPEventReport()
            report.name = '%s report %s' % (name, random())
            report.content = name
            report.distribution = 5
            report = check_response(cls.owner.add_event_report(cls.event.id, report))
            cls.report_ids[name] = int(report.id)
        check_response(cls.owner.delete_event_report(cls.report_ids['gone']))

    @classmethod
    def tearDownClass(cls):
        drop_fixtures(cls.admin, cls.created_orgs, cls.created_users)

    def _view(self, connector, name):
        return connector._prepare_request('GET', 'event_reports/view/%d' % self.report_ids[name])

    def _index(self, connector, context):
        response = connector._prepare_request(
            'GET', 'event_reports/index/event_id:%d/context:%s' % (int(self.event.id), context))
        self.assertEqual(200, response.status_code, response.text[:300])
        return sorted(int(r['EventReport']['id']) for r in response.json())

    def test_outsider_cannot_read_a_soft_deleted_report(self):
        self.assertEqual(200, self._view(self.outsider, 'kept').status_code,
                         'the outsider cannot read the reports at all, so the test proves nothing')
        self.assertEqual(404, self._view(self.outsider, 'gone').status_code,
                         "another organisation's soft-deleted report was served")
        self.assertEqual([], self._index(self.outsider, 'deleted'),
                         "another organisation's soft-deleted report was listed")
        self.assertEqual([self.report_ids['kept']], self._index(self.outsider, 'all'))

    def test_owner_keeps_its_soft_deleted_report(self):
        self.assertEqual(200, self._view(self.owner, 'gone').status_code)
        self.assertEqual([self.report_ids['gone']], self._index(self.owner, 'deleted'))
        self.assertEqual(sorted(self.report_ids.values()), self._index(self.owner, 'all'))


class EventSearchAttributeAcl(unittest.TestCase):
    """Event and object searches select on the attributes the user can see.

    events/restSearch and objects/restSearch selected an event (or object) through attribute
    and object subqueries that carried neither the attribute ACL nor the deleted scope, so
    whether it came back told a user who could see the event what its organisation-only,
    sharing-group, soft-deleted or organisation-only-object elements held: value (also as a
    prefix, one character at a time), searchall, tags and type, and value with NOT in reverse.
    The event index's tag, galaxy and quick filters did the same with the tags of hidden
    attributes.
    """

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        cls.role_id = least_privileged_role(cls.admin, 'perm_add')
        cls.owner_org = make_org(cls.admin, 'regression event search owner org')
        cls.outsider_org = make_org(cls.admin, 'regression event search outsider org')
        cls.created_orgs = [cls.owner_org, cls.outsider_org]
        cls.owner_user = make_user(cls.admin, cls.owner_org.id, cls.role_id)
        cls.outsider_user = make_user(cls.admin, cls.outsider_org.id, cls.role_id)
        cls.created_users = [cls.owner_user, cls.outsider_user]
        cls.owner = PyMISP(url, cls.owner_user.authkey)
        cls.owner.global_pythonify = True
        cls.outsider = PyMISP(url, cls.outsider_user.authkey)
        cls.outsider.global_pythonify = True
        cls.tag_id = cls.cluster_tag_id = cls.galaxy = None
        cls._seed()

    @classmethod
    def tearDownClass(cls):
        drop_fixtures(cls.admin, cls.created_orgs, cls.created_users)
        if cls.tag_id:
            send(cls.admin, 'POST', 'tags/delete/%d' % cls.tag_id, check_errors=False)

    @classmethod
    def _seed(cls):
        """A community event of the owner org holding a shared attribute, an organisation-only
        tagged one, a soft-deleted one, a shared object with a shared and an
        organisation-only attribute, and an organisation-only object holding a shared one."""
        event = MISPEvent()
        event.info = 'regression event search acl %s' % random()
        event.distribution = 1        # community, so the outsider can open it
        cls.event = check_response(cls.owner.add_event(event))
        cls.event_id = int(cls.event.id)

        cls.values = {name: '%s-%s' % (name, random())
                      for name in ('kept', 'hidden', 'gone', 'objkept', 'objhidden', 'inobj')}
        cls.values['inobj'] += '.example.com'
        cls.tag = 'regression-hidden-%s' % random()
        tag = send(cls.admin, 'POST', 'tags/add', data={'name': cls.tag})
        cls.tag_id = int(tag['Tag']['id'] if 'Tag' in tag else tag['id'])

        def attribute(name, distribution):
            return check_response(cls.owner.add_attribute(
                cls.event.id, {'type': 'text', 'value': cls.values[name],
                               'distribution': distribution}))

        attribute('kept', 5)
        hidden = attribute('hidden', 0)
        send(cls.admin, 'POST', 'tags/attachTagToObject',
             data={'uuid': hidden.uuid, 'tag': cls.tag})
        cls._attach_cluster_tag(hidden)
        gone = attribute('gone', 5)
        check_response(cls.owner.delete_attribute(int(gone.id)))
        # Security.sanitise_attribute_on_delete overwrites the value: nothing is left to match.
        full = cls.admin.get_event(cls.event_id, deleted=True, pythonify=True)
        cls.gone_sanitised = any(a.uuid == gone.uuid and a.value != cls.values['gone']
                                 for a in full.attributes)

        shared = MISPObject('file')
        shared.distribution = 5
        shared.add_attribute('filename', value=cls.values['objkept'], distribution=5)
        shared.add_attribute('filename', value=cls.values['objhidden'], distribution=0)
        shared = check_response(cls.owner.add_object(cls.event.id, shared))
        cls.object_id = int(shared.id)

        private = MISPObject('domain-ip')
        private.distribution = 0
        private.add_attribute('domain', value=cls.values['inobj'], distribution=5)
        check_response(cls.owner.add_object(cls.event.id, private))

    @classmethod
    def _attach_cluster_tag(cls, attribute):
        for galaxy in send(cls.admin, 'GET', 'galaxies/index'):
            galaxy = galaxy['Galaxy']
            clusters = send(cls.admin, 'GET', 'galaxy_clusters/index/%s' % galaxy['id'])
            if clusters:
                break
        else:
            return
        cluster_tag = clusters[0]['GalaxyCluster']['tag_name']
        known = {t['name']: int(t['id']) for t in send(cls.admin, 'GET', 'tags/index')['Tag']}
        send(cls.admin, 'POST', 'tags/attachTagToObject',
             data={'uuid': attribute.uuid, 'tag': cluster_tag})
        if cluster_tag not in known:
            cls.cluster_tag_id = int(next(t['id'] for t in send(cls.admin, 'GET', 'tags/index')['Tag']
                                          if t['name'] == cluster_tag))
        cls.galaxy = galaxy['name']

    def _events(self, connector, **filters):
        data = dict(filters, eventid=self.event_id, returnFormat='json', metadata=True)
        response = connector._prepare_request('POST', 'events/restSearch', data=data)
        self.assertEqual(200, response.status_code, response.text[:300])
        return [int(e['Event']['id']) for e in response.json()['response']]

    def _objects(self, connector, name):
        data = {'eventid': self.event_id, 'value': self.values[name], 'returnFormat': 'json'}
        response = connector._prepare_request('POST', 'objects/restSearch', data=data)
        self.assertEqual(200, response.status_code, response.text[:300])
        return [int(o['Object']['id']) for o in response.json()['response']]

    def test_outsider_matches_only_the_elements_it_sees(self):
        v = self.values
        self.assertIn(self.event_id, self._events(self.outsider, value=v['kept']),
                      'the outsider cannot search the event at all, so the test proves nothing')
        probes = {
            "an organisation-only attribute's value": {'value': v['hidden']},
            "the prefix of an organisation-only attribute's value": {'value': v['hidden'][:8] + '%'},
            "an organisation-only attribute's value through searchall": {'searchall': v['hidden']},
            "a tag carried only by an organisation-only attribute": {'tags': [self.tag]},
            "the attribute value of an organisation-only object": {'value': v['inobj']},
        }
        for what, filters in probes.items():
            self.assertNotIn(self.event_id, self._events(self.outsider, **filters),
                             'the outsider selected the event through %s' % what)
        self.assertIn(self.event_id, self._events(self.outsider, value={'NOT': [v['hidden']]}),
                      "an organisation-only attribute's value excluded the event through NOT")

    def test_outsider_object_search_matches_only_visible_attributes(self):
        self.assertIn(self.object_id, self._objects(self.outsider, 'objkept'),
                      'the outsider cannot search the object at all, so the test proves nothing')
        self.assertNotIn(self.object_id, self._objects(self.outsider, 'objhidden'),
                         "an organisation-only attribute's value selected the object")

    def _indexed(self, connector, galaxy=None, **filters):
        path = 'events/index' + ('/searchgalaxy:' + quote(galaxy, safe='') if galaxy else '')
        data = dict(filters, eventid=self.event_id)
        response = connector._prepare_request('POST', path, data=data)
        self.assertEqual(200, response.status_code, response.text[:300])
        return [int(e['id']) for e in response.json()]

    def test_outsider_event_index_matches_only_visible_tags(self):
        if not self.galaxy:
            self.skipTest('no galaxy cluster is loaded')
        self.assertIn(self.event_id, self._indexed(self.outsider),
                      'the outsider cannot list the event at all, so the test proves nothing')
        probes = {
            'the tag filter': {'tags': [self.tag]},
            'the quick filter': {'all': self.tag},
            'the galaxy filter': {'galaxy': self.galaxy},
        }
        for what, filters in probes.items():
            self.assertNotIn(self.event_id, self._indexed(self.outsider, **filters),
                             "the outsider selected the event through an organisation-only attribute's tag in %s" % what)
        self.assertIn(self.event_id, self._indexed(self.outsider, galaxy='!' + self.galaxy),
                      "an organisation-only attribute's tag excluded the event through the galaxy block")
        self.assertIn(self.event_id, self._indexed(self.owner, tags=[self.tag]))

    def test_owner_and_site_admin_keep_their_matches(self):
        v = self.values
        self.assertIn(self.event_id, self._events(self.owner, value=v['hidden']))
        self.assertIn(self.event_id, self._events(self.owner, tags=[self.tag]))
        self.assertIn(self.event_id, self._events(self.admin, value=v['hidden']))

    def test_soft_deleted_value_matches_only_for_the_site_admin(self):
        if self.gone_sanitised:
            self.skipTest('Security.sanitise_attribute_on_delete is on: the soft-deleted value is gone')
        self.assertNotIn(self.event_id, self._events(self.outsider, value=self.values['gone']),
                         "the outsider selected the event through a soft-deleted attribute's value")
        self.assertIn(self.event_id, self._events(self.admin, value=self.values['gone']))


class EventCorrelationsAcl(unittest.TestCase):
    """correlations/eventCorrelations vets the event and both sides of every correlation.

    The action never checked that the caller can see the event it was asked about, and the
    correlation engines only filtered the related side of each row. So any user got the
    correlations of an organisation-only event of another organisation, and for an event they
    could open, those of the attributes hidden from them (organisation-only, in a sharing group
    they are not in, or inside an organisation-only object): keyed by the hidden attribute's id,
    with its value. The default
    engine's related-event list (events/view) named events related only through such
    attributes too.
    """

    sharing_groups = []

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        cls.role_id = least_privileged_role(cls.admin, 'perm_add')
        cls.owner_org = make_org(cls.admin, 'regression event correlations owner org')
        cls.outsider_org = make_org(cls.admin, 'regression event correlations outsider org')
        cls.created_orgs = [cls.owner_org, cls.outsider_org]
        cls.owner_user = make_user(cls.admin, cls.owner_org.id, cls.role_id)
        cls.outsider_user = make_user(cls.admin, cls.outsider_org.id, cls.role_id)
        cls.created_users = [cls.owner_user, cls.outsider_user]
        cls.owner = PyMISP(url, cls.owner_user.authkey)
        cls.owner.global_pythonify = True
        cls.outsider = PyMISP(url, cls.outsider_user.authkey)
        cls.outsider.global_pythonify = True
        cls._seed()

    @classmethod
    def tearDownClass(cls):
        uuids = [e.uuid for e in (getattr(cls, n, None) for n in ('H', 'P', 'R', 'R2')) if e]
        drop_fixtures(cls.admin, cls.created_orgs, cls.created_users)
        for sg_id in cls.sharing_groups:
            send(cls.admin, 'POST', 'sharingGroups/delete/%d' % sg_id, check_errors=False)
        for row in send(cls.admin, 'GET', 'eventBlocklists/index', check_errors=False):
            row = row.get('EventBlocklist', row)
            if row.get('event_uuid') in uuids:
                send(cls.admin, 'POST', 'eventBlocklists/delete/%s' % row['id'], check_errors=False)

    @classmethod
    def _seed(cls):
        """H (org only) holds V1. P (community) holds V2 (shared), V3 (organisation-only) and an
        organisation-only object with V4, V5 in a sharing group the outsider is in and V6 in one it
        is not. R (community) and R2 (organisation-only) belong to the outsider; R holds all
        values and R2 only V3, so the owner sees R but not R2."""
        token = random()
        cls.sharing_groups = []
        cls.values = {'V1': '198.51.100.%d' % (1 + int(token[:2], 16) % 250)}
        cls.values.update({n: '%s-%s.example.com' % (n.lower(), token) for n in ('V2', 'V3', 'V4', 'V5', 'V6')})
        groups = {}
        for name, orgs in (('in', cls.created_orgs), ('out', cls.created_orgs[:1])):
            group = send(cls.admin, 'POST', 'sharingGroups/add', data={
                'name': 'regression event correlations %s %s' % (name, token), 'releasability': 'x',
                'roaming': False,
                'SharingGroupOrg': [{'Organisation': {'uuid': o.uuid, 'name': o.name}, 'extend': False}
                                    for o in orgs]})
            groups[name] = int(group['SharingGroup']['id'])
            cls.sharing_groups.append(groups[name])

        def event(connector, name, distribution, attributes):
            ev = MISPEvent()
            ev.info = 'regression event correlations %s %s' % (name, token)
            ev.distribution = distribution
            for typ, value, dist, *group in attributes:
                ev.add_attribute(typ, value, distribution=dist, category='Network activity',
                                 sharing_group_id=group[0] if group else 0)
            return check_response(connector.add_event(ev))

        v = cls.values
        cls.H = event(cls.owner, 'H', 0, [('ip-dst', v['V1'], 5)])
        cls.P = event(cls.owner, 'P', 1, [('domain', v['V2'], 5), ('domain', v['V3'], 0),
                                              ('domain', v['V5'], 4, groups['in']),
                                              ('domain', v['V6'], 4, groups['out'])])
        obj = MISPObject('domain-ip')
        obj.distribution = 0
        obj.add_attribute('domain', value=v['V4'], distribution=5)
        check_response(cls.owner.add_object(cls.P.id, obj))
        cls.R = event(cls.outsider, 'R', 1, [('ip-dst', v['V1'], 5), ('domain', v['V2'], 5),
                                             ('domain', v['V3'], 5), ('domain', v['V4'], 5),
                                             ('domain', v['V5'], 5), ('domain', v['V6'], 5)])
        cls.R2 = event(cls.outsider, 'R2', 0, [('domain', v['V3'], 5)])
        cls.attr_ids = {}
        for ev in (cls.H, cls.P):
            full = cls.admin.get_event(ev.id, pythonify=True)
            for a in full.attributes + [a for o in full.objects for a in o.attributes]:
                cls.attr_ids[a.value] = int(a.id)

    def _correlations(self, connector, event_id, query=''):
        response = connector._prepare_request(
            'GET', 'correlations/eventCorrelations/%s%s' % (event_id, query))
        return response.status_code, response.json()

    def _keys(self, connector, event_id, query=''):
        status, body = self._correlations(connector, event_id, query)
        self.assertEqual(200, status, body)
        if isinstance(body, dict) and 'correlations' in body:
            body = body['correlations']
        return {int(k) for k in body} if body else set()

    def test_outsider_gets_nothing_for_an_invisible_event(self):
        v, ids = self.values, self.attr_ids
        self.assertIn(ids[v['V1']], self._keys(self.admin, self.H.id),
                      'H does not correlate, so the test proves nothing')
        gone = self._correlations(self.outsider, 2147483646)
        self.assertEqual(404, gone[0], gone[1])
        for ref in (self.H.id, self.H.uuid):
            probe = self._correlations(self.outsider, ref, '?include_attributes=1')
            self.assertEqual(404, probe[0], 'the outsider got the correlations of an invisible event')
            for field in ('name', 'message'):
                self.assertEqual(gone[1][field], probe[1][field],
                                 'an invisible event is told apart from a missing one')

    def test_outsider_gets_only_the_correlations_of_visible_attributes(self):
        v, ids = self.values, self.attr_ids
        hidden = {ids[v[n]] for n in ('V3', 'V4', 'V6')}
        for query in ('', '?include_attributes=1', '?include_warninglist_hits=1'):
            keys = self._keys(self.outsider, self.P.id, query)
            self.assertLessEqual({ids[v['V2']], ids[v['V5']]}, keys,
                                 'the outsider lost the correlations of the attributes it can see')
            self.assertFalse(keys & hidden,
                             'correlations of attributes hidden from the outsider came back (%s)' % query)

    def test_outsider_related_events_skip_hidden_attributes(self):
        response = self.outsider._prepare_request('GET', 'events/view/%s' % self.P.id)
        related = {int(e['Event']['id']) for e in response.json()['Event'].get('RelatedEvent', [])}
        self.assertIn(int(self.R.id), related)
        self.assertNotIn(int(self.R2.id), related,
                         'an event related only through an organisation-only attribute is listed')

    def test_owner_and_site_admin_keep_their_correlations(self):
        v, ids = self.values, self.attr_ids
        self.assertEqual({ids[v['V1']]}, self._keys(self.admin, self.H.id))
        self.assertEqual({ids[v[n]] for n in ('V2', 'V3', 'V4', 'V5', 'V6')}, self._keys(self.admin, self.P.id))
        self.assertEqual({ids[v['V1']]}, self._keys(self.owner, self.H.id))
        self.assertEqual({ids[v[n]] for n in ('V2', 'V3', 'V4', 'V5', 'V6')}, self._keys(self.owner, self.P.id),
                         'the owner lost the correlations of its own organisation-only attributes')
        response = self.owner._prepare_request('GET', 'events/view/%s' % self.P.id)
        related = {int(e['Event']['id']) for e in response.json()['Event'].get('RelatedEvent', [])}
        self.assertIn(int(self.R.id), related)
        self.assertNotIn(int(self.R2.id), related)
        own = self._keys(self.outsider, self.R.id)
        self.assertTrue(own, 'the outsider lost the correlations of its own event')


class EventDelegationSharingGroupAcl(unittest.TestCase):
    """A delegation request only names a sharing group its requester is authorised for.

    delegateEvent stored whatever sharing_group_id was submitted with distribution 4, without
    checking it. The delegation view then showed that group's name to the requester, so the
    name of any sharing group on the instance, including ones the requester's organisation is
    not in, could be read by guessing ids. An unauthorised or malformed id now answers like a
    missing group and stores nothing.
    """

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        cls.role_id = least_privileged_role(cls.admin, 'perm_add', 'perm_delegate')
        cls.requester_org = make_org(cls.admin, 'regression delegation requester org')
        cls.recipient_org = make_org(cls.admin, 'regression delegation recipient org')
        cls.created_orgs = [cls.requester_org, cls.recipient_org]
        cls.requester_user = make_user(cls.admin, cls.requester_org.id, cls.role_id)
        cls.created_users = [cls.requester_user]
        cls.requester = PyMISP(url, cls.requester_user.authkey)
        cls.requester.global_pythonify = True
        cls.sharing_groups = []
        token = random()

        def group(name, orgs):
            made = send(cls.admin, 'POST', 'sharingGroups/add', data={
                'name': 'regression delegation %s %s' % (name, token), 'releasability': 'x',
                'roaming': False,
                'SharingGroupOrg': [{'Organisation': {'uuid': o.uuid, 'name': o.name}, 'extend': False}
                                    for o in orgs]})
            cls.sharing_groups.append(int(made['SharingGroup']['id']))
            return made['SharingGroup']

        cls.hidden = group('hidden', [cls.recipient_org])
        cls.own = group('own', cls.created_orgs)
        event = MISPEvent()
        event.info = 'regression delegation %s' % token
        event.distribution = 0
        cls.event = check_response(cls.requester.add_event(event))
        cls.extra_uuids = []

    @classmethod
    def tearDownClass(cls):
        uuids = [cls.event.uuid] + cls.extra_uuids
        drop_fixtures(cls.admin, cls.created_orgs, cls.created_users)
        for sg_id in cls.sharing_groups:
            send(cls.admin, 'POST', 'sharingGroups/delete/%d' % sg_id, check_errors=False)
        for row in send(cls.admin, 'GET', 'eventBlocklists/index', check_errors=False):
            row = row.get('EventBlocklist', row)
            if row.get('event_uuid') in uuids:
                send(cls.admin, 'POST', 'eventBlocklists/delete/%s' % row['id'], check_errors=False)

    def _delegate(self, connector, event_id, **fields):
        data = dict({'org_id': int(self.recipient_org.id)}, **fields)
        response = connector._prepare_request(
            'POST', 'eventDelegations/delegateEvent/%s' % event_id, data=data)
        body = response.json()
        if response.status_code == 200:
            self.addCleanup(connector._prepare_request, 'POST',
                            'eventDelegations/deleteDelegation/%s' % body['EventDelegation']['id'])
        return response.status_code, body

    def _revoke(self, body):
        if 'EventDelegation' in body:
            self.requester._prepare_request(
                'POST', 'eventDelegations/deleteDelegation/%s' % body['EventDelegation']['id'])

    def _issued(self):
        response = self.requester._prepare_request('GET', 'eventDelegations/index/context:issued')
        return [d for d in response.json() if int(d['EventDelegation']['event_id']) == int(self.event.id)]

    def test_unauthorised_or_malformed_sharing_group_is_refused(self):
        gone_status, gone = self._delegate(self.requester, self.event.id, distribution=4,
                                           sharing_group_id=2147483646)
        self._revoke(gone)
        for what, value in (('id', int(self.hidden['id'])), ('uuid', self.hidden['uuid']),
                            ('id with a suffix', '%sabc' % self.hidden['id'])):
            status, body = self._delegate(self.requester, self.event.id, distribution=4,
                                          sharing_group_id=value)
            issued = self._issued()
            self._revoke(body)
            self.assertEqual(404, status, 'a sharing group the requester is not in was accepted by %s' % what)
            for field in ('name', 'message'):
                self.assertEqual(gone[field], body[field],
                                 'an unauthorised sharing group is told apart from a missing one (%s)' % what)
            self.assertEqual([], issued, 'a delegation was stored for the %s' % what)
        self.assertEqual(404, gone_status, gone)

    def test_own_sharing_group_is_kept_and_ignored_unless_distribution_4(self):
        status, body = self._delegate(self.requester, self.event.id, distribution=4,
                                      sharing_group_id=int(self.own['id']))
        self.assertEqual(200, status, body)
        self.assertEqual(int(self.own['id']), int(body['EventDelegation']['sharing_group_id']))
        self.assertEqual(int(self.own['id']), int(self._issued()[0]['EventDelegation']['sharing_group_id']))
        self.requester._prepare_request(
            'POST', 'eventDelegations/deleteDelegation/%s' % body['EventDelegation']['id'])
        status, body = self._delegate(self.requester, self.event.id, distribution=1,
                                      sharing_group_id=int(self.own['id']))
        self.assertEqual(200, status, body)
        self.assertEqual(0, int(body['EventDelegation']['sharing_group_id']))

    def test_site_admin_may_name_any_sharing_group(self):
        event = MISPEvent()
        event.info = 'regression delegation admin %s' % random()
        event.distribution = 0
        event = check_response(self.admin.add_event(event))
        self.extra_uuids.append(event.uuid)
        try:
            status, body = self._delegate(self.admin, event.id, distribution=4,
                                          sharing_group_id=int(self.hidden['id']))
            self.assertEqual(200, status, body)
            self.assertEqual(int(self.hidden['id']), int(body['EventDelegation']['sharing_group_id']))
        finally:
            self.doCleanups()
            self.admin.delete_event(event)


class UserDeleteRemovesAuthKeys(unittest.TestCase):
    """Deleting a user deletes its authentication keys.

    A deleted user's rows stayed in auth_keys, so they became valid for whichever user was
    later given the same id.
    """

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        cls.role_id = least_privileged_role(cls.admin, 'perm_add')
        cls.org = make_org(cls.admin, 'regression user keys org')
        cls.user = make_user(cls.admin, cls.org.id, cls.role_id)
        cls.user_deleted = False

    @classmethod
    def tearDownClass(cls):
        if not cls.user_deleted:
            cls.admin.delete_user(cls.user)
        for key_id in getattr(cls, 'key_ids', []):
            cls.admin._prepare_request('POST', 'authKeys/delete/%s' % key_id)
        cls.admin.delete_organisation(cls.org)

    def _keys_of(self, user_id):
        response = self.admin._prepare_request('GET', 'authKeys/index/user_id:%s' % user_id)
        body = response.json()
        return [int(k['AuthKey']['id']) for k in body if int(k['AuthKey']['user_id']) == int(user_id)]

    def test_deleting_a_user_deletes_its_keys(self):
        send(self.admin, 'POST', 'authKeys/add/%s' % self.user.id, data={'comment': 'regression'})
        type(self).key_ids = self._keys_of(self.user.id)
        self.assertEqual(2, len(self.key_ids), 'the user does not hold two keys, so the test proves nothing')
        check_response(self.admin.delete_user(self.user))
        type(self).user_deleted = True
        self.assertEqual([], self._keys_of(self.user.id), 'the deleted user kept its keys')


if __name__ == '__main__':
    unittest.main()
