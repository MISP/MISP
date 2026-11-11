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
import html
import json
import re
import shutil
import subprocess
import tempfile
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


class UserDeleteRemovesSettings(unittest.TestCase):
    """Deleting a user deletes its settings, which would otherwise pass to a user given its id."""

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        cls.role_id = least_privileged_role(cls.admin, 'perm_add')
        cls.org = make_org(cls.admin, 'regression user settings org')
        cls.user = make_user(cls.admin, cls.org.id, cls.role_id)
        cls.user_deleted = False

    @classmethod
    def tearDownClass(cls):
        if not cls.user_deleted:
            cls.admin.delete_user(cls.user)
        for setting_id in getattr(cls, 'setting_ids', []):
            cls.admin._prepare_request('POST', 'userSettings/delete/%s' % setting_id)
        cls.admin.delete_organisation(cls.org)

    def _settings_of(self, user_id):
        response = self.admin._prepare_request('GET', 'userSettings/index/user_id:%s' % user_id)
        return [int(s['UserSetting']['id']) for s in response.json()
                if int(s['UserSetting']['user_id']) == int(user_id)]

    def test_deleting_a_user_deletes_its_settings(self):
        # A dict value reaches MISP as "b'...'" when PyMISP has orjson.
        homepage = json.dumps({'path': '/events/index'})
        check_response(self.admin.set_user_setting('homepage', homepage, self.user))
        type(self).setting_ids = self._settings_of(self.user.id)
        self.assertEqual(1, len(self.setting_ids), 'the user holds no setting, so the test proves nothing')
        check_response(self.admin.delete_user(self.user))
        type(self).user_deleted = True
        self.assertEqual([], self._settings_of(self.user.id), 'the deleted user kept its settings')


class SightingsAnonymisedOrgFilter(unittest.TestCase):
    """With Sightings_anonymise on, an org filter does not unmask who reported a sighting.

    listSightings and sightings/restSearch applied a caller-chosen org_id filter in SQL before
    the reporter was masked, so filtering by another organisation returned exactly that
    organisation's sightings and named the reporter. A non-site-admin's filter naming another
    organisation now matches nothing, and a negated one excludes nothing.
    """

    SETTINGS = ('Plugin.Sightings_anonymise', 'Plugin.Sightings_policy')
    POLICIES = (0, 2)

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        cls.previous = {name: send(cls.admin, 'GET', 'servers/getSetting/%s' % name)['value']
                        for name in cls.SETTINGS}
        cls.created_orgs = []
        cls.created_users = []
        cls.event = None
        try:
            role_id = least_privileged_role(cls.admin, 'perm_add', 'perm_sighting')
            cls.orgs = {}
            cls.api = {}
            for name in ('owner', 'reporter', 'other'):
                org = make_org(cls.admin, 'regression sighting %s org' % name)
                cls.created_orgs.append(org)
                user = make_user(cls.admin, org.id, role_id)
                cls.created_users.append(user)
                connector = PyMISP(url, user.authkey)
                connector.global_pythonify = False
                cls.orgs[name] = org
                cls.api[name] = connector
            event = MISPEvent()
            event.info = 'regression sightings %s' % random()
            event.distribution = 1
            event.add_attribute('ip-dst', '192.0.2.%d' % (int(random(), 16) % 250), distribution=5)
            cls.event = check_response(cls.api['owner'].add_event(event, pythonify=True))
            cls.attribute_id = int(cls.event.attributes[0].id)
            cls.sightings = {'owner': [], 'reporter': [], 'other': []}
            for name, count in (('owner', 1), ('reporter', 2), ('other', 1)):
                for _ in range(count):
                    made = send(cls.api[name], 'POST', 'sightings/add/%d' % cls.attribute_id)
                    cls.sightings[name].append(int(made['Sighting']['id']))
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for name, value in getattr(cls, 'previous', {}).items():
            send(cls.admin, 'POST', 'servers/serverSettingsEdit/%s' % name, data={'value': value})
        drop_fixtures(cls.admin, cls.created_orgs, cls.created_users)

    def _configure(self, anonymise, policy):
        send(self.admin, 'POST', 'servers/serverSettingsEdit/Plugin.Sightings_anonymise',
             data={'value': anonymise})
        send(self.admin, 'POST', 'servers/serverSettingsEdit/Plugin.Sightings_policy',
             data={'value': policy})

    def _list(self, connector, org=None):
        path = 'sightings/listSightings/%d/attribute' % self.attribute_id
        if org is not None:
            path += '/%s' % org
        return send(connector, 'GET', path)

    def _search(self, connector, org=None):
        data = {'context': 'attribute', 'id': self.attribute_id, 'returnFormat': 'json'}
        if org is not None:
            data['org_id'] = org
        return {int(s['Sighting']['id']) for s in send(connector, 'POST', 'sightings/restSearch', data=data)}

    def _all(self):
        return {i for ids in self.sightings.values() for i in ids}

    def test_list_sightings_org_filter_does_not_unmask(self):
        owner, reporter = self.orgs['owner'], self.orgs['reporter']
        for policy in self.POLICIES:
            with self.subTest(policy=policy):
                self._configure(True, policy)
                everything = self._list(self.api['owner'])
                self.assertEqual(4, len(everything), 'the observer does not see every sighting')
                self.assertTrue(all(int(s['Sighting']['org_id']) in (0, int(owner.id)) for s in everything))
                for org in (reporter.id, reporter.uuid):
                    self.assertEqual([], self._list(self.api['owner'], org),
                                     'filtering by another organisation returned its sightings')
                own = self._list(self.api['owner'], owner.id)
                self.assertEqual(self.sightings['owner'], [int(s['Sighting']['id']) for s in own])

    def test_rest_search_org_filter_does_not_unmask(self):
        owner, reporter = self.orgs['owner'], self.orgs['reporter']
        theirs = set(self.sightings['reporter'])
        for policy in self.POLICIES:
            with self.subTest(policy=policy):
                self._configure(True, policy)
                everything = self._search(self.api['owner'])
                self.assertEqual(self._all(), everything, 'the observer does not see every sighting')
                for org in (reporter.uuid, int(reporter.id), str(reporter.id)):
                    self.assertFalse(theirs & self._search(self.api['owner'], org),
                                     'filtering by %r returned the reporter\'s sightings' % (org,))
                self.assertEqual(everything, self._search(self.api['owner'], '!' + reporter.uuid),
                                 'the negated filter excluded the reporter\'s sightings')
                self.assertEqual(set(self.sightings['owner']), self._search(self.api['owner'], owner.uuid))

    def test_site_admin_can_filter_by_any_organisation(self):
        reporter = self.orgs['reporter']
        # Policy 2: under 0, restSearch shows a site admin only its own org's sightings.
        self._configure(True, 2)
        listed = self._list(self.admin, reporter.id)
        self.assertEqual(self.sightings['reporter'], sorted(int(s['Sighting']['id']) for s in listed))
        self.assertTrue(all(int(s['Sighting']['org_id']) == int(reporter.id) for s in listed))
        self.assertEqual(set(self.sightings['reporter']), self._search(self.admin, reporter.uuid))

    def test_filter_is_harmless_without_anonymisation(self):
        reporter = self.orgs['reporter']
        self._configure(False, 2)
        self.assertEqual(set(self.sightings['reporter']), self._search(self.api['owner'], reporter.uuid))
        self.assertEqual(2, len(self._list(self.api['owner'], reporter.id)))


class TagEndpointsHiddenTargets(unittest.TestCase):
    """The tag endpoints load their target with the caller's visibility applied.

    canModifyTag lets users of the host organisation set local tags on whatever they are given,
    and addTag, removeTag and attributes/removeTag loaded the event or attribute unscoped. A
    hidden event or attribute could be tagged or untagged by the host organisation, and
    removeTag told any tagger whether a tag was on a hidden event. A target the caller cannot
    see now answers like a missing one; local tagging of visible records still works.
    """

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        cls.created_orgs = []
        cls.created_users = []
        cls.event_ids = []
        cls.event_uuids = []
        cls.tag_ids = []
        try:
            setting = send(cls.admin, 'GET', 'servers/getSetting/MISP.host_org_id')
            cls.host_org_id = int(setting.get('value') or 0)
            tagger_role = least_privileged_role(cls.admin, 'perm_tagger', 'perm_add')
            owner_role = least_privileged_role(cls.admin, 'perm_add')
            owner_org = make_org(cls.admin, 'regression tag owner org')
            other_org = make_org(cls.admin, 'regression tag other org')
            cls.created_orgs = [owner_org, other_org]
            owner_user = make_user(cls.admin, owner_org.id, owner_role)
            other_user = make_user(cls.admin, other_org.id, tagger_role)
            cls.created_users = [owner_user, other_user]
            cls.other = PyMISP(url, other_user.authkey)
            cls.other.global_pythonify = False
            cls.host = None
            if cls.host_org_id:
                host_user = make_user(cls.admin, cls.host_org_id, tagger_role)
                cls.created_users.append(host_user)
                cls.host = PyMISP(url, host_user.authkey)
                cls.host.global_pythonify = False
            owner = PyMISP(url, owner_user.authkey)
            owner.global_pythonify = False
            token = random()
            cls.tags = {}
            for i in range(1, 5):
                made = send(cls.admin, 'POST', 'tags/add', data={'name': 'regression-tag-%s-t%d' % (token, i)})
                cls.tags[i] = int(made['Tag']['id'])
                cls.tag_ids.append(cls.tags[i])

            def make(label, distribution):
                made = send(owner, 'POST', 'events/add', data={
                    'info': 'regression tag %s %s' % (label, token), 'distribution': distribution,
                    'Attribute': [{'type': 'ip-dst', 'value': '192.0.2.%d' % (int(random(), 16) % 250),
                                   'distribution': 5}]})['Event']
                cls.event_ids.append(int(made['id']))
                cls.event_uuids.append(made['uuid'])
                return int(made['id']), int(made['Attribute'][0]['id'])

            cls.hidden, cls.hidden_attr = make('hidden', 0)
            cls.visible, cls.visible_attr = make('visible', 3)
            cls._tag('events', cls.hidden, 1, False)
            cls._tag('events', cls.hidden, 2, True)
            cls._tag('attributes', cls.hidden_attr, 2, True)
            cls._tag('attributes', cls.visible_attr, 2, True)
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def _tag(cls, scope, target_id, tag, local):
        send(cls.admin, 'POST', '%s/addTag/%d/%d/local:%d' % (scope, target_id, cls.tags[tag], int(local)))

    @classmethod
    def tearDownClass(cls):
        for event_id in getattr(cls, 'event_ids', []):
            send(cls.admin, 'POST', 'events/delete/%d' % event_id, check_errors=False)
        uuids = getattr(cls, 'event_uuids', [])
        for row in send(cls.admin, 'GET', 'eventBlocklists/index', check_errors=False) or []:
            row = row.get('EventBlocklist', row) if isinstance(row, dict) else {}
            if row.get('event_uuid') in uuids:
                send(cls.admin, 'POST', 'eventBlocklists/delete/%s' % row['id'], check_errors=False)
        for tag_id in getattr(cls, 'tag_ids', []):
            send(cls.admin, 'POST', 'tags/delete/%d' % tag_id, check_errors=False)
        for user in getattr(cls, 'created_users', []):
            cls.admin.delete_user(user)
        for org in getattr(cls, 'created_orgs', []):
            cls.admin.delete_organisation(org)

    def _post(self, connector, path, data=None):
        response = connector._prepare_request('POST', path, data=data if data is not None else {})
        try:
            body = response.json()
        except ValueError:
            body = response.text
        return response.status_code, body

    def _answer(self, connector, path, data=None):
        status, body = self._post(connector, path, data)
        if isinstance(body, dict):
            body = {k: body.get(k) for k in ('saved', 'success', 'errors', 'message', 'name')}
        return status, body

    def _event_tags(self, event_id):
        event = send(self.admin, 'GET', 'events/view/%d' % event_id)['Event']
        return {int(t['id']) for t in event.get('Tag', [])}

    def _attribute_tags(self, attribute_id):
        attribute = send(self.admin, 'GET', 'attributes/view/%d' % attribute_id)['Attribute']
        return {int(t['id']) for t in attribute.get('Tag', [])}

    def _require_host(self):
        if not self.host_org_id:
            self.skipTest('MISP.host_org_id is not set')

    def test_remove_tag_does_not_reveal_hidden_event_tags(self):
        before = self._event_tags(self.hidden)
        missing = self._answer(self.other, 'events/removeTag/2147483646/%d' % self.tags[1])
        present = self._answer(self.other, 'events/removeTag/%d/%d' % (self.hidden, self.tags[1]))
        absent = self._answer(self.other, 'events/removeTag/%d/%d' % (self.hidden, self.tags[3]))
        self.assertEqual(present, absent, 'removeTag reveals whether a hidden event has the tag')
        self.assertEqual(missing, present, 'a hidden event is told apart from a missing one')
        self.assertEqual(before, self._event_tags(self.hidden))

    def test_host_org_cannot_tag_hidden_event(self):
        self._require_host()
        local = self._answer(self.host, 'events/addTag/%d/%d/local:1' % (self.hidden, self.tags[3]))
        missing = self._answer(self.host, 'events/addTag/2147483646/%d/local:1' % self.tags[1])
        existing = self._answer(self.host, 'events/addTag/%d/%d/local:1' % (self.hidden, self.tags[1]))
        bulk = self._answer(self.host, 'events/addTag/selected/local:1',
                            data={'event_ids': json.dumps([self.hidden]), 'tag': self.tags[4]})
        self.assertEqual(missing, local, 'the host organisation tagged a hidden event')
        self.assertEqual(missing, existing, 'addTag on a hidden event is told apart from a missing event')
        after = self._event_tags(self.hidden)
        self.assertNotIn(self.tags[3], after, 'addTag attached a tag to a hidden event')
        self.assertNotIn(self.tags[4], after, 'bulk addTag attached a tag to a hidden event: %s' % (bulk,))

    def test_host_org_cannot_untag_hidden_event(self):
        self._require_host()
        self._answer(self.host, 'events/removeTag/%d/%d' % (self.hidden, self.tags[2]))
        self.assertIn(self.tags[2], self._event_tags(self.hidden), 'removeTag removed a tag from a hidden event')

    def test_host_org_cannot_untag_hidden_attribute(self):
        self._require_host()
        missing = self._answer(self.host, 'attributes/removeTag/2147483646/%d' % self.tags[2])
        hidden = self._answer(self.host, 'attributes/removeTag/%d/%d' % (self.hidden_attr, self.tags[2]))
        self.assertIn(self.tags[2], self._attribute_tags(self.hidden_attr),
                      'attributes/removeTag removed a tag from a hidden attribute')
        self.assertEqual(missing, hidden, 'a hidden attribute is told apart from a missing one')

    def test_host_org_local_tags_on_visible_event(self):
        self._require_host()
        added = self._post(self.host, 'events/addTag/%d/%d/local:1' % (self.visible, self.tags[3]))
        self.assertIn(self.tags[3], self._event_tags(self.visible), added)
        bulk = self._post(self.host, 'events/addTag/selected/local:1',
                          data={'event_ids': json.dumps([self.visible]), 'tag': self.tags[4]})
        self.assertIn(self.tags[4], self._event_tags(self.visible), bulk)
        removed = self._post(self.host, 'events/removeTag/%d/%d' % (self.visible, self.tags[3]))
        self.assertNotIn(self.tags[3], self._event_tags(self.visible), removed)
        removed = self._post(self.host, 'attributes/removeTag/%d/%d' % (self.visible_attr, self.tags[2]))
        self.assertNotIn(self.tags[2], self._attribute_tags(self.visible_attr), removed)

    def test_site_admin_tags_hidden_event(self):
        send(self.admin, 'POST', 'events/removeTag/%d/%d' % (self.hidden, self.tags[3]), check_errors=False)
        send(self.admin, 'POST', 'events/addTag/%d/%d' % (self.hidden, self.tags[3]))
        self.assertIn(self.tags[3], self._event_tags(self.hidden))
        send(self.admin, 'POST', 'events/removeTag/%d/%d' % (self.hidden, self.tags[3]))
        self.assertNotIn(self.tags[3], self._event_tags(self.hidden))


class HiddenRecordsAnswerLikeMissing(unittest.TestCase):
    """Endpoints that load a record by id answer for a hidden record exactly as for a missing one.

    sharingGroups/edit, shadowAttributes/acceptSelected and discardSelected, objects/editField and
    objects/delete, and organisations/getOrgLogo told a record the caller cannot see apart from
    one that does not exist (a permission error instead of not found). A hidden record now gets
    the missing-id answer; a visible record the caller may not change keeps its permission error.
    """

    MISSING = 2147483646
    SETTING = 'Security.hide_organisation_index_from_users'

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        cls.created_orgs = []
        cls.created_users = []
        cls.event_ids = []
        cls.sharing_group_ids = []
        cls.previous_hide = None
        try:
            cls.previous_hide = send(cls.admin, 'GET', 'servers/getSetting/%s' % cls.SETTING)['value']
            full_role = least_privileged_role(cls.admin, 'perm_add', 'perm_modify', 'perm_sharing_group')
            weak_role = None
            for entry in send(cls.admin, 'GET', 'roles'):
                role = entry['Role'] if 'Role' in entry else entry
                if (int(role['perm_add']) and not int(role['perm_sharing_group'])
                        and not int(role['perm_site_admin']) and not int(role['perm_sync'])):
                    weak_role = int(role['id'])
                    break
            if weak_role is None:
                raise unittest.SkipTest('no non-admin role with perm_add and without perm_sharing_group')
            cls.owner_org = make_org(cls.admin, 'regression hidden owner org')
            cls.outsider_org = make_org(cls.admin, 'regression hidden outsider org')
            cls.silent_org = make_org(cls.admin, 'regression hidden silent org')
            cls.created_orgs = [cls.owner_org, cls.outsider_org, cls.silent_org]
            users = [make_user(cls.admin, cls.owner_org.id, full_role),
                     make_user(cls.admin, cls.outsider_org.id, full_role),
                     make_user(cls.admin, cls.outsider_org.id, weak_role),
                     make_user(cls.admin, cls.silent_org.id, full_role)]
            cls.created_users = users
            cls.owner, cls.outsider, cls.weak, silent = [PyMISP(url, u.authkey) for u in users]
            token = random()
            template = next((t['ObjectTemplate'] for t in send(cls.admin, 'GET', 'objectTemplates/index')
                             if t['ObjectTemplate']['name'] == 'file'), None)
            if template is None:
                raise unittest.SkipTest('no file object template on this instance')

            def make(label, distribution, object_distribution):
                made = send(cls.owner, 'POST', 'events/add', data={
                    'info': 'regression hidden %s %s' % (label, token), 'distribution': distribution,
                    'Attribute': [{'type': 'ip-dst', 'value': '192.0.2.%d' % (int(random(), 16) % 250),
                                   'distribution': 5}],
                    'Object': [{'name': 'file', 'meta-category': 'file', 'template_uuid': template['uuid'],
                                'template_version': template['version'], 'distribution': object_distribution,
                                'Attribute': [{'type': 'filename', 'object_relation': 'filename',
                                               'value': 'regression-%s.bin' % random(), 'distribution': 5}]}],
                })['Event']
                cls.event_ids.append(int(made['id']))
                return send(cls.admin, 'GET', 'events/view/%s' % made['id'])['Event']

            cls.hidden_event = make('hidden', 0, 5)
            cls.visible_event = make('visible', 3, 5)
            cls.hidden_object_event = make('hidden object', 3, 0)
            cls.own_event = make('own', 3, 5)
            cls.own_delete_event = make('own delete', 3, 5)
            cls.visible_event_proposal = int(send(cls.outsider, 'POST', 'shadow_attributes/add/%s' % cls.visible_event['id'],
                                                  data={'type': 'ip-dst', 'value': '198.51.100.%d' % (int(random(), 16) % 250)}
                                                  )['ShadowAttribute']['id'])
            made = send(silent, 'POST', 'events/add', data={
                'info': 'regression hidden silent %s' % token, 'distribution': 0})['Event']
            cls.event_ids.append(int(made['id']))
            cls.private_group = cls._make_group('regression hidden private sg %s' % token, [])
            cls.shared_group = cls._make_group('regression hidden shared sg %s' % token, [cls.outsider_org])
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def _make_group(cls, name, members):
        made = send(cls.owner, 'POST', 'sharingGroups/add', data={
            'name': name, 'uuid': str(uuidlib.uuid4()), 'releasability': 'regression', 'roaming': 0,
            'SharingGroupOrg': [{'Organisation': {'uuid': org.uuid, 'name': org.name}, 'extend': extend}
                                for org, extend in [(cls.owner_org, 1)] + [(o, 0) for o in members]]})
        group_id = int(made['SharingGroup']['id'])
        cls.sharing_group_ids.append(group_id)
        return group_id

    @classmethod
    def tearDownClass(cls):
        previous = getattr(cls, 'previous_hide', None)
        if previous is not None:
            send(cls.admin, 'POST', 'servers/serverSettingsEdit/%s' % cls.SETTING,
                 data={'value': previous}, check_errors=False)
        for group_id in getattr(cls, 'sharing_group_ids', []):
            send(cls.admin, 'POST', 'sharingGroups/delete/%d' % group_id, check_errors=False)
        drop_fixtures(cls.admin, cls.created_orgs, cls.created_users)

    def _answer(self, connector, method, path, data=None, ajax=False):
        if ajax:  # the proposal bulk actions accept only ajax requests
            response = requests.request(
                method, '%s/%s' % (url, path), json=data, allow_redirects=False,
                headers={'Authorization': connector.key, 'Accept': 'application/json',
                         'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})
        else:
            response = connector._prepare_request(method, path, data=data if data is not None else {})
        try:
            body = response.json()
        except ValueError:
            body = response.text
        if isinstance(body, dict):
            body = {k: body.get(k) for k in ('saved', 'success', 'errors', 'message', 'name')}
        return response.status_code, body

    def test_sharing_group_edit(self):
        missing = self._answer(self.outsider, 'GET', 'sharingGroups/edit/%d' % self.MISSING)
        hidden = self._answer(self.outsider, 'GET', 'sharingGroups/edit/%d' % self.private_group)
        self.assertEqual(404, missing[0], missing)
        self.assertEqual(missing, hidden, 'a hidden sharing group is told apart from a missing one')
        visible = self._answer(self.outsider, 'GET', 'sharingGroups/edit/%d' % self.shared_group)
        self.assertEqual(405, visible[0], 'a visible group the user cannot extend lost its answer')
        own = self._answer(self.owner, 'GET', 'sharingGroups/edit/%d' % self.private_group)
        self.assertEqual(200, own[0], own)

    def _selected(self, action, field, connector, event_id, ids):
        return self._answer(connector, 'POST', 'shadowAttributes/%s/%s' % (action, event_id),
                            data={'ShadowAttribute': {field: json.dumps(ids)}}, ajax=True)

    def test_proposal_bulk_actions(self):
        for action, field in (('acceptSelected', 'ids_accept'), ('discardSelected', 'ids_discard')):
            with self.subTest(action=action):
                ids = [self.visible_event_proposal]
                missing = self._selected(action, field, self.outsider, self.MISSING, ids)
                self.assertIn('Invalid event.', str(missing[1]))
                hidden = self._selected(action, field, self.outsider, self.hidden_event['id'], ids)
                self.assertEqual(missing, hidden, 'a hidden event is told apart from a missing one')
                visible = self._selected(action, field, self.outsider, self.visible_event['id'], ids)
                self.assertIn("You don't have permission to do that.", str(visible[1]))

    def test_proposal_bulk_actions_by_event_owner(self):
        ids = [self.visible_event_proposal]
        answer = self._selected('discardSelected', 'ids_discard', self.owner, self.visible_event['id'], ids)
        self.assertEqual(True, answer[1]['saved'], answer)

    def test_object_edit_field(self):
        body = {'Object': {'comment': 'regression %s' % random()}}
        hidden_ids = (self.hidden_event['Object'][0]['id'], self.hidden_object_event['Object'][0]['id'])
        missing = self._answer(self.outsider, 'POST', 'objects/editField/%d' % self.MISSING, data=body)
        self.assertIn('Invalid object', str(missing[1]))
        for object_id in hidden_ids:
            hidden = self._answer(self.outsider, 'POST', 'objects/editField/%s' % object_id, data=body)
            self.assertEqual(missing, hidden, 'a hidden object is told apart from a missing one')
        visible = self._answer(self.outsider, 'POST', 'objects/editField/%s' % self.visible_event['Object'][0]['id'],
                               data=body)
        self.assertIn('You do not have permission to do that.', str(visible[1]))
        own = self._answer(self.owner, 'POST', 'objects/editField/%s' % self.own_event['Object'][0]['id'], data=body)
        self.assertEqual(200, own[0], own)
        self.assertTrue(own[1].get('saved') or own[1].get('success'), own)

    def test_object_delete(self):
        missing = self._answer(self.outsider, 'POST', 'objects/delete/%d' % self.MISSING)
        self.assertEqual(404, missing[0], missing)
        for event in (self.hidden_event, self.hidden_object_event):
            hidden = self._answer(self.outsider, 'POST', 'objects/delete/%s' % event['Object'][0]['id'])
            self.assertEqual(missing, hidden, 'a hidden object is told apart from a missing one')
        visible = self._answer(self.outsider, 'POST', 'objects/delete/%s' % self.visible_event['Object'][0]['id'])
        self.assertEqual(403, visible[0], visible)
        own = self._answer(self.owner, 'POST', 'objects/delete/%s' % self.own_delete_event['Object'][0]['id'])
        self.assertEqual(200, own[0], own)

    def test_org_logo(self):
        send(self.admin, 'POST', 'servers/serverSettingsEdit/%s' % self.SETTING, data={'value': True})
        missing = self._answer(self.weak, 'GET', 'organisations/getOrgLogo/%d' % self.MISSING)
        self.assertEqual(404, missing[0], missing)
        self.assertIn('Invalid organisation', str(missing[1]))
        hidden = self._answer(self.weak, 'GET', 'organisations/getOrgLogo/%s' % self.silent_org.id)
        self.assertEqual(missing, hidden, 'a hidden organisation is told apart from a missing one')
        own = self._answer(self.weak, 'GET', 'organisations/getOrgLogo/%s' % self.outsider_org.id)
        self.assertIn('Organisation logo not found', str(own[1]))
        privileged = self._answer(self.outsider, 'GET', 'organisations/getOrgLogo/%s' % self.silent_org.id)
        self.assertIn('Organisation logo not found', str(privileged[1]))


class DelegationRequestVisibility(unittest.TestCase):
    """The event view shows a pending delegation request only to an organisation it involves.

    __viewUI() and view2() looked the request up unrestricted for a viewer whose role lacked
    perm_publish, so on the classic event view a third organisation's user saw "You have
    requested that <org> take over this event." for a request between two other organisations.
    """

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        cls.created_orgs = []
        cls.created_users = []
        cls.delegation_id = None
        cls.requester = None
        try:
            if not cls.admin.get_server_setting('MISP.delegation')['value']:
                raise unittest.SkipTest('MISP.delegation is disabled on this instance')
            if not cls.admin.get_server_setting('MISP.enable_themes')['value']:
                raise unittest.SkipTest('events/view2 needs MISP.enable_themes')
            delegate_role = least_privileged_role(cls.admin, 'perm_add', 'perm_delegate')
            publish_role = least_privileged_role(cls.admin, 'perm_publish')
            plain_role = cls._role_without_publish()
            org_a = make_org(cls.admin, 'regression delegation requester org')
            cls.created_orgs.append(org_a)
            org_b = make_org(cls.admin, 'regression delegation target org')
            cls.created_orgs.append(org_b)
            org_c = make_org(cls.admin, 'regression delegation third org')
            cls.created_orgs.append(org_c)
            cls.org_b = org_b
            cls.org_c = org_c
            cls.password = 'Rg%s-%sAa1!' % (random(), random())
            cls.users = {}
            for name, org, role in (('a', org_a, delegate_role), ('b', org_b, plain_role),
                                    ('b_publish', org_b, publish_role), ('c_plain', org_c, plain_role),
                                    ('c_publish', org_c, publish_role)):
                user = make_user(cls.admin, org.id, role)
                cls.created_users.append(user)
                cls.users[name] = user
                check_response(cls.admin.update_user(
                    {'password': cls.password, 'confirm_password': cls.password,
                     'change_pw': 0, 'termsaccepted': 1}, user.id))
            cls.requester = PyMISP(url, cls.users['a'].authkey)
            cls.requester.global_pythonify = True
            event = make_event(cls.requester, 'regression delegation visibility')
            cls.event = event
            created = send(cls.requester, 'POST', 'eventDelegations/delegateEvent/%s' % event.id,
                           data={'EventDelegation': {'org_id': org_b.id, 'distribution': 0,
                                                     'message': 'regression delegation'}})
            cls.delegation_id = created['EventDelegation']['id']
            # distribution 1 so the third organisation can open the event
            event.distribution = 1
            check_response(cls.requester.update_event(event))
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        if cls.delegation_id is not None and cls.requester is not None:
            cls.requester._prepare_request(
                'POST', 'eventDelegations/deleteDelegation/%s' % cls.delegation_id)
        drop_fixtures(cls.admin, cls.created_orgs, cls.created_users)

    @classmethod
    def _role_without_publish(cls) -> int:
        candidates = []
        for entry in send(cls.admin, 'GET', 'roles'):
            role = entry['Role'] if 'Role' in entry else entry
            if (int(role.get('perm_site_admin', 0)) or int(role.get('perm_sync', 0))
                    or int(role.get('perm_publish', 0))):
                continue
            weight = sum(1 for k, v in role.items() if k.startswith('perm_') and int(v or 0))
            candidates.append((weight, int(role['id'])))
        if not candidates:
            raise unittest.SkipTest('no non-admin role without perm_publish on this instance')
        return sorted(candidates)[0][1]

    def _set_theme(self, user, theme):
        """events/view2 renders only in the Overmind theme, which then also serves events/view
        as a different page; the classic view needs the Default theme (3.0 falls back to
        Overmind when the user has none)."""
        listed = self.admin._prepare_request('GET', 'userSettings/index/user_id:%s' % user.id)
        for entry in listed.json():
            if int(entry['UserSetting']['user_id']) == int(user.id) \
                    and entry['UserSetting']['setting'] == 'ui_theme':
                self.admin._prepare_request('POST', 'userSettings/delete/%s' % entry['UserSetting']['id'])
        if theme:
            send(self.admin, 'POST', 'userSettings/setSetting/%s/ui_theme' % user.id,
                 data={'value': theme})

    def _page(self, user, page: str) -> str:
        """The rendered HTML of a page as a user. An API key is redirected to the login page
        for HTML views, so this signs in through the web form."""
        self._set_theme(user, 'Overmind' if page == 'events/view2' else 'Default')
        session = requests.Session()
        login = session.get(url + '/users/login', allow_redirects=False)
        form = login.text[login.text.index('id="UserLoginForm"'):]
        form = form[:form.index('</form>')]
        fields = {}
        for tag in re.findall(r'<input[^>]*>', form):
            name = re.search(r'name="([^"]+)"', tag)
            value = re.search(r'value="([^"]*)"', tag)
            if name and value:
                fields[name.group(1)] = html.unescape(value.group(1))
        fields['data[User][email]'] = user.email
        fields['data[User][password]'] = self.password
        session.post(url + '/users/login', data=fields, allow_redirects=False)
        response = session.get('%s/%s/%s' % (url, page, self.event.id), allow_redirects=False)
        self.assertEqual(200, response.status_code,
                         '%s did not render for %s: %s %s' % (
                             page, user.email, response.status_code,
                             response.headers.get('Location')))
        self.assertIn(self.event.info, response.text,
                      '%s did not show the event, so the absence of a message proves nothing' % page)
        return response.text

    ACTIONS = ('Accept Delegation Request', 'Discard Delegation Request')

    def _assert_no_view_request(self, name: str):
        text = self._page(self.users[name], 'events/view')
        self.assertNotIn('take over this event', text, 'events/view showed the request to %s' % name)

    def _assert_no_view2_request(self, name: str):
        text = self._page(self.users[name], 'events/view2')
        for label in self.ACTIONS:
            self.assertNotIn(label, text, 'events/view2 offered %r to %s' % (label, name))

    def test_third_org_without_publish_sees_no_request_on_view(self):
        self._assert_no_view_request('c_plain')

    def test_third_org_with_publish_sees_no_request(self):
        self._assert_no_view_request('c_publish')
        self._assert_no_view2_request('c_publish')

    def test_target_org_sees_request(self):
        text = self._page(self.users['b'], 'events/view')
        self.assertIn('has requested that you take over this event', text)
        text = self._page(self.users['b_publish'], 'events/view2')
        self.assertIn('Accept Delegation Request', text)

    def test_requester_org_sees_request(self):
        text = self._page(self.users['a'], 'events/view')
        self.assertIn('You have requested that %s take over this event' % html.escape(self.org_b.name),
                      text)
        text = self._page(self.users['a'], 'events/view2')
        self.assertIn('Discard Delegation Request', text)
        self.assertNotIn('Accept Delegation Request', text)


class ApiDescriptionDecayingModels(unittest.TestCase):
    """api/getAllApis lists only the decaying models the caller may see.

    The allowed values of the decayingModel parameter were built from every model on the
    instance, so another organisation's private model (all_orgs 0) was disclosed by name and id.
    A site admin sees all models; anyone else only their own organisation's and the shared ones.
    """

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        cls.created_orgs = []
        cls.created_users = []
        cls.created_models = []
        try:
            decaying_role = least_privileged_role(cls.admin, 'perm_decaying')
            plain_role = least_privileged_role(cls.admin, 'perm_auth')
            cls.owner_org = make_org(cls.admin, 'regression api decaying owner org')
            cls.outsider_org = make_org(cls.admin, 'regression api decaying outsider org')
            cls.created_orgs = [cls.owner_org, cls.outsider_org]
            owner_user = make_user(cls.admin, cls.owner_org.id, decaying_role)
            outsider_user = make_user(cls.admin, cls.outsider_org.id, plain_role)
            cls.created_users = [owner_user, outsider_user]
            cls.owner = PyMISP(url, owner_user.authkey)
            cls.outsider = PyMISP(url, outsider_user.authkey)
            cls.private_name = 'regression private %s' % random()
            cls.shared_name = 'regression shared %s' % random()
            cls.private_id = cls._make_model(cls.private_name, 0)
            cls.shared_id = cls._make_model(cls.shared_name, 1)
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def _make_model(cls, name, all_orgs):
        made = send(cls.owner, 'POST', 'decayingModel/add', data={
            'name': name, 'formula': 'polynomial', 'version': '1', 'all_orgs': all_orgs,
            'parameters': {'threshold': 30, 'lifetime': 30, 'decay_speed': 0.5,
                           'default_base_score': 0}})
        model = made['data']['DecayingModel'] if 'data' in made else made['DecayingModel']
        cls.created_models.append(model['id'])
        return str(model['id'])

    @classmethod
    def tearDownClass(cls):
        for model_id in cls.created_models:
            send(cls.admin, 'POST', 'decayingModel/delete/%s' % model_id, check_errors=False)
        drop_fixtures(cls.admin, cls.created_orgs, cls.created_users)

    @staticmethod
    def _described(api):
        """(id, label) pairs from every decayingModel field of the API description."""
        found = []
        entries = 0

        def walk(node):
            nonlocal entries
            if isinstance(node, dict):
                field = node.get('decayingModel')
                if isinstance(field, dict) and isinstance(field.get('values'), list):
                    entries += 1
                    for value in field['values']:
                        found.append((str(value['value']), value['label']))
                for child in node.values():
                    walk(child)
            elif isinstance(node, list):
                for child in node:
                    walk(child)

        walk(send(api, 'GET', 'api/getAllApis').get('fieldsConstraint', {}))
        return entries, found

    def _check(self, api, expect_private):
        entries, found = self._described(api)
        self.assertGreater(entries, 0, 'no decayingModel field in the API description')
        ids = {i for i, _ in found}
        labels = {label for _, label in found}
        self.assertIn(self.shared_id, ids)
        self.assertIn(self.shared_name, labels)
        if expect_private:
            self.assertIn(self.private_id, ids)
            self.assertIn(self.private_name, labels)
        else:
            self.assertNotIn(self.private_id, ids, 'another organisation\'s private model id is listed')
            self.assertNotIn(self.private_name, labels,
                             'another organisation\'s private model name is listed')

    def test_outsider_does_not_see_private_model(self):
        self._check(self.outsider, False)

    def test_owner_sees_both_models(self):
        self._check(self.owner, True)

    def test_site_admin_sees_both_models(self):
        self._check(self.admin, True)


class EventSubviewStatsAcl(unittest.TestCase):
    """The themed event sub-views count and warninglist-match only what the viewer can see.

    viewEventStats and viewWarninglistHits checked access to the event, then aggregated every
    attribute and object of it, so counts, categories, object names, attachments and warninglist
    hits disclosed rows hidden by distribution, sharing group or a hidden parent object.
    """

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        cls.created_orgs = []
        cls.created_users = []
        cls.sharing_group = None
        cls.warninglists = []
        try:
            if not cls.admin.get_server_setting('MISP.enable_themes')['value']:
                raise unittest.SkipTest('the event sub-views need MISP.enable_themes')
            add_role = least_privileged_role(cls.admin, 'perm_add')
            plain_role = least_privileged_role(cls.admin, 'perm_auth')
            cls.owner_org = make_org(cls.admin, 'regression subview owner org')
            cls.outsider_org = make_org(cls.admin, 'regression subview outsider org')
            cls.created_orgs = [cls.owner_org, cls.outsider_org]
            owner_user = make_user(cls.admin, cls.owner_org.id, add_role)
            outsider_user = make_user(cls.admin, cls.outsider_org.id, plain_role)
            cls.created_users = [owner_user, outsider_user]
            cls.owner = PyMISP(url, owner_user.authkey)
            cls.owner.global_pythonify = True
            cls.outsider = PyMISP(url, outsider_user.authkey)
            cls.outsider.global_pythonify = True
            token = random()
            group = send(cls.admin, 'POST', 'sharingGroups/add', data={
                'name': 'regression subview %s' % token, 'releasability': 'x', 'roaming': False,
                'SharingGroupOrg': [{'Organisation': {'uuid': o.uuid, 'name': o.name}, 'extend': False}
                                    for o in cls.created_orgs]})
            cls.sharing_group = int(group['SharingGroup']['id'])
            cls.list_names = {}
            cls.list_values = {}
            for key_name in ('a', 'b'):
                name = 'regression subview list %s %s' % (key_name, token)
                value = '%s-%s.example.org' % (key_name, token)
                made = send(cls.admin, 'POST', 'warninglists/add', data={
                    'name': name, 'description': 'regression', 'version': 1, 'type': 'string',
                    'category': 'false_positive', 'entries': value})
                list_id = int((made.get('Warninglist') or made['data']['Warninglist'])['id'])
                cls.warninglists.append(list_id)
                send(cls.admin, 'POST', 'warninglists/toggleEnable',
                     data={'id': list_id, 'enabled': 1})
                cls.list_names[key_name] = name
                cls.list_values[key_name] = value
            cls._seed(token)
            # Retired on 3.0: its checks skip there, the warninglist hits still run
            probe = cls.admin._prepare_request('GET', 'events/viewEventStats/%s' % cls.event.id)
            cls.has_stats = probe.status_code != 404
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def _seed(cls, token):
        event = MISPEvent()
        event.info = 'regression subview %s' % token
        event.distribution = 1
        event.add_attribute('domain', 'visible-%s.example.net' % token, category='Network activity',
                            distribution=5)
        event.add_attribute('domain', 'group-%s.example.net' % token, category='External analysis',
                            distribution=4, sharing_group_id=cls.sharing_group)
        event.add_attribute('domain', cls.list_values['a'], category='Payload delivery',
                            distribution=0)
        event.add_attribute('attachment', 'hidden-%s.txt' % token, category='Payload delivery',
                            distribution=0, data='aGlkZGVu')
        cls.event = check_response(cls.owner.add_event(event))
        for distribution, value in ((5, 'obj-%s.example.net' % token), (0, cls.list_values['b'])):
            obj = MISPObject('domain-ip')
            obj.distribution = distribution
            obj.add_attribute('domain', value=value, distribution=5)
            check_response(cls.owner.add_object(cls.event.id, obj))

    @classmethod
    def tearDownClass(cls):
        drop_fixtures(cls.admin, cls.created_orgs, cls.created_users)
        if cls.sharing_group is not None:
            send(cls.admin, 'POST', 'sharingGroups/delete/%d' % cls.sharing_group, check_errors=False)
        for list_id in cls.warninglists:
            send(cls.admin, 'POST', 'warninglists/delete/%d' % list_id, check_errors=False)

    def _get(self, api, path):
        response = api._prepare_request('GET', '%s/%s' % (path, self.event.id))
        self.assertEqual(200, response.status_code, '%s: %s' % (path, response.text[:300]))
        return response.json()

    def _stats(self, api):
        if not self.has_stats:
            self.skipTest('events/viewEventStats is not on this line')
        return self._get(api, 'events/viewEventStats')

    def _hit_names(self, api):
        names = []

        def walk(node):
            if isinstance(node, dict):
                for child in node.values():
                    walk(child)
            elif isinstance(node, list):
                for child in node:
                    walk(child)
            else:
                names.append(str(node))

        walk(self._get(api, 'events/viewWarninglistHits'))
        return names

    def _own_view(self, api):
        """Attributes and objects as the viewer's own events/view returns them."""
        event = self._get(api, 'events/view')['Event']
        objects = event.get('Object', [])
        attributes = event.get('Attribute', []) + [a for o in objects for a in o.get('Attribute', [])]
        return attributes, objects

    def _assert_all_rows(self, api, who):
        hits = self._hit_names(api)
        for name in self.list_names.values():
            self.assertIn(name, hits, 'warninglist hits for %s lack %s' % (who, name))
        if not self.has_stats:
            return
        stats = self._stats(api)
        categories = stats['attributes']['by_category']
        self.assertIn('Payload delivery', categories, 'stats for %s lack the hidden attribute category' % who)
        self.assertEqual(1, stats['attachments'], 'stats for %s lack the hidden attachment' % who)
        self.assertEqual(2, stats['objects']['total'], 'stats for %s lack the hidden object' % who)
        self.assertEqual(2, sum(stats['objects']['by_name'].values()))

    def test_outsider_stats_cover_visible_rows_only(self):
        stats = self._stats(self.outsider)
        attributes, objects = self._own_view(self.outsider)
        expected = {}
        for attribute in attributes:
            expected[attribute['category']] = expected.get(attribute['category'], 0) + 1
        names = {}
        for obj in objects:
            names[obj['name']] = names.get(obj['name'], 0) + 1
        categories = stats['attributes']['by_category']
        self.assertNotIn('Payload delivery', categories,
                         'stats counted the hidden attribute and attachment')
        self.assertIn('External analysis', categories,
                      'stats dropped the sharing group attribute the viewer can see')
        self.assertEqual(expected, categories, 'attribute categories differ from the viewer\'s own view')
        self.assertEqual(len(attributes), stats['attributes']['total'],
                         'attribute total counted rows the viewer cannot see')
        self.assertEqual(len(objects), stats['objects']['total'],
                         'object total counted a hidden object')
        self.assertEqual(names, stats['objects']['by_name'],
                         'object names counted a hidden object')
        self.assertEqual(0, stats['attachments'], 'attachment count included a hidden attachment')

    def test_outsider_warninglist_hits_skip_hidden_rows(self):
        hits = self._hit_names(self.outsider)
        self.assertNotIn(self.list_names['a'], hits, 'a hit on a hidden attribute was listed')
        self.assertNotIn(self.list_names['b'], hits,
                         'a hit on an attribute of a hidden object was listed')

    def test_owner_sees_all_rows(self):
        self._assert_all_rows(self.owner, 'the owner')

    def test_site_admin_sees_all_rows(self):
        self._assert_all_rows(self.admin, 'a site admin')


class GalaxyClusterCaptureUpdateGate(unittest.TestCase):
    """An import or push may replace an existing cluster only for its owner organisation, a site
    admin, or a sync user that can see it, and a replacement never changes the cluster's owner.

    captureCluster() replaced any locked cluster with a newer version for every galaxy editor
    and wrote the importer's organisation as org_id and orgc_id.
    """

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        cls.created_orgs = []
        cls.created_users = []
        cls.cluster_uuids = []
        cls.galaxy_id = None
        try:
            editor_role = least_privileged_role(cls.admin, 'perm_galaxy_editor')
            sync_role = None
            for entry in send(cls.admin, 'GET', 'roles'):
                role = entry['Role'] if 'Role' in entry else entry
                if (int(role['perm_sync']) and int(role['perm_galaxy_editor'])
                        and not int(role['perm_site_admin'])):
                    sync_role = int(role['id'])
                    break
            if sync_role is None:
                raise unittest.SkipTest('no non-admin role with perm_sync and perm_galaxy_editor')
            cls.owner_org = make_org(cls.admin, 'regression cluster owner org')
            cls.other_org = make_org(cls.admin, 'regression cluster other org')
            cls.sync_org = make_org(cls.admin, 'regression cluster sync org')
            cls.created_orgs = [cls.owner_org, cls.other_org, cls.sync_org]
            users = [make_user(cls.admin, cls.owner_org.id, editor_role),
                     make_user(cls.admin, cls.other_org.id, editor_role),
                     make_user(cls.admin, cls.sync_org.id, sync_role)]
            cls.created_users = users
            cls.owner, cls.other, cls.syncer = [PyMISP(url, u.authkey) for u in users]
            cls.token = random()
            cls.galaxy_type = 'regression-gate-%s' % cls.token
            cls.galaxy = {'uuid': str(uuidlib.uuid4()), 'type': cls.galaxy_type,
                          'name': 'regression gate %s' % cls.token, 'description': 'regression',
                          'version': 1, 'namespace': 'regression'}
            seed = cls._new_cluster(0, with_galaxy=True)
            cls.galaxy_id = int(cls._stored(seed)['galaxy_id'])
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def _new_cluster(cls, distribution, with_galaxy=False):
        cluster_uuid = str(uuidlib.uuid4())
        cls.cluster_uuids.append(cluster_uuid)
        body = cls._body(cluster_uuid, 'original %s' % random(), 1, distribution)
        if with_galaxy:
            body['GalaxyCluster']['Galaxy'] = cls.galaxy
        response = cls.owner._prepare_request('POST', 'galaxies/import', data=[body])
        assert response.status_code == 200, 'seeding a cluster failed: %s' % response.text[:300]
        return cluster_uuid

    @classmethod
    def _body(cls, cluster_uuid, value, version, distribution):
        return {'GalaxyCluster': {'uuid': cluster_uuid, 'type': cls.galaxy_type, 'value': value,
                                  'description': 'regression', 'version': version,
                                  'distribution': distribution}}

    @classmethod
    def _stored(cls, cluster_uuid):
        response = cls.admin._prepare_request('GET', 'galaxy_clusters/view/%s' % cluster_uuid)
        if response.status_code != 200:
            return None
        return response.json()['GalaxyCluster']

    @classmethod
    def tearDownClass(cls):
        for cluster_uuid in cls.cluster_uuids:
            found = cls._stored(cluster_uuid)
            if found:
                cls.admin._prepare_request('POST', 'galaxy_clusters/delete/%s/1' % found['id'],
                                           data={'hard': 1})
            cls.admin._prepare_request('POST', 'galaxy_cluster_blocklists/delete/%s' % cluster_uuid)
        if cls.galaxy_id is not None:
            cls.admin._prepare_request('POST', 'galaxies/delete/%d' % cls.galaxy_id)
        drop_fixtures(cls.admin, cls.created_orgs, cls.created_users)

    def _import(self, api, cluster_uuid, value, distribution=3):
        body = self._body(cluster_uuid, value, 2, distribution)
        return api._prepare_request('POST', 'galaxies/import', data=[body])

    def _assert_unchanged(self, cluster_uuid, before, what):
        after = self._stored(cluster_uuid)
        for field in ('value', 'distribution', 'version', 'org_id', 'orgc_id'):
            self.assertEqual(before[field], after[field],
                             '%s changed %s of a cluster it may not update' % (what, field))

    def _assert_updated(self, cluster_uuid, before, value, what):
        after = self._stored(cluster_uuid)
        self.assertEqual(value, after['value'], '%s: an allowed update was not applied' % what)
        self.assertEqual(before['org_id'], after['org_id'], '%s changed the cluster org_id' % what)
        self.assertEqual(before['orgc_id'], after['orgc_id'], '%s changed the cluster orgc_id' % what)

    def _refused(self, api, distribution, what):
        cluster_uuid = self._new_cluster(distribution)
        before = self._stored(cluster_uuid)
        self._import(api, cluster_uuid, 'hijacked %s' % random(), 3)
        self._assert_unchanged(cluster_uuid, before, what)

    def _accepted(self, api, distribution, what):
        cluster_uuid = self._new_cluster(distribution)
        before = self._stored(cluster_uuid)
        value = 'updated %s' % random()
        self._import(api, cluster_uuid, value)
        self._assert_updated(cluster_uuid, before, value, what)

    def test_other_org_cannot_replace_hidden_cluster(self):
        self._refused(self.other, 0, 'an unrelated editor importing a newer version')

    def test_other_org_cannot_replace_visible_cluster(self):
        self._refused(self.other, 3, 'an unrelated editor importing a visible cluster')

    def test_owner_can_update_own_cluster(self):
        self._accepted(self.owner, 0, 'the owner re-importing')

    def test_sync_user_updates_visible_cluster_without_taking_ownership(self):
        self._accepted(self.syncer, 3, 'a sync user updating a visible cluster')

    def test_sync_user_cannot_replace_hidden_cluster(self):
        self._refused(self.syncer, 0, 'a sync user importing a cluster it cannot see')

    def test_site_admin_updates_without_taking_ownership(self):
        self._accepted(self.admin, 0, 'the site admin importing')


class GalaxyCaptureUpdateGate(unittest.TestCase):
    """A galaxy carried by an imported cluster may change an existing non-default galaxy only for
    a site admin, its owner organisation, or a sync user that can see it, never a default galaxy,
    and an update never changes the galaxy's org_id, orgc_id or default flag.
    """

    FIELDS = ('name', 'description', 'distribution', 'version', 'org_id', 'orgc_id', 'default')

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        cls.created_orgs = []
        cls.created_users = []
        cls.cluster_uuids = []
        cls.galaxy_ids = []
        cls.default_before = None
        cls.restore_report = []
        try:
            editor_role = least_privileged_role(cls.admin, 'perm_galaxy_editor')
            sync_role = None
            for entry in send(cls.admin, 'GET', 'roles'):
                role = entry['Role'] if 'Role' in entry else entry
                if (int(role['perm_sync']) and int(role['perm_galaxy_editor'])
                        and not int(role['perm_site_admin'])):
                    sync_role = int(role['id'])
                    break
            if sync_role is None:
                raise unittest.SkipTest('no non-admin role with perm_sync and perm_galaxy_editor')
            cls.owner_org = make_org(cls.admin, 'regression galaxy owner org')
            cls.other_org = make_org(cls.admin, 'regression galaxy other org')
            cls.sync_org = make_org(cls.admin, 'regression galaxy sync org')
            cls.created_orgs = [cls.owner_org, cls.other_org, cls.sync_org]
            users = [make_user(cls.admin, cls.owner_org.id, editor_role),
                     make_user(cls.admin, cls.other_org.id, editor_role),
                     make_user(cls.admin, cls.sync_org.id, sync_role)]
            cls.created_users = users
            cls.owner, cls.other, cls.syncer = [PyMISP(url, u.authkey) for u in users]
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def _stored_galaxy(cls, galaxy_id):
        response = cls.admin._prepare_request('GET', 'galaxies/view/%s' % galaxy_id)
        if response.status_code != 200:
            return None
        return response.json()['Galaxy']

    @classmethod
    def _stored_cluster(cls, cluster_uuid):
        response = cls.admin._prepare_request('GET', 'galaxy_clusters/view/%s' % cluster_uuid)
        if response.status_code != 200:
            return None
        return response.json()['GalaxyCluster']

    @classmethod
    def _cluster_body(cls, galaxy):
        cluster_uuid = str(uuidlib.uuid4())
        cls.cluster_uuids.append(cluster_uuid)
        return cluster_uuid, [{'GalaxyCluster': {
            'uuid': cluster_uuid, 'type': galaxy['type'], 'value': 'regression %s' % random(),
            'description': 'regression', 'version': 1, 'distribution': 3, 'Galaxy': galaxy}}]

    @classmethod
    def _new_galaxy(cls, distribution):
        galaxy = {'uuid': str(uuidlib.uuid4()), 'type': 'regression-galaxy-%s' % random(),
                  'name': 'regression galaxy %s' % random(), 'description': 'regression',
                  'version': 1, 'namespace': 'regression', 'distribution': distribution}
        cluster_uuid, body = cls._cluster_body(galaxy)
        response = cls.owner._prepare_request('POST', 'galaxies/import', data=body)
        assert response.status_code == 200, 'seeding a galaxy failed: %s' % response.text[:300]
        stored = cls._stored_cluster(cluster_uuid)
        assert stored, 'the seeded cluster was not stored'
        cls.galaxy_ids.append(int(stored['galaxy_id']))
        return cls._stored_galaxy(stored['galaxy_id'])

    def _attempt(self, api, galaxy):
        """Import a new cluster whose payload galaxy tries to rewrite the stored one.

        A stored version 0 becomes a timestamp, so only the changed icon makes the non-forced
        misp-galaxy update rewrite a default galaxy that was overwritten.
        """
        payload = {'uuid': galaxy['uuid'], 'type': galaxy['type'],
                   'name': 'rewritten %s' % random(), 'description': 'rewritten %s' % random(),
                   'distribution': 0, 'version': 0, 'icon': 'regression-icon',
                   'namespace': galaxy.get('namespace', '')}
        cluster_uuid, body = self._cluster_body(payload)
        response = api._prepare_request('POST', 'galaxies/import', data=body)
        self.assertEqual(200, response.status_code, 'the import was refused: %s' % response.text[:300])
        return payload, cluster_uuid

    def _assert_unchanged(self, before, what):
        after = self._stored_galaxy(before['id'])
        for field in self.FIELDS:
            self.assertEqual(str(before[field]), str(after[field]),
                             '%s changed %s of a galaxy it may not update' % (what, field))

    def _assert_updated(self, before, payload, what):
        after = self._stored_galaxy(before['id'])
        self.assertEqual(payload['name'], after['name'], '%s: an allowed update was not applied' % what)
        for field in ('org_id', 'orgc_id', 'default'):
            self.assertEqual(str(before[field]), str(after[field]), '%s changed the galaxy %s' % (what, field))

    @classmethod
    def tearDownClass(cls):
        try:
            cls._restore_default()
        finally:
            for cluster_uuid in cls.cluster_uuids:
                found = cls._stored_cluster(cluster_uuid)
                if found:
                    cls.admin._prepare_request('POST', 'galaxy_clusters/delete/%s/1' % found['id'],
                                               data={'hard': 1})
                cls.admin._prepare_request('POST', 'galaxy_cluster_blocklists/delete/%s' % cluster_uuid)
            for galaxy_id in cls.galaxy_ids:
                cls.admin._prepare_request('POST', 'galaxies/delete/%d' % galaxy_id)
            drop_fixtures(cls.admin, cls.created_orgs, cls.created_users)

    @classmethod
    def _restore_default(cls):
        before = cls.default_before
        if not before:
            return
        now = cls._stored_galaxy(before['id'])
        if now and all(str(now[f]) == str(before[f]) for f in cls.FIELDS):
            return
        started = time.time()
        response = cls.admin._prepare_request('POST', 'galaxies/update')
        elapsed = time.time() - started
        now = cls._stored_galaxy(before['id'])
        exact = bool(now) and all(str(now[f]) == str(before[f]) for f in cls.FIELDS)
        cls.restore_report.append('restore of the default galaxy took %.1fs (HTTP %s), row %s the snapshot'
                                  % (elapsed, response.status_code, 'matches' if exact else 'DIFFERS FROM'))
        print('\n' + cls.restore_report[-1])
        assert exact, 'the default galaxy was not restored: %s' % cls.restore_report[-1]

    def test_other_org_cannot_update_visible_galaxy(self):
        before = self._new_galaxy(3)
        self._attempt(self.other, before)
        self._assert_unchanged(before, 'an unrelated editor importing a visible galaxy')

    def test_other_org_cannot_update_hidden_galaxy(self):
        before = self._new_galaxy(0)
        self._attempt(self.other, before)
        self._assert_unchanged(before, 'an unrelated editor importing a hidden galaxy')

    def test_owner_can_update_own_galaxy(self):
        before = self._new_galaxy(0)
        payload, _ = self._attempt(self.owner, before)
        self._assert_updated(before, payload, 'the owner re-importing')

    def test_sync_user_updates_visible_galaxy_without_taking_ownership(self):
        before = self._new_galaxy(3)
        payload, _ = self._attempt(self.syncer, before)
        self._assert_updated(before, payload, 'a sync user updating a visible galaxy')

    def test_sync_user_cannot_update_hidden_galaxy(self):
        before = self._new_galaxy(0)
        self._attempt(self.syncer, before)
        self._assert_unchanged(before, 'a sync user importing a galaxy it cannot see')

    def test_site_admin_updates_without_taking_ownership(self):
        before = self._new_galaxy(0)
        payload, _ = self._attempt(self.admin, before)
        self._assert_updated(before, payload, 'the site admin importing')

    def test_default_galaxy_is_never_changed(self):
        listing = send(self.admin, 'GET', 'galaxies/index')
        chosen = None
        for entry in listing:
            galaxy = entry['Galaxy'] if 'Galaxy' in entry else entry
            if int(galaxy['default']) and int(galaxy['org_id']) == 0:
                chosen = galaxy
                break
        if chosen is None:
            self.skipTest('no default galaxy on the instance')
        type(self).default_before = self._stored_galaxy(chosen['id'])
        before = self.default_before
        print('\ndefault galaxy used: %s (id %s)' % (before['name'], before['id']))
        try:
            for api, who in ((self.other, 'an unrelated editor'), (self.admin, 'the site admin')):
                payload, cluster_uuid = self._attempt(api, before)
                self._assert_unchanged(before, '%s importing a default galaxy' % who)
                cluster = self._stored_cluster(cluster_uuid)
                self.assertTrue(cluster, 'the cluster was refused along with the galaxy update')
                self.assertEqual(str(before['id']), str(cluster['galaxy_id']),
                                 'the cluster did not go into the default galaxy')
                self.admin._prepare_request('POST', 'galaxy_clusters/delete/%s/1' % cluster['id'],
                                            data={'hard': 1})
        finally:
            self._restore_default()


class ProtectedEventSyncWrites(unittest.TestCase):
    """A protected event may be changed by an external sync user only through events/edit with a
    valid signature; no other write route (attributes, objects, populate, publish, tags, reports,
    galaxy clusters, cryptographic keys, unprotect) may be used by that user to change it.

    Only events/edit checked the protection, so the creator organisation's sync user could change
    a protected event through every other route without a signature.
    """

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        cls.created_orgs = []
        cls.created_users = []
        cls.created_roles = []
        cls.event_ids = []
        cls.event_uuids = []
        cls.tag_id = None
        cls.cluster_id = None
        cls.gnupg_home = None
        try:
            org_role = least_privileged_role(cls.admin, 'perm_modify_org', 'perm_publish',
                                             'perm_tagger')
            ext_role = None
            int_role = None
            for entry in send(cls.admin, 'GET', 'roles'):
                role = entry['Role'] if 'Role' in entry else entry
                if int(role['perm_site_admin']) or not int(role['perm_sync']):
                    continue
                if any(not int(role.get(p, 0) or 0)
                       for p in ('perm_modify_org', 'perm_publish', 'perm_tagger')):
                    continue
                if int(role.get('perm_sync_internal', 0) or 0):
                    int_role = int_role or role
                else:
                    ext_role = ext_role or role
            if ext_role is None:
                raise unittest.SkipTest('no external sync role with modify_org, publish, tagger')
            ext_role_id = int(ext_role['id'])
            int_role_id = int(int_role['id']) if int_role else None
            if int_role_id is None:
                body = {k: v for k, v in ext_role.items()
                        if k.startswith('perm_') and k != 'perm_sync_internal'}
                body['perm_sync_internal'] = 1
                body['permission'] = 3
                body['name'] = 'regression internal sync %s' % random()
                response = cls.admin._prepare_request('POST', 'admin/roles/add', data={'Role': body})
                created = response.json() if response.status_code == 200 else {}
                created = created.get('Role', created)
                if created.get('id') and int(created.get('perm_sync_internal', 0)):
                    int_role_id = int(created['id'])
                    cls.created_roles.append(int_role_id)
            cls.corg = make_org(cls.admin, 'regression protected org')
            cls.created_orgs = [cls.corg]
            cls.org_admin_user = make_user(cls.admin, cls.corg.id, org_role)
            cls.ext_user = make_user(cls.admin, cls.corg.id, ext_role_id)
            cls.created_users = [cls.org_admin_user, cls.ext_user]
            cls.int_user = None
            if int_role_id is not None:
                cls.int_user = make_user(cls.admin, cls.corg.id, int_role_id)
                cls.created_users.append(cls.int_user)
            cls.org_admin = PyMISP(url, cls.org_admin_user.authkey)
            cls.ext = PyMISP(url, cls.ext_user.authkey)
            cls.internal = PyMISP(url, cls.int_user.authkey) if cls.int_user else None
            cls.tag_name = 'regression-protected-%s' % random()
            tag = send(cls.admin, 'POST', 'tags/add', {'name': cls.tag_name})
            cls.tag_id = int(tag['Tag']['id'])
            cls.pgp_key = cls._make_pgp_key()
            cls.template_id = None
            for entry in send(cls.admin, 'GET', 'objectTemplates/index'):
                template = entry['ObjectTemplate'] if 'ObjectTemplate' in entry else entry
                if template['name'] == 'domain-ip':
                    cls.template_id = int(template['id'])
            if cls.template_id is None:
                raise unittest.SkipTest('no domain-ip object template')
            for galaxy in send(cls.admin, 'GET', 'galaxies/index'):
                galaxy = galaxy['Galaxy'] if 'Galaxy' in galaxy else galaxy
                clusters = send(cls.admin, 'GET', 'galaxy_clusters/index/%s' % galaxy['id'])
                if clusters:
                    cluster = clusters[0]
                    cluster = cluster['GalaxyCluster'] if 'GalaxyCluster' in cluster else cluster
                    cls.cluster_id = int(cluster['id'])
                    break
            if cls.cluster_id is None:
                raise unittest.SkipTest('no galaxy cluster on the instance')
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def _make_pgp_key(cls):
        base = os.environ.get('REGRESSION_TMP') or tempfile.gettempdir()
        cls.gnupg_home = tempfile.mkdtemp(prefix='regression-gnupg-', dir=base)
        os.chmod(cls.gnupg_home, 0o700)
        env = dict(os.environ, GNUPGHOME=cls.gnupg_home)
        try:
            subprocess.run(['gpg', '--batch', '--passphrase', '', '--quick-generate-key',
                            'regression-%s@test.local' % random(), 'rsa2048', 'sign', '1d'],
                           env=env, check=True, capture_output=True, timeout=120)
            exported = subprocess.run(['gpg', '--batch', '--armor', '--export'], env=env,
                                      check=True, capture_output=True, timeout=30)
            return exported.stdout.decode()
        except Exception:
            shutil.rmtree(cls.gnupg_home, ignore_errors=True)
            cls.gnupg_home = None
            return None

    @classmethod
    def tearDownClass(cls):
        for event_id in getattr(cls, 'event_ids', []):
            cls.admin._prepare_request('POST', 'events/delete/%s' % event_id, data={'hard': 1})
        uuids = getattr(cls, 'event_uuids', [])
        for row in send(cls.admin, 'GET', 'eventBlocklists/index', check_errors=False) or []:
            row = row.get('EventBlocklist', row) if isinstance(row, dict) else {}
            if row.get('event_uuid') in uuids:
                send(cls.admin, 'POST', 'eventBlocklists/delete/%s' % row['id'], check_errors=False)
        if getattr(cls, 'tag_id', None) is not None:
            cls.admin._prepare_request('POST', 'tags/delete/%d' % cls.tag_id)
        drop_fixtures(cls.admin, getattr(cls, 'created_orgs', []), getattr(cls, 'created_users', []))
        for role_id in getattr(cls, 'created_roles', []):
            cls.admin._prepare_request('POST', 'admin/roles/delete/%d' % role_id)
        if getattr(cls, 'gnupg_home', None):
            shutil.rmtree(cls.gnupg_home, ignore_errors=True)

    def _stored(self):
        response = self.admin._prepare_request('POST', 'events/restSearch',
            data={'eventid': self.event_id, 'returnFormat': 'json'})
        self.assertEqual(200, response.status_code, response.text[:300])
        return response.json()['response'][0]['Event']

    def _build_event(self):
        event = send(self.org_admin, 'POST', 'events/add',
                     {'info': 'regression protected %s' % random(), 'distribution': 0,
                      'threat_level_id': 4, 'analysis': 0})['Event']
        self.event_id = int(event['id'])
        type(self).event_ids.append(self.event_id)
        type(self).event_uuids.append(event['uuid'])
        for _ in range(2):
            send(self.org_admin, 'POST', 'attributes/add/%d' % self.event_id,
                 {'type': 'comment', 'category': 'Other', 'value': 'seed %s' % random()})
        send(self.org_admin, 'POST', 'objects/add/%d/%d' % (self.event_id, self.template_id),
             {'name': 'domain-ip', 'meta-category': 'network', 'distribution': 0,
              'Attribute': [{'object_relation': 'domain', 'type': 'domain',
                             'category': 'Network activity', 'value': '%s.example' % random(),
                             'distribution': 0}]})
        send(self.org_admin, 'POST', 'eventReports/add/%d' % self.event_id,
             {'name': 'report %s' % random(), 'content': 'original content', 'distribution': 0})
        send(self.org_admin, 'POST', 'galaxies/attachCluster/%d/event' % self.event_id,
             {'Galaxy': {'target_id': self.cluster_id}})
        send(self.org_admin, 'POST', 'events/protect/%d' % self.event_id)
        stored = self._stored()
        self.assertTrue(int(stored['protected']), 'the event did not become protected')
        self.assertTrue(stored['Attribute'] and stored['Object'] and stored['EventReport']
                        and stored['Galaxy'], 'the event was not built as expected')
        return stored

    def setUp(self):
        self.stored = self._build_event()

    def _refused(self, response):
        self.assertTrue(400 <= response.status_code < 500,
                        'expected a 4xx, got %s: %s' % (response.status_code, response.text[:200]))

    def _plain_attribute(self, event=None):
        event = event or self.stored
        return [a for a in event['Attribute'] if not int(a.get('object_id', 0))][0]

    def test_sync_user_cannot_add_attribute(self):
        n = len(self.stored['Attribute'])
        response = self.ext._prepare_request('POST', 'attributes/add/%d' % self.event_id,
            data={'type': 'comment', 'category': 'Other', 'value': 'inject %s' % random()})
        self._refused(response)
        self.assertEqual(n, len(self._stored()['Attribute']))

    def test_sync_user_cannot_edit_attribute(self):
        attribute = self._plain_attribute()
        response = self.ext._prepare_request('POST', 'attributes/edit/%s' % attribute['id'],
            data={'value': 'changed %s' % random()})
        self._refused(response)
        after = [a for a in self._stored()['Attribute'] if a['id'] == attribute['id']][0]
        self.assertEqual(attribute['value'], after['value'])

    def test_sync_user_cannot_delete_attribute(self):
        attribute = self._plain_attribute()
        response = self.ext._prepare_request('POST', 'attributes/delete/%s' % attribute['id'],
            data={'hard': 1})
        self._refused(response)
        ids = [a['id'] for a in self._stored()['Attribute']]
        self.assertIn(attribute['id'], ids)

    def test_sync_user_cannot_delete_object(self):
        object_id = self.stored['Object'][0]['id']
        response = self.ext._prepare_request('POST', 'objects/delete/%s/1' % object_id)
        self._refused(response)
        self.assertEqual([object_id], [o['id'] for o in self._stored()['Object']])

    def test_sync_user_cannot_populate(self):
        n = len(self.stored['Attribute'])
        body = {'Attribute': [{'type': 'comment', 'category': 'Other',
                               'value': 'populated %s' % random()}]}
        response = self.ext._prepare_request('POST', 'events/populate/%d' % self.event_id,
                                             data=body)
        self._refused(response)
        self.assertEqual(n, len(self._stored()['Attribute']))

    def test_sync_user_cannot_unprotect(self):
        response = self.ext._prepare_request('POST', 'events/unprotect/%d' % self.event_id)
        self._refused(response)
        self.assertTrue(int(self._stored()['protected']))

    def test_sync_user_cannot_publish(self):
        response = self.ext._prepare_request('POST', 'events/publish/%d' % self.event_id)
        self._refused(response)
        self.assertFalse(int(self._stored()['published']))

    def test_sync_user_cannot_attach_tag(self):
        response = self.ext._prepare_request('POST', 'tags/attachTagToObject',
            data={'uuid': self.stored['uuid'], 'tag': self.tag_name})
        self._refused(response)
        self.assertNotIn(self.tag_name, [t['name'] for t in self._stored().get('Tag', [])])

    def test_sync_user_cannot_edit_report(self):
        report = self.stored['EventReport'][0]
        response = self.ext._prepare_request('POST', 'eventReports/edit/%s' % report['id'],
            data={'content': 'changed %s' % random()})
        self._refused(response)
        after = self._stored()['EventReport'][0]
        self.assertEqual(report['content'], after['content'])

    def test_sync_user_cannot_detach_cluster(self):
        galaxy_tags = [t for t in self._stored().get('Tag', []) if 'misp-galaxy:' in t['name']]
        self.assertTrue(galaxy_tags, 'no galaxy tag on the event')
        response = self.ext._prepare_request('POST', 'galaxy_clusters/detach/%d/event/%s' % (
            self.event_id, galaxy_tags[0]['id']))
        self._refused(response)
        still = [t['id'] for t in self._stored().get('Tag', [])]
        self.assertIn(galaxy_tags[0]['id'], still)

    def test_sync_user_cannot_add_cryptographic_key(self):
        if self.pgp_key:
            key_data = self.pgp_key
        else:
            key_data = '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----'
        response = self.ext._prepare_request('POST', 'cryptographicKeys/add/Event/%d' % self.event_id,
            data={'CryptographicKey': {'type': 'pgp', 'key_data': key_data}})
        self._refused(response)
        # Without a GnuPG home the instance refuses any key: only the protection's refusal counts.
        self.assertIn('protected', response.text)
        self.assertFalse(self._stored().get('CryptographicKey'))

    def test_control_internal_sync_user_can_delete_attribute(self):
        if self.internal is None:
            self.skipTest('no internal sync role could be created')
        attribute = self._plain_attribute()
        response = self.internal._prepare_request('POST', 'attributes/delete/%s' % attribute['id'],
                                                  data={'hard': 1})
        self.assertEqual(200, response.status_code, response.text[:300])
        self.assertNotIn(attribute['id'], [a['id'] for a in self._stored()['Attribute']])

    def test_control_org_admin_can_add_attribute(self):
        n = len(self.stored['Attribute'])
        send(self.org_admin, 'POST', 'attributes/add/%d' % self.event_id,
             {'type': 'comment', 'category': 'Other', 'value': 'added %s' % random()})
        self.assertEqual(n + 1, len(self._stored()['Attribute']))

    def test_control_sync_user_can_delete_after_unprotect(self):
        send(self.org_admin, 'POST', 'events/unprotect/%d' % self.event_id)
        self.assertFalse(int(self._stored()['protected']))
        attribute = self._plain_attribute()
        response = self.ext._prepare_request('POST', 'attributes/delete/%s' % attribute['id'],
                                             data={'hard': 1})
        self.assertEqual(200, response.status_code, response.text[:300])
        self.assertNotIn(attribute['id'], [a['id'] for a in self._stored()['Attribute']])


class ObjectReferenceCaptureScope(unittest.TestCase):
    """Saving an event may update an existing object reference, matched by uuid, only when that
    reference belongs to the event being saved; a reference uuid owned by another organisation's
    event is skipped, never overwritten and never recreated in the saving event.

    The lookup was by uuid across the whole instance, so a user saving their own event could
    rewrite timestamp, relationship_type, comment and deleted on a reference in an event they
    cannot see.
    """

    FIELDS = ('timestamp', 'relationship_type', 'comment', 'deleted')
    FAR_FUTURE = 2147480000

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        cls.created_orgs = []
        cls.created_users = []
        cls.event_ids = []
        cls.event_uuids = []
        try:
            role = least_privileged_role(cls.admin, 'perm_add', 'perm_modify_org')
            cls.victim_org = make_org(cls.admin, 'regression reference victim')
            cls.attacker_org = make_org(cls.admin, 'regression reference attacker')
            cls.created_orgs = [cls.victim_org, cls.attacker_org]
            cls.victim_user = make_user(cls.admin, cls.victim_org.id, role)
            cls.attacker_user = make_user(cls.admin, cls.attacker_org.id, role)
            cls.created_users = [cls.victim_user, cls.attacker_user]
            cls.victim = PyMISP(url, cls.victim_user.authkey)
            cls.attacker = PyMISP(url, cls.attacker_user.authkey)
            cls.template = None
            for entry in send(cls.admin, 'GET', 'objectTemplates/index'):
                template = entry['ObjectTemplate'] if 'ObjectTemplate' in entry else entry
                if template['name'] == 'domain-ip':
                    cls.template = template
            if cls.template is None:
                raise unittest.SkipTest('no domain-ip object template')
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for event_id in getattr(cls, 'event_ids', []):
            cls.admin._prepare_request('POST', 'events/delete/%s' % event_id, data={'hard': 1})
        uuids = getattr(cls, 'event_uuids', [])
        for row in send(cls.admin, 'GET', 'eventBlocklists/index', check_errors=False) or []:
            row = row.get('EventBlocklist', row) if isinstance(row, dict) else {}
            if row.get('event_uuid') in uuids:
                send(cls.admin, 'POST', 'eventBlocklists/delete/%s' % row['id'], check_errors=False)
        drop_fixtures(cls.admin, getattr(cls, 'created_orgs', []), getattr(cls, 'created_users', []))

    @classmethod
    def _object(cls):
        return {'name': 'domain-ip', 'meta-category': 'network', 'uuid': str(uuidlib.uuid4()),
                'template_uuid': cls.template['uuid'], 'template_version': cls.template['version'],
                'distribution': 0,
                'Attribute': [{'object_relation': 'domain', 'type': 'domain',
                               'category': 'Network activity', 'uuid': str(uuidlib.uuid4()),
                               'value': '%s.example' % random(), 'distribution': 0}]}

    @classmethod
    def _add_event(cls, connector, objects):
        event = send(connector, 'POST', 'events/add',
                     {'info': 'regression reference %s' % random(), 'distribution': 0,
                      'threat_level_id': 4, 'analysis': 0, 'Object': objects})['Event']
        cls.event_ids.append(int(event['id']))
        cls.event_uuids.append(event['uuid'])
        return event

    @classmethod
    def _references(cls, event_id):
        """Every reference of the event as the admin stores it, soft-deleted ones included."""
        response = cls.admin._prepare_request('POST', 'events/restSearch',
            data={'eventid': event_id, 'returnFormat': 'json', 'deleted': [0, 1]})
        assert response.status_code == 200, response.text[:300]
        found = []
        for obj in response.json()['response'][0]['Event'].get('Object', []):
            found.extend(obj.get('ObjectReference', []))
        return found

    def _stored_reference(self):
        for reference in self._references(self.victim_event['id']):
            if reference['uuid'] == self.reference_uuid:
                return {f: str(reference[f]) for f in self.FIELDS}
        return None

    def setUp(self):
        self.reference_uuid = str(uuidlib.uuid4())
        self.victim_objects = [self._object() for _ in range(2)]
        self.victim_objects[0]['ObjectReference'] = [{
            'uuid': self.reference_uuid, 'object_uuid': self.victim_objects[0]['uuid'],
            'referenced_uuid': self.victim_objects[1]['uuid'],
            'relationship_type': 'related-to', 'comment': 'victim comment %s' % random()}]
        self.victim_event = self._add_event(self.victim, self.victim_objects)
        self.baseline = self._stored_reference()
        self.assertIsNotNone(self.baseline, 'the victim reference was not created')

    def _attacker_event_objects(self):
        return [self._object() for _ in range(2)]

    def _forged(self, objects):
        """The forged reference sits on the first object and targets the attacker's own second one."""
        objects[0]['ObjectReference'] = [{
            'uuid': self.reference_uuid, 'object_uuid': objects[0]['uuid'],
            'referenced_uuid': objects[1]['uuid'], 'timestamp': self.FAR_FUTURE,
            'relationship_type': 'false-positive', 'comment': 'forged %s' % random(),
            'deleted': True}]
        return objects

    def _assert_victim_untouched(self):
        self.assertEqual(self.baseline, self._stored_reference())

    def test_event_add_leaves_foreign_reference_alone(self):
        event = self._add_event(self.attacker, self._forged(self._attacker_event_objects()))
        self._assert_victim_untouched()
        self.assertEqual([], [r for r in self._references(event['id'])
                              if r['uuid'] == self.reference_uuid])

    def test_event_edit_leaves_foreign_reference_alone(self):
        event = self._add_event(self.attacker, self._attacker_event_objects())
        edited = {'Object': self._forged(self._attacker_event_objects())}
        send(self.attacker, 'POST', 'events/edit/%s' % event['id'], edited)
        self._assert_victim_untouched()
        self.assertEqual([], [r for r in self._references(event['id'])
                              if r['uuid'] == self.reference_uuid])

    def test_owner_still_updates_its_own_reference(self):
        comment = 'updated %s' % random()
        objects = [dict(o) for o in self.victim_objects]
        objects[0]['ObjectReference'] = [{
            'uuid': self.reference_uuid, 'object_uuid': objects[0]['uuid'],
            'referenced_uuid': objects[1]['uuid'], 'timestamp': self.FAR_FUTURE,
            'comment': comment}]
        send(self.victim, 'POST', 'events/edit/%s' % self.victim_event['id'], {'Object': objects})
        after = self._stored_reference()
        self.assertEqual(comment, after['comment'])
        self.assertEqual(str(self.FAR_FUTURE), after['timestamp'])
        self.assertEqual('related-to', after['relationship_type'])

    def test_new_reference_still_created(self):
        objects = self._attacker_event_objects()
        fresh = str(uuidlib.uuid4())
        objects[0]['ObjectReference'] = [{
            'uuid': fresh, 'object_uuid': objects[0]['uuid'],
            'referenced_uuid': objects[1]['uuid'], 'relationship_type': 'related-to',
            'comment': 'fresh'}]
        event = self._add_event(self.attacker, objects)
        created = [r for r in self._references(event['id']) if r['uuid'] == fresh]
        self.assertEqual(1, len(created))
        self.assertEqual('fresh', created[0]['comment'])
        self.assertEqual(objects[1]['uuid'], created[0]['referenced_uuid'])


class ProposalSyncScope(unittest.TestCase):
    """Proposals pushed through events/pushProposals land only on events the sync user can see,
    carry the local event's identity rather than the sender's, and edit proposals point only at
    an attribute of that same event.

    The event was found by uuid with no ACL (a hidden event answered differently from a missing
    one and accepted proposals), event_org_id, event_uuid and old_id were stored as sent, and an
    edit proposal carrying another event's attribute uuid was stored with the sender's old_id.
    """

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        cls.admin.global_pythonify = True
        cls.created_orgs = []
        cls.created_users = []
        cls.created_roles = []
        cls.captured_org_uuids = []
        cls.event_ids = []
        cls.event_uuids = []
        try:
            role = least_privileged_role(cls.admin, 'perm_add')
            body = {'name': 'regression proposal sync %s' % random(), 'permission': 3,
                    'perm_add': 1, 'perm_modify': 1, 'perm_sync': 1, 'perm_auth': 1}
            response = cls.admin._prepare_request('POST', 'admin/roles/add', data={'Role': body})
            created = response.json() if response.status_code == 200 else {}
            created = created.get('Role', created)
            if not (created.get('id') and int(created.get('perm_sync', 0))
                    and int(created.get('perm_add', 0))):
                raise unittest.SkipTest('could not create a sync role with perm_add')
            cls.created_roles.append(int(created['id']))
            cls.victim_org = make_org(cls.admin, 'regression proposal victim')
            cls.sync_org = make_org(cls.admin, 'regression proposal sync')
            cls.created_orgs = [cls.victim_org, cls.sync_org]
            cls.victim_user = make_user(cls.admin, cls.victim_org.id, role)
            cls.sync_user = make_user(cls.admin, cls.sync_org.id, int(created['id']))
            cls.created_users = [cls.victim_user, cls.sync_user]
            cls.victim = PyMISP(url, cls.victim_user.authkey)
            cls.sync = PyMISP(url, cls.sync_user.authkey)
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        for event_id in getattr(cls, 'event_ids', []):
            cls.admin._prepare_request('POST', 'events/delete/%s' % event_id, data={'hard': 1})
        uuids = getattr(cls, 'event_uuids', [])
        for row in send(cls.admin, 'GET', 'eventBlocklists/index', check_errors=False) or []:
            row = row.get('EventBlocklist', row) if isinstance(row, dict) else {}
            if row.get('event_uuid') in uuids:
                send(cls.admin, 'POST', 'eventBlocklists/delete/%s' % row['id'], check_errors=False)
        drop_fixtures(cls.admin, getattr(cls, 'created_orgs', []), getattr(cls, 'created_users', []))
        for org_uuid in getattr(cls, 'captured_org_uuids', []):
            response = cls.admin._prepare_request('GET', 'organisations/view/%s' % org_uuid)
            if response.status_code == 200:
                found = response.json().get('Organisation', {})
                if found.get('uuid') == org_uuid and found.get('id'):
                    cls.admin._prepare_request('POST', 'admin/organisations/delete/%s' % found['id'])
        for role_id in getattr(cls, 'created_roles', []):
            cls.admin._prepare_request('POST', 'admin/roles/delete/%d' % role_id)

    @classmethod
    def _add_event(cls, distribution, attributes=2):
        event = send(cls.victim, 'POST', 'events/add', {
            'info': 'regression proposal %s' % random(), 'distribution': distribution,
            'threat_level_id': 4, 'analysis': 0,
            'Attribute': [{'type': 'domain', 'category': 'Network activity',
                           'value': '%s.example' % random(), 'uuid': str(uuidlib.uuid4()),
                           'distribution': 5} for _ in range(attributes)]})['Event']
        cls.event_ids.append(int(event['id']))
        cls.event_uuids.append(event['uuid'])
        return event

    def _proposals(self, event_id):
        """Every proposal stored on the event, as the admin sees it."""
        response = self.admin._prepare_request('GET', 'shadow_attributes/index/%s/all:1.json' % event_id)
        self.assertEqual(200, response.status_code, response.text[:300])
        rows = response.json()
        return [row['ShadowAttribute'] if 'ShadowAttribute' in row else row for row in rows]

    def _stored_columns(self, proposal_id):
        """event_org_id and event_uuid of one proposal row: no API output carries the stored
        columns, so read them with the mysql client using this tree's own database.php."""
        config = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'app', 'Config',
                              'database.php')
        try:
            with open(config) as handle:
                text = handle.read()
            default = text[text.index('$default'):]
            creds = {k: re.search(r"'%s'\s*=>\s*'([^']*)'" % k, default).group(1)
                     for k in ('host', 'login', 'password', 'database')}
            out = subprocess.run(
                ['mysql', '-N', '-B', '-h', creds['host'], '-u', creds['login'], '-D',
                 creds['database'], '-e',
                 'SELECT event_org_id, event_uuid FROM shadow_attributes WHERE id = %d'
                 % int(proposal_id)],
                env=dict(os.environ, MYSQL_PWD=creds['password']), check=True,
                capture_output=True, timeout=30).stdout.decode().split()
        except Exception:
            raise unittest.SkipTest('stored proposal columns not readable on this instance')
        return {'event_org_id': out[0], 'event_uuid': out[1]}

    def _proposal(self, event, **override):
        """The shape Server::syncProposals sends: a ShadowAttribute row with an Org block."""
        org_uuid = str(uuidlib.uuid4())
        self.captured_org_uuids.append(org_uuid)
        proposal = {
            'event_id': 0, 'event_uuid': event['uuid'], 'event_org_id': int(event['org_id']),
            'old_id': 0, 'uuid': str(uuidlib.uuid4()), 'type': 'domain',
            'category': 'Network activity', 'value': 'proposal-%s.example' % random(),
            'to_ids': 0, 'comment': 'regression proposal %s' % random(),
            'timestamp': int(time.time()), 'deleted': 0, 'proposal_to_delete': 0,
            'org_id': 0, 'email': '', 'first_seen': None, 'last_seen': None,
            'Org': {'name': 'regression proposer %s' % random(), 'uuid': org_uuid}}
        proposal.update(override)
        return proposal

    def _push(self, uuid, proposals):
        response = self.sync._prepare_request('POST', 'events/pushProposals/%s' % uuid,
                                              data=proposals)
        self.assertEqual(200, response.status_code, response.text[:300])
        return response.json()

    def test_hidden_event_answers_like_missing_event(self):
        hidden = self._add_event(0)
        proposal = self._proposal(hidden)
        answer = self._push(hidden['uuid'], [proposal])
        missing = self._push(str(uuidlib.uuid4()), [self._proposal(hidden)])
        self.assertEqual(missing, answer)
        self.assertEqual({'success': False, 'message': 'Event not found.', 'counter': 0}, answer)
        self.assertEqual([], self._proposals(hidden['id']))

    def test_visible_event_proposal_takes_local_identity(self):
        event = self._add_event(3)
        bogus_uuid = str(uuidlib.uuid4())
        proposal = self._proposal(event, event_uuid=bogus_uuid,
                                  event_org_id=int(self.sync_org.id))
        answer = self._push(event['uuid'], [proposal])
        self.assertTrue(answer['success'], answer)
        self.assertEqual(1, answer['counter'], answer)
        stored = self._proposals(event['id'])
        self.assertEqual([proposal['value']], [p['value'] for p in stored])
        self.assertEqual(event['uuid'], stored[0]['event_uuid'])
        columns = self._stored_columns(stored[0]['id'])
        self.assertEqual(str(event['org_id']), columns['event_org_id'])
        self.assertEqual(event['uuid'], columns['event_uuid'])

    def test_edit_proposal_for_attribute_of_other_event_is_not_stored(self):
        event = self._add_event(3)
        other = self._add_event(0)
        own_attribute = event['Attribute'][0]
        foreign_attribute = other['Attribute'][0]
        misdirected = self._proposal(event, old_id=int(own_attribute['id']),
                                     uuid=foreign_attribute['uuid'])
        answer = self._push(event['uuid'], [misdirected])
        self.assertEqual(0, answer['counter'], answer)
        self.assertEqual('Nothing to update.', answer['message'])
        stored = [p for p in self._proposals(event['id'])
                  if p['uuid'] == foreign_attribute['uuid']]
        self.assertEqual([], stored, 'the proposal for a foreign attribute uuid was stored')
        self.assertEqual([], self._proposals(other['id']))

    def test_edit_proposal_for_attribute_of_the_event_points_at_it(self):
        event = self._add_event(3)
        attribute = event['Attribute'][1]
        proposal = self._proposal(event, old_id=2147480000, uuid=attribute['uuid'],
                                  value='edited-%s.example' % random())
        answer = self._push(event['uuid'], [proposal])
        self.assertEqual(1, answer['counter'], answer)
        stored = self._proposals(event['id'])
        self.assertEqual(1, len(stored))
        self.assertEqual(str(attribute['id']), str(stored[0]['old_id']))
        self.assertEqual(attribute['uuid'], stored[0]['uuid'])

    def test_new_attribute_proposal_keeps_old_id_zero(self):
        event = self._add_event(3)
        answer = self._push(event['uuid'], [self._proposal(event, old_id=0)])
        self.assertEqual(1, answer['counter'], answer)
        self.assertEqual(['0'], [str(p['old_id']) for p in self._proposals(event['id'])])

    def test_same_proposal_pushed_twice_is_stored_once(self):
        event = self._add_event(3)
        proposal = self._proposal(event)
        first = self._push(event['uuid'], [proposal])
        self.assertEqual(1, first['counter'], first)
        second = self._push(event['uuid'], [proposal])
        self.assertEqual(0, second['counter'], second)
        self.assertEqual('Nothing to update.', second['message'])
        self.assertEqual(1, len([p for p in self._proposals(event['id'])
                                 if p['value'] == proposal['value']]))

    def test_duplicate_is_found_whatever_event_uuid_the_sender_gives(self):
        event = self._add_event(3)
        proposal = self._proposal(event)
        self.assertEqual(1, self._push(event['uuid'], [proposal])['counter'])
        again = self._push(event['uuid'], [dict(proposal, event_uuid=str(uuidlib.uuid4()))])
        self.assertEqual(0, again['counter'], again)
        self.assertEqual(1, len([p for p in self._proposals(event['id'])
                                 if p['value'] == proposal['value']]))

    def test_newer_version_of_a_proposal_replaces_the_older(self):
        event = self._add_event(3)
        proposal = self._proposal(event)
        self._push(event['uuid'], [proposal])
        newer = dict(proposal, timestamp=proposal['timestamp'] + 100)
        answer = self._push(event['uuid'], [newer])
        self.assertEqual(1, answer['counter'], answer)
        stored = [p for p in self._proposals(event['id']) if p['value'] == proposal['value']]
        self.assertEqual([str(newer['timestamp'])], [str(p['timestamp']) for p in stored])


if __name__ == '__main__':
    unittest.main()
