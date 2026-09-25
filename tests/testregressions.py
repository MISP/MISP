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
import unittest
import warnings

import urllib3  # type: ignore

try:
    from pymisp import PyMISP, MISPEvent, MISPUser, MISPOrganisation, MISPSighting
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


if __name__ == '__main__':
    unittest.main()
