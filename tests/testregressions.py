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


def ordinary_role_id(admin: PyMISP) -> int:
    """The least privileged non-admin, non-sync role that can still add attributes.

    Looked up rather than hard-coded, so the suite does not assume a particular role table.
    """
    roles = send(admin, 'GET', 'roles')
    candidates = []
    for entry in roles:
        role = entry['Role'] if 'Role' in entry else entry
        if int(role.get('perm_site_admin', 0)) or int(role.get('perm_sync', 0)):
            continue
        if not int(role.get('perm_add', 0)):
            continue
        weight = sum(1 for k, v in role.items() if k.startswith('perm_') and int(v or 0))
        candidates.append((weight, int(role['id'])))
    if not candidates:
        raise unittest.SkipTest('no non-admin role with perm_add on this instance')
    return sorted(candidates)[0][1]


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
        cls.role_id = ordinary_role_id(cls.admin)
        cls.created_users = []
        cls.created_orgs = []

        cls.victim_org = cls._org('regression victim org')
        cls.attacker_org = cls._org('regression attacker org')
        cls.victim_user = cls._user(cls.victim_org.id)
        cls.attacker_user = cls._user(cls.attacker_org.id)
        cls.victim = PyMISP(url, cls.victim_user.authkey)
        cls.victim.global_pythonify = True
        cls.attacker = PyMISP(url, cls.attacker_user.authkey)
        cls.attacker.global_pythonify = True

    @classmethod
    def tearDownClass(cls):
        # events first: an organisation that still owns one cannot be deleted
        for org in cls.created_orgs:
            for event in cls.admin.search(controller='events', org=int(org.id),
                                          metadata=True, pythonify=True):
                cls.admin.delete_event(event)
        for user in cls.created_users:
            cls.admin.delete_user(user)
        for org in cls.created_orgs:
            cls.admin.delete_organisation(org)

    @classmethod
    def _org(cls, label):
        org = MISPOrganisation()
        org.name = '%s %s' % (label, random())
        org = check_response(cls.admin.add_organisation(org))
        cls.created_orgs.append(org)
        return org

    @classmethod
    def _user(cls, org_id):
        user = MISPUser()
        user.email = 'regression-%s@test.local' % random()
        user.org_id = org_id
        user.role_id = cls.role_id
        user = check_response(cls.admin.add_user(user))
        cls.created_users.append(user)
        return user

    def _event(self, connector, label):
        event = MISPEvent()
        event.info = '%s %s' % (label, random())
        event.distribution = 0        # organisation only
        return check_response(connector.add_event(event))

    def _victim_attribute(self):
        """An attribute in an organisation-only event of an organisation the attacker is not in."""
        event = self._event(self.victim, 'regression victim event')
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
        own = self._event(self.attacker, 'regression attacker event')
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
        own = self._event(self.attacker, 'regression attacker event')
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

        own = self._event(self.attacker, 'regression attacker event')
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


if __name__ == '__main__':
    unittest.main()
