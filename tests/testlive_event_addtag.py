#!/usr/bin/env python3
"""
Regression guard for the single-event `/events/addTag/{id}` contract.

T1 of docs/dev/event-index-mass-actions-prd.md (§9.1): locks the current
behavior of EventsController::addTag BEFORE the 'selected' bulk-tagging
refactor (T2). Run against the unmodified instance first, then re-run
after the refactor — message wording may change consciously, semantics
must not.

Covers: single tag id (body and URL), JSON tag list, tag name,
collection_N expansion, local:1, duplicate skip, local_only constraint,
unpublish side effect, UUID/body event references, invalid event/tag/
collection, and no-permission cases (foreign-org tagger, global and
local).

Usage:
    HOST=localhost:5007 AUTH=<site-admin-key> python3 testlive_event_addtag.py -v

Falls back to tests/keys.py (url/key) when the env vars are unset.
"""
import json
import os
import unittest
import uuid
import warnings

from pymisp import PyMISP, MISPOrganisation, MISPUser

try:
    url = "http://" + os.environ["HOST"]
    key = os.environ["AUTH"]
except KeyError:
    import keys
    url = keys.url
    key = keys.key


def random() -> str:
    return str(uuid.uuid4()).split("-")[0]


def check_response(response):
    if isinstance(response, dict) and "errors" in response:
        raise Exception(response["errors"])
    return response


def send(api: PyMISP, request_type: str, path: str, data=None, check_errors: bool = True) -> dict:
    if data is None:
        data = {}
    response = api._prepare_request(request_type, path, data=data)
    response = api._check_response(response)
    if check_errors:
        check_response(response)
    return response


class TestEventAddTag(unittest.TestCase):
    """Single-event addTag contract — pre-refactor regression guard."""

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        assert cls.admin._current_role.perm_site_admin

        # Org A owns the test events; its user tags its own events.
        cls.org_a = cls._create_org_with_user('A')
        # Org B is neither owner nor host org; its user must be refused.
        cls.org_b = cls._create_org_with_user('B')

        cls.tag_a = cls._create_tag()
        cls.tag_b = cls._create_tag()
        cls.tag_local_only = cls._create_tag({'local_only': 1})

        cls.events = []
        cls.collections = []

    @classmethod
    def tearDownClass(cls):
        for event_id in cls.events:
            send(cls.admin, 'POST', f'events/delete/{event_id}', check_errors=False)
        for collection_id in cls.collections:
            send(cls.admin, 'POST', f'tagCollections/delete/{collection_id}', check_errors=False)
        for tag in (cls.tag_a, cls.tag_b, cls.tag_local_only):
            send(cls.admin, 'POST', f"tags/delete/{tag['id']}", check_errors=False)
        for fixture in (cls.org_a, cls.org_b):
            cls.admin.delete_user(fixture['user'])
            cls.admin.delete_organisation(fixture['org'])

    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)

    @classmethod
    def _create_org_with_user(cls, label: str) -> dict:
        org = MISPOrganisation()
        org.name = f'addTag Test Org {label} ' + random()
        org = cls.admin.add_organisation(org, pythonify=True)
        check_response(org)
        user = MISPUser()
        user.email = f'addtag.{label.lower()}.{random()}@user.local'
        user.org_id = org.id
        user.role_id = 2  # org admin: guaranteed perm_tagger + perm_modify
        user = cls.admin.add_user(user, pythonify=True)
        check_response(user)
        authkey = send(cls.admin, 'POST', f'authKeys/add/{user.id}')['AuthKey']['authkey_raw']
        connector = PyMISP(url, authkey)
        assert connector._current_role.perm_tagger
        assert not connector._current_role.perm_site_admin
        return {'org': org, 'user': user, 'api': connector}

    @classmethod
    def _create_tag(cls, extra: dict = None) -> dict:
        data = {'name': 'addtag-regression-' + random(), 'colour': '#112233'}
        data.update(extra or {})
        return send(cls.admin, 'POST', 'tags/add', data)['Tag']

    def _create_event(self, api: PyMISP = None) -> dict:
        api = api or self.org_a['api']
        event = send(api, 'POST', 'events/add', {
            'info': 'addTag regression ' + random(),
            'distribution': 0,
            'analysis': 0,
            'threat_level_id': 4,
        })['Event']
        self.events.append(event['id'])
        return event

    def _add_tag(self, api: PyMISP, event_ref, payload: dict = None, local: bool = False,
                 tag_url=None) -> dict:
        path = f'events/addTag/{event_ref}'
        if tag_url is not None:
            path += f'/{tag_url}'
        if local:
            path += '/local:1'
        return send(api, 'POST', path, data=payload or {}, check_errors=False)

    def _event_tags(self, event_id) -> dict:
        event = send(self.admin, 'GET', f'events/view/{event_id}')['Event']
        return {tag['name']: tag for tag in event.get('Tag', [])}

    def _published(self, event_id) -> bool:
        return bool(send(self.admin, 'GET', f'events/view/{event_id}')['Event']['published'])

    def test_invalid_event(self):
        response = self._add_tag(self.org_a['api'], 99999999, {'tag': self.tag_a['id']})
        self.assertFalse(response['saved'])
        self.assertEqual('Invalid event.', response['errors'])

    def test_single_tag_by_id(self):
        event = self._create_event()
        response = self._add_tag(self.org_a['api'], event['id'], {'tag': self.tag_a['id']})
        self.assertTrue(response['saved'], response)
        self.assertEqual('Tag added.', response['success'])
        self.assertTrue(response['check_publish'])
        tags = self._event_tags(event['id'])
        self.assertIn(self.tag_a['name'], tags)
        self.assertFalse(bool(tags[self.tag_a['name']]['local']))

    def test_single_tag_by_id_in_url(self):
        event = self._create_event()
        response = self._add_tag(self.org_a['api'], event['id'], tag_url=self.tag_a['id'])
        self.assertTrue(response['saved'], response)
        self.assertIn(self.tag_a['name'], self._event_tags(event['id']))

    def test_tag_json_list(self):
        event = self._create_event()
        payload = {'tag': json.dumps([int(self.tag_a['id']), int(self.tag_b['id'])])}
        response = self._add_tag(self.org_a['api'], event['id'], payload)
        self.assertTrue(response['saved'], response)
        self.assertEqual('Tags added.', response['success'])
        tags = self._event_tags(event['id'])
        self.assertIn(self.tag_a['name'], tags)
        self.assertIn(self.tag_b['name'], tags)

    def test_tag_by_name(self):
        event = self._create_event()
        response = self._add_tag(self.org_a['api'], event['id'], {'tag': self.tag_a['name']})
        self.assertTrue(response['saved'], response)
        self.assertIn(self.tag_a['name'], self._event_tags(event['id']))

    def test_tag_by_unknown_name(self):
        event = self._create_event()
        response = self._add_tag(self.org_a['api'], event['id'], {'tag': 'no-such-tag-' + random()})
        self.assertFalse(response['saved'])
        self.assertEqual('Invalid Tag.', response['errors'])

    def test_tag_collection(self):
        # Created by the tagging user so fetchTagCollection can see it
        collection = send(self.org_a['api'], 'POST', 'tagCollections/add', {
            'name': 'addTag regression collection ' + random(),
            'description': 'T1 regression guard',
        })['TagCollection']
        self.collections.append(collection['id'])
        check_response(send(
            self.org_a['api'], 'POST', f"tagCollections/addTag/{collection['id']}",
            {'tag': json.dumps([int(self.tag_a['id']), int(self.tag_b['id'])])},
            check_errors=False))
        event = self._create_event()
        response = self._add_tag(self.org_a['api'], event['id'],
                                 {'tag': f"collection_{collection['id']}"})
        self.assertTrue(response['saved'], response)
        self.assertEqual('Tags added.', response['success'])
        tags = self._event_tags(event['id'])
        self.assertIn(self.tag_a['name'], tags)
        self.assertIn(self.tag_b['name'], tags)

    def test_invalid_tag_collection(self):
        event = self._create_event()
        response = self._add_tag(self.org_a['api'], event['id'], {'tag': 'collection_99999999'})
        self.assertFalse(response['saved'])
        self.assertEqual('Invalid Tag Collection.', response['errors'])

    def test_local_tag(self):
        event = self._create_event()
        response = self._add_tag(self.org_a['api'], event['id'], {'tag': self.tag_a['id']},
                                 local=True)
        self.assertTrue(response['saved'], response)
        tags = self._event_tags(event['id'])
        self.assertTrue(bool(tags[self.tag_a['name']]['local']))

    def test_unpublish_semantics(self):
        event = self._create_event()
        send(self.admin, 'POST', f"events/publish/{event['id']}/disable_background_processing:1")
        self.assertTrue(self._published(event['id']))
        response = self._add_tag(self.org_a['api'], event['id'], {'tag': self.tag_a['id']},
                                 local=True)
        self.assertTrue(response['saved'], response)
        self.assertTrue(self._published(event['id']), 'local tag must not unpublish')
        response = self._add_tag(self.org_a['api'], event['id'], {'tag': self.tag_b['id']})
        self.assertTrue(response['saved'], response)
        self.assertFalse(self._published(event['id']), 'global tag must unpublish')

    def test_duplicate_skip(self):
        event = self._create_event()
        check_response(self._add_tag(self.org_a['api'], event['id'], {'tag': self.tag_a['id']}))
        response = self._add_tag(self.org_a['api'], event['id'], {'tag': self.tag_a['id']})
        self.assertFalse(response['saved'])
        self.assertEqual('Tag is already attached to this event.', response['errors'])
        # Dedup ignores the local flag: local re-attach of a global tag is a duplicate too
        response = self._add_tag(self.org_a['api'], event['id'], {'tag': self.tag_a['id']},
                                 local=True)
        self.assertFalse(response['saved'])
        self.assertEqual('Tag is already attached to this event.', response['errors'])

    def test_duplicate_mixed_with_new(self):
        event = self._create_event()
        check_response(self._add_tag(self.org_a['api'], event['id'], {'tag': self.tag_a['id']}))
        payload = {'tag': json.dumps([int(self.tag_a['id']), int(self.tag_b['id'])])}
        response = self._add_tag(self.org_a['api'], event['id'], payload)
        self.assertTrue(response['saved'], response)  # partial success keeps saved: true
        self.assertIn('could not be added', response['success'])
        self.assertIn('already attached', response['success'])
        self.assertIn(self.tag_b['name'], self._event_tags(event['id']))

    def test_local_only_tag(self):
        event = self._create_event()
        response = self._add_tag(self.org_a['api'], event['id'],
                                 {'tag': self.tag_local_only['id']})
        self.assertFalse(response['saved'])
        self.assertIn('can only be set as a local tag', response['errors'])
        response = self._add_tag(self.org_a['api'], event['id'],
                                 {'tag': self.tag_local_only['id']}, local=True)
        self.assertTrue(response['saved'], response)
        tags = self._event_tags(event['id'])
        self.assertTrue(bool(tags[self.tag_local_only['name']]['local']))

    def test_no_permission_foreign_event(self):
        # org-B tagger on an org-A event: refused globally AND locally
        # (org B is neither owner nor host org)
        event = self._create_event()
        for local in (False, True):
            response = self._add_tag(self.org_b['api'], event['id'],
                                     {'tag': self.tag_a['id']}, local=local)
            self.assertFalse(response['saved'], response)
            self.assertEqual("You don't have permission to do that.", response['errors'])
        self.assertEqual({}, self._event_tags(event['id']))

    def test_event_by_uuid(self):
        event = self._create_event()
        response = self._add_tag(self.org_a['api'], event['uuid'], {'tag': self.tag_a['id']})
        self.assertTrue(response['saved'], response)
        self.assertIn(self.tag_a['name'], self._event_tags(event['id']))

    def test_event_id_in_body(self):
        event = self._create_event()
        response = send(self.org_a['api'], 'POST', 'events/addTag',
                        {'event': event['id'], 'tag': self.tag_a['id']}, check_errors=False)
        self.assertTrue(response['saved'], response)
        self.assertIn(self.tag_a['name'], self._event_tags(event['id']))


if __name__ == '__main__':
    unittest.main()
