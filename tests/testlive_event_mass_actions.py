#!/usr/bin/env python3
"""
Integration coverage for the event index mass actions (PRD §9.2–9.3):
bulk tagging via `/events/addTag/selected` and bulk galaxy cluster
attachment via `/galaxies/attachMultipleClusters/selected/event`.

Focus: the D6 global→local downgrade matrix and its security boundary —
 - owner-org tagger, global preference  -> global rows, unpublish
 - host-org tagger, global preference   -> local rows (downgraded),
                                            events stay published
 - unrelated-org tagger, global + local -> refused, counted as failed
 - site admin, global preference        -> global rows, no downgrade
 - tamper attempts (forged local flags) -> assert the *stored* local
   flag, not the response message
 - local_only tags / local_only-galaxy clusters under a global
   preference -> whole batch rejected up front

Events are created with distribution 1 (community) so they are visible
to the host-org user: attachMultipleClusters resolves events through an
ACL-checked fetch (invisible events count as failed), while addTag uses
a raw find — a pre-existing asymmetry, see the progress tracker.

Usage:
    HOST=localhost:5007 AUTH=<site-admin-key> python3 testlive_event_mass_actions.py -v

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


class TestEventMassActions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        cls.admin = PyMISP(url, key)
        assert cls.admin._current_role.perm_site_admin

        # Host org: the org the instance belongs to (MISP.host_org_id).
        try:
            setting = send(cls.admin, 'GET', 'servers/getSetting/MISP.host_org_id')
            cls.host_org_id = int(setting['value'])
        except Exception:
            cls.host_org_id = 1
        assert cls.host_org_id, 'MISP.host_org_id must be configured for the downgrade matrix'

        # Org A owns the test events
        cls.org_a = cls._create_org_with_user('A')
        # Host-org tagger: downgrade beneficiary (local attach on foreign events)
        cls.host = cls._create_user(cls.host_org_id, 'host')
        # Org C: neither owner nor host org — must always be refused
        cls.org_c = cls._create_org_with_user('C')

        cls.tag_a = cls._create_tag()
        cls.tag_b = cls._create_tag()
        cls.tag_lo = cls._create_tag({'local_only': 1})

        # Two clusters from non-local_only galaxies, discovered at runtime
        cls.cluster_a, cls.cluster_b = cls._discover_clusters()

        cls.events = []

    @classmethod
    def tearDownClass(cls):
        for event_id in cls.events:
            send(cls.admin, 'POST', f'events/delete/{event_id}', check_errors=False)
        for tag in (cls.tag_a, cls.tag_b, cls.tag_lo):
            send(cls.admin, 'POST', f"tags/delete/{tag['id']}", check_errors=False)
        cls.admin.delete_user(cls.host['user'])
        for fixture in (cls.org_a, cls.org_c):
            cls.admin.delete_user(fixture['user'])
            cls.admin.delete_organisation(fixture['org'])

    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)

    # --- fixtures -----------------------------------------------------

    @classmethod
    def _create_user(cls, org_id, label: str) -> dict:
        user = MISPUser()
        user.email = f'massactions.{label}.{random()}@user.local'
        user.org_id = org_id
        user.role_id = 2  # org admin: perm_tagger + perm_modify, not site admin
        user = cls.admin.add_user(user, pythonify=True)
        check_response(user)
        authkey = send(cls.admin, 'POST', f'authKeys/add/{user.id}')['AuthKey']['authkey_raw']
        connector = PyMISP(url, authkey)
        assert connector._current_role.perm_tagger
        assert not connector._current_role.perm_site_admin
        return {'user': user, 'api': connector}

    @classmethod
    def _create_org_with_user(cls, label: str) -> dict:
        org = MISPOrganisation()
        org.name = f'massactions Org {label} ' + random()
        org = cls.admin.add_organisation(org, pythonify=True)
        check_response(org)
        fixture = cls._create_user(org.id, label.lower())
        fixture['org'] = org
        return fixture

    @classmethod
    def _create_tag(cls, extra: dict = None) -> dict:
        data = {'name': 'massactions-' + random(), 'colour': '#112233'}
        data.update(extra or {})
        return send(cls.admin, 'POST', 'tags/add', data)['Tag']

    @classmethod
    def _discover_clusters(cls):
        found = send(cls.admin, 'POST', 'galaxy_clusters/restSearch',
                     {'default': 1, 'limit': 10})
        if isinstance(found, dict):
            found = found.get('response', [])
        usable = []
        galaxy_local_only = {}
        for entry in found:
            cluster = entry['GalaxyCluster']
            galaxy_id = cluster['galaxy_id']
            if galaxy_id not in galaxy_local_only:
                galaxy = send(cls.admin, 'GET', f'galaxies/view/{galaxy_id}')['Galaxy']
                galaxy_local_only[galaxy_id] = bool(galaxy.get('local_only'))
            if not galaxy_local_only[galaxy_id]:
                usable.append(cluster)
            if len(usable) >= 2:
                break
        assert len(usable) >= 2, 'instance needs >= 2 default clusters from non-local_only galaxies'
        return usable[0], usable[1]

    def _create_events(self, count: int, api: PyMISP = None, publish: bool = False) -> list:
        api = api or self.org_a['api']
        events = []
        for _ in range(count):
            event = send(api, 'POST', 'events/add', {
                'info': 'massactions ' + random(),
                'distribution': 1,  # community — visible to host/org-C users
                'analysis': 0,
                'threat_level_id': 4,
            })['Event']
            self.events.append(event['id'])
            if publish:
                send(self.admin, 'POST',
                     f"events/publish/{event['id']}/disable_background_processing:1")
            events.append(event)
        return events

    # --- helpers ------------------------------------------------------

    @staticmethod
    def _ids(events) -> str:
        return json.dumps([int(e['id']) for e in events])

    def _bulk_tag(self, api: PyMISP, events, payload: dict, named: str = '') -> dict:
        return send(api, 'POST', f'events/addTag/selected{named}',
                    {'event_ids': self._ids(events), **payload}, check_errors=False)

    def _bulk_cluster(self, api: PyMISP, events, cluster_id, named: str = '') -> dict:
        return send(api, 'POST', f'galaxies/attachMultipleClusters/selected/event{named}',
                    {'Galaxy': {'event_ids': self._ids(events),
                                'target_ids': json.dumps([int(cluster_id)])}},
                    check_errors=False)

    def _event_tags(self, event_id) -> dict:
        event = send(self.admin, 'GET', f'events/view/{event_id}')['Event']
        return {tag['name']: tag for tag in event.get('Tag', [])}

    def _published(self, event_id) -> bool:
        return bool(send(self.admin, 'GET', f'events/view/{event_id}')['Event']['published'])

    def _assert_local_flags(self, events, tag_name, expected_local):
        for event in events:
            tags = self._event_tags(event['id'])
            self.assertIn(tag_name, tags, f"tag missing on event {event['id']}")
            self.assertEqual(expected_local, bool(tags[tag_name]['local']),
                             f"wrong local flag on event {event['id']}")

    # --- §9.2 bulk tag ------------------------------------------------

    def test_tag_own_org_global(self):
        events = self._create_events(3, publish=True)
        response = self._bulk_tag(self.org_a['api'], events, {'tag': self.tag_a['id']})
        self.assertTrue(response['saved'], response)
        self.assertEqual(3, response['attached'])
        self.assertEqual(0, response['downgraded'])
        self._assert_local_flags(events, self.tag_a['name'], False)
        for event in events:
            self.assertFalse(self._published(event['id']), 'global tag must unpublish own events')

    def test_tag_rerun_skips_duplicates(self):
        events = self._create_events(3)
        check_response(self._bulk_tag(self.org_a['api'], events, {'tag': self.tag_a['id']}))
        response = self._bulk_tag(self.org_a['api'], events, {'tag': self.tag_a['id']})
        self.assertFalse(response['saved'])
        self.assertEqual(3, response['skipped'])
        self.assertEqual(0, response['attached'])

    def test_tag_hostorg_global_downgraded(self):
        events = self._create_events(3, publish=True)
        response = self._bulk_tag(self.host['api'], events, {'tag': self.tag_a['id']})
        self.assertTrue(response['saved'], response)
        self.assertEqual(3, response['downgraded'])
        self.assertEqual(0, response['attached'])
        self._assert_local_flags(events, self.tag_a['name'], True)
        for event in events:
            self.assertTrue(self._published(event['id']),
                            'downgraded (local) attach must not unpublish')

    def test_tag_unrelated_org_fails(self):
        events = self._create_events(3)
        for named in ('', '/local:1'):
            response = self._bulk_tag(self.org_c['api'], events, {'tag': self.tag_a['id']}, named)
            self.assertFalse(response['saved'], response)
            self.assertEqual(3, response['failed'], response)
        for event in events:
            self.assertEqual({}, self._event_tags(event['id']))

    def test_tag_site_admin_global_no_downgrade(self):
        events = self._create_events(3, publish=True)
        response = self._bulk_tag(self.admin, events, {'tag': self.tag_a['id']})
        self.assertTrue(response['saved'], response)
        self.assertEqual(3, response['attached'])
        self.assertEqual(0, response['downgraded'])
        self._assert_local_flags(events, self.tag_a['name'], False)
        for event in events:
            self.assertFalse(self._published(event['id']),
                             'site admin global attach unpublishes even foreign events')

    def test_tag_mixed_selection(self):
        foreign = self._create_events(2)
        own = self._create_events(1, api=self.host['api'])
        response = self._bulk_tag(self.host['api'], foreign + own, {'tag': self.tag_a['id']})
        self.assertTrue(response['saved'], response)
        self.assertEqual(1, response['attached'], response)
        self.assertEqual(2, response['downgraded'], response)
        self._assert_local_flags(foreign, self.tag_a['name'], True)
        self._assert_local_flags(own, self.tag_a['name'], False)

    def test_tag_tamper_forged_local_flag(self):
        # Host-org tagger posts to the GLOBAL url with forged local fields in
        # the body: the stored flag must still be local=1 (downgrade is
        # derived from canModifyEvent server-side, never from the payload).
        events = self._create_events(2)
        response = self._bulk_tag(self.host['api'], events,
                                  {'tag': self.tag_a['id'], 'local': 0})
        self.assertTrue(response['saved'], response)
        self.assertEqual(2, response['downgraded'], response)
        self._assert_local_flags(events, self.tag_a['name'], True)

    def test_tag_local_only_global_batch_rejected(self):
        events = self._create_events(2)
        payload = {'tag': json.dumps([int(self.tag_lo['id']), int(self.tag_a['id'])])}
        response = self._bulk_tag(self.org_a['api'], events, payload)
        self.assertFalse(response['saved'], response)
        self.assertIn('local', response['errors'])
        for event in events:
            self.assertEqual({}, self._event_tags(event['id']),
                             'up-front rejection must attach nothing at all')
        # the same batch through the local action works
        response = self._bulk_tag(self.org_a['api'], events, payload, '/local:1')
        self.assertTrue(response['saved'], response)
        self._assert_local_flags(events, self.tag_lo['name'], True)
        self._assert_local_flags(events, self.tag_a['name'], True)

    def test_tag_junk_and_empty_selection(self):
        response = send(self.org_a['api'], 'POST', 'events/addTag/selected',
                        {'event_ids': '[999999999, "junk"]', 'tag': self.tag_a['id']},
                        check_errors=False)
        self.assertFalse(response['saved'])
        self.assertEqual(2, response['failed'])
        response = send(self.org_a['api'], 'POST', 'events/addTag/selected',
                        {'event_ids': '[]', 'tag': self.tag_a['id']}, check_errors=False)
        self.assertFalse(response['saved'])
        self.assertEqual('Nothing to add.', response['errors'])

    # --- §9.3 bulk clusters --------------------------------------------

    def test_cluster_own_org_global(self):
        events = self._create_events(3, publish=True)
        response = self._bulk_cluster(self.org_a['api'], events, self.cluster_a['id'])
        self.assertTrue(response['saved'], response)
        self.assertEqual(3, response['attached'])
        self.assertEqual(0, response['downgraded'])
        # the galaxy tag was captured and attached globally
        self._assert_local_flags(events, self.cluster_a['tag_name'], False)
        for event in events:
            self.assertFalse(self._published(event['id']),
                             'global cluster attach must unpublish own events')

    def test_cluster_rerun_skips_duplicates(self):
        events = self._create_events(2)
        check_response(self._bulk_cluster(self.org_a['api'], events, self.cluster_a['id']))
        response = self._bulk_cluster(self.org_a['api'], events, self.cluster_a['id'])
        self.assertFalse(response['saved'])
        self.assertEqual(2, response['skipped'])
        self.assertEqual(0, response['attached'])

    def test_cluster_hostorg_global_downgraded(self):
        events = self._create_events(3, publish=True)
        response = self._bulk_cluster(self.host['api'], events, self.cluster_a['id'])
        self.assertTrue(response['saved'], response)
        self.assertEqual(3, response['downgraded'])
        self.assertEqual(0, response['attached'])
        self._assert_local_flags(events, self.cluster_a['tag_name'], True)
        for event in events:
            self.assertTrue(self._published(event['id']),
                            'downgraded (local) cluster must not unpublish')

    def test_cluster_unrelated_org_fails(self):
        events = self._create_events(2)
        for named in ('', '/local:1'):
            response = self._bulk_cluster(self.org_c['api'], events, self.cluster_a['id'], named)
            self.assertFalse(response['saved'], response)
            self.assertEqual(2, response['failed'], response)
        for event in events:
            self.assertEqual({}, self._event_tags(event['id']))

    def test_cluster_tamper_forced_global_param(self):
        # Explicit /local:0 named param must not grant global on foreign events
        events = self._create_events(2)
        response = self._bulk_cluster(self.host['api'], events, self.cluster_b['id'], '/local:0')
        self.assertTrue(response['saved'], response)
        self.assertEqual(2, response['downgraded'], response)
        self._assert_local_flags(events, self.cluster_b['tag_name'], True)

    def test_cluster_mixed_selection(self):
        foreign = self._create_events(2)
        own = self._create_events(1, api=self.host['api'])
        response = self._bulk_cluster(self.host['api'], foreign + own, self.cluster_b['id'])
        self.assertTrue(response['saved'], response)
        self.assertEqual(1, response['attached'], response)
        self.assertEqual(2, response['downgraded'], response)
        self._assert_local_flags(foreign, self.cluster_b['tag_name'], True)
        self._assert_local_flags(own, self.cluster_b['tag_name'], False)

    def test_cluster_local_only_galaxy_global_rejected(self):
        galaxies = send(self.admin, 'GET', 'galaxies/index/searchall:')
        local_only_galaxy = None
        for entry in galaxies if isinstance(galaxies, list) else []:
            if entry['Galaxy'].get('local_only'):
                local_only_galaxy = entry['Galaxy']
                break
        if local_only_galaxy is None:
            self.skipTest('no local_only galaxy on this instance')
        clusters = send(self.admin, 'POST', 'galaxy_clusters/restSearch',
                        {'galaxy_id': local_only_galaxy['id'], 'limit': 1})
        if isinstance(clusters, dict):
            clusters = clusters.get('response', [])
        if not clusters:
            self.skipTest('local_only galaxy has no clusters')
        cluster = clusters[0]['GalaxyCluster']
        events = self._create_events(2)
        response = self._bulk_cluster(self.org_a['api'], events, cluster['id'])
        self.assertFalse(response['saved'], response)
        self.assertIn('local', response['errors'])
        for event in events:
            self.assertEqual({}, self._event_tags(event['id']))

    def test_cluster_junk_and_empty_selection(self):
        response = send(self.org_a['api'], 'POST',
                        'galaxies/attachMultipleClusters/selected/event',
                        {'Galaxy': {'event_ids': '[999999999, "junk"]',
                                    'target_ids': json.dumps([int(self.cluster_a['id'])])}},
                        check_errors=False)
        self.assertFalse(response['saved'])
        self.assertEqual(2, response['failed'])
        response = send(self.org_a['api'], 'POST',
                        'galaxies/attachMultipleClusters/selected/event',
                        {'Galaxy': {'event_ids': '[]',
                                    'target_ids': json.dumps([int(self.cluster_a['id'])])}},
                        check_errors=False)
        self.assertFalse(response['saved'])
        self.assertEqual('Nothing to add.', response['errors'])


if __name__ == '__main__':
    unittest.main()
