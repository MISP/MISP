#!/usr/bin/env python3
import os
import unittest
import uuid
import urllib3  # type: ignore

import logging
logging.disable(logging.CRITICAL)
logger = logging.getLogger('pymisp')


from pymisp import PyMISP, MISPOrganisation, MISPUser, MISPRole, MISPSharingGroup, MISPEvent, MISPLog, MISPSighting, Distribution, ThreatLevel, Analysis

# Load access information for env variables
url = "http://" + os.environ["HOST"]
key = os.environ["AUTH"]

urllib3.disable_warnings()


def create_simple_event():
    mispevent = MISPEvent()
    mispevent.info = 'This is a super simple test'
    mispevent.distribution = Distribution.your_organisation_only
    mispevent.threat_level_id = ThreatLevel.low
    mispevent.analysis = Analysis.completed
    mispevent.add_attribute('text', str(uuid.uuid4()))
    return mispevent


def check_response(response):
    if isinstance(response, dict) and "errors" in response:
        raise Exception(response["errors"])


class TestComprehensive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.maxDiff = None
        # Connect as admin
        cls.admin_misp_connector = PyMISP(url, key, ssl=False, debug=False)
        cls.admin_misp_connector.set_server_setting('debug', 1, force=True)
        # Creates an org
        organisation = MISPOrganisation()
        organisation.name = 'Test Org'
        cls.test_org = cls.admin_misp_connector.add_organisation(organisation, pythonify=True)
        # Set the refault role (id 3 on the VM)
        cls.admin_misp_connector.set_default_role(3)
        # Creates a user
        user = MISPUser()
        user.email = 'testusr@user.local'
        user.org_id = cls.test_org.id
        cls.test_usr = cls.admin_misp_connector.add_user(user, pythonify=True)
        cls.user_misp_connector = PyMISP(url, cls.test_usr.authkey, ssl=False, debug=True)

    @classmethod
    def tearDownClass(cls):
        # Delete user
        cls.admin_misp_connector.delete_user(cls.test_usr)
        # Delete org
        cls.admin_misp_connector.delete_organisation(cls.test_org)

    def setUp(self):
        self.user_misp_connector.global_pythonify = True
        self.admin_misp_connector.global_pythonify = True

    def test_search_index(self):
        # Search all events
        index = self.user_misp_connector.search_index()
        self.assertGreater(len(index), 0)

        # Search published
        index_published = self.user_misp_connector.search_index(published=True)
        self.assertEqual(len(index_published), 0, "No event should be published.")

        # Create test event
        event = create_simple_event()
        event = self.user_misp_connector.add_event(event)
        check_response(event)

        # Search by org name
        index_org = self.user_misp_connector.search_index(org="Test Org")
        self.assertGreater(len(index_org), 0)

        # Search by org name with different case
        index_org_lower = self.user_misp_connector.search_index(org="test org")
        self.assertGreater(len(index_org_lower), 0)

        # Search by org uuid
        index_org_uuid = self.user_misp_connector.search_index(org=self.test_org.uuid)
        self.assertGreater(len(index_org_uuid), 0)

        # Search by org ID
        index_org_id = self.user_misp_connector.search_index(org=self.test_org.id)
        self.assertGreater(len(index_org_id), 0)

        self.assertEqual(len(index_org), len(index_org_lower))
        self.assertEqual(len(index_org), len(index_org_uuid))
        self.assertEqual(len(index_org), len(index_org_id))

        self.user_misp_connector.delete_event(event)

    def test_search_index_by_info(self):
        event = create_simple_event()
        event.info = uuid.uuid4()

        # No event should exists
        index = self.user_misp_connector.search_index(eventinfo=event.info)
        self.assertEqual(len(index), 0, "No event should exists")

        event = self.user_misp_connector.add_event(event)
        check_response(event)

        # One event should exists
        index = self.user_misp_connector.search_index(eventinfo=event.info)
        self.assertEqual(len(index), 1)
        self.assertEqual(index[0].uuid, event.uuid)

        index = self.user_misp_connector.search_index(eventinfo="!" + str(event.info))
        for index_event in index:
            self.assertNotEqual(event.uuid, index_event.uuid, index)

        self.user_misp_connector.delete_event(event)

    def test_search_index_by_all(self):
        event = create_simple_event()

        index = self.user_misp_connector.search_index(all=event.attributes[0].value)
        self.assertEqual(len(index), 0, "No event should exists")

        event = self.user_misp_connector.add_event(event)
        check_response(event)

        index = self.user_misp_connector.search_index(all=event.attributes[0].value)
        self.assertEqual(len(index), 1, "One event should exists")
        self.assertEqual(index[0].uuid, event.uuid)

        index = self.user_misp_connector.search_index(all=event.attributes[0].value.upper())
        self.assertEqual(len(index), 1, "One event should exists")
        self.assertEqual(index[0].uuid, event.uuid)

        self.user_misp_connector.delete_event(event)

    def test_search_index_by_attribute(self):
        event = create_simple_event()

        index = self.user_misp_connector.search_index(attribute=event.attributes[0].value)
        self.assertEqual(len(index), 0, "No event should exists")

        event = self.user_misp_connector.add_event(event)
        check_response(event)

        index = self.user_misp_connector.search_index(attribute=event.attributes[0].value)
        self.assertEqual(len(index), 1, "One event should exists")
        self.assertEqual(index[0].uuid, event.uuid)

        index = self.user_misp_connector.search_index(attribute=event.attributes[0].value.upper())
        self.assertEqual(len(index), 1, "One event should exists")
        self.assertEqual(index[0].uuid, event.uuid)

        self.user_misp_connector.delete_event(event)

    def test_search_index_by_tag(self):
        tags = self.user_misp_connector.search_tags("tlp:red", True)

        index = self.user_misp_connector.search_index(tags="tlp:red")
        self.assertEqual(len(index), 0, "No event should exists")

        index = self.user_misp_connector.search_index(tags=tags[0].id)
        self.assertEqual(len(index), 0, "No event should exists")

        event = create_simple_event()
        event.add_tag("tlp:red")
        event = self.user_misp_connector.add_event(event)
        check_response(event)

        index = self.user_misp_connector.search_index(tags="tlp:red")
        self.assertEqual(len(index), 1, "One event should exists")

        index = self.user_misp_connector.search_index(tags="tlp:red|not_exists")
        self.assertEqual(len(index), 1, "One event should exists")

        index = self.user_misp_connector.search_index(tags=["tlp:red", "not_exists"])
        self.assertEqual(len(index), 1, "One event should exists")

        index = self.user_misp_connector.search_index(tags=tags[0].id)
        self.assertEqual(len(index), 1, "One event should exists")

        index = self.user_misp_connector.search_index(tags="!tlp:red")
        for index_event in index:
            self.assertNotEqual(event.uuid, index_event.uuid, index)

        index = self.user_misp_connector.search_index(tags="!" + str(tags[0].id))
        for index_event in index:
            self.assertNotEqual(event.uuid, index_event.uuid, index)

        self.user_misp_connector.delete_event(event)

    def test_search_index_by_email(self):
        index = self.user_misp_connector.search_index(email=self.test_usr.email)
        self.assertEqual(len(index), 0, index)

        event = create_simple_event()
        event = self.user_misp_connector.add_event(event)
        check_response(event)

        index = self.user_misp_connector.search_index(email=self.test_usr.email)
        self.assertEqual(len(index), 1, "One event should exists")

        self.user_misp_connector.delete_event(event)

    def test_search_index_by_email_admin(self):
        index = self.admin_misp_connector.search_index(email="no_existing_exmail@example.com")
        self.assertEqual(len(index), 0, index)

        index = self.admin_misp_connector.search_index(email=self.test_usr.email)
        self.assertEqual(len(index), 0, index)

        event = create_simple_event()
        event = self.user_misp_connector.add_event(event)
        check_response(event)

        index = self.admin_misp_connector.search_index(email=self.test_usr.email)
        self.assertEqual(len(index), 1, index)

        # Search by partial match
        index = self.admin_misp_connector.search_index(email="testusr@user")
        self.assertEqual(len(index), 1, index)

        self.user_misp_connector.delete_event(event)

    def test_search_index_minimal(self):
        # pythonify is not supported for minimal results
        self.user_misp_connector.global_pythonify = False

        minimal = self.user_misp_connector.search_index(minimal=True)
        self.assertGreater(len(minimal), 0)
        minimal_event = minimal[0]
        self.assertIn("id", minimal_event)
        self.assertIn("timestamp", minimal_event)
        self.assertIn("sighting_timestamp", minimal_event)
        self.assertIn("published", minimal_event)
        self.assertIn("uuid", minimal_event)
        self.assertIn("orgc_uuid", minimal_event)
        for event in minimal:
            self.assertFalse(event["published"], "No event should be published.")

    def test_search_index_minimal_published(self):
        # pythonify is not supported for minimal results
        self.user_misp_connector.global_pythonify = False

        index = self.user_misp_connector.search_index(minimal=True, published=True)
        self.assertEqual(len(index), 0, "No event should be published.")

        index = self.user_misp_connector.search_index(minimal=True)
        not_published = self.user_misp_connector.search_index(minimal=True, published=0)
        both_2 = self.user_misp_connector.search_index(minimal=True, published=2)
        both_array = self.user_misp_connector.search_index(minimal=True, published=[0, 1])

        self.assertEqual(len(index), len(not_published))
        self.assertEqual(len(index), len(both_2))
        self.assertEqual(len(index), len(both_array))

    def test_search_index_minimal_by_org(self):
        # pythonify is not supported for minimal results
        self.user_misp_connector.global_pythonify = False

        # Create test event
        event = create_simple_event()
        event = self.user_misp_connector.add_event(event, pythonify=True)
        check_response(event)

        # Search by org name
        minimal_org = self.user_misp_connector.search_index(minimal=True, org="Test Org")
        self.assertGreater(len(minimal_org), 0)
        for event in minimal_org:
            self.assertEqual(event["orgc_uuid"], self.test_org.uuid)

        # Search by org name with different case
        minimal_org_lower = self.user_misp_connector.search_index(minimal=True, org="test org")
        self.assertGreater(len(minimal_org), 0)
        for event in minimal_org:
            self.assertEqual(event["orgc_uuid"], self.test_org.uuid)

        # Search by non exists org name
        minimal_org_non_existing = self.user_misp_connector.search_index(minimal=True, org="Test Org that doesn't exists")
        self.assertEqual(len(minimal_org_non_existing), 0)

        # Search by org uuid
        minimal_org_uuid = self.user_misp_connector.search_index(minimal=True, org=self.test_org.uuid)
        self.assertGreater(len(minimal_org), 0)
        for event in minimal_org:
            self.assertEqual(event["orgc_uuid"], self.test_org.uuid)

        # Search by non existing uuid
        minimal_org_uuid_non_existing = self.user_misp_connector.search_index(minimal=True, org=uuid.uuid4())
        self.assertEqual(len(minimal_org_uuid_non_existing), 0)

        # Search by org ID
        minimal_org_id = self.user_misp_connector.search_index(minimal=True, org=self.test_org.id)
        self.assertGreater(len(minimal_org), 0)
        for event in minimal_org:
            self.assertEqual(event["orgc_uuid"], self.test_org.uuid)

        self.assertEqual(len(minimal_org), len(minimal_org_lower))
        self.assertEqual(len(minimal_org), len(minimal_org_uuid))
        self.assertEqual(len(minimal_org), len(minimal_org_id))

        # Search not by org
        minimal_org_not = self.user_misp_connector.search_index(minimal=True, org="!Test Org")
        for event in minimal_org_not:
            self.assertNotEqual(event["orgc_uuid"], self.test_org.uuid)
        minimal_org_lower_not = self.user_misp_connector.search_index(minimal=True, org="!test org")
        for event in minimal_org_lower_not:
            self.assertNotEqual(event["orgc_uuid"], self.test_org.uuid)
        minimal_org_uuid_not = self.user_misp_connector.search_index(minimal=True, org="!" + self.test_org.uuid)
        for event in minimal_org_uuid_not:
            self.assertNotEqual(event["orgc_uuid"], self.test_org.uuid)
        minimal_org_id_not = self.user_misp_connector.search_index(minimal=True, org="!" + self.test_org.id)
        for event in minimal_org_id_not:
            self.assertNotEqual(event["orgc_uuid"], self.test_org.uuid)

        self.assertEqual(len(minimal_org_not), len(minimal_org_lower_not))
        self.assertEqual(len(minimal_org_not), len(minimal_org_uuid_not))
        self.assertEqual(len(minimal_org_not), len(minimal_org_id_not))

        self.user_misp_connector.delete_event(event)

    def test_delete_event_blocklist(self):
        check_response(self.admin_misp_connector.set_server_setting('MISP.enableEventBlocklisting', 1))

        # Create test event
        event = create_simple_event()
        event = self.user_misp_connector.add_event(event)
        check_response(event)

        # Delete event
        check_response(self.user_misp_connector.delete_event(event))

        check_response(self.admin_misp_connector.set_server_setting('MISP.enableEventBlocklisting', 0))

    def test_deleted_attributes(self):
        # Create test event
        event = create_simple_event()
        event.add_attribute('text', "deleted", deleted=True)
        event.add_attribute('text', "not-deleted")
        event = self.user_misp_connector.add_event(event)
        check_response(event)

        # Not deleted
        fetched_event = self.user_misp_connector.get_event(event)
        check_response(fetched_event)
        self.assertEqual(len(fetched_event.attributes), 2, fetched_event)

        # Not deleted
        fetched_event = self.user_misp_connector.get_event(event, deleted=0)
        check_response(fetched_event)
        self.assertEqual(len(fetched_event.attributes), 2, fetched_event)

        # Include deleted
        fetched_event = self.user_misp_connector.get_event(event, deleted=1)
        check_response(fetched_event)
        self.assertEqual(len(fetched_event.attributes), 3, fetched_event)

        # Deleted only
        fetched_event = self.user_misp_connector.get_event(event, deleted=2)
        check_response(fetched_event)
        self.assertEqual(len(fetched_event.attributes), 1, fetched_event)

        # Both
        fetched_event = self.user_misp_connector.get_event(event, deleted=[0, 1])
        check_response(fetched_event)
        self.assertEqual(len(fetched_event.attributes), 3, fetched_event)

        check_response(self.user_misp_connector.delete_event(event))

    def test_view_event_exclude_local_tags(self):
        event = create_simple_event()
        event.add_tag({"name": "local", "local": 1})
        event.add_tag({"name": "global", "local": 0})
        event.attributes[0].add_tag({"name": "local", "local": 1})
        event.attributes[0].add_tag({"name": "global", "local": 0})

        event = self.admin_misp_connector.add_event(event)
        check_response(event)

        event_with_local_tags = self.admin_misp_connector.get_event(event)
        check_response(event_with_local_tags)
        self.assertEqual(len(event_with_local_tags.tags), 2)
        self.assertEqual(len(event_with_local_tags.attributes[0].tags), 2)

        event_without_local_tags = self.admin_misp_connector._check_json_response(self.admin_misp_connector._prepare_request('GET', f'events/view/{event.id}/excludeLocalTags:1'))
        check_response(event_without_local_tags)

        self.assertEqual(event_without_local_tags["Event"]["Tag"][0]["local"], 0, event_without_local_tags)
        self.assertEqual(event_without_local_tags["Event"]["Attribute"][0]["Tag"][0]["local"], 0, event_without_local_tags)

        check_response(self.admin_misp_connector.delete_event(event))


if __name__ == '__main__':
    unittest.main()
