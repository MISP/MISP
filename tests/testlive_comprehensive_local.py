#!/usr/bin/env python3
import os
import json
import uuid
import subprocess
import unittest
from xml.etree import ElementTree as ET
from io import BytesIO
import urllib3  # type: ignore

import logging
logging.disable(logging.CRITICAL)
logger = logging.getLogger('pymisp')


from pymisp import PyMISP, MISPOrganisation, MISPUser, MISPRole, MISPSharingGroup, MISPEvent, MISPLog, MISPSighting, Distribution, ThreatLevel, Analysis, MISPEventReport

# Load access information for env variables
url = "http://" + os.environ["HOST"]
key = os.environ["AUTH"]

urllib3.disable_warnings()


def create_simple_event():
    event = MISPEvent()
    event.info = 'This is a super simple test'
    event.distribution = Distribution.your_organisation_only
    event.threat_level_id = ThreatLevel.low
    event.analysis = Analysis.completed
    event.add_attribute('text', str(uuid.uuid4()))
    return event


def check_response(response):
    if isinstance(response, dict) and "errors" in response:
        raise Exception(response["errors"])
    return response


class MISPSetting:
    def __init__(self, admin_connector: PyMISP, new_setting: dict):
        self.admin_connector = admin_connector
        self.new_setting = new_setting

    def __enter__(self):
        self.original = self.__run("modify", json.dumps(self.new_setting))
        # Try to reset config cache
        self.admin_connector.get_server_setting("MISP.live")

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.__run("replace", self.original)
        # Try to reset config cache
        self.admin_connector.get_server_setting("MISP.live")

    @staticmethod
    def __run(command: str, data: str) -> str:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        r = subprocess.run(["php", dir_path + "/modify_config.php", command, data], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode != 0:
            raise Exception([r.returncode, r.stdout, r.stderr])
        return r.stdout.decode("utf-8")


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
        # Set the default role (id 3 on the VM)
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

    def test_publish_alert_filter(self):
        check_response(self.admin_misp_connector.set_server_setting('MISP.background_jobs', 0, force=True))

        first = create_simple_event()
        first.add_tag('test_publish_filter')
        first.threat_level_id = ThreatLevel.medium

        second = create_simple_event()
        second.add_tag('test_publish_filter')
        second.threat_level_id = ThreatLevel.high

        third = create_simple_event()
        third.add_tag('test_publish_filter')
        third.threat_level_id = ThreatLevel.low

        four = create_simple_event()
        four.threat_level_id = ThreatLevel.high

        try:
            # Enable autoalert on admin
            self.admin_misp_connector._current_user.autoalert = True
            check_response(self.admin_misp_connector.update_user(self.admin_misp_connector._current_user))

            # Set publish_alert_filter tag to `test_publish_filter`
            setting_value = {'AND': {'Tag.name': 'test_publish_filter', 'ThreatLevel.name': ['High', 'Medium']}}
            check_response(self.admin_misp_connector.set_user_setting('publish_alert_filter', setting_value))

            # Add  events
            first = check_response(self.admin_misp_connector.add_event(first))
            second = check_response(self.admin_misp_connector.add_event(second))
            third = check_response(self.admin_misp_connector.add_event(third))
            four = check_response(self.admin_misp_connector.add_event(four))

            # Publish events
            for event in (first, second, third, four):
                check_response(self.admin_misp_connector.publish(event, alert=True))

            # Email notification should be send just to first event
            mail_logs = self.admin_misp_connector.search_logs(model='User', action='email')
            log_titles = [log.title for log in mail_logs]

            self.assertIn('Email  to admin@admin.test sent, titled "[ORGNAME MISP] Event ' + str(first.id) + ' - Medium - TLP:AMBER".', log_titles)
            self.assertIn('Email  to admin@admin.test sent, titled "[ORGNAME MISP] Event ' + str(second.id) + ' - High - TLP:AMBER".', log_titles)
            self.assertNotIn('Email  to admin@admin.test sent, titled "[ORGNAME MISP] Event ' + str(third.id) + ' - Low - TLP:AMBER".', log_titles)
            self.assertNotIn('Email  to admin@admin.test sent, titled "[ORGNAME MISP] Event ' + str(four.id) + ' - High - TLP:AMBER".', log_titles)

        finally:
            # Disable autoalert
            self.admin_misp_connector._current_user.autoalert = False
            check_response(self.admin_misp_connector.update_user(self.admin_misp_connector._current_user))
            # Delete filter
            self.admin_misp_connector.delete_user_setting('publish_alert_filter')
            # Reenable background jobs
            check_response(self.admin_misp_connector.set_server_setting('MISP.background_jobs', 1, force=True))
            # Delete events
            for event in (first, second, third, four):
                check_response(self.admin_misp_connector.delete_event(event))

    def test_remove_orphaned_correlations(self):
        result = self.admin_misp_connector._check_json_response(self.admin_misp_connector._prepare_request('GET', 'servers/removeOrphanedCorrelations'))
        check_response(result)
        self.assertIn("message", result)

    def test_restsearch_event_by_tags(self):
        first = create_simple_event()
        first.add_tag('test_search_tag')
        first.add_tag('test_search_tag_third')
        first.add_tag('test_search_tag_both')
        first = self.admin_misp_connector.add_event(first)
        check_response(first)

        second = create_simple_event()
        second.add_tag('test_search_tag_second')
        second.add_tag('test_search_tag_both')
        second = self.admin_misp_connector.add_event(second)
        check_response(second)

        search_result = self.admin_misp_connector.search(metadata=True, tags=["non_exists_tag"])
        self.assertEqual(0, len(search_result))

        search_result = self.admin_misp_connector.search(metadata=True, tags=["test_search_tag"])
        self.assertEqual(1, len(search_result))
        self.assertEqual(first.id, search_result[0].id)

        search_result = self.admin_misp_connector.search(metadata=True, tags="test_search_tag")
        self.assertEqual(1, len(search_result))
        self.assertEqual(first.id, search_result[0].id)

        # Like style match
        search_result = self.admin_misp_connector.search(metadata=True, tags=["test_search_tag%"])
        self.assertEqual(2, len(search_result))

        search_result = self.admin_misp_connector.search(metadata=True, tags=["test_search_tag_second"])
        self.assertEqual(1, len(search_result))
        self.assertEqual(second.id, search_result[0].id)

        search_result = self.admin_misp_connector.search(metadata=True, tags=["!test_search_tag"])
        search_result_ids = [event.id for event in search_result]
        self.assertNotIn(first.id, search_result_ids)
        self.assertIn(second.id, search_result_ids)

        search_result = self.admin_misp_connector.search(metadata=True, tags={"NOT": ["test_search_tag"]})
        search_result_ids = [event.id for event in search_result]
        self.assertNotIn(first.id, search_result_ids)
        self.assertIn(second.id, search_result_ids)

        search_result = self.admin_misp_connector.search(metadata=True, tags={"NOT": "test_search_tag"})
        search_result_ids = [event.id for event in search_result]
        self.assertNotIn(first.id, search_result_ids)
        self.assertIn(second.id, search_result_ids)

        search_result = self.admin_misp_connector.search(metadata=True, tags=["test_search_tag", "test_search_tag_second"])
        self.assertEqual(2, len(search_result))

        search_result = self.admin_misp_connector.search(metadata=True, tags={"AND": ["test_search_tag", "test_search_tag_third"]})
        self.assertEqual(1, len(search_result))
        self.assertEqual(first.id, search_result[0].id)

        search_result = self.admin_misp_connector.search(metadata=True, tags={"AND": ["test_search_tag", "test_search_tag_both"]})
        search_result_ids = [event.id for event in search_result]
        self.assertEqual(1, len(search_result_ids))
        self.assertIn(first.id, search_result_ids)

        check_response(self.admin_misp_connector.delete_event(first))
        check_response(self.admin_misp_connector.delete_event(second))

    def test_log_new_audit(self):
        check_response(self.admin_misp_connector.set_server_setting('MISP.log_new_audit', 1, force=True))

        event = create_simple_event()
        event.add_tag('test_log_new_audit_tag')
        event = check_response(self.admin_misp_connector.add_event(event))

        check_response(self.admin_misp_connector.delete_event(event))

        check_response(self.admin_misp_connector.set_server_setting('MISP.log_new_audit', 0, force=True))

        audit_logs = self.admin_misp_connector._check_json_response(self.admin_misp_connector._prepare_request('GET', 'admin/audit_logs/index'))
        check_response(audit_logs)
        self.assertGreater(len(audit_logs), 0)

    def test_add_tag_to_attachment(self):
        event = create_simple_event()
        with open(__file__, 'rb') as f:
            event.add_attribute('attachment', value='testfile.py', data=BytesIO(f.read()))
        event = check_response(self.admin_misp_connector.add_event(event))

        attribute_uuids = [attribute.uuid for attribute in event.attributes if attribute.type == 'attachment']
        self.assertEqual(1, len(attribute_uuids))

        check_response(self.admin_misp_connector.tag(attribute_uuids[0], 'generic_tag_test'))

        check_response(self.admin_misp_connector.delete_event(event))

    def test_add_duplicate_tags(self):
        event = create_simple_event()
        event = check_response(self.admin_misp_connector.add_event(event))

        # Just first tag should be added
        check_response(self.admin_misp_connector.tag(event.uuid, 'generic_tag_test', local=True))
        check_response(self.admin_misp_connector.tag(event.uuid, 'generic_tag_test', local=False))

        fetched_event = check_response(self.admin_misp_connector.get_event(event))
        self.assertEqual(1, len(fetched_event.tags), fetched_event.tags)
        self.assertTrue(fetched_event.tags[0].local, fetched_event.tags[0])

    def test_export(self):
        event = create_simple_event()
        event.add_attribute("ip-src", "1.2.4.5", to_ids=True)
        event = check_response(self.admin_misp_connector.add_event(event))

        result = self._search({'returnFormat': "openioc", 'eventid': event.id, "published": [0, 1]})
        ET.fromstring(result)  # check if result is valid XML
        self.assertTrue("1.2.4.5" in result, result)

        result = self._search({'returnFormat': "yara", 'eventid': event.id, "published": [0, 1]})
        self.assertTrue("1.2.4.5" in result, result)
        self.assertTrue("GENERATED" in result, result)
        self.assertTrue("AS-IS" in result, result)

        result = self._search({'returnFormat': "yara-json", 'eventid': event.id, "published": [0, 1]})
        self.assertIn("generated", result)
        self.assertEqual(len(result["generated"]), 1, result)
        self.assertIn("as-is", result)

        check_response(self.admin_misp_connector.delete_event(event))

    def test_event_report_empty_name(self):
        event = create_simple_event()
        new_event_report = MISPEventReport()
        new_event_report.name = ""
        new_event_report.content = "# Example report markdown"
        new_event_report.distribution = 5  # Inherit

        try:
            event = check_response(self.user_misp_connector.add_event(event))
            new_event_report = self.user_misp_connector.add_event_report(event.id, new_event_report)
            self.assertIn("errors", new_event_report)
        finally:
            self.user_misp_connector.delete_event(event)

    def test_new_audit(self):
        with MISPSetting(self.admin_misp_connector, {"MISP.log_new_audit": True}):
            event = create_simple_event()
            event = check_response(self.user_misp_connector.add_event(event))
            self.user_misp_connector.delete_event(event)

    def _search(self, query: dict):
        response = self.admin_misp_connector._prepare_request('POST', 'events/restSearch', data=query)
        response = self.admin_misp_connector._check_response(response)
        check_response(response)
        return response


if __name__ == '__main__':
    unittest.main()
