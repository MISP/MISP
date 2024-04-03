#!/usr/bin/env python3
import os
import json
import uuid
import logging
import inspect
import subprocess
import unittest
import requests
import time
from xml.etree import ElementTree as ET
from io import BytesIO
import urllib3  # type: ignore
from datetime import datetime, timedelta
from typing import Union
from pymisp import PyMISP, MISPOrganisation, MISPUser, MISPRole, MISPSharingGroup, MISPEvent, MISPLog, MISPSighting, Distribution, ThreatLevel, Analysis, MISPEventReport, MISPServerError
from pymisp.tools import DomainIPObject
from pymisp.api import get_uuid_or_id_from_abstract_misp

logging.disable(logging.CRITICAL)
logger = logging.getLogger('pymisp')
urllib3.disable_warnings()

# Load access information for env variables
url = "http://" + os.environ["HOST"]
key = os.environ["AUTH"]


def create_simple_event() -> MISPEvent:
    caller_name = inspect.stack()[1].function
    event_uuid = str(uuid.uuid4())

    event = MISPEvent()
    event.uuid = event_uuid
    event.info = 'This is a super simple test ({}, {})'.format(event_uuid.split('-')[0], caller_name)
    event.distribution = Distribution.your_organisation_only
    event.threat_level_id = ThreatLevel.low
    event.analysis = Analysis.completed
    event.add_attribute('text', event_uuid)
    return event


def check_response(response):
    if isinstance(response, dict) and "errors" in response:
        raise Exception(response["errors"])
    return response


def request(pymisp: PyMISP, request_type: str, url: str, data: dict = {}) -> dict:
    response = pymisp._prepare_request(request_type, url, data)
    return pymisp._check_response(response)


def publish_immediately(pymisp: PyMISP, event: Union[MISPEvent, int, str, uuid.UUID], with_email: bool = False):
    event_id = get_uuid_or_id_from_abstract_misp(event)
    action = "alert" if with_email else "publish"
    return check_response(request(pymisp, 'POST', f'events/{action}/{event_id}/disable_background_processing:1'))


class MISPSetting:
    def __init__(self, admin_connector: PyMISP, new_setting: dict):
        self.admin_connector = admin_connector
        self.new_setting = new_setting

    def __enter__(self):
        self.original = self.__run("modify", json.dumps(self.new_setting).encode("utf-8"))
        # Try to reset config cache
        self.admin_connector.get_server_setting("MISP.live")

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.__run("replace", self.original)
        # Try to reset config cache
        self.admin_connector.get_server_setting("MISP.live")

    @staticmethod
    def __run(command: str, data: bytes) -> bytes:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        r = subprocess.run(["php", dir_path + "/modify_config.php", command, data], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode != 0:
            raise Exception([r.returncode, r.stdout, r.stderr])
        return r.stdout


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

    @unittest.skip("FIXME: That index will be empty.")
    def test_search_index(self):
        # Search all events
        index = self.user_misp_connector.search_index()
        self.assertGreater(len(index), 0)

        # Search published
        index_published = self.user_misp_connector.search_index(published=True)
        if len(index_published):
            print(index_published)
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

        # No event should exist
        index = self.user_misp_connector.search_index(eventinfo=event.info)
        self.assertEqual(len(index), 0, "No event should exists")

        event = self.user_misp_connector.add_event(event)
        check_response(event)

        # One event should exist
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
        self.assertEqual(len(tags), 1, tags)  # tlp:red tag doesn't exists

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

    def test_search_index_by_eventid(self):
        # Search by non exists uuid
        index = self.admin_misp_connector.search_index(eventid=uuid.uuid4())
        self.assertEqual(len(index), 0, index)

        # Search by non exists id
        index = self.admin_misp_connector.search_index(eventid=9999)
        self.assertEqual(len(index), 0, index)

        event = create_simple_event()
        event = self.user_misp_connector.add_event(event)
        check_response(event)

        index = self.admin_misp_connector.search_index(eventid=event.id)
        self.assertEqual(len(index), 1, index)

        index = self.admin_misp_connector.search_index(eventid=event.uuid)
        self.assertEqual(len(index), 1, index)

        self.user_misp_connector.delete_event(event)

    @unittest.skip("FIXME: That index will be empty.")
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

        # Search by non-existing uuid
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

        event_without_local_tags = self.admin_misp_connector._check_response(self.admin_misp_connector._prepare_request('GET', f'events/view/{event.id}/excludeLocalTags:1'))
        check_response(event_without_local_tags)

        self.assertEqual(event_without_local_tags["Event"]["Tag"][0]["local"], 0, event_without_local_tags)
        self.assertEqual(event_without_local_tags["Event"]["Attribute"][0]["Tag"][0]["local"], 0, event_without_local_tags)

        check_response(self.admin_misp_connector.delete_event(event))

    def test_publish_alert_filter(self):
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
                publish_immediately(self.admin_misp_connector, event, with_email=True)

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
            # Delete events
            for event in (first, second, third, four):
                check_response(self.admin_misp_connector.delete_event(event))

    def test_correlations(self):
        first = create_simple_event()
        first.add_attribute("ip-src", "10.0.0.1")
        first = check_response(self.admin_misp_connector.add_event(first))

        second = create_simple_event()
        second.add_attribute("ip-src", "10.0.0.1")
        second = check_response(self.admin_misp_connector.add_event(second))

        # Reload to get event data with related events
        first = check_response(self.admin_misp_connector.get_event(first))

        try:
            self.assertEqual(1, len(first.RelatedEvent), first.RelatedEvent)
            self.assertEqual(1, len(second.RelatedEvent), second.RelatedEvent)
        except:
            raise
        finally:
            # Delete events
            for event in (first, second):
                check_response(self.admin_misp_connector.delete_event(event))

    def test_correlations_object(self):
        first = create_simple_event()
        dom_ip_obj = DomainIPObject({'ip': ['10.0.0.1']})
        first.add_object(dom_ip_obj)
        first = check_response(self.admin_misp_connector.add_event(first))

        second = create_simple_event()
        dom_ip_obj = DomainIPObject({'ip': ['10.0.0.1']})
        second.add_object(dom_ip_obj)
        second = check_response(self.admin_misp_connector.add_event(second))

        # Reload to get event data with related events
        first = check_response(self.admin_misp_connector.get_event(first))

        try:
            self.assertEqual(1, len(first.RelatedEvent), first.RelatedEvent)
            self.assertEqual(1, len(second.RelatedEvent), second.RelatedEvent)
        except:
            raise
        finally:
            # Delete events
            for event in (first, second):
                check_response(self.admin_misp_connector.delete_event(event))

    def test_correlations_noacl(self):
        with MISPSetting(self.admin_misp_connector, {"MISP.correlation_engine": "NoAcl"}):
            self.test_correlations()
            self.test_correlations_object()
            self.test_recorrelate()

    def test_advanced_correlations(self):
        with MISPSetting(self.admin_misp_connector, {"MISP.enable_advanced_correlations": True}):
            first = create_simple_event()
            first.add_attribute("ip-src", "10.0.0.0/8")
            first = check_response(self.admin_misp_connector.add_event(first))

            second = create_simple_event()
            second.add_attribute("ip-src", "10.0.0.1")
            second = check_response(self.admin_misp_connector.add_event(second))

            # Reload to get event data with related events
            first = check_response(self.admin_misp_connector.get_event(first))

            try:
                self.assertEqual(1, len(first.RelatedEvent), first.RelatedEvent)
                self.assertEqual(1, len(second.RelatedEvent), second.RelatedEvent)
            except:
                raise
            finally:
                # Delete events
                for event in (first, second):
                    check_response(self.admin_misp_connector.delete_event(event))

    def test_remove_orphaned_correlations(self):
        result = self.admin_misp_connector._check_response(self.admin_misp_connector._prepare_request('GET', 'servers/removeOrphanedCorrelations'))
        check_response(result)
        self.assertIn("message", result)

    def test_recorrelate(self):
        first = create_simple_event()
        dom_ip_obj = DomainIPObject({'ip': ['10.0.0.1']})
        first.add_object(dom_ip_obj)
        first = check_response(self.admin_misp_connector.add_event(first))

        second = create_simple_event()
        dom_ip_obj = DomainIPObject({'ip': ['10.0.0.1']})
        second.add_object(dom_ip_obj)
        second = check_response(self.admin_misp_connector.add_event(second))

        check_response(self.admin_misp_connector.set_server_setting('MISP.background_jobs', 0, force=True))
        result = self.admin_misp_connector._check_response(self.admin_misp_connector._prepare_request('POST', 'attributes/generateCorrelation'))
        check_response(result)
        self.assertIn("message", result)
        check_response(self.admin_misp_connector.set_server_setting('MISP.background_jobs', 1, force=True))

        first = check_response(self.admin_misp_connector.get_event(first))
        second = check_response(self.admin_misp_connector.get_event(second))

        try:
            self.assertEqual(1, len(first.RelatedEvent), first.RelatedEvent)
            self.assertEqual(1, len(second.RelatedEvent), second.RelatedEvent)
        except:
            raise
        finally:
            # Delete events
            for event in (first, second):
                check_response(self.admin_misp_connector.delete_event(event))

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

        audit_logs = self.admin_misp_connector._check_response(self.admin_misp_connector._prepare_request('GET', 'admin/audit_logs/index'))
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

        result = self._search_event({'returnFormat': "openioc", 'eventid': event.id, "published": [0, 1]})
        ET.fromstring(result)  # check if result is valid XML
        self.assertTrue("1.2.4.5" in result, result)

        result = self._search_event({'returnFormat': "yara", 'eventid': event.id, "published": [0, 1]})
        self.assertTrue("1.2.4.5" in result, result)
        self.assertTrue("GENERATED" in result, result)
        self.assertTrue("AS-IS" in result, result)

        result = self._search_event({'returnFormat': "yara-json", 'eventid': event.id, "published": [0, 1]})
        self.assertIn("generated", result)
        self.assertEqual(len(result["generated"]), 1, result)
        self.assertIn("as-is", result)

        # RPZ
        result = self._search_event({'returnFormat': "rpz", 'eventid': event.id, "published": [0, 1]})
        self.assertTrue("32.5.4.2.1" in result, result)

        result = self._search_attribute({'returnFormat': "rpz", 'eventid': event.id, "published": [0, 1]})
        self.assertTrue("32.5.4.2.1" in result, result)

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

    def test_csp_report(self):
        response = self.admin_misp_connector._prepare_request('POST', 'servers/cspReport', data={
            "csp-report": {
                "test": "test",
            }
        })
        self.assertEqual(204, response.status_code)

    def test_redacted_setting(self):
        response = self.admin_misp_connector.get_server_setting('Security.salt')
        self.assertEqual(403, response["errors"][0])

        response = self.admin_misp_connector._prepare_request('GET', 'servers/serverSettingsEdit/Security.salt')
        response = self.admin_misp_connector._check_response(response)
        self.assertEqual(403, response["errors"][0])

    def test_custom_warninglist(self):
        warninglist = {
            "Warninglist": {
                "name": "Test",
                "description": "Test",
                "type": "cidr",
                "category": "false_positive",
                "matching_attributes": ["ip-src", "ip-dst"],
                "entries": "1.2.3.4",
            }
        }
        wl = request(self.admin_misp_connector, 'POST', 'warninglists/add', data=warninglist)
        check_response(wl)

        exported = request(self.admin_misp_connector, 'GET', f'warninglists/export/{wl["Warninglist"]["id"]}')
        self.assertIn('name', exported)
        self.assertEqual('Test', exported['name'])

        check_response(self.admin_misp_connector.enable_warninglist(wl["Warninglist"]["id"]))

        response = self.admin_misp_connector.values_in_warninglist("1.2.3.4")
        self.assertEqual(wl["Warninglist"]["id"], response["1.2.3.4"][0]["id"])

        warninglist["Warninglist"]["entries"] = "1.2.3.4\n2.3.4.5"
        response = request(self.admin_misp_connector, 'POST', f'warninglists/edit/{wl["Warninglist"]["id"]}', data=warninglist)
        check_response(response)

        response = self.admin_misp_connector.values_in_warninglist("2.3.4.5")
        self.assertEqual(wl["Warninglist"]["id"], response["2.3.4.5"][0]["id"])

        warninglist["Warninglist"]["entries"] = "2.3.4.5"
        response = request(self.admin_misp_connector, 'POST', f'warninglists/edit/{wl["Warninglist"]["id"]}', data=warninglist)
        check_response(response)

        response = self.admin_misp_connector.values_in_warninglist("1.2.3.4")
        self.assertEqual(0, len(response))

        response = self.admin_misp_connector.values_in_warninglist("2.3.4.5")
        self.assertEqual(wl["Warninglist"]["id"], response["2.3.4.5"][0]["id"])

        check_response(self.admin_misp_connector.disable_warninglist(wl["Warninglist"]["id"]))

        response = self.admin_misp_connector.values_in_warninglist("2.3.4.5")
        self.assertEqual(0, len(response))

        # Update by importing
        response = request(self.admin_misp_connector, 'POST', f'warninglists/import', exported)
        check_response(response)

        response = request(self.admin_misp_connector, 'POST', f'warninglists/delete/{wl["Warninglist"]["id"]}')
        check_response(response)

        # Create new warninglist by importing under different name
        exported["name"] = "Test2"
        response = request(self.admin_misp_connector, 'POST', f'warninglists/import', exported)
        check_response(response)

        response = request(self.admin_misp_connector, 'POST', f'warninglists/delete/{response["id"]}')
        check_response(response)

    def test_protected_event(self):
        event = create_simple_event()
        event = check_response(self.admin_misp_connector.add_event(event))

        response = request(self.admin_misp_connector, 'POST', f'events/protect/{event.id}')
        check_response(response)

        response = request(self.admin_misp_connector, 'POST', f'events/unprotect/{event.uuid}')
        check_response(response)

        response = request(self.admin_misp_connector, 'POST', f'events/protect/{event.uuid}')
        check_response(response)

        response = self.admin_misp_connector._prepare_request('GET', f'events/view/{event.id}')
        self.assertIn('x-pgp-signature', response.headers)
        self.assertTrue(len(response.headers['x-pgp-signature']) > 0, response.headers['x-pgp-signature'])

    def test_get_all_apis(self):
        response = self.admin_misp_connector._prepare_request('GET', 'api/getAllApis.json')
        self.assertEqual(200, response.status_code, response)
        response.json()

    def test_taxonomy_export(self):
        response = self.admin_misp_connector._prepare_request('GET', 'taxonomies/export/1')
        self.assertEqual(200, response.status_code, response)
        response.json()

    def test_etag(self):
        headers = {
            'Authorization': key.strip(),
            'Accept': 'application/json',
            'User-Agent': 'PyMISP',
            'If-None-Match': '',
        }
        response = requests.get(self.admin_misp_connector.root_url + '/attributes/describeTypes.json', headers=headers)
        self.assertEqual(200, response.status_code)
        self.assertIn('Etag', response.headers)
        self.assertTrue(len(response.headers['Etag']) > 0, response.headers['Etag'])

        headers['If-None-Match'] = response.headers['Etag']
        response = requests.get(self.admin_misp_connector.root_url + '/attributes/describeTypes.json', headers=headers)
        self.assertEqual(304, response.status_code, response.headers)

    def test_event_alert_default_enabled(self):
        user = MISPUser()
        user.email = 'testusr_alert_disabled@user.local'
        user.org_id = self.test_org.id

        created_user = check_response(self.admin_misp_connector.add_user(user))
        self.assertFalse(created_user.autoalert, created_user)
        self.admin_misp_connector.delete_user(created_user)

        with MISPSetting(self.admin_misp_connector, {"MISP.default_publish_alert": True}):
            user = MISPUser()
            user.email = 'testusr_alert_enabled@user.local'
            user.org_id = self.test_org.id

            created_user = check_response(self.admin_misp_connector.add_user(user))
            self.assertTrue(created_user.autoalert, created_user)
            self.admin_misp_connector.delete_user(created_user)

    def test_attribute_search(self):
        request(self.admin_misp_connector, "GET", "/attributes/search/value:8.8.8.8.json")

    def test_search_snort_suricata(self):
        event = create_simple_event()
        event.add_attribute('ip-src', '8.8.8.8', to_ids=True)
        event.add_attribute('snort', 'alert tcp 192.168.1.0/24 any -> 131.171.127.1 25 (content: "hacking"; msg: "malicious packet"; sid:2000001;)', to_ids=True)
        # Snort rule without msg, test for #9515
        event.add_attribute('snort', 'alert tcp 192.168.1.0/24 any -> 131.171.127.1 25 (content: "hacking"; sid:2000001;)', to_ids=True)
        event = check_response(self.user_misp_connector.add_event(event))

        publish_immediately(self.admin_misp_connector, event)

        snort = self._search_event({'returnFormat': 'snort', 'eventid': event.id})
        self.assertIsInstance(snort, str)
        self.assertIn('8.8.8.8', snort)

        suricata = self._search_event({'returnFormat': 'suricata', 'eventid': event.id})
        self.assertIsInstance(suricata, str)
        self.assertIn('8.8.8.8', suricata)

        self.admin_misp_connector.delete_event(event)

    def test_restsearch_composite_attribute(self):
        event = create_simple_event()
        attribute_1 = event.add_attribute('ip-src|port', '10.0.0.1|8080')
        attribute_2 = event.add_attribute('ip-src|port', '10.0.0.2|8080')
        event = self.user_misp_connector.add_event(event)
        check_response(event)

        search_result = self._search_attribute({'value': '10.0.0.1', 'eventid': event.id})
        self.assertEqual(search_result['Attribute'][0]['uuid'], attribute_1.uuid)
        self.assertEqual(len(search_result['Attribute']), 1)

        search_result = self._search_attribute({'value': '8080', 'eventid': event.id})
        self.assertEqual(len(search_result['Attribute']), 2)

        search_result = self._search_attribute({'value1': '10.0.0.1', 'eventid': event.id})
        self.assertEqual(len(search_result['Attribute']), 1)
        self.assertEqual(search_result['Attribute'][0]['uuid'], attribute_1.uuid)

        search_result = self._search_attribute({'value1': '10.0.0.2', 'eventid': event.id})
        self.assertEqual(len(search_result['Attribute']), 1)
        self.assertEqual(search_result['Attribute'][0]['uuid'], attribute_2.uuid)

        search_result = self._search_attribute({'value2': '8080', 'eventid': event.id})
        self.assertEqual(len(search_result['Attribute']), 2)

        search_result = self._search_attribute({'value1': '10.0.0.1', 'value2': '8080', 'eventid': event.id})
        self.assertEqual(len(search_result['Attribute']), 1)
        self.assertEqual(search_result['Attribute'][0]['uuid'], attribute_1.uuid)

        self.admin_misp_connector.delete_event(event)

    def test_restsearch_sightings(self):
        # Create test event
        event = create_simple_event()
        event = self.admin_misp_connector.add_event(event)
        check_response(event)

        # Add sighting
        sighting = MISPSighting()
        sighting.value = 'test'
        sighting.source = 'Testcases'
        sighting.type = '1'

        response = self.admin_misp_connector.add_sighting(sighting, event.attributes[0])
        check_response(response)
        self.assertEqual(response.source, 'Testcases')

        # Try to find sighting by event UUID, this is the same type of request when doing sync
        search_result = self._search_sighting('event', {
            'returnFormat': 'json',
            'last': 0,
            'includeUuid': True,
            'uuid': [event.uuid],
        })
        self.assertEqual(len(search_result), 1, search_result)
        sighting = search_result[0]["Sighting"]
        self.assertIn("attribute_uuid", sighting)
        self.assertIn("event_uuid", sighting)
        self.assertEqual(sighting["event_uuid"], event.uuid, search_result)

        self.admin_misp_connector.delete_event(event)

    def _search_event(self, query: dict):
        response = self.admin_misp_connector._prepare_request('POST', 'events/restSearch', data=query)
        response = self.admin_misp_connector._check_response(response)
        check_response(response)
        return response

    def _search_attribute(self, query: dict):
        response = self.admin_misp_connector._prepare_request('POST', 'attributes/restSearch', data=query)
        response = self.admin_misp_connector._check_response(response)
        check_response(response)
        return response

    def _search_sighting(self, context: str, query: dict):
        response = self.admin_misp_connector._prepare_request('POST', f'sightings/restSearch/{context}', data=query)
        response = self.admin_misp_connector._check_response(response)
        check_response(response)
        return response


class TestLastPwChange(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin_misp_connector = PyMISP(url, key)

        organisation = MISPOrganisation()
        organisation.name = 'Test org for last pw change tests'
        cls.test_org = cls.admin_misp_connector.add_organisation(organisation, pythonify=True)
        check_response(cls.test_org)
        cls.test_org_id = cls.test_org.id

    @classmethod
    def tearDownClass(cls) -> None:
        cls.admin_misp_connector.delete_organisation(cls.test_org)

    def setUp(self) -> None:
        self.admin_misp_connector = type(self).admin_misp_connector

        # Create a user
        user = MISPUser()
        user.email = 'testusr_last_pw_change@user' + gen_random_id() + '.local'  # make name always unique
        user.org_id = type(self).test_org_id
        user.role_id = 3  # User role
        user.password = str(uuid.uuid4())
        self.test_usr = self.admin_misp_connector.add_user(user, pythonify=True)
        check_response(self.test_usr)
        self.test_usr_misp_connector = PyMISP(url, self.test_usr.authkey)

    def tearDown(self) -> None:
        # Delete Authkey and user
        body = {
            "authkey_start": self.test_usr.authkey[0:4],
            "authkey_end": self.test_usr.authkey[-4:],
            "User.id": self.test_usr.id
        }
        auth_key = type(self).admin_misp_connector.direct_call('auth_keys', body)
        check_response(auth_key)
        if len(auth_key) == 1 and "AuthKey" in auth_key[0]:
            type(self).admin_misp_connector.direct_call(f'auth_keys/delete/{auth_key[0]["AuthKey"]["id"]}', {})

        type(self).admin_misp_connector.delete_user(self.test_usr)

    def test_new_user_last_pw_change_is_date_created(self):
        self.assertEqual(self.test_usr.last_pw_change, self.test_usr.date_created)
        time.sleep(1)

    def test_admin_edit_password_updates_last_pw_change(self):
        old_last_pw_change = self.test_usr.last_pw_change

        # edit user password
        self.test_usr.password = uuid.uuid4()
        time_just_before_update = datetime.now()
        self.updated_test_usr = self.admin_misp_connector.update_user(self.test_usr, pythonify=True)
        time_just_after_update = datetime.now()
        check_response(self.updated_test_usr)

        self.check_last_pw_change_timestamp(old_last_pw_change, time_just_before_update, time_just_after_update)
        time.sleep(1)

    def test_user_change_password_updates_last_pw_change(self):
        old_last_pw_change = self.test_usr.last_pw_change

        # edit user password
        time_just_before_update = datetime.now()
        change_password_result = self.test_usr_misp_connector.change_user_password(uuid.uuid4())
        time_just_after_update = datetime.now()
        check_response(change_password_result)
        self.updated_test_usr = self.test_usr_misp_connector.get_user(pythonify=True)
        check_response(self.updated_test_usr)

        self.check_last_pw_change_timestamp(old_last_pw_change, time_just_before_update, time_just_after_update)
        time.sleep(1)

    def test_reset_user_password_updates_last_pw_change(self):
        old_last_pw_change = self.test_usr.last_pw_change

        # reset user password
        time_just_before_update = datetime.now()
        self.admin_misp_connector.direct_call(f'users/initiatePasswordReset/{self.test_usr.id}', {})
        time.sleep(1)
        time_just_after_update = datetime.now()
        self.updated_test_usr = self.test_usr_misp_connector.get_user(pythonify=True)
        check_response(self.updated_test_usr)

        self.check_last_pw_change_timestamp(old_last_pw_change, time_just_before_update, time_just_after_update)
        time.sleep(1)

    def last_pw_change_almost_equal_to_date_modified(self):
        date_modified = datetime.fromtimestamp(int(self.updated_test_usr.date_modified))
        last_pw_change = datetime.fromtimestamp(int(self.updated_test_usr.last_pw_change))
        return date_modified - last_pw_change < timedelta(milliseconds=5)

    def last_pw_change_time_is_in_expected_range(self, time_just_before_update, time_just_after_update):
        timediff_last_pw_change_now = datetime.fromtimestamp(int(self.updated_test_usr.last_pw_change)) - time_just_before_update
        max_accepted_timediff = time_just_after_update - time_just_before_update
        return timediff_last_pw_change_now <= max_accepted_timediff

    def check_last_pw_change_timestamp(self, old_last_pw_change, time_just_before_update, time_just_after_update):
        # check if new last_pw_change timestamp looks okay, starting with fact that it should be newer than previous one
        # self.assertGreater(self.updated_test_usr.last_pw_change, old_last_pw_change)

        # last pw change should be set to timestamp sometime between time_just_before_update and time_just_after_update
        self.assertTrue(self.last_pw_change_time_is_in_expected_range(time_just_before_update, time_just_after_update))

        # last_pw_change should be relatively close to date_modified
        self.assertTrue(self.last_pw_change_almost_equal_to_date_modified())


def gen_random_id() -> str:
    return str(uuid.uuid4()).split("-")[0]


if __name__ == '__main__':
    unittest.main()
