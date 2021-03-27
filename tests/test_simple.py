import sys
import unittest
import urllib3  # type: ignore
from uuid import uuid4
from keys import url, key  # type: ignore

import logging
logging.disable(logging.CRITICAL)
logger = logging.getLogger('pymisp')


try:
    from pymisp import register_user, PyMISP, MISPEvent, MISPOrganisation, MISPUser, Distribution, ThreatLevel, Analysis, MISPObject, MISPAttribute, MISPSighting, MISPShadowAttribute, MISPTag, MISPSharingGroup, MISPFeed, MISPServer, MISPUserSetting, MISPEventBlocklist, MISPEventReport, MISPGalaxyCluster
except ImportError:
    if sys.version_info < (3, 6):
        print('This test suite requires Python 3.6+, breaking.')
        sys.exit(0)
    else:
        raise

urllib3.disable_warnings()


def create_simple_event(force_timestamps=False):
    mispevent = MISPEvent(force_timestamps=force_timestamps)
    mispevent.info = 'This is a super simple test'
    mispevent.distribution = Distribution.your_organisation_only
    mispevent.threat_level_id = ThreatLevel.low
    mispevent.analysis = Analysis.completed
    mispevent.add_attribute('text', str(uuid4()))
    return mispevent


def check_response(response):
    if isinstance(response, dict) and "errors" in response:
        raise Exception(response["errors"])

class TestComprehensive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Connect as admin
        cls.admin_misp_connector = PyMISP(url, key, False, debug=False)
        check_response(cls.admin_misp_connector.set_server_setting('debug', 1, force=True))
        check_response(cls.admin_misp_connector.set_default_role(3))

        # Creates an org
        organisation = MISPOrganisation()
        organisation.name = 'Test Org'
        cls.test_org = cls.admin_misp_connector.add_organisation(organisation, pythonify=True)
        check_response(cls.test_org)

        # Creates a user
        user = MISPUser()
        user.email = 'testusr@user.local'
        user.org_id = cls.test_org.id
        cls.test_usr = cls.admin_misp_connector.add_user(user, pythonify=True)
        check_response(cls.test_usr)
        cls.user_misp_connector = PyMISP(url, cls.test_usr.authkey, False, debug=True)
        cls.user_misp_connector.toggle_global_pythonify()

        # Creates a publisher
        user = MISPUser()
        user.email = 'testpub@user.local'
        user.org_id = cls.test_org.id
        user.role_id = 4
        cls.test_pub = cls.admin_misp_connector.add_user(user, pythonify=True)
        check_response(cls.test_pub)
        cls.pub_misp_connector = PyMISP(url, cls.test_pub.authkey, False)

    @classmethod
    def tearDownClass(cls):
        # Delete publisher
        cls.admin_misp_connector.delete_user(cls.test_pub)
        # Delete user
        cls.admin_misp_connector.delete_user(cls.test_usr)
        # Delete org
        cls.admin_misp_connector.delete_organisation(cls.test_org)

    def test_event_galaxy(self):
        self.admin_misp_connector.toggle_global_pythonify()
        event = create_simple_event()
        try:
            galaxy = self.admin_misp_connector.galaxies()[0]
            print(galaxy.id)
            galaxy = self.admin_misp_connector.get_galaxy(galaxy.id, withCluster=True)
            print(galaxy)
            galaxy_cluster = galaxy.clusters[0]
            event.add_tag(galaxy_cluster.tag_name)
            event = self.admin_misp_connector.add_event(event)
            # The event should have a galaxy attached
            self.assertEqual(len(event.galaxies), 1)
            event_galaxy = event.galaxies[0]
            # The galaxy ID should equal the galaxy from which the cluster came from
            self.assertEqual(event_galaxy.id, galaxy.id)
            # The galaxy cluster should equal the cluster added
            self.assertEqual(event_galaxy.clusters[0].id, galaxy_cluster.id)
        finally:
            self.admin_misp_connector.delete_event(event)
            self.admin_misp_connector.toggle_global_pythonify()

if __name__ == '__main__':
    unittest.main()
