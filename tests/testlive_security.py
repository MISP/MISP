#!/usr/bin/env python3
import os
import sys
import time
import json
import datetime
import unittest
from unittest.util import safe_repr
from typing import Union, List, Optional
import urllib3  # type: ignore
import logging
import uuid
import warnings
import requests
import subprocess
from lxml.html import fromstring
from enum import Enum

try:
    from pymisp import PyMISP, MISPOrganisation, MISPUser, MISPRole, MISPSharingGroup, MISPEvent, MISPLog, MISPSighting, Distribution
    from pymisp.exceptions import PyMISPError, NoKey, MISPServerError
    from pymisp.api import get_uuid_or_id_from_abstract_misp
except ImportError:
    if sys.version_info < (3, 6):
        print('This test suite requires Python 3.6+, breaking.')
        sys.exit(0)
    else:
        raise

# Load access information for env variables
url = "http://" + os.environ["HOST"]
key = os.environ["AUTH"]

# TODO?
urllib3.disable_warnings()
logging.disable(logging.CRITICAL)
logger = logging.getLogger('pymisp')


class ROLE(Enum):
    ADMIN = 1
    ORG_ADMIN = 2
    USER = 3
    PUBLISHER = 4
    SYNC_USER = 5


def check_response(response):
    if isinstance(response, dict) and "errors" in response:
        raise Exception(response["errors"])
    return response


def login(url: str, email: str, password: str) -> requests.Session:
    session = requests.Session()

    r = session.get(url)
    r.raise_for_status()

    parsed = fromstring(r.text)

    if len(parsed.forms) != 1:
        raise Exception("Login form not found in: " + r.text)

    form = parsed.forms[0]
    form_fields = form.fields

    login_form = {}
    for name in form_fields:
        login_form[name] = form_fields[name]
    login_form["data[User][email]"] = email
    login_form["data[User][password]"] = password

    r = session.post(url + form.action, login_form, allow_redirects=False)
    r.raise_for_status()
    if r.status_code == 302:
        r = session.get(r.headers['Location'].replace(":8080", ""), allow_redirects=False)  # TODO
        r.raise_for_status()

    r = session.get(url + "/users/view/me.json")
    try:
        r.raise_for_status()
    except requests.HTTPError:
        return False

    r = r.json()
    if email != r["User"]["email"]:
        raise Exception(r)  # logged in as different user
    return session


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


def send(api: PyMISP, request_type: str, url: str, data=None, check_errors: bool = True) -> dict:
    if data is None:
        data = {}
    response = api._prepare_request(request_type, url, data=data)
    response = api._check_response(response)
    if check_errors:
        check_response(response)
    return response


def random() -> str:
    return str(uuid.uuid4()).split("-")[0]


def publish_immediately(pymisp: PyMISP, event: Union[MISPEvent, int, str, uuid.UUID], with_email: bool = False):
    event_id = get_uuid_or_id_from_abstract_misp(event)
    action = "alert" if with_email else "publish"
    return send(pymisp, 'POST', f'events/{action}/{event_id}/disable_background_processing:1')


class TestSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)

        # Connect as site admin
        cls.admin_misp_connector = PyMISP(url, key)

        # Set expected config values
        check_response(cls.admin_misp_connector.set_server_setting('debug', 1, force=True))
        check_response(cls.admin_misp_connector.set_server_setting('Security.advanced_authkeys', True, force=True))
        cls.admin_misp_connector.global_pythonify = True

        # we get rid of the legacy authkey checks as those are currently broken since the fix to not having the same keys in the old + new system

        # Check if admin is really site admin
        assert cls.admin_misp_connector._current_role.perm_site_admin

        # Create advanced authkey, so connector will work even after advanced keys are required
        cls.admin_advanced_authkey = cls.__create_advanced_authkey(cls, cls.admin_misp_connector._current_user.id)
        cls.admin_misp_connector.key = cls.admin_misp_connector.key + "," + cls.admin_advanced_authkey["authkey_raw"]

        # Creates an org
        organisation = MISPOrganisation()
        organisation.name = 'Test Org ' + random()  # make name always unique
        cls.test_org = cls.admin_misp_connector.add_organisation(organisation)
        check_response(cls.test_org)

        # Creates org admin
        org_admin = MISPUser()
        org_admin.email = 'testorgadmin@user' + random() + '.local'  # make name always unique
        org_admin.org_id = cls.test_org.id
        org_admin.role_id = 2  # Org admin role
        cls.test_org_admin = cls.admin_misp_connector.add_user(org_admin)
        check_response(cls.test_org_admin)

        # Creates advanced auth key for org admin
        cls.org_admin_advanced_authkey = cls.__create_advanced_authkey(cls, cls.test_org_admin.id)
        cls.org_admin_misp_connector = PyMISP(url, cls.test_org_admin.authkey + "," + cls.org_admin_advanced_authkey["authkey_raw"])
        cls.org_admin_misp_connector.global_pythonify = True

        # Creates an user
        cls.test_usr_password = str(uuid.uuid4())
        user = MISPUser()
        user.email = 'testusr@user' + random() + '.local'  # make name always unique
        user.org_id = cls.test_org.id
        user.role_id = 3  # User role
        user.password = cls.test_usr_password
        cls.test_usr = cls.admin_misp_connector.add_user(user)
        check_response(cls.test_usr)

        test_usr_key = cls.__create_advanced_authkey(cls, cls.test_usr.id)
        cls.test_usr.authkey = test_usr_key["authkey_raw"]
        assert(cls.test_usr.authkey == test_usr_key["authkey_raw"])

        # Try to connect as user to check if everything works
        PyMISP(url, cls.test_usr.authkey)
        # Check if user can login with given password
        assert isinstance(login(url, cls.test_usr.email, cls.test_usr_password), requests.Session)

    @classmethod
    def tearDownClass(cls):
        cls.admin_misp_connector.delete_user(cls.test_usr)
        cls.admin_misp_connector.delete_user(cls.test_org_admin)
        cls.admin_misp_connector.delete_organisation(cls.test_org)
        cls.__delete_advanced_authkey(cls, cls.admin_advanced_authkey["id"])
        cls.__delete_advanced_authkey(cls, cls.org_admin_advanced_authkey["id"])

    def setUp(self):
        # Do not show warning about not closed resources, because that something we want
        warnings.simplefilter("ignore", ResourceWarning)

    def test_not_logged_in(self):
        session = requests.Session()

        # Should redirect to login page
        for path in ("/", "/events/index", "/servers/index", "/users/checkIfLoggedIn"):
            r = session.get(url + path, allow_redirects=False)
            self.assertEqual(302, r.status_code, path)
            self.assertEqual(url + "/users/login", r.headers['Location'], path)

        # Should be accessible without login
        for path in ("/users/login",):
            r = session.get(url + path, allow_redirects=False)
            self.assertEqual(200, r.status_code, path)

        with self.__setting("Security.allow_self_registration", True):
            r = session.get(url + "/users/register", allow_redirects=False)
            self.assertEqual(200, r.status_code, path)

        with self.__setting("Security.allow_self_registration", False):
            r = session.get(url + "/users/register", allow_redirects=False)
            self.assertEqual(302, r.status_code)
            self.assertEqual(url + "/users/login", r.headers['Location'])

    def test_empty_authkey(self):
        with self.assertRaises(NoKey):
            PyMISP(url, "")

    def test_invalid_length_authkey(self):
        with self.assertRaises(PyMISPError):
            PyMISP(url, "ahoj")

    def test_invalid_authkey(self):
        with self.assertRaises(PyMISPError):
            PyMISP(url, "pCZDbBr3wYPlY0DrlQzoD8EWrcClGc0Dqu2yMYyE")

    def test_invalid_authkey_start_end_correct(self):
        authkey = self.test_usr.authkey[0:4] + ("a" * 32) + self.test_usr.authkey[:-4]
        with self.assertRaises(PyMISPError):
            PyMISP(url, authkey)

    def test_no_auth_access(self):
        no_access_role = MISPRole()
        no_access_role.name = "No auth access"

        no_access_role = send(self.admin_misp_connector, "POST", 'admin/roles/add', data=no_access_role)
        self.assertFalse(no_access_role["Role"]["perm_auth"])
        no_access_role_id = no_access_role["Role"]["id"]

        # Change user role to no access role
        updated_user = self.admin_misp_connector.update_user({'role_id': no_access_role_id}, self.test_usr)
        check_response(updated_user)
        self.assertEqual(no_access_role_id, updated_user.role_id)

        with self.assertRaises(PyMISPError):
            PyMISP(url, self.test_usr.authkey)

        # Change user role back to origin one and try to connect
        updated_user = self.admin_misp_connector.update_user({'role_id': self.test_usr.role_id}, self.test_usr)
        check_response(updated_user)
        self.assertEqual(self.test_usr.role_id, updated_user.role_id)
        PyMISP(url, self.test_usr.authkey)

        # Delete test role
        self.admin_misp_connector._prepare_request('POST', f'admin/roles/delete/{no_access_role_id}')

    def test_assign_role_by_myself(self):
        logged_in = PyMISP(url, self.test_usr.authkey)
        logged_in.global_pythonify = True
        update_user = logged_in.update_user({'role_id': 1}, self.test_usr)
        # Check if role was not changed
        self.assertEqual(self.test_usr.role_id, update_user.role_id)

    def test_assign_site_admin_role_by_org_admin(self):
        with self.assertRaises(MISPServerError):
            self.org_admin_misp_connector.update_user({'role_id': 1}, self.test_usr)

    def test_user_must_change_password(self):
        updated_user = self.admin_misp_connector.update_user({'change_pw': 1}, self.test_usr)
        check_response(updated_user)
        self.assertTrue(updated_user.change_pw)

        # Try to login, should still work because key is still valid
        PyMISP(url, self.test_usr.authkey)

        updated_user = self.admin_misp_connector.update_user({'change_pw': 0}, self.test_usr)
        check_response(updated_user)
        self.assertFalse(updated_user.change_pw)

        # Try to login, should also still works
        PyMISP(url, self.test_usr.authkey)

    def test_user_must_change_password_by_myself(self):
        # Admin set that user must change password
        updated_user = self.admin_misp_connector.update_user({'change_pw': 1}, self.test_usr)
        check_response(updated_user)
        self.assertTrue(updated_user.change_pw)

        # User try to change back through API
        logged_in = PyMISP(url, self.test_usr.authkey)
        logged_in.update_user({'change_pw': 0}, self.test_usr)

        updated_user = self.admin_misp_connector.get_user(self.test_usr)
        # Should not be possible
        self.assertTrue(updated_user.change_pw)

    def test_disabled_user(self):
        # Disable user
        updated_user = self.admin_misp_connector.update_user({'disabled': True}, self.test_usr)
        check_response(updated_user)
        self.assertTrue(updated_user.disabled)

        # Try to login
        self.assertFalse(login(url, self.test_usr.email, self.test_usr_password))

        # Enable user
        updated_user = self.admin_misp_connector.update_user({'disabled': False}, self.test_usr)
        check_response(updated_user)
        self.assertFalse(updated_user.disabled)

        # Try to login
        self.assertIsInstance(login(url, self.test_usr.email, self.test_usr_password), requests.Session)

    def test_disabled_user_api_access(self):
        # Disable user
        updated_user = self.admin_misp_connector.update_user({'disabled': True}, self.test_usr)
        check_response(updated_user)
        self.assertTrue(updated_user.disabled)

        # Try to login
        with self.assertRaises(PyMISPError):
            PyMISP(url, self.test_usr.authkey)

        # Enable user
        updated_user = self.admin_misp_connector.update_user({'disabled': False}, self.test_usr)
        check_response(updated_user)
        self.assertFalse(updated_user.disabled)

        # Try to login
        PyMISP(url, self.test_usr.authkey)

    def test_disabled_misp(self):
        with self.__setting("MISP.live", False):
            self.assertFalse(login(url, self.test_usr.email, self.test_usr_password))

        # Check if user can login with given password
        self.assertIsInstance(login(url, self.test_usr.email, self.test_usr_password), requests.Session)

    def test_disabled_misp_api_access(self):
        with self.__setting("MISP.live", False):
            # Try to login
            with self.assertRaises(PyMISPError):
                PyMISP(url, self.test_usr.authkey)

        # Try to login
        PyMISP(url, self.test_usr.authkey)

    def test_advanced_authkeys(self):
        with self.__setting("Security.advanced_authkeys", True):
            # Create advanced authkey
            auth_key = self.__create_advanced_authkey(self.test_usr.id)
            self.assertNotIn("authkey", auth_key)

            # Try to login
            logged_in = PyMISP(url, auth_key["authkey_raw"])
            self.assertEqual(logged_in._current_user.id, self.test_usr.id)

            self.__delete_advanced_authkey(auth_key["id"])

    def test_advanced_authkeys_expired(self):
        with self.__setting("Security.advanced_authkeys", True):
            # Create expired advanced authkey
            auth_key = self.__create_advanced_authkey(self.test_usr.id, {
                "expiration": "1990-01-05",
            })

            # Try to login
            with self.assertRaises(PyMISPError):
                PyMISP(url, auth_key["authkey_raw"])

            self.__delete_advanced_authkey(auth_key["id"])

    def test_advanced_authkeys_invalid_start_end_correct(self):
        with self.__setting("Security.advanced_authkeys", True):
            # Create advanced authkey
            auth_key = self.__create_advanced_authkey(self.test_usr.id)

            # Try to login
            authkey = auth_key["authkey_raw"][0:4] + ("a" * 32) + auth_key["authkey_raw"][:-4]
            with self.assertRaises(PyMISPError):
                PyMISP(url, authkey)

            self.__delete_advanced_authkey(auth_key["id"])

    def test_advanced_authkeys_deleted(self):
        with self.__setting("Security.advanced_authkeys", True):
            auth_key = self.__create_advanced_authkey(self.test_usr.id)

            logged_in = PyMISP(url, auth_key["authkey_raw"])
            self.assertEqual(logged_in._current_user.id, self.test_usr.id)

            self.__delete_advanced_authkey(auth_key["id"])

            self.assertErrorResponse(logged_in.get_user())

    def test_advanced_authkeys_deleted_keep_session(self):
        with self.__setting({
            "Security": {
                "advanced_authkeys": True,
                "authkey_keep_session": True,
            }
        }):
            auth_key = self.__create_advanced_authkey(self.test_usr.id)

            logged_in = PyMISP(url, auth_key["authkey_raw"])
            self.assertEqual(logged_in._current_user.id, self.test_usr.id)

            # Wait one second to really know that session will be reloaded
            time.sleep(1)

            self.__delete_advanced_authkey(auth_key["id"])

            with self.assertRaises(MISPServerError):
                logged_in.get_user()

        time.sleep(1)

    def test_advanced_authkeys_non_exists_user(self):
        new_auth_key = send(self.admin_misp_connector, "POST", "authKeys/add/9999", check_errors=False)
        self.assertErrorResponse(new_auth_key)
        self.assertIn("user_id", new_auth_key["errors"][1]["errors"])

    def test_advanced_authkeys_own_key_not_possible(self):
        authkey = ("a" * 40)
        auth_key = self.__create_advanced_authkey(self.test_usr.id, {"authkey": authkey})
        self.__delete_advanced_authkey(auth_key["id"])
        self.assertNotEqual(authkey, auth_key["authkey_raw"])

    def test_advanced_authkeys_reset_own(self):
        with self.__setting("Security.advanced_authkeys", True):
            # Create advanced authkey
            auth_key = self.__create_advanced_authkey(self.test_usr.id)

            # Try to login
            logged_in = PyMISP(url, auth_key["authkey_raw"])
            self.assertEqual(logged_in._current_user.id, self.test_usr.id)

            # Reset auth key
            new_auth_key = send(logged_in, "POST", "users/resetauthkey/me")
            new_auth_key = new_auth_key["message"].replace("Authkey updated: ", "")

            # Try to login with old key
            with self.assertRaises(PyMISPError):
                PyMISP(url, auth_key["authkey_raw"])

            # Try to login with new key
            logged_in = PyMISP(url, new_auth_key)
            self.assertEqual(logged_in._current_user.id, self.test_usr.id)

            self.__delete_advanced_authkey(auth_key["id"])
            # TODO: Delete new key

    def test_advanced_authkeys_reset_for_different_user(self):
        with self.__setting("Security.advanced_authkeys", True):
            # Create advanced authkey
            auth_key = self.__create_advanced_authkey(self.test_usr.id)

            # Try to login
            logged_in = PyMISP(url, auth_key["authkey_raw"])
            self.assertEqual(logged_in._current_user.id, self.test_usr.id)

            # Reset auth key for different user
            new_auth_key = send(logged_in, "POST", "users/resetauthkey/1", check_errors=False)
            self.assertErrorResponse(new_auth_key)

            # Try to login again
            logged_in = PyMISP(url, auth_key["authkey_raw"])
            self.assertEqual(logged_in._current_user.id, self.test_usr.id)

            self.__delete_advanced_authkey(auth_key["id"])

    def test_advanced_authkeys_reset_org_admin(self):
        with self.__setting("Security.advanced_authkeys", True):
            # Create advanced authkey
            auth_key = self.__create_advanced_authkey(self.test_usr.id)

            # Try to login
            logged_in = PyMISP(url, auth_key["authkey_raw"])
            self.assertEqual(logged_in._current_user.id, self.test_usr.id)

            # Reset auth key from org admin account
            new_auth_key = send(self.org_admin_misp_connector, "POST", f"users/resetauthkey/{self.test_usr.id}")
            new_auth_key = new_auth_key["message"].replace("Authkey updated: ", "")
            self.test_usr.authkey = new_auth_key

            # Try to login with old key
            with self.assertRaises(PyMISPError):
                PyMISP(url, auth_key["authkey_raw"])

            # Try to login with new key
            logged_in = PyMISP(url, new_auth_key)
            self.assertEqual(logged_in._current_user.id, self.test_usr.id)

            self.__delete_advanced_authkey(auth_key["id"])
            # TODO: Delete new key

    def test_advanced_authkeys_expiration_invalid(self):
        with self.__setting("Security.advanced_authkeys", True):
            with self.assertRaises(Exception) as cm:
                self.__create_advanced_authkey(self.test_usr.id, {"expiration": "__nonsense__"})
            self.assertIn("expiration", cm.exception.args[0][1]["errors"])

    def test_advanced_authkeys_validity_autoset(self):
        with self.__setting({
            "Security": {
                "advanced_authkeys": True,
                "advanced_authkeys_validity": 365,
            }
        }):
            auth_key = self.__create_advanced_authkey(self.test_usr.id)
            self.assertNotEqual(0, auth_key["expiration"])

    def test_advanced_authkeys_validity_in_range(self):
        with self.__setting({
            "Security": {
                "advanced_authkeys": True,
                "advanced_authkeys_validity": 365,
            }
        }):
            expiration = int((datetime.datetime.now() + datetime.timedelta(days=300)).timestamp())
            auth_key = self.__create_advanced_authkey(self.test_usr.id, {"expiration": expiration})
            self.__delete_advanced_authkey(auth_key["id"])
            self.assertEqual(expiration, int(auth_key["expiration"]))

    def test_advanced_authkeys_validity_not_in_range(self):
        with self.__setting({
            "Security": {
                "advanced_authkeys": True,
                "advanced_authkeys_validity": 365,
            }
        }):
            expiration = int((datetime.datetime.now() + datetime.timedelta(days=400)).timestamp())
            with self.assertRaises(Exception) as cm:
                self.__create_advanced_authkey(self.test_usr.id, {"expiration": expiration})
            self.assertIn("expiration", cm.exception.args[0][1]["errors"])

    def test_advanced_authkeys_view(self):
        with self.__setting("Security.advanced_authkeys", True):
            auth_key = self.__create_advanced_authkey(self.test_usr.id)
            auth_key_id = auth_key["id"]
            auth_key = send(self.admin_misp_connector, "GET", f'authKeys/view/{auth_key_id}')
            self.__delete_advanced_authkey(auth_key_id)
            self.assertNotIn("authkey", auth_key["AuthKey"], "Response should not contain hashed authkey")

    def test_advanced_authkeys_index(self):
        with self.__setting("Security.advanced_authkeys", True):
            auth_key_id = self.__create_advanced_authkey(self.test_usr.id)["id"]
            auth_keys = send(self.admin_misp_connector, "GET", 'authKeys/index/')
            self.__delete_advanced_authkey(auth_key_id)

            self.assertGreaterEqual(len(auth_keys), 1, "Response should contains at least one key")
            for auth_key in auth_keys:
                self.assertNotIn("authkey", auth_key["AuthKey"], "Response should not contain hashed authkey")

    def test_advanced_authkeys_user_disabled(self):
        with self.__setting("Security.advanced_authkeys", True):
            auth_key = self.__create_advanced_authkey(self.test_usr.id)

            updated_user = self.admin_misp_connector.update_user({'disabled': True}, self.test_usr)
            check_response(updated_user)
            self.assertTrue(updated_user.disabled)

            # Try to login
            with self.assertRaises(PyMISPError):
                PyMISP(url, auth_key["authkey_raw"])

            # Enable user
            updated_user = self.admin_misp_connector.update_user({'disabled': False}, self.test_usr)
            check_response(updated_user)
            self.assertFalse(updated_user.disabled)

            # Try to login
            PyMISP(url, auth_key["authkey_raw"])

            self.__delete_advanced_authkey(auth_key["id"])

    def test_advanced_authkeys_invalid_ip(self):
        with self.__setting("Security.advanced_authkeys", True):
            auth_key = self.__create_advanced_authkey(self.test_usr.id, {
                "allowed_ips": ["1.2.3.4"],
            })

            # Try to login
            with self.assertRaises(PyMISPError):
                PyMISP(url, auth_key["authkey_raw"])

            self.__delete_advanced_authkey(auth_key["id"])

    def test_advanced_authkeys_allow_all(self):
        with self.__setting("Security.advanced_authkeys", True):
            auth_key = self.__create_advanced_authkey(self.test_usr.id, {
                "allowed_ips": ["0.0.0.0/0", "::/0"],
            })

            # Try to login
            PyMISP(url, auth_key["authkey_raw"])

            self.__delete_advanced_authkey(auth_key["id"])

    def test_advanced_authkeys_read_only_false(self):
        with self.__setting("Security.advanced_authkeys", True):
            auth_key = self.__create_advanced_authkey(self.test_usr.id, {
                "read_only": 0,
            })
            self.assertFalse(auth_key["read_only"])

            # Try to login
            logged_in = self.__login_by_advanced_authkey(auth_key)

            # Create new event should not be possible with read only key
            event = logged_in.add_event(self.__generate_event())
            check_response(event)

            self.__delete_advanced_authkey(auth_key["id"])

    def test_advanced_authkeys_read_only(self):
        with self.__setting("Security.advanced_authkeys", True):
            auth_key = self.__create_advanced_authkey(self.test_usr.id, {
                "read_only": 1,
            })
            self.assertTrue(auth_key["read_only"])

            # Try to login
            logged_in = self.__login_by_advanced_authkey(auth_key)

            # Create new event should not be possible with read only key
            event = logged_in.add_event(self.__generate_event())
            with self.assertRaises(Exception):
                check_response(event)

            self.__delete_advanced_authkey(auth_key["id"])

    def test_advanced_authkeys_read_only_edit_self(self):
        with self.__setting("Security.advanced_authkeys", True):
            auth_key = self.__create_advanced_authkey(self.test_usr.id, {
                "read_only": 1,
            })
            self.assertTrue(auth_key["read_only"])

            # Try to login
            logged_in = self.__login_by_advanced_authkey(auth_key)

            # Edit current auth key and set it to not read_only should be not possible
            with self.assertRaises(Exception):
                send(logged_in, "POST", f'authKeys/edit/{auth_key["id"]}', {"read_only": 0})

            self.__delete_advanced_authkey(auth_key["id"])

    def test_advanced_authkeys_read_only_create_new_authkey(self):
        with self.__setting("Security.advanced_authkeys", True):
            auth_key = self.__create_advanced_authkey(self.test_usr.id, {
                "read_only": 1,
            })
            self.assertTrue(auth_key["read_only"])

            # Try to login
            logged_in = self.__login_by_advanced_authkey(auth_key)

            # Create new auth key should be not possible
            with self.assertRaises(Exception):
                send(logged_in, "POST", f'authKeys/add/{logged_in._current_user.id}')

            self.__delete_advanced_authkey(auth_key["id"])

    def test_advanced_authkeys_read_only_reset_authkey(self):
        with self.__setting("Security.advanced_authkeys", True):
            auth_key = self.__create_advanced_authkey(self.test_usr.id, {
                "read_only": 1,
            })
            self.assertTrue(auth_key["read_only"])

            # Try to login
            logged_in = self.__login_by_advanced_authkey(auth_key)

            # Create new auth key should be not possible
            with self.assertRaises(Exception):
                send(logged_in, "POST", "users/resetauthkey/me")

            self.__delete_advanced_authkey(auth_key["id"])

    def test_authkey_keep_session(self):
        with self.__setting("Security.authkey_keep_session", True):
            logged_in = PyMISP(url, self.test_usr.authkey)
            check_response(logged_in.get_user())
            check_response(logged_in.get_user())

    def test_change_login(self):
        new_email = 'testusr@user' + random() + '.local'

        logged_in = PyMISP(url, self.test_usr.authkey)
        logged_in.global_pythonify = True

        # Change email
        updated_user = logged_in.update_user({'email': new_email}, self.test_usr)
        check_response(updated_user)
        self.assertEqual(new_email, updated_user.email)

        # Change email back
        updated_user = logged_in.update_user({'email': self.test_usr.email}, self.test_usr)
        check_response(updated_user)
        self.assertEqual(self.test_usr.email, updated_user.email)

    def test_change_login_disabled(self):
        with self.__setting("MISP.disable_user_login_change", True):
            new_email = 'testusr@user' + random() + '.local'

            logged_in = PyMISP(url, self.test_usr.authkey)
            logged_in.global_pythonify = True

            # Try to change email
            updated_user = logged_in.update_user({'email': new_email}, self.test_usr)
            check_response(updated_user)

            # Change should be not successful
            self.assertEqual(self.test_usr.email, updated_user.email)

    def test_change_login_org_admin(self):
        # Try to change email as org admin
        new_email = 'testusr@user' + random() + '.local'
        updated_user = self.org_admin_misp_connector.update_user({'email': new_email}, self.test_usr)
        check_response(updated_user)

        # Change should be successful
        self.assertEqual(new_email, updated_user.email)

        # Change email back
        updated_user = self.org_admin_misp_connector.update_user({'email': self.test_usr.email}, self.test_usr)
        check_response(updated_user)
        self.assertEqual(self.test_usr.email, updated_user.email)

    def test_change_login_disabled_org_admin(self):
        with self.__setting("MISP.disable_user_login_change", True):
            # Try to change email as org admin
            new_email = 'testusr@user' + random() + '.local'
            updated_user = self.org_admin_misp_connector.update_user({'email': new_email}, self.test_usr)
            self.assertEqual(self.test_usr.email, updated_user.email, "Email should be still same")

    def test_change_pw_disabled(self):
        with self.__setting("MISP.disable_user_password_change", True):
            logged_in = PyMISP(url, self.test_usr.authkey)
            logged_in.global_pythonify = True
            logged_in.change_user_password(str(uuid.uuid4()))

        # Password should be still the same
        self.assertIsInstance(login(url, self.test_usr.email, self.test_usr_password), requests.Session)

    def test_change_pw_disabled_different_way(self):
        with self.__setting("MISP.disable_user_password_change", True):
            logged_in = PyMISP(url, self.test_usr.authkey)
            logged_in.global_pythonify = True
            logged_in.update_user({"password": str(uuid.uuid4())}, self.test_usr.id)

        # Password should be still the same
        self.assertIsInstance(login(url, self.test_usr.email, self.test_usr_password), requests.Session)

    def test_change_pw_by_site_admin(self):
        old_password = self.test_usr_password
        new_password = str(uuid.uuid4())
        check_response(self.admin_misp_connector.update_user({"password": new_password}, self.test_usr.id))

        self.assertFalse(login(url, self.test_usr.email, old_password), "Old password should not works")
        self.assertIsInstance(login(url, self.test_usr.email, new_password), requests.Session)

        # Set password back to original
        self.admin_misp_connector.update_user({"password": old_password}, self.test_usr.id)

    def test_change_pw_by_org_admin(self):
        old_password = self.test_usr_password
        new_password = str(uuid.uuid4())
        check_response(self.org_admin_misp_connector.update_user({"password": new_password}, self.test_usr.id))

        self.assertFalse(login(url, self.test_usr.email, old_password), "Old password should not works")
        self.assertIsInstance(login(url, self.test_usr.email, new_password), requests.Session)

        # Set password back to original
        self.org_admin_misp_connector.update_user({"password": old_password}, self.test_usr.id)

    def test_change_pw_disabled_by_org_admin(self):
        with self.__setting("MISP.disable_user_password_change", True):
            self.org_admin_misp_connector.update_user({"password": str(uuid.uuid4())}, self.test_usr.id)

        # Password should be still the same
        self.assertIsInstance(login(url, self.test_usr.email, self.test_usr_password), requests.Session)

    def test_forget_password_not_enabled(self):
        logged_in = PyMISP(url, self.test_usr.authkey)
        logged_in.global_pythonify = True

        with self.assertRaises(Exception):
            send(logged_in, "GET", f"/users/forget")

        with self.assertRaises(Exception):
            send(logged_in, "GET", f"/users/password_reset/abcd")

    def test_otp_disabled(self):
        with self.__setting("Security.otp_disabled", True):
            logged_in = PyMISP(url, self.test_usr.authkey)
            logged_in.global_pythonify = True

            with self.assertRaises(Exception):
                send(logged_in, "GET", f"/users/totp_new")

            with self.assertRaises(Exception):
                send(logged_in, "GET", f"/users/totp_delete/1")

    def test_add_user_by_org_admin(self):
        user = MISPUser()
        user.email = 'testusr@user' + random() + '.local'  # make name always unique
        user.org_id = self.test_org.id
        user.role_id = 3
        created_user = self.org_admin_misp_connector.add_user(user)
        check_response(created_user)

        deleted = self.org_admin_misp_connector.delete_user(created_user)
        check_response(deleted)

    def test_add_user_by_org_admin_to_different_org(self):
        user = MISPUser()
        user.email = 'testusr@user' + random() + '.local'  # make name always unique
        user.org_id = 1
        user.role_id = 3
        created_user = self.org_admin_misp_connector.add_user(user)
        check_response(created_user)

        # Org should be silently changed to correct org
        self.assertEqual(created_user.org_id, self.test_org_admin.org_id)

        deleted = self.org_admin_misp_connector.delete_user(created_user)
        check_response(deleted)

    def test_add_user_by_org_admin_disabled(self):
        with self.__setting("MISP.disable_user_add", True):
            user = MISPUser()
            user.email = 'testusr@user' + random() + '.local'  # make name always unique
            user.org_id = self.test_org.id
            user.role_id = 3
            created_user = self.org_admin_misp_connector.add_user(user)
            self.assertErrorResponse(created_user)

    def test_change_user_org_by_org_admin_different_org(self):
        updated_user = self.org_admin_misp_connector.update_user({'org_id': 1}, self.test_usr)
        check_response(updated_user)

        # Org should be silently keep to correct org
        self.assertEqual(updated_user.org_id, self.test_usr.org_id)

    def test_change_user_org_by_myself(self):
        logged_in = PyMISP(url, self.test_usr.authkey)
        logged_in.global_pythonify = True
        updated_user = logged_in.update_user({'org_id': 1}, self.test_usr)

        # Org should be silently keep to correct org
        self.assertEqual(updated_user.org_id, self.test_usr.org_id)

    def test_shibb_existing_user(self):
        with self.__setting(self.__default_shibb_config()):
            session = requests.Session()
            session.headers["Email-Tag"] = self.test_usr.email
            session.headers["Federation-Tag"] = self.test_org.name
            session.headers["Group-Tag"] = "user"

            session.get(url, allow_redirects=False)
            r = session.get(url + "/users/view/me.json")
            r.raise_for_status()
            json_response = r.json()
            self.assertEqual(self.test_usr.email, json_response["User"]["email"])
            self.assertEqual(3, int(json_response["User"]["role_id"]))
            self.assertEqual(session.headers["Federation-Tag"], json_response["Organisation"]["name"])

    def test_shibb_new_user(self):
        with self.__setting(self.__default_shibb_config()):
            session = requests.Session()
            session.headers["Email-Tag"] = "external@user" + random() + ".local"
            session.headers["Federation-Tag"] = self.test_org.name
            session.headers["Group-Tag"] = "user"

            session.get(url, allow_redirects=False)
            r = session.get(url + "/users/view/me.json")
            r.raise_for_status()
            json_response = r.json()
            self.assertEqual(session.headers["Email-Tag"], json_response["User"]["email"])
            self.assertEqual(3, int(json_response["User"]["role_id"]))
            self.assertEqual(session.headers["Federation-Tag"], json_response["Organisation"]["name"])

            self.admin_misp_connector.delete_user(json_response["User"]["id"])

    def test_shibb_new_user_multiple_groups(self):
        with self.__setting(self.__default_shibb_config()):
            session = requests.Session()
            session.headers["Email-Tag"] = "external@user" + random() + ".local"
            session.headers["Federation-Tag"] = self.test_org.name
            session.headers["Group-Tag"] = "user,invalid,admin"

            session.get(url, allow_redirects=False)
            r = session.get(url + "/users/view/me.json")
            r.raise_for_status()
            json_response = r.json()
            self.assertEqual(session.headers["Email-Tag"], json_response["User"]["email"])
            self.assertEqual(1, int(json_response["User"]["role_id"]))
            self.assertEqual(session.headers["Federation-Tag"], json_response["Organisation"]["name"])

            self.admin_misp_connector.delete_user(json_response["User"]["id"])

    def test_shibb_new_user_non_exists_org(self):
        with self.__setting(self.__default_shibb_config()):
            session = requests.Session()
            session.headers["Email-Tag"] = "external@user" + random() + ".local"
            session.headers["Federation-Tag"] = "Non exists org " + random()
            session.headers["Group-Tag"] = "user"

            session.get(url, allow_redirects=False)
            r = session.get(url + "/users/view/me.json")
            r.raise_for_status()
            json_response = r.json()
            self.assertEqual(session.headers["Email-Tag"], json_response["User"]["email"])
            self.assertEqual(3, int(json_response["User"]["role_id"]))
            self.assertEqual(session.headers["Federation-Tag"], json_response["Organisation"]["name"])
            self.assertEqual(1, int(json_response["Organisation"]["local"]), "Newly created org should be local")

            self.admin_misp_connector.delete_user(json_response["User"]["id"])
            self.admin_misp_connector.delete_organisation(json_response["User"]["org_id"])

    def test_shibb_new_user_org_uuid(self):
        with self.__setting(self.__default_shibb_config()):
            r = self.__shibb_login({
                "Email-Tag": "external@user" + random() + ".local",
                "Federation-Tag": self.test_org.uuid,
                "Group-Tag": "user",
            })

            r.raise_for_status()
            json_response = r.json()
            self.assertEqual(r.request.headers["Email-Tag"], json_response["User"]["email"])
            self.assertEqual(3, int(json_response["User"]["role_id"]))
            self.assertEqual(self.test_org.name, json_response["Organisation"]["name"])

            self.admin_misp_connector.delete_user(json_response["User"]["id"])
            self.admin_misp_connector.delete_organisation(json_response["User"]["org_id"])

    def test_shibb_new_user_non_exists_org_uuid(self):
        with self.__setting(self.__default_shibb_config()):
            r = self.__shibb_login({
                "Email-Tag": "external@user" + random() + ".local",
                "Federation-Tag": str(uuid.uuid4()),
                "Group-Tag": "user",
            })
            if r.status_code != 403:
                print(r.text)
                self.fail()

    def test_shibb_new_user_no_org_provided(self):
        with self.__setting(self.__default_shibb_config()):
            session = requests.Session()
            session.headers["Email-Tag"] = "external@user" + random() + ".local"
            session.headers["Group-Tag"] = "user"

            session.get(url, allow_redirects=False)
            r = session.get(url + "/users/view/me.json")
            r.raise_for_status()
            json_response = r.json()
            self.assertEqual(3, int(json_response["User"]["role_id"]))
            # Default org is used
            self.assertEqual(self.test_org.name, json_response["Organisation"]["name"])

            self.admin_misp_connector.delete_user(json_response["User"]["id"])

    def test_shibb_invalid_group(self):
        with self.__setting(self.__default_shibb_config()):
            session = requests.Session()
            session.headers["Email-Tag"] = "external@user" + random() + ".local"
            session.headers["Federation-Tag"] = self.test_org.name
            session.headers["Group-Tag"] = "invalid"

            session.get(url, allow_redirects=False)
            r = session.get(url + "/users/view/me.json")
            if r.status_code != 403:
                print(r.text)
                self.fail()

    def test_shibb_invalid_email(self):
        with self.__setting(self.__default_shibb_config()):
            session = requests.Session()
            session.headers["Email-Tag"] = "external.user" + random() + ".local"
            session.headers["Federation-Tag"] = self.test_org.name
            session.headers["Group-Tag"] = "user"

            session.get(url, allow_redirects=False)
            r = session.get(url + "/users/view/me.json")
            if r.status_code != 403:
                print(r.text)
                self.fail()

    def test_shibb_change_role(self):
        org_admin = self.__create_user(self.test_org.id, ROLE.ORG_ADMIN)

        with self.__setting(self.__default_shibb_config()):
            session = requests.Session()
            session.headers["Email-Tag"] = org_admin.email
            session.headers["Federation-Tag"] = self.test_org.name
            session.headers["Group-Tag"] = "user"

            session.get(url, allow_redirects=False)
            r = session.get(url + "/users/view/me.json")
            r.raise_for_status()
            json_response = r.json()
            # Change role back to user
            self.assertEqual(3, int(json_response["User"]["role_id"]))

        self.admin_misp_connector.delete_user(org_admin)

    def test_shibb_change_org(self):
        user = self.__create_user(self.test_org.id, ROLE.USER)

        with self.__setting(self.__default_shibb_config()):
            session = requests.Session()
            session.headers["Email-Tag"] = user.email
            session.headers["Federation-Tag"] = "Non exists org " + random()
            session.headers["Group-Tag"] = "user"

            session.get(url, allow_redirects=False)
            r = session.get(url + "/users/view/me.json")
            r.raise_for_status()
            json_response = r.json()
            # Change role back to user
            self.assertEqual(session.headers["Federation-Tag"], json_response["Organisation"]["name"])

            self.admin_misp_connector.delete_user(user)
            self.admin_misp_connector.delete_organisation(json_response["User"]["org_id"])

    def test_shibb_form_login(self):
        with self.__setting(self.__default_shibb_config()):
            # Form login should still works when no header provided
            self.assertIsInstance(login(url, self.test_usr.email, self.test_usr_password), requests.Session)

    def test_shibb_api_login(self):
        with self.__setting(self.__default_shibb_config()):
            PyMISP(url, self.test_usr.authkey)

    def test_shibb_enforced_existing_user(self):
        config = self.__default_shibb_config()
        config["Security"]["auth_enforced"] = True
        with self.__setting(config):
            r = self.__shibb_login({
                "Email-Tag": self.test_usr.email,
                "Federation-Tag": self.test_org.name,
                "Group-Tag": "user",
            })
            r.raise_for_status()
            json_response = r.json()
            self.assertEqual(self.test_usr.email, json_response["User"]["email"])
            self.assertEqual(3, int(json_response["User"]["role_id"]))
            self.assertEqual(self.test_org.name, json_response["Organisation"]["name"])

    def test_shibb_enforced_form_login(self):
        config = self.__default_shibb_config()
        config["Security"]["auth_enforced"] = True
        with self.__setting(config):
            # Form login should not work when shibb is enforced, because form doesn't exists
            with self.assertRaises(Exception):
                login(url, self.test_usr.email, self.test_usr_password)

    def test_shibb_enforced_api_login(self):
        config = self.__default_shibb_config()
        config["Security"]["auth_enforced"] = True
        with self.__setting(config):
            PyMISP(url, self.test_usr.authkey)

    def test_user_monitoring_enabled_no_user(self):
        request_logs_before = self.__get_logs(action="request")

        with self.__setting("Security.user_monitoring_enabled", True):
            logged_in = PyMISP(url, self.test_usr.authkey)
            check_response(logged_in.get_user())

        request_logs_after = self.__get_logs(action="request")
        # Number of logs should be same, because user is not monitored
        self.assertEqual(len(request_logs_after), len(request_logs_before))

    def test_user_monitoring_enabled_add_user(self):
        request_logs_before = self.__get_logs(action="request")

        with self.__setting("Security.user_monitoring_enabled", True):
            # Enable monitoring of test user
            send(self.admin_misp_connector, "POST", f"/admin/users/monitor/{self.test_usr.id}", {
                "value": 1,
            })

            logged_in = PyMISP(url, self.test_usr.authkey)
            check_response(logged_in.get_user())

            # Disable monitoring of test user
            send(self.admin_misp_connector, "POST", f"/admin/users/monitor/{self.test_usr.id}", {
                "value": 0,
            })

        request_logs_after = self.__get_logs(action="request")
        self.assertGreater(len(request_logs_after), len(request_logs_before))

    def test_log_paranoid(self):
        request_logs_before = self.__get_logs(action="request")

        with self.__setting("MISP.log_paranoid", True):
            logged_in = PyMISP(url, self.test_usr.authkey)
            check_response(logged_in.get_user())

        request_logs_after = self.__get_logs(action="request")
        self.assertGreater(len(request_logs_after), len(request_logs_before), "Number of logs should be greater")

    def test_log_paranoid_include_post_body(self):
        request_logs_before = self.__get_logs(action="request")

        with self.__setting({
            "MISP": {
                "log_paranoid": True,
                "log_paranoid_include_post_body": True,
            }
        }):
            logged_in = PyMISP(url, self.test_usr.authkey)
            check_response(logged_in.get_user())

        request_logs_after = self.__get_logs(action="request")
        self.assertGreater(len(request_logs_after), len(request_logs_before), "Number of logs should be greater")

    def test_log_paranoid_skip_db(self):
        request_logs_before = self.__get_logs(action="request")

        with self.__setting({
            "MISP": {
                "log_paranoid": True,
                "log_paranoid_skip_db": True,
            }
        }):
            logged_in = PyMISP(url, self.test_usr.authkey)
            check_response(logged_in.get_user())

        request_logs_after = self.__get_logs(action="request")
        # Number of logs should be same, because saving to database is disabled
        self.assertEqual(len(request_logs_after), len(request_logs_before))

    def test_log_auth_fail_multiple(self):
        request_logs_before = self.__get_logs(action="auth_fail")

        with self.assertRaises(PyMISPError):
            PyMISP(url, "JCZDbBr3wYPlY0DrlQzoD8EWrcClGc0Dqu2yMYyE")
        with self.assertRaises(PyMISPError):
            PyMISP(url, "JCZDbBr3wYPlY0DrlQzoD8EWrcClGc0Dqu2yMYyE")

        request_logs_after = self.__get_logs(action="auth_fail")
        # Just one new record should be logged for multiple tries with same key
        self.assertEqual(len(request_logs_after), len(request_logs_before) + 1)

    def test_log_user_ips(self):
        with self.__setting("MISP.log_user_ips", True):
            logged_in = PyMISP(url, self.test_usr.authkey)
            check_response(logged_in.get_user())

    def test_log_user_ips_auth(self):
        with self.__setting({
            "MISP": {
                "log_user_ips": True,
                "log_user_ips_authkeys": True,
            }
        }):
            logged_in = PyMISP(url, self.test_usr.authkey)
            check_response(logged_in.get_user())

    def test_username_in_response_header(self):
        with self.__setting("Security.username_in_response_header", True):
            logged_in = login(url, self.test_usr.email, self.test_usr_password)
            self.assertIsInstance(logged_in, requests.Session)

            response = logged_in.get(url + "/users/view/me.json")
            self.assertIn("X-Username", response.headers)
            self.assertEqual(self.test_usr.email, response.headers["X-Username"])

    def test_username_in_response_header_advanced_api_access(self):
        with self.__setting({
            "Security": {
                "advanced_authkeys": True,
                "username_in_response_header": True,
            }
        }):
            auth_key = self.__create_advanced_authkey(self.test_usr.id)

            logged_in = PyMISP(url, auth_key["authkey_raw"])
            response = logged_in._prepare_request('GET', 'users/view/me')

            self.__delete_advanced_authkey(auth_key["id"])

            self.assertIn("X-Username", response.headers)
            self.assertEqual(f"{self.test_usr.email}/API/{auth_key['id']}", response.headers["X-Username"])

    def test_event_publish_no_perm(self):
        test_usr = self.__login(self.test_usr)

        created_event = test_usr.add_event(self.__generate_event())
        self.assertSuccessfulResponse(created_event, "User should be able to create event")

        access_event = test_usr.get_event(created_event)
        self.assertSuccessfulResponse(access_event, "User should be able to access that event")

        published = test_usr.publish(access_event)
        self.assertErrorResponse(published, "User should not be able to publish that event without perm_publish permission")

        published = test_usr.publish(access_event, alert=True)
        self.assertErrorResponse(published, "User should not be able to publish that event without perm_publish permission")

        self.assertSuccessfulResponse(test_usr.delete_event(access_event), "User should be able to delete his event")

    def test_event_publish_with_perm(self):
        publisher_user = self.__create_user(self.test_org.id, ROLE.PUBLISHER)
        logged_in = self.__login(publisher_user)

        created_event = logged_in.add_event(self.__generate_event())
        self.assertSuccessfulResponse(created_event, "User should be able to create event")

        access_event = logged_in.get_event(created_event)
        self.assertSuccessfulResponse(access_event, "User should be able to access that event")

        published = logged_in.publish(access_event)
        self.assertSuccessfulResponse(published, "User should be able to publish that event without perm_publish permission")

        published = logged_in.publish(access_event, alert=True)
        self.assertSuccessfulResponse(published, "User should be able to publish (alert) that event without perm_publish permission")

        self.assertSuccessfulResponse(logged_in.delete_event(access_event), "User should be able to delete his event")

        # Cleanup
        self.admin_misp_connector.delete_user(publisher_user)

    def test_event_publish_different_org(self):
        different_org = self.__create_org()
        publisher_user = self.__create_user(different_org.id, ROLE.PUBLISHER)
        logged_in = self.__login(publisher_user)

        test_usr = self.__login(self.test_usr)

        created_event = test_usr.add_event(self.__generate_event())
        self.assertSuccessfulResponse(created_event, "User should be able to create event")

        access_event = test_usr.get_event(created_event)
        self.assertSuccessfulResponse(access_event, "User should be able to access that event")

        published = logged_in.publish(created_event)
        self.assertErrorResponse(published, "User from different org should not be able to publish that event")

        published = logged_in.publish(created_event, alert=True)
        self.assertErrorResponse(published, "User from different org should not be able to publish that event")

        # Cleanup
        test_usr.delete_event(created_event)
        self.admin_misp_connector.delete_user(publisher_user)
        self.admin_misp_connector.delete_organisation(different_org)

    def test_unpublished_private(self):
        with self.__setting("MISP.unpublishedprivate", True):
            created_event = self.admin_misp_connector.add_event(self.__generate_event())
            self.assertIsInstance(created_event, MISPEvent, "Admin user should be able to create event")

            logged_in = PyMISP(url, self.test_usr.authkey)
            # Event is not published, so normal user should not see that event
            self.assertFalse(logged_in.event_exists(created_event.uuid))
            fetched_event = logged_in.get_event(created_event.uuid)
            self.assertEqual(fetched_event["errors"][0], 404)
            attributes = logged_in.search(controller='attributes', uuid=created_event.uuid)
            self.assertEqual(len(attributes["Attribute"]), 0, attributes)

            # Publish
            self.assertSuccessfulResponse(publish_immediately(self.admin_misp_connector, created_event))

            # Event is published, so normal user should see that event
            self.assertTrue(logged_in.event_exists(created_event.uuid))
            fetched_event = logged_in.get_event(created_event.uuid)
            self.assertSuccessfulResponse(fetched_event, "User should be able to see published event")
            attributes = logged_in.search(controller='attributes', uuid=created_event.uuid)
            self.assertEqual(len(attributes["Attribute"]), 1, attributes)

            # Cleanup
            self.admin_misp_connector.delete_event(created_event)

    def test_sg_index_user_cannot_see(self):
        org = self.__create_org()
        hidden_sg = self.__create_sharing_group()
        check_response(self.admin_misp_connector.add_org_to_sharing_group(hidden_sg, org.uuid))

        logged_in = PyMISP(url, self.test_usr.authkey)
        logged_in.global_pythonify = True
        sgs = logged_in.sharing_groups()
        check_response(sgs)

        self.admin_misp_connector.delete_sharing_group(hidden_sg)
        self.admin_misp_connector.delete_organisation(org)

        for sg in sgs:
            self.assertNotEqual(sg.uuid, hidden_sg.uuid)

    def test_sg_index_user_can_see(self):
        visible_sg = self.__create_sharing_group()
        check_response(self.admin_misp_connector.add_org_to_sharing_group(visible_sg, self.test_org.uuid))

        logged_in = PyMISP(url, self.test_usr.authkey)
        logged_in.global_pythonify = True
        sgs = logged_in.sharing_groups()
        check_response(sgs)

        self.admin_misp_connector.delete_sharing_group(visible_sg)

        sg_found = False
        for sg in sgs:
            if sg.uuid == visible_sg.uuid:
                sg_found = True
        self.assertTrue(sg_found)

    def test_sg_view_user_cannot_see(self):
        org = self.__create_org()
        hidden_sg = self.__create_sharing_group()
        check_response(self.admin_misp_connector.add_org_to_sharing_group(hidden_sg, org.uuid))

        logged_in = PyMISP(url, self.test_usr.authkey)
        logged_in.global_pythonify = True

        with self.assertRaises(Exception):
            send(logged_in, "GET", f"/sharingGroups/view/{hidden_sg.id}")

        with self.assertRaises(Exception):
            send(logged_in, "GET", f"/sharingGroups/view/{hidden_sg.uuid}")

        with self.assertRaises(Exception):
            send(logged_in, "POST", f"/sharingGroups/edit/{hidden_sg.id}", {"name": "New name1"})

        with self.assertRaises(Exception):
            send(logged_in, "POST", f"/sharingGroups/edit/{hidden_sg.uuid}", {"name": "New name2"})

        self.assertErrorResponse(logged_in.add_org_to_sharing_group(hidden_sg, self.test_org.uuid))
        self.assertErrorResponse(logged_in.remove_org_from_sharing_group(hidden_sg, org.uuid))
        self.assertErrorResponse(logged_in.delete_sharing_group(hidden_sg))

        self.admin_misp_connector.delete_sharing_group(hidden_sg)
        self.admin_misp_connector.delete_organisation(org)

    def test_sg_view_user_can_see(self):
        org1 = self.__create_org()
        sg = self.__create_sharing_group()
        check_response(self.admin_misp_connector.add_org_to_sharing_group(sg, org1.uuid))
        check_response(self.admin_misp_connector.add_org_to_sharing_group(sg, self.test_org.uuid))

        logged_in = PyMISP(url, self.test_usr.authkey)
        send(logged_in, "GET", f"/sharingGroups/view/{sg.id}")
        send(logged_in, "GET", f"/sharingGroups/view/{sg.uuid}")

        self.admin_misp_connector.delete_sharing_group(sg)
        self.admin_misp_connector.delete_organisation(org1)

    def test_sg_view_user_can_see_cannot_edit(self):
        org = self.__create_org()
        sync_user = self.__create_user(org.id, ROLE.SYNC_USER)
        sg = self.__create_sharing_group()
        check_response(self.admin_misp_connector.add_org_to_sharing_group(sg, org.uuid))

        logged_in = PyMISP(url, sync_user.authkey)
        self.assertTrue(logged_in._current_role.perm_sharing_group, "Sync user should have permission to edit sharing groups")

        send(logged_in, "GET", f"/sharingGroups/view/{sg.id}")

        # This was a logic bug that has been corrected by 26ec3274374c4771e6996272c8108422f0fec34e
        # A sync user should in fact be able to update a sharing group that they can view, even if they're not the creator user
        # Otherwise race conditions via multiple sync paths may block future updates to the sharing group.
        # with self.assertRaises(Exception):
        #    send(logged_in, "POST", f"/sharingGroups/edit/{sg.id}", {"name": "New name1"})
        # self.assertEqual(sg.name, send(logged_in, "GET", f"/sharingGroups/view/{sg.id}")["SharingGroup"]["name"])

        # with self.assertRaises(Exception):
        #     send(logged_in, "POST", f"/sharingGroups/edit/{sg.uuid}", {"name": "New name2"})
        # self.assertEqual(sg.name, send(logged_in, "GET", f"/sharingGroups/view/{sg.id}")["SharingGroup"]["name"])

        # self.assertErrorResponse(logged_in.add_org_to_sharing_group(sg, self.test_org.uuid))
        # self.assertErrorResponse(logged_in.remove_org_from_sharing_group(sg, org.uuid))
        # self.assertErrorResponse(logged_in.delete_sharing_group(sg))

        self.admin_misp_connector.delete_sharing_group(sg)
        self.admin_misp_connector.delete_user(sync_user)
        self.admin_misp_connector.delete_organisation(org)

    def test_sg_view_user_can_see_can_edit(self):
        org = self.__create_org()
        sync_user = self.__create_user(org.id, ROLE.SYNC_USER)
        sg = self.__create_sharing_group()
        check_response(self.admin_misp_connector.add_org_to_sharing_group(sg, org.uuid, True))

        logged_in = PyMISP(url, sync_user.authkey)
        self.assertTrue(logged_in._current_role.perm_sharing_group, "Sync user should have permission to edit sharing groups")

        send(logged_in, "GET", f"/sharingGroups/view/{sg.id}")
        after_edit = send(logged_in, "POST", f"/sharingGroups/edit/{sg.id}", {"name": "New name1"})
        self.assertEqual("New name1", after_edit["SharingGroup"]["name"])
        after_edit = send(logged_in, "POST", f"/sharingGroups/edit/{sg.uuid}", {"name": "New name2"})
        self.assertEqual("New name2", after_edit["SharingGroup"]["name"])

        self.assertErrorResponse(logged_in.delete_sharing_group(sg))

        self.admin_misp_connector.delete_sharing_group(sg)
        self.admin_misp_connector.delete_user(sync_user)
        self.admin_misp_connector.delete_organisation(org)

    def test_org_user_can_see(self):
        org = self.__create_org()

        logged_in = PyMISP(url, self.test_usr.authkey)
        for key in (org.id, org.uuid, org.name):
            fetched_org = logged_in.get_organisation(key)
            check_response(fetched_org)
            self.assertNotIn("created_by", fetched_org["Organisation"])
            self.assertNotIn("created_by_email", fetched_org["Organisation"])

        self.admin_misp_connector.delete_organisation(org)

    def test_org_hide_index(self):
        with self.__setting("Security.hide_organisation_index_from_users", True):
            logged_in = PyMISP(url, self.test_usr.authkey)
            self.assertErrorResponse(logged_in.organisations())

    def test_org_hide_org_cannot_set(self):
        org = self.__create_org()
        with self.__setting("Security.hide_organisation_index_from_users", True):
            logged_in = PyMISP(url, self.test_usr.authkey)
            self.assertErrorResponse(logged_in.get_organisation(org.id))
            self.assertErrorResponse(logged_in.get_organisation(org.uuid))

            self.admin_misp_connector.delete_organisation(org)

    def test_org_hide_org_can_see_his_own(self):
        org = self.__create_org()
        user = self.__create_user(org.id, ROLE.USER)

        with self.__setting("Security.hide_organisation_index_from_users", True):
            logged_in = PyMISP(url, user.authkey)
            for key in (org.id, org.uuid, org.name):
                fetched_org = logged_in.get_organisation(key)
                check_response(fetched_org)
                self.assertNotIn("created_by", fetched_org["Organisation"])
                self.assertNotIn("created_by_email", fetched_org["Organisation"])

            self.admin_misp_connector.delete_user(user)
            self.admin_misp_connector.delete_organisation(org)

    def test_org_hide_org_cannot_see_event_after_contribution(self):
        org = self.__create_org()
        user = self.__create_user(org.id, ROLE.USER)
        logged_in = PyMISP(url, user.authkey)
        event = logged_in.add_event(self.__generate_event(distribution=0))
        check_response(event)

        with self.__setting("Security.hide_organisation_index_from_users", True):
            logged_in = PyMISP(url, self.test_usr.authkey)
            for key in (org.id, org.uuid, org.name):
                self.assertErrorResponse(logged_in.get_organisation(key))

            self.admin_misp_connector.delete_event(event)
            self.admin_misp_connector.delete_user(user)
            self.admin_misp_connector.delete_organisation(org)

    def test_org_hide_org_can_see_after_contribution(self):
        org = self.__create_org()
        user = self.__create_user(org.id, ROLE.USER)
        logged_in = PyMISP(url, user.authkey)
        event = logged_in.add_event(self.__generate_event())
        check_response(event)

        with self.__setting("Security.hide_organisation_index_from_users", True):
            logged_in = PyMISP(url, self.test_usr.authkey)
            for key in (org.id, org.uuid):
                fetched_org = logged_in.get_organisation(key)
                check_response(fetched_org)
                self.assertNotIn("created_by", fetched_org["Organisation"])
                self.assertNotIn("created_by_email", fetched_org["Organisation"])

            self.admin_misp_connector.delete_event(event)
            self.admin_misp_connector.delete_user(user)
            self.admin_misp_connector.delete_organisation(org)

    def test_get_org_as_site_admin(self):
        org = self.admin_misp_connector.get_organisation(self.test_org)
        check_response(org)
        self.assertIn("created_by", org.to_dict())
        self.assertIn("created_by_email", org.to_dict())

    def test_get_org_as_org_admin(self):
        org = self.org_admin_misp_connector.get_organisation(self.test_org)
        check_response(org)
        self.assertIn("created_by", org.to_dict())
        self.assertIn("created_by_email", org.to_dict())

    def test_get_org_as_org_admin_different_org(self):
        org = self.__create_org()
        org = self.org_admin_misp_connector.get_organisation(org)
        check_response(org)
        self.assertNotIn("created_by", org.to_dict())
        self.assertNotIn("created_by_email", org.to_dict())
        self.admin_misp_connector.delete_organisation(org)

    def test_org_index_site_admin(self):
        created_org = self.__create_org()
        orgs = self.admin_misp_connector.organisations(created_org)
        check_response(orgs)
        contains = False
        for org in orgs:
            if org.id == created_org.id:
                contains = True
            self.assertIn("created_by", org.to_dict())
            self.assertIn("created_by_email", org.to_dict())
        self.assertTrue(contains)
        self.admin_misp_connector.delete_organisation(created_org)

    def test_org_index_org_admin(self):
        created_org = self.__create_org()
        orgs = self.org_admin_misp_connector.organisations(created_org)
        check_response(orgs)
        contains = False
        for org in orgs:
            if org.id == created_org.id:
                contains = True
            self.assertNotIn("created_by", org.to_dict())
            self.assertNotIn("created_by_email", org.to_dict())
        self.assertTrue(contains)
        self.admin_misp_connector.delete_organisation(created_org)

    def test_org_hide_from_sharing_group(self):
        secret_org = self.__create_org()
        visible_sg = self.__create_sharing_group()
        check_response(self.admin_misp_connector.add_org_to_sharing_group(visible_sg, self.test_org.uuid))
        check_response(self.admin_misp_connector.add_org_to_sharing_group(visible_sg, secret_org.uuid))

        logged_in = PyMISP(url, self.test_usr.authkey)
        logged_in.global_pythonify = True

        with self.__setting("Security.hide_organisations_in_sharing_groups", True):
            sg = send(logged_in, "GET", f"/sharingGroups/view/{visible_sg.id}")
            self.assertNotIn("SharingGroupOrg", sg)

        self.admin_misp_connector.delete_organisation(secret_org)
        self.admin_misp_connector.delete_sharing_group(visible_sg)

    def test_sighting_policy_host_org(self):
        s = MISPSighting()
        s.source = 'Testcases'
        s.type = '1'

        user1 = PyMISP(url, self.test_usr.authkey)
        user1.global_pythonify = True

        event = user1.add_event(self.__generate_event())
        check_response(event)
        check_response(user1.add_sighting(s, event.Attribute[0]))
        self.assertEqual(len(user1.sightings(event)), 1, "User should see only own sighting")
        self.assertEqual(len(user1.search_sightings('event', event.id)), 1)

        org = self.__create_org()
        user = self.__create_user(org.id, ROLE.USER)
        user2 = PyMISP(url, user.authkey)
        user2.global_pythonify = True

        self.assertEqual(len(user2.sightings(event)), 0, "User should not seen any sighting")
        self.assertEqual(len(user2.search_sightings('event', event.id)), 0)

        with self.__setting({"MISP.host_org_id": self.test_org.id, "Plugin.Sightings_policy": 3}):
            self.assertEqual(len(user2.sightings(event)), 1, "User should see host org sighting")
            self.assertEqual(len(user2.search_sightings('event', event.id)), 1)

        self.admin_misp_connector.delete_event(event)
        self.admin_misp_connector.delete_user(user)
        self.admin_misp_connector.delete_organisation(org)

    def test_sighting_rest_search_permission(self):
        s = MISPSighting()
        s.source = 'Testcases'
        s.type = '1'

        user1 = PyMISP(url, self.test_usr.authkey)
        user1.global_pythonify = True

        private_event = check_response(user1.add_event(self.__generate_event(Distribution.your_organisation_only)))
        check_response(user1.add_sighting(s, private_event.Attribute[0]))
        self.assertEqual(len(user1.sightings(private_event)), 1, "User should see their own sighting")

        sightings = user1.search_sightings("event", private_event.id)
        self.assertEqual(len(sightings), 1, sightings)

        org = self.__create_org()
        user = self.__create_user(org.id, ROLE.USER)
        user2 = PyMISP(url, user.authkey)
        user2.global_pythonify = True

        self.assertFalse(user2.event_exists(private_event), "User should not see the event")

        sightings = user2.sightings(private_event)
        self.assertErrorResponse(sightings, "User should not seen any sighting for private event")

        sightings = user2.search_sightings("event", private_event.id)
        self.assertEqual(len(sightings), 0, "User should not seen any sighting from private event from rest search")

        with self.__setting("Plugin.Sightings_policy", 2):  # set sighting policy to everyone
            sightings = user2.sightings(private_event)
            self.assertErrorResponse(sightings, "User should not seen any sighting for private event")

            sightings = user2.search_sightings("event", private_event.id)
            self.assertEqual(len(sightings), 0, "User should not seen any sighting from private event from rest search")

        self.admin_misp_connector.delete_event(private_event)
        self.admin_misp_connector.delete_user(user)
        self.admin_misp_connector.delete_organisation(org)

    def test_user_setting_delete(self):
        # Admin user can set their own user setting
        setting = self.admin_misp_connector.set_user_setting('publish_alert_filter', {'Tag.name': 'test_publish_filter'})
        check_response(setting)

        logged_in = PyMISP(url, self.test_usr.authkey)
        logged_in.global_pythonify = True

        # Normal user should not be able to delete setting for different user
        deleted = logged_in.delete_user_setting('publish_alert_filter', self.admin_misp_connector._current_user)
        self.assertEqual(deleted["errors"][0], 404, deleted)

        setting = self.admin_misp_connector.get_user_setting('publish_alert_filter')
        check_response(setting)
        self.assertEqual({'Tag.name': 'test_publish_filter'}, setting.value)

        # User should be able to delete self setting
        check_response(self.admin_misp_connector.delete_user_setting('publish_alert_filter'))

    def __generate_event(self, distribution: int = Distribution.this_community_only) -> MISPEvent:
        mispevent = MISPEvent()
        mispevent.info = 'This is a super simple test'
        mispevent.distribution = distribution
        mispevent.threat_level_id = 1
        mispevent.analysis = 1
        mispevent.add_attribute('text', "Ahoj")
        return mispevent

    def __create_org(self) -> MISPOrganisation:
        organisation = MISPOrganisation()
        organisation.name = 'TestOrg' + random()  # make name always unique
        org = self.admin_misp_connector.add_organisation(organisation)
        check_response(org)
        return org

    def __create_sharing_group(self) -> MISPSharingGroup:
        sg = MISPSharingGroup()
        sg.name = 'Testcases SG ' + random()  # make name always unique
        sg.releasability = 'Nic'
        sg = self.admin_misp_connector.add_sharing_group(sg)
        check_response(sg)
        return sg

    def __shibb_login(self, headers: dict) -> requests.Response:
        session = requests.Session()
        session.headers.update(headers)

        r = session.get(url, allow_redirects=False)
        if 500 <= r.status_code < 600:
            raise Exception(r)

        r = session.get(url + "/users/view/me.json")
        if 500 <= r.status_code < 600:
            raise Exception(r)

        return r

    def __create_user(self, org_id: int, role_id: Union[int, ROLE]) -> MISPUser:
        if isinstance(role_id, ROLE):
            role_id = role_id.value

        user = MISPUser()
        user.email = 'test@' + random() + '.local'  # make name always unique
        if org_id:
            user.org_id = org_id
        if role_id:
            user.role_id = role_id
        self.admin_misp_connector.global_pythonify = True
        user = self.admin_misp_connector.add_user(user)
        check_response(user)
        if org_id:
            assert int(org_id) == int(user.org_id)
        if role_id:
            assert int(role_id) == int(user.role_id)
        return user

    def __create_advanced_authkey(self, user_id: int, data: Optional[dict] = None) -> dict:
        auth_key = send(self.admin_misp_connector, "POST", f'authKeys/add/{user_id}', data=data)["AuthKey"]
        # it is not possible to call `assertEqual`, because we use this method in `setUpClass` method
        assert int(user_id) == int(auth_key["user_id"]), f"Key was created for different user ({user_id} != {auth_key['user_id']})"
        return auth_key

    def __login(self, user: MISPUser) -> PyMISP:
        logged_in = PyMISP(url, user.authkey)
        self.assertEqual(logged_in._current_user.id, user.id, "Logged in by different user")
        if int(user.role_id) == ROLE.PUBLISHER.value:
            self.assertTrue(logged_in._current_role.perm_publish, "Publisher user should have permission to publish events")
        return logged_in

    def __login_by_advanced_authkey(self, auth_key: dict) -> PyMISP:
        logged_in = PyMISP(url, auth_key["authkey_raw"])
        self.assertEqual(logged_in._current_user.id, auth_key["user_id"], "Logged in by different user")
        return logged_in

    def __delete_advanced_authkey(self, key_id: int):
        return send(self.admin_misp_connector, "POST", f'authKeys/delete/{key_id}')

    def __get_logs(self, action: str) -> List[MISPLog]:
        response = self.admin_misp_connector.search_logs(action=action)
        check_response(response)
        return response

    def assertSuccessfulResponse(self, response, msg=None):
        self.assertIsInstance(response, dict)
        if "errors" in response:
            msg = self._formatMessage(msg, safe_repr(response["errors"]))
            self.fail(msg)

    def assertErrorResponse(self, response, msg=None):
        self.assertIsInstance(response, dict)
        if "errors" not in response:
            msg = self._formatMessage(msg, safe_repr(response))
            self.fail(msg)

    def __setting(self, key, value=None) -> MISPSetting:
        if not isinstance(key, dict):
            new_setting = {key: value}
        else:
            new_setting = key
        return MISPSetting(self.admin_misp_connector, new_setting)

    def __default_shibb_config(self) -> dict:
        return {
            "ApacheShibbAuth": {
                "DefaultOrg": self.test_org.name,
                "UseDefaultOrg": False,
                "MailTag": "HTTP_EMAIL_TAG",
                "OrgTag": "HTTP_FEDERATION_TAG",
                "GroupTag": "HTTP_GROUP_TAG",
                "GroupSeparator": ",",
                "GroupRoleMatching": {
                    "admin": 1,
                    "user": 3,
                }
            },
            "Security": {
                "auth": ["ShibbAuth.ApacheShibb"],
            }
        }


class TestComplexQueryAcl(unittest.TestCase):
    """The `query` tree of /attributes/restSearch must never widen what the user's ACL allows."""

    @classmethod
    def api(cls, token: str, method: str, path: str, body=None, accept_json: bool = True):
        headers = {"Authorization": token, "Accept": "application/json", "Content-Type": "application/json"}
        r = requests.request(method, f"{url}/{path}", json=body, headers=headers, verify=False)
        try:
            data = r.json()
        except ValueError:
            data = None
        return r.status_code, data

    @classmethod
    def admin_api(cls, method: str, path: str, body=None) -> dict:
        status, data = cls.api(key, method, path, body)
        assert status == 200, (method, path, status, data)
        return data

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        admin = PyMISP(url, key)
        check_response(admin.set_server_setting('Security.advanced_authkeys', True, force=True))
        cls.marker = "mqa" + random()
        cls.created = {"events": [], "users": [], "roles": [], "sgs": [], "keys": []}
        cls.org = None
        try:
            cls.__build_fixture()
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def __build_fixture(cls):

        cls.org = cls.admin_api("POST", "admin/organisations/add", {"name": "MQA Org " + random(), "local": True})["Organisation"]
        cls.admin_org_uuid = cls.admin_api("GET", "users/view/me")["Organisation"]["uuid"]
        role_flagged = cls.admin_api("POST", "admin/roles/add", {"Role": {
            "name": "MQA flagged " + random(), "permission": "0", "perm_auth": 1, "perm_sighting": 1, "perm_complex_query": 1}})["Role"]
        role_plain = cls.admin_api("POST", "admin/roles/add", {"Role": {
            "name": "MQA plain " + random(), "permission": "0", "perm_auth": 1, "perm_sighting": 1}})["Role"]
        cls.created["roles"] = [role_flagged["id"], role_plain["id"]]
        cls.user_key = cls.__make_user(role_flagged["id"])
        cls.plain_user_key = cls.__make_user(role_plain["id"])

        # a sharing group the test org is not a member of
        sg = cls.admin_api("POST", "sharingGroups/add", {
            "SharingGroup": {"name": "MQA SG " + random(), "releasability": "test", "description": "test", "active": 1,
                             "organisation_uuid": cls.admin_org_uuid, "roaming": 0},
            "Organisation": [{"uuid": cls.admin_org_uuid, "extend": True}]})
        cls.sg_id = sg["SharingGroup"]["id"]
        cls.created["sgs"].append(cls.sg_id)

        # E1 fully visible, E2 partly visible, E3 not visible at all
        cls.e1 = cls.__make_event("e1", 3, [("a1", 5), ("a2", 3)])
        cls.e2 = cls.__make_event("e2", 3, [("v1", 5), ("v2", 3), ("h1", 0), ("h2", 4)])
        cls.e3 = cls.__make_event("e3", 0, [("x1", 5), ("x2", 0)])
        cls.all_events = [cls.e1, cls.e2, cls.e3]
        cls.visible = {cls.__value(n) for n in ("e1-a1", "e1-a2", "e2-v1", "e2-v2")}
        cls.hidden = {cls.__value(n) for n in ("e2-h1", "e2-h2", "e3-x1", "e3-x2")}

    @classmethod
    def tearDownClass(cls):
        for kind, path in (("events", "events/delete/{}"), ("keys", "authKeys/delete/{}"), ("users", "admin/users/delete/{}"),
                           ("sgs", "sharingGroups/delete/{}"), ("roles", "admin/roles/delete/{}")):
            for item in cls.created[kind]:
                try:
                    cls.api(key, "POST", path.format(item))
                except Exception:
                    pass
        if cls.org:
            try:
                cls.api(key, "POST", f"admin/organisations/delete/{cls.org['id']}")
            except Exception:
                pass

    @classmethod
    def __make_user(cls, role_id) -> str:
        user = cls.admin_api("POST", "admin/users/add", {
            "email": f"mqa{random()}@user.local", "org_id": cls.org["id"], "role_id": role_id, "password": str(uuid.uuid4())})["User"]
        cls.created["users"].append(user["id"])
        auth_key = cls.admin_api("POST", f"authKeys/add/{user['id']}")["AuthKey"]
        cls.created["keys"].append(auth_key["id"])
        return auth_key["authkey_raw"]

    @classmethod
    def __value(cls, name: str) -> str:
        return f"{cls.marker}-{name}.example.com"

    @classmethod
    def __make_event(cls, name: str, distribution: int, attributes) -> int:
        body = {"Event": {"info": f"{cls.marker} {name}", "distribution": distribution, "threat_level_id": 4, "analysis": 0,
                          "Attribute": [{"type": "domain", "category": "Network activity", "value": cls.__value(f"{name}-{n}"),
                                         "comment": cls.marker, "distribution": d,
                                         **({"sharing_group_id": cls.sg_id} if d == 4 else {})} for n, d in attributes]}}
        event_id = cls.admin_api("POST", "events/add", body)["Event"]["id"]
        cls.created["events"].append(event_id)
        cls.admin_api("POST", f"events/publish/{event_id}/disable_background_processing:1")
        return int(event_id)

    def __search(self, query, token=None, extra=None, method="POST"):
        body = {"returnFormat": "json", "limit": 1000, "query": query}
        body.update(extra or {})
        status, data = self.api(token or self.user_key, method, "attributes/restSearch", body)
        values = None
        if status == 200 and isinstance(data, dict):
            values = {a["value"] for a in data["response"]["Attribute"]}
        return status, values, data

    def __anchored(self, tree):
        return {"AND": [{"event_id": {"IN": self.all_events}}, tree]}

    def test_fixture_is_discriminating(self):
        # admin sees every attribute, so the hidden set is only hidden by the ACL
        status, data = self.api(key, "POST", "attributes/restSearch", {"returnFormat": "json", "limit": 1000, "eventid": self.all_events})
        self.assertEqual(status, 200)
        self.assertEqual({a["value"] for a in data["response"]["Attribute"]}, self.visible | self.hidden)

    def test_baseline_returns_exactly_the_visible_attributes(self):
        status, values, _ = self.__search({"event_id": self.e1})
        self.assertEqual((status, values), (200, {self.__value("e1-a1"), self.__value("e1-a2")}))
        status, values, _ = self.__search({"event_id": self.e2})
        self.assertEqual((status, values), (200, {self.__value("e2-v1"), self.__value("e2-v2")}))
        status, values, _ = self.__search({"event_id": self.e3})
        self.assertEqual((status, values), (200, set()))
        status, values, _ = self.__search({"AND": [{"comment": self.marker}, {"value": {"LIKE": "%e2-v%"}}]})
        self.assertEqual((status, values), (200, {self.__value("e2-v1"), self.__value("e2-v2")}))

    def test_match_all_queries_never_return_hidden_data(self):
        tautology = {"OR": [{"id": {">": 0}}, {"NOT": {"id": {">": 0}}}]}
        trees = {
            "tautology": tautology,
            "double negation": {"NOT": {"NOT": {"comment": self.marker}}},
            "or with a matching leaf": {"OR": [{"comment": self.marker}, {"id": {">": 0}}]},
            "broad like": {"value": {"LIKE": "%.example.com"}},
            "not of nothing": {"NOT": {"comment": "no-such-comment"}},
            "every distribution": {"distribution": {"IN": [0, 1, 2, 3, 4, 5]}},
            "negated distribution": {"distribution": {"NOT IN": [9]}},
            "all event ids": {"event_id": {"IN": self.all_events}},
        }
        for name, tree in trees.items():
            with self.subTest(name):
                status, values, _ = self.__search(self.__anchored(tree))
                self.assertEqual(status, 200)
                self.assertEqual(values & self.hidden, set(), "hidden data leaked")
                self.assertEqual(values, self.visible)

    def test_malformed_queries_return_no_data(self):
        bad = {
            "string": "id=1", "list": [{"id": 1}], "empty": {}, "number": 5, "two keys": {"id": 1, "type": "domain"},
            "empty and": {"AND": []}, "not a list": {"OR": {"id": 1}}, "empty not": {"NOT": {}},
            "unknown field": {"nope": 1}, "acl field": {"sharing_group_id": self.sg_id}, "org id": {"org_id": 1},
            "unknown operator": {"id": {"=~": 1}}, "two operators": {"id": {">": 1, "<": 99999999}},
            "wrong type": {"id": "1"}, "bool as int": {"to_ids": 1}, "float": {"id": 1.5},
            "wildcard in equals": {"value": "%.example.com"}, "like without wildcard": {"value": {"LIKE": "abc"}},
            "empty in": {"id": {"IN": []}}, "legacy shape": {"type": ["domain", "!url"]},
            "too deep": {"NOT": {"NOT": {"NOT": {"NOT": {"NOT": {"NOT": {"id": 1}}}}}}},
            "too many nodes": {"AND": [{"id": 1}] * 80},
            "too long list": {"id": {"IN": list(range(500))}},
            "too long value": {"value": "a" * 5000},
        }
        for name, tree in bad.items():
            with self.subTest(name):
                status, values, data = self.__search(tree)
                self.assertEqual(status, 400, data)
                self.assertIsNone(values)
                self.assertNotIn("Attribute", json.dumps(data))
        for token, expected in ((self.plain_user_key, 403), ("x" * 40, 403)):
            with self.subTest(f"{token[:4]} {expected}"):
                status, values, _ = self.__search({"event_id": self.e1}, token=token)
                self.assertEqual((status, values), (expected, None))

    def test_unknown_order_fields_are_rejected(self):
        tree = {"event_id": self.e1}
        for order in ("nope", "id,nope", "Event.id", "id up", ["id", 5], "a.b.c"):
            with self.subTest(order):
                status, values, data = self.__search(tree, extra={"order": order})
                self.assertEqual((status, values), (400, None), data)
                self.assertEqual(data["errors"][0]["code"] in ("unknown_field", "bad_shape", "bad_type"), True)
        status, values, _ = self.__search(tree, extra={"order": "id desc"})
        self.assertEqual((status, values), (200, {self.__value("e1-a1"), self.__value("e1-a2")}))
        status, values, _ = self.__search(tree, extra={"order": ["Event.publish_timestamp desc", "value"]})
        self.assertEqual(status, 200)

    def test_query_is_only_accepted_in_a_post_body(self):
        status, data = self.api(self.user_key, "GET", f"attributes/restSearch?returnFormat=json&query[event_id]={self.e1}")
        self.assertEqual(status, 400)
        status, data = self.api(self.user_key, "POST", f"attributes/restSearch?query[event_id]={self.e1}", {"returnFormat": "json"})
        self.assertEqual(status, 400)
        status, data = self.api(self.user_key, "POST", f"attributes/restSearch/query:{self.e1}", {"returnFormat": "json"})
        self.assertEqual(status, 400)
        # a copy in the URL must not replace the tree of the body
        body = {"returnFormat": "json", "query": {"event_id": self.e1}}
        for path in ("attributes/restSearch?query[type]=domain", "attributes/restSearch/query:x"):
            with self.subTest(path):
                status, data = self.api(self.user_key, "POST", path, body)
                self.assertEqual(status, 400)
                self.assertNotIn("Attribute", json.dumps(data))

    def test_other_restsearch_filter_consumers_reject_the_query(self):
        # sightings/add hands its filters to the attribute restSearch
        for token in (self.user_key, self.plain_user_key):
            with self.subTest(token[:4]):
                status, data = self.api(token, "POST", "sightings/add", {
                    "value": self.__value("e1-a1"), "filters": {"ignore": 1, "query": {"id": {">": 0}}}})
                self.assertEqual(status, 400, str(data)[:200])
                self.assertNotIn("Sighting", json.dumps(data))

    def test_error_responses_do_not_echo_the_input(self):
        needle = "ZZ_ECHO_" + random()
        for tree in ({needle: 1}, {"id": needle}, {"id": {needle: 1}}, {"AND": [{"id": 1}, {needle: {"=": needle}}]}):
            status, _, data = self.__search(tree)
            self.assertEqual(status, 400)
            self.assertNotIn(needle, json.dumps(data))

    def test_acl_cannot_be_overridden_through_the_query(self):
        attempts = {
            "hidden event only": {"event_id": self.e3},
            "hidden event or visible": {"OR": [{"event_id": self.e3}, {"event_id": self.e1}]},
            "org-only distribution": {"AND": [{"event_id": self.e2}, {"distribution": 0}]},
            "sharing group distribution": {"AND": [{"event_id": self.e2}, {"distribution": 4}]},
            "not visible": {"NOT": {"event_id": {"IN": [self.e1, self.e2]}}},
            "foreign org leaf": {"OR": [{"org": "no-such-org"}, {"event_id": {"IN": self.all_events}}]},
            "by hidden values": {"OR": [{"value": self.__value("e3-x1")}, {"value": self.__value("e2-h1")}]},
            "by hidden values in": {"value": {"IN": sorted(self.hidden)}},
            "hidden values like": {"AND": [{"comment": self.marker}, {"value": {"LIKE": "%-h%"}}]},
        }
        for name, tree in attempts.items():
            with self.subTest(name):
                status, values, _ = self.__search(tree)
                self.assertEqual(status, 200)
                self.assertEqual(values & self.hidden, set(), "hidden data leaked")
        # legacy parameters next to the tree stay subject to the ACL and cannot widen it
        tree = self.__anchored({"OR": [{"id": {">": 0}}, {"NOT": {"id": {">": 0}}}]})
        for extra in ({"deleted": [0, 1]}, {"sharinggroup": [self.sg_id]}, {"org": "ADMIN"}, {"published": [0, 1]}, {"includeAllTags": 1},
                      {"distribution": [0, 1, 2, 3, 4, 5]}, {"ignore": 1}):
            with self.subTest(extra):
                status, values, _ = self.__search(tree, extra=extra)
                self.assertIn(status, (200, 400, 403))
                if status == 200:
                    self.assertEqual(values & self.hidden, set(), "hidden data leaked")
                    self.assertTrue(values <= self.visible)

    def test_discovery_endpoint_requires_the_permission(self):
        status, data = self.api(self.user_key, "GET", "attributes/queryDescribe")
        self.assertEqual(status, 200)
        self.assertIn("attributes", data["tables"])
        self.assertEqual(self.api(self.plain_user_key, "GET", "attributes/queryDescribe")[0], 403)


class TestComplexEventQueryAcl(unittest.TestCase):
    """The `query` tree of /events/restSearch must select events only through what the user can see."""

    api = staticmethod(TestComplexQueryAcl.api)
    admin_api = staticmethod(TestComplexQueryAcl.admin_api)

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        admin = PyMISP(url, key)
        check_response(admin.set_server_setting('Security.advanced_authkeys', True, force=True))
        cls.marker = "mqe" + random()
        cls.created = {"events": [], "tags": set(), "users": [], "roles": [], "sgs": [], "keys": []}
        cls.org = None
        try:
            cls.__build_fixture()
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def __build_fixture(cls):
        cls.org = cls.admin_api("POST", "admin/organisations/add", {"name": "MQE Org " + random(), "local": True})["Organisation"]
        me = cls.admin_api("GET", "users/view/me")["Organisation"]
        cls.admin_org_id, admin_org_uuid = int(me["id"]), me["uuid"]
        roles = {
            "flagged": {"permission": "1", "perm_auth": 1, "perm_complex_query": 1},
            "plain": {"permission": "0", "perm_auth": 1},
            "site_admin": {"permission": "3", "perm_auth": 1, "perm_site_admin": 1, "perm_complex_query": 0},
        }
        keys = {}
        for name, perms in roles.items():
            role = cls.admin_api("POST", "admin/roles/add", {"Role": {"name": f"MQE {name} {random()}", **perms}})["Role"]
            cls.created["roles"].append(role["id"])
            keys[name] = cls.__make_user(role["id"])
        cls.user_key, cls.plain_user_key, cls.site_admin_key = keys["flagged"], keys["plain"], keys["site_admin"]

        # a sharing group the test org is not a member of
        sg = cls.admin_api("POST", "sharingGroups/add", {
            "SharingGroup": {"name": "MQE SG " + random(), "releasability": "test", "description": "test", "active": 1,
                             "organisation_uuid": admin_org_uuid, "roaming": 0},
            "Organisation": [{"uuid": admin_org_uuid, "extend": True}]})
        cls.sg_id = sg["SharingGroup"]["id"]
        cls.created["sgs"].append(cls.sg_id)

        cls.tag_vis, cls.tag_hid, cls.tag_evt = (f"{cls.marker}:{t}" for t in ("vis", "hid", "evt"))
        # E1 visible, E2 visible with hidden elements, E3 not visible, E4 owned by the test org
        cls.e1 = cls.__make_event("e1", 3, [("a1", 5, cls.tag_vis), ("a2", 3, None)], event_tag=cls.tag_evt)
        cls.e2 = cls.__make_event("e2", 3, [("v1", 5, None), ("h1", 0, cls.tag_hid), ("h2", 4, None)], hidden_object="oa")
        cls.e3 = cls.__make_event("e3", 0, [("x1", 5, cls.tag_vis)], event_tag=cls.tag_evt)
        cls.e4 = cls.__make_event("e4", 0, [("p1", 0, None)], token=cls.user_key)
        cls.all_events = [cls.e1, cls.e2, cls.e3, cls.e4]
        cls.visible = {cls.e1: {cls.__value("e1-a1"), cls.__value("e1-a2")}, cls.e2: {cls.__value("e2-v1")},
                       cls.e4: {cls.__value("e4-p1")}}
        cls.hidden_values = {cls.__value(n) for n in ("e2-h1", "e2-h2", "e2-oa", "e3-x1")}

    @classmethod
    def tearDownClass(cls):
        for kind, path in (("events", "events/delete/{}"), ("tags", "tags/delete/{}"), ("keys", "authKeys/delete/{}"),
                           ("users", "admin/users/delete/{}"), ("sgs", "sharingGroups/delete/{}"), ("roles", "admin/roles/delete/{}")):
            for item in cls.created[kind]:
                try:
                    cls.api(key, "POST", path.format(item))
                except Exception:
                    pass
        if cls.org:
            try:
                cls.api(key, "POST", f"admin/organisations/delete/{cls.org['id']}")
            except Exception:
                pass

    @classmethod
    def __make_user(cls, role_id) -> str:
        user = cls.admin_api("POST", "admin/users/add", {
            "email": f"mqe{random()}@user.local", "org_id": cls.org["id"], "role_id": role_id, "password": str(uuid.uuid4())})["User"]
        cls.created["users"].append(user["id"])
        auth_key = cls.admin_api("POST", f"authKeys/add/{user['id']}")["AuthKey"]
        cls.created["keys"].append(auth_key["id"])
        return auth_key["authkey_raw"]

    @classmethod
    def __value(cls, name: str) -> str:
        return f"{cls.marker}-{name}.example.com"

    @classmethod
    def __make_event(cls, name: str, distribution: int, attributes, event_tag=None, hidden_object=None, token=None) -> int:
        def attribute(n, d, tag=None, **extra):
            return {"type": "domain", "category": "Network activity", "value": cls.__value(f"{name}-{n}"), "distribution": d,
                    **({"sharing_group_id": cls.sg_id} if d == 4 else {}), **({"Tag": [{"name": tag}]} if tag else {}), **extra}
        event = {"info": f"{cls.marker} {name}", "distribution": distribution, "threat_level_id": 4, "analysis": 0,
                 "Attribute": [attribute(n, d, tag) for n, d, tag in attributes]}
        if event_tag:
            event["Tag"] = [{"name": event_tag}]
        if hidden_object:
            event["Object"] = [{"name": "domain-ip", "meta-category": "network", "distribution": 0,
                                "template_uuid": "43b3b146-77eb-4931-b4cc-b66c60f28734", "template_version": "9",
                                "Attribute": [attribute(hidden_object, 5, object_relation="domain")]}]
        status, data = cls.api(token or key, "POST", "events/add", {"Event": event})
        assert status == 200, (status, str(data)[:300])
        event_id = data["Event"]["id"]
        cls.created["events"].append(event_id)
        for tag in data["Event"].get("Tag", []) + [t for a in data["Event"].get("Attribute", []) for t in a.get("Tag", [])]:
            if tag["name"].startswith(cls.marker):
                cls.created["tags"].add(tag["id"])
        cls.admin_api("POST", f"events/publish/{event_id}/disable_background_processing:1")
        return int(event_id)

    def __search(self, query, token=None, extra=None, method="POST"):
        body = {"returnFormat": "json", "query": query}
        body.update(extra or {})
        status, data = self.api(token or self.user_key, method, "events/restSearch", body)
        events = None
        if status == 200 and isinstance(data, dict):
            events = {}
            for e in data["response"]:
                attributes = e["Event"].get("Attribute", []) + [a for o in e["Event"].get("Object", []) for a in o.get("Attribute", [])]
                events[int(e["Event"]["id"])] = {a["value"] for a in attributes}
        return status, events, data

    def __anchored(self, tree):
        return {"AND": [{"id": {"IN": self.all_events}}, tree]}

    def assertNoHiddenData(self, events, msg=None):
        self.assertNotIn(self.e3, events, msg)
        self.assertEqual(set().union(*events.values()) & self.hidden_values, set(), msg)

    def test_fixture_is_discriminating(self):
        status, events, _ = self.__search({"id": {"IN": self.all_events}}, token=key)
        self.assertEqual(status, 200)
        self.assertEqual(set(events), set(self.all_events))
        self.assertTrue(self.hidden_values <= set().union(*events.values()))
        # the user sees E1, E2 without its hidden elements, and its own E4
        status, events, _ = self.__search({"id": {"IN": self.all_events}})
        self.assertEqual((status, events), (200, self.visible))
        # without the visibility restriction the hidden attribute would select E2
        status, events, _ = self.__search({"value": self.__value("e2-h1")}, token=key)
        self.assertEqual(status, 200)
        self.assertEqual(set(events), {self.e2})

    def test_element_leaves_count_only_visible_elements(self):
        cases = {
            "visible value": ({"value": self.__value("e2-v1")}, {self.e2}),
            "hidden value": ({"value": self.__value("e2-h1")}, set()),
            "sharing group value": ({"value": self.__value("e2-h2")}, set()),
            "attribute in a hidden object": ({"value": self.__value("e2-oa")}, set()),
            "hidden value prefix": ({"value": {"LIKE": f"{self.marker}-e2-h%"}}, set()),
            "hidden values in": ({"value": {"IN": sorted(self.hidden_values)}}, set()),
            "tag of a hidden attribute": ({"tags": self.tag_hid}, set()),
            "hidden object name": ({"AND": [{"id": self.e2}, {"object_name": "domain-ip"}]}, set()),
            "visible attribute tag": ({"tags": self.tag_vis}, {self.e1}),
            "own org private attribute": ({"value": self.__value("e4-p1")}, {self.e4}),
            "hidden or visible": ({"OR": [{"value": self.__value("e2-h1")}, {"value": self.__value("e2-v1")}]}, {self.e2}),
        }
        for name, (tree, expected) in cases.items():
            with self.subTest(name):
                status, events, _ = self.__search(tree)
                self.assertEqual(status, 200)
                self.assertEqual(set(events), expected)
                self.assertNoHiddenData(events)

    def test_match_all_queries_never_return_hidden_data(self):
        trees = {
            "tautology": {"OR": [{"id": {">": 0}}, {"NOT": {"id": {">": 0}}}]},
            "double negation": {"NOT": {"NOT": {"eventinfo": {"LIKE": f"{self.marker}%"}}}},
            "or with element leaves": {"OR": [{"value": {"LIKE": f"{self.marker}%"}}, {"id": {">": 0}}]},
            "every distribution": {"distribution": {"IN": [0, 1, 2, 3, 4, 5]}},
            "negated distribution": {"distribution": {"NOT IN": [9]}},
            "any date": {"date": {">=": "1970-01-02"}},
        }
        for name, tree in trees.items():
            with self.subTest(name):
                status, events, _ = self.__search(self.__anchored(tree))
                self.assertEqual((status, events), (200, self.visible))

    def test_acl_cannot_be_overridden_through_the_query(self):
        attempts = {
            "hidden event": {"id": self.e3},
            "hidden or visible event": {"OR": [{"id": self.e3}, {"id": self.e1}]},
            "admin org": self.__anchored({"org_id": self.admin_org_id}),
            "creator org": self.__anchored({"orgc_id": self.admin_org_id}),
            "org-only distribution": self.__anchored({"distribution": 0}),
            "not the visible ones": self.__anchored({"NOT": {"id": {"IN": [self.e1, self.e2, self.e4]}}}),
        }
        for name, tree in attempts.items():
            with self.subTest(name):
                status, events, _ = self.__search(tree)
                self.assertEqual(status, 200)
                self.assertNoHiddenData(events)
        tree = self.__anchored({"OR": [{"id": {">": 0}}, {"NOT": {"id": {">": 0}}}]})
        for extra in ({"eventid": [self.e3]}, {"sharinggroup": [self.sg_id]}, {"org": "ADMIN"}, {"published": [0, 1]},
                      {"distribution": [0, 1, 2, 3, 4, 5]}, {"includeAllTags": 1}, {"deleted": [0, 1]}):
            with self.subTest(extra):
                status, events, _ = self.__search(tree, extra=extra)
                self.assertIn(status, (200, 400, 403))
                if status == 200:
                    self.assertNoHiddenData(events)

    def test_negated_tags(self):
        status, events, _ = self.__search(self.__anchored({"tags": {"!=": self.tag_vis}}))
        self.assertEqual((status, events), (200, {**self.visible, self.e1: {self.__value("e1-a2")}}))
        status, events, _ = self.__search(self.__anchored({"tags": {"NOT LIKE": f"{self.marker}:v%"}}))
        self.assertEqual((status, events), (200, {**self.visible, self.e1: {self.__value("e1-a2")}}))
        for negated in ({"NOT IN": [self.tag_evt]}, {"NOT LIKE": f"{self.marker}:e%"}):
            status, events, _ = self.__search(self.__anchored({"tags": negated}))
            self.assertEqual(status, 200)
            self.assertEqual(set(events), {self.e2, self.e4})
        rejected = {
            "negated tag under or": ({"OR": [{"id": self.e1}, {"tags": {"!=": self.tag_vis}}]}, "bad_shape"),
            "not like tag under or": ({"OR": [{"id": self.e1}, {"tags": {"NOT LIKE": f"{self.marker}:%"}}]}, "bad_shape"),
            "not like attribute field": ({"value": {"NOT LIKE": f"{self.marker}%"}}, "unknown_operator"),
            "tag under not": ({"NOT": {"tags": self.tag_vis}}, "bad_shape"),
            "attribute field under not": ({"NOT": {"AND": [{"id": self.e1}, {"type": "domain"}]}}, "bad_shape"),
            "negated attribute field": ({"type": {"!=": "domain"}}, "unknown_operator"),
        }
        for name, (tree, code) in rejected.items():
            with self.subTest(name):
                status, events, data = self.__search(tree)
                self.assertEqual((status, events), (400, None))
                self.assertEqual(data["errors"][0]["code"], code)

    def test_malformed_queries_return_no_data(self):
        bad = {
            "string": "id=1", "list": [{"id": 1}], "empty": {}, "unknown field": {"nope": 1}, "renamed field": {"info": "x"},
            "acl field": {"sharing_group_id": self.sg_id}, "wrong type": {"id": "1"}, "impossible date": {"date": "2026-02-30"},
            "relative date in hours": {"date": "7h"}, "template like": {"object_template_uuid": {"LIKE": "%a"}},
            "too deep": {"NOT": {"NOT": {"NOT": {"NOT": {"NOT": {"NOT": {"id": 1}}}}}}},
        }
        for name, tree in bad.items():
            with self.subTest(name):
                status, events, data = self.__search(tree)
                self.assertEqual((status, events), (400, None), data)
                self.assertNotIn("response", data)
        for token in (self.plain_user_key, "x" * 40):
            with self.subTest(token[:4]):
                status, events, _ = self.__search({"id": self.e1}, token=token)
                self.assertEqual((status, events), (403, None))

    def test_site_admins_need_no_permission_flag(self):
        status, events, _ = self.__search({"value": self.__value("e2-h1")}, token=self.site_admin_key)
        self.assertEqual(status, 200)
        self.assertEqual(set(events), {self.e2})
        self.assertEqual(self.api(self.site_admin_key, "GET", "events/queryDescribe")[0], 200)

    def test_query_is_only_accepted_in_a_post_body(self):
        status, _ = self.api(self.user_key, "GET", f"events/restSearch?returnFormat=json&query[id]={self.e1}")
        self.assertEqual(status, 400)
        for path in (f"events/restSearch?query[id]={self.e3}", "events/restSearch/query:x"):
            with self.subTest(path):
                status, data = self.api(self.user_key, "POST", path, {"returnFormat": "json", "query": {"id": self.e1}})
                self.assertEqual(status, 400)
                self.assertNotIn("response", data)

    def test_unknown_order_fields_are_rejected(self):
        tree = {"id": self.e1}
        for order in ("nope", "Attribute.id", "id up", "eventinfo"):
            with self.subTest(order):
                status, events, data = self.__search(tree, extra={"order": order})
                self.assertEqual((status, events), (400, None), data)
        for order in ("timestamp desc", "Event.id", "info"):
            with self.subTest(order):
                status, events, _ = self.__search(tree, extra={"order": order})
                self.assertEqual(status, 200)
                self.assertEqual(set(events), {self.e1})

    def test_error_responses_do_not_echo_the_input(self):
        needle = "ZZ_ECHO_" + random()
        for tree in ({needle: 1}, {"id": needle}, {"date": needle}, {"AND": [{"id": 1}, {"tags": {needle: needle}}]}):
            status, _, data = self.__search(tree)
            self.assertEqual(status, 400)
            self.assertNotIn(needle, json.dumps(data))

    def test_discovery_endpoint(self):
        status, data = self.api(self.user_key, "GET", "events/queryDescribe")
        self.assertEqual(status, 200)
        table = data["tables"]["events"]
        self.assertEqual(table["endpoint"], "/events/restSearch")
        self.assertEqual(table["fields"]["tags"]["level"], ["event", "attribute"])
        self.assertEqual(table["fields"]["value"]["operators"], ["=", "IN", "LIKE"])
        self.assertIn("eventinfo", table["fields"])
        self.assertIn("info", table["sortable"])
        self.assertEqual(self.api(self.plain_user_key, "GET", "events/queryDescribe")[0], 403)

class TestComplexObjectQueryAcl(unittest.TestCase):
    """The `query` tree of /objects/restSearch must select objects and attributes only through what the user can see."""

    api = staticmethod(TestComplexQueryAcl.api)
    admin_api = staticmethod(TestComplexQueryAcl.admin_api)

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        admin = PyMISP(url, key)
        check_response(admin.set_server_setting('Security.advanced_authkeys', True, force=True))
        cls.marker = "mqo" + random()
        cls.created = {"events": [], "tags": set(), "users": [], "roles": [], "sgs": [], "keys": []}
        cls.org = None
        try:
            cls.__build_fixture()
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def __build_fixture(cls):
        cls.org = cls.admin_api("POST", "admin/organisations/add", {"name": "MQO Org " + random(), "local": True})["Organisation"]
        me = cls.admin_api("GET", "users/view/me")["Organisation"]
        cls.admin_org_id, admin_org_uuid = int(me["id"]), me["uuid"]
        roles = {
            "flagged": {"permission": "1", "perm_add": 1, "perm_auth": 1, "perm_complex_query": 1},
            "plain": {"permission": "0", "perm_auth": 1},
            "site_admin": {"permission": "3", "perm_auth": 1, "perm_site_admin": 1, "perm_complex_query": 0},
        }
        keys = {}
        for name, perms in roles.items():
            role = cls.admin_api("POST", "admin/roles/add", {"Role": {"name": f"MQO {name} {random()}", **perms}})["Role"]
            cls.created["roles"].append(role["id"])
            keys[name] = cls.__make_user(role["id"])
        cls.user_key, cls.plain_user_key, cls.site_admin_key = keys["flagged"], keys["plain"], keys["site_admin"]

        # a sharing group the test org is not a member of
        sg = cls.admin_api("POST", "sharingGroups/add", {
            "SharingGroup": {"name": "MQO SG " + random(), "releasability": "test", "description": "test", "active": 1,
                             "organisation_uuid": admin_org_uuid, "roaming": 0},
            "Organisation": [{"uuid": admin_org_uuid, "extend": True}]})
        cls.sg_id = sg["SharingGroup"]["id"]
        cls.created["sgs"].append(cls.sg_id)

        cls.tag_vis, cls.tag_hid, cls.tag_evt = (f"{cls.marker}:{t}" for t in ("vis", "hid", "evt"))
        # (name, distribution, attributes (name, distribution, tag))
        cls.e1, cls.o1 = cls.__make_event("e1", 3, [("o1", 5, [("a", 5, None)])], event_tag=cls.tag_evt)
        e2 = cls.__make_event("e2", 3, [("o2a", 5, [("vis", 5, cls.tag_vis), ("hid", 0, cls.tag_hid), ("sg", 4, None)]), ("o2b", 0, [("b", 5, None)])])
        cls.e2, cls.o2a, cls.o2b = e2[0], e2[1][0], e2[1][1]
        cls.e3, cls.o3 = cls.__make_event("e3", 0, [("o3", 5, [("x", 5, None)])])
        cls.e4, cls.o4 = cls.__make_event("e4", 0, [("o4", 5, [("p", 0, None)])], token=cls.user_key)
        cls.all_events = [cls.e1, cls.e2, cls.e3, cls.e4]
        cls.visible = {cls.o1: {cls.__value("o1-a")}, cls.o2a: {cls.__value("o2a-vis")}, cls.o4: {cls.__value("o4-p")}}
        cls.hidden_values = {cls.__value(n) for n in ("o2a-hid", "o2a-sg", "o2b-b", "o3-x")}

    @classmethod
    def tearDownClass(cls):
        for kind, path in (("events", "events/delete/{}"), ("tags", "tags/delete/{}"), ("keys", "authKeys/delete/{}"),
                           ("users", "admin/users/delete/{}"), ("sgs", "sharingGroups/delete/{}"), ("roles", "admin/roles/delete/{}")):
            for item in cls.created[kind]:
                try:
                    cls.api(key, "POST", path.format(item))
                except Exception:
                    pass
        if cls.org:
            try:
                cls.api(key, "POST", f"admin/organisations/delete/{cls.org['id']}")
            except Exception:
                pass

    @classmethod
    def __make_user(cls, role_id) -> str:
        user = cls.admin_api("POST", "admin/users/add", {
            "email": f"mqo{random()}@user.local", "org_id": cls.org["id"], "role_id": role_id, "password": str(uuid.uuid4())})["User"]
        cls.created["users"].append(user["id"])
        auth_key = cls.admin_api("POST", f"authKeys/add/{user['id']}")["AuthKey"]
        cls.created["keys"].append(auth_key["id"])
        return auth_key["authkey_raw"]

    @classmethod
    def __value(cls, name: str) -> str:
        return f"{cls.marker}-{name}.example.com"

    @classmethod
    def __comment(cls, name: str) -> str:
        return f"{cls.marker}-c-{name}"

    @classmethod
    def __make_event(cls, name: str, distribution: int, objects, event_tag=None, token=None):
        """Returns (event id, id of the object) for one object, or (event id, [object ids]) for several."""
        def attribute(obj, n, d, tag):
            return {"type": "domain", "category": "Network activity", "object_relation": "domain", "distribution": d,
                    "value": cls.__value(f"{obj}-{n}"), "comment": cls.__comment(f"{obj}-{n}"),
                    **({"sharing_group_id": cls.sg_id} if d == 4 else {}), **({"Tag": [{"name": tag}]} if tag else {})}
        uuids = {obj: str(uuid.uuid4()) for obj, _, _ in objects}
        event = {"info": f"{cls.marker} {name}", "distribution": distribution, "threat_level_id": 4, "analysis": 0,
                 "Object": [{"name": "domain-ip", "meta-category": "network", "distribution": d, "uuid": uuids[obj],
                             "template_uuid": "43b3b146-77eb-4931-b4cc-b66c60f28734", "template_version": "9",
                             "Attribute": [attribute(obj, n, ad, tag) for n, ad, tag in attrs]} for obj, d, attrs in objects]}
        if event_tag:
            event["Tag"] = [{"name": event_tag}]
        status, data = cls.api(token or key, "POST", "events/add", {"Event": event})
        assert status == 200, (status, str(data)[:300])
        event_id = data["Event"]["id"]
        cls.created["events"].append(event_id)
        found = data["Event"].get("Tag", []) + [t for o in data["Event"].get("Object", []) for a in o.get("Attribute", [])
                                                 for t in a.get("Tag", [])]
        for tag in found:
            if tag["name"].startswith(cls.marker):
                cls.created["tags"].add(tag["id"])
        cls.admin_api("POST", f"events/publish/{event_id}/disable_background_processing:1")
        ids = {o["uuid"]: int(o["id"]) for o in data["Event"]["Object"]}
        result = [ids[uuids[obj]] for obj, _, _ in objects]
        return (int(event_id), result[0]) if len(result) == 1 else (int(event_id), result)

    def __search(self, query, token=None, extra=None, method="POST"):
        """Returns (status, {object id: [attribute values]} or None, raw data)."""
        body = {"returnFormat": "json", "query": query}
        body.update(extra or {})
        status, data = self.api(token or self.user_key, method, "objects/restSearch", body)
        objects = None
        if status == 200 and isinstance(data, dict):
            objects = {int(o["Object"]["id"]): [a["value"] for a in o["Object"].get("Attribute", [])] for o in data["response"]}
        return status, objects, data

    def __anchored(self, tree):
        return {"AND": [{"event_id": {"IN": self.all_events}}, tree]}

    def __values(self, objects):
        return {i: set(v) for i, v in objects.items()}

    def assertNoHiddenData(self, objects, msg=None):
        self.assertNotIn(self.o2b, objects, msg)
        self.assertNotIn(self.o3, objects, msg)
        self.assertEqual({v for vals in objects.values() for v in vals} & self.hidden_values, set(), msg)

    def test_fixture_is_discriminating(self):
        status, objects, _ = self.__search({"event_id": {"IN": self.all_events}}, token=key)
        self.assertEqual(status, 200)
        self.assertEqual(set(objects), {self.o1, self.o2a, self.o2b, self.o3, self.o4})
        self.assertTrue(self.hidden_values <= {v for vals in objects.values() for v in vals})
        status, objects, _ = self.__search({"event_id": {"IN": self.all_events}})
        self.assertEqual(status, 200)
        self.assertEqual(self.__values(objects), self.visible)

    def test_baseline(self):
        cases = {
            "object field": ({"AND": [{"event_id": {"IN": self.all_events}}, {"object_name": "domain-ip"}]}, set(self.visible)),
            "object id": ({"id": self.o1}, {self.o1}),
            "attribute leaf": ({"value": self.__value("o2a-vis")}, {self.o2a}),
            "attribute like": ({"value": {"LIKE": f"{self.marker}-o2a-vis%"}}, {self.o2a}),
            "type and relation": (self.__anchored({"AND": [{"type": "domain"}, {"object_relation": "domain"}]}), set(self.visible)),
            "comment": ({"comment": self.__comment("o1-a")}, {self.o1}),
        }
        for name, (tree, expected) in cases.items():
            with self.subTest(name):
                status, objects, data = self.__search(tree)
                self.assertEqual(status, 200, data)
                self.assertEqual(set(objects), expected)
                self.assertNoHiddenData(objects)
        status, objects, _ = self.__search({"id": self.o2a})
        self.assertEqual((status, self.__values(objects)), (200, {self.o2a: {self.__value("o2a-vis")}}))
        status, data = self.api(self.user_key, "POST", "objects/restSearch", {
            "returnFormat": "json", "metadata": True, "query": {"id": self.o2a}})
        self.assertEqual(status, 200)
        self.assertEqual([o["Object"]["id"] for o in data["response"]], [str(self.o2a)])
        self.assertNotIn("Attribute", data["response"][0]["Object"])

    def test_hidden_attribute_selects_nothing(self):
        hid = self.__value("o2a-hid")
        trees = {
            "value": {"value": hid},
            "value in": {"value": {"IN": [hid]}},
            "value like": {"value": {"LIKE": f"{self.marker}-o2a-hid%"}},
            "comment": {"comment": self.__comment("o2a-hid")},
            "type and value": {"AND": [{"type": "domain"}, {"value": hid}]},
            "or with nothing": {"OR": [{"value": hid}, {"comment": "no-such-comment"}]},
            "sharing group value": {"value": self.__value("o2a-sg")},
        }
        for name, tree in trees.items():
            with self.subTest(name):
                status, objects, data = self.__search(tree)
                self.assertEqual((status, objects), (200, {}), data)
                status, objects, data = self.__search(tree, token=key)
                self.assertEqual(status, 200, data)
                self.assertEqual(set(objects), {self.o2a}, "fixture is not discriminating")

    def test_hidden_objects_and_events_are_never_returned(self):
        cases = {
            "id": {"id": self.o2b}, "object_id": {"object_id": {"IN": [self.o2b, self.o3]}},
            "event_id": {"event_id": self.e3}, "attribute value": {"value": self.__value("o2b-b")},
            "attribute value of the hidden event": {"value": self.__value("o3-x")},
            "attribute like": {"value": {"LIKE": f"{self.marker}-o%"}},
            "attribute comment": {"comment": {"IN": [self.__comment("o2b-b"), self.__comment("o3-x")]}},
            "attribute type": self.__anchored({"type": "domain"}),
            "object name": self.__anchored({"object_name": "domain-ip"}),
            "tautology": self.__anchored({"OR": [{"id": {">=": 0}}, {"NOT": {"id": {">=": 0}}}]}),
            "distribution": self.__anchored({"distribution": {"IN": [0, 1, 2, 3, 4, 5]}}),
        }
        for name, tree in cases.items():
            with self.subTest(name):
                status, objects, data = self.__search(tree)
                self.assertEqual(status, 200, data)
                self.assertNoHiddenData(objects)
        uuid_by_object = {}
        status, objects, data = self.__search({"event_id": {"IN": self.all_events}}, token=key)
        self.assertEqual(status, 200)
        for o in data["response"]:
            uuid_by_object[int(o["Object"]["id"])] = o["Object"]["uuid"]
        for hidden in (self.o2b, self.o3):
            with self.subTest(f"uuid {hidden}"):
                status, objects, data = self.__search({"uuid": uuid_by_object[hidden]})
                self.assertEqual((status, objects), (200, {}), data)
                status, objects, data = self.__search({"uuid": uuid_by_object[hidden]}, token=key)
                self.assertEqual((status, set(objects)), (200, {hidden}))

    def test_own_org_sees_its_private_attribute(self):
        for tree in ({"value": self.__value("o4-p")}, {"comment": self.__comment("o4-p")}, {"id": self.o4}):
            with self.subTest(str(tree)):
                status, objects, data = self.__search(tree)
                self.assertEqual(status, 200, data)
                self.assertEqual(self.__values(objects), {self.o4: {self.__value("o4-p")}})

    def test_tags(self):
        cases = {
            "visible attribute tag": ({"tags": self.tag_vis}, {self.o2a}),
            "hidden attribute tag": ({"tags": self.tag_hid}, set()),
            "hidden attribute tag in": ({"tags": {"IN": [self.tag_hid]}}, set()),
            "hidden tag or visible tag": ({"OR": [{"tags": self.tag_hid}, {"tags": self.tag_vis}]}, {self.o2a}),
            "event tag": ({"tags": self.tag_evt}, {self.o1}),
        }
        for name, (tree, expected) in cases.items():
            with self.subTest(name):
                status, objects, data = self.__search(tree)
                self.assertEqual(status, 200, data)
                self.assertEqual(set(objects), expected)
                self.assertNoHiddenData(objects)
        status, objects, data = self.__search({"tags": self.tag_hid}, token=key)
        self.assertEqual(status, 200, data)
        self.assertEqual(set(objects), {self.o2a})

    def test_negated_tags(self):
        status, objects, data = self.__search(self.__anchored({"tags": {"!=": self.tag_evt}}))
        self.assertEqual(status, 200, data)
        self.assertEqual(set(objects), {self.o2a, self.o4})
        status, objects, data = self.__search(self.__anchored({"tags": {"NOT IN": [self.tag_evt]}}))
        self.assertEqual(status, 200, data)
        self.assertEqual(set(objects), {self.o2a, self.o4})
        status, objects, data = self.__search(self.__anchored({"tags": {"NOT LIKE": f"{self.marker}:e%"}}))
        self.assertEqual(status, 200, data)
        self.assertEqual(set(objects), {self.o2a, self.o4})
        status, objects, data = self.__search({"id": self.o2a})
        self.assertEqual((status, self.__values(objects)), (200, {self.o2a: {self.__value("o2a-vis")}}))
        for tree in ({"AND": [{"id": self.o2a}, {"tags": {"!=": self.tag_vis}}]},
                     {"AND": [{"id": self.o2a}, {"tags": {"NOT IN": [self.tag_vis]}}]},
                     {"AND": [{"id": self.o2a}, {"tags": {"NOT LIKE": f"{self.marker}:v%"}}]}):
            with self.subTest(str(tree)):
                status, objects, data = self.__search(tree)
                self.assertEqual(status, 200, data)
                self.assertEqual(objects, {self.o2a: []})
        # stripping applies to the site admin's view too
        status, objects, data = self.__search({"AND": [{"id": self.o2a}, {"tags": {"!=": self.tag_vis}}]}, token=key)
        self.assertEqual(status, 200, data)
        self.assertEqual(self.__values(objects), {self.o2a: {self.__value("o2a-hid"), self.__value("o2a-sg")}})

    def test_hidden_attribute_never_appears_in_attribute_lists(self):
        trees = [{"id": self.o2a}, {"value": self.__value("o2a-vis")}, {"tags": self.tag_vis}, {"object_name": "domain-ip"},
                 {"AND": [{"id": self.o2a}, {"tags": {"!=": self.tag_evt}}]}, {"AND": [{"id": self.o2a}, {"tags": {"!=": self.tag_hid}}]}]
        for tree in trees:
            with self.subTest(str(tree)):
                status, objects, data = self.__search(self.__anchored(tree))
                self.assertEqual(status, 200, data)
                self.assertNoHiddenData(objects)
                self.assertNotIn(self.tag_hid, json.dumps(data))

    def test_match_all_queries_never_return_hidden_data(self):
        trees = {
            "tautology": {"OR": [{"id": {">=": 0}}, {"NOT": {"id": {">=": 0}}}]},
            "every distribution": {"distribution": {"IN": [0, 1, 2, 3, 4, 5]}},
            "hidden event id": {"OR": [{"event_id": self.e3}, {"event_id": self.e1}]},
            "double negation": {"NOT": {"NOT": {"eventinfo": {"LIKE": f"{self.marker}%"}}}},
            "admin org": {"orgc_id": self.admin_org_id},
            "not the visible ones": {"NOT": {"id": {"IN": [self.o1, self.o2a, self.o4]}}},
            "or with attribute leaves": {"OR": [{"value": {"LIKE": f"{self.marker}%"}}, {"id": {">=": 0}}]},
        }
        for name, tree in trees.items():
            with self.subTest(name):
                status, objects, data = self.__search(self.__anchored(tree))
                self.assertEqual(status, 200, data)
                self.assertNoHiddenData(objects)
                self.assertLessEqual(set(objects), set(self.visible))
        status, objects, data = self.__search({"event_id": self.e3})
        self.assertEqual((status, objects), (200, {}), data)
        tree = self.__anchored({"OR": [{"id": {">=": 0}}, {"NOT": {"id": {">=": 0}}}]})
        for extra in ({"eventid": [self.e3]}, {"sharinggroup": [self.sg_id]}, {"org": "ADMIN"}, {"published": [0, 1]},
                      {"distribution": [0, 1, 2, 3, 4, 5]}, {"deleted": [0, 1]}):
            with self.subTest(extra):
                status, objects, _ = self.__search(tree, extra=extra)
                self.assertIn(status, (200, 400, 403))
                if status == 200:
                    self.assertNoHiddenData(objects)

    def test_rejections(self):
        rejected = {
            "negated attribute field": ({"type": {"!=": "domain"}}, "unknown_operator"),
            "not attribute field": ({"NOT": {"type": "domain"}}, "bad_shape"),
            "not over a subtree with an attribute field": ({"NOT": {"AND": [{"id": self.o1}, {"value": "x"}]}}, "bad_shape"),
            "negated tags under or": ({"OR": [{"id": self.o1}, {"tags": {"!=": self.tag_vis}}]}, "bad_shape"),
            "tags under not": ({"NOT": {"tags": self.tag_vis}}, "bad_shape"),
        }
        for name, (tree, code) in rejected.items():
            with self.subTest(name):
                status, objects, data = self.__search(tree)
                self.assertEqual((status, objects), (400, None), data)
                self.assertNotIn("response", data)
                self.assertEqual(data["errors"][0]["code"], code)
        status, objects, data = self.__search({"id": self.o1}, extra={"order": "id"})
        self.assertEqual((status, objects), (400, None), data)
        self.assertNotIn("response", data)
        self.assertEqual(data["errors"][0]["path"], "order[0]")
        bad = {
            "string": "id=1", "list": [{"id": 1}], "empty": {}, "unknown field": {"nope": 1}, "wrong type": {"id": "1"},
            "two keys": {"id": 1, "uuid": "x"}, "acl field": {"sharing_group_id": self.sg_id},
            "too deep": {"NOT": {"NOT": {"NOT": {"NOT": {"NOT": {"NOT": {"id": 1}}}}}}},
        }
        for name, tree in bad.items():
            with self.subTest(name):
                status, objects, data = self.__search(tree)
                self.assertEqual((status, objects), (400, None), data)
                self.assertNotIn("response", data)

    def test_query_is_only_accepted_in_a_post_body(self):
        status, data = self.api(self.user_key, "GET", f"objects/restSearch?returnFormat=json&query[id]={self.o1}")
        self.assertEqual(status, 400)
        self.assertNotIn("response", data or {})
        status, data = self.api(self.user_key, "GET", "objects/restSearch", {"returnFormat": "json", "query": {"id": self.o1}})
        self.assertEqual(status, 400)
        self.assertNotIn("response", data or {})
        for path in (f"objects/restSearch?query[id]={self.o3}", "objects/restSearch/query:x"):
            with self.subTest(path):
                status, data = self.api(self.user_key, "POST", path, {"returnFormat": "json", "query": {"id": self.o1}})
                self.assertEqual(status, 400)
                self.assertNotIn("response", data or {})

    def test_permission_flag(self):
        for token in (self.plain_user_key, "x" * 40):
            with self.subTest(token[:4]):
                status, objects, _ = self.__search({"id": self.o1}, token=token)
                self.assertEqual((status, objects), (403, None))
                self.assertEqual(self.api(token, "GET", "objects/queryDescribe")[0], 403)
        status, data = self.api(self.user_key, "GET", "objects/queryDescribe")
        self.assertEqual(status, 200)
        table = data["tables"]["objects"]
        self.assertEqual(table["endpoint"], "/objects/restSearch")
        self.assertEqual(table["sortable"], [])
        for name, field in table["fields"].items():
            self.assertIn("level", field, name)
        self.assertEqual(table["fields"]["tags"]["level"], ["event", "attribute"])
        status, objects, _ = self.__search({"value": self.__value("o2a-hid")}, token=self.site_admin_key)
        self.assertEqual(status, 200)
        self.assertEqual(set(objects), {self.o2a})
        self.assertEqual(self.api(self.site_admin_key, "GET", "objects/queryDescribe")[0], 200)


class TestComplexGalaxyClusterQueryAcl(unittest.TestCase):
    """The `query` tree of /galaxy_clusters/restSearch must only narrow what the legacy endpoint shows the user."""

    api = staticmethod(TestComplexQueryAcl.api)
    admin_api = staticmethod(TestComplexQueryAcl.admin_api)

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        admin = PyMISP(url, key)
        check_response(admin.set_server_setting('Security.advanced_authkeys', True, force=True))
        cls.marker = "mqg" + random()
        cls.created = {"clusters": [], "galaxies": [], "keys": [], "users": [], "sgs": [], "roles": []}
        cls.org = None
        try:
            cls.__build_fixture()
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def __build_fixture(cls):
        cls.org = cls.admin_api("POST", "admin/organisations/add", {"name": "MQG Org " + random(), "local": True})["Organisation"]
        me = cls.admin_api("GET", "users/view/me")["Organisation"]
        cls.admin_org_id, cls.admin_org_uuid, cls.admin_org_name = int(me["id"]), me["uuid"], me["name"]
        roles = {
            "flagged": {"permission": "1", "perm_add": 1, "perm_auth": 1, "perm_galaxy_editor": 1, "perm_complex_query": 1},
            "plain": {"permission": "0", "perm_auth": 1},
            "site_admin": {"permission": "3", "perm_auth": 1, "perm_site_admin": 1, "perm_complex_query": 0},
        }
        keys = {}
        for name, perms in roles.items():
            role = cls.admin_api("POST", "admin/roles/add", {"Role": {"name": f"MQG {name} {random()}", **perms}})["Role"]
            cls.created["roles"].append(role["id"])
            keys[name] = cls.__make_user(role["id"])
        cls.user_key, cls.plain_user_key, cls.site_admin_key = keys["flagged"], keys["plain"], keys["site_admin"]

        def sharing_group(label, members):
            sg = cls.admin_api("POST", "sharingGroups/add", {
                "SharingGroup": {"name": f"MQG SG {label} {random()}", "releasability": "test", "description": "test", "active": 1,
                                 "organisation_uuid": cls.admin_org_uuid, "roaming": 0}})["SharingGroup"]["id"]
            cls.created["sgs"].append(sg)
            for org_id in members:
                cls.api(key, "POST", f"sharingGroups/addOrg/{sg}/{org_id}", {"extend": 0})
            return sg
        cls.sg_out = sharing_group("out", [cls.admin_org_id])
        cls.sg_in = sharing_group("in", [cls.admin_org_id, cls.org["id"]])

        # a galaxy the test org can see, and one it cannot (distribution 0, admin org)
        cls.galaxy_vis = cls.__make_galaxy("vis", 3)
        cls.galaxy_hid = cls.__make_galaxy("hid", 0)
        # (distribution, sharing group, galaxy, token)
        specs = {"pub": (3, None, cls.galaxy_vis, key), "org": (0, None, cls.galaxy_vis, key),
                 "sg_out": (4, cls.sg_out, cls.galaxy_vis, key), "sg_in": (4, cls.sg_in, cls.galaxy_vis, key),
                 "own": (0, None, cls.galaxy_vis, cls.user_key), "hg": (3, None, cls.galaxy_hid, key)}
        cls.c = {name: cls.__make_cluster(name, *spec) for name, spec in specs.items()}
        cls.visible = {cls.c[n] for n in ("pub", "sg_in", "own")}
        cls.hidden = {cls.c[n] for n in ("org", "sg_out", "hg")}
        cls.all_ids = cls.visible | cls.hidden
        status, data = cls.api(key, "POST", "galaxy_clusters/restSearch", {"returnFormat": "json", "value": cls.marker + "%"})
        assert status == 200, (status, data)
        cls.uuids = {int(c["GalaxyCluster"]["id"]): c["GalaxyCluster"]["uuid"] for c in data["response"]}

    @classmethod
    def tearDownClass(cls):
        for cid, cluster_uuid in list(cls.created["clusters"]):
            try:
                cls.api(key, "POST", f"galaxy_clusters/delete/{cid}/hard:1", {"hard": 1})
                cls.api(key, "POST", f"galaxy_cluster_blocklists/delete/{cluster_uuid}")
            except Exception:
                pass
        for kind, path in (("galaxies", "galaxies/delete/{}"), ("keys", "authKeys/delete/{}"), ("users", "admin/users/delete/{}"),
                           ("sgs", "sharingGroups/delete/{}"), ("roles", "admin/roles/delete/{}")):
            for item in cls.created[kind]:
                try:
                    cls.api(key, "POST", path.format(item))
                except Exception:
                    pass
        if cls.org:
            try:
                cls.api(key, "POST", f"admin/organisations/delete/{cls.org['id']}")
            except Exception:
                pass

    @classmethod
    def __make_user(cls, role_id) -> str:
        user = cls.admin_api("POST", "admin/users/add", {
            "email": f"mqg{random()}@user.local", "org_id": cls.org["id"], "role_id": role_id, "password": str(uuid.uuid4())})["User"]
        cls.created["users"].append(user["id"])
        auth_key = cls.admin_api("POST", f"authKeys/add/{user['id']}")["AuthKey"]
        cls.created["keys"].append(auth_key["id"])
        return auth_key["authkey_raw"]

    @classmethod
    def __make_galaxy(cls, name: str, distribution: int) -> dict:
        galaxy = cls.admin_api("POST", "galaxies/add", {"Galaxy": {
            "name": f"{cls.marker} galaxy {name}", "namespace": f"{cls.marker}-ns-{name}", "description": "test", "icon": "cog",
            "distribution": distribution, "enabled": True, "version": 1}})["Galaxy"]
        cls.created["galaxies"].append(galaxy["id"])
        return galaxy

    @classmethod
    def __make_cluster(cls, name, distribution, sharing_group, galaxy, token) -> int:
        cluster = {"value": cls.__value(name), "description": cls.__text("desc", name), "source": cls.__text("src", name),
                   "authors": [cls.__text("auth", name)], "distribution": distribution}
        if sharing_group:
            cluster["sharing_group_id"] = sharing_group
        status, data = cls.api(token, "POST", f"galaxy_clusters/add/{galaxy['id']}", {"GalaxyCluster": cluster})
        assert status == 200, (name, status, str(data)[:300])
        cls.created["clusters"].append((data["GalaxyCluster"]["id"], data["GalaxyCluster"]["uuid"]))
        return int(data["GalaxyCluster"]["id"])

    @classmethod
    def __value(cls, name: str) -> str:
        return f"{cls.marker}-{name}"

    @classmethod
    def __text(cls, kind: str, name: str) -> str:
        return f"{kind}-{cls.marker}-{name}"

    def __search(self, query, token=None, extra=None, method="POST"):
        """Returns (status, {cluster id: cluster} or None, raw data)."""
        body = {"returnFormat": "json", "query": query}
        body.update(extra or {})
        status, data = self.api(token or self.user_key, method, "galaxy_clusters/restSearch", body)
        clusters = None
        if status == 200 and isinstance(data, dict):
            clusters = {int(c["GalaxyCluster"]["id"]): c["GalaxyCluster"] for c in data["response"]}
        return status, clusters, data

    def __anchored(self, tree):
        return {"AND": [{"value": {"LIKE": self.marker + "%"}}, tree]}

    def __ids(self, tree, token=None, **kwargs):
        status, clusters, data = self.__search(self.__anchored(tree), token, **kwargs)
        self.assertEqual(status, 200, data)
        return set(clusters)

    def test_fixture_is_discriminating(self):
        status, clusters, _ = self.__search({"value": {"LIKE": self.marker + "%"}}, token=key)
        self.assertEqual((status, set(clusters)), (200, self.all_ids))
        status, clusters, _ = self.__search({"value": {"LIKE": self.marker + "%"}})
        self.assertEqual((status, set(clusters)), (200, self.visible))

    def test_baseline(self):
        c = self.c
        pub_sg = {c["pub"], c["sg_in"]}
        cases = {
            "id": ({"id": c["pub"]}, {c["pub"]}),
            "uuid": ({"uuid": self.uuids[c["own"]]}, {c["own"]}),
            "value": ({"value": self.__value("sg_in")}, {c["sg_in"]}),
            "value like": ({"value": {"LIKE": f"{self.marker}-p%"}}, {c["pub"]}),
            "value in another case": ({"value": self.__value("sg_in").upper()}, {c["sg_in"]}),
            "description like": ({"description": {"LIKE": f"%{self.__text('desc', 'own')}"}}, {c["own"]}),
            "source like": ({"source": {"LIKE": f"%{self.__text('src', 'pub')}"}}, {c["pub"]}),
            "authors like": ({"authors": {"LIKE": f"%{self.__text('auth', 'sg_in')}%"}}, {c["sg_in"]}),
            "distribution": (self.__anchored({"distribution": 3}), {c["pub"]}),
            "org by name in another case": (self.__anchored({"org": self.admin_org_name.upper()}), pub_sg),
            "org by uuid": (self.__anchored({"org": self.admin_org_uuid}), pub_sg),
            "org in": (self.__anchored({"org": {"IN": [self.org["name"].lower()]}}), {c["own"]}),
            "org not in": (self.__anchored({"org": {"NOT IN": [self.admin_org_name]}}), {c["own"]}),
            "org !=": (self.__anchored({"org": {"!=": self.org["name"]}}), pub_sg),
            "org_id": (self.__anchored({"org_id": int(self.org["id"])}), {c["own"]}),
            "orgc_id": (self.__anchored({"orgc_id": self.admin_org_id}), pub_sg),
            "galaxy_id": (self.__anchored({"galaxy_id": int(self.galaxy_vis["id"])}), self.visible),
            "galaxy_uuid": (self.__anchored({"galaxy_uuid": self.galaxy_vis["uuid"]}), self.visible),
            "galaxy_name": (self.__anchored({"galaxy_name": f"{self.marker} galaxy vis"}), self.visible),
            "galaxy_namespace": (self.__anchored({"galaxy_namespace": f"{self.marker}-ns-vis"}), self.visible),
            "booleans": (self.__anchored({"AND": [{"default": False}, {"deleted": False}]}), self.visible),
            "default true": (self.__anchored({"default": True}), set()),
            "NOT": (self.__anchored({"NOT": {"id": c["pub"]}}), {c["sg_in"], c["own"]}),
            "id !=": (self.__anchored({"id": {"!=": c["pub"]}}), {c["sg_in"], c["own"]}),
            "NOT IN": (self.__anchored({"id": {"NOT IN": [c["pub"], c["own"]]}}), {c["sg_in"]}),
            "hidden galaxy": (self.__anchored({"galaxy_name": f"{self.marker} galaxy hid"}), set()),
        }
        for name, (tree, expected) in cases.items():
            with self.subTest(name):
                status, clusters, data = self.__search(tree)
                self.assertEqual(status, 200, data)
                self.assertEqual(set(clusters), expected)

    def test_hidden_clusters_are_never_returned(self):
        c = self.c
        hidden = sorted(self.hidden)
        cases = {f"id {n}": {"id": c[n]} for n in ("org", "sg_out", "hg")}
        cases.update({f"uuid {n}": {"uuid": self.uuids[c[n]]} for n in ("org", "sg_out", "hg")})
        cases.update({f"value {n}": {"value": self.__value(n)} for n in ("org", "sg_out", "hg")})
        cases.update({
            "value like": {"value": {"LIKE": f"{self.marker}-%"}},
            "description": {"description": {"LIKE": f"%{self.__text('desc', 'org')}"}},
            "hidden galaxy description source": {"source": {"LIKE": f"%{self.__text('src', 'hg')}"}},
            "org of the admin": self.__anchored({"org": self.admin_org_name}),
            "orgc_id of the admin": self.__anchored({"orgc_id": self.admin_org_id}),
            "distribution": self.__anchored({"distribution": {"IN": [0, 1, 2, 3, 4, 5]}}),
            "sharing group distribution": self.__anchored({"distribution": 4}),
            "tautology": self.__anchored({"OR": [{"id": {">=": 0}}, {"NOT": {"id": {">=": 0}}}]}),
            "double negation": self.__anchored({"NOT": {"NOT": {"id": {">=": 0}}}}),
            "not the visible ids": self.__anchored({"NOT": {"id": {"IN": sorted(self.visible)}}}),
            "not in the visible ids": self.__anchored({"id": {"NOT IN": sorted(self.visible)}}),
            "or with a hidden leaf": self.__anchored({"OR": [{"id": c["org"]}, {"id": c["pub"]}]}),
            "hidden galaxy": self.__anchored({"galaxy_uuid": self.galaxy_hid["uuid"]}),
            "hidden galaxy namespace": self.__anchored({"galaxy_namespace": f"{self.marker}-ns-hid"}),
        })
        for name, tree in cases.items():
            with self.subTest(name):
                status, clusters, data = self.__search(tree)
                self.assertEqual(status, 200, data)
                self.assertEqual(set(clusters) & self.hidden, set())
        for name in ("id org", "id sg_out", "id hg", "uuid hg", "value like", "org of the admin", "tautology", "not the visible ids"):
            with self.subTest(f"admin {name}"):
                status, clusters, data = self.__search(cases[name], token=key)
                self.assertEqual(status, 200, data)
                self.assertTrue(set(clusters) & self.hidden, "fixture is not discriminating")
        tree = self.__anchored({"OR": [{"id": {">=": 0}}, {"NOT": {"id": {">=": 0}}}]})
        for extra in ({"distribution": [0, 1, 2, 3, 4]}, {"org_id": self.admin_org_id}, {"id": hidden}, {"deleted": [0, 1]},
                      {"published": [0, 1]}):
            with self.subTest(extra):
                status, clusters, _ = self.__search(tree, extra=extra)
                self.assertIn(status, (200, 400, 403))
                if status == 200:
                    self.assertEqual(set(clusters) & self.hidden, set())

    def test_query_equals_the_legacy_endpoint(self):
        status, legacy, data = self.__search_legacy()
        self.assertEqual((status, set(legacy)), (200, self.visible), data)
        galaxy_vis = int(self.galaxy_vis["id"])
        trees = {
            "distribution": ({"distribution": {"IN": [0, 3]}}, lambda c: c["distribution"] in ("0", "3")),
            "not distribution": ({"NOT": {"distribution": 3}}, lambda c: c["distribution"] != "3"),
            "org_id or value": ({"OR": [{"org_id": int(self.org["id"])}, {"value": {"LIKE": "%-sg_in"}}]},
                                lambda c: int(c["org_id"]) == int(self.org["id"]) or c["value"].endswith("-sg_in")),
            "galaxy and text": ({"AND": [{"galaxy_id": galaxy_vis}, {"description": {"LIKE": "desc-%"}}]},
                                lambda c: int(c["galaxy_id"]) == galaxy_vis and c["description"].startswith("desc-")),
            "everything": ({"id": {">=": 0}}, lambda c: True),
            "nothing": ({"NOT": {"id": {">=": 0}}}, lambda c: False),
        }
        for name, (tree, condition) in trees.items():
            with self.subTest(name):
                status, clusters, data = self.__search(self.__anchored(tree))
                self.assertEqual(status, 200, data)
                self.assertEqual(set(clusters), {i for i, c in legacy.items() if condition(c)})

    def __search_legacy(self, extra=None, token=None):
        body = {"returnFormat": "json", "value": self.marker + "%", **(extra or {})}
        status, data = self.api(token or self.user_key, "POST", "galaxy_clusters/restSearch", body)
        clusters = None
        if status == 200:
            clusters = {int(c["GalaxyCluster"]["id"]): c["GalaxyCluster"] for c in data["response"]}
        return status, clusters, data

    def test_count(self):
        trees = {"marker": {"value": {"LIKE": self.marker + "%"}}, "distribution": self.__anchored({"distribution": {"IN": [0, 3]}}),
                 "org": self.__anchored({"org": self.admin_org_name}), "galaxy": self.__anchored({"galaxy_name": f"{self.marker} galaxy hid"})}
        for token in (self.user_key, key):
            for name, tree in trees.items():
                with self.subTest(f"{name} {token[:4]}"):
                    status, clusters, data = self.__search(tree, token)
                    self.assertEqual(status, 200, data)
                    status, count = self.api(token, "POST", "galaxy_clusters/restSearch", {"returnFormat": "count", "query": tree})
                    self.assertEqual((status, int(count)), (200, len(clusters)))
        status, count = self.api(self.user_key, "POST", "galaxy_clusters/restSearch", {
            "returnFormat": "count", "query": self.__anchored({"id": {"IN": sorted(self.hidden)}})})
        self.assertEqual((status, int(count)), (200, 0))
        status, count = self.api(key, "POST", "galaxy_clusters/restSearch", {
            "returnFormat": "count", "query": self.__anchored({"id": {"IN": sorted(self.hidden)}})})
        self.assertEqual((status, int(count)), (200, len(self.hidden)))
        status, count = self.api(self.user_key, "POST", "galaxy_clusters/restSearch", {"returnFormat": "count", "value": self.marker + "%"})
        self.assertEqual((status, int(count)), (200, len(self.visible)))

    def test_order(self):
        def order_of(extra, query=None):
            body = {"returnFormat": "json", "order": extra}
            body.update({"query": query} if query else {"value": self.marker + "%"})
            status, data = self.api(self.user_key, "POST", "galaxy_clusters/restSearch", body)
            self.assertEqual(status, 200, data)
            return [int(c["GalaxyCluster"]["id"]) for c in data["response"]]
        marker_query = {"value": {"LIKE": self.marker + "%"}}
        for query in (None, marker_query):
            with self.subTest(str(query)):
                asc, desc = order_of("value asc", query), order_of("value desc", query)
                self.assertEqual(set(asc), self.visible)
                self.assertEqual(asc, desc[::-1])
        self.assertEqual(order_of("id", marker_query), sorted(self.visible))
        for order in ("0.id", "event_id", "sharing_group_id"):
            with self.subTest(order):
                status, clusters, data = self.__search(marker_query, extra={"order": order})
                self.assertEqual((status, clusters), (400, None), data)
                self.assertNotIn("response", data)
                self.assertEqual(data["errors"][0]["path"], "order[0]")
                status, _, data = self.__search_legacy({"order": order})
                self.assertEqual(status, 200, data)

    def test_rejections(self):
        rejected = {
            "sharing_group_id": ({"sharing_group_id": 1}, "unknown_field"),
            "org like": ({"org": {"LIKE": "a%"}}, "unknown_operator"),
            "uuid like": ({"uuid": {"LIKE": "a%"}}, "unknown_operator"),
        }
        for name, (tree, code) in rejected.items():
            with self.subTest(name):
                status, clusters, data = self.__search(tree)
                self.assertEqual((status, clusters), (400, None), data)
                self.assertNotIn("response", data)
                self.assertEqual(data["errors"][0]["code"], code)
        bad = {
            "string": "id=1", "list": [{"id": 1}], "empty": {}, "unknown field": {"nope": 1}, "wrong type": {"id": "1"},
            "two keys": {"id": 1, "uuid": "x"},
            "too deep": {"NOT": {"NOT": {"NOT": {"NOT": {"NOT": {"NOT": {"id": 1}}}}}}},
        }
        for name, tree in bad.items():
            with self.subTest(name):
                status, clusters, data = self.__search(tree)
                self.assertEqual((status, clusters), (400, None), data)
                self.assertNotIn("response", data)

    def test_query_is_only_accepted_in_a_post_body(self):
        status, data = self.api(self.user_key, "GET", f"galaxy_clusters/restSearch?returnFormat=json&query[id]={self.c['pub']}")
        self.assertEqual(status, 400)
        self.assertNotIn("response", data or {})
        status, data = self.api(self.user_key, "GET", "galaxy_clusters/restSearch", {"returnFormat": "json", "query": {"id": self.c["pub"]}})
        self.assertEqual(status, 400)
        self.assertNotIn("response", data or {})
        for path in (f"galaxy_clusters/restSearch?query[id]={self.c['org']}", "galaxy_clusters/restSearch/query:x"):
            with self.subTest(path):
                status, data = self.api(self.user_key, "POST", path, {"returnFormat": "json", "query": {"id": self.c["pub"]}})
                self.assertEqual(status, 400)
                self.assertNotIn("response", data or {})

    def test_permission_flag(self):
        for token in (self.plain_user_key, "x" * 40):
            with self.subTest(token[:4]):
                status, clusters, _ = self.__search({"id": self.c["pub"]}, token=token)
                self.assertEqual((status, clusters), (403, None))
                self.assertEqual(self.api(token, "GET", "galaxy_clusters/queryDescribe")[0], 403)
        status, data = self.api(self.user_key, "GET", "galaxy_clusters/queryDescribe")
        self.assertEqual(status, 200)
        table = data["tables"]["galaxy_clusters"]
        self.assertEqual(table["endpoint"], "/galaxy_clusters/restSearch")
        self.assertNotIn("sharing_group_id", table["fields"])
        status, clusters, data = self.__search({"value": {"LIKE": self.marker + "%"}}, token=self.site_admin_key)
        self.assertEqual((status, set(clusters)), (200, self.all_ids), data)
        self.assertEqual(self.api(self.site_admin_key, "GET", "galaxy_clusters/queryDescribe")[0], 200)


if __name__ == '__main__':
    unittest.main()
