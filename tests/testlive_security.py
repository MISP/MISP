#!/usr/bin/env python3
import os
import re
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
import hashlib
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
        cls.meta_key = f"{cls.marker} note.x"
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
                   "authors": [cls.__text("auth", name)], "distribution": distribution,
                   "GalaxyElement": [{"key": "synonyms", "value": cls.__text("syn", name)}, {"key": cls.meta_key, "value": name}]}
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
            "meta": ({"meta.synonyms": self.__text("syn", "pub")}, {c["pub"]}),
            "meta like, key in another case": ({"meta.SYNONYMS": {"LIKE": f"%{self.__text('syn', 'own').upper()}"}}, {c["own"]}),
            "meta key with spaces and dots": (self.__anchored({f"meta.{self.meta_key}": "sg_in"}), {c["sg_in"]}),
            "meta in": (self.__anchored({f"meta.{self.meta_key}": {"IN": ["pub", "own"]}}), {c["pub"], c["own"]}),
            "meta !=": (self.__anchored({"meta.synonyms": {"!=": self.__text("syn", "pub")}}), {c["sg_in"], c["own"]}),
            "meta not like": (self.__anchored({f"meta.{self.meta_key}": {"NOT LIKE": "s%"}}), {c["pub"], c["own"]}),
            "meta unknown key": (self.__anchored({f"meta.{self.marker} nosuch": "pub"}), set()),
            "meta unknown key negated": (self.__anchored({f"meta.{self.marker} nosuch": {"!=": "pub"}}), self.visible),
        }
        for name, (tree, expected) in cases.items():
            with self.subTest(name):
                status, clusters, data = self.__search(tree)
                self.assertEqual(status, 200, data)
                self.assertEqual(set(clusters), expected)

    def test_misp_is_also_the_built_in_organisation(self):
        def count(tree):
            status, data = self.api(self.user_key, "POST", "galaxy_clusters/restSearch", {"returnFormat": "count", "query": tree})
            self.assertEqual(status, 200, data)
            return data
        # MISP's own clusters have creator 0, which has no organisation row
        threat_actor = {"galaxy_name": "Threat Actor"}
        built_in = count({"AND": [threat_actor, {"orgc_id": 0}]})
        self.assertGreater(built_in, 0, "no default Threat Actor clusters on this instance")
        self.assertEqual(count({"AND": [threat_actor, {"org": "misp"}]}), built_in)
        self.assertEqual(count({"AND": [threat_actor, {"org": {"IN": [self.org["name"], "MISP"]}}]}), built_in)
        self.assertEqual(count({"AND": [threat_actor, {"org": {"!=": "MISP"}}]}), count(threat_actor) - built_in)
        self.assertEqual(self.__ids({"org": "MISP"}), set())
        self.assertEqual(self.__ids({"org": {"NOT IN": ["MISP"]}}), self.visible)

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
            "meta like": {"meta.synonyms": {"LIKE": f"syn-{self.marker}-%"}},
            "meta key like": self.__anchored({f"meta.{self.meta_key}": {"LIKE": "s%"}}),
            "not meta of the visible": self.__anchored(
                {"NOT": {"meta.synonyms": {"IN": [self.__text("syn", n) for n in ("pub", "sg_in", "own")]}}}),
        })
        cases.update({f"meta {n}": {"meta.synonyms": self.__text("syn", n)} for n in ("org", "sg_out", "hg")})
        for name, tree in cases.items():
            with self.subTest(name):
                status, clusters, data = self.__search(tree)
                self.assertEqual(status, 200, data)
                self.assertEqual(set(clusters) & self.hidden, set())
        for name in ("id org", "id sg_out", "id hg", "uuid hg", "value like", "org of the admin", "tautology", "not the visible ids",
                     "meta org", "meta hg", "meta like", "meta key like", "not meta of the visible"):
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
            "meta": ({"meta.synonyms": {"LIKE": "%-sg_in"}},
                     lambda c: any(e["key"] == "synonyms" and e["value"].endswith("-sg_in") for e in c["GalaxyElement"])),
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
                 "org": self.__anchored({"org": self.admin_org_name}), "galaxy": self.__anchored({"galaxy_name": f"{self.marker} galaxy hid"}),
                 "meta": {"meta.synonyms": {"LIKE": f"syn-{self.marker}-%"}}}
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
            "meta operator": ({"meta.synonyms": {">": "a"}}, "unknown_operator"),
            "meta without a key": ({"meta.": "a"}, "unknown_field"),
        }
        for name, (tree, code) in rejected.items():
            with self.subTest(name):
                status, clusters, data = self.__search(tree)
                self.assertEqual((status, clusters), (400, None), data)
                self.assertNotIn("response", data)
                self.assertEqual(data["errors"][0]["code"], code)
                if name.startswith("meta"):
                    self.assertIn(data["errors"][0]["path"], ("query.<unknown>", "query.meta.<key>"))
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


class TestComplexEventReportQueryAcl(unittest.TestCase):
    """The `query` tree of /event_reports/restSearch must only narrow what /event_reports/index shows the user."""

    api = staticmethod(TestComplexQueryAcl.api)
    admin_api = staticmethod(TestComplexQueryAcl.admin_api)

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        admin = PyMISP(url, key)
        check_response(admin.set_server_setting('Security.advanced_authkeys', True, force=True))
        cls.marker = "mqr" + random()
        cls.created = {"events": [], "tags": set(), "users": [], "roles": [], "sgs": [], "keys": []}
        cls.org = None
        try:
            cls.__build_fixture()
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def __build_fixture(cls):
        cls.org = cls.admin_api("POST", "admin/organisations/add", {"name": "MQR Org " + random(), "local": True})["Organisation"]
        me = cls.admin_api("GET", "users/view/me")
        admin_org_uuid = me["Organisation"]["uuid"]
        cls.admin_org_id, cls.admin_sync = int(me["Organisation"]["id"]), bool(int(me["Role"]["perm_sync"]))
        roles = {
            "flagged": {"permission": "1", "perm_add": 1, "perm_auth": 1, "perm_complex_query": 1},
            "plain": {"permission": "0", "perm_auth": 1},
            "site_admin": {"permission": "3", "perm_auth": 1, "perm_site_admin": 1, "perm_complex_query": 0},
        }
        keys = {}
        for name, perms in roles.items():
            role = cls.admin_api("POST", "admin/roles/add", {"Role": {"name": f"MQR {name} {random()}", **perms}})["Role"]
            cls.created["roles"].append(role["id"])
            keys[name] = cls.__make_user(role["id"])
        cls.user_key, cls.plain_user_key, cls.site_admin_key = keys["flagged"], keys["plain"], keys["site_admin"]

        def sharing_group(label, members):
            sg = cls.admin_api("POST", "sharingGroups/add", {
                "SharingGroup": {"name": f"MQR SG {label} {random()}", "releasability": "test", "description": "test", "active": 1,
                                 "organisation_uuid": admin_org_uuid, "roaming": 0},
                "Organisation": [{"uuid": admin_org_uuid, "extend": True}]})["SharingGroup"]["id"]
            cls.created["sgs"].append(sg)
            for org_id in members:
                cls.api(key, "POST", f"sharingGroups/addOrg/{sg}/{org_id}", {"extend": 0})
            return sg
        cls.sg_out = sharing_group("out", [])
        cls.sg_in = sharing_group("in", [cls.org["id"]])

        cls.tag_rep, cls.tag_evt = (f"{cls.marker}:{t}" for t in ("rep", "evt"))
        tag_ids = {}
        for tag in (cls.tag_rep, cls.tag_evt):
            tag_ids[tag] = cls.admin_api("POST", "tags/add", {"name": tag, "colour": "#123456"})["Tag"]["id"]
            cls.created["tags"].add(tag_ids[tag])

        # events (distribution, sharing group, token, tag); "own" belongs to the test org, the others to the admin org
        cls.events = {
            "own": cls.__make_event("own", 0, None, cls.user_key),
            "b1": cls.__make_event("b1", 1, None, key, cls.tag_evt),
            "b0": cls.__make_event("b0", 0, None, key),
            "bsg": cls.__make_event("bsg", 4, cls.sg_out, key),
        }
        # (event, distribution, sharing group, deleted, tag, visible to the flagged user)
        specs = {
            "own_0": ("own", 0, None, False, None, True), "own_5": ("own", 5, None, False, None, True),
            "own_sgout": ("own", 4, cls.sg_out, False, None, True), "own_del": ("own", 5, None, True, None, True),
            "b1_0": ("b1", 0, None, False, cls.tag_rep, False), "b1_1": ("b1", 1, None, False, cls.tag_rep, True),
            "b1_5": ("b1", 5, None, False, None, True), "b1_sgin": ("b1", 4, cls.sg_in, False, None, True),
            "b1_sgout": ("b1", 4, cls.sg_out, False, None, False), "b1_del": ("b1", 1, None, True, None, False),
            "b0_1": ("b0", 1, None, False, None, False), "bsg_5": ("bsg", 5, None, False, None, False),
        }
        cls.reports = {}
        for name, (event, distribution, sg, deleted, tag, visible) in specs.items():
            report = {"name": f"{cls.marker} {name}", "content": f"content {cls.marker} {name}", "distribution": distribution}
            if sg:
                report["sharing_group_id"] = sg
            status, data = cls.api(key, "POST", f"event_reports/add/{cls.events[event]}", report)
            assert status == 200, (name, status, str(data)[:300])
            report_id = int(data["EventReport"]["id"])
            if tag:
                status, data = cls.api(key, "POST", f"event_reports/addTag/{report_id}/{tag_ids[tag]}")
                assert status == 200 and data.get("saved"), (name, status, data)
            if deleted:
                status, data = cls.api(key, "POST", f"event_reports/delete/{report_id}")
                assert status == 200, (name, status, data)
            cls.reports[name] = {"id": report_id, "name": report["name"], "event": event, "distribution": distribution, "deleted": deleted,
                                 "tags": {tag} if tag else set(), "visible": visible}
        cls.event_ids = sorted(cls.events.values())
        cls.by_id = {r["id"]: r for r in cls.reports.values()}

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
            "email": f"mqr{random()}@user.local", "org_id": cls.org["id"], "role_id": role_id, "password": str(uuid.uuid4())})["User"]
        cls.created["users"].append(user["id"])
        auth_key = cls.admin_api("POST", f"authKeys/add/{user['id']}")["AuthKey"]
        cls.created["keys"].append(auth_key["id"])
        return auth_key["authkey_raw"]

    @classmethod
    def __make_event(cls, name: str, distribution: int, sharing_group, token: str, tag=None) -> int:
        event = {"info": f"{cls.marker} ev-{name}", "distribution": distribution, "threat_level_id": 4, "analysis": 0}
        if sharing_group:
            event["sharing_group_id"] = sharing_group
        if tag:
            event["Tag"] = [{"name": tag}]
        status, data = cls.api(token, "POST", "events/add", {"Event": event})
        assert status == 200, (name, status, str(data)[:300])
        cls.created["events"].append(data["Event"]["id"])
        return int(data["Event"]["id"])

    def __anchored(self, tree=None):
        anchor = {"event_id": {"IN": self.event_ids}}
        return anchor if tree is None else {"AND": [anchor, tree]}

    def __search(self, tree, token=None, extra=None, method="POST", anchored=True):
        """Returns (status, [report] or None, raw data)."""
        body = {"returnFormat": "json", "limit": 1000, "query": self.__anchored(tree) if anchored else tree}
        body.update(extra or {})
        status, data = self.api(token or self.user_key, method, "event_reports/restSearch", body)
        reports = None
        if status == 200 and isinstance(data, dict):
            reports = [r["EventReport"] for r in data["response"]]
        return status, reports, data

    def __ids(self, tree, token=None, **kwargs):
        status, reports, data = self.__search(tree, token, **kwargs)
        self.assertEqual(status, 200, data)
        return {int(r["id"]) for r in reports}

    def __index(self, deleted: bool):
        status, data = self.api(self.user_key, "GET", "event_reports/index" + ("/context:all" if deleted else ""))
        self.assertEqual(status, 200, data)
        rows = {}
        for row in data:
            report = row["EventReport"]
            if int(report["id"]) in self.by_id:
                rows[int(report["id"])] = report
        return rows

    def __admin_sees(self, report) -> bool:
        return not report["deleted"] or self.admin_sync or report["event"] != "own"

    def __cases(self):
        """(label, tree, predicate on a fixture report, whether the tree names `deleted`)"""
        def tags(report):
            return report["tags"] | ({self.tag_evt} if report["event"] == "b1" else set())
        return {
            "no query": (None, lambda r: True, False),
            "name like": ({"name": {"LIKE": f"%{self.marker}%"}}, lambda r: True, False),
            "distribution in": ({"distribution": {"IN": [0, 4]}}, lambda r: r["distribution"] in (0, 4), False),
            "report tag": ({"tags": self.tag_rep}, lambda r: self.tag_rep in tags(r), False),
            "report tag negated": ({"tags": {"!=": self.tag_rep}}, lambda r: self.tag_rep not in tags(r), False),
            "event tag": ({"tags": self.tag_evt}, lambda r: self.tag_evt in tags(r), False),
            "eventinfo like": ({"eventinfo": {"LIKE": "%ev-b1"}}, lambda r: r["event"] == "b1", False),
            "deleted": ({"deleted": True}, lambda r: r["deleted"], True),
        }

    def test_fixture_is_discriminating(self):
        visible = {r["id"] for r in self.reports.values() if r["visible"]}
        self.assertEqual(self.__ids(None), visible - {r["id"] for r in self.reports.values() if r["deleted"]})
        everything = {r["id"] for r in self.reports.values() if self.__admin_sees(r) and not r["deleted"]}
        self.assertEqual(self.__ids(None, token=key), everything)
        self.assertEqual(len(everything - self.__ids(None)), 4)

    def test_query_equals_the_index_and_the_matrix(self):
        index = {False: self.__index(False), True: self.__index(True)}
        for label, (tree, predicate, names_deleted) in self.__cases().items():
            with self.subTest(label):
                shown = {r["id"] for r in self.reports.values() if r["visible"] and predicate(r) and (names_deleted or not r["deleted"])}
                self.assertEqual(self.__ids(tree), shown)
                admin_shown = {r["id"] for r in self.reports.values()
                               if self.__admin_sees(r) and predicate(r) and (names_deleted or not r["deleted"])}
                self.assertEqual(self.__ids(tree, token=key), admin_shown)
                self.assertTrue(admin_shown - shown, "fixture is not discriminating")
                legacy = index[names_deleted]
                self.assertEqual({i for i, r in legacy.items() if predicate(self.by_id[i]) and (names_deleted or not self.by_id[i]["deleted"])},
                                 shown)

    def test_count(self):
        for token in (self.user_key, key):
            for label, (tree, _, _) in self.__cases().items():
                with self.subTest(f"{label} {token[:4]}"):
                    ids = self.__ids(tree, token=token)
                    status, count = self.api(token, "POST", "event_reports/restSearch", {
                        "returnFormat": "count", "query": self.__anchored(tree)})
                    self.assertEqual((status, int(count)), (200, len(ids)))

    def test_hidden_reports_tags_never_match(self):
        hidden_tagged = self.reports["b1_0"]["id"]
        visible_tagged = self.reports["b1_1"]["id"]
        self.assertEqual(self.__ids({"tags": self.tag_rep}), {visible_tagged})
        self.assertEqual(self.__ids({"tags": self.tag_rep}, token=key), {visible_tagged, hidden_tagged})
        self.assertNotIn(hidden_tagged, self.__ids({"tags": {"LIKE": f"{self.marker}:%"}}))
        self.assertNotIn(hidden_tagged, self.__ids({"tags": {"!=": self.tag_evt}}))
        self.assertNotIn(self.reports["b1_del"]["id"], self.__ids({"AND": [{"deleted": True}, {"tags": self.tag_evt}]}))
        self.assertIn(self.reports["b1_del"]["id"], self.__ids({"AND": [{"deleted": True}, {"tags": self.tag_evt}]}, token=key))

    def test_permission_flag(self):
        for token in (self.plain_user_key, "x" * 40):
            with self.subTest(token[:4]):
                status, reports, _ = self.__search({"id": self.reports["b1_1"]["id"]}, token=token)
                self.assertEqual((status, reports), (403, None))
                status, data = self.api(token, "POST", "event_reports/restSearch", {"returnFormat": "json"})
                self.assertEqual(status, 403, data)
                self.assertEqual(self.api(token, "GET", "event_reports/queryDescribe")[0], 403)
        status, data = self.api(self.user_key, "GET", "event_reports/queryDescribe")
        self.assertEqual(status, 200)
        self.assertEqual(data["tables"]["event_reports"]["endpoint"], "/event_reports/restSearch")
        self.assertNotIn("sharing_group_id", data["tables"]["event_reports"]["fields"])
        everything = {r["id"] for r in self.reports.values() if self.__admin_sees(r) and not r["deleted"]}
        self.assertEqual(self.__ids(None, token=self.site_admin_key), everything)
        self.assertEqual(self.api(self.site_admin_key, "GET", "event_reports/queryDescribe")[0], 200)

    def test_rejections(self):
        for order in ("content", "Event.info", "sharing_group_id"):
            for query in (True, False):
                with self.subTest(f"{order} {query}"):
                    body = {"returnFormat": "json", "order": order}
                    if query:
                        body["query"] = self.__anchored()
                    status, data = self.api(self.user_key, "POST", "event_reports/restSearch", body)
                    self.assertEqual(status, 400, data)
                    self.assertNotIn("response", data)
                    self.assertEqual(data["errors"][0]["path"], "order[0]")
        status, reports, data = self.__search({"sharing_group_id": 1})
        self.assertEqual((status, reports), (400, None), data)
        self.assertEqual(data["errors"][0]["code"], "unknown_field")
        id_ = self.reports["b1_1"]["id"]
        status, data = self.api(self.user_key, "GET", f"event_reports/restSearch?returnFormat=json&query[id]={id_}")
        self.assertEqual(status, 400)
        self.assertNotIn("response", data or {})
        status, data = self.api(self.user_key, "GET", "event_reports/restSearch", {"returnFormat": "json", "query": {"id": id_}})
        self.assertEqual(status, 400)
        self.assertNotIn("response", data or {})

    def test_paging(self):
        for token, expected in ((self.user_key, {r["name"] for r in self.reports.values() if r["visible"] and not r["deleted"]}),
                                (key, {r["name"] for r in self.reports.values() if self.__admin_sees(r) and not r["deleted"]})):
            with self.subTest(token[:4]):
                status, reports, data = self.__search(None, token, extra={"order": "name desc"})
                self.assertEqual(status, 200, data)
                names = [r["name"] for r in reports]
                self.assertEqual(names, sorted(expected, reverse=True))
                paged = []
                for page in range(1, 6):
                    status, reports, data = self.__search(None, token, extra={"order": "name desc", "limit": 4, "page": page})
                    self.assertEqual(status, 200, data)
                    self.assertLessEqual(len(reports), 4)
                    paged += [r["name"] for r in reports]
                self.assertEqual(paged, names)


class TestComplexAnalystDataQueryAcl(unittest.TestCase):
    """The `query` tree of /analyst_data/restSearch must only narrow what /analyst_data/index shows the user."""

    api = staticmethod(TestComplexQueryAcl.api)
    admin_api = staticmethod(TestComplexQueryAcl.admin_api)
    TYPES = {"Note": ("notes", "note"), "Opinion": ("opinions", "comment"), "Relationship": ("relationships", "relationship_type")}

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        admin = PyMISP(url, key)
        check_response(admin.set_server_setting('Security.advanced_authkeys', True, force=True))
        cls.marker = "mqd" + random()
        cls.created = {"records": [], "events": [], "users": [], "roles": [], "sgs": [], "keys": []}
        cls.org = None
        try:
            cls.__build_fixture()
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def __build_fixture(cls):
        cls.org = cls.admin_api("POST", "admin/organisations/add", {"name": "MQD Org " + random(), "local": True})["Organisation"]
        me = cls.admin_api("GET", "users/view/me")
        admin_org_uuid = me["Organisation"]["uuid"]
        cls.admin_org_name = me["Organisation"]["name"]
        roles = {
            "flagged": {"permission": "1", "perm_add": 1, "perm_auth": 1, "perm_complex_query": 1, "perm_analyst_data": 1},
            "plain": {"permission": "0", "perm_auth": 1},
            "site_admin": {"permission": "3", "perm_auth": 1, "perm_site_admin": 1, "perm_complex_query": 0},
        }
        keys = {}
        for name, perms in roles.items():
            role = cls.admin_api("POST", "admin/roles/add", {"Role": {"name": f"MQD {name} {random()}", **perms}})["Role"]
            cls.created["roles"].append(role["id"])
            keys[name] = cls.__make_user(role["id"])
        cls.user_key, cls.plain_user_key, cls.site_admin_key = keys["flagged"], keys["plain"], keys["site_admin"]

        def sharing_group(label, members):
            sg = cls.admin_api("POST", "sharingGroups/add", {
                "SharingGroup": {"name": f"MQD SG {label} {random()}", "releasability": "test", "description": "test", "active": 1,
                                 "organisation_uuid": admin_org_uuid, "roaming": 0},
                "Organisation": [{"uuid": admin_org_uuid, "extend": True}]})["SharingGroup"]["id"]
            cls.created["sgs"].append(sg)
            for org_id in members:
                cls.api(key, "POST", f"sharingGroups/addOrg/{sg}/{org_id}", {"extend": 0})
            return sg
        cls.sg_out = sharing_group("out", [cls.org["id"]])  # membership is needed to add; removed below
        cls.sg_in = sharing_group("in", [cls.org["id"]])

        # `hidden` is the anchor target; a relationship cannot point at its own target, so it points at `hidden2` instead
        cls.hidden, cls.hidden2, cls.visible = (cls.__make_event(n, d) for n, d in (("hidden", 0), ("hidden2", 0), ("visible", 1)))
        # (holder, distribution, sharing group, visible to the flagged user, relationship target)
        specs = {
            "own_0": ("own", 0, None, True, cls.hidden2), "own_sgout": ("own", 4, cls.sg_out, True, cls.visible),
            "b_0": ("b", 0, None, False, cls.hidden2), "b_1": ("b", 1, None, True, cls.visible),
            "b_2": ("b", 2, None, True, cls.hidden2), "b_3": ("b", 3, None, True, cls.visible),
            "b_sgin": ("b", 4, cls.sg_in, True, cls.visible), "b_sgout": ("b", 4, cls.sg_out, False, cls.hidden2),
        }
        cls.records = {ty: {} for ty in cls.TYPES}
        for ty, (_, text_field) in cls.TYPES.items():
            for n, (name, (holder, distribution, sg, visible, target)) in enumerate(specs.items()):
                body = {"object_uuid": cls.hidden["uuid"], "object_type": "Event", "distribution": distribution,
                        text_field: f"{cls.marker} {name}"}
                if sg:
                    body["sharing_group_id"] = sg
                if ty == "Note":
                    body["language"] = "fr" if name == "b_3" else "en"
                elif ty == "Opinion":
                    body["opinion"] = n * 10
                else:
                    body.update({"related_object_type": "Event", "related_object_uuid": target["uuid"]})
                status, data = cls.api(cls.user_key if holder == "own" else key, "POST", f"analyst_data/add/{ty}", body)
                assert status == 200, (ty, name, status, str(data)[:300])
                record = data[ty]
                cls.created["records"].append((ty, record["id"]))
                if holder == "own":
                    assert record["org_uuid"] == cls.org["uuid"], record
                cls.records[ty][name] = {"id": int(record["id"]), "name": name, "holder": holder, "distribution": distribution,
                                         "sg": sg, "visible": visible, "target": target, "text": body[text_field],
                                         "language": body.get("language"), "opinion": body.get("opinion")}
        status, data = cls.api(key, "POST", f"sharingGroups/removeOrg/{cls.sg_out}/{cls.org['id']}")
        assert status == 200, (status, data)
        cls.by_id = {ty: {r["id"]: r for r in recs.values()} for ty, recs in cls.records.items()}

    @classmethod
    def tearDownClass(cls):
        for ty, record_id in cls.created["records"]:
            try:
                cls.api(key, "POST", f"analyst_data/delete/{ty}/{record_id}")
            except Exception:
                pass
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
            "email": f"mqd{random()}@user.local", "org_id": cls.org["id"], "role_id": role_id, "password": str(uuid.uuid4())})["User"]
        cls.created["users"].append(user["id"])
        auth_key = cls.admin_api("POST", f"authKeys/add/{user['id']}")["AuthKey"]
        cls.created["keys"].append(auth_key["id"])
        return auth_key["authkey_raw"]

    @classmethod
    def __make_event(cls, name: str, distribution: int) -> dict:
        event = {"info": f"{cls.marker} ev-{name}", "distribution": distribution, "threat_level_id": 4, "analysis": 0}
        data = cls.admin_api("POST", "events/add", {"Event": event})
        cls.created["events"].append(data["Event"]["id"])
        return {"id": int(data["Event"]["id"]), "uuid": data["Event"]["uuid"]}

    def __anchored(self, tree=None):
        anchor = {"object_uuid": self.hidden["uuid"]}
        return anchor if tree is None else {"AND": [anchor, tree]}

    def __search(self, ty, tree, token=None, extra=None, method="POST", anchored=True):
        """Returns (status, [row] or None, raw data)."""
        body = {"returnFormat": "json", "limit": 1000, "query": self.__anchored(tree) if anchored else tree}
        body.update(extra or {})
        status, data = self.api(token or self.user_key, method, f"analyst_data/restSearch/{ty}", body)
        rows = None
        if status == 200 and isinstance(data, dict):
            rows = [r[ty] for r in data["response"]]
        return status, rows, data

    def __ids(self, ty, tree, token=None, **kwargs):
        status, rows, data = self.__search(ty, tree, token, **kwargs)
        self.assertEqual(status, 200, data)
        return {int(r["id"]) for r in rows}

    def __index(self, ty, token):
        status, data = self.api(token, "GET", f"analyst_data/index/{ty}/limit:1000")
        self.assertEqual(status, 200, data)
        return {int(row[ty]["id"]): row[ty] for row in data if int(row[ty]["id"]) in self.by_id[ty]}

    def __cases(self, ty):
        """(tree, predicate on a fixture record)"""
        field = self.TYPES[ty][1]
        holder_org = {"own": self.org["name"], "b": self.admin_org_name}
        cases = {
            "no query": (None, lambda r: True),
            "distribution in": ({"distribution": {"IN": [0, 4]}}, lambda r: r["distribution"] in (0, 4)),
            "org upper": ({"org": self.org["name"].upper()}, lambda r: r["holder"] == "own"),
            "org admin": ({"org": self.admin_org_name}, lambda r: r["holder"] == "b"),
            "not text like": ({"NOT": {field: {"LIKE": "%b_1"}}}, lambda r: r["name"] != "b_1"),
            "modified recent": ({"modified": {">": "1d"}}, lambda r: True),
        }
        if ty == "Note":
            cases["language"] = ({"language": {"!=": "en"}}, lambda r: r["language"] != "en")
        elif ty == "Opinion":
            cases["opinion"] = ({"opinion": {">=": 40}}, lambda r: r["opinion"] >= 40)
        else:
            cases["related"] = ({"related_object_uuid": self.visible["uuid"]}, lambda r: r["target"] == self.visible)
        return cases

    def test_fixture_is_discriminating(self):
        for ty, recs in self.records.items():
            with self.subTest(ty):
                visible = {r["id"] for r in recs.values() if r["visible"]}
                self.assertEqual(self.__ids(ty, None), visible)
                self.assertEqual(self.__ids(ty, None, token=key), {r["id"] for r in recs.values()})
                self.assertEqual(len(recs) - len(visible), 2)

    def test_query_equals_the_index_and_the_matrix(self):
        for ty, recs in self.records.items():
            for label, (tree, predicate) in self.__cases(ty).items():
                with self.subTest(f"{ty} {label}"):
                    shown = {r["id"] for r in recs.values() if r["visible"] and predicate(r)}
                    self.assertEqual(self.__ids(ty, tree), shown)
                    admin_shown = {r["id"] for r in recs.values() if predicate(r)}
                    self.assertEqual(self.__ids(ty, tree, token=key), admin_shown)
                    if label in ("no query", "distribution in", "org admin", "not text like", "modified recent"):
                        self.assertTrue(admin_shown - shown, "fixture is not discriminating")
                    index = self.__index(ty, self.user_key)
                    self.assertEqual({i for i in index if predicate(self.by_id[ty][i])}, shown)

    def test_rows_equal_the_index_rows(self):
        for ty, recs in self.records.items():
            for token in (self.user_key, key):
                with self.subTest(f"{ty} {token[:4]}"):
                    status, rows, data = self.__search(ty, None, token)
                    self.assertEqual(status, 200, data)
                    index = self.__index(ty, token)
                    self.assertEqual({int(r["id"]): r for r in rows}, index)
                    self.assertEqual(len(index), 8 if token == key else 6)

    def test_row_details(self):
        for ty, recs in self.records.items():
            with self.subTest(ty):
                user_rows = {r["id"]: r for r in self.__search(ty, None)[1]}
                admin_rows = {r["id"]: r for r in self.__search(ty, None, key)[1]}
                own_sgout, b_sgin = str(recs["own_sgout"]["id"]), str(recs["b_sgin"]["id"])
                self.assertNotIn("SharingGroup", user_rows[own_sgout])
                self.assertEqual(int(user_rows[b_sgin]["SharingGroup"]["id"]), int(self.sg_in))
                self.assertIn("SharingGroup", admin_rows[own_sgout])
                self.assertEqual(user_rows[str(recs["own_0"]["id"])]["Orgc"]["name"], self.org["name"])
                if ty == "Relationship":
                    for name in ("own_0", "b_2"):
                        self.assertEqual(user_rows[str(recs[name]["id"])]["related_object"], [])
                        self.assertTrue(admin_rows[str(recs[name]["id"])]["related_object"])

    def test_count(self):
        for ty in self.records:
            for token in (self.user_key, key):
                for label, (tree, _) in self.__cases(ty).items():
                    with self.subTest(f"{ty} {label} {token[:4]}"):
                        ids = self.__ids(ty, tree, token=token)
                        status, count = self.api(token, "POST", f"analyst_data/restSearch/{ty}", {
                            "returnFormat": "count", "query": self.__anchored(tree)})
                        self.assertEqual((status, int(count)), (200, len(ids)))

    def test_permission_flag(self):
        for ty, (table, _) in self.TYPES.items():
            for token in (self.plain_user_key, "x" * 40):
                with self.subTest(f"{ty} {token[:4]}"):
                    status, rows, _ = self.__search(ty, None, token=token)
                    self.assertEqual((status, rows), (403, None))
                    status, data = self.api(token, "POST", f"analyst_data/restSearch/{ty}", {"returnFormat": "json"})
                    self.assertEqual(status, 403, data)
                    self.assertEqual(self.api(token, "GET", f"analyst_data/queryDescribe/{ty}")[0], 403)
            with self.subTest(ty):
                status, data = self.api(self.user_key, "GET", f"analyst_data/queryDescribe/{ty}")
                self.assertEqual(status, 200)
                self.assertEqual(data["tables"][table]["endpoint"], f"/analyst_data/restSearch/{ty}")
                for hidden_field in ("sharing_group_id", "content", "node_count"):
                    self.assertNotIn(hidden_field, data["tables"][table]["fields"])
                self.assertEqual(self.__ids(ty, None, token=self.site_admin_key), {r["id"] for r in self.records[ty].values()})
                self.assertEqual(self.api(self.site_admin_key, "GET", f"analyst_data/queryDescribe/{ty}")[0], 200)

    def test_rejections(self):
        self.assertEqual(self.api(self.user_key, "POST", "analyst_data/restSearch/Workspace", {"returnFormat": "json"})[0], 404)
        self.assertEqual(self.api(self.user_key, "GET", "analyst_data/queryDescribe/Workspace")[0], 404)
        for ty in self.TYPES:
            for field in ("node_count", "sharing_group_id"):
                with self.subTest(f"{ty} {field}"):
                    status, rows, data = self.__search(ty, {field: 1})
                    self.assertEqual((status, rows), (400, None), data)
                    self.assertEqual(data["errors"][0]["code"], "unknown_field")
            for order in ("note", "sharing_group_id", "Event.id"):
                for query in (True, False):
                    with self.subTest(f"{ty} {order} {query}"):
                        body = {"returnFormat": "json", "order": order}
                        if query:
                            body["query"] = self.__anchored()
                        status, data = self.api(self.user_key, "POST", f"analyst_data/restSearch/{ty}", body)
                        self.assertEqual(status, 400, data)
                        self.assertNotIn("response", data)
                        self.assertEqual(data["errors"][0]["path"], "order[0]")
            with self.subTest(f"{ty} limit and format"):
                self.assertEqual(self.__search(ty, None, extra={"limit": -1})[0], 400)
                self.assertEqual(self.__search(ty, None, extra={"returnFormat": "csv"})[0], 404)
            with self.subTest(f"{ty} query by GET"):
                status, data = self.api(self.user_key, "GET", f"analyst_data/restSearch/{ty}", {"returnFormat": "json", "query": self.__anchored()})
                self.assertEqual(status, 400)
                self.assertNotIn("response", data or {})
                status, data = self.api(self.user_key, "POST", f"analyst_data/restSearch/{ty}?returnFormat=json&query[id]=1")
                self.assertEqual(status, 400)
                self.assertNotIn("response", data or {})

    def test_paging(self):
        for ty, recs in self.records.items():
            orders = ["id desc"] + (["opinion desc"] if ty == "Opinion" else [])
            for token, expected in ((self.user_key, {r["id"] for r in recs.values() if r["visible"]}), (key, {r["id"] for r in recs.values()})):
                for order in orders:
                    with self.subTest(f"{ty} {order} {token[:4]}"):
                        status, rows, data = self.__search(ty, None, token, extra={"order": order})
                        self.assertEqual(status, 200, data)
                        ids = [int(r["id"]) for r in rows]
                        self.assertEqual(set(ids), expected)
                        self.assertEqual(len(ids), len(expected))
                        paged = []
                        for page in range(1, 6):
                            status, rows, data = self.__search(ty, None, token, extra={"order": order, "limit": 3, "page": page})
                            self.assertEqual(status, 200, data)
                            self.assertLessEqual(len(rows), 3)
                            paged += [int(r["id"]) for r in rows]
                        self.assertEqual(paged, ids)


class TestComplexCollectionQueryAcl(unittest.TestCase):
    """The `query` tree of /collections/restSearch must only narrow what /collections/index shows the user."""

    api = staticmethod(TestComplexQueryAcl.api)
    admin_api = staticmethod(TestComplexQueryAcl.admin_api)
    ELEMENT_TYPES = ["Event", "GalaxyCluster", "Attribute", "Object", "AttributeValue"]

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        admin = PyMISP(url, key)
        check_response(admin.set_server_setting('Security.advanced_authkeys', True, force=True))
        cls.marker = "mqc" + random()
        cls.created = {"collections": [], "notes": [], "events": [], "users": [], "roles": [], "sgs": [], "keys": []}
        cls.org = None
        try:
            cls.__build_fixture()
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def __build_fixture(cls):
        cls.org = cls.admin_api("POST", "admin/organisations/add", {"name": "MQC Org " + random(), "local": True})["Organisation"]
        me = cls.admin_api("GET", "users/view/me")
        admin_org_uuid = me["Organisation"]["uuid"]
        cls.admin_org_name = me["Organisation"]["name"]
        roles = {
            "flagged": {"permission": "1", "perm_add": 1, "perm_auth": 1, "perm_complex_query": 1},
            "plain": {"permission": "0", "perm_auth": 1},
            "site_admin": {"permission": "3", "perm_auth": 1, "perm_site_admin": 1, "perm_complex_query": 0},
        }
        keys = {}
        for name, perms in roles.items():
            role = cls.admin_api("POST", "admin/roles/add", {"Role": {"name": f"MQC {name} {random()}", **perms}})["Role"]
            cls.created["roles"].append(role["id"])
            keys[name] = cls.__make_user(role["id"])
        cls.user_key, cls.plain_user_key, cls.site_admin_key = keys["flagged"], keys["plain"], keys["site_admin"]

        def sharing_group(label, members):
            sg = cls.admin_api("POST", "sharingGroups/add", {
                "SharingGroup": {"name": f"MQC SG {label} {random()}", "releasability": "test", "description": "test", "active": 1,
                                 "organisation_uuid": admin_org_uuid, "roaming": 0},
                "Organisation": [{"uuid": admin_org_uuid, "extend": True}]})["SharingGroup"]["id"]
            cls.created["sgs"].append(sg)
            for org_id in members:
                cls.api(key, "POST", f"sharingGroups/addOrg/{sg}/{org_id}", {"extend": 0})
            return sg
        cls.sg_out = sharing_group("out", [cls.org["id"]])  # membership is needed to add; removed below
        cls.sg_in = sharing_group("in", [cls.org["id"]])

        cls.hidden, cls.visible = (cls.__make_event(n, d) for n, d in (("hidden", 0), ("visible", 1)))
        status, data = cls.api(key, "POST", "galaxy_clusters/restSearch", {"returnFormat": "json", "limit": 1, "default": True})
        assert status == 200 and data["response"], (status, str(data)[:300])
        cls.cluster = data["response"][0]["GalaxyCluster"]["uuid"]
        cls.sha_a, cls.sha_b = (hashlib.sha256(random().encode()).hexdigest() for _ in range(2))

        H, V, C = cls.hidden["uuid"], cls.visible["uuid"], cls.cluster
        ev = lambda uuid_, desc=None: {"element_type": "Event", "element_uuid": uuid_, "description": desc}
        cl = lambda desc=None: {"element_type": "GalaxyCluster", "element_uuid": C, "description": desc}
        av = lambda sha, desc=None: {"element_type": "AttributeValue", "element_sha256": sha, "description": desc}
        probe = f"{cls.marker} probe"
        # (holder, distribution, sharing group, type, description, elements, visible to the flagged user)
        specs = {
            "own_0": ("own", 0, None, "campaign", "probe", [ev(V, "own ev"), av(cls.sha_a)], True),
            "own_sgout": ("own", 4, cls.sg_out, "other", None, [cl()], True),
            "b_0": ("b", 0, None, "other", "probe", [ev(H), av(cls.sha_a)], False),
            "b_1": ("b", 1, None, "other", None, [], True),
            "b_2": ("b", 2, None, "other", "probe", [ev(H), cl(probe)], True),
            "b_3": ("b", 3, None, "campaign", None, [av(cls.sha_b, probe)], True),
            "b_sgin": ("b", 4, cls.sg_in, "other", "probe", [ev(V)], True),
            "b_sgout": ("b", 4, cls.sg_out, "other", None, [ev(H), cl()], False),
            "b_stale": ("b", 2, cls.sg_out, "other", None, [], True),
        }
        cls.records = {}
        for name, (holder, distribution, sg, ctype, description, elements, visible) in specs.items():
            body = {"name": f"{cls.marker} {name}", "type": ctype, "distribution": distribution, "description": description,
                    "CollectionElement": elements}
            if sg:
                body["sharing_group_id"] = sg
            status, data = cls.api(cls.user_key if holder == "own" else key, "POST", "collections/add", body)
            assert status == 200, (name, status, str(data)[:300])
            record = data["Collection"]
            cls.created["collections"].append(record["id"])
            if holder == "own":
                assert str(record["org_id"]) == str(cls.org["id"]), record
            stored = cls.admin_api("GET", f"collections/view/{record['id']}.json")
            assert len(stored["Collection"]["CollectionElement"]) == len(elements), (name, stored)
            cls.records[name] = {"id": int(record["id"]), "uuid": record["uuid"], "name": name, "holder": holder,
                                 "distribution": distribution, "sg": sg, "type": ctype, "description": description,
                                 "elements": elements, "visible": visible}
        note = cls.admin_api("POST", "analyst_data/add/Note", {
            "object_uuid": cls.records["b_2"]["uuid"], "object_type": "Collection", "note": cls.marker, "distribution": 3})["Note"]
        cls.created["notes"].append(note["id"])
        status, data = cls.api(key, "POST", f"sharingGroups/removeOrg/{cls.sg_out}/{cls.org['id']}")
        assert status == 200, (status, data)
        cls.by_id = {r["id"]: r for r in cls.records.values()}

    @classmethod
    def tearDownClass(cls):
        for collection_id in cls.created["collections"]:
            try:
                cls.api(key, "POST", f"collections/delete/{collection_id}")
            except Exception:
                pass
        for note_id in cls.created["notes"]:
            try:
                cls.api(key, "POST", f"analyst_data/delete/Note/{note_id}")
            except Exception:
                pass
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
            "email": f"mqc{random()}@user.local", "org_id": cls.org["id"], "role_id": role_id, "password": str(uuid.uuid4())})["User"]
        cls.created["users"].append(user["id"])
        auth_key = cls.admin_api("POST", f"authKeys/add/{user['id']}")["AuthKey"]
        cls.created["keys"].append(auth_key["id"])
        return auth_key["authkey_raw"]

    @classmethod
    def __make_event(cls, name: str, distribution: int) -> dict:
        event = {"info": f"{cls.marker} ev-{name}", "distribution": distribution, "threat_level_id": 4, "analysis": 0}
        data = cls.admin_api("POST", "events/add", {"Event": event})
        cls.created["events"].append(data["Event"]["id"])
        return {"id": int(data["Event"]["id"]), "uuid": data["Event"]["uuid"]}

    def __anchored(self, tree=None):
        anchor = {"name": {"LIKE": self.marker + "%"}}
        return anchor if tree is None else {"AND": [anchor, tree]}

    def __search(self, tree, token=None, extra=None, method="POST", anchored=True):
        """Returns (status, [row] or None, raw data)."""
        body = {"returnFormat": "json", "limit": 1000, "query": self.__anchored(tree) if anchored else tree}
        body.update(extra or {})
        status, data = self.api(token or self.user_key, method, "collections/restSearch", body)
        rows = data["response"] if status == 200 and isinstance(data, dict) else None
        return status, rows, data

    def __ids(self, tree, token=None, **kwargs):
        status, rows, data = self.__search(tree, token, **kwargs)
        self.assertEqual(status, 200, data)
        return {int(r["Collection"]["id"]) for r in rows}

    def __index(self, token):
        status, data = self.api(token, "GET", "collections/index/limit:5000")
        self.assertEqual(status, 200, str(data)[:300])
        return {int(row["Collection"]["id"]): row for row in data if int(row["Collection"]["id"]) in self.by_id}

    @staticmethod
    def __search_shape(index_row):
        row = json.loads(json.dumps(index_row))
        for t in ("Note", "Opinion", "Relationship", "RelationshipInbound"):
            if t in row:
                row["Collection"][t] = row.pop(t)
        if str(row["Collection"]["distribution"]) != "4":
            row["SharingGroup"] = {"id": None, "uuid": None, "name": None}
        return row

    @staticmethod
    def __trim_orgs(row):
        """The attached analyst data may carry the full organisation record; compare id, name and uuid only."""
        for t in ("Note", "Opinion", "Relationship"):
            for item in row["Collection"].get(t, []):
                for o in ("Org", "Orgc"):
                    if isinstance(item.get(o), dict):
                        item[o] = {k: item[o].get(k) for k in ("id", "name", "uuid")}
        return row

    def __cases(self):
        """(tree, predicate on a fixture record)"""
        H, C = self.hidden["uuid"], self.cluster
        any_element = lambda r, test: any(test(e) for e in r["elements"])
        no_element = lambda r, test: not any_element(r, test)
        holder_org = {"own": self.org["name"], "b": self.admin_org_name}
        return {
            "no query": (None, lambda r: True),
            "distribution in": ({"distribution": {"IN": [0, 4]}}, lambda r: r["distribution"] in (0, 4)),
            "org upper": ({"org": self.org["name"].upper()}, lambda r: r["holder"] == "own"),
            "org admin": ({"org": self.admin_org_name}, lambda r: r["holder"] == "b"),
            "type": ({"type": "campaign"}, lambda r: r["type"] == "campaign"),
            "not name like": ({"NOT": {"name": {"LIKE": "%b_1"}}}, lambda r: r["name"] != "b_1"),
            "description !=": ({"description": {"!=": "probe"}}, lambda r: r["description"] != "probe"),
            "modified recent": ({"modified": {">": "1d"}}, lambda r: True),
            "element_uuid": ({"element_uuid": H}, lambda r: any_element(r, lambda e: e.get("element_uuid") == H)),
            "element_uuid !=": ({"element_uuid": {"!=": H}}, lambda r: no_element(r, lambda e: e.get("element_uuid") == H)),
            "element_type": ({"element_type": "GalaxyCluster"}, lambda r: any_element(r, lambda e: e["element_type"] == "GalaxyCluster")),
            "element_sha256": ({"element_sha256": self.sha_a.upper()}, lambda r: any_element(r, lambda e: e.get("element_sha256") == self.sha_a)),
            "element_description like": ({"element_description": {"LIKE": "%probe%"}},
                                         lambda r: any_element(r, lambda e: "probe" in (e["description"] or ""))),
            "not element_type in": ({"NOT": {"element_type": {"IN": self.ELEMENT_TYPES}}}, lambda r: not r["elements"]),
            "and or": ({"AND": [{"OR": [{"type": "campaign"}, {"distribution": 4}]}, {"NOT": {"org": self.org["name"]}}]},
                       lambda r: (r["type"] == "campaign" or r["distribution"] == 4) and r["holder"] != "own"),
        }

    def test_fixture_is_discriminating(self):
        visible = {r["id"] for r in self.records.values() if r["visible"]}
        self.assertEqual(len(visible), 7)
        self.assertEqual(self.__ids(None), visible)
        self.assertEqual(self.__ids(None, token=key), {r["id"] for r in self.records.values()})
        self.assertEqual(len(self.records), 9)

    def test_query_equals_the_index_and_the_matrix(self):
        for label, (tree, predicate) in self.__cases().items():
            with self.subTest(label):
                shown = {r["id"] for r in self.records.values() if r["visible"] and predicate(r)}
                self.assertEqual(self.__ids(tree), shown)
                admin_shown = {r["id"] for r in self.records.values() if predicate(r)}
                self.assertEqual(self.__ids(tree, token=key), admin_shown)
                if label in ("no query", "distribution in", "org admin", "element_uuid", "element_type",
                             "element_sha256"):
                    self.assertTrue(admin_shown - shown, "fixture is not discriminating")
                index = self.__index(self.user_key)
                self.assertEqual({i for i in index if predicate(self.by_id[i])}, shown)

    def test_rows_equal_the_index_rows(self):
        for token in (self.user_key, key):
            with self.subTest(token[:4]):
                status, rows, data = self.__search(None, token)
                self.assertEqual(status, 200, data)
                index = {i: self.__trim_orgs(self.__search_shape(row)) for i, row in self.__index(token).items()}
                self.assertEqual({int(r["Collection"]["id"]): self.__trim_orgs(r) for r in rows}, index)
                self.assertEqual(len(index), 9 if token == key else 7)

    def test_row_details(self):
        rows = {}
        for token in (self.user_key, key):
            rows[token] = {int(r["Collection"]["id"]): r for r in self.__search(None, token)[1]}
        user_rows, admin_rows = rows[self.user_key], rows[key]
        rec = self.records
        null_sg = {"id": None, "uuid": None, "name": None}
        self.assertEqual(user_rows[rec["b_stale"]["id"]]["SharingGroup"], null_sg)
        self.assertEqual(admin_rows[rec["b_stale"]["id"]]["SharingGroup"], null_sg)
        self.assertEqual(int(user_rows[rec["b_sgin"]["id"]]["SharingGroup"]["id"]), int(self.sg_in))
        self.assertEqual(int(user_rows[rec["own_sgout"]["id"]]["SharingGroup"]["id"]), int(self.sg_out))
        b_2 = user_rows[rec["b_2"]["id"]]
        self.assertEqual(b_2["Collection"]["element_count"], 2)
        self.assertIn(self.hidden["uuid"], {e.get("element_uuid") for e in b_2["CollectionElement"]})
        self.assertIn(self.marker, [n["note"] for n in b_2["Collection"]["Note"]])
        me = self.admin_api("GET", "users/view/me")["Organisation"]
        orgc = b_2["Collection"]["Note"][0]["Orgc"]
        self.assertEqual({k: orgc[k] for k in ("id", "name", "uuid")}, {k: me[k] for k in ("id", "name", "uuid")})

    def test_count(self):
        for token in (self.user_key, key):
            for label, (tree, _) in self.__cases().items():
                with self.subTest(f"{label} {token[:4]}"):
                    ids = self.__ids(tree, token=token)
                    status, count = self.api(token, "POST", "collections/restSearch", {
                        "returnFormat": "count", "query": self.__anchored(tree)})
                    self.assertEqual((status, int(count)), (200, len(ids)))

    def test_permission_flag(self):
        for token in (self.plain_user_key, "x" * 40):
            with self.subTest(token[:4]):
                status, rows, _ = self.__search(None, token=token)
                self.assertEqual((status, rows), (403, None))
                status, data = self.api(token, "POST", "collections/restSearch", {"returnFormat": "json"})
                self.assertEqual(status, 403, data)
                self.assertEqual(self.api(token, "GET", "collections/queryDescribe")[0], 403)
        status, data = self.api(self.user_key, "GET", "collections/queryDescribe")
        self.assertEqual(status, 200)
        self.assertEqual(data["tables"]["collections"]["endpoint"], "/collections/restSearch")
        for hidden_field in ("sharing_group_id", "element_count"):
            self.assertNotIn(hidden_field, data["tables"]["collections"]["fields"])
        self.assertEqual(self.__ids(None, token=self.site_admin_key), {r["id"] for r in self.records.values()})
        self.assertEqual(self.api(self.site_admin_key, "GET", "collections/queryDescribe")[0], 200)

    def test_rejections(self):
        for field in ("sharing_group_id", "element_count"):
            with self.subTest(field):
                status, rows, data = self.__search({field: 1})
                self.assertEqual((status, rows), (400, None), data)
                self.assertEqual(data["errors"][0]["code"], "unknown_field")
        for order in ("element_count", "user_id", "Orgc.name"):
            for query in (True, False):
                with self.subTest(f"{order} {query}"):
                    body = {"returnFormat": "json", "order": order}
                    if query:
                        body["query"] = self.__anchored()
                    status, data = self.api(self.user_key, "POST", "collections/restSearch", body)
                    self.assertEqual(status, 400, data)
                    self.assertNotIn("response", data)
                    self.assertEqual(data["errors"][0]["path"], "order[0]")
        with self.subTest("limit and format"):
            self.assertEqual(self.__search(None, extra={"limit": -1})[0], 400)
            self.assertEqual(self.__search(None, extra={"returnFormat": "csv"})[0], 404)
        with self.subTest("query by GET"):
            status, data = self.api(self.user_key, "GET", "collections/restSearch", {"returnFormat": "json", "query": self.__anchored()})
            self.assertEqual(status, 400)
            self.assertNotIn("response", data or {})
            status, data = self.api(self.user_key, "POST", "collections/restSearch?returnFormat=json&query[id]=1")
            self.assertEqual(status, 400)
            self.assertNotIn("response", data or {})

    def test_paging(self):
        for token, expected in ((self.user_key, {r["id"] for r in self.records.values() if r["visible"]}),
                                (key, {r["id"] for r in self.records.values()})):
            for order in ("id desc", "name desc"):
                with self.subTest(f"{order} {token[:4]}"):
                    status, rows, data = self.__search(None, token, extra={"order": order})
                    self.assertEqual(status, 200, data)
                    ids = [int(r["Collection"]["id"]) for r in rows]
                    self.assertEqual(set(ids), expected)
                    self.assertEqual(len(ids), len(expected))
                    paged = []
                    for page in range(1, 5):
                        status, rows, data = self.__search(None, token, extra={"order": order, "limit": 3, "page": page})
                        self.assertEqual(status, 200, data)
                        self.assertLessEqual(len(rows), 3)
                        paged += [int(r["Collection"]["id"]) for r in rows]
                    self.assertEqual(paged, ids)


class TestComplexTagQueryAcl(unittest.TestCase):
    """The `query` tree of /tags/restSearch must only narrow what /tags/index shows the user."""

    api = staticmethod(TestComplexQueryAcl.api)
    admin_api = staticmethod(TestComplexQueryAcl.admin_api)
    FIELDS = ["id", "org_id", "user_id", "numerical_value", "name", "colour",
              "exportable", "hide_tag", "is_galaxy", "is_custom_galaxy", "local_only"]
    BOOLS = ("exportable", "hide_tag", "is_galaxy", "is_custom_galaxy", "local_only")

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        admin = PyMISP(url, key)
        check_response(admin.set_server_setting('Security.advanced_authkeys', True, force=True))
        cls.marker = "mqt" + random()
        cls.created = {"tags": [], "events": [], "users": [], "roles": [], "keys": [], "settings": []}
        cls.org = None
        try:
            cls.__build_fixture()
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def __build_fixture(cls):
        cls.org = cls.admin_api("POST", "admin/organisations/add", {"name": "MQT Org " + random(), "local": True})["Organisation"]
        me = cls.admin_api("GET", "users/view/me")
        cls.admin_org_id, cls.admin_user_id = int(me["Organisation"]["id"]), int(me["User"]["id"])
        roles = {
            "flagged": {"permission": "1", "perm_add": 1, "perm_auth": 1, "perm_complex_query": 1},
            "plain": {"permission": "0", "perm_auth": 1},
            "site_admin": {"permission": "3", "perm_auth": 1, "perm_site_admin": 1, "perm_complex_query": 0},
        }
        keys = {}
        cls.user_ids = {}
        for name, perms in roles.items():
            role = cls.admin_api("POST", "admin/roles/add", {"Role": {"name": f"MQT {name} {random()}", **perms}})["Role"]
            cls.created["roles"].append(role["id"])
            keys[name] = cls.__make_user(role["id"], name)
        cls.user_key, cls.plain_user_key, cls.site_admin_key = keys["flagged"], keys["plain"], keys["site_admin"]

        m = cls.marker
        specs = {
            "plain": (f"{m} alpha", {"colour": "#AbCdEf", "numerical_value": 40}),
            "hidden": (f"{m} bravo", {"colour": "#111111", "hide_tag": 1}),
            "org": (f"{m} charlie", {"colour": "#222222", "org_id": cls.admin_org_id}),
            "user": (f"{m} delta", {"colour": "#333333", "user_id": cls.admin_user_id}),
            "num": (f"{m} echo", {"colour": "#444444", "numerical_value": 70}),
            "local": (f"{m} foxtrot", {"colour": "#555555", "local_only": 1, "exportable": 0}),
            "galaxy": (f'misp-galaxy:{m}="golf"', {"colour": "#666666"}),
            "custom": (f'misp-galaxy:{m}="{uuid.uuid4()}"', {"colour": "#777777"}),
        }
        cls.tags = {}
        for label, (name, columns) in specs.items():
            added = cls.admin_api("POST", "tags/add", {"name": name, **columns})
            tag_id = int(added["Tag"]["id"])
            cls.created["tags"].append(tag_id)
            stored = cls.admin_api("GET", f"tags/view/{tag_id}")
            stored = stored.get("Tag", stored)
            record = {"key": label, "id": tag_id, "name": stored["name"], "colour": stored["colour"],
                      "org_id": int(stored["org_id"]), "user_id": int(stored["user_id"]),
                      "numerical_value": None if stored["numerical_value"] is None else int(stored["numerical_value"])}
            for field in cls.BOOLS:
                record[field] = bool(int(stored[field]))
            assert record["name"] == name, (label, stored)
            for column, value in columns.items():
                expected = value if column in ("colour",) else (bool(value) if column in cls.BOOLS else int(value))
                assert record[column] == expected, (label, column, record)
            cls.tags[label] = record
        t = cls.tags
        assert not t["plain"]["hide_tag"] and t["plain"]["exportable"] and not t["plain"]["is_galaxy"], t["plain"]
        assert t["galaxy"]["is_galaxy"] and not t["galaxy"]["is_custom_galaxy"], t["galaxy"]
        assert t["custom"]["is_galaxy"] and t["custom"]["is_custom_galaxy"], t["custom"]
        assert [r["key"] for r in t.values() if r["numerical_value"] is not None] == ["plain", "num"], t
        cls.by_id = {r["id"]: r for r in t.values()}

        # the flagged user overrides the numerical value of one tag and favourites another
        flagged_id = cls.user_ids["flagged"]
        status, data = cls.api(key, "POST", f"user_settings/setSetting/{flagged_id}/tag_numerical_value_override",
                               {"value": {t["num"]["name"]: 10}})
        assert status == 200, (status, data)
        cls.created["settings"].append(data["id"])
        status, data = cls.api(cls.user_key, "POST", "favourite_tags/toggle", {"FavouriteTag": {"data": t["plain"]["id"]}})
        assert status == 200 and data.get("saved") is True, (status, data)

        cls.hidden_event = cls.__make_event("hidden", 0)
        cls.visible_event = cls.__make_event("visible", 1)
        for event in (cls.hidden_event, cls.visible_event):
            cls.__attach(f"events/addTag/{event['id']}/{t['plain']['id']}")
        cls.__attach(f"events/addTag/{cls.hidden_event['id']}/{t['org']['id']}")
        attribute = cls.admin_api("POST", f"attributes/add/{cls.hidden_event['id']}", {
            "type": "ip-dst", "category": "Network activity", "value": "10.77.0.%d" % (int(random(), 16) % 250 + 1)})["Attribute"]
        cls.__attach(f"attributes/addTag/{attribute['id']}/{t['plain']['id']}")

        index = cls.admin_api("GET", f"tags/index/searchall:{m}")
        assert len(index["Tag"]) == 8, index
        row = [r for r in cls.__get(cls.user_key, f"tags/index/searchall:{m}")["Tag"] if int(r["id"]) == t["num"]["id"]][0]
        assert (int(row["numerical_value"]), int(row["original_numerical_value"])) == (10, 70), row

    @classmethod
    def __get(cls, token, path):
        status, data = cls.api(token, "GET", path)
        assert status == 200, (path, status, str(data)[:300])
        return data

    @classmethod
    def __attach(cls, path):
        status, data = cls.api(key, "POST", path, {})
        assert status == 200 and not (isinstance(data, dict) and data.get("errors")), (path, status, data)
        assert "success" in json.dumps(data).lower() or data.get("saved") is True, (path, data)

    @classmethod
    def tearDownClass(cls):
        for kind, path in (("events", "events/delete/{}"), ("settings", "user_settings/delete/{}"),
                           ("tags", "tags/delete/{}"), ("keys", "authKeys/delete/{}"),
                           ("users", "admin/users/delete/{}"), ("roles", "admin/roles/delete/{}")):
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
    def __make_user(cls, role_id, label) -> str:
        user = cls.admin_api("POST", "admin/users/add", {
            "email": f"mqt{random()}@user.local", "org_id": cls.org["id"], "role_id": role_id, "password": str(uuid.uuid4())})["User"]
        cls.created["users"].append(user["id"])
        cls.user_ids[label] = int(user["id"])
        auth_key = cls.admin_api("POST", f"authKeys/add/{user['id']}")["AuthKey"]
        cls.created["keys"].append(auth_key["id"])
        return auth_key["authkey_raw"]

    @classmethod
    def __make_event(cls, name: str, distribution: int) -> dict:
        event = {"info": f"{cls.marker} ev-{name}", "distribution": distribution, "threat_level_id": 4, "analysis": 0}
        data = cls.admin_api("POST", "events/add", {"Event": event})
        cls.created["events"].append(data["Event"]["id"])
        return {"id": int(data["Event"]["id"]), "uuid": data["Event"]["uuid"]}

    def __anchored(self, tree=None):
        anchor = {"name": {"LIKE": "%" + self.marker + "%"}}
        return anchor if tree is None else {"AND": [anchor, tree]}

    def __search(self, tree, token=None, extra=None, method="POST", anchored=True):
        """Returns (status, [row] or None, raw data)."""
        body = {"returnFormat": "json", "limit": 1000, "query": self.__anchored(tree) if anchored else tree}
        body.update(extra or {})
        status, data = self.api(token or self.user_key, method, "tags/restSearch", body)
        rows = data["response"] if status == 200 and isinstance(data, dict) else None
        return status, rows, data

    def __ids(self, tree, token=None, **kwargs):
        status, rows, data = self.__search(tree, token, **kwargs)
        self.assertEqual(status, 200, data)
        return [int(r["Tag"]["id"]) for r in rows]

    def __index(self, token, search=None):
        status, data = self.api(token, "GET", f"tags/index/searchall:{search or self.marker}")
        self.assertEqual(status, 200, str(data)[:300])
        return {int(row["id"]): row for row in data["Tag"]}

    def __cases(self):
        """(tree, predicate on a fixture record)"""
        m, admin_org, admin_user = self.marker, self.admin_org_id, self.admin_user_id
        null = lambda r: r["numerical_value"] is None
        return {
            "no query": (None, lambda r: True),
            "id in": ({"id": {"IN": [self.tags["plain"]["id"], self.tags["org"]["id"]]}}, lambda r: r["key"] in ("plain", "org")),
            "name = other case": ({"name": f"{m} ALPHA".upper()}, lambda r: r["key"] == "plain"),
            "name like": ({"name": {"LIKE": f"%{m} b%"}}, lambda r: r["key"] == "hidden"),
            "name not like": ({"name": {"NOT LIKE": "% alpha"}}, lambda r: r["key"] != "plain"),
            "colour other case": ({"colour": "#ABCDEF"}, lambda r: r["key"] == "plain"),
            "colour in": ({"colour": {"IN": ["#abcdef", "#222222"]}}, lambda r: r["key"] in ("plain", "org")),
            "colour !=": ({"colour": {"!=": "#ABCDEF"}}, lambda r: r["key"] != "plain"),
            "exportable false": ({"exportable": False}, lambda r: not r["exportable"]),
            "org_id": ({"org_id": admin_org}, lambda r: r["org_id"] == admin_org),
            "user_id !=": ({"user_id": {"!=": 0}}, lambda r: r["user_id"] != 0),
            "user_id": ({"user_id": admin_user}, lambda r: r["user_id"] == admin_user),
            "hide_tag": ({"hide_tag": True}, lambda r: r["hide_tag"]),
            "numerical_value >=": ({"numerical_value": {">=": 40}}, lambda r: not null(r) and r["numerical_value"] >= 40),
            "numerical_value !=": ({"numerical_value": {"!=": 40}}, lambda r: null(r) or r["numerical_value"] != 40),
            "numerical_value not in": ({"numerical_value": {"NOT IN": [40]}}, lambda r: null(r) or r["numerical_value"] != 40),
            "not numerical_value <": ({"NOT": {"numerical_value": {"<": 50}}}, lambda r: null(r) or not r["numerical_value"] < 50),
            "is_galaxy": ({"is_galaxy": True}, lambda r: r["is_galaxy"]),
            "is_custom_galaxy": ({"is_custom_galaxy": True}, lambda r: r["is_custom_galaxy"]),
            "local_only": ({"local_only": True}, lambda r: r["local_only"]),
            "and or": ({"AND": [{"OR": [{"hide_tag": True}, {"is_galaxy": True}]}, {"NOT": {"is_custom_galaxy": True}}]},
                       lambda r: (r["hide_tag"] or r["is_galaxy"]) and not r["is_custom_galaxy"]),
        }

    def test_fixture_is_discriminating(self):
        t = self.tags
        user_index, admin_index = self.__index(self.user_key), self.__index(key)
        self.assertEqual(set(user_index), set(self.by_id))
        self.assertEqual(set(admin_index), set(self.by_id))
        self.assertEqual(len(user_index), 8)
        self.assertEqual((int(admin_index[t["plain"]["id"]]["count"]), int(user_index[t["plain"]["id"]]["count"])), (2, 1))
        self.assertEqual((int(admin_index[t["org"]["id"]]["count"]), int(user_index[t["org"]["id"]]["count"])), (1, 0))
        self.assertTrue(user_index[t["plain"]["id"]]["favourite"])
        self.assertFalse(admin_index[t["plain"]["id"]]["favourite"])
        for label in ("hidden", "org", "user"):
            self.assertIn(t[label]["id"], user_index)

    def test_query_equals_the_index_and_the_matrix(self):
        tokens = {"flagged": self.user_key, "site_admin": self.site_admin_key, "admin": key}
        for label, (tree, predicate) in self.__cases().items():
            with self.subTest(label):
                expected = sorted(r["id"] for r in self.tags.values() if predicate(r))
                self.assertTrue(expected, "empty expectation")
                for who, token in tokens.items():
                    self.assertEqual(self.__ids(tree, token=token), expected, who)
                index = self.__index(self.user_key)
                self.assertEqual(sorted(i for i in index if predicate(self.by_id[i])), expected)
        with self.subTest("discriminating"):
            for label in ("id in", "colour !=", "numerical_value !=", "not numerical_value <"):
                tree, predicate = self.__cases()[label]
                self.assertTrue(any(not predicate(r) for r in self.tags.values()))

    def test_rows_equal_the_index_rows(self):
        for token in (self.user_key, key):
            with self.subTest(token[:4]):
                status, rows, data = self.__search(None, token)
                self.assertEqual(status, 200, data)
                index = self.__index(token)
                self.assertEqual({int(r["Tag"]["id"]): r["Tag"] for r in rows}, index)
                self.assertEqual(len(index), 8)
        with self.subTest("taxonomy"):
            status, data = self.api(self.user_key, "GET", "taxonomies/index")
            self.assertEqual(status, 200)
            checked = False
            for item in data:
                taxonomy = item["Taxonomy"]
                ns = taxonomy["namespace"]
                if not taxonomy.get("enabled") or not re.fullmatch(r"[A-Za-z0-9-]+", ns):
                    continue
                status, count = self.api(self.user_key, "POST", "tags/restSearch", {
                    "returnFormat": "count", "query": {"name": {"LIKE": f"{ns}:%"}}})
                self.assertEqual(status, 200, count)
                if not 0 < int(count) <= 500:
                    continue
                status, rows, data = self.__search({"name": {"LIKE": f"{ns}:%"}}, anchored=False)
                self.assertEqual(status, 200, data)
                index = {i: row for i, row in self.__index(self.user_key, f"{ns}:").items()
                         if row["name"].lower().startswith(ns.lower() + ":")}
                self.assertEqual({int(r["Tag"]["id"]): r["Tag"] for r in rows}, index)
                self.assertTrue(any("Taxonomy" in r["Tag"] for r in rows), ns)
                checked = True
                break
            if not checked:
                self.skipTest("no enabled taxonomy with tags")

    def test_row_details(self):
        t = self.tags
        rows = {tok: {int(r["Tag"]["id"]): r["Tag"] for r in self.__search(None, tok)[1]} for tok in (self.user_key, key)}
        user_rows, admin_rows = rows[self.user_key], rows[key]
        plain = t["plain"]["id"]
        self.assertEqual((user_rows[plain]["favourite"], int(user_rows[plain]["count"]), int(user_rows[plain]["attribute_count"])), (True, 1, 1))
        self.assertEqual((admin_rows[plain]["favourite"], int(admin_rows[plain]["count"]), int(admin_rows[plain]["attribute_count"])), (False, 2, 1))
        org = t["org"]["id"]
        self.assertEqual((int(user_rows[org]["count"]), int(admin_rows[org]["count"])), (0, 1))
        num = t["num"]["id"]
        self.assertEqual((int(user_rows[num]["numerical_value"]), int(user_rows[num]["original_numerical_value"])), (10, 70))
        self.assertEqual(int(admin_rows[num]["numerical_value"]), 70)
        self.assertNotIn("original_numerical_value", admin_rows[num])
        self.assertEqual(self.__ids({"numerical_value": 70}), [num])
        self.assertEqual(self.__ids({"numerical_value": 10}), [])

    def test_count(self):
        for label, (tree, _) in self.__cases().items():
            with self.subTest(label):
                ids = self.__ids(tree)
                status, count = self.api(self.user_key, "POST", "tags/restSearch", {
                    "returnFormat": "count", "query": self.__anchored(tree)})
                self.assertEqual((status, int(count)), (200, len(ids)))

    def test_permission_flag(self):
        for with_query in (True, False):
            body = {"returnFormat": "json"}
            if with_query:
                body["query"] = self.__anchored()
            status, data = self.api(self.plain_user_key, "POST", "tags/restSearch", body)
            self.assertEqual(status, 403, data)
        self.assertEqual(self.api(self.plain_user_key, "GET", "tags/queryDescribe")[0], 403)
        self.assertEqual(self.api(self.plain_user_key, "GET", "tags/index")[0], 200)
        for token in (self.user_key, self.site_admin_key):
            self.assertEqual(len(self.__ids(None, token=token)), 8)
            status, data = self.api(token, "GET", "tags/queryDescribe")
            self.assertEqual(status, 200)
            table = data["tables"]["tags"]
            self.assertEqual(sorted(table["fields"]), sorted(self.FIELDS))
            self.assertEqual(table["sortable"], ["id", "name", "numerical_value"])

    def test_rejections(self):
        for field in ("count", "attribute_count", "favourite", "Taxonomy", "original_numerical_value", "org"):
            with self.subTest(field):
                status, rows, data = self.__search({field: 1})
                self.assertEqual((status, rows), (400, None), data)
                self.assertEqual(data["errors"][0]["code"], "unknown_field")
        with self.subTest("colour like"):
            status, rows, data = self.__search({"colour": {"LIKE": "#ab%"}})
            self.assertEqual((status, rows), (400, None), data)
            self.assertEqual(data["errors"][0]["code"], "unknown_operator")
        for order in ("count", "colour", "attribute_count desc"):
            for query in (True, False):
                with self.subTest(f"{order} {query}"):
                    body = {"returnFormat": "json", "order": order}
                    if query:
                        body["query"] = self.__anchored()
                    status, data = self.api(self.user_key, "POST", "tags/restSearch", body)
                    self.assertEqual(status, 400, data)
                    self.assertNotIn("response", data)
        with self.subTest("limit and format"):
            self.assertEqual(self.__search(None, extra={"limit": -1})[0], 400)
            self.assertEqual(self.__search(None, extra={"returnFormat": "csv"})[0], 404)
        with self.subTest("query by GET"):
            status, data = self.api(self.user_key, "GET", "tags/restSearch", {"returnFormat": "json", "query": self.__anchored()})
            self.assertEqual(status, 400)
            self.assertNotIn("response", data or {})
            status, data = self.api(self.user_key, "POST", "tags/restSearch?returnFormat=json&query[id]=1")
            self.assertEqual(status, 400)
            self.assertNotIn("response", data or {})

    def test_paging_and_order(self):
        t = self.tags
        full = sorted(self.by_id)
        self.assertEqual(self.__ids(None), full)
        paged = []
        for page in range(1, 6):
            ids = self.__ids(None, extra={"limit": 2, "page": page})
            self.assertLessEqual(len(ids), 2)
            paged += ids
        self.assertEqual(paged, full)
        with self.subTest("name desc"):
            names = sorted((r for r in t.values() if not r["is_galaxy"]), key=lambda r: r["name"], reverse=True)
            self.assertEqual(self.__ids({"is_galaxy": False}, extra={"order": "name desc"}), [r["id"] for r in names])
        nulls = [r for r in t.values() if r["numerical_value"] is None]
        with self.subTest("numerical_value desc"):
            expected = [t["num"]["id"], t["plain"]["id"]] + sorted(r["id"] for r in nulls)
            self.assertEqual(self.__ids(None, extra={"order": "numerical_value desc"}), expected)
        with self.subTest("numerical_value, name desc"):
            expected = [r["id"] for r in sorted(nulls, key=lambda r: r["name"], reverse=True)] + [t["plain"]["id"], t["num"]["id"]]
            ordered = {"order": ["numerical_value", "name desc"]}
            self.assertEqual(self.__ids(None, extra={**ordered, "limit": 3, "page": 2}), expected[3:6])
            self.assertEqual(self.__ids(None, extra=ordered), expected)


class TestComplexOrganisationQueryAcl(unittest.TestCase):
    """The `query` tree of /organisations/restSearch must only narrow what /organisations/index/scope:all shows."""

    api = staticmethod(TestComplexQueryAcl.api)
    admin_api = staticmethod(TestComplexQueryAcl.admin_api)
    HIDE = "Security.hide_organisation_index_from_users"
    FIELDS = ["id", "uuid", "name", "type", "nationality", "sector", "description", "contacts",
              "landingpage", "local", "date_created", "date_modified"]

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", ResourceWarning)
        admin = PyMISP(url, key)
        check_response(admin.set_server_setting('Security.advanced_authkeys', True, force=True))
        cls.marker = "mqo" + random()
        cls.created = {"orgs": [], "users": [], "roles": [], "keys": []}
        cls.org = None
        cls.hide_to_restore = None
        try:
            cls.__build_fixture()
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def __build_fixture(cls):
        m = cls.marker
        me = cls.admin_api("GET", "users/view/me")
        cls.admin_user_id, cls.admin_email = int(me["User"]["id"]), me["User"]["email"]
        specs = {
            "home": (f"{m} alpha", {"local": True, "type": "Company", "nationality": "Lux", "sector": "Finance",
                                    "description": "Home org"}),
            "bravo": (f"{m} Bravo", {"local": False, "type": "CERT", "nationality": "FR", "sector": "Telecom",
                                     "contacts": "bravo@x.test"}),
            "charlie": (f"{m} charlie", {"local": False, "type": "company", "nationality": "DE", "sector": "finance",
                                         "description": "Third", "landingpage": "https://c.test"}),
            "delta": (f"{m} DELTA", {"local": True, "type": "NGO", "nationality": "lux", "sector": "Energy",
                                     "restricted_to_domain": ["d.test"]}),
            "echo": (f"{m} echo", {"local": False, "type": "CERT", "nationality": "FR", "sector": "Health",
                                   "description": "Fifth"}),
        }
        cls.orgs = {}
        for n, (label, (name, columns)) in enumerate(specs.items()):
            added = cls.admin_api("POST", "admin/organisations/add", {"name": name, **columns})
            org_id = int(added["Organisation"]["id"])
            cls.created["orgs"].append(org_id)
            stored = cls.admin_api("GET", f"organisations/view/{org_id}")
            stored = stored.get("Organisation", stored)
            record = {"key": label, "id": org_id, "name": stored["name"], "uuid": stored["uuid"],
                      "local": bool(stored["local"]), "date_created": stored["date_created"],
                      "date_modified": stored["date_modified"]}
            for column in ("type", "nationality", "sector", "description", "contacts"):
                record[column] = stored.get(column)
            record["landingpage"] = added["Organisation"].get("landingpage")
            assert record["name"] == name and record["local"] == columns["local"], (label, stored)
            for column, value in columns.items():
                if column not in ("local", "restricted_to_domain"):
                    assert record[column] == value, (label, column, stored)
            if "restricted_to_domain" in columns:
                assert added["Organisation"]["restricted_to_domain"] == columns["restricted_to_domain"], added
            cls.orgs[label] = record
            if n == 0:
                cls.org = {"id": org_id}
                time.sleep(2)
        o = cls.orgs
        assert o["home"]["date_created"] < o["bravo"]["date_created"], o
        assert o["bravo"]["description"] is None and o["delta"]["description"] is None, o
        assert o["home"]["contacts"] is None and o["bravo"]["contacts"] and o["charlie"]["landingpage"], o
        cls.by_id = {r["id"]: r for r in o.values()}

        roles = {
            "flagged": {"permission": "1", "perm_add": 1, "perm_auth": 1, "perm_complex_query": 1, "perm_sharing_group": 0},
            "flagged_sg": {"permission": "1", "perm_add": 1, "perm_auth": 1, "perm_complex_query": 1, "perm_sharing_group": 1},
            "plain": {"permission": "0", "perm_auth": 1},
            "site_admin": {"permission": "3", "perm_auth": 1, "perm_site_admin": 1, "perm_complex_query": 0},
        }
        keys = {}
        cls.user_ids = {}
        for name, perms in roles.items():
            role = cls.admin_api("POST", "admin/roles/add", {"Role": {"name": f"MQO {name} {random()}", **perms}})["Role"]
            cls.created["roles"].append(role["id"])
            stored = cls.admin_api("GET", f"roles/view/{role['id']}")
            stored = stored.get("Role", stored)
            for perm in ("perm_complex_query", "perm_sharing_group", "perm_site_admin"):
                if perm in perms:
                    assert int(stored[perm]) == perms[perm], (name, perm, stored)
            keys[name] = cls.__make_user(role["id"], name)
        cls.user_key, cls.sg_key, cls.plain_user_key, cls.site_admin_key = (
            keys["flagged"], keys["flagged_sg"], keys["plain"], keys["site_admin"])
        index = cls.admin_api("GET", f"organisations/index/scope:all/searchall:{m}")
        assert {int(r["Organisation"]["id"]) for r in index} == set(cls.by_id), index

    @classmethod
    def tearDownClass(cls):
        if cls.hide_to_restore is not None:
            try:
                PyMISP(url, key).set_server_setting(cls.HIDE, cls.hide_to_restore, force=True)
            except Exception:
                pass
        for kind, path in (("keys", "authKeys/delete/{}"), ("users", "admin/users/delete/{}"),
                           ("roles", "admin/roles/delete/{}"), ("orgs", "admin/organisations/delete/{}")):
            for item in cls.created[kind]:
                try:
                    cls.api(key, "POST", path.format(item))
                except Exception:
                    pass

    @classmethod
    def __make_user(cls, role_id, label) -> str:
        user = cls.admin_api("POST", "admin/users/add", {
            "email": f"mqo{random()}@user.local", "org_id": cls.org["id"], "role_id": role_id, "password": str(uuid.uuid4())})["User"]
        cls.created["users"].append(user["id"])
        cls.user_ids[label] = int(user["id"])
        auth_key = cls.admin_api("POST", f"authKeys/add/{user['id']}")["AuthKey"]
        cls.created["keys"].append(auth_key["id"])
        return auth_key["authkey_raw"]

    def __anchored(self, tree=None):
        anchor = {"name": {"LIKE": self.marker + "%"}}
        return anchor if tree is None else {"AND": [anchor, tree]}

    def __search(self, tree, token=None, extra=None, method="POST", anchored=True):
        """Returns (status, [row] or None, raw data)."""
        body = {"returnFormat": "json", "limit": 1000, "query": self.__anchored(tree) if anchored else tree}
        body.update(extra or {})
        status, data = self.api(token or self.user_key, method, "organisations/restSearch", body)
        rows = data["response"] if status == 200 and isinstance(data, dict) else None
        return status, rows, data

    def __ids(self, tree, token=None, **kwargs):
        status, rows, data = self.__search(tree, token, **kwargs)
        self.assertEqual(status, 200, data)
        return [int(r["Organisation"]["id"]) for r in rows]

    def __index(self, token):
        status, data = self.api(token, "GET", f"organisations/index/scope:all/searchall:{self.marker}")
        self.assertEqual(status, 200, str(data)[:300])
        return {int(row["Organisation"]["id"]): row["Organisation"] for row in data if int(row["Organisation"]["id"]) in self.by_id}

    def __setting(self):
        status, data = self.api(key, "GET", f"servers/getSetting/{self.HIDE}")
        self.assertEqual(status, 200, data)
        return bool(data["value"])

    def __cases(self):
        """(tree, predicate on a fixture record)"""
        o, m = self.orgs, self.marker
        lower = lambda v: None if v is None else v.lower()
        first = o["home"]["date_created"]
        return {
            "no query": (None, lambda r: True),
            "id in": ({"id": {"IN": [o["home"]["id"], o["charlie"]["id"]]}}, lambda r: r["key"] in ("home", "charlie")),
            "uuid upper": ({"uuid": o["charlie"]["uuid"].upper()}, lambda r: r["key"] == "charlie"),
            "uuid not in": ({"uuid": {"NOT IN": [o["bravo"]["uuid"]]}}, lambda r: r["key"] != "bravo"),
            "name = other case": ({"name": f"{m} BRAVO"}, lambda r: r["key"] == "bravo"),
            "name like": ({"name": {"LIKE": "%a"}}, lambda r: r["name"].lower().endswith("a")),
            "name not like": ({"name": {"NOT LIKE": "% echo"}}, lambda r: r["key"] != "echo"),
            "type": ({"type": "COMPANY"}, lambda r: lower(r["type"]) == "company"),
            "nationality in": ({"nationality": {"IN": ["LUX", "fr"]}}, lambda r: lower(r["nationality"]) in ("lux", "fr")),
            "sector like": ({"sector": {"LIKE": "FIN%"}}, lambda r: lower(r["sector"]).startswith("fin")),
            "description !=": ({"description": {"!=": "THIRD"}}, lambda r: r["description"] is None or lower(r["description"]) != "third"),
            "contacts not like": ({"contacts": {"NOT LIKE": "%BRAVO%"}}, lambda r: r["contacts"] is None or "bravo" not in lower(r["contacts"])),
            "landingpage": ({"landingpage": "HTTPS://C.TEST"}, lambda r: lower(r["landingpage"]) == "https://c.test"),
            "landingpage not in": ({"landingpage": {"NOT IN": ["https://c.test"]}}, lambda r: r["landingpage"] is None),
            "local true": ({"local": True}, lambda r: r["local"]),
            "local false": ({"local": False}, lambda r: not r["local"]),
            "date_created <=": ({"date_created": {"<=": first}}, lambda r: r["date_created"] <= first),
            "date_modified >=": ({"date_modified": {">=": "1d"}}, lambda r: True),
            "and or": ({"AND": [{"OR": [{"local": False}, {"sector": {"LIKE": "en%"}}]}, {"NOT": {"type": "CERT"}}]},
                       lambda r: (not r["local"] or lower(r["sector"]).startswith("en")) and lower(r["type"]) != "cert"),
        }

    def test_fixture_is_discriminating(self):
        user_index, admin_index = self.__index(self.user_key), self.__index(key)
        self.assertEqual(set(user_index), set(self.by_id))
        self.assertEqual(set(admin_index), set(self.by_id))
        home = self.orgs["home"]["id"]
        for row in admin_index.values():
            self.assertEqual(int(row["created_by"]), self.admin_user_id)
            self.assertEqual(row["created_by_email"], self.admin_email)
        for row in user_index.values():
            self.assertNotIn("created_by", row)
            self.assertNotIn("created_by_email", row)
        self.assertEqual(int(user_index[home]["user_count"]), 4)
        self.assertEqual(int(admin_index[home]["user_count"]), 4)
        names = [r["name"] for r in self.orgs.values()]
        self.assertNotEqual(sorted(names), sorted(names, key=str.lower))

    def test_query_equals_the_index_and_the_matrix(self):
        tokens = {"flagged": self.user_key, "site_admin": self.site_admin_key, "admin": key}
        index = self.__index(self.user_key)
        cases = self.__cases()
        for label, (tree, predicate) in cases.items():
            with self.subTest(label):
                expected = sorted(r["id"] for r in self.orgs.values() if predicate(r))
                self.assertTrue(expected, "empty expectation")
                for who, token in tokens.items():
                    self.assertEqual(self.__ids(tree, token=token), expected, who)
                self.assertEqual(sorted(i for i in index if predicate(self.by_id[i])), expected)
        with self.subTest("discriminating"):
            for label in ("id in", "uuid not in", "name not like", "description !=", "contacts not like",
                          "landingpage not in", "local false", "date_created <=", "and or"):
                self.assertTrue(any(not cases[label][1](r) for r in self.orgs.values()), label)
            self.assertTrue(any(r["description"] is None for r in self.orgs.values()))
            self.assertTrue(any(r["contacts"] is None for r in self.orgs.values()))

    def test_rows_equal_the_index_rows(self):
        for token in (self.user_key, self.site_admin_key, key):
            with self.subTest(token[:4]):
                status, rows, data = self.__search(None, token)
                self.assertEqual(status, 200, data)
                index = self.__index(token)
                self.assertEqual({int(r["Organisation"]["id"]): r["Organisation"] for r in rows}, index)
                self.assertEqual(len(index), 5)

    def test_row_details(self):
        rows = {tok: {int(r["Organisation"]["id"]): r["Organisation"] for r in self.__search(None, tok)[1]}
                for tok in (self.user_key, key)}
        user_rows, admin_rows = rows[self.user_key], rows[key]
        for row in user_rows.values():
            self.assertNotIn("created_by", row)
            self.assertNotIn("created_by_email", row)
        for row in admin_rows.values():
            self.assertEqual(int(row["created_by"]), self.admin_user_id)
            self.assertEqual(row["created_by_email"], self.admin_email)
        for row in list(user_rows.values()) + list(admin_rows.values()):
            self.assertIsInstance(row["restricted_to_domain"], (list, type(None)))
        for rows_by_id in (user_rows, admin_rows):
            self.assertEqual(rows_by_id[self.orgs["delta"]["id"]]["restricted_to_domain"], ["d.test"])
        home = self.orgs["home"]["id"]
        self.assertEqual((int(user_rows[home]["user_count"]), int(admin_rows[home]["user_count"])), (4, 4))

    def test_count(self):
        for label, (tree, _) in self.__cases().items():
            with self.subTest(label):
                ids = self.__ids(tree)
                status, count = self.api(self.user_key, "POST", "organisations/restSearch", {
                    "returnFormat": "count", "query": self.__anchored(tree)})
                self.assertEqual((status, int(count)), (200, len(ids)))

    def test_permission_flag(self):
        for with_query in (True, False):
            body = {"returnFormat": "json"}
            if with_query:
                body["query"] = self.__anchored()
            status, data = self.api(self.plain_user_key, "POST", "organisations/restSearch", body)
            self.assertEqual(status, 403, data)
        self.assertEqual(self.api(self.plain_user_key, "GET", "organisations/queryDescribe")[0], 403)
        self.assertEqual(self.api(self.plain_user_key, "GET", "organisations/index")[0], 200)
        for token in (self.user_key, self.sg_key, self.site_admin_key):
            self.assertEqual(len(self.__ids(None, token=token)), 5)
            status, data = self.api(token, "GET", "organisations/queryDescribe")
            self.assertEqual(status, 200)
            table = data["tables"]["organisations"]
            self.assertEqual(sorted(table["fields"]), sorted(self.FIELDS))
            self.assertEqual(len(table["fields"]), 12)
            self.assertEqual(table["sortable"], ["id", "name", "date_created", "date_modified"])

    def test_hidden_index_gate(self):
        original = self.__setting()
        admin = PyMISP(url, key)
        type(self).hide_to_restore = original
        try:
            check_response(admin.set_server_setting(self.HIDE, True, force=True))
            for _ in range(10):
                if self.api(self.user_key, "GET", "organisations/index")[0] == 403:
                    break
                time.sleep(1)
            body = {"returnFormat": "json", "query": self.__anchored()}
            with self.subTest("flagged"):
                self.assertEqual(self.api(self.user_key, "POST", "organisations/restSearch", body)[0], 403)
                self.assertEqual(self.api(self.user_key, "GET", "organisations/queryDescribe")[0], 403)
                self.assertEqual(self.api(self.user_key, "GET", "organisations/index")[0], 403)
            with self.subTest("flagged_sg"):
                status, data = self.api(self.sg_key, "POST", "organisations/restSearch", body)
                self.assertEqual(status, 200, data)
                self.assertEqual(self.api(self.sg_key, "GET", "organisations/queryDescribe")[0], 200)
                self.assertEqual(self.api(self.sg_key, "GET", "organisations/index")[0], 200)
                self.assertEqual({int(r["Organisation"]["id"]): r["Organisation"] for r in data["response"]},
                                 self.__index(self.sg_key))
            with self.subTest("site_admin"):
                self.assertEqual(self.api(self.site_admin_key, "POST", "organisations/restSearch", body)[0], 200)
                self.assertEqual(self.api(self.site_admin_key, "GET", "organisations/queryDescribe")[0], 200)
                self.assertEqual(self.api(self.site_admin_key, "GET", "organisations/index")[0], 200)
        finally:
            check_response(admin.set_server_setting(self.HIDE, original, force=True))
            type(self).hide_to_restore = None
            for _ in range(10):
                if self.__setting() == original and self.api(self.user_key, "GET", "organisations/index")[0] == 200:
                    break
                time.sleep(1)
        self.assertEqual(self.__setting(), original)

    def test_rejections(self):
        for field in ("created_by", "created_by_email", "user_count", "restricted_to_domain", "org"):
            with self.subTest(field):
                status, rows, data = self.__search({field: 1})
                self.assertEqual((status, rows), (400, None), data)
                self.assertEqual(data["errors"][0]["code"], "unknown_field")
        with self.subTest("uuid like"):
            status, rows, data = self.__search({"uuid": {"LIKE": "a%"}})
            self.assertEqual((status, rows), (400, None), data)
            self.assertEqual(data["errors"][0]["code"], "unknown_operator")
        with self.subTest("empty string"):
            status, rows, data = self.__search({"sector": ""})
            self.assertEqual((status, rows), (400, None), data)
            self.assertEqual(data["errors"][0]["code"], "bad_type")
        for order in ("user_count", "sector", "created_by desc"):
            for query in (True, False):
                with self.subTest(f"{order} {query}"):
                    body = {"returnFormat": "json", "order": order}
                    if query:
                        body["query"] = self.__anchored()
                    status, data = self.api(self.user_key, "POST", "organisations/restSearch", body)
                    self.assertEqual(status, 400, data)
                    self.assertNotIn("response", data)
        with self.subTest("limit and format"):
            self.assertEqual(self.__search(None, extra={"limit": -1})[0], 400)
            self.assertEqual(self.__search(None, extra={"returnFormat": "csv"})[0], 404)
        with self.subTest("query by GET"):
            status, data = self.api(self.user_key, "GET", "organisations/restSearch", {"returnFormat": "json", "query": self.__anchored()})
            self.assertEqual(status, 400)
            self.assertNotIn("response", data or {})
            status, data = self.api(self.user_key, "POST", "organisations/restSearch?returnFormat=json&query[id]=1")
            self.assertEqual(status, 400)
            self.assertNotIn("response", data or {})

    def test_paging_and_order(self):
        o = self.orgs
        full = sorted(self.by_id)
        self.assertEqual(self.__ids(None), full)
        paged = []
        for page in range(1, 5):
            ids = self.__ids(None, extra={"limit": 2, "page": page})
            self.assertLessEqual(len(ids), 2)
            paged += ids
        self.assertEqual(paged, full)
        insensitive = [r["id"] for r in sorted(o.values(), key=lambda r: r["name"].lower())]
        binary = [r["id"] for r in sorted(o.values(), key=lambda r: r["name"])]
        self.assertNotEqual(insensitive, binary)
        with self.subTest("name"):
            ids = self.__ids(None, extra={"order": "name"})
            self.assertEqual(ids, insensitive)
            self.assertNotEqual(ids, binary)
        with self.subTest("name desc page 2"):
            self.assertEqual(self.__ids(None, extra={"order": "name desc", "limit": 2, "page": 2}),
                             insensitive[::-1][2:4])
        with self.subTest("date_created"):
            ids = self.__ids(None, extra={"order": "date_created"})
            self.assertEqual(ids[0], o["home"]["id"])
            self.assertEqual(sorted(ids), full)


if __name__ == '__main__':
    unittest.main()
