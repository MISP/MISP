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
        check_response(cls.admin_misp_connector.set_server_setting('Security.advanced_authkeys', False, force=True))
        cls.admin_misp_connector.global_pythonify = True
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

        # User try to change back trough API
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

    def test_username_in_response_header_api_access(self):
        with self.__setting("Security.username_in_response_header", True):
            logged_in = PyMISP(url, self.test_usr.authkey)

            response = logged_in._prepare_request('GET', 'users/view/me')
            self.assertIn("X-Username", response.headers)
            self.assertEqual(self.test_usr.email + "/API/default", response.headers["X-Username"])

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
            self.failIf(sg.uuid == hidden_sg.uuid)

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

        with self.assertRaises(Exception):
            send(logged_in, "POST", f"/sharingGroups/edit/{sg.id}", {"name": "New name1"})
        self.assertEqual(sg.name, send(logged_in, "GET", f"/sharingGroups/view/{sg.id}")["SharingGroup"]["name"])

        with self.assertRaises(Exception):
            send(logged_in, "POST", f"/sharingGroups/edit/{sg.uuid}", {"name": "New name2"})
        self.assertEqual(sg.name, send(logged_in, "GET", f"/sharingGroups/view/{sg.id}")["SharingGroup"]["name"])

        self.assertErrorResponse(logged_in.add_org_to_sharing_group(sg, self.test_org.uuid))
        self.assertErrorResponse(logged_in.remove_org_from_sharing_group(sg, org.uuid))
        self.assertErrorResponse(logged_in.delete_sharing_group(sg))

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
        self.assertEqual(len(user1.sightings(private_event)), 1, "User should see hos own sighting")

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
        user = self.admin_misp_connector.add_user(user)
        check_response(user)
        if org_id:
            self.assertEqual(int(org_id), int(user.org_id))
        if role_id:
            self.assertEqual(int(role_id), int(user.role_id))
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


if __name__ == '__main__':
    unittest.main()
