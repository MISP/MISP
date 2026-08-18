"""Shared fixtures for the LdapAuth plugin end-to-end test suite.

The suite drives the real MISP login form against a real LDAP directory,
so it exercises app/Plugin/LdapAuth/Controller/Component/Auth/LdapAuthenticate.php
rather than re-implementing its logic in Python.

Everything is env-driven; the defaults match the openldap/misp-core docker
setup used for local development:

    LDAP_URI            ldap://127.0.0.1:1389
    LDAP_ADMIN_DN       cn=admin,dc=example,dc=com
    LDAP_ADMIN_PASSWORD password
    LDAP_READER_DN      cn=testuser,ou=users,dc=example,dc=com
                        (MISP's LdapAuth.ldapReaderUser)
    LDAP_READER_PASSWORD userpassword
    LDAP_ROOT           dc=example,dc=com
    LDAP_SEARCH_BASE    ou=users,dc=example,dc=com   (MISP's LdapAuth.ldapDn)
    LDAP_USERS_OU       ou=users
    LDAP_GROUPS_OU      ou=groups
    MISP_URL            https://localhost
    MISP_VERIFY_SSL     0
    AUTH                <admin authkey>  (used to delete auto-provisioned users)
    MISP_LDAP_ORG_ID    1   (MISP's LdapAuth.ldapDefaultOrgId)
    MISP_LDAP_ROLE_ID   3   (MISP's LdapAuth.ldapDefaultRoleId)
    MISP_LDAP_MIXED_AUTH 0  (MISP's LdapAuth.mixedAuth)
"""

import os
import re
import uuid
import warnings

import pytest
import requests
import urllib3
from ldap3 import ALL, Connection, Server
from ldap3.core.exceptions import LDAPException

urllib3.disable_warnings()


# Distinguishes "caller did not specify a mail" (auto-generate one) from
# "caller explicitly wants no mail attribute" (mail=None).
_UNSET = object()


def pytest_configure(config):
    # Self-signed certs are the norm for a local MISP container; the suite
    # opts out of verification on purpose (MISP_VERIFY_SSL), so don't spam.
    config.addinivalue_line(
        "filterwarnings",
        "ignore::urllib3.exceptions.InsecureRequestWarning",
    )


def _env(name, default):
    value = os.environ.get(name, "").strip()
    return value if value else default


class LdapConfig:
    def __init__(self):
        self.uri = _env("LDAP_URI", "ldap://127.0.0.1:1389")
        self.admin_dn = _env("LDAP_ADMIN_DN", "cn=admin,dc=example,dc=com")
        self.admin_password = _env("LDAP_ADMIN_PASSWORD", "password")
        # Mirror of MISP's LdapAuth.ldapReaderUser/ldapReaderPassword. The
        # plugin binds with these before it can search for anyone, so if they
        # are wrong EVERY login fails -- and it fails with the error attributed
        # to the person logging in. Kept separate from the admin credentials
        # above precisely so a broken reader is visible as its own failure.
        self.reader_dn = _env(
            "LDAP_READER_DN", "cn=testuser,ou=users,dc=example,dc=com"
        )
        self.reader_password = _env("LDAP_READER_PASSWORD", "userpassword")
        self.root = _env("LDAP_ROOT", "dc=example,dc=com")
        self.users_ou = _env("LDAP_USERS_OU", "ou=users")
        self.groups_ou = _env("LDAP_GROUPS_OU", "ou=groups")
        # MISP's LdapAuth.ldapDn. It is NOT necessarily the directory root --
        # narrowing it to the users OU is common, and it decides which entries
        # the plugin can see at all. Fixture users are created here so they are
        # actually reachable by the plugin's search.
        self.search_base = _env(
            "LDAP_SEARCH_BASE", "{},{}".format(self.users_ou, self.root)
        )

    @property
    def users_dn(self):
        return self.search_base

    @property
    def groups_dn(self):
        return "{},{}".format(self.groups_ou, self.root)


class MispConfig:
    def __init__(self):
        self.url = _env("MISP_URL", "https://localhost").rstrip("/")
        self.verify_ssl = _env("MISP_VERIFY_SSL", "0") not in ("0", "false", "no")
        # Mirror of the instance's LdapAuth settings, so the tests can assert
        # what the plugin is supposed to do rather than what it happens to do.
        self.ldap_org_id = int(_env("MISP_LDAP_ORG_ID", "1"))
        self.ldap_role_id = int(_env("MISP_LDAP_ROLE_ID", "3"))
        self.ldap_mixed_auth = _env("MISP_LDAP_MIXED_AUTH", "0") not in (
            "0", "false", "no",
        )
        # A successful LDAP login auto-provisions a local MISP user that
        # outlives the directory fixture, so the suite needs an admin authkey
        # to clean up after itself. Same variable the other testlive_* suites
        # use; MISP_ADMIN_KEY is accepted as an alias.
        self.admin_key = _env("AUTH", "") or _env("MISP_ADMIN_KEY", "")


@pytest.fixture(scope="session")
def ldap_config():
    return LdapConfig()


@pytest.fixture(scope="session")
def misp_config():
    return MispConfig()


@pytest.fixture(scope="session")
def ldap_admin(ldap_config):
    """Bound ldap3 connection as the directory admin.

    Skips the whole suite when the directory is unreachable, so a missing
    docker container reads as "not run" instead of a wall of failures.
    """
    server = Server(ldap_config.uri, get_info=ALL)
    try:
        connection = Connection(
            server,
            ldap_config.admin_dn,
            ldap_config.admin_password,
            auto_bind=True,
            raise_exceptions=False,
        )
    except LDAPException as exc:
        pytest.skip("LDAP server {} unreachable: {}".format(ldap_config.uri, exc))

    if not connection.bound:
        pytest.skip(
            "Could not bind as {} on {}: {}".format(
                ldap_config.admin_dn, ldap_config.uri, connection.result
            )
        )

    yield connection
    connection.unbind()


class LdapFixtureFactory:
    """Creates directory entries and removes them when the test ends."""

    def __init__(self, connection, config, misp_admin_api=None):
        self.connection = connection
        self.config = config
        self.misp_admin_api = misp_admin_api
        self._created = []
        self._provisioned_emails = []

    def _add(self, dn, object_classes, attributes):
        if not self.connection.add(dn, object_classes, attributes):
            raise AssertionError(
                "Failed to create {}: {}".format(dn, self.connection.result)
            )
        # Prepend so children are deleted before their parents.
        self._created.insert(0, dn)
        return dn

    def ensure_ou(self, dn, ou_name):
        """Create an organizationalUnit only if it is missing (never cleaned up)."""
        self.connection.search(dn, "(objectClass=*)", search_scope="BASE")
        if self.connection.entries:
            return dn
        if not self.connection.add(dn, "organizationalUnit", {"ou": ou_name}):
            raise AssertionError(
                "Failed to create {}: {}".format(dn, self.connection.result)
            )
        return dn

    def add_user(self, uid=None, password="userpassword", mail=_UNSET, **extra):
        uid = uid or "misptest-{}".format(uuid.uuid4().hex[:10])
        if mail is _UNSET:
            mail = "{}@example.com".format(uid)
        base = self.config.users_dn
        first_rdn = base.split(",")[0]
        if first_rdn.lower().startswith("ou="):
            self.ensure_ou(base, first_rdn.split("=", 1)[1])
        dn = "uid={},{}".format(uid, self.config.users_dn)
        attributes = {
            "cn": uid,
            "sn": uid,
            "uid": uid,
            "userPassword": password,
        }
        if mail:
            attributes["mail"] = mail
        attributes.update(extra)
        self._add(dn, "inetOrgPerson", attributes)
        if mail:
            # Logging in as this user makes MISP create a local account for it.
            self._provisioned_emails.append(mail)
        return {"dn": dn, "uid": uid, "mail": mail, "password": password}

    def add_group(self, cn=None, members=()):
        cn = cn or "misptest-group-{}".format(uuid.uuid4().hex[:8])
        self.ensure_ou(self.config.groups_dn, self.config.groups_ou)
        dn = "cn={},{}".format(cn, self.config.groups_dn)
        members = list(members) or [self.config.admin_dn]
        self._add(dn, "groupOfNames", {"cn": cn, "member": members})
        return {"dn": dn, "cn": cn, "member": members}

    def cleanup(self):
        for dn in self._created:
            self.connection.delete(dn)
        self._created = []

        if self.misp_admin_api is None:
            self._provisioned_emails = []
            return

        for email in self._provisioned_emails:
            try:
                self.misp_admin_api.delete_user_by_email(email)
            except requests.RequestException as exc:
                warnings.warn("Could not delete MISP user {}: {}".format(email, exc))
        self._provisioned_emails = []


@pytest.fixture
def ldap_fixtures(ldap_admin, ldap_config, misp_admin_api):
    factory = LdapFixtureFactory(ldap_admin, ldap_config, misp_admin_api)
    yield factory
    factory.cleanup()


class MispAdminApi:
    """Thin admin-API client, used only to undo what the login tests provision."""

    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": config.admin_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    def _url(self, path):
        return "{}/{}".format(self.config.url, path.lstrip("/"))

    def users(self):
        response = self.session.get(
            self._url("/admin/users.json"),
            verify=self.config.verify_ssl,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    def find_user_id(self, email):
        """Return the MISP user id for an email, or None.

        The index endpoint ignores an email filter in the body, so the match is
        done here rather than server-side.
        """
        for entry in self.users():
            user = entry.get("User", entry)
            if user.get("email") == email:
                return user["id"]
        return None

    def delete_user(self, user_id):
        response = self.session.post(
            self._url("/admin/users/delete/{}".format(user_id)),
            verify=self.config.verify_ssl,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    def delete_user_by_email(self, email):
        """Delete the user with this email if it exists. Returns True if deleted."""
        user_id = self.find_user_id(email)
        if user_id is None:
            return False
        self.delete_user(user_id)
        return True


@pytest.fixture(scope="session")
def misp_admin_api(misp_config):
    """Admin API client, or None when AUTH is not set.

    Without it the suite still passes -- fixture emails are unique per test --
    but auto-provisioned MISP users pile up in the database.
    """
    if not misp_config.admin_key:
        warnings.warn(
            "AUTH is not set: MISP users auto-provisioned by the login tests "
            "will not be cleaned up.",
            stacklevel=2,
        )
        return None

    api = MispAdminApi(misp_config)
    try:
        api.users()
    except requests.RequestException as exc:
        pytest.skip("AUTH key rejected by {}: {}".format(misp_config.url, exc))
    return api


class MispClient:
    """Minimal MISP web-session client that satisfies CakePHP's SecurityComponent."""

    TOKEN_INPUT = re.compile(
        r'<input[^>]*\bname="(?P<name>data\[_Token\]\[[^"]+\]|_method)"'
        r'[^>]*\bvalue="(?P<value>[^"]*)"',
        re.IGNORECASE,
    )

    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.login_url = None

    def url(self, path):
        return "{}/{}".format(self.config.url, path.lstrip("/"))

    def get(self, path, **kwargs):
        kwargs.setdefault("verify", self.config.verify_ssl)
        kwargs.setdefault("timeout", 30)
        return self.session.get(self.url(path), **kwargs)

    def post(self, path, data, **kwargs):
        kwargs.setdefault("verify", self.config.verify_ssl)
        kwargs.setdefault("timeout", 30)
        return self.session.post(self.url(path), data=data, **kwargs)

    def login_form_tokens(self):
        """Fetch /users/login and return its hidden CSRF/SecurityComponent fields."""
        response = self.get("/users/login")
        response.raise_for_status()
        # MISP commonly 301s http -> https; requests turns a redirected POST
        # into a GET, so remember where the form actually lives and post there.
        self.login_url = response.url
        tokens = {
            match.group("name"): match.group("value")
            for match in self.TOKEN_INPUT.finditer(response.text)
        }
        if "data[_Token][key]" not in tokens:
            raise AssertionError(
                "No CakePHP security token in the login form; "
                "is {} really a MISP instance?".format(response.url)
            )
        return tokens

    def login(self, email, password):
        """POST the login form. Returns the final response after redirects."""
        data = self.login_form_tokens()
        data["data[User][email]"] = email
        data["data[User][password]"] = password
        return self.session.post(
            self.login_url,
            data=data,
            verify=self.config.verify_ssl,
            timeout=30,
        )

    def logout(self):
        return self.get("/users/logout")

    def assert_logged_in(self, email):
        """Assert an authenticated session, explaining the usual causes if not.

        A failed LDAP login looks identical from the outside no matter why it
        failed, so point at the server-side log instead of asserting on a bare
        status code.
        """
        if self.is_authenticated():
            return
        raise AssertionError(
            "{} was not logged in. Check, in order:\n"
            "  1. LdapAuth.Ldap is listed in Security.auth\n"
            "  2. LdapAuth.ldapReaderUser is a full DN that binds "
            "(see test_plugin_reader_user_can_bind)\n"
            "  3. the user is inside LdapAuth.ldapDn and has the "
            "ldapSearchAttribute\n"
            "MISP logs the real reason to app/tmp/logs/error.log as "
            "[LdapAuth].".format(email)
        )

    def is_authenticated(self):
        """True when the current session resolves to a logged-in MISP user."""
        response = self.get("/users/view/me.json")
        if response.status_code != 200:
            return False
        try:
            payload = response.json()
        except ValueError:
            return False
        return "User" in payload

    def current_user(self):
        response = self.get("/users/view/me.json")
        response.raise_for_status()
        return response.json()["User"]


@pytest.fixture
def misp(misp_config):
    client = MispClient(misp_config)
    yield client
    client.session.close()
