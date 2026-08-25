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

import json
import os
import re
import subprocess
import time
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


def _env(name, default, allow_empty=False):
    """Read an environment variable, falling back to `default`.

    With `allow_empty`, an explicitly empty value is honoured rather than
    treated as unset. That is how "MISP is not in a container" is expressed:
    `MISP_CONTAINER=""` has to mean "run php directly", not "use the default
    container name".
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    value = raw.strip()
    if value or allow_empty:
        return value
    return default


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
        self.ldap_update_user = _env("MISP_LDAP_UPDATE_USER", "1") not in (
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


MEMBEROF_MODULE_LDIF = """dn: cn=module{{0}},cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: {module}
"""

MEMBEROF_OVERLAY_LDIF = """dn: olcOverlay=memberof,{database}
changetype: add
objectClass: olcOverlayConfig
objectClass: olcMemberOf
olcOverlay: memberof
olcMemberOfRefInt: TRUE
olcMemberOfGroupOC: groupOfNames
olcMemberOfMemberAD: member
olcMemberOfMemberOfAD: memberOf
"""


def _directory_maintains_memberof(ldap_config):
    """True when a new group membership actually produces a memberOf value.

    Deliberately a functional probe rather than a schema lookup. OpenLDAP
    cannot unload a module, so once memberof.so has been loaded the attribute
    type stays advertised in the schema even if the overlay is removed --
    a schema check would report support that is not there.
    """
    probe = "memberof-probe-{}".format(uuid.uuid4().hex[:8])
    user_dn = "uid={},{}".format(probe, ldap_config.users_dn)
    group_dn = "cn={},{}".format(probe, ldap_config.groups_dn)
    try:
        connection = Connection(
            Server(ldap_config.uri),
            ldap_config.admin_dn,
            ldap_config.admin_password,
            auto_bind=True,
        )
    except LDAPException:
        return False

    try:
        if not connection.add(user_dn, "inetOrgPerson",
                              {"cn": probe, "sn": probe, "uid": probe}):
            return False
        if not connection.add(group_dn, "groupOfNames",
                              {"cn": probe, "member": [user_dn]}):
            return False
        connection.search(user_dn, "(objectClass=*)", search_scope="BASE",
                          attributes=["memberOf"])
        if not connection.entries:
            return False
        values = connection.entries[0].entry_attributes_as_dict.get("memberOf")
        return bool(values)
    except LDAPException:
        # On a server that never loaded the overlay, memberOf is not a known
        # attribute type at all and ldap3 raises rather than returning an
        # empty result. That is the state a freshly created container is in,
        # so it has to read as "unsupported", not as an error.
        return False
    finally:
        connection.delete(group_dn)
        connection.delete(user_dn)
        connection.unbind()


def _enable_memberof_overlay(ldap_config, container, module_path):
    """Load the memberof overlay into a containerised OpenLDAP.

    bitnami/openldap ships memberof.so but exposes no environment variable for
    it, and its data lives in the container layer rather than a volume, so a
    recreated container comes back without the overlay. Rather than making
    that a manual setup step, enable it on demand -- it is idempotent, and the
    alternative is a test that quietly skips forever.
    """
    def run(*command, stdin=None):
        return subprocess.run(
            ["docker", "exec"] + (["-i"] if stdin else []) + [container] + list(command),
            input=stdin, capture_output=True, text=True,
        )

    found = run(
        "ldapsearch", "-Y", "EXTERNAL", "-H", "ldapi:///", "-Q",
        "-b", "cn=config", "-s", "one", "(objectClass=olcDatabaseConfig)", "dn",
    )
    if found.returncode != 0:
        return False, "cannot read cn=config: {}".format(found.stderr.strip())

    # Matching on the DN here rather than with an (olcDatabase=*mdb) filter:
    # that attribute has no substring matching rule, so such a filter quietly
    # returns nothing at all.
    databases = [
        line[len("dn:"):].strip()
        for line in found.stdout.splitlines()
        if line.startswith("dn:") and "mdb" in line
    ]
    if not databases:
        return False, "no mdb database found under cn=config"

    # Applied as two calls, not one LDIF: the module may already be loaded
    # from an earlier run (OpenLDAP cannot unload one), and re-adding the
    # value fails in a way that would abort the overlay step with it.
    steps = [
        ("module", MEMBEROF_MODULE_LDIF.format(module=module_path),
         ("already exists", "type or value exists")),
        ("overlay", MEMBEROF_OVERLAY_LDIF.format(database=databases[0]),
         ("already exists",)),
    ]
    for name, ldif, benign in steps:
        applied = run("ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///",
                      stdin=ldif)
        if applied.returncode == 0:
            continue
        output = (applied.stderr + applied.stdout).lower()
        if any(phrase in output for phrase in benign):
            continue
        return False, "{} step failed: {}".format(
            name, applied.stderr.strip() or applied.stdout.strip()
        )
    return True, None


# LDAP_CAP_ACTIVE_DIRECTORY_OID, advertised in the root DSE by AD only.
ACTIVE_DIRECTORY_CAPABILITY = "1.2.840.113556.1.4.800"

# Auxiliary class letting a test entry carry userAccountControl, which is an
# Active Directory attribute no standard schema defines. The attribute uses
# AD's real OID and Integer syntax; the class OID is private to this suite.
AD_ACCOUNT_OBJECT_CLASS = "mispTestAdAccount"

AD_SCHEMA_LDIF = """dn: cn=misptest-ad,cn=schema,cn=config
changetype: add
objectClass: olcSchemaConfig
cn: misptest-ad
olcAttributeTypes: ( 1.2.840.113556.1.4.8 NAME 'userAccountControl' \
SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
olcObjectClasses: ( 1.3.6.1.4.1.53658.1.1 NAME '{object_class}' AUXILIARY \
MAY ( userAccountControl ) )
""".format(object_class=AD_ACCOUNT_OBJECT_CLASS)


def _directory_accepts_user_account_control(ldap_config):
    """Probe whether an entry may carry userAccountControl."""
    probe = "uac-probe-{}".format(uuid.uuid4().hex[:8])
    dn = "uid={},{}".format(probe, ldap_config.users_dn)
    try:
        connection = Connection(
            Server(ldap_config.uri), ldap_config.admin_dn,
            ldap_config.admin_password, auto_bind=True,
        )
    except LDAPException:
        return False

    try:
        return bool(connection.add(
            dn,
            ["inetOrgPerson", AD_ACCOUNT_OBJECT_CLASS],
            {"cn": probe, "sn": probe, "uid": probe, "userAccountControl": "512"},
        ))
    except LDAPException:
        return False
    finally:
        connection.delete(dn)
        connection.unbind()


@pytest.fixture(scope="session")
def user_account_control_supported(ldap_config, ldap_admin):
    """Whether test entries can carry userAccountControl, adding it if needed.

    No standard schema defines the attribute, so OpenLDAP rejects it outright.
    Rather than skip the ACCOUNTDISABLE tests, load a minimal schema for it,
    the same on-demand approach used for the memberof overlay.

    Takes `ldap_admin` because ldap3 validates object classes against the
    schema it read when that connection opened, and this fixture may add the
    class afterwards. Without re-reading it, every add() using the new class
    fails client-side even though the server would accept it -- which is
    exactly what happens on a directory that starts out without the schema.
    """
    if _directory_accepts_user_account_control(ldap_config):
        return True

    container = _env("LDAP_CONTAINER", "misp-docker-openldap-1", allow_empty=True)
    if not container:
        return False

    try:
        applied = subprocess.run(
            ["docker", "exec", "-i", container,
             "ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///"],
            input=AD_SCHEMA_LDIF, capture_output=True, text=True,
        )
    except OSError as exc:
        warnings.warn("Could not add the userAccountControl schema: {}".format(exc))
        return False

    if applied.returncode != 0:
        output = (applied.stderr + applied.stdout).lower()
        if "already exists" not in output:
            warnings.warn(
                "Could not add the userAccountControl schema: {}".format(
                    applied.stderr.strip() or applied.stdout.strip()
                )
            )
            return False

    # ldap3 checks object classes against the schema it read when the shared
    # connection opened, so it must re-read after the class is added or every
    # add() using it fails client-side while the server would accept it.
    try:
        ldap_admin.refresh_server_info()
    except LDAPException as exc:
        warnings.warn("Could not refresh the cached LDAP schema: {}".format(exc))
        return False

    return _directory_accepts_user_account_control(ldap_config)


@pytest.fixture(scope="session")
def active_directory(ldap_config):
    """Whether the directory under test is Active Directory.

    `ldapNestedGroups` relies on a matching rule only AD implements, so the
    tests covering it split on this rather than pretending either behaviour is
    universal.
    """
    try:
        server = Server(ldap_config.uri, get_info=ALL)
        connection = Connection(
            server, ldap_config.admin_dn, ldap_config.admin_password,
            auto_bind=True,
        )
    except LDAPException:
        return False

    try:
        capabilities = (server.info.other or {}).get("supportedCapabilities") or []
        return ACTIVE_DIRECTORY_CAPABILITY in [str(c) for c in capabilities]
    finally:
        connection.unbind()


@pytest.fixture(scope="session")
def memberof_supported(ldap_config):
    """Whether the directory maintains `memberOf`, enabling it if it can."""
    if _directory_maintains_memberof(ldap_config):
        return True

    container = _env("LDAP_CONTAINER", "misp-docker-openldap-1",
                     allow_empty=True)
    if not container or _env("LDAP_AUTO_MEMBEROF", "1") in ("0", "false", "no"):
        return False

    module = _env(
        "LDAP_MEMBEROF_MODULE",
        "/opt/bitnami/openldap/lib/openldap/memberof.so",
    )
    try:
        ok, error = _enable_memberof_overlay(ldap_config, container, module)
    except OSError as exc:
        warnings.warn("Could not enable the memberof overlay: {}".format(exc))
        return False

    if not ok:
        warnings.warn("Could not enable the memberof overlay: {}".format(error))
        return False

    return _directory_maintains_memberof(ldap_config)


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

    def add_user(self, uid=None, password="userpassword", mail=_UNSET,
                 base=None, object_classes=None, **extra):
        """Create an inetOrgPerson.

        `base` defaults to the search base MISP is configured with; pass the
        directory root to place an entry deliberately *outside* it.
        `object_classes` adds auxiliary classes, which is how attributes
        outside inetOrgPerson (such as userAccountControl) become allowed.
        """
        uid = uid or "misptest-{}".format(uuid.uuid4().hex[:10])
        if mail is _UNSET:
            mail = "{}@example.com".format(uid)
        base = base or self.config.users_dn
        first_rdn = base.split(",")[0]
        if first_rdn.lower().startswith("ou="):
            self.ensure_ou(base, first_rdn.split("=", 1)[1])
        dn = "uid={},{}".format(uid, base)
        attributes = {
            "cn": uid,
            "sn": uid,
            "uid": uid,
            "userPassword": password,
        }
        if mail:
            attributes["mail"] = mail
        attributes.update(extra)
        classes = ["inetOrgPerson"] + list(object_classes or [])
        self._add(dn, classes, attributes)
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

    def track_provisioned_email(self, email):
        """Register an address whose MISP account also needs deleting.

        add_user() does this for the addresses it generates; call it by hand
        when a test makes MISP name an account from something else, such as an
        ldapEmailField fallback.
        """
        self._provisioned_emails.append(email)

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


class MispInstanceConfig:
    """Reads and rewrites the running instance's `LdapAuth` settings.

    Uses MISP's own `tests/modify_config.php`, the same helper the docker image
    calls from `configure_misp.sh`, so the file is written exactly the way MISP
    writes it. CakePHP re-reads `config.php` on every request, so changes take
    effect on the next login with **no container restart**.

    `cake Admin setSetting` is not an option here: `LdapAuth.*` keys are not in
    MISP's settings schema and it rejects them with "No valid setting found".

    Note the docker entrypoint regenerates `config.php` from `LDAPAUTH_*`
    environment variables on container start, so anything written here is
    reverted by a restart. That is fine for tests, which restore the original
    themselves, but it means this is not a way to configure an instance.
    """

    def __init__(self, container, script, php_user="www-data",
                 config_file=None, settle_seconds=None):
        self.container = container
        self.script = script
        self.php_user = php_user
        self.config_file = config_file or "/var/www/MISP/app/Config/config.php"
        self._settle_seconds = settle_seconds

    def _argv(self, *command):
        argv = []
        if self.container:
            argv += ["docker", "exec", self.container]
        if self.php_user:
            argv += ["sudo", "-u", self.php_user]
        return argv + list(command)

    def _exec(self, *command):
        result = subprocess.run(
            self._argv(*command), capture_output=True, text=True
        )
        if result.returncode != 0:
            raise RuntimeError(
                "{} failed ({}): {}".format(
                    command[0], result.returncode, result.stderr.strip()
                )
            )
        return result.stdout

    @property
    def settle_seconds(self):
        """How long to wait for PHP to notice a rewritten config.php.

        PHP's opcache only re-stats a file every `opcache.revalidate_freq`
        seconds, so a config written moments ago is invisible to the next
        request and MISP keeps executing the previous one. Tests that write a
        setting and immediately log in would otherwise assert against config
        that is not in effect yet -- silently, and only sometimes.
        """
        if self._settle_seconds is None:
            self._settle_seconds = self._detect_settle_seconds()
        return self._settle_seconds

    def _detect_settle_seconds(self):
        try:
            raw = self._exec(
                "php", "-r",
                'echo ini_get("opcache.validate_timestamps"), ",",'
                ' ini_get("opcache.revalidate_freq");',
            )
            validates, freq = raw.strip().split(",")
        except (RuntimeError, OSError, ValueError):
            return 5.0

        if validates in ("", "0"):
            raise RuntimeError(
                "opcache.validate_timestamps is off on this instance, so "
                "config.php changes never take effect without restarting PHP. "
                "Set MISP_CONFIG_SETTLE_SECONDS only if you know otherwise."
            )
        # opcache may re-stat the file anywhere up to revalidate_freq seconds
        # *after* our write, and the recompile happens on the request after
        # that, so one full cycle of margin is not enough. Measured on
        # freq=2: 2.5s still served the old config, 5s was reliable.
        return max(1.0, float(freq or 0) * 2 + 1.0)

    def _settle(self):
        time.sleep(self.settle_seconds)

    def read(self):
        """Return the whole config, without writing anything.

        `modify_config.php` always rewrites the file, even for a no-op merge,
        so reading through it would churn the mtime on every call. Including
        the file directly keeps reads free of side effects.
        """
        raw = self._exec(
            "php", "-r",
            'include "{}"; echo json_encode($config);'.format(self.config_file),
        )
        return json.loads(raw)

    def replace(self, config):
        """Write `config` verbatim, then wait for PHP to pick it up.

        Deliberately not `modify`: that merges recursively, so shrinking a list
        setting such as `ldapEmailField` would leave the old trailing entries
        in place. Replacing a config we just read avoids that entirely.
        """
        previous = self._exec(
            "php", self.script, "replace", json.dumps(config)
        )
        self._settle()
        return json.loads(previous)

    def available(self):
        try:
            self.read()
            return True
        except (RuntimeError, OSError, ValueError):
            return False


class LdapSettings:
    """Applies `LdapAuth` overrides to a live instance and restores them."""

    def __init__(self, instance_config):
        self.instance_config = instance_config
        self.original = instance_config.read()

    def set(self, **overrides):
        """Merge `overrides` into the LdapAuth block and write it out.

        Values are whatever the plugin expects: `ldapDefaultRoleId` may be an
        int or a group->role dict, `ldapEmailField` a list, and so on.
        """
        config = self.instance_config.read()
        config.setdefault("LdapAuth", {}).update(overrides)
        self.instance_config.replace(config)
        return config["LdapAuth"]

    def current(self):
        return self.instance_config.read().get("LdapAuth", {})

    def restore(self):
        self.instance_config.replace(self.original)


class MispConsole:
    """Runs `app/Console/cake` against the instance under test."""

    def __init__(self, container, php_user, app_dir):
        self.container = container
        self.php_user = php_user
        self.app_dir = app_dir

    def run(self, *arguments):
        command = []
        if self.container:
            command += ["docker", "exec", "-w", self.app_dir, self.container]
        if self.php_user:
            command += ["sudo", "-u", self.php_user]
        command += ["app/Console/cake"] + list(arguments)

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=None if self.container else self.app_dir,
        )
        # The console prints diagnostics to both streams and LdapAuth.debug
        # makes the LDAP library very chatty, so hand back everything and let
        # the caller look for what it cares about.
        return result.returncode, result.stdout + result.stderr

    def available(self):
        try:
            code, output = self.run("User")
            return code == 0 or "check_validity" in output
        except OSError:
            return False


@pytest.fixture(scope="session")
def misp_console():
    """CLI runner, or None when the console cannot be reached."""
    console = MispConsole(
        container=_env("MISP_CONTAINER", "misp-docker-misp-core-1",
                       allow_empty=True),
        php_user=_env("MISP_PHP_USER", "www-data", allow_empty=True),
        app_dir=_env("MISP_APP_DIR", "/var/www/MISP"),
    )
    return console if console.available() else None


@pytest.fixture(scope="session")
def misp_instance_config():
    """Helper for mutating the instance's config, or None when unreachable."""
    settle = _env("MISP_CONFIG_SETTLE_SECONDS", "")
    instance = MispInstanceConfig(
        # Both accept an explicit empty value: no container means run php on
        # this host, no php user means run it as whoever we already are.
        container=_env("MISP_CONTAINER", "misp-docker-misp-core-1",
                       allow_empty=True),
        script=_env("MISP_CONFIG_SCRIPT", "/var/www/MISP/tests/modify_config.php"),
        php_user=_env("MISP_PHP_USER", "www-data", allow_empty=True),
        config_file=_env("MISP_CONFIG_FILE", "/var/www/MISP/app/Config/config.php"),
        settle_seconds=float(settle) if settle else None,
    )
    return instance if instance.available() else None


# Substrings identifying accounts this suite provisions. Used only by the
# end-of-session sweep, which is a backstop for the per-test cleanup.
TEST_ACCOUNT_MARKERS = (
    "misptest-", "duplicate-", "fallback-", "jdoe-", "cased-", "local-",
    "renamed-", "upn-", "ldaptest-",
)


@pytest.fixture(scope="session", autouse=True)
def restore_instance_config(misp_instance_config):
    """Put the instance's LdapAuth settings back when the session ends.

    `ldap_settings` already restores per test, but a run interrupted mid-test
    -- a timeout, a Ctrl-C -- never reaches that teardown and leaves the
    instance configured for whatever it was exercising. `updateUser: false` is
    the nasty one: the plugin then returns existing users untouched, so group
    and role mappings silently stop applying and *later runs* fail in tests
    that look unrelated.

    This is a second line of defence inside the session. A SIGKILL still
    escapes it, so the README documents how to check and repair by hand.
    """
    if misp_instance_config is None:
        yield
        return

    original = misp_instance_config.read()
    try:
        yield
    finally:
        misp_instance_config.replace(original)


@pytest.fixture(scope="session", autouse=True)
def sweep_provisioned_accounts(misp_admin_api):
    """Delete any accounts this suite provisioned that survived their test."""
    yield
    if misp_admin_api is None:
        return

    for entry in misp_admin_api.users():
        email = entry.get("User", entry).get("email", "")
        if not any(marker in email for marker in TEST_ACCOUNT_MARKERS):
            continue
        try:
            misp_admin_api.delete_user_by_email(email)
            warnings.warn("Swept leftover MISP account {}".format(email))
        except requests.RequestException as exc:
            warnings.warn("Could not sweep {}: {}".format(email, exc))


@pytest.fixture
def misp_org(misp_admin_api):
    """A throwaway local organisation to place LDAP users into."""
    if misp_admin_api is None:
        pytest.skip("needs AUTH to create an organisation")

    org = misp_admin_api.create_org("ldaptest-{}".format(uuid.uuid4().hex[:8]))
    yield org
    misp_admin_api.delete_org(org["id"])


@pytest.fixture
def another_misp_org(misp_admin_api):
    """A second throwaway organisation, for precedence between two of them.

    A fixture rather than an inline create/delete so pytest tears it down
    after `ldap_fixtures` has removed the accounts: MISP refuses to delete an
    organisation that still has users in it.
    """
    if misp_admin_api is None:
        pytest.skip("needs AUTH to create an organisation")

    org = misp_admin_api.create_org("ldaptest-{}".format(uuid.uuid4().hex[:8]))
    yield org
    misp_admin_api.delete_org(org["id"])


@pytest.fixture
def ldap_settings(misp_instance_config):
    """Change LdapAuth settings for one test, then put them back.

    Skips when the instance's config cannot be reached, since a test that
    silently ran against unchanged settings would assert the wrong thing.
    """
    if misp_instance_config is None:
        pytest.skip(
            "cannot reach the instance's config.php; set MISP_CONTAINER "
            "(or MISP_CONTAINER='' when MISP runs on this host)"
        )

    settings = LdapSettings(misp_instance_config)
    try:
        yield settings
    finally:
        settings.restore()


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

    def create_user(self, email, password, org_id=1, role_id=3):
        """Create a database-only user, for testing the mixedAuth fallback."""
        response = self.session.post(
            self._url("/admin/users/add"),
            data=json.dumps({"User": {
                "email": email,
                "org_id": org_id,
                "role_id": role_id,
                "password": password,
                "confirm_password": password,
                "change_pw": 0,
            }}),
            verify=self.config.verify_ssl,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()["User"]

    def create_org(self, name):
        """Create a local organisation, for the org-mapping tests."""
        response = self.session.post(
            self._url("/admin/organisations/add"),
            data=json.dumps({"Organisation": {"name": name, "local": True}}),
            verify=self.config.verify_ssl,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()["Organisation"]

    def delete_org(self, org_id):
        response = self.session.post(
            self._url("/admin/organisations/delete/{}".format(org_id)),
            verify=self.config.verify_ssl,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    def view_user(self, user_id):
        response = self.session.get(
            self._url("/admin/users/view/{}.json".format(user_id)),
            verify=self.config.verify_ssl,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()["User"]

    def set_disabled(self, user_id, disabled):
        """Enable or disable a MISP account, the way an admin would."""
        response = self.session.post(
            self._url("/admin/users/edit/{}".format(user_id)),
            data=json.dumps({"User": {"id": user_id, "disabled": bool(disabled)}}),
            verify=self.config.verify_ssl,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

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
