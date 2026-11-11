"""Connectivity checks for the LdapAuth end-to-end suite.

These tests do not exercise the plugin's login path yet; they verify the two
moving parts the rest of the suite depends on -- a reachable LDAP directory
that accepts the reader bind, and a MISP instance serving a login form.
When one of these fails, every other LdapAuth test failure is noise.
"""

import pytest
from ldap3 import SUBTREE, Connection, Server


def test_ldap_bind_as_admin(ldap_admin, ldap_config):
    """The credentials the suite uses to manage its own fixtures."""
    assert ldap_admin.bound
    assert ldap_admin.extend.standard.who_am_i() == "dn:{}".format(
        ldap_config.admin_dn
    )


def test_plugin_reader_user_can_bind(ldap_config):
    """The bind LdapAuthenticate performs before it can search for anyone.

    This is the single highest-value check in the suite. The plugin binds as
    ldapReaderUser first, so a bad value here fails every login while the error
    surfaces against whoever tried to log in. A bare username (`testuser`
    instead of its full DN) is the classic version of this and yields
    `invalidDNSyntax`.
    """
    connection = Connection(
        Server(ldap_config.uri),
        ldap_config.reader_dn,
        ldap_config.reader_password,
        auto_bind=False,
    )
    bound = connection.bind()
    if not bound:
        pytest.fail(
            "Reader bind as {!r} failed: {}.\n"
            "MISP's LdapAuth.ldapReaderUser must be a full DN and must match "
            "LDAP_READER_DN. Every login fails until this binds.".format(
                ldap_config.reader_dn,
                connection.result.get("description"),
            )
        )
    connection.unbind()


def test_ldap_exposes_configured_base_dn(ldap_admin, ldap_config):
    """ldapDn must be a naming context the server actually serves."""
    assert ldap_config.root in ldap_admin.server.info.naming_contexts

    found = ldap_admin.search(
        ldap_config.root, "(objectClass=*)", search_scope="BASE"
    )
    assert found, ldap_admin.result
    assert ldap_admin.entries[0].entry_dn.lower() == ldap_config.root.lower()


def test_ldap_search_returns_no_match_for_unknown_mail(ldap_admin, ldap_config):
    """The default ldapSearchAttribute (mail) yields an empty, non-error result."""
    found = ldap_admin.search(
        ldap_config.root,
        "(&(objectClass=inetOrgPerson)(mail=does-not-exist@example.com))",
        search_scope=SUBTREE,
        attributes=["mail"],
    )
    assert ldap_admin.result["description"] == "success", ldap_admin.result
    assert found is False
    assert ldap_admin.entries == []


def test_fixture_user_is_searchable_and_can_bind(ldap_admin, ldap_config,
                                                 ldap_fixtures):
    """Mirrors the plugin's flow: search by mail, then bind as the found DN."""
    user = ldap_fixtures.add_user()

    found = ldap_admin.search(
        ldap_config.root,
        "(&(objectClass=inetOrgPerson)(mail={}))".format(user["mail"]),
        search_scope=SUBTREE,
        attributes=["mail"],
    )
    assert found, ldap_admin.result
    assert len(ldap_admin.entries) == 1
    assert ldap_admin.entries[0].entry_dn == user["dn"]

    user_connection = Connection(
        Server(ldap_config.uri),
        user["dn"],
        user["password"],
        auto_bind=True,
    )
    assert user_connection.bound
    user_connection.unbind()


def test_fixture_user_bind_rejects_wrong_password(ldap_config, ldap_fixtures):
    """A bad password must fail the bind rather than silently succeed."""
    user = ldap_fixtures.add_user()

    user_connection = Connection(
        Server(ldap_config.uri),
        user["dn"],
        "definitely-not-the-password",
        auto_bind=False,
    )
    assert user_connection.bind() is False
    assert user_connection.result["description"] == "invalidCredentials"


def test_misp_login_form_is_served(misp):
    """MISP is up and its login form carries CakePHP's security tokens."""
    response = misp.get("/users/login")
    assert response.status_code == 200, response.text[:500]

    tokens = misp.login_form_tokens()
    assert tokens["data[_Token][key]"]
    assert "data[_Token][fields]" in tokens
    assert 'name="data[User][email]"' in response.text
    assert 'name="data[User][password]"' in response.text


def test_instance_settings_match_what_the_suite_assumes(misp_config,
                                                        misp_instance_config):
    """The instance's LdapAuth block still matches the suite's baseline.

    Several tests rewrite these settings and restore them afterwards, but a run
    interrupted mid-test never reaches its teardown and leaves the instance
    configured for whatever it was exercising. `updateUser: false` is the worst
    of those: the plugin then returns existing users untouched, so role and
    organisation mappings silently stop applying and later runs fail in tests
    that look entirely unrelated.

    Checking it here turns that into one obvious failure instead of a handful
    of misleading ones.
    """
    if misp_instance_config is None:
        pytest.skip("cannot read the instance's config.php")

    settings = misp_instance_config.read().get("LdapAuth", {})
    drifted = {}

    if bool(settings.get("updateUser")) is not misp_config.ldap_update_user:
        drifted["updateUser"] = settings.get("updateUser")
    if bool(settings.get("mixedAuth")) is not misp_config.ldap_mixed_auth:
        drifted["mixedAuth"] = settings.get("mixedAuth")
    if int(settings.get("ldapDefaultOrgId", 0)) != misp_config.ldap_org_id:
        drifted["ldapDefaultOrgId"] = settings.get("ldapDefaultOrgId")
    role = settings.get("ldapDefaultRoleId")
    if not isinstance(role, dict) and int(role or 0) != misp_config.ldap_role_id:
        drifted["ldapDefaultRoleId"] = role
    for left_over in ("ldapOrgField", "ldapOrgGroupMapping", "ldapRoleField",
                      "ldapRoleGroupMapping", "ldapSearchFilter",
                      "ldapNestedGroups", "ldapCheckUserAccountControl",
                      "ldapHeaderAuth"):
        if settings.get(left_over):
            drifted[left_over] = settings.get(left_over)

    assert not drifted, (
        "The instance's LdapAuth settings have drifted from the suite's "
        "baseline: {}. A previous run was probably interrupted before it could "
        "restore them. Fix the values in app/Config/config.php, or override "
        "the MISP_LDAP_* variables if this instance is meant to differ."
        .format(drifted)
    )


def test_misp_session_starts_unauthenticated(misp):
    """Baseline for the login tests: no session means no current user."""
    misp.get("/users/login")
    assert misp.is_authenticated() is False
