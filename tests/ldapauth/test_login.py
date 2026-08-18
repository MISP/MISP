"""End-to-end login tests for the LdapAuth plugin.

Every test here drives the real MISP login form, so the code under test is
LdapAuthenticate::getUser(). Fixture users are created in the directory with a
unique uid/mail per test, which keeps repeated runs isolated even though MISP
auto-provisions a local user row on first successful login.

Requires `LdapAuth.Ldap` in the instance's `Security.auth` -- see README.md.
"""

import pytest
from ldap3 import SUBTREE


def test_ldap_user_can_log_in(misp, ldap_fixtures):
    """The happy path: a directory user authenticates against MISP."""
    user = ldap_fixtures.add_user()

    misp.login(user["mail"], user["password"])

    misp.assert_logged_in(user["mail"])


def test_login_provisions_user_with_configured_defaults(misp, misp_config,
                                                        ldap_fixtures):
    """First login creates the MISP user with ldapDefaultOrgId/RoleId."""
    user = ldap_fixtures.add_user()

    misp.login(user["mail"], user["password"])
    misp.assert_logged_in(user["mail"])

    misp_user = misp.current_user()
    assert misp_user["email"] == user["mail"]
    assert int(misp_user["org_id"]) == misp_config.ldap_org_id
    assert int(misp_user["role_id"]) == misp_config.ldap_role_id
    assert int(misp_user["disabled"]) == 0


def test_login_is_idempotent_across_sessions(misp_config, ldap_fixtures):
    """A second login reuses the provisioned account instead of duplicating it."""
    from conftest import MispClient

    user = ldap_fixtures.add_user()

    first = MispClient(misp_config)
    first.login(user["mail"], user["password"])
    first.assert_logged_in(user["mail"])
    first_id = first.current_user()["id"]
    first.session.close()

    second = MispClient(misp_config)
    second.login(user["mail"], user["password"])
    second.assert_logged_in(user["mail"])
    assert second.current_user()["id"] == first_id
    second.session.close()


def test_wrong_password_is_refused(misp, ldap_fixtures):
    """A valid user with a bad password must not get a session."""
    user = ldap_fixtures.add_user()

    misp.login(user["mail"], "definitely-not-the-password")

    assert not misp.is_authenticated()


def test_user_without_search_attribute_cannot_log_in(misp, ldap_fixtures,
                                                     ldap_admin, ldap_config):
    """A user missing `mail` is invisible to the default ldapSearchAttribute.

    This is exactly why the bitnami `testuser` entry cannot log in: it has a
    uid but no mail, so the plugin's filter never matches it.
    """
    user = ldap_fixtures.add_user(mail=None)

    found = ldap_admin.search(
        ldap_config.search_base,
        "(&(objectClass=inetOrgPerson)(uid={}))".format(user["uid"]),
        search_scope=SUBTREE,
        attributes=["mail"],
    )
    assert found, "fixture user should exist in the directory"
    # ldap3 reports a requested-but-absent attribute as an empty list.
    attributes = ldap_admin.entries[0].entry_attributes_as_dict
    assert not attributes.get("mail"), "fixture user should have no mail"

    misp.login("{}@example.com".format(user["uid"]), user["password"])
    assert not misp.is_authenticated()


def test_unknown_user_is_refused(misp, misp_config):
    """A user that exists in neither LDAP nor MISP gets no session."""
    misp.login("no-such-user-anywhere@example.com", "irrelevant")
    assert not misp.is_authenticated()


def test_local_user_follows_mixed_auth_setting(misp, misp_config):
    """With mixedAuth off there is no database fallback, and vice versa.

    The built-in admin has no LDAP entry, so it is the cleanest probe for
    whether the plugin falls through to local authentication.
    """
    misp.login("admin@admin.test", "admin")

    if misp_config.ldap_mixed_auth:
        pytest.skip("mixedAuth is enabled; local fallback needs valid credentials")
    assert not misp.is_authenticated(), (
        "mixedAuth is disabled, so the local admin must not be able to "
        "authenticate through the login form"
    )


def test_logout_ends_the_session(misp, ldap_fixtures):
    """Logging out must actually drop the authenticated session."""
    user = ldap_fixtures.add_user()

    misp.login(user["mail"], user["password"])
    misp.assert_logged_in(user["mail"])

    misp.logout()
    assert not misp.is_authenticated()
