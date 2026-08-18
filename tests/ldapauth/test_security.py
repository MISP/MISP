"""Hardening tests for the LdapAuth plugin.

These cover the ways a login must be *refused*, plus one case where a refusal
is silently undone. Each was verified against a live instance before being
written, so a failure here means real behaviour changed rather than an
assumption being wrong.
"""

import pytest


# Payloads aimed at the LDAP search filter built in getLdapUserData(). The
# plugin runs ldap_escape() on the submitted address; these pin that it stays.
INJECTION_PAYLOADS = [
    "*",
    "*@example.com",
    "*)(objectClass=*",
    "admin@admin.test)(|(mail=*",
    r"\2a",
]


def test_empty_password_is_refused(misp, ldap_fixtures):
    """An empty password must never authenticate.

    LdapAuthenticate passes the submitted password straight to ldap_bind()
    with no empty check. An empty password is an *unauthenticated bind* in
    LDAP terms, which some servers answer with success -- that would be a
    complete authentication bypass for any known account.

    OpenLDAP refuses it (`Server is unwilling to perform`), so the protection
    here comes from the directory rather than from the plugin. That is exactly
    why this test exists: it fails loudly if the directory is ever swapped for
    one that permits unauthenticated binds.
    """
    user = ldap_fixtures.add_user()

    misp.login(user["mail"], "")

    assert not misp.is_authenticated(), (
        "Empty password authenticated {}. The LDAP server accepted an "
        "unauthenticated bind and the plugin has no empty-password guard."
        .format(user["mail"])
    )


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_search_filter_injection_is_refused(misp, ldap_fixtures, payload):
    """Filter metacharacters in the email must not widen the search."""
    ldap_fixtures.add_user()

    misp.login(payload, "userpassword")

    assert not misp.is_authenticated(), (
        "Login succeeded for injection payload {!r}; the search filter is no "
        "longer being escaped.".format(payload)
    )


def test_user_outside_search_base_is_refused(misp, ldap_fixtures, ldap_config):
    """ldapDn must actually bound who can log in.

    A valid account with correct credentials, placed outside the configured
    search base, must not authenticate -- otherwise narrowing ldapDn gives no
    real containment.
    """
    user = ldap_fixtures.add_user(base=ldap_config.root)
    assert not user["dn"].endswith(
        ",{}".format(ldap_config.search_base)
    ), "fixture should sit outside the search base for this test to mean anything"

    misp.login(user["mail"], user["password"])

    assert not misp.is_authenticated(), (
        "{} authenticated from outside the configured ldapDn ({})."
        .format(user["dn"], ldap_config.search_base)
    )


def test_ldap_login_reenables_a_disabled_account(misp, misp_admin_api,
                                                 ldap_fixtures):
    """A locally disabled account is re-enabled by logging in over LDAP.

    With updateUser enabled the plugin unconditionally writes `disabled = 0`
    when refreshing a user, so disabling someone in MISP does not keep them
    out while they still exist in the directory. Revocation has to happen in
    LDAP, not in MISP.

    This documents current behaviour rather than endorsing it -- if the plugin
    is ever changed to respect the local flag, this test should be inverted.
    """
    if misp_admin_api is None:
        pytest.skip("needs AUTH to disable the account")

    user = ldap_fixtures.add_user()

    misp.login(user["mail"], user["password"])
    misp.assert_logged_in(user["mail"])
    misp.logout()

    user_id = misp_admin_api.find_user_id(user["mail"])
    assert user_id is not None
    misp_admin_api.set_disabled(user_id, True)
    assert misp_admin_api.view_user(user_id)["disabled"] is True

    misp.login(user["mail"], user["password"])

    assert misp.is_authenticated(), (
        "Disabled user was refused -- the plugin now respects the local "
        "disabled flag. That is an improvement; invert this test."
    )
    assert misp_admin_api.view_user(user_id)["disabled"] is False
