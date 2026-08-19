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

    An empty password makes ldap_bind() perform an *unauthenticated* bind,
    which LDAP treats as a success for any existing DN. A directory that does
    not refuse those -- RFC 4513 leaves that to the server -- would hand out a
    session for any account whose identifier is known.
    """
    user = ldap_fixtures.add_user()

    misp.login(user["mail"], "")

    assert not misp.is_authenticated(), (
        "Empty password authenticated {}".format(user["mail"])
    )


def test_empty_password_never_reaches_the_directory(misp_config, ldap_settings,
                                                    ldap_fixtures):
    """The refusal is the plugin's, not the directory's.

    The previous test passes either way, because OpenLDAP happens to answer an
    unauthenticated bind with `Server is unwilling to perform`. That makes it
    blind to the guard being removed, as long as the directory keeps covering
    for it.

    Pointing the plugin at a dead address separates the two: an empty password
    is rejected before any connection is attempted, so the login fails
    normally (HTTP 200). Anything that does reach the directory blows up on
    the unreachable server instead and surfaces as a 401, which is what the
    control case below asserts.
    """
    from conftest import MispClient

    user = ldap_fixtures.add_user()
    ldap_settings.set(ldapServer="ldap://127.0.0.1:1")

    refused = MispClient(misp_config)
    response = refused.login(user["mail"], "")
    assert not refused.is_authenticated()
    assert response.status_code == 200, (
        "expected the empty password to be refused before connecting; a 401 "
        "means the plugin went to the directory first"
    )
    refused.session.close()

    # Control: a real password does reach the (dead) directory, proving the
    # server really was unreachable and the 200 above was the guard.
    contacted = MispClient(misp_config)
    control = contacted.login(user["mail"], user["password"])
    assert not contacted.is_authenticated()
    assert control.status_code == 401, (
        "the directory was reachable after all, so this test proves nothing"
    )
    contacted.session.close()


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


# userAccountControl values and whether the account they describe may log in.
# 512 is NORMAL_ACCOUNT, 2 is ACCOUNTDISABLE, 65536 is DONT_EXPIRE_PASSWORD.
# The 514 and 66050 cases are the point: an equality check against 2 would let
# both of them through, because the flag is combined with the others.
ACCOUNT_CONTROL_CASES = [
    (512, True),
    (66048, True),
    (2, False),
    (514, False),
    (66050, False),
]


@pytest.mark.parametrize("control,may_log_in", ACCOUNT_CONTROL_CASES)
def test_account_control_disable_flag_is_read_as_a_bitmask(
    misp, misp_admin_api, user_account_control_supported, ldap_settings,
    ldap_fixtures, control, may_log_in
):
    """userAccountControl is a bit field, so ACCOUNTDISABLE must be masked.

    Active Directory combines flags: an ordinary enabled account reads 512 and
    the same account disabled reads 514. Comparing the attribute to 2 would
    therefore treat almost every disabled account as enabled.
    """
    if not user_account_control_supported:
        pytest.skip("directory will not accept a userAccountControl attribute")

    user = ldap_fixtures.add_user(
        object_classes=["mispTestAdAccount"],
        userAccountControl=str(control),
    )

    ldap_settings.set(ldapCheckUserAccountControl=True)

    misp.login(user["mail"], user["password"])
    assert misp.is_authenticated() is may_log_in, (
        "userAccountControl {} should {} the login".format(
            control, "allow" if may_log_in else "refuse"
        )
    )

    if not may_log_in and misp_admin_api is not None:
        assert misp_admin_api.find_user_id(user["mail"]) is None, (
            "a disabled directory account was provisioned in MISP anyway"
        )


def test_account_control_is_ignored_unless_the_setting_is_enabled(
    misp, user_account_control_supported, ldap_settings, ldap_fixtures
):
    """The check is opt-in, so ACCOUNTDISABLE means nothing by default.

    Only directories that populate `userAccountControl` meaningfully should
    have it consulted, so an instance that has not asked for it keeps behaving
    as before. Here the same entry that is refused with the setting on logs in
    fine with it off, which is what makes the gate observable.
    """
    if not user_account_control_supported:
        pytest.skip("directory will not accept a userAccountControl attribute")

    user = ldap_fixtures.add_user(
        object_classes=["mispTestAdAccount"],
        userAccountControl="514",
    )

    ldap_settings.set(ldapCheckUserAccountControl=False)
    misp.login(user["mail"], user["password"])
    misp.assert_logged_in(user["mail"])
    misp.logout()

    ldap_settings.set(ldapCheckUserAccountControl=True)
    misp.login(user["mail"], user["password"])
    assert not misp.is_authenticated(), (
        "the same entry must be refused once the check is enabled"
    )


def test_account_control_disables_an_existing_misp_user(misp_config,
                                                        misp_admin_api,
                                                        user_account_control_supported,
                                                        ldap_admin,
                                                        ldap_settings,
                                                        ldap_fixtures):
    """Disabling the account in the directory disables it in MISP too.

    Checked against the directory entry rather than the bind result, because
    AD refuses the bind for a disabled account: waiting for that would never
    reveal the reason and would leave the MISP account enabled. The revocation
    lands the next time that person tries to log in.
    """
    if not user_account_control_supported:
        pytest.skip("directory will not accept a userAccountControl attribute")
    if misp_admin_api is None:
        pytest.skip("needs AUTH to read the disabled flag")

    from conftest import MispClient

    user = ldap_fixtures.add_user(
        object_classes=["mispTestAdAccount"],
        userAccountControl="512",
    )

    ldap_settings.set(ldapCheckUserAccountControl=True)

    enabled = MispClient(misp_config)
    enabled.login(user["mail"], user["password"])
    enabled.assert_logged_in(user["mail"])
    enabled.session.close()

    user_id = misp_admin_api.find_user_id(user["mail"])
    assert misp_admin_api.view_user(user_id)["disabled"] is False

    assert ldap_admin.modify(
        user["dn"], {"userAccountControl": [("MODIFY_REPLACE", ["514"])]}
    ), ldap_admin.result

    refused = MispClient(misp_config)
    refused.login(user["mail"], user["password"])
    assert not refused.is_authenticated()
    refused.session.close()

    assert misp_admin_api.view_user(user_id)["disabled"] is True, (
        "the MISP account stayed enabled after the directory disabled it"
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
