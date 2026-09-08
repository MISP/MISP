"""Tests for `cake User check_validity` reconciling MISP against the directory.

The command is the batch counterpart of a login: it re-runs the same decisions
without anyone signing in, so accounts that have lost their directory entry,
been disabled in it, or moved organisation do not linger.

These tests drive the real console command, so they need the plugin listed in
`Security.auth` like everything else in this suite.
"""

import pytest


def _check_validity(console, *flags):
    code, output = console.run("User", "check_validity", *flags)
    assert code == 0, "check_validity exited {}:\n{}".format(code, output[-2000:])
    return output


@pytest.fixture
def console(misp_console):
    if misp_console is None:
        pytest.skip("cannot reach the MISP console")
    return misp_console


def test_user_removed_from_the_directory_is_disabled(console, misp_config,
                                                     misp_admin_api,
                                                     ldap_admin, ldap_settings,
                                                     ldap_fixtures):
    """An account whose directory entry is gone gets disabled.

    Only meaningful with mixedAuth off: with it on, an account missing from
    LDAP may legitimately be a local one, which the next test covers.
    """
    if misp_admin_api is None:
        pytest.skip("needs AUTH to read the disabled flag")

    from conftest import MispClient

    user = ldap_fixtures.add_user()
    ldap_settings.set(mixedAuth=False)

    client = MispClient(misp_config)
    client.login(user["mail"], user["password"])
    client.assert_logged_in(user["mail"])
    client.session.close()

    user_id = misp_admin_api.find_user_id(user["mail"])
    assert misp_admin_api.view_user(user_id)["disabled"] is False

    assert ldap_admin.delete(user["dn"]), ldap_admin.result

    _check_validity(console, "--block_invalid")

    assert misp_admin_api.view_user(user_id)["disabled"] is True, (
        "account survived the removal of its directory entry"
    )


def test_missing_user_is_left_alone_when_mixed_auth_is_enabled(console,
                                                               misp_config,
                                                               misp_admin_api,
                                                               ldap_admin,
                                                               ldap_settings,
                                                               ldap_fixtures):
    """With mixedAuth on, absence from LDAP is not evidence of anything.

    Local accounts are legitimate in that mode, and there is no way to tell
    one from an LDAP-provisioned account -- the plugin creates users with an
    empty password, which is then hashed like any other -- so the command must
    not disable them.
    """
    if misp_admin_api is None:
        pytest.skip("needs AUTH to read the disabled flag")

    from conftest import MispClient

    user = ldap_fixtures.add_user()
    ldap_settings.set(mixedAuth=False)

    client = MispClient(misp_config)
    client.login(user["mail"], user["password"])
    client.assert_logged_in(user["mail"])
    client.session.close()

    user_id = misp_admin_api.find_user_id(user["mail"])
    assert ldap_admin.delete(user["dn"]), ldap_admin.result

    ldap_settings.set(mixedAuth=True)
    _check_validity(console, "--block_invalid")

    assert misp_admin_api.view_user(user_id)["disabled"] is False, (
        "a possibly-local account was disabled for not being in LDAP"
    )


def test_site_admin_is_never_disabled(console, misp_admin_api, ldap_settings):
    """The built-in admin is reported but left enabled.

    Deliberate: no marker distinguishes an LDAP-provisioned account from a
    local one, so a directory that does not list `admin@admin.test` makes it
    look invalid. Disabling every site admin would lock the instance out of
    its own administration, which cannot be undone from inside MISP.
    """
    if misp_admin_api is None:
        pytest.skip("needs AUTH to read the disabled flag")

    ldap_settings.set(mixedAuth=False)

    admin_id = misp_admin_api.find_user_id("admin@admin.test")
    assert admin_id is not None

    output = _check_validity(console, "--block_invalid")

    assert misp_admin_api.view_user(admin_id)["disabled"] is False, (
        "check_validity disabled a site admin, locking the instance out"
    )
    assert "site admin, NOT disabled" in output, (
        "expected the skip to be reported, not silent"
    )


@pytest.mark.parametrize("update_user,expected_role", [(True, 2), (False, 3)])
def test_role_is_updated_only_when_update_user_is_enabled(console, misp_config,
                                                          misp_admin_api,
                                                          ldap_config,
                                                          ldap_settings,
                                                          ldap_fixtures,
                                                          update_user,
                                                          expected_role):
    """`--update` applies role changes, but only if updateUser permits it.

    The CLI flag says "do it now"; the setting says the directory owns these
    fields at all. A run must not overrule an instance that has turned the
    setting off.
    """
    if misp_admin_api is None:
        pytest.skip("needs AUTH to read the provisioned role")

    from conftest import MispClient

    user = ldap_fixtures.add_user()

    # Log in first with the default role, so there is something to change.
    ldap_settings.set(ldapDefaultRoleId=3, updateUser=True)
    client = MispClient(misp_config)
    client.login(user["mail"], user["password"])
    client.assert_logged_in(user["mail"])
    client.session.close()

    user_id = misp_admin_api.find_user_id(user["mail"])
    assert int(misp_admin_api.view_user(user_id)["role_id"]) == 3

    group = ldap_fixtures.add_group(members=[user["dn"]])
    ldap_settings.set(
        ldapDn=ldap_config.root,
        ldapRoleGroupMapping={group["cn"]: "Org Admin"},
        updateUser=update_user,
    )

    _check_validity(console, "--update")

    assert int(misp_admin_api.view_user(user_id)["role_id"]) == expected_role


@pytest.mark.parametrize("admin_action,expected_disabled", [
    ("blockInvalidUsers", True),
    ("checkUserValidity", False),
])
def test_schedulable_admin_action_matches_the_cli(console, misp_config,
                                                  misp_admin_api, ldap_admin,
                                                  ldap_settings, ldap_fixtures,
                                                  admin_action,
                                                  expected_disabled):
    """The Admin actions the Tasks UI schedules do what the CLI does.

    `cake Admin blockInvalidUsers` is what a scheduled task ends up running,
    so it is worth asserting directly rather than trusting that it dispatches
    the right thing. The reporting variant is the control: same situation, no
    change, which is what makes it safe to schedule.
    """
    if misp_admin_api is None:
        pytest.skip("needs AUTH to read the disabled flag")

    from conftest import MispClient

    user = ldap_fixtures.add_user()
    ldap_settings.set(mixedAuth=False)

    client = MispClient(misp_config)
    client.login(user["mail"], user["password"])
    client.assert_logged_in(user["mail"])
    client.session.close()

    user_id = misp_admin_api.find_user_id(user["mail"])
    assert ldap_admin.delete(user["dn"]), ldap_admin.result

    code, output = console.run("Admin", admin_action)
    assert code == 0, "{} exited {}:\n{}".format(admin_action, code, output[-2000:])

    disabled = misp_admin_api.view_user(user_id)["disabled"]
    assert disabled is expected_disabled, (
        "{} left disabled={}".format(admin_action, disabled)
    )


def test_directory_disabled_account_is_disabled(console, misp_config,
                                                misp_admin_api,
                                                user_account_control_supported,
                                                ldap_admin, ldap_settings,
                                                ldap_fixtures):
    """userAccountControl is honoured here too, not just at login."""
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

    client = MispClient(misp_config)
    client.login(user["mail"], user["password"])
    client.assert_logged_in(user["mail"])
    client.session.close()

    user_id = misp_admin_api.find_user_id(user["mail"])
    assert misp_admin_api.view_user(user_id)["disabled"] is False

    assert ldap_admin.modify(
        user["dn"], {"userAccountControl": [("MODIFY_REPLACE", ["514"])]}
    ), ldap_admin.result

    _check_validity(console, "--block_invalid")

    assert misp_admin_api.view_user(user_id)["disabled"] is True
