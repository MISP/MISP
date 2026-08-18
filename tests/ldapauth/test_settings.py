"""Tests for LdapAuth settings that change how logins are resolved.

Each test rewrites the running instance's `LdapAuth` block through the
`ldap_settings` fixture and restores it afterwards, so no container restart is
needed. That also means these tests mutate global state: run the suite
serially, never with `pytest-xdist`.

Where a setting could plausibly do nothing, the test also exercises the
opposite value, so a passing assertion cannot be explained by the login having
failed for some unrelated reason.
"""

import uuid

import pytest


@pytest.fixture
def local_user(misp_admin_api):
    """A database-only MISP account with a password we know."""
    if misp_admin_api is None:
        pytest.skip("needs AUTH to create a local user")

    email = "local-{}@example.com".format(uuid.uuid4().hex[:8])
    password = "LocalPassw0rd!{}".format(uuid.uuid4().hex[:4])
    misp_admin_api.delete_user_by_email(email)
    misp_admin_api.create_user(email, password)
    yield {"email": email, "password": password}
    misp_admin_api.delete_user_by_email(email)


@pytest.mark.parametrize("mixed_auth", [False, True])
def test_mixed_auth_controls_the_local_database_fallback(
    misp_config, ldap_settings, local_user, mixed_auth
):
    """mixedAuth decides whether non-LDAP accounts can still log in.

    With it off, a user absent from the directory is refused outright even
    with a correct MISP password -- which is what locks `admin@admin.test` out
    of the web form on an LDAP-only instance.
    """
    from conftest import MispClient

    ldap_settings.set(mixedAuth=mixed_auth)

    client = MispClient(misp_config)
    client.login(local_user["email"], local_user["password"])
    try:
        assert client.is_authenticated() is mixed_auth, (
            "local account login was {} with mixedAuth={}".format(
                "accepted" if client.is_authenticated() else "refused",
                mixed_auth,
            )
        )
    finally:
        client.session.close()


def test_search_filter_excludes_non_matching_users(misp, ldap_settings,
                                                   ldap_fixtures):
    """ldapSearchFilter narrows who may log in, on top of the attribute match."""
    user = ldap_fixtures.add_user()

    # A filter the fixture cannot satisfy: it is a person, not a device.
    ldap_settings.set(ldapSearchFilter="(objectClass=device)")
    misp.login(user["mail"], user["password"])
    assert not misp.is_authenticated(), "excluded user got in"

    # Same user, same credentials, a filter that does match.
    ldap_settings.set(ldapSearchFilter="(objectClass=inetOrgPerson)")
    misp.login(user["mail"], user["password"])
    misp.assert_logged_in(user["mail"])


def test_search_attribute_can_be_uid(misp, ldap_settings, ldap_fixtures):
    """With ldapSearchAttribute=uid the login field holds a uid, not an address.

    The MISP account is still named from ldapEmailField, so what someone types
    to log in and what identifies them inside MISP are different values.
    """
    user = ldap_fixtures.add_user()

    ldap_settings.set(ldapSearchAttribute="uid")

    misp.login(user["uid"], user["password"])
    misp.assert_logged_in(user["uid"])
    assert misp.current_user()["email"] == user["mail"]


def test_email_field_falls_back_to_the_next_attribute(misp, ldap_settings,
                                                      ldap_fixtures):
    """ldapEmailField is tried in order; the first present attribute wins.

    A user with no `mail` therefore still gets an account, named from the
    fallback attribute.
    """
    uid = "fallback-{}@example.com".format(uuid.uuid4().hex[:8])
    user = ldap_fixtures.add_user(uid=uid, mail=None)

    ldap_settings.set(
        ldapSearchAttribute="uid",
        ldapEmailField=["mail", "uid"],
    )

    misp.login(uid, user["password"])
    misp.assert_logged_in(uid)
    assert misp.current_user()["email"] == uid, (
        "expected the account to be named from the uid fallback"
    )
    # Registered by hand: add_user() only tracks fixtures that carry a mail.
    ldap_fixtures.track_provisioned_email(uid)


def test_update_user_false_freezes_an_existing_account(misp_config, misp_admin_api,
                                                       ldap_settings,
                                                       ldap_fixtures):
    """updateUser decides whether LDAP re-applies role/org on every login."""
    from conftest import MispClient

    if misp_admin_api is None:
        pytest.skip("needs AUTH to read the provisioned role")

    user = ldap_fixtures.add_user()

    ldap_settings.set(ldapDefaultRoleId=3, updateUser=True)
    first = MispClient(misp_config)
    first.login(user["mail"], user["password"])
    first.assert_logged_in(user["mail"])
    first.session.close()

    user_id = misp_admin_api.find_user_id(user["mail"])
    assert int(misp_admin_api.view_user(user_id)["role_id"]) == 3

    # Role changes in config must NOT reach an existing user.
    ldap_settings.set(ldapDefaultRoleId=1, updateUser=False)
    second = MispClient(misp_config)
    second.login(user["mail"], user["password"])
    second.assert_logged_in(user["mail"])
    second.session.close()
    assert int(misp_admin_api.view_user(user_id)["role_id"]) == 3, (
        "updateUser=false still rewrote the user's role"
    )

    # ...and with updateUser back on they must, proving the check above means
    # something.
    ldap_settings.set(updateUser=True)
    third = MispClient(misp_config)
    third.login(user["mail"], user["password"])
    third.assert_logged_in(user["mail"])
    third.session.close()
    assert int(misp_admin_api.view_user(user_id)["role_id"]) == 1


def test_group_membership_maps_to_a_role(misp, misp_admin_api, ldap_config,
                                         ldap_settings, ldap_fixtures):
    """ldapDefaultRoleId as a dict assigns a role from the user's groups."""
    if misp_admin_api is None:
        pytest.skip("needs AUTH to read the provisioned role")

    user = ldap_fixtures.add_user()
    group = ldap_fixtures.add_group(members=[user["dn"]])

    # Groups live outside the users OU, so the search base has to be widened
    # for the plugin's `(member=<dn>)` lookup to find anything at all.
    ldap_settings.set(
        ldapDn=ldap_config.root,
        ldapDefaultRoleId={group["cn"]: 1},
    )

    misp.login(user["mail"], user["password"])
    misp.assert_logged_in(user["mail"])

    user_id = misp_admin_api.find_user_id(user["mail"])
    assert int(misp_admin_api.view_user(user_id)["role_id"]) == 1


def test_unmapped_group_membership_refuses_a_new_user(misp, misp_admin_api,
                                                      ldap_config,
                                                      ldap_settings,
                                                      ldap_fixtures):
    """No mapped group means no login, and no half-created account."""
    user = ldap_fixtures.add_user()
    ldap_fixtures.add_group(members=[user["dn"]])

    ldap_settings.set(
        ldapDn=ldap_config.root,
        ldapDefaultRoleId={"a-group-nobody-is-in": 1},
    )

    misp.login(user["mail"], user["password"])
    assert not misp.is_authenticated()

    if misp_admin_api is not None:
        assert misp_admin_api.find_user_id(user["mail"]) is None, (
            "a user with no mapped role was created anyway"
        )


def test_losing_the_mapped_group_disables_an_existing_user(
    misp_config, misp_admin_api, ldap_admin, ldap_config, ldap_settings,
    ldap_fixtures
):
    """Dropping out of every mapped group disables the MISP account."""
    from conftest import MispClient

    if misp_admin_api is None:
        pytest.skip("needs AUTH to read the disabled flag")

    user = ldap_fixtures.add_user()
    group = ldap_fixtures.add_group(members=[user["dn"]])

    ldap_settings.set(
        ldapDn=ldap_config.root,
        ldapDefaultRoleId={group["cn"]: 1},
    )

    first = MispClient(misp_config)
    first.login(user["mail"], user["password"])
    first.assert_logged_in(user["mail"])
    first.session.close()

    user_id = misp_admin_api.find_user_id(user["mail"])
    assert misp_admin_api.view_user(user_id)["disabled"] is False

    # groupOfNames must keep at least one member, so swap ours out rather
    # than emptying the attribute.
    assert ldap_admin.modify(
        group["dn"],
        {"member": [("MODIFY_REPLACE", [ldap_config.admin_dn])]},
    ), ldap_admin.result

    second = MispClient(misp_config)
    second.login(user["mail"], user["password"])
    assert not second.is_authenticated()
    second.session.close()

    assert misp_admin_api.view_user(user_id)["disabled"] is True, (
        "user lost every mapped group but stayed enabled"
    )


def test_group_mapping_finds_nothing_when_groups_are_outside_ldap_dn(
    misp, ldap_config, ldap_settings, ldap_fixtures
):
    """A narrowed ldapDn silently breaks group-to-role mapping.

    The plugin looks for groups with `(member=<dn>)` under `ldapDn`. Point
    that at the users OU while groups live elsewhere and the lookup returns
    nothing, so every user is treated as having no mapped role and refused --
    with no hint that the search base is the cause.
    """
    user = ldap_fixtures.add_user()
    group = ldap_fixtures.add_group(members=[user["dn"]])

    assert not group["dn"].endswith(",{}".format(ldap_config.search_base)), (
        "this test needs the groups OU to sit outside the users OU"
    )

    ldap_settings.set(
        ldapDn=ldap_config.search_base,
        ldapDefaultRoleId={group["cn"]: 1},
    )
    misp.login(user["mail"], user["password"])
    assert not misp.is_authenticated(), (
        "groups resolved from a base that does not contain them"
    )

    # The same mapping works once the base actually covers the groups.
    ldap_settings.set(ldapDn=ldap_config.root)
    misp.login(user["mail"], user["password"])
    misp.assert_logged_in(user["mail"])


def test_use_member_of_reads_groups_from_the_user_entry(
    misp, misp_admin_api, memberof_supported, ldap_config, ldap_settings,
    ldap_fixtures
):
    """ldapUseMemberOf resolves groups without searching for them.

    It reads `memberOf` off the user entry, so it works even when groups sit
    outside `ldapDn` -- note the search base here stays narrowed, which the
    `(member=<dn>)` path cannot cope with. The mapping keys are full group DNs
    rather than CNs.

    Requires the directory to maintain `memberOf`. bitnami/openldap ships the
    overlay but does not enable it, so `memberof_supported` turns it on.
    """
    if not memberof_supported:
        pytest.skip("directory does not maintain memberOf (overlay unavailable)")

    if misp_admin_api is None:
        pytest.skip("needs AUTH to read the provisioned role")

    user = ldap_fixtures.add_user()
    group = ldap_fixtures.add_group(members=[user["dn"]])

    ldap_settings.set(
        ldapDn=ldap_config.search_base,
        ldapUseMemberOf=True,
        ldapDefaultRoleId={group["dn"]: 1},
    )

    misp.login(user["mail"], user["password"])
    misp.assert_logged_in(user["mail"])

    user_id = misp_admin_api.find_user_id(user["mail"])
    assert int(misp_admin_api.view_user(user_id)["role_id"]) == 1
