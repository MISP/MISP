"""Tests for authenticating on a header asserted by a front-end proxy.

The intended deployment is an Apache in front of MISP that performs Kerberos
and passes the resulting username on. MISP has to treat that header as
worthless unless the request demonstrably came from that proxy, so most of
what is tested here is the refusal.

Note these tests do not go through the login form at all: AuthComponent calls
`getUser()` on every request without a session, so a plain GET carrying the
header is the whole login.
"""

import pytest


HEADER = "X-Remote-User"

# Documentation range (RFC 5737), so it cannot be the address any real test
# runner arrives from.
UNTRUSTED_ADDRESS = "203.0.113.9"
UNTRUSTED_RANGE = "203.0.113.0/24"

# Matches whatever the peer address turns out to be, v4 or v6, without the
# suite having to discover it. Precision is covered by the refusals above and
# by the /32 case, which must not match.
ANY_ADDRESS = ["0.0.0.0/0", "::/0"]


def _header_login(client, username):
    """Authenticate by requesting a UI page with the proxy header set.

    The request has to be an HTML one. MISP authenticates `.json` requests by
    authkey and never consults the authenticate objects, so probing a JSON
    endpoint reports "not logged in" whatever the plugin does -- which makes
    for tests that pass without exercising anything at all. A successful header
    login writes the usual session, which is what the assertions then read.
    """
    client.get("/events/index", headers={HEADER: username})
    if not client.is_authenticated():
        return None
    return client.current_user()


@pytest.mark.parametrize("trusted_proxies,reason", [
    ([], "no trusted proxy configured at all"),
    ([UNTRUSTED_ADDRESS], "peer address not in the list"),
    ([UNTRUSTED_RANGE], "peer address not in the range"),
    (["0.0.0.0/32"], "a /32 of a different address"),
])
def test_header_is_ignored_from_an_untrusted_source(misp_config, ldap_settings,
                                                    ldap_fixtures,
                                                    trusted_proxies, reason):
    """The header must buy nothing unless the request came from a proxy.

    The empty-list case is the important one: it is the half-finished
    configuration, and honouring the header there would let anyone able to
    reach MISP log in as anyone.
    """
    from conftest import MispClient

    user = ldap_fixtures.add_user()

    ldap_settings.set(
        ldapHeaderAuth=True,
        ldapHeaderAuthHeader=HEADER,
        ldapHeaderAuthTrustedProxies=trusted_proxies,
    )

    client = MispClient(misp_config)
    try:
        assert _header_login(client, user["mail"]) is None, (
            "header was honoured despite {}".format(reason)
        )
    finally:
        client.session.close()


def test_header_authenticates_from_a_trusted_proxy(misp_config, ldap_settings,
                                                   ldap_fixtures):
    """From a trusted source the header alone logs the user in.

    No password is sent and the login form is never touched.
    """
    from conftest import MispClient

    user = ldap_fixtures.add_user()

    ldap_settings.set(
        ldapHeaderAuth=True,
        ldapHeaderAuthHeader=HEADER,
        ldapHeaderAuthTrustedProxies=ANY_ADDRESS,
    )

    client = MispClient(misp_config)
    try:
        account = _header_login(client, user["mail"])
        assert account is not None, "header authentication did not log the user in"
        assert account["email"] == user["mail"]
    finally:
        client.session.close()


def test_header_authentication_is_off_by_default(misp_config, ldap_settings,
                                                 ldap_fixtures):
    """With the feature disabled the header is just another header."""
    from conftest import MispClient

    user = ldap_fixtures.add_user()

    ldap_settings.set(
        ldapHeaderAuth=False,
        ldapHeaderAuthHeader=HEADER,
        ldapHeaderAuthTrustedProxies=ANY_ADDRESS,
    )

    client = MispClient(misp_config)
    try:
        assert _header_login(client, user["mail"]) is None
    finally:
        client.session.close()


def test_header_user_must_exist_in_the_directory(misp_config, misp_admin_api,
                                                 ldap_settings, ldap_fixtures):
    """A name the directory does not know is refused, even from the proxy.

    There is deliberately no mixedAuth fallback on this path: the header would
    otherwise be enough to log into a local account the directory knows
    nothing about.
    """
    from conftest import MispClient

    ldap_settings.set(
        ldapHeaderAuth=True,
        ldapHeaderAuthHeader=HEADER,
        ldapHeaderAuthTrustedProxies=ANY_ADDRESS,
    )

    unknown = "no-such-directory-user@example.com"
    client = MispClient(misp_config)
    try:
        assert _header_login(client, unknown) is None
    finally:
        client.session.close()

    if misp_admin_api is not None:
        assert misp_admin_api.find_user_id(unknown) is None


def test_header_authentication_provisions_org_and_role(misp_config,
                                                       misp_admin_api,
                                                       misp_org, ldap_config,
                                                       ldap_settings,
                                                       ldap_fixtures):
    """Header logins go through the same provisioning as password logins.

    Asserted because the two paths share `provisionUser()` -- if they were ever
    split again, the header path silently losing org and role mapping is the
    first thing that would go wrong.
    """
    if misp_admin_api is None:
        pytest.skip("needs AUTH to read the provisioned account")

    from conftest import MispClient

    user = ldap_fixtures.add_user()
    group = ldap_fixtures.add_group(members=[user["dn"]])

    ldap_settings.set(
        ldapDn=ldap_config.root,
        ldapHeaderAuth=True,
        ldapHeaderAuthHeader=HEADER,
        ldapHeaderAuthTrustedProxies=ANY_ADDRESS,
        ldapOrgGroupMapping={group["cn"]: misp_org["name"]},
        ldapRoleGroupMapping={group["cn"]: "Org Admin"},
    )

    client = MispClient(misp_config)
    try:
        account = _header_login(client, user["mail"])
        assert account is not None
        assert int(account["org_id"]) == int(misp_org["id"])
        assert int(account["role_id"]) == 2
    finally:
        client.session.close()


def test_header_authentication_respects_a_disabled_directory_account(
    misp_config, user_account_control_supported, ldap_settings, ldap_fixtures
):
    """ACCOUNTDISABLE still refuses, on this path too.

    The same shared-code argument as above: a proxy vouching for someone says
    nothing about whether the directory still wants them to have access.
    """
    if not user_account_control_supported:
        pytest.skip("directory will not accept a userAccountControl attribute")

    from conftest import MispClient

    user = ldap_fixtures.add_user(
        object_classes=["mispTestAdAccount"],
        userAccountControl="514",
    )

    ldap_settings.set(
        ldapHeaderAuth=True,
        ldapHeaderAuthHeader=HEADER,
        ldapHeaderAuthTrustedProxies=ANY_ADDRESS,
        ldapCheckUserAccountControl=True,
    )

    client = MispClient(misp_config)
    try:
        assert _header_login(client, user["mail"]) is None
    finally:
        client.session.close()
