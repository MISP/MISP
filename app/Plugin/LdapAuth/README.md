# LdapAuth 
This plugin allows MISP to authenticate against an LDAP server.

## How to
1. Add your LDAP server configuration to `app/Config/config.php` configuration file:
    ```
    'LdapAuth' => [
        'ldapServer' => 'ldap://openldap:1389',
        'ldapDn' => 'dc=example,dc=com',
        'ldapReaderUser' => 'cn=reader,dc=example,dc=com',
        'ldapReaderPassword' => 'password'
    ],
    ```
    > **NOTE:** This plugin requires a reader user to query the LDAP server.
2. Add the LDAP authentication method in the `Security.auth` key of the `app/Config/config.php` configuration file:
    ```
    ...
    'Security' => [
        ...,
       'auth' => [
           0 => 'LdapAuth.Ldap',
       ]
    ]
    ``` 
3. Log in with your LDAP credentials using the MISP Login form, if the user doesn't exist on MISP it will be created on the first log in.

## Settings
Each setting is stored in the `LdapAuth` configuration array and can be customized as per your LDAP server and application requirements.

### `ldapServer`
- **Description**: The LDAP server's hostname or IP address.
- **Type**: `string`
- **Example**: `'ldap://ldap.example.com'` or `'ldap://ldap.example.com:3389'` for using a custom port.

### `ldapDn`
- **Description**: The distinguished name (DN) for the LDAP search base.
- **Type**: `string`
- **Example**: `'dc=example,dc=com'`

### `ldapReaderUser`
- **Description**: The username for the LDAP reader account, used to authenticate search requests.
- **Type**: `string`
- **Example**: `'cn=reader,dc=example,dc=com'`

### `ldapReaderPassword`
- **Description**: The password for the LDAP reader account.
- **Type**: `string`
- **Example**: `'password'`

### `ldapSearchFilter`
- **Description**: The LDAP search filter used to locate the user entry.
- **Type**: `string`
- **Example**: `'(objectclass=inetOrgPerson)(!(nsaccountlock=True))(memberOf=cn=misp,cn=groups,cn=accounts,dc=example,dc=com)'`

### `ldapSearchAttribute`
- **Description**: The LDAP attribute used to match the user's identifier, typically their email or username.
- **Type**: `string`
- **Default**: `'mail'`
- **Example**: `'uid'`

### `ldapEmailField`
- **Description**: Specifies which LDAP attribute(s) to use for retrieving the user's email address. The attributes are tried in order and the first one present on the entry is used. Its value becomes the MISP user's email, which is what links the MISP account to the LDAP user, so prefer an attribute that is unique and as stable as possible. Attribute names are matched case-insensitively. The special value `dn` uses the entry's full distinguished name.
- **Type**: `array`
- **Default**: `['mail']`
- **Example**: `['mail', 'userPrincipalName']`
- **Example of linking by DN**: `['dn']`

> **NOTE:** MISP has no immutable identifier for an LDAP user, the value of this attribute *is* the identity. If it changes in the directory, the next login creates a second MISP account instead of updating the existing one, and the old account keeps its role and stays enabled.

### `ldapNetworkTimeout`
- **Description**: Sets the timeout for the network connection to the LDAP server, in seconds.
- **Type**: `integer`
- **Default**: `-1` (no timeout)
- **Example**: `10`

### `ldapProtocol`
- **Description**: Specifies the LDAP protocol version.
- **Type**: `integer`
- **Default**: `3`
- **Example**: `3`

### `ldapAllowReferrals`
- **Description**: Determines whether LDAP referrals are allowed.
- **Type**: `boolean`
- **Default**: `true`
- **Example**: `true`

### `starttls`
- **Description**: Enables or disables StartTLS for LDAP, which provides a secure connection.
- **Type**: `boolean`
- **Default**: `false`
- **Example**: `true`

### `mixedAuth`
- **Description**: Allows mixed authentication modes (e.g., both LDAP and local database authentication).
- **Type**: `boolean`
- **Default**: `true`
- **Example**: `true`

### `ldapDefaultOrgId`
- **Description**: The organisation ID assigned to LDAP users. Applies only when neither `ldapOrgField` nor `ldapOrgGroupMapping` is configured.
- **Type**: `string`
- **Example**: `1`

### `ldapOrgField`
- **Description**: An attribute on the user's LDAP entry that holds their organisation. An all-digit value is looked up as an organisation ID, anything else as an organisation name. Several attributes may be given, in which case the first one present on the entry is used. Attribute names are matched case-insensitively.
- **Type**: `string` | `array`
- **Default**: unset, meaning `ldapDefaultOrgId` is used
- **Example**: `'o'`, or `['o', 'departmentNumber']`

### `ldapOrgGroupMapping`
- **Description**: Maps LDAP group memberships to MISP organisations, for directories where the organisation is expressed as a group rather than an attribute. Values are organisation IDs or names, resolved the same way as `ldapOrgField`. Keys are group CNs, or full group DNs when `ldapUseMemberOf` is enabled, matching how the role mappings are keyed.
- **Precedence**: For a user in several mapped groups, **the first entry in this setting wins** — precedence is the order you write, not the order the directory happens to return memberships in. Put the group whose organisation should take priority first.
- **Type**: `array`
- **Default**: unset
- **Example**:
    ```
    [
        'misp_org_a' => 'Organisation A',
        'misp_org_b' => 2,
    ]
    ```

> **NOTE — how the organisation is resolved:**
>
> * If **neither** `ldapOrgField` nor `ldapOrgGroupMapping` is configured, every LDAP user is placed in `ldapDefaultOrgId`.
> * If **either** is configured, the organisation comes from the directory. `ldapOrgField` is tried first, then `ldapOrgGroupMapping`, so the two compose: a user without the attribute can still be resolved by a group, and vice versa.
> * If **neither mechanism resolves an organisation** — the attribute is absent, or names an organisation MISP does not have, and no group maps to one either — **the login is refused**. `ldapDefaultOrgId` is *not* used as a fallback here, and no MISP account is created.
>
> That refusal is deliberate. An organisation is a sharing boundary in MISP, so defaulting a user into one on the strength of missing directory data would widen their access to other organisations' events. Each step logs a warning before the refusal, so `app/tmp/logs/error.log` shows which part did not resolve.
>
> Practical consequence: a directory that stops publishing the attribute, or a `ldapOrgGroupMapping` value that no longer matches an organisation name, locks the affected users out rather than silently misplacing them. Existing accounts keep their current organisation and stay enabled, they simply cannot log in until the directory or the mapping is corrected.

### `ldapDefaultRoleId`
- **Description**: The role ID assigned to users authenticated through LDAP. Applies only when neither `ldapRoleField` nor `ldapRoleGroupMapping` is configured. Can also be an array representing the mapping of group memberships of the LDAP user with the corresponding MISP `role_id`, which is an older spelling of `ldapRoleGroupMapping` and still supported.
- **Type**: `integer` | `array`
- **Default**: `3`
- **Example**: `3`
- **Example of _LDAP group -> role_id_ mapping**: 
    ```
    [
        'misp_admin'        => 1,
        'misp_orgadmin'     => 2,
        'misp_user'         => 3,
        'misp_publisher'    => 4,
        'misp_syncuser'     => 5,
        'misp_readonly'     => 6,
    ]
    ```

### `ldapRoleField`
- **Description**: An attribute on the user's LDAP entry that holds their role. An all-digit value is looked up as a role ID, anything else as a role name (`admin`, `Org Admin`, `User`, `Publisher`, `Sync user`, `Read Only`). Several attributes may be given, in which case the first one present on the entry is used. Attribute names are matched case-insensitively.
- **Type**: `string` | `array`
- **Default**: unset, meaning `ldapDefaultRoleId` is used
- **Example**: `'title'`, or `['mispRole', 'title']`

### `ldapRoleGroupMapping`
- **Description**: Maps LDAP group memberships to MISP roles. Values are role IDs or names, resolved the same way as `ldapRoleField`. Keys are group CNs, or full group DNs when `ldapUseMemberOf` is enabled. Takes precedence over the array form of `ldapDefaultRoleId`, which does the same thing.
- **Precedence**: For a user in several mapped groups, **the first entry in this setting wins** — precedence is the order you write, not the order the directory happens to return memberships in. Put the group whose role should take priority first. The array form of `ldapDefaultRoleId` is the exception: it still resolves against the directory's order, left alone so upgrading does not silently move existing users between roles.
- **Type**: `array`
- **Default**: unset
- **Example**:
    ```
    [
        'misp_admin'    => 'admin',
        'misp_user'     => 3,
    ]
    ```

> **NOTE — how the role is resolved:** the same rules as the organisation, above. If neither `ldapRoleField` nor `ldapRoleGroupMapping` (nor the array form of `ldapDefaultRoleId`) is configured, everyone gets `ldapDefaultRoleId`. If any of them is, the role comes from the directory: the attribute is tried first, then the groups, and **if none of them resolves an existing MISP role the login is refused** rather than falling back to `ldapDefaultRoleId` — defaulting there would grant permissions nobody asked for. A role that is mapped but does not exist in MISP counts as unresolved, so a typo in a role name refuses the login instead of silently misassigning.
>
> One difference from the organisation: when an **existing** user can no longer be given a role, the account is also **disabled**, not merely refused. That is long-standing behaviour for roles and is what makes removing someone from their LDAP group revoke their access.

### `updateUser`
- **Description**: Indicates whether user information in the local application database should be updated with LDAP data on each login. If the user exists on MISP but the LDAP role doesn't, the user is disabled and not allowed to log in.
- **Type**: `boolean`
- **Default**: `true`
- **Example**: `true`


### `debug`
- **Description**: Increments the default debug level of the PHP LDAP library.
- **Type**: `boolean`
- **Default**: `false`
- **Example**: `true`

### `ldapTlsRequireCert`
- **Description**: Sets the value for `LDAP_OPT_X_TLS_REQUIRE_CERT` setting.
- **Type**: `int`
- **Default**: `LDAP_OPT_X_TLS_DEMAND`
- **Options**: `LDAP_OPT_X_TLS_NEVER` | `LDAP_OPT_X_TLS_HARD` | `LDAP_OPT_X_TLS_DEMAND` | `LDAP_OPT_X_TLS_ALLOW` | `LDAP_OPT_X_TLS_TRY`
- **Example**: `LDAP_OPT_X_TLS_NEVER`

### `ldapTlsCustomCaCert`
- **Description**: Sets the value for `LDAP_OPT_X_TLS_CACERTDIR` and `LDAP_OPT_X_TLS_CACERTFILE`. Ensure the file is readable by the PHP user (`www-data` or `apache` depending on the system).
- **Type**: `boolean|string`
- **Default**: `false`
- **Example**: `/var/wwww/MISP/app/files/certs/ldap.crt`

### `ldapTlsCrlCheck`
- **Description**: Sets the value for `LDAP_OPT_X_TLS_CRLCHECK`.
- **Type**: `int`
- **Options**: `LDAP_OPT_X_TLS_CRL_NONE`|`LDAP_OPT_X_TLS_CRL_PEER`|`LDAP_OPT_X_TLS_CRL_ALL`.
- **Default**: `LDAP_OPT_X_TLS_CRL_PEER`
- **Example**: `LDAP_OPT_X_TLS_CRL_NONE`

### `ldapTlsProtocolMin`
- **Description**: Sets the value for `LDAP_OPT_X_TLS_PROTOCOL_MIN`.
- **Type**: `int`
- **Options**: `LDAP_OPT_X_TLS_PROTOCOL_SSL2`|`LDAP_OPT_X_TLS_PROTOCOL_SSL3`|`LDAP_OPT_X_TLS_PROTOCOL_TLS1_0`|`LDAP_OPT_X_TLS_PROTOCOL_TLS1_1`|`LDAP_OPT_X_TLS_PROTOCOL_TLS1_2`
- **Default**: `LDAP_OPT_X_TLS_PROTOCOL_TLS1_2`
- **Example**: `LDAP_OPT_X_TLS_PROTOCOL_SSL3`

* See also: https://www.php.net/manual/en/ldap.constants.php

### `ldapEscape`
- **Description**: Escapes filters sent to ldap_search.
- **Type**: `boolean`
- **Default**: `false`
- **Example**: `true`

### `ldapEscapeIgnoreChars`
- **Description**: Characters to ignore when escaping .
- **Type**: `string`
- **Default**: `""`
- **Example**: `" "`

### `ldapUseMemberOf`
- **Description**: When enabled, group membership is resolved by reading the `memberOf` attribute directly from the user entry instead of searching for groups whose `member` attribute contains the user DN. Recommended for Microsoft Active Directory. When enabled, keys in the group mappings must be the full group DN (e.g. `CN=MISP Admins,OU=Groups,DC=example,DC=com`) rather than the group CN. Resolves **direct** memberships only, since Active Directory does not populate `memberOf` transitively; see `ldapNestedGroups`.
- **Type**: `boolean`
- **Default**: `false`
- **Example**: `true`

## Reconciling accounts from the CLI

A login is the only thing that normally re-checks a user against the
directory, so somebody removed from LDAP keeps their MISP account — and any
API keys on it — until they next try to sign in. `cake User check_validity`
closes that gap by re-running the same decisions in bulk:

```bash
# report only
app/Console/cake User check_validity

# disable accounts the directory no longer backs
app/Console/cake User check_validity --block_invalid

# also write back organisation and role changes
app/Console/cake User check_validity --block_invalid --update

# a single user, by id or address
app/Console/cake User check_validity alice@example.com
```

An account is considered invalid when it is **absent from the directory**,
**disabled there** (`userAccountControl`, if `ldapCheckUserAccountControl` is
on), or **no longer resolves to a role**. The same code decides this as at
login, so the two cannot disagree about who is allowed in.

`--update` additionally applies organisation and role changes, but only when
`updateUser` is also enabled: the flag says *do it now*, the setting says the
directory owns those fields at all, and a CLI run should not overrule an
instance that has turned it off.

### Scheduling it

The same reconciliation is schedulable from the UI, under
*Administration → Scheduled Tasks → Add*, as task type **Admin** with one of:

| Action | Equivalent to |
| --- | --- |
| Check User Validity (report only) | `check_validity` |
| Check User Validity (disable invalid users) | `check_validity --block_invalid --update` |

They are separate actions rather than one with a checkbox so that scheduling
the destructive variant is an explicit choice. Both are also available as
`cake Admin checkUserValidity` / `cake Admin blockInvalidUsers`, which is what
the scheduler runs; each dispatches `cake User check_validity` rather than
reimplementing it, and writes its outcome to the task's job so the Tasks index
shows the result and per-user lines are in the job log.

Scheduled tasks need the scheduler worker running — the Tasks index says so if
it is not.

Four things worth knowing before running it with `--block_invalid`:

* **Site admins are reported but never disabled or moved.** Nothing
  distinguishes an LDAP-provisioned account from a local one — the plugin
  creates users with an empty password, which is then hashed like any other —
  so a directory that does not list `admin@admin.test` makes it look invalid.
  Disabling every site admin would lock the instance out of its own
  administration, and that cannot be undone from inside MISP. Revoke admins in
  the directory and disable them by hand.
* **With `mixedAuth` enabled, absence from LDAP is ignored.** Local accounts
  are legitimate in that mode and indistinguishable from LDAP ones, so they
  are left alone. Only with `mixedAuth` off does a missing entry mean the
  account is dead.
* **It only ever disables, never re-enables.** The command skips accounts that
  are already disabled, so someone restored in the directory is re-enabled by
  their next successful login (which `updateUser` does), not by this command.
* **A failed reader bind aborts the run** rather than treating every user as
  missing. Otherwise one wrong credential would disable the entire instance.

If both `OidcAuth.Oidc` and `LdapAuth.Ldap` are in `Security.auth`, the
command uses OIDC, which is what it did before LDAP support was added.

## Authenticating on a header from a front-end proxy

For deployments where an Apache in front of MISP performs the authentication —
Kerberos via `mod_auth_gssapi`, for instance — and passes the resulting
username on in an HTTP header.

The user still has to exist in the directory: the header only replaces the
password, so the entry must be found under `ldapDn`, must not be disabled, and
its organisation and role are resolved exactly as for a form login, including
provisioning on first sight.

### `ldapHeaderAuth`
- **Description**: Enable authentication from a header set by a trusted proxy. Off by default.
- **Type**: `boolean`
- **Default**: `false`
- **Example**: `true`

### `ldapHeaderAuthHeader`
- **Description**: The header carrying the authenticated username. Either an HTTP header name (`X-Remote-User`, matched case-insensitively and translated to `HTTP_X_REMOTE_USER`) or a raw server variable (`REMOTE_USER`, which Apache sets itself when it performs the Kerberos handshake in the same process rather than proxying). The value is matched against `ldapSearchAttribute`, so with the default it should be the user's mail address; point `ldapSearchAttribute` at `userPrincipalName` or `sAMAccountName` if the proxy passes one of those instead.
- **Type**: `string`
- **Default**: unset
- **Example**: `'X-Remote-User'`

### `ldapHeaderAuthTrustedProxies`
- **Description**: The addresses allowed to assert an identity. Accepts single addresses or CIDR ranges, IPv4 and IPv6, as a list or a comma-separated string. **Required**: with this empty the header is refused outright.
- **Type**: `array` | `string`
- **Default**: `[]`
- **Example**: `['10.0.0.7', '192.0.2.0/24']`

> **NOTE — why the proxy list is mandatory.** A header is just something the
> client sends. Anyone who can reach MISP directly can set it and name any
> account, so it is worth nothing unless the request demonstrably came from the
> proxy you put in front. With no list there is nothing to check against, so
> the plugin refuses rather than trusting it, and logs why.
>
> The check compares against `REMOTE_ADDR`, the peer address, and nothing else.
> A forwarded-for style header cannot be used for this: it is set by the same
> client whose claim is in question. Note MISP's own `_remoteIp()` *does*
> honour `MISP.log_client_ip_header`, which is right for logging and wrong for
> a trust decision, so it is deliberately not used here.
>
> **Deploy accordingly:** MISP must not be reachable except through the proxy,
> and the proxy must overwrite the header on every request rather than passing
> a client-supplied one through. A trusted proxy that forwards whatever the
> client sent is the same hole with extra steps.
>
> A header from an untrusted source is *ignored*, not fatal: the request falls
> through to the normal login form, so a stray header cannot lock anyone out.
> Unlike a form login there is no `mixedAuth` fallback — a name the directory
> does not know is refused rather than matched against local accounts.

MISP core has an unrelated header mechanism, `Plugin.CustomAuth_*`, which
matches the header against an existing MISP user and does no directory lookup:
no provisioning, no organisation or role mapping. Use that if you have no LDAP
directory behind the proxy; use these settings if you do.

## Disabled Active Directory accounts

### `ldapCheckUserAccountControl`
- **Description**: When enabled, an entry whose Active Directory `userAccountControl` attribute has the `ACCOUNTDISABLE` bit (`2`) set is refused, and the matching MISP account is **disabled**. Off by default, so only instances whose directory populates the attribute meaningfully consult it.
- **Type**: `boolean`
- **Default**: `false`
- **Example**: `true`

Two details worth knowing once it is on:

* The attribute is a **bit field**, so the flag is masked rather than compared.
  An ordinary enabled account reads `512` and the same account disabled reads
  `514`; combined with other flags it can be `66050`. All of those with the
  bit set are treated as disabled.
* It is evaluated against the directory entry, **not** the bind result. AD
  refuses the bind for a disabled account, so waiting for that would never
  reveal why and would leave the MISP account enabled. The revocation
  therefore lands the next time that person attempts to log in, not at the
  moment the directory changes.

Note this is the one case where MISP's `disabled` flag is set *from* the
directory. In the other direction the flag is not respected: an account
disabled in MISP but still active in LDAP is re-enabled on its next login, so
revocation belongs in the directory.

### `ldapNestedGroups`
- **Description**: Resolve group membership through nested groups, so a user who belongs to a group only by way of another group still matches. Without it, only groups listing the user directly are matched, by either membership lookup.
- **Type**: `boolean`
- **Default**: `false`
- **Example**: `true`

> **NOTE — Active Directory only.** This works by applying AD's `LDAP_MATCHING_RULE_IN_CHAIN` (`1.2.840.113556.1.4.1941`) to the `member` search, which makes the directory walk the chain server-side. No other directory implements that matching rule, and OpenLDAP in particular answers an extensible match it does not recognise with **success and zero entries** rather than an error. The plugin therefore cannot distinguish "this user has no groups" from "this directory ignored the rule": every group mapping resolves to nothing and the affected logins are refused. A warning naming the matching rule is logged whenever the setting is on and no groups come back, so check `app/tmp/logs/error.log` before assuming the mappings are wrong.
>
> Two further consequences:
> * It **overrides `ldapUseMemberOf`**, which is logged. `memberOf` cannot answer this question, so groups are searched from the group side instead. `ldapDn` must therefore contain the groups, and the mapping keys are group CNs rather than DNs.
> * The chain walk is more expensive than a plain `member` match, and on large directories it can be noticeably slower per login.


## Example Usage

To configure these settings in your application, ensure each setting is defined in your configuration file as follows:

```php
'LdapAuth' => [
    'ldapServer' => 'ldap://ldap.example.com',
    'ldapDn' => 'dc=example,dc=com',
    'ldapReaderUser' => 'cn=reader,dc=example,dc=com',
    'ldapReaderPassword' => 'password',
    'ldapSearchFilter' => '(objectClass=inetOrgPerson)',
    'ldapSearchAttribute' => 'mail',
    'ldapEmailField' => ['mail', 'uid'],
    'ldapNetworkTimeout' => -1,
    'ldapProtocol' => 3,
    'ldapAllowReferrals' => 0,
    'starttls' => true,
    'mixedAuth' => true,
    'ldapDefaultOrg' => 1,
    'ldapOrgField' => 'o',
    'ldapDefaultRoleId' => 3,
    'updateUser' => true
]
```

Adjust the values as needed based on your LDAP server setup.

## Troubleshooting
* Start your tests with `debug` set to `true`.
* Start your tests with `starttls` set to `false`.
* Check `app/tmp/logs/error.log`, you can see the error responses from the LDAP server.

### TLS
If experiencing issues when configuring MISP to use LDAPS, try:
1. Set `ldapTlsRequireCert` to `LDAP_OPT_X_TLS_NEVER`.
2. Set `ldapTlsCrlCheck` to `LDAP_OPT_X_TLS_CRL_NONE`
3. Set `ldapTlsProtocolMin` to `LDAP_OPT_X_TLS_PROTOCOL_SSL3`.
4. Then set the this setting to the correct (safe) value one at a time.


* Ensure the user www-data has sufficient permissions to read the custom CA certificate. 

* If you are using a self-signed certificate, ensure the CN matches the host name of the LDAP server, otherwise the TLS session will fail.

* If you are using a custom CA cert (ldapTlsCustomCaCert) please ensure the certificate file is readable by the php user (`www-data` or `apache` depending on the system).

#### Debugging

There is a test/diagnostics script that uses the LdapAuth configuration from `app/Config/config.php`

**Usage:**
`php app/Plugin/LdapAuth/Controller/Component/Auth/TestLdapAuth.php`

```
################################################
##           LdapAuth test script             ##
################################################
LdapAuth Configuration:
Array
(
    [ldapServer] => ldap://openldap:1389
    [ldapDn] => dc=example,dc=com
    [ldapReaderUser] => cn=reader,dc=example,dc=com
    [ldapReaderPassword] => readerpassword
    [ldapSearchFilter] => (objectclass=inetOrgPerson)
    [ldapSearchAttribute] => mail
    [ldapEmailField] => Array
        (
            [0] => mail
        )

    [ldapNetworkTimeout] => -1
    [ldapProtocol] => 3
    [ldapAllowReferrals] => 1
    [starttls] => 
    [mixedAuth] => 1
    [ldapDefaultOrgId] => 1
    [ldapDefaultRoleId] => 3
    [updateUser] => 1
    [debug] => 
    [ldapTlsRequireCert] => 2
    [ldapTlsCustomCaCert] => 
    [ldapTlsCrlCheck] => 1
    [ldapTlsProtocolMin] => 771
)


LdapAuth Connection:
ldap_url_parse_ext(ldap://localhost/)
ldap_init: trying /etc/ldap/ldap.conf
ldap_init: using /etc/ldap/ldap.conf
[]...]
ldap_create
ldap_url_parse_ext(ldap://openldap:1389)no  
ldap_sasl_bind_s
ldap_sasl_bind
ldap_send_initial_request
ldap_new_connection 1 1 0
ldap_int_open_connection
ldap_connect_to_host: TCP openldap:1389
ldap_new_socket: 4
ldap_prepare_socket: 4
ldap_connect_to_host: Trying 172.19.0.5:1389
ldap_pvt_connect: fd: 4 tm: -1 async: 0
attempting to connect: 
connect success
ldap_open_defconn: successful
ldap_send_server_request
[...]
ldap_free_request_int: lr 0x557da8b88240 msgid 1 removed
ldap_do_free_request: asked to free lr 0x557da8b88240 msgid 1 refcnt 0
ldap_parse_result
ldap_msgfree
[Info] LDAP bind with reader user successful.
Enter the email to search in the LDAP server: jdoe@example.com
LDAP search filter: (&(objectclass=inetOrgPerson)(mail=jdoe@example.com))
ldap_search_ext
put_filter: "(&(objectclass=inetOrgPerson)(mail=jdoe@example.com))"
put_filter: AND
put_filter_list "(objectclass=inetOrgPerson)(mail=jdoe@example.com)"
put_filter: "(objectclass=inetOrgPerson)"
put_filter: simple
put_simple_filter: "objectclass=inetOrgPerson"
put_filter: "(mail=jdoe@example.com)"
put_filter: simple
put_simple_filter: "mail=jdoe@example.com"
ldap_build_search_req ATTRS: mail
[...]
User Data:
Array
(
    [count] => 1
    [0] => Array
        (
            [mail] => Array
                (
                    [count] => 1
                    [0] => jdoe@example.com
                )

            [0] => mail
            [count] => 1
            [dn] => uid=jdoe,ou=users,dc=example,dc=com
        )

)

LDAP bind with user: uid=jdoe,ou=users,dc=example,dc=com
Enter password: ********
[...]
[Success] LDAP user authentication successful!
ldap_free_connection 1 1
ldap_send_unbind
ldap_free_connection: actually freed
ldap_msgfree
```

Additionally, you can install `ldap-utils` and use the `ldapsearch` tool to verify the connection.
In this scenario you may have to edit the `/etc/ldap/ldap.conf` to match the LDAP settings used by MISP

Example `/etc/ldap/ldap.conf` configuration using a custom CA, equivalent to setting `LdapAuthldapTlsCustomCaCert`:
```
#
# LDAP Defaults
#

# See ldap.conf(5) for details
# This file should be world readable but not world writable.

#BASE   dc=example,dc=com
#URI    ldap://ldap.example.com ldap://ldap-provider.example.com:666

#SIZELIMIT      12
#TIMELIMIT      15
#DEREF          never

# TLS certificates (needed for GnuTLS)

#TLS_CACERT     /etc/ssl/certs/ca-certificates.crt
#TLS_REQCERT    never

TLS_CACERTDIR   /var/www/MISP/app/files/certs
TLS_CACERT      /var/www/MISP/app/files/certs/ldap.crt
```

Example test (failed) search:
```
# ldapsearch -H ldaps://localhost:1636 -x -b "dc=example,dc=com" -D "cn=reader,dc=example,dc=com" -w password -d 1
TLS: hostname (localhost) does not match common name in certificate (ldap.example.com).
TLS: can't connect: (unknown error code).

### Known issues
#### Error: [LdapAuth] LDAP user search failed: Operations error
```
Warning (2): ldap_search(): Search: Operations error in [/var/www/MISP/app/Plugin/LdapAuth/Controller/Component/Auth/LdapAuthenticate.php, line ...]
```

Try setting `"ldapAllowReferrals" => 0`
