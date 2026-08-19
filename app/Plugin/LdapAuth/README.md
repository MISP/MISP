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
- **Description**: Maps LDAP group memberships to MISP organisations, for directories where the organisation is expressed as a group rather than an attribute. Values are organisation IDs or names, resolved the same way as `ldapOrgField`. Keys are group CNs, or full group DNs when `ldapUseMemberOf` is enabled, matching how `ldapDefaultRoleId` is keyed. The first group that maps to an existing organisation wins, so ordering matters for users in several mapped groups.
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
- **Description**: The default role ID assigned to users authenticated through LDAP. Can also be an array representing the mapping of group memberships of the LDAP user with the corresponding MISP `role_id`.
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
- **Description**: When enabled, group membership is resolved by reading the `memberOf` attribute directly from the user entry instead of searching for groups whose `member` attribute contains the user DN. Recommended for Microsoft Active Directory. When enabled, keys in `ldapDefaultRoleId` must be the full group DN (e.g. `CN=MISP Admins,OU=Groups,DC=example,DC=com`) rather than the group CN.
- **Type**: `boolean`
- **Default**: `false`
- **Example**: `true`


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
