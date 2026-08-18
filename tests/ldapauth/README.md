# LdapAuth plugin test suite

End-to-end tests for `app/Plugin/LdapAuth`. They drive a real MISP instance and
a real LDAP directory, so the PHP plugin
(`Controller/Component/Auth/LdapAuthenticate.php`) is the code under test.

## Requirements

* A running MISP instance with `LdapAuth.Ldap` in `Security.auth`.
* A running LDAP server the MISP instance can reach.
* `python3 -m pip install ldap3 pytest requests`

`test_connection.py` passes without the plugin enabled, but every test that
logs in as an LDAP user needs it switched on. Having an `LdapAuth` block in
`app/Config/config.php` is **not** enoug, the authenticate handler must also
be listed:

```php
'Security' => [
    'auth' => ['LdapAuth.Ldap'],
],
```

Verify what the instance is actually running with:

```bash
php -r '$c = include "app/Config/config.php"; var_export($config["Security"]["auth"] ?? "NOT SET");'
```

An empty array means logins never reach the plugin, they fall through to
regular database authentication and the tests will fail for the wrong reason.

## Running

```bash
export AUTH=<admin authkey>
python3 -m pytest tests/ldapauth -v
```

The defaults match the local docker setup (bitnami/openldap + misp-core).
Override anything via environment variables:

| Variable | Default | Notes |
| --- | --- | --- |
| `LDAP_URI` | `ldap://127.0.0.1:1389` | As seen **from the test runner** |
| `LDAP_ADMIN_DN` | `cn=admin,dc=example,dc=com` | Creates fixtures; not the plugin's reader |
| `LDAP_ADMIN_PASSWORD` | `password` | |
| `LDAP_READER_DN` | `cn=testuser,ou=users,dc=example,dc=com` | Must match `LdapAuth.ldapReaderUser` |
| `LDAP_READER_PASSWORD` | `userpassword` | Must match `LdapAuth.ldapReaderPassword` |
| `LDAP_ROOT` | `dc=example,dc=com` | Directory root |
| `LDAP_SEARCH_BASE` | `ou=users,dc=example,dc=com` | Must match MISP's `LdapAuth.ldapDn` |
| `LDAP_USERS_OU` | `ou=users` | Created if missing |
| `LDAP_GROUPS_OU` | `ou=groups` | Created if missing |
| `LDAP_CONTAINER` | `misp-docker-openldap-1` | Used only to enable the memberof overlay |
| `LDAP_AUTO_MEMBEROF` | `1` | Set `0` to never touch the directory's config |
| `LDAP_MEMBEROF_MODULE` | `/opt/bitnami/openldap/lib/openldap/memberof.so` | Absolute path, see below |
| `MISP_CONTAINER` | `misp-docker-misp-core-1` | Empty when MISP runs on this host |
| `MISP_CONFIG_SETTLE_SECONDS` | auto-detected | Wait after a config write, see below |
| `MISP_URL` | `https://localhost` | |
| `MISP_VERIFY_SSL` | `0` | Set to `1` for a real certificate |
| `MISP_LDAP_ORG_ID` | `1` | Must match `LdapAuth.ldapDefaultOrgId` |
| `MISP_LDAP_ROLE_ID` | `3` | Must match `LdapAuth.ldapDefaultRoleId` |
| `MISP_LDAP_MIXED_AUTH` | `0` | Must match `LdapAuth.mixedAuth` |
| `AUTH` | *(unset)* | Admin authkey, used to clean up provisioned users |

`LDAP_SEARCH_BASE` is deliberately separate from `LDAP_ROOT`: narrowing
`ldapDn` to the users OU is common, and it decides which entries the plugin can
see at all. Fixture users are created inside the search base so the plugin can
actually find them.

Note also that MISP reaches the directory by its own hostname
(`ldap://openldap:1389` inside docker) while the tests reach it on the published
port, the same server under two names, which is why `LDAP_URI` is configured
separately from MISP's `LdapAuth.ldapServer`.

## Cleanup

Directory entries are always removed at the end of each test. A **successful
login also auto-provisions a local MISP user**, which outlives the directory
entry, so the suite deletes those through the admin API using `AUTH`
(`MISP_ADMIN_KEY` is accepted as an alias).

Without `AUTH` the suite still passes, since fixture emails are unique per
test, but it emits a warning once and the accounts accumulate. To prune them
by hand:

```bash
curl -sk -H "Authorization: $AUTH" -H "Accept: application/json" \
     "$MISP_URL/admin/users.json" \
  | python3 -c "import sys,json; print('\n'.join(u['User']['id'] for u in json.load(sys.stdin) if u['User']['email'].startswith('misptest-')))" \
  | xargs -I{} curl -sk -X POST -H "Authorization: $AUTH" "$MISP_URL/admin/users/delete/{}"
```

## Layout

* `conftest.py`: env-driven config, the admin LDAP connection, the
  create-and-tear-down fixture factory, a MISP web-session client that
  satisfies CakePHP's `SecurityComponent` tokens, and the admin API client used
  for cleanup.
* `test_connection.py`: connectivity only, reader bind, base DN, search
  behaviour, fixture bind, and a MISP login form that is actually being served.
  If these fail, every other failure in the suite is noise.
* `test_login.py`: the plugin's login path, successful authentication,
  auto-provisioning with the configured org/role, repeat logins reusing the
  same account, case-insensitive address matching, duplicate `mail` entries,
  wrong passwords, users invisible to `ldapSearchAttribute`, unknown users,
  the `mixedAuth` fallback, and logout.
* `test_security.py`: the ways a login must be refused, empty passwords,
  search-filter injection, and accounts sitting outside `ldapDn`. Also pins
  the one case where a refusal is silently undone, see below.
* `test_settings.py`: settings that change how a login resolves, `mixedAuth`,
  `ldapSearchFilter`, `ldapSearchAttribute`, the `ldapEmailField` fallback,
  `updateUser`, and group-to-role mapping via `ldapDefaultRoleId`. These
  rewrite the instance's config, see below.

## Fixtures

`ldap_fixtures` creates entries and deletes them at the end of each test:

```python
def test_something(ldap_fixtures, misp):
    user = ldap_fixtures.add_user(mail="alice@example.com", password="s3cret")
    group = ldap_fixtures.add_group(cn="misp_admin", members=[user["dn"]])
    misp.login(user["mail"], user["password"])
    assert misp.is_authenticated()
```

`add_user(mail=None)` creates a user with **no** `mail` attribute, which is how
you test entries that `ldapSearchAttribute` cannot match. Container OUs
(`ou=users`, `ou=groups`) are created only when missing and never deleted.

## Configuration traps

Two misconfigurations that produce confusing failures, both seen in practice:

1. **`ldapReaderUser` must be a full DN.** A bare `testuser` fails the reader
   bind with `Invalid DN syntax`, and the plugin throws before it ever looks at
   the user's credentials, so *every* login fails, with the error attributed to
   the person logging in rather than to the reader account.
2. **`mixedAuth => false` locks local accounts out of the web form**, including
   `admin@admin.test`, since they have no LDAP entry. API access via authkey is
   unaffected, which is why `AUTH` still works for cleanup.

## Changing settings from a test

`ldap_settings` rewrites the running instance's `LdapAuth` block and restores
it when the test ends, with no container restart:

```python
def test_something(ldap_settings, misp, ldap_fixtures):
    user = ldap_fixtures.add_user()
    ldap_settings.set(ldapDn="dc=example,dc=com", ldapDefaultRoleId={"admins": 1})
    misp.login(user["mail"], user["password"])
```

It writes through MISP's own `tests/modify_config.php`, the same helper the
docker image uses, so the file ends up exactly as MISP would write it.
`cake Admin setSetting` cannot be used: `LdapAuth.*` keys are not in MISP's
settings schema and it answers "No valid setting found".

**These tests mutate instance-wide state — run them serially, never with
`pytest-xdist`.**

Two things make this slower than it looks:

* **PHP opcache.** `opcache.revalidate_freq` (2s by default here) means PHP
  re-stats `config.php` only every few seconds, so a freshly written setting
  is *not* in effect for the next request. The fixture waits
  `revalidate_freq * 2 + 1` seconds after each write, which measured reliable;
  `revalidate_freq + 0.5` was not. Override with `MISP_CONFIG_SETTLE_SECONDS`,
  and set `opcache.revalidate_freq=0` on a test instance to drop the wait
  entirely. Without this wait the tests fail confusingly: the login runs
  against the *previous* config, so the assertion is right and the state is
  wrong.
* **Brute-force protection.** `SecureAuth.amount` failed attempts (5) for one
  address blocks it for `SecureAuth.expire` seconds (300). Tests that
  deliberately fail logins therefore use a fresh fixture user rather than
  reusing one, and `bruteforces` is worth checking if a valid login starts
  being refused for no visible reason:

  ```sql
  SELECT ip, username, expire FROM bruteforces ORDER BY expire DESC;
  ```

## The memberof overlay

`ldapUseMemberOf` needs the directory to maintain a `memberOf` attribute on
each user. bitnami/openldap ships `memberof.so` but exposes no environment
variable for it, and its data lives in the container's writable layer rather
than a volume, so a recreated container comes back without it.

The `memberof_supported` fixture therefore enables it on demand, idempotently,
and the test skips only if that fails. Set `LDAP_AUTO_MEMBEROF=0` to opt out,
`LDAP_CONTAINER` to name the container (default `misp-docker-openldap-1`), and
`LDAP_MEMBEROF_MODULE` for the module path.

To do it by hand instead:

```bash
docker exec -i misp-docker-openldap-1 ldapmodify -Y EXTERNAL -H ldapi:/// <<'EOF'
dn: cn=module{0},cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: /opt/bitnami/openldap/lib/openldap/memberof.so

dn: olcOverlay=memberof,olcDatabase={2}mdb,cn=config
changetype: add
objectClass: olcOverlayConfig
objectClass: olcMemberOf
olcOverlay: memberof
olcMemberOfRefInt: TRUE
olcMemberOfGroupOC: groupOfNames
olcMemberOfMemberAD: member
olcMemberOfMemberOfAD: memberOf
EOF
```

Four things that make this fiddlier than it looks:

* **The module path must be absolute.** `olcModulePath` on this image points
  at `libexec/openldap`, which holds only `autogroup.so` and `pw-sha2.so`;
  `memberof.so` lives in `lib/openldap`. A bare `olcModuleLoad: memberof.so`
  therefore fails to find it.
* **`(olcDatabase=*mdb)` matches nothing.** That attribute has no substring
  matching rule, so the filter returns success with zero entries rather than
  an error. Enumerate `(objectClass=olcDatabaseConfig)` and pick the mdb DN.
* **A schema check is not a support check.** OpenLDAP cannot unload a module,
  so once `memberof.so` is loaded the attribute type stays advertised even if
  the overlay is deleted. Support is probed functionally instead: create a
  group and see whether `memberOf` actually appears.
* **`memberOf` is only maintained going forward.** Memberships that existed
  before the overlay was loaded do not get it retroactively, so the
  pre-existing `cn=readers` group has none. The fixtures create their groups
  per test, so this does not affect the suite.

## Behaviour worth knowing

Verified against a live instance while writing `test_security.py`:

* **Disabling a user in MISP does not lock them out.** With `updateUser`
  enabled the plugin writes `disabled = 0` every time it refreshes an account,
  so the next LDAP login silently re-enables it. Revocation has to happen in
  the directory, by removing the entry or the attribute that
  `ldapSearchAttribute` matches.
* **Empty passwords are refused by the directory, not by the plugin.**
  `ldap_bind()` is called with whatever was submitted and no empty-password
  check. OpenLDAP answers an unauthenticated bind with `Server is unwilling to
  perform`, but a directory configured to allow it would turn this into an
  authentication bypass for any known address.
* **The address is matched case-insensitively and canonicalised.** The MISP
  account is keyed on the value read back from the directory, not on what was
  typed, so varying the case cannot fork one person into several accounts.
