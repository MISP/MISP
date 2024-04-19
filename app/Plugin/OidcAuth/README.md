# MISP OpenID Connect Authentication

This plugin provides ability to use OpenID as Single sign-on for login users to MISP.
When plugin is enabled, users are directly redirected to SSO provider and it is not possible
to login with passwords stored in MISP.

## Usage

1. Install required library using composer

```
cd app
php composer.phar require jakub-onderka/openid-connect-php:1.0.0-rc1
```

2. Enable in `app/Config/config.php`

```php
$config = array(
    ...
    'Security' => array(
        ...
        'auth' => 'array('OidcAuth.Oidc')',
    ),
    ...
```

3. Configure in `app/Config/config.php` (replace variables in `{{ }}` with your values)

```php
$config = array(
    ...
    'OidcAuth' = [
        'provider_url' => '{{ OIDC_PROVIDER }}',
        'issuer' => '{{ OIDC_ISSUER }}', // If omitted, it defaults to provider_url
        'client_id' => '{{ OIDC_CLIENT_ID }}',
        'client_secret' => '{{ OIDC_CLIENT_SECRET }}',
        'role_mapper' => [ // if user has multiple roles, first role that match will be assigned to user
            'misp-user' => 3, // User
            'misp-admin' => 1, // Admin
        ],
        'default_org' => '{{ MISP_ORG }}',
    ],
    ...
```

## Caveats

When user is blocked in SSO (IdM), he/she will be not blocked in MISP. He could not log in, but users authentication keys will still work and also he/she will still receive all emails. 

To solve this problem:
1) set `OidcAuth.offline_access` to `true` - with that, IdP will be requested to provide offline access token
2) set `OidcAuth.check_user_validity` to number of seconds, after which user will be revalidated if he is still active in IdP. Zero means that this functionality is disabled. Recommended value is `300`.
3) because offline tokens will expire when not used, you can run `cake user check_user_validity` to check all user in one call
