# MISP OpenID Connect Authentication

This plugin provides ability to use OpenID as Single sign-on for login users to MISP.
When plugin is enabled, users are direcly redirected to SSO provider and it is not possible
to login with passwords stored in MISP.

## Usage

1. Install required library using composer

```
cd app
php composer.phar require jumbojett/openid-connect-php
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

* When user is blocked in SSO (IdM), he/she will be not blocked in MISP. He could not log in, but users authentication keys will still work and also he/she will still receive all emails. 

