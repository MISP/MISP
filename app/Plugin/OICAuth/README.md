# Open ID Connect / Oauth 2 authentication

This plugin enables authentication with an identity provider using the protocol open id connect / oauth 2. Tested with:
Keycloak v11. Others might work as well.

Every user

Azure authentication code inspired by the implementation of Azure Directory authentication plugin.

## Configuration

1. Create a client within your IDP

Note your Client ID, Client Secret. Set the redirect url property to your MISP
instance and make sure you add the path /users/login. (https://my-misp.com/users/login)

2. Enable the plugin

Enable the plugin at bootstrap.php:

```php
CakePlugin::load('OICAuth');
```

3. Configure

* Uncomment the line "'auth'=>array('OICAuth.OpenIDConnect')," in Config.php, section "Security"

```php
  ....
  'Security' =>
  array (
    'level' => 'medium',
    'salt' => 'XXXX',
    'cipherSeed' => '',
    'require_password_confirmation' => true,
     'auth'=>array('OICAuth.OpenIDConnect'),
  ),
    .....
```

* Uncomment the following lines in Config.php, section "OICAuth" and configure them.

```php
	 'OICAuth' =>
        array(
        'idp_metadata_url' => '', # Keycloak example https://MY-KEYCLOAK.com/auth/realms/MY-REALM/.well-known/openid-configuration
        'client_id' => '', # client id of the newly created client
        'client_secret' => '', # client secret,
        'button_text' => 'My IDP', # Text of the button displayed on MISP login page
    ),
```
# Next steps

1. Implement client role enforcement
2. Auto create users.