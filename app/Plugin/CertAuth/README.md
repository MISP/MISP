# Client SSL Certificate Authentication for CakePHP

This plugin enables CakePHP applications to use client SSL certificates to stateless authenticate its users. It reads information from the client certificate and can synchronize data with a foreign REST API and the client User model.

Basically it loads the `SSL_CLIENT_*` variables, parses and maps the certificate information to the user. So you first need a server that checks client certificates and forwards that information to the PHP `$_SERVER` environment.

## Configuration

1. Enable the plugin

Enable the plugin at bootstrap.php:

```php
CakePlugin::load('CertAuth');
```

2. Configure

* Uncomment the line "'auth'=>array('CertAuth.Certificate')," in Config.php, section "Security"

```php
    ....
	'Security'         =>
		array(
			'level'      => 'medium',
			'salt'       => '',
			'cipherSeed' => '',
		    'auth'=>array('CertAuth.Certificate'), // additional authentication methods
			//'auth'=>array('ShibbAuth.ApacheShibb'dd),
		),
    .....
```

* Uncomment the following lines in Config.php, section "CertAuth" and configure them.

```php
	'CertAuth'         =>
        array(

            // CA
            'ca'           => array('FIRST.Org'), // List of CAs authorized
            'caId'         => 'O',          // Certificate field used to verify the CA. In this example, the field O (organization) of the client certificate has to equal to 'FIRST.Org' in order to validate the CA

            // User/client configuration
			'userModel'    => 'User',       // name of the User class (MISP class) to check if the user exists
            'userModelKey' => 'email',      // User field that will be used for querying. In this example, the field email of the MISP accounts will be used to search if the user exists.
            'map'          => array(        // maps client certificate attributes to User properties. This map will be used as conditions to find if the user exists. In this example, the client certificate fields 'O' (organization) and 'emailAddress' have to match with the MISP fields 'org' and 'email' to validate the user.
				'O'            => 'org',
				'emailAddress' => 'email',
            ),

            // Synchronization/RestAPI
			'syncUser'     => true,         // should the User be synchronized with an external REST API
			'userDefaults' => array(          // default user attributes, only used when creating new users. By default, new users are "Read only" users (role_id: 6).
				'role_id' => 6,
            ),
			'restApi'      => array(        // API parameters
				'url'     => 'https://example.com/data/users',  // URL to query
				'headers' => array(),                           // additional headers, used for authentication
				'param'   => array('email' => 'email'),       // query parameters to add to the URL, mapped to User properties
				'map'     => array(                            // maps REST result to the User properties
					'uid'        => 'nids_sid',
					'team'       => 'org',
					'email'      => 'email',
					'pgp_public' => 'gpgkey',
				),
			),
			'userDefaults' => array('role_id' => 6),          // default attributes for new users. By default, new users are "Read only" users (role_id: 6).
		),
```

If you set *syncUser* to *true* and *restApi.url* to *null*, new users will be created with the defaults defined by *userDefaults* without the need for a REST server.

