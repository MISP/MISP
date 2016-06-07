#Client SSL Certificate Authentication for CakePHP

This plugin enables CakePHP applications to use client SSL certificates to stateless authenticate its users. It reads information from the client certificate and can synchronize data with a foreign REST API and the client User model.

Basically it loads the `SSL_CLIENT_*` variables, parses and maps the certificate information to the user. So you first need a server that checks client certificates and forwards that information to the PHP `$_SERVER` environment.

## Usage

Enable the plugin at bootstrap.php:

```php
CakePlugin::load('CertAuth');
```

And configure it:

```php
Configure::write('CertAuth',
  array(
    'ca'    => array( 'FIRST.Org' ), // allowed CAs
    'caId'          => 'O',          // which attribute will be used to verify the CA
    'userModel'     => 'User',       // name of the User class to check if user exists
    'userModelKey'  => 'nids_sid',   // User field that will be used for querying
    'map'           => array(        // maps client certificate attributes to User properties
      'O'           => 'org',
      'emailAddress'=>'email',
    ),
    'syncUser'      => true,         // should the User be synchronized with an external REST API
    'restApi'       => array(        // API parameters
      'url'         => 'https://example.com/data/users',  // URL to query
      'headers'     => array(),                           // additional headers, used for authentication
      'param'       => array( 'email' => 'email'),        // query parameters to add to the URL, mapped to USer properties
      'map'         =>  array(                            // maps REST result to the User properties
        'uid'       => 'id',
        'name'      => 'name',
        'company'   => 'org',
        'email'     => 'email',
      ),
    ),
    'userDefaults'  => array ( 'role_id' => 3 ),          // default attributes for new users
  )
);
```

If you set *syncUser* to *true* and *restApi.url* to *null*, new users will be created with the defaults defined by *userDefaults* without the need for a REST server.

