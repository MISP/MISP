# Client SSO Authentication (Shibboleth based) for CakePHP

This plugin enables CakePHP applications to use Single Sign-On to authenticate its users. It gets the information given by Apache environment variables.


## Usage

### Prerequisites - Shibboleth Service Provider
The MISP plugin takes care of the mapping of your shibboleth session attributes to MISP, but you will still need to install the service provider (SP) and configure it yourself. The documentation for Shibboleth Service Provider 3 can be found at https://wiki.shibboleth.net/confluence/display/SP3/Home.

To install Shibboleth SP3 on Ubuntu, you can use the instructions provided by SWITCH at https://www.switch.ch/aai/guides/sp/installation/ and then follow the below steps. If you already installed and configured Shibboleth you can skip this section.

Create signing and encryption certificate. The value following -e should be your entity ID, for example https://&lt;host&gt;/shibboleth.
```bash
sudo shib-keygen -f -u _shibd -h <host> -y 5 -e https://<host>/shibboleth -o /etc/shibboleth
```

Edit /etc/shibboleth/shibboleth2.xml to use the created certificate for both signing and encryption (change the values for key and certificate).
```xml
    <CredentialResolver type="File" use="signing"
        key="sp-key.pem" certificate="sp-cert.pem"/>
    <CredentialResolver type="File" use="encryption"
        key="sp-key.pem" certificate="sp-cert.pem"/>
```

Edit /etc/shibboleth/shibboleth2.xml to set secure cookie properties (cookieProps) if you want to.
```xml
<Sessions lifetime="28800" timeout="3600" relayState="ss:mem"
                  checkAddress="false" handlerSSL="false" cookieProps="https"
                  redirectLimit="exact">
```

At this point, you should already be able to test your configuration. The last line of the output should be "overall configuration is loadable, check console for non-fatal problems".
```bash
sudo shibd -t
```

Set entityID in /etc/shibboleth/shibboleth2.xml.
```xml
<ApplicationDefaults entityID="https://<host>/shibboleth"
        REMOTE_USER="eppn subject-id pairwise-id persistent-id"
        cipherSuites="DEFAULT:!EXP:!LOW:!aNULL:!eNULL:!DES:!IDEA:!SEED:!RC4:!3DES:!kRSA:!SSLv2:!SSLv3:!TLSv1:!TLSv1.1">
```

Copy your identity provider metadata to /etc/shibboleth, for example to /etc/shibboleth/idp-metadata.xml and refer to it in /etc/shibboleth/shibboleth2.xml. Uncomment and edit the relevant line.
```xml
<MetadataProvider type="XML" validate="true" path="idp-metadata.xml"/>
```

Optionally, you can make sure the service provider does not create a session if some attributes, like OrgTag and GroupTag are missing. If users attempt to login an this happens, they will receive a pre-configured reply (default at /etc/shibboleth/attrChecker.html).
In /etc/shibboleth/shibboleth2.xml, edit ApplicationDefaults by adding the sessionHook:
```xml
<ApplicationDefaults entityID="https://<HOST>/shibboleth"
  REMOTE_USER="eppn persistent-id targeted-id"
  signing="front" encryption="false"
  sessionHook="/Shibboleth.sso/AttrChecker"
```
Optional for attribute checking: add your checks (note that the incoming attribute names can be different for you, for more info on possible checks refer to https://wiki.shibboleth.net/confluence/display/SP3/Attribute+Checker+Handler):
```xml
<Handler type="AttributeChecker" Location="/AttrChecker" template="attrChecker.html" attributes="OrgTag GroupTag" flushSession="true"/>
```

At this point you will have to send your metadata to your identity provider. You can get template metadata based on your configuration from https://&lt;host&gt;/Shibboleth.sso/Metadata.

### MISP plugin configuration

Edit your MISP apache configuration by adding the below (location depends on your handler path, /Shibboleth.sso by default).
```Apache
  <Location /Shibboleth.sso>
    SetHandler shib
  </Location>

  <Location />
    AuthType shibboleth
    Require shibboleth
    # Optional: always directly redirect to the IdP upon access without
    # an active session. If not enabled, a "Login with SAML" button
    # will be shown on the login screen to start the login process..
    # ShibRequestSetting requiresession On
  </Location>

```

The above will always redirect to your IdP if MISP is accessed without
an active session. An alternative is not to require Shibboleth before
the application can be accessed but show the login screen if no
Shibboleth session is present. This will then have a
"Login with SAML" button to trigger the login.

You may need to tell the rewriterules for MISP in its `.htaccess` file not to apply to Shibboleth, so add a line to exclude this from processing:

```Apache
    RewriteEngine On
    RewriteCond %{REQUEST_URI} !^/Shibboleth\.sso
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^(.*)$ index.php?/$1 [QSA,L]
```

Configure it at config.php:

Uncomment the following line to enable SSO authorization
```php
'auth'=>array('ShibbAuth.ApacheShibb'),
```

If the line does not exist, add it to 'Security' array, for example like below. Note that you should just add the line to your own existing config.
```php
'Security' =>
  array (
    'level' => 'medium',
    'salt' => '',
    'cipherSeed' => '',
    'password_policy_length' => 12,
    'password_policy_complexity' => '/^((?=.*\\d)|(?=.*\\W+))(?![\\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/',
    'self_registration_message' => 'If you would like to send us a registration request, please fill out the form below. Make sure you fill out as much information as possible in order to ease the task of the administrators.',
    'auth'=>array('ShibbAuth.ApacheShibb'),
  )
```

The plugin needs to be configured. Here is the list of available directives:
  * MailTag => string: environment variable containing user email adress
  * OrgTag => string: environment variable containing user organization
  * GroupTag => string: environment variable containing user list of groups
  * GroupSeparator => char: multiple values separator (default: ";")
  * GroupRoleMatching => array(string => int): list of group/role identifier (3: user, 1: admin) mappings
  * DefaultOrg => string: name of default organization to use as fallback
  * DefaultRole => int: default role identifier to use as fallback
  * BlockRoleModifications => boolean: if true, roles will not be updated during login. Especially useful if you manually change roles in MISP
  * BlockOrgModifications => boolean: if true, organizations will not be updated during login. Especially useful if you manually change orgs in MISP

MailTag, OrgTag and GroupTag are the name of the environment variables (or HTTP
headers) used by the SAML Service Provider to pass user attributes from the
SAML response to the application. A local Shibboleth Service Provider,
receiving SAML attributes mail, schacHomeOrganization and eduPersonAffiliation,
and using default mappings, for instance, will need the
following settings:
```php
     'MailTag'  => 'mail',
     'OrgTag'   => 'schacHomeOrganization',
     'GroupTag' => 'unscoped-affiliation',
```
A different set of attributes, a different SAML implementation, or a different
setup, will require different settings.

MailTag is mandatory, at least one of OrgTag or DefaultOrg is mandatory, at
least one of GroupTag+GroupRoleMatching or DefaultRole is mandatory.

Here is a complete working configuration, using dynamic organization and role
assignement from SAML response, and using default values as fallback if related
user attribute is missing:

```php
'ApacheShibbAuth' =>
    array(
         'MailTag'               => 'mail',
         'OrgTag'                => 'schacHomeOrganization',
         'DefaultOrg'            => 'my.organization.tld',
         'GroupTag'              => 'unscoped-affiliation',
         'GroupRoleMatching'     => array(
               'member' => 3,
               'staff'  => 1,
          ),
         'DefaultRole'            => 3,
         'BlockRoleModifications' => false,
         'BlockOrgModifications'  => false,
    ),
```

If used with Apache as webserver it might be useful to make a distinction to filter out API/Syncs from SSO login. It can be added to the vhost as follows (Added lines are the If/Else clauses):

```Apache
  <Directory /var/www/MISP/app/webroot>
    Options -Indexes
    AllowOverride all
    <If "-T req('Authorization')">
        Require all granted
        AuthType None
    </If>
    <Else>
        Require valid-user
        AuthType shibboleth
        ShibRequestSetting requiresession On
    </Else>
  </Directory>
```

If you want the logout button to work for killing your session, you can use the CustomAuth plugin to configure a custom logout url, by default the url should be https://&lt;host&gt;/Shibboleth.sso/Logout. This leads to a local logout. If you want to also trigger a logout at the identity provider, you can use the return mechanism. In this case you will need to change the allowed redirects. Your logout url will look like https://&lt;host&gt;/Shibboleth.sso/Logout?return=https://<idp_host>/Logout. Edit your shibboleth configuration (often at /etc/shibboleth/shibboleth2.xml) as necessary. Relevant shibboleth documentation can be found at https://wiki.shibboleth.net/confluence/display/SP3/Logout and https://wiki.shibboleth.net/confluence/display/SP3/Sessions.
```xml
<Sessions lifetime="28800" timeout="3600" relayState="ss:mem"
                  checkAddress="false" handlerSSL="true" cookieProps="https"
                  redirectLimit="exact+whitelist" redirectWhitelist="https://<idp_host>">
```


