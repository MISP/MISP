#Client SSO Authentication (Shibboleth based) for CakePHP

This plugin enables CakePHP applications to use Single Sign-On to authenticate its users. It gets the information given by Apache environment variables.


## Usage

Enable the plugin at bootstrap.php:

```php
CakePlugin::load('ShibbAuth');
```

And configure it at config.php:

Uncomment the following line to enable SSO authorization
```php
'auth'=>array('ShibbAuth.ApacheShibb'),
```

And configure it. MailTag, OrgTag and GroupTag are the string that represent the key for the values needed by the plugin.
For example if you are using ADFS OrgTag will be ADFS_FEDERATION, GroupTag will be ADFS_GROUP, etc. meaning the key for the values needed.
DefaultOrg are values that come by default just in case they are not defined or obtained from the environment variables.
The GroupRoleMatching is an array that allows the definition and correlation between groups and roles in MISP, being them updated
if the groups are updated (i.e. a user that was admin and their groups changed inside the organization will have his role changed in MISP
upon the next login being now user or org admin respectively). The GroupSeparator is the character used to separate the different groups
in the list given by apache.

```php
'ApacheShibbAuth' =>                      // Configuration for shibboleth authentication
    array(
         'MailTag' => 'EMAIL_TAG',
         'OrgTag' => 'FEDERATION_TAG',
	 'GroupTag' => 'GROUP_TAG',
	 'GroupSeparator' => ';',
         'GroupRoleMatching' => array(                // 3:User, 1:admin. May be good to set "1" for the first user
               'group_three' => '3',
	       'group_two' => 2,
	       'group_one' => 1,
          ),
         'DefaultOrg' => 'DEFAULT_ORG',
    ),
```
If used with Apache as webserver it might be useful to make a distinction to filter out API/Syncs from SSO login. It can be added to the vhost as follows:

```Apache
  <If "-T reqenv('HTTP_AUTHORIZATION')">
    Require all granted
    AuthType None
  </If>
  <Else>
    Require valid-user
    AuthType shibboleth
    ShibRequestSetting requiresession On
    ShibRequestSetting shibexportassertion Off
    ShibUseHeaders On
  </Else>
```


