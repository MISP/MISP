# Azure Active Directory authentication

This plugin enables authentication with an Azure Active Directory server. Under the hood it uses oAuth2.
There are still a number of rough edges but in general the plugin works.

It supports verification if a user has the proper 'MISP AD' groups.
Users should already exist in MISP. Future enhancement could include autocreate users

Azure authentication code inspired by https://www.sipponen.com/archives/4024

## Configuration

1. Create an Azure Application

In Azure, add a new App Registration. Select **Web** and set the Redirect URI to your MISP server login page (fe. https://localhost/users/login). The MISP instance does not need to be publicly accessible, as long as it's reacheable by your browser. The redirect URI that you specify here must be exactly the same as used in the MISP configuration. Then note the

* Application (client) ID
* Directory (tenant) ID

2. Set the application secret

In the application details, select Certificates & secrets and then add a new client secret. Note the 
* Client secret value

3. (optional) Add group permissions

If you want to limit access to users belonging to certain AD groups then add the permissions to query the group data. In the application details, select API permissions, select Microsoft Graph, Delegated permissions and add the permission 'Group.Read.All'. Once that's done, in the API permissions screen, click the "Grant admin consent".

4. Enable the plugin

Enable the plugin at bootstrap.php:

```php
CakePlugin::load('AadAuth');
```

5. Configure

* Uncomment the line "'auth'=>array('AadAuth.AadAuthenticate')," in Config.php, section "Security"

```php
    ....
	'Security'         =>
		array(
			'level'      => 'medium',
			'salt'       => '',
			'cipherSeed' => '',
		    'auth'=>array('AadAuth.AadAuthenticate'), 
		),
    .....
```

* Uncomment the following lines in Config.php, section "AadAuth" and configure them.

```php
	'AadAuth'         =>
        array(
			'client_id' => '', // Client ID (see Azure AD)
			'ad_tenant' => '', // Directory ID (see Azure AD)
			'client_secret' => '', // Client secret (see Azure AD)
			'redirect_uri' => '', // Your MISP URI, must be the same as in Azure AD
			'auth_provider' => 'https://login.microsoftonline.com/',	// Can be left to this default
			'auth_provider_user' => 'https://graph.microsoft.com/',		// Can be left to this default
			'misp_user' => 'MISP Users',	// The AD group for MISP users
			'misp_orgadmin' => 'MISP Administrators',	// The AD group for MISP administrators
			'misp_siteadmin' => 'MISP Site Administrators', 	// The AD group for MISP site administrators
			'check_ad_groups' => true	// Should we check if the user belongs to one of the above AD groups?
		),
```
