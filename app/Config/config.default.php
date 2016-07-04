<?php
$config = array (
  'debug' => 0,
  'Security' =>
  array (
    'level' => 'medium',
    'salt' => 'Rooraenietu8Eeyo<Qu2eeNfterd-dd+',
    'cipherSeed' => '',
    //'auth'=>array('CertAuth.Certificate'), // additional authentication methods
  ),
  'MISP' =>
  array (
    'baseurl' => '',
    'footermidleft' => '',
    'footermidright' => '',
    'org' => 'ORGNAME',
    'showorg' => true,
    'background_jobs' => true,
    'cached_attachments' => true,
    'email' => 'email@address.com',
    'contact' => 'email@address.com',
    'cveurl' => 'http://cve.circl.lu/cve/',
    'disablerestalert' => false,
    'default_event_distribution' => '1',
    'default_attribute_distribution' => 'event',
    'tagging' => true,
    'full_tags_on_event_index' => true,
    'footer_logo' => '',
    'take_ownership_xml_import' => false,
    'unpublishedprivate' => false,
  	'disable_emailing' => false,
  ),
  'GnuPG' =>
  array (
    'onlyencrypted' => false,
    'email' => '',
    'homedir' => '',
    'password' => '',
    'bodyonlyencrypted' => false,
	),
  'SMIME' =>
  array (
    'enabled' => false,
    'email' => '',
    'cert_public_sign' => '',
    'key_sign' => '',
    'password' => '',
	),
  'Proxy' =>
  array (
    'host' => '',
    'port' => '',
    'method' => '',
    'user' => '',
    'password' => '',
  ),
  'SecureAuth' =>
  array (
    'amount' => 5,
    'expire' => 300,
  ),
  // Uncomment the following to enable client SSL certificate authentication
  /*
  'CertAuth' =>
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
    'userDefaults'=> array(          // default user attributes, only used when creating new users
      'role_id'   => 4,
    ),
    'restApi'       => array(        // API parameters
      'url'         => 'https://example.com/data/users',  // URL to query
      'headers'     => array(),                           // additional headers, used for authentication
      'param'       => array( 'email' => 'email' ),       // query parameters to add to the URL, mapped to User properties
      'map'         =>  array(                            // maps REST result to the User properties
        'uid'       => 'nids_sid',
        'team'      => 'org',
        'email'     => 'email',
        'pgp_public'=> 'gpgkey',
      ),
    ),
    'userDefaults'  => array ( 'role_id' => 3 ),          // default attributes for new users
  ),
  */
  // Warning: The following is a 3rd party contribution and still untested (including security) by the MISP-project team.
  // Feel free to enable it and report back to us if you run into any issues.
  //
  // Uncomment the following to enable Kerberos authentication
  // needs PHP LDAP support enabled (e.g. compile flag --with-ldap or Debian package php5-ldap)
  /*
   'ApacheSecureAuth' => // Configuration for kerberos authentication
    array(
        'apacheEnv' => 'REMOTE_USER',           // If proxy variable = HTTP_REMOTE_USER
        'ldapServer' => 'ldap://example.com',   // FQDN or IP
        'ldapProtocol' => 3,
        'ldapReaderUser' => 'cn=userWithReadAccess,ou=users,dc=example,dc=com', // DN ou RDN LDAP with reader user right
        'ldapReaderPassword' => 'UserPassword', // the LDAP reader user password
        'ldapDN' => 'dc=example,dc=com',
        'ldapSearchAttribut' => 'uid',          // filter for search
        'ldapFilter' => array(
            'mail',
        ),
        'ldapDefaultRoleId' => 3,               // 3:User, 1:admin. May be good to set "1" for the first user
        'ldapDefaultOrg' => '1',      // uses 1st local org in MISP if undefined
    ),
   */
);
