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
      'param'       => array( 'email' => 'email'),        // query parameters to add to the URL, mapped to USer properties 
      'map'         =>  array(                            // maps REST result to the User properties
        'uid'       => 'nids_sid',
        'team'      => 'org',
        'email'     => 'email',
        'pgp_public'=> 'gpgkey',
      ),
    ),
  ),
  */
  // Uncomment the following to enable Kerberos authentification
  // need php5-ldap mod for apache
  /*
   'ApacheSecureAuth' => // Configuration for kerberos authentification
    array(
        'apacheEnv' => 'REMOTE_USER',           // If proxy variable = HTTP_REMOTE_USER
        'ldapServer' => 'ldap://sample.com',    // fqdn or ip
        'ldapProtocol' => 3,
        'ldapReaderUser' => 'cn=userWithReadAccess,ou=users,', // DN ou RDN LDAP with reader user right
        'ldapReaderPassword' => 'UserPassword', //the ldap reader user password
        'ldapDN' => 'dc=sample,dc=com', 
        'ldapFilter' => array(
            'mail',                             // filter for ldap search
        ),
        'ldapDefaultRoleId' => 3,   // 3:User-1:admin. Maybe good to make 1 for the first user
        'ldapDefaultOrg' => '',     // if not define default org = 1 misp org
    ),
   */
);
