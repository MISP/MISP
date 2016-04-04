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
    'onlyencrypted' => false,
    'email' => 'email@address.com',
    'cert_public_sign' => '/var/www/MISP/.smime/email@address.com.pem',
    'key_sign' => '/var/www/MISP/.smime/email@address.com.key',
    'password' => 'XXXXXXXXXXXXXXXXXXXXXX',
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
);
