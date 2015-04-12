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
    'footerpart1' => 'Powered by MISP',
    'footerpart2' => '&copy; Belgian Defense CERT & NCIRC',
    'org' => 'ORGNAME',
    'showorg' => true,
    'background_jobs' => true,
    'cached_attachments' => false,
    'email' => 'email@address.com',
    'contact' => 'email@address.com',
    'cveurl' => 'http://web.nvd.nist.gov/view/vuln/detail?vulnId=',
    'disablerestalert' => false,
    'default_event_distribution' => '0',
    'default_attribute_distribution' => 'event',
    'tagging' => true,
    'full_tags_on_event_index' => true,
    'footer_logo' => '',
  	'take_ownership_xml_import' => false,
  ),
  'GnuPG' => 
  array (
    'onlyencrypted' => false,
    'email' => '',
    'homedir' => '',
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
    'register'=>true,
    'ca'=>'FIRST.Org',
    'caId'=>'org',
    'mapCa'=>array(
      'O'=>'org',
      'emailAddress'=>'email',
    ),
    'map'=>array(
      'O'=>'org',
      'emailAddress'=>'email',
    ),
    'userModel'=>'User',
    'userModelKey'=>'nids_sid',
    'enableSession' => true,
    'syncUser'=>true,
    'restApi'=>array(
      'url'=>'https://www.first.org/data/members?scope=full&limit=1',
      'headers'=>array(),
      'param'=>array('email'=>'email'),
      'map'=>array(
        'uid'=>'nids_sid',
        'team'=>'org',
        'email'=>'email',
        'pgp_public'=>'gpgkey',
      ),
    ),
  ),
  */
);
