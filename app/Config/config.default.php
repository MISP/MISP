<?php
$config = array (
  'debug' => 0,
  'Security' => 
  array (
    'level' => 'medium',
    'salt' => 'Rooraenietu8Eeyo<Qu2eeNfterd-dd+',
    'cipherSeed' => '',
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
);
