<?php
$config = array (
  'debug' => 0,
  'Security' => 
  array (
    'level' => 'medium',
    'salt' => 'vfdG7EQp?Msnr3~VFJLP&6?ZU9yfDnK"',
    'cipherSeed' => '',
    'password_policy_length' => 8,
  ),
  'MISP' => 
  array (
    'baseurl' => 'http://mispu',
    'footermidleft' => '',
    'footermidright' => '',
    'org' => 'ORGNAME',
    'showorg' => true,
    'background_jobs' => true,
    'cached_attachments' => true,
    'email' => 'cristian.bell@freenet.de',
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
    'live' => true,
    'email_subject_TLP_string' => 'TLP:AMBER',
  ),
  'GnuPG' => 
  array (
    'onlyencrypted' => false,
    'email' => 'cristian.bell@freenet.de',
    'homedir' => './gnupg',
    'password' => 'd;ljr43jrkfrje43',
    'bodyonlyencrypted' => false,
    'binary' => '/usr/bin/gpg',
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
  'site_admin_debug' => false,
  'Plugin' => 
  array (
    'Enrichment_services_enable' => true,
    'Enrichment_hover_enable' => true,
  ),
);