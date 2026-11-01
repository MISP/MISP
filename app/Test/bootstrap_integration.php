<?php
/**
 * Bootstrap for MISP's PHP integration suite (layer 2).
 *
 * Unlike the unit bootstrap, this boots the REAL CakePHP stack against the
 * real database, so integration tests can drive genuine models. The two
 * bootstraps are mutually exclusive - the unit layer's framework stubs would
 * collide with the classes loaded here - which is why the integration suite
 * has its own phpunit-integration.xml rather than sharing phpunit.xml.
 */
if (!defined('DS'))                     { define('DS', DIRECTORY_SEPARATOR); }
if (!defined('ROOT'))                   { define('ROOT', dirname(dirname(__DIR__))); }
if (!defined('APP_DIR'))                { define('APP_DIR', 'app'); }
if (!defined('WEBROOT_DIR'))            { define('WEBROOT_DIR', 'webroot'); }
if (!defined('WWW_ROOT'))               { define('WWW_ROOT', ROOT . DS . APP_DIR . DS . 'webroot' . DS); }
if (!defined('CAKE_CORE_INCLUDE_PATH')) { define('CAKE_CORE_INCLUDE_PATH', ROOT . DS . APP_DIR . DS . 'Lib' . DS . 'cakephp' . DS . 'lib'); }
if (!defined('CORE_PATH'))              { define('CORE_PATH', CAKE_CORE_INCLUDE_PATH . DS); }
if (!defined('APP'))                    { define('APP', ROOT . DS . APP_DIR . DS); }
if (!defined('TMP'))                    { define('TMP', APP . 'tmp' . DS); }

require_once CAKE_CORE_INCLUDE_PATH . DS . 'Cake' . DS . 'bootstrap.php';

App::uses('ClassRegistry', 'Utility');
App::uses('ConnectionManager', 'Model');
