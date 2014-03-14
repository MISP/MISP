<?php
/**
 * This file is loaded automatically by the app/webroot/index.php file after core.php
 *
 * This file should load/create any application wide configuration settings, such as
 * Caching, Logging, loading additional configuration files.
 *
 * You should also use this file to include any files that provide global functions/constants
 * that your application uses.
 */

/**
 * Cache Engine Configuration
 * Default settings provided below
 *
 * File storage engine.
 *
 * 	 Cache::config('default', array(
 *		'engine' => 'File', //[required]
 *		'duration'=> 3600, //[optional]
 *		'probability'=> 100, //[optional]
 * 		'path' => CACHE, //[optional] use system tmp directory - remember to use absolute path
 * 		'prefix' => 'cake_', //[optional]  prefix every cache file with this string
 * 		'lock' => false, //[optional]  use file locking
 * 		'serialize' => true, // [optional]
 * 		'mask' => 0666, // [optional] permission mask to use when creating cache files
 *	));
 *
 * APC (http://pecl.php.net/package/APC)
 *
 * 	 Cache::config('default', array(
 *		'engine' => 'Apc', //[required]
 *		'duration'=> 3600, //[optional]
 *		'probability'=> 100, //[optional]
 * 		'prefix' => Inflector::slug(APP_DIR) . '_', //[optional]  prefix every cache file with this string
 *	));
 *
 * Xcache (http://xcache.lighttpd.net/)
 *
 * 	 Cache::config('default', array(
 *		'engine' => 'Xcache', //[required]
 *		'duration'=> 3600, //[optional]
 *		'probability'=> 100, //[optional]
 *		'prefix' => Inflector::slug(APP_DIR) . '_', //[optional] prefix every cache file with this string
 *		'user' => 'user', //user from xcache.admin.user settings
 *		'password' => 'password', //plaintext password (xcache.admin.pass)
 *	));
 *
 * Memcache (http://memcached.org/)
 *
 * 	 Cache::config('default', array(
 *		'engine' => 'Memcache', //[required]
 *		'duration'=> 3600, //[optional]
 *		'probability'=> 100, //[optional]
 * 		'prefix' => Inflector::slug(APP_DIR) . '_', //[optional]  prefix every cache file with this string
 * 		'servers' => array(
 * 			'127.0.0.1:11211' // localhost, default port 11211
 * 		), //[optional]
 * 		'persistent' => true, // [optional] set this to false for non-persistent connections
 * 		'compress' => false, // [optional] compress data in Memcache (slower, but uses less memory)
 *	));
 *
 *  Wincache (http://php.net/wincache)
 *
 * 	 Cache::config('default', array(
 *		'engine' => 'Wincache', //[required]
 *		'duration'=> 3600, //[optional]
 *		'probability'=> 100, //[optional]
 *		'prefix' => Inflector::slug(APP_DIR) . '_', //[optional]  prefix every cache file with this string
 *	));
 *
 * Redis (http://http://redis.io/)
 *
 * 	 Cache::config('default', array(
 *		'engine' => 'Redis', //[required]
 *		'duration'=> 3600, //[optional]
 *		'probability'=> 100, //[optional]
 *		'prefix' => Inflector::slug(APP_DIR) . '_', //[optional]  prefix every cache file with this string
 *		'server' => '127.0.0.1' // localhost
 *		'port' => 6379 // default port 6379
 *		'timeout' => 0 // timeout in seconds, 0 = unlimited
 *		'persistent' => true, // [optional] set this to false for non-persistent connections
 *	));
 */
Cache::config('default', array('engine' => 'File'));

Configure::write('MISP.baseurl', 'http://localhost:8888');
if (!Configure::read('MISP.baseurl')) {
	if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) {
		Configure::write('MISP.baseurl', sprintf('https://%s:%d', $_SERVER['SERVER_ADDR'], $_SERVER['SERVER_PORT']));
	} else {
		Configure::write('MISP.baseurl', sprintf('http://%s:%d', $_SERVER['SERVER_ADDR'], $_SERVER['SERVER_PORT']));
	}
}
Configure::write('MISP.name', 'MISP');
Configure::write('MISP.version', '2.2');
Configure::write('MISP.header', 'MISP: Malware Information Sharing Platform');
Configure::write('MISP.footerpart1', 'Powered by MISP');
Configure::write('MISP.footerpart2', '&copy; Belgian Defense CERT & NCIRC');
Configure::write('MISP.footer', Configure::read('MISP.footerpart1') . ' ' . Configure::read('MISP.footerpart2'));
Configure::write('MISP.footerversion', Configure::read('MISP.footerpart1') . ' version ' . Configure::read('MISP.version') . ' ' . Configure::read('MISP.footerpart2'));
// The following field is optional
// Configure::write('MISP.footer_logo', 'imagename');     // Logo for the bottom right corner of the screen. Place a .png image into your app/webroot/img folder 
Configure::write('MISP.org', 'ORGNAME');                // if sync this will be Event.org content on the peer side
Configure::write('MISP.logo', 'orgs/ORGNAME.png');     // used in Events::index for owned events


Configure::write('MISP.showorg', 'true');             // show the name/flag of the organisation that uploaded the data

Configure::write('MISP.sync', 'true');                 // (Warning, do not disable this!!!) enable features related to syncing with other MISP instances - should be always on because of the current distribution model.
Configure::write('MISP.taxii_sync', 'false');		 	// Use the taxii demon to offload the synchronisation to a background process - see https://github.com/MISP/MISP-TAXII
Configure::write('MISP.taxii_client_path', '/usr/local/taxii-client-vanilla');
Configure::write('MISP.background_jobs', false);      // Use CakeResque to delegate jobs to a background worker and to schedule jobs (synchronisation, e-mailing, caching of exports) - Please also enable CakeResque (at the end of this file)

Configure::write('MISP.email', 'email@address.com'); // email from for all the mails
Configure::write('MISP.contact', 'email@address.com'); // contact address for this instance's support person / group

Configure::write('GnuPG.onlyencrypted', 'true');         // only allow encrypted email, do not allow plaintext mails
Configure::write('GnuPG.email', 'email@address.com');
Configure::write('GnuPG.password', 'yourpassword');
Configure::write('GnuPG.homedir', '/path/to/your/.gnupg/');

Configure::write('SecureAuth.amount', 5);              // the maximum amount of failed logins
Configure::write('SecureAuth.expire', 300);            // the time-window for the maximum amount of logins in seconds

Configure::write('MISP.dns', 'false');				// there is a nameserver available to do resolution.

Configure::write('MISP.cveurl', 'http://web.nvd.nist.gov/view/vuln/detail?vulnId='); 	// Default URL for NVD/CVE reference.

// The following 4 fields are optional

// Configure::write('MISP.welcome_text_top', 'Welcome to the Organisation community\'s');     // used in Events::login before the MISP logo
// Configure::write('MISP.welcome_text_bottom', 'instance');     // used in Events::login after the MISP logo
// Configure::write('MISP.welcome_logo', 'organisation');     // used in Events::login to the left of the MISP logo, place a .png file in app/webroot/img with the name specified here. In this case it would be organisation.png
// Configure::write('MISP.welcome_logo2', 'organisation2');     // used in Events::login to the right of the MISP logo, place a .png file in app/webroot/img with the name specified here. In this case it would be organisation2.png
Configure::write('MISP.disablerestalert', 'false');
// Events will be created with the default distribution setting based on this. Valid options: '0', '1', '2', '3'
Configure::write('MISP.default_event_distribution', '3');
// Setting this to 'event' will create attributes that take the event's distribution as the initial setting. Valid options: '0', '1', '2', '3', 'event'
Configure::write('MISP.default_attribute_distribution', 'event');

// Enable the tagging feature, it shou
Configure::write('MISP.tagging', true);
// enabling this flag will allow the event description to be transmitted in the alert e-mail's subject. Be aware that this is not encrypted by PGP, so only enable it if you accept that part of the event description will be sent out in clear-text 
Configure::write('MISP.extended_alert_subject', false);

/**
 * The settings below can be used to set additional paths to models, views and controllers.
 *
 * App::build(array(
 *     'Model'                     => array('/path/to/models', '/next/path/to/models'),
 *     'Model/Behavior'            => array('/path/to/behaviors', '/next/path/to/behaviors'),
 *     'Model/Datasource'          => array('/path/to/datasources', '/next/path/to/datasources'),
 *     'Model/Datasource/Database' => array('/path/to/databases', '/next/path/to/database'),
 *     'Model/Datasource/Session'  => array('/path/to/sessions', '/next/path/to/sessions'),
 *     'Controller'                => array('/path/to/controllers', '/next/path/to/controllers'),
 *     'Controller/Component'      => array('/path/to/components', '/next/path/to/components'),
 *     'Controller/Component/Auth' => array('/path/to/auths', '/next/path/to/auths'),
 *     'Controller/Component/Acl'  => array('/path/to/acls', '/next/path/to/acls'),
 *     'View'                      => array('/path/to/views', '/next/path/to/views'),
 *     'View/Helper'               => array('/path/to/helpers', '/next/path/to/helpers'),
 *     'Console'                   => array('/path/to/consoles', '/next/path/to/consoles'),
 *     'Console/Command'           => array('/path/to/commands', '/next/path/to/commands'),
 *     'Console/Command/Task'      => array('/path/to/tasks', '/next/path/to/tasks'),
 *     'Lib'                       => array('/path/to/libs', '/next/path/to/libs'),
 *     'Locale'                    => array('/path/to/locales', '/next/path/to/locales'),
 *     'Vendor'                    => array('/path/to/vendors', '/next/path/to/vendors'),
 *     'Plugin'                    => array('/path/to/plugins', '/next/path/to/plugins'),
 * ));
 *
 */

/**
 * Custom Inflector rules, can be set to correctly pluralize or singularize table, model, controller names or whatever other
 * string is passed to the inflection functions
 *
 * Inflector::rules('singular', array('rules' => array(), 'irregular' => array(), 'uninflected' => array()));
 * Inflector::rules('plural', array('rules' => array(), 'irregular' => array(), 'uninflected' => array()));
 *
 */

/**
 * Plugins need to be loaded manually, you can either load them one by one or all of them in a single call
 * Uncomment one of the lines below, as you need. make sure you read the documentation on CakePlugin to use more
 * advanced ways of loading plugins
 *
 * CakePlugin::loadAll(); // Loads all plugins at once
 * CakePlugin::load('DebugKit'); //Loads a single plugin named DebugKit
 *
 */

CakePlugin::load('SysLog');
CakePlugin::load('Assets'); // having Logable
CakePlugin::load('SysLogLogable');
CakePlugin::load('UrlCache');

/**
 * You can attach event listeners to the request lifecyle as Dispatcher Filter . By Default CakePHP bundles two filters:
 *
 * - AssetDispatcher filter will serve your asset files (css, images, js, etc) from your themes and plugins
 * - CacheDispatcher filter will read the Cache.check configure variable and try to serve cached content generated from controllers
 *
 * Feel free to remove or add filters as you see fit for your application. A few examples:
 *
 * Configure::write('Dispatcher.filters', array(
 *		'MyCacheFilter', //  will use MyCacheFilter class from the Routing/Filter package in your app.
 *		'MyPlugin.MyFilter', // will use MyFilter class from the Routing/Filter package in MyPlugin plugin.
 * 		array('callable' => $aFunction, 'on' => 'before', 'priority' => 9), // A valid PHP callback type to be called on beforeDispatch
 *		array('callable' => $anotherMethod, 'on' => 'after'), // A valid PHP callback type to be called on afterDispatch
 *
 * ));
 */
Configure::write('Dispatcher.filters', array(
	'AssetDispatcher',
	'CacheDispatcher'
));

/**
 * Configures default file logging options
 */
App::uses('CakeLog', 'Log');
CakeLog::config('debug', array(
	'engine' => 'FileLog',
	'types' => array('notice', 'info', 'debug'),
	'file' => 'debug',
));
CakeLog::config('error', array(
	'engine' => 'FileLog',
	'types' => array('warning', 'error', 'critical', 'alert', 'emergency'),
	'file' => 'error',
));

/*
CakePlugin::loadAll(array(
	'CakeResque' => array('bootstrap' => true)
));
*/