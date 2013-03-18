<?php
/**
 * This file is loaded automatically by the app/webroot/index.php file after core.php
 *
 * This file should load/create any application wide configuration settings, such as
 * Caching, Logging, loading additional configuration files.
 *
 * You should also use this file to include any files that provide global functions/constants
 * that your application uses.
 *
 * PHP 5
 *
 * CakePHP(tm) : Rapid Development Framework (http://cakephp.org)
 * Copyright 2005-2012, Cake Software Foundation, Inc. (http://cakefoundation.org)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright 2005-2012, Cake Software Foundation, Inc. (http://cakefoundation.org)
 * @link          http://cakephp.org CakePHP(tm) Project
 * @package       app.Config
 * @since         CakePHP(tm) v 0.10.8.2117
 * @license       MIT License (http://www.opensource.org/licenses/mit-license.php)
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

//Configure::write('CyDefSIG.baseurl', 'https://sig.cyber-defence.be');
Configure::write('CyDefSIG.baseurl', 'http://localhost:8888');
if (!Configure::read('CyDefSIG.baseurl')) {
	if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) {
		Configure::write('CyDefSIG.baseurl', sprintf('https://%s:%d', $_SERVER['SERVER_ADDR'], $_SERVER['SERVER_PORT']));
	} else {
		Configure::write('CyDefSIG.baseurl', sprintf('http://%s:%d', $_SERVER['SERVER_ADDR'], $_SERVER['SERVER_PORT']));
	}
}
Configure::write('CyDefSIG.name', 'MISP');
Configure::write('CyDefSIG.version', '2.0');
Configure::write('CyDefSIG.header', 'CyDefSIG: Cyber Defence Signature Sharing Platform');
Configure::write('CyDefSIG.footerpart1', 'Powered by MISP');
Configure::write('CyDefSIG.footerpart2', '&copy; Belgian Defense CERT & NCIRC');
Configure::write('CyDefSIG.footer', Configure::read('CyDefSIG.footerpart1') . ' ' . Configure::read('CyDefSIG.footerpart2'));
Configure::write('CyDefSIG.footerversion', Configure::read('CyDefSIG.footerpart1') . ' version ' . Configure::read('CyDefSIG.version') . ' ' . Configure::read('CyDefSIG.footerpart2'));
Configure::write('CyDefSIG.org', 'ORGNAME');                // if sync this will be Event.org content on the peer side
Configure::write('CyDefSIG.logo', 'orgs/ORGNAME.png');     // used in Events::index for owned events


Configure::write('CyDefSIG.showorg', 'true');             // show the name/flag of the organisation that uploaded the data
Configure::write('CyDefSIG.showowner', 'false');           // show the email of the owner that uploaded the data
Configure::write('CyDefSIG.sync', 'true');                 // enable features related to syncing with other CyDefSIG instances - should be always on because of the current distribution model.
Configure::write('CyDefSIG.private', 'true');                 // respect private to org or server.
if ('true' == Configure::read('CyDefSIG.private')) {
	Configure::write('CyDefSIG.sync', 'true');
}
Configure::write('CyDefSIG.email', 'email@address.com'); // email from for all the mails

Configure::write('GnuPG.onlyencrypted', 'true');         // only allow encrypted email, do not allow plaintext mails
Configure::write('GnuPG.email', 'email@address.com');
Configure::write('GnuPG.password', 'yourpassword');
Configure::write('GnuPG.homedir', '/path/to/your/.gnupg/');

Configure::write('SecureAuth.amount', 5);              // the maximum amount of failed logins
Configure::write('SecureAuth.expire', 300);            // the time-window for the maximum amount of logins in seconds

Configure::write('CyDefSIG.correlation', 'db');        // correlation between attributes of events.
														// possible values:
														// - default, like it was (this is depreciated, use 'db' instead)
														// - db, correlation in database
														// - sql, selection on event i.s.o. per attribute (improvement possible) (this is depreciated, use 'db' instead)
/**
 * Network activity, ip-src
 * 30 class-C network ip addresses
 * (time in ms)
 *
 *           default     db    sql
 * all         25366  16601  15941
 *             24839  16604  15611
 * paginated   16759   8447   6615
 *             17734   8639   8846
 */
Configure::write('CyDefSIG.dns', 'false');				// there is a nameserver available to do resolution.

Configure::write('CyDefSIG.rest', 'ii');				// i is unchecked, use ii
														// RESTfull, possible values:
														// - i, event without attributes
														// - ii, event with attributes (more framework friendly and more RESTfull friendly)

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

CakePlugin::load('AclExtras');

CakePlugin::load('SysLog');
CakePlugin::load('Assets'); // having Logable
CakePlugin::load('SysLogLogable');
CakePlugin::load('MagicTools'); // having OrphansProtectable

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
