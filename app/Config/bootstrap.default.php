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
 *	Cache::config('default', array(
 *		'engine' => 'File', //[required]
 *		'duration'=> 3600, //[optional]
 *		'probability'=> 100, //[optional]
 *		'path' => CACHE, //[optional] use system tmp directory - remember to use absolute path
 *		'prefix' => 'cake_', //[optional]  prefix every cache file with this string
 *		'lock' => false, //[optional]  use file locking
 *		'serialize' => true, // [optional]
 *		'mask' => 0666, // [optional] permission mask to use when creating cache files
 *	));
 *
 * APC (http://pecl.php.net/package/APC)
 *
 *	Cache::config('default', array(
 *		'engine' => 'Apc', //[required]
 *		'duration'=> 3600, //[optional]
 *		'probability'=> 100, //[optional]
 *		'prefix' => Inflector::slug(APP_DIR) . '_', //[optional]  prefix every cache file with this string
 *	));
 *
 * Xcache (http://xcache.lighttpd.net/)
 *
 *	Cache::config('default', array(
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
 *	Cache::config('default', array(
 *		'engine' => 'Memcache', //[required]
 *		'duration'=> 3600, //[optional]
 *		'probability'=> 100, //[optional]
 *		'prefix' => Inflector::slug(APP_DIR) . '_', //[optional]  prefix every cache file with this string
 *		'servers' => array(
 *			'127.0.0.1:11211' // localhost, default port 11211
 *		), //[optional]
 *		'persistent' => true, // [optional] set this to false for non-persistent connections
 *		'compress' => false, // [optional] compress data in Memcache (slower, but uses less memory)
 *	));
 *
 *  Wincache (http://php.net/wincache)
 *
 *	Cache::config('default', array(
 *		'engine' => 'Wincache', //[required]
 *		'duration'=> 3600, //[optional]
 *		'probability'=> 100, //[optional]
 *		'prefix' => Inflector::slug(APP_DIR) . '_', //[optional]  prefix every cache file with this string
 *	));
 *
 * Redis (http://http://redis.io/)
 *
 *	Cache::config('default', array(
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
Configure::load('config');

$appendPort = true;
$relativePaths = false;

if (!$relativePaths) {
	if (isset($_SERVER['SERVER_NAME'])) $serverName = $_SERVER['SERVER_NAME'];
	else if (isset($_SERVER['HTTP_HOST'])) $serverName = $_SERVER['HTTP_HOST'];
	else if (isset($_SERVER['SERVER_ADDR'])) $serverName = $_SERVER['SERVER_ADDR'];

	if (!Configure::read('MISP.baseurl') && isset($serverName)) {
		if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443)) {
			$protocol = 'https';
		} else {
			$protocol = 'http';
		}
		if (!isset($_SERVER['SERVER_PORT']) || in_array($_SERVER['SERVER_PORT'], array('443', '80')) || !$appendPort) {
			Configure::write('MISP.baseurl', sprintf($protocol . '://%s', $serverName));
		} else {
			Configure::write('MISP.baseurl', sprintf($protocol . '://%s:%d', $serverName, $_SERVER['SERVER_PORT']));
		}
	}
}

/**
 * Configure base URL for CakePHP
 */
if (Configure::read('MISP.baseurl')) {
	$regex = "%^(?<fullBaseUrl>(?<proto>https?)://(?<host>(?:(?:\w|-)+\.)+[a-z]{2,5})(?::(?<port>[0-9]+))?)(?<base>/[a-z0-9_\-\.]+)?$%i";
	if (preg_match($regex, Configure::read('MISP.baseurl'), $matches)) {
		if (isset($matches['base'])) {
			Configure::write('App.base', $matches['base']);
			Configure::write('App.fullBaseUrl', $matches['fullBaseUrl']);
		}
	}
}
/*
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

/**
 * Uncomment the following line to enable client SSL certificate authentication.
 * It's also necessary to configure the plugin — for more information, please read app/Plugin/CertAuth/reame.md
 */
// CakePlugin::load('CertAuth');
// CakePlugin::load('ShibbAuth');
// CakePlugin::load('LinOTPAuth');
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
 *		array('callable' => $aFunction, 'on' => 'before', 'priority' => 9), // A valid PHP callback type to be called on beforeDispatch
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

// comment the following out if you do not with to use the background processing (not recommended)
CakePlugin::loadAll(array(
	'CakeResque' => array('bootstrap' => true)
));


// Enable the additional exception logging for certain failures (timeouts, out of memory, etc)
Configure::write('Exception.renderer', 'AppExceptionRenderer');