<?php
/**
 * CakeResque configuration file
 *
 * Default settings for Resque workers and queues.
 *
 * PHP version 5
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @author        Wan Qi Chen <kami@kamisama.me>
 * @copyright     Copyright 2012, Wan Qi Chen <kami@kamisama.me>
 * @link          http://cakeresque.kamisama.me
 * @package       CakeResque
 * @subpackage	  CakeResque.Config
 * @since         3.4.0
 * @license       MIT License (http://www.opensource.org/licenses/mit-license.php)
 */

/**
 * Configure the default value for Resque
 *
 * ## Mandatory indexes :
 * Redis
 * 		Redis server settings
 * Worker
 * 		Workers default settings
 * Resque
 * 		Default values used to init the php-resque library path
 *
 * ## Optional indexes :
 * Queues
 * 		An array of queues to start with Resque::load()
 * 		Used when you have multiple queues, as you don't need
 * 		to start each queues individually each time you start Resque
 * Env
 * 		Additional environment variables to pass to Resque
 * Log
 * 		Log handler and its arguments, to save the log with Monolog
 *
 *
 * There are many ways to configure the plugin:
 *
 * 1. This file is automagically loaded by the bootstrapping process, when no 'CakeResque'
 * configuration key exists.
 *
 *   CakePlugin::load('CakeResque', array('bootstrap' => true));
 *
 * 2. If a 'CakeResque' configuration key already exists, the default configuration will not be loaded,
 * and the 'CakeResque' key is expected to contain all the values present in the default configuration.
 *
 *   Configure::load('my_cakeresque_config');
 *   CakePlugin::load('CakeResque', array('bootstrap' => true));
 *
 * 3. Another way to configure the plugin is to load it using a custom bootstrap file.
 *
 *   CakePlugin::load('CakeResque', array('bootstrap' => 'my_bootstrap'));
 *
 *   // APP/Plugin/CakeResque/Config/my_bootstrap.php
 *   require_once dirname(__DIR__) . DS . 'Lib' . DS . 'CakeResque.php';
 *   $config = array(); // Custom configuration
 *   CakeResque::init($config);
 *
 * @see CakeResque::init(), CakeResque::loadConfig().
 */
$config['CakeResque'] = array(
	'Redis' => array(
		'host' => 'localhost',		// Redis server hostname
		'port' => 6379,				// Redis server port
		'database' => 0,			// Redis database number
		'namespace' => 'resque'		// Redis keys namespace
	),

	'Worker' => array(
		'queue' => 'default',		// Name of the default queue
		'interval' => 5,			// Number of second between each poll
		'workers' => 1,				// Number of workers to create
		// 'user' => 'www-data' 	// User running the worker process

		// Path to the log file
		// Can be an
		// - absolute path,
		// - an relative path, that will be relative to
		// 	 app/tmp/logs folder
		// - a simple filename, file will be created inside app/tmp/logs
		'log' => TMP . 'logs' . DS . 'resque-worker-error.log',

		// Log Verbose mode
		// true to log more debugging informations
		// Can also be enabled per worker, by starting with --verbose
		'verbose' => false
	),
	'Job' => array(
		// Whether to track job status
		// Enabling this will allow you to track a job status by its ID
		// Job status are purged after 24 hours
		//
		// You can also define per-job tracking by passing true/false when calling
		// CakeResque::enqueue(), CakeResque::enqueueAt() or CakeResque::enqueueIn()
		'track' => true
	),
	/*
	'Queues' => array(
		array(
			'queue' => 'default',	// Use default values from above for missing interval and count indexes
			'user' => 'www-data'	// If PHP is running as a different user on you webserver
		),
		array(
			'queue' => 'my-second-queue',
			'interval' => 10
		)
	)
	*/
	'Resque' => array(

		// Path to the php-resque library
		//
		// Relative or absolute path to the php-resque library
		// If you are using Composer to install dependencies,
		// this is the name of the vendor library
		// Path is relative to the CakeResque/vendor
		// Don't add trailing slash to path
		'lib' => 'kamisama/php-resque-ex',

		// Path to the directory containing the worker PID files
		'tmpdir' => App::pluginPath('CakeResque') . 'tmp' . DS
	),

	// Other usefull environment variable you wish to set
	// Passing a key only will search for its value in the $_SERVER scope
	// eg : array('SERVER_NAME'); => will search for the value in $_SERVER['SERVER_NAME']
	// Passing a key and a value will set the env variable to this value
	// eg : array('ARCH' => 'x64')
	'Env' => array(),

	// Log Handler
	// If saving the logs in a plain text file doesn't suit you
	// you can send them to Mysql, or MongoDB, etc ...
	// In that case, you'll need a handler to manage your logs
	// All logs outputted by resque will go to the handler.
	// The classic log file (above) will still be used, for logging
	// stuff likes php error, or other STDOUT outputted by your job classses
	//
	// php-resque-ex uses Monolog to manage all the logging stuff
	// If you uses the original php-resque library, these settings
	// will be ignored
	//
	// handler
	//		Name of the Handler (the handler classname, without the 'Handler' part)
	// target
	//		Arguments taken by the handler constructor. If the handler required
	//		multiple arguments, separate them with a comma
	//
	// As of now, the following handler are supported:
	//
	// [HANDLER]		[TARGET]
	// Cube 			Cube server address (e.g: udp://127.0.0.1:1180)
	// RotatingFile 	Path to the log file (e.g: /path/to/resque.log)
	// Syslog 			Facility name
	// Socket 			Address (e.g: udp://127.0.0.1:23)
	// MongoDB 			MongoDB server address  (e.g: mongodb://localhost:27017)
	'Log' => array(
		'handler' => 'RotatingFile',
		'target' => TMP . 'logs' . DS . 'resque.log'
	),

	// Scheduler Worker
	// It's the worker handling all the scheduled jobs
	// Only one scheduler worker is permitted to run at one time
	// It can be paused, resumed and stopped like any other workers
	// It can be started only with the `startscheduler` command,
	// or with `load` if Scheduler Worker is enabled.
	//
	// Scheduled jobs requires the php-resque-ex-scheduler library,
	// that should be installed with automatically via the
	// `composer update` or `composer install` command
	//
	// The Scheduler Worker have its own default settings
	//
	// @since 2.3.0
	//
	'Scheduler' => array(
		// Enable or disable delayed job
		'enabled' => true,

		// Path to the php-resque-ex-scheduler's library
		'lib' => 'kamisama/php-resque-ex-scheduler',
		// Path to the log file
		'log' => TMP . 'logs' . DS . 'resque-scheduler-error.log',

		// Optional
		// Will not default to settings defined in the global scope above
		'Env' => array(),

		// Optional
		// Will default to settings defined in the global scope above
		// Only available setting is `interval`
		// The worker will always poll a fixed special queue, and only one worker can run at one time
		'Worker' => array(
			'interval' => 3
		),

		// Optional
		// Will default to settings defined in the global scope above
		'Log' => array(
			'handler' => 'RotatingFile',
			'target' => TMP . 'logs' . DS . 'resque-scheduler.log'
		)
	),
	'Status' => array(
		// Path to the resque-status library
		'lib' => 'kamisama/resque-status',
	)
);
