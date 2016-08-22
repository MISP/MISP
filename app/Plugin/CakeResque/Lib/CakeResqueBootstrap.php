<?php
/**
 * Bootstrap file
 *
 * Use to bootstrap the job classes
 * All code is from CakePHP bootstrap files
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
 * @subpackage	  CakeResque.lib
 * @since         0.5
 * @license       MIT License (http://www.opensource.org/licenses/mit-license.php)
 */

/**
 * Copy/Paste from lib/Cake/Console/cake.php, except /lib path calculation.
 */
$ds = DIRECTORY_SEPARATOR;
$dispatcher = 'Cake' . $ds . 'Console' . $ds . 'ShellDispatcher.php';
$found = false;
$paths = explode(PATH_SEPARATOR, ini_get('include_path'));

foreach ($paths as $path) {
	if (file_exists($path . $ds . $dispatcher)) {
		$found = $path;
		break;
	}
}

if (!$found) {
	$root = dirname(dirname(getenv('CAKE')));
	if (!include $root . $ds . 'lib' . $ds . $dispatcher) {
		trigger_error('Could not locate CakePHP core files.', E_USER_ERROR);
	}
} else {
	include $found . $ds . $dispatcher;
}

array_push($argv, '--app', getenv('APP'));

unset($paths, $path, $found, $dispatcher, $root, $ds);

new ShellDispatcher($argv);
App::uses('Shell', 'Console');

App::uses('Resque_Job_Creator', 'CakeResque.Lib');
