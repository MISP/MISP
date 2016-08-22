<?php

/**
 * Resque Job Creator Class
 *
 * Create a job instance
 *
 * This will find and instanciate a class from a classname.
 * Particulary important if the classname isn't the real classname,
 * like in CakePHP, where the classname can be prefixed with
 * a plugin name, and the classname doesn't give a clue about
 * the class file location.
 *
 * This class is optional, and if missing, Resque will handle the job
 * creation itself, with the standard method.
 *
 * @since 1.0
 * @author kamisama
 *
 */
class Resque_Job_Creator {

/**
 * Application Root Folder path
 *
 * @var String
 */
	public static $rootFolder = null;

/**
 * Create and return a job instance
 *
 * @param string $className className of the job to instanciate
 * @param array $args Array of method name and arguments used to build the job
 * @return object $args a job instance
 * @throws Resque_Exception when the class is not found, or does not follow the job file convention
 */
	public static function createJob($className, $args) {
		list($plugin, $model) = pluginSplit($className);

		if (self::$rootFolder === null) {
			self::$rootFolder = dirname(dirname(dirname(__DIR__))) . DS;
		}

		$classpath = self::$rootFolder . (empty($plugin) ? '' : 'Plugin' . DS . $plugin . DS) . 'Console' . DS . 'Command' . DS . $model . '.php';

		if (file_exists($classpath)) {
			require_once $classpath;
		} else {
			throw new Resque_Exception('Could not find job class ' . $className . '.');
		}

		if (!class_exists($model)) {
			throw new Resque_Exception('Could not find job class ' . $className . '.');
		}

		if (!method_exists($model, 'perform')) {
			throw new Resque_Exception('Job class ' . $className . ' does not contain a perform method.');
		}

		if (!isset($args[0]) || !method_exists($model, $args[0])) {
			throw new Resque_Exception('Job class ' . $className . ' does not contain ' . $args[0] . ' method.');
		}

		return new $model();
	}
}
