<?php
/**
 * CakeResque bootstrap configuration file.
 *
 * Used to load the default configuration file.
 *
 * PHP version 5
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @author        Ber Clausen <ber.clausen [at] gmail.com>
 * @copyright     Copyright 2012, Ber Clausen <ber.clausen [at] gmail.com>
 * @link          http://cakeresque.kamisama.me
 * @package       CakeResque
 * @subpackage	  CakeResque.Config
 * @since         3.4.0
 * @license       MIT License (http://www.opensource.org/licenses/mit-license.php)
 */

/**
 * Bootstrap configuration file.
 *
 * It is intended to ease bootstrapping CakeResque with a custom configuration.
 *
 * CakePlugin::load('CakeResque', array('bootstrap' => ['bootstrap_config', '../../../Config/cakeresque', 'bootstrap']));
 *
 * Where '../../../Config/cakeresque' indicates the path to the App's custom configuration file:
 *
 * // APP/Config/cakeresque.php
 * Configure::write('CakeResque.Redis.host', 'my_hostname');
 *
 * @see CakeResque::init(), CakeResque::loadConfig().
 */
Configure::load('CakeResque.config');
