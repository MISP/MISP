#!/usr/bin/php -q
<?php
/**
 * Command-line code generation utility to automate programmer chores.
 *
 * PHP 5
 *
 * CakePHP(tm) : Rapid Development Framework (http://cakephp.org)
 * Copyright 2005-2012, Cake Software Foundation, Inc.
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright 2005-2012, Cake Software Foundation, Inc. (http://cakefoundation.org)
 * @link          http://cakephp.org CakePHP(tm) Project
 * @package       app.Console
 * @since         CakePHP(tm) v 2.0
 * @license       MIT License (http://www.opensource.org/licenses/mit-license.php)
 */
if (!defined('DS')) {
    define('DS', DIRECTORY_SEPARATOR);
}
$dispatcher = 'Cake' . DS . 'Console' . DS . 'ShellDispatcher.php';

if (function_exists('ini_set')) {
    $root = dirname(dirname(dirname(__FILE__)));
    $appDir = basename(dirname(dirname(__FILE__)));
    $install = $root . DS . $appDir . DS . 'Lib' . DS . 'cakephp' . DS . 'lib';
    $composerInstall = $root . DS . $appDir . DS . 'Vendor' . DS . 'cakephp' . DS . 'cakephp' . DS . 'lib';

    if (file_exists($composerInstall . DS . $dispatcher)) {
        $install = $composerInstall; // prefer compose install
    }

    ini_set('include_path', $install . PATH_SEPARATOR . ini_get('include_path'));
    unset($root, $appDir, $install, $composerInstall);
}

if (!include $dispatcher) {
    trigger_error('Could not locate CakePHP core files.', E_USER_ERROR);
}
unset($dispatcher);

return ShellDispatcher::run($argv);
