<?php
/**
 * Boots CakePHP against the configured database, for the behaviour oracle
 * captures driven by tests/value_oracle. Only for tests that run in their
 * own process.
 */

$appDir = dirname(__DIR__);
set_include_path(
    $appDir . DIRECTORY_SEPARATOR . 'Lib' . DIRECTORY_SEPARATOR . 'cakephp' .
    DIRECTORY_SEPARATOR . 'lib' . PATH_SEPARATOR . get_include_path()
);
require_once 'Cake/Console/ShellDispatcher.php';
new ShellDispatcher(['cake', 'ValueOracle', '-working', $appDir]);
unset($appDir);
