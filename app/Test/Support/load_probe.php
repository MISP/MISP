<?php
/**
 * Loads one MISP source file in a fresh process under the test stubs and
 * prints OK or FAIL. A separate process per file is required because PHP
 * cannot unload a class once declared.
 *
 * Framework classes are stubbed; only in-repo parent classes (which no stub
 * can stand in for) are loaded for real, after the stubs are in place.
 */
require_once __DIR__ . '/../../Vendor/autoload.php';
require_once __DIR__ . '/FrameworkStubs.php';

use MispTest\Support\FrameworkStubs;

$file = $argv[1] ?? '';
FrameworkStubs::defineConstants();
// Safe in a throwaway probe process: some files reference these at load time.
if (!defined('WWW_ROOT')) { define('WWW_ROOT', APP . 'webroot' . DIRECTORY_SEPARATOR); }
if (!defined('TMP'))      { define('TMP', APP . 'tmp' . DIRECTORY_SEPARATOR); }
if ($file === '' || !is_file($file)) {
    echo "FAIL no such file\n";
    exit(1);
}
try {
    FrameworkStubs::install();
    FrameworkStubs::loadRealParents($file);
    require_once $file;
    echo "OK\n";
} catch (\Throwable $e) {
    echo 'FAIL ' . get_class($e) . ': ' . str_replace("\n", ' ', $e->getMessage()) . "\n";
}
