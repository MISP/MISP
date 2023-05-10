<?php

declare(strict_types=1);

/**
 * CakePHP(tm) : Rapid Development Framework (https://cakephp.org)
 * Copyright (c) Cake Software Foundation, Inc. (https://cakefoundation.org)
 *
 * Licensed under The MIT License
 * For full copyright and license information, please see the LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright Copyright (c) Cake Software Foundation, Inc. (https://cakefoundation.org)
 * @link      https://cakephp.org CakePHP(tm) Project
 * @since     3.0.0
 * @license   https://opensource.org/licenses/mit-license.php MIT License
 */

use Cake\Core\Configure;
use Cake\Datasource\ConnectionManager;
use Migrations\TestSuite\Migrator;
use \League\OpenAPIValidation\PSR7\ValidatorBuilder;

/**
 * Test runner bootstrap.
 *
 * Add additional configuration/setup your application needs when running
 * unit tests in this file.
 */
require dirname(__DIR__) . '/vendor/autoload.php';

require dirname(__DIR__) . '/config/bootstrap.php';

$_SERVER['PHP_SELF'] = '/';

Configure::write('App.fullBaseUrl', 'http://localhost');

// DebugKit skips settings these connection config if PHP SAPI is CLI / PHPDBG.
// But since PagesControllerTest is run with debug enabled and DebugKit is loaded
// in application, without setting up these config DebugKit errors out.
ConnectionManager::setConfig('test_debug_kit', [
    'className' => 'Cake\Database\Connection',
    'driver' => 'Cake\Database\Driver\Sqlite',
    'database' => TMP . 'debug_kit.sqlite',
    'encoding' => 'utf8',
    'cacheMetadata' => true,
    'quoteIdentifiers' => false,
]);

ConnectionManager::alias('test_debug_kit', 'debug_kit');

// Fixate sessionid early on, as php7.2+
// does not allow the sessionid to be set after stdout
// has been written to.
session_id('cli');

if (!$_ENV['SKIP_DB_MIGRATIONS']) {
    echo "[ * ] Running DB migrations, it may take some time ...\n";
    $migrator = new Migrator();
    $migrator->runMany(
        [
            ['connection' => 'test'],
            ['plugin' => 'Tags', 'connection' => 'test'],
            ['plugin' => 'ADmad/SocialAuth', 'connection' => 'test']
        ],
        false // Do not truncate tables
    );
} else {
    echo "[ * ] Skipping DB migrations ...\n";
}

$specFile = $_ENV['OPENAPI_SPEC'] ?? APP . '../webroot/docs/openapi.yaml';

// Initialize OpenAPI spec validator
Configure::write('App.OpenAPIValidator', (new ValidatorBuilder)->fromYamlFile($specFile));
