<?php
/**
 * Shared scaffolding for the app/Lib/Migration/ schema-DSL tests
 * (MigrationGrammarTest, SchemaBuilderTest, SchemaInspectorTest).
 *
 * Not a test file - the name deliberately does not end in `Test.php`, so
 * `phpunit app/Test/` does not collect it.
 *
 * Same spirit as every other test under app/Test/: bare PHPUnit, no CakePHP
 * bootstrap, no database. The difference is that the classes under test are
 * *about* CakePHP's datasources - most of the type rendering they rely on is
 * DboSource::buildColumn() and the drivers' own $columns / $fieldParameters
 * maps. Stubbing those out would leave the tests asserting our own stubs, so
 * instead the real Cake driver classes are loaded and instantiated without ever
 * connecting:
 *
 *   - the class chain (CakeObject -> DataSource -> DboSource -> Mysql/Postgres)
 *     loads with nothing but a no-op App::uses() and a Configure stub;
 *   - the test subclasses skip DboSource::__construct entirely - it would call
 *     enabled(), which needs the PDO driver present, and connect();
 *   - $cacheMethods = false makes DboSource::cacheMethod() early-return, so
 *     name() never reaches the Cache facade;
 *   - value() is the only method that needs a connection, for quoting, so a
 *     three-line PDO stand-in covers it.
 *
 * This file lives here rather than being copy-pasted into each test file
 * because the three tests need the identical setup, and because the guarded
 * framework stubs below have to stay compatible with the ones other test files
 * declare (all of which use a no-op App::uses, so this one does too).
 */

require_once __DIR__ . '/../Vendor/autoload.php';

if (!defined('DS')) {
    define('DS', DIRECTORY_SEPARATOR);
}
if (!defined('CAKE')) {
    define('CAKE', __DIR__ . '/../Lib/cakephp/lib/Cake/');
}
if (!defined('APPLIBS')) {
    define('APPLIBS', __DIR__ . '/../Lib/');
}

// -------- framework stubs (must exist BEFORE the Cake classes load) --------
// Guarded so that in a full-suite run whichever file loads first wins for
// everyone. Both contracts match the ones the other test files declare.

if (!class_exists('App', false)) {
    class App
    {
        // No-op, like every other App stub under app/Test/. The file-level
        // App::uses() calls in the classes under test are inert because this
        // file require_once's each of them explicitly below.
        public static function uses($class = null, $package = null)
        {
        }
    }
}

if (!class_exists('Configure', false)) {
    class Configure
    {
        private static $values = array();

        public static function read($key)
        {
            return isset(self::$values[$key]) ? self::$values[$key] : null;
        }

        public static function check($key)
        {
            return isset(self::$values[$key]);
        }

        public static function write($key, $value)
        {
            self::$values[$key] = $value;
        }

        public static function reset()
        {
            self::$values = array();
        }
    }
}

// -------- the real CakePHP datasource classes --------

require_once CAKE . 'Core/CakeObject.php';
require_once CAKE . 'Model/Datasource/DataSource.php';
require_once CAKE . 'Model/Datasource/DboSource.php';
require_once CAKE . 'Model/Datasource/Database/Mysql.php';
require_once CAKE . 'Model/Datasource/Database/Postgres.php';

// MISP never runs vanilla Mysql - every datasource in database.default.php is
// MysqlExtended or a subclass of it, and MysqlExtended::value() short-circuits
// integers rather than quoting them. Loaded so the tests can pin what the
// driver MISP actually runs renders, not only the base contract.
require_once __DIR__ . '/../Model/Datasource/Database/MysqlExtended.php';

// -------- the classes under test --------

require_once APPLIBS . 'Migration/Grammar/AbstractGrammar.php';
require_once APPLIBS . 'Migration/Grammar/MysqlGrammar.php';
require_once APPLIBS . 'Migration/Grammar/PostgresGrammar.php';
require_once APPLIBS . 'Migration/SchemaTableBuilder.php';
require_once APPLIBS . 'Migration/SchemaBuilder.php';
require_once APPLIBS . 'Migration/SchemaInspector.php';

// -------- connectionless datasources --------

if (!class_exists('MigrationTestPdo', false)) {
    /**
     * Stands in for the PDO handle DboSource::value() quotes through. Quotes the
     * way both real drivers do - single quotes, doubled to escape.
     */
    class MigrationTestPdo
    {
        public function quote($value, $type = null)
        {
            return "'" . str_replace("'", "''", (string)$value) . "'";
        }
    }
}

if (!class_exists('MigrationTestMysql', false)) {
    class MigrationTestMysql extends Mysql
    {
        // Deliberately does not call parent::__construct(): it would call
        // enabled() (needs pdo_mysql) and then connect().
        public function __construct()
        {
            $this->_connection = new MigrationTestPdo();
            $this->cacheMethods = false;
            $this->config = array('prefix' => '', 'database' => 'misp');
        }
    }
}

if (!class_exists('MigrationTestMysqlExtended', false)) {
    class MigrationTestMysqlExtended extends MysqlExtended
    {
        public function __construct()
        {
            $this->_connection = new MigrationTestPdo();
            $this->cacheMethods = false;
            $this->config = array('prefix' => '', 'database' => 'misp');
        }
    }
}

if (!class_exists('MigrationTestPostgres', false)) {
    class MigrationTestPostgres extends Postgres
    {
        public function __construct()
        {
            $this->_connection = new MigrationTestPdo();
            $this->cacheMethods = false;
            $this->config = array('prefix' => '', 'database' => 'misp', 'schema' => 'public');
        }
    }
}
