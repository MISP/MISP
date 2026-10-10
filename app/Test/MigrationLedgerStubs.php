<?php
/**
 * Shared scaffolding for the migration-system tests (MigrationManagerTest,
 * MigrationOrderingTest, MigrationIdTest).
 *
 * Not a test file - the name deliberately does not end in `Test.php`, so
 * `phpunit app/Test/` does not collect it.
 *
 * MigrationSchemaStubs.php already loads the real CakePHP datasources for the
 * DSL tests; this file builds on it and adds what the manager needs: a handful
 * of real migration classes to be discovered, and a MigrationManager whose four
 * I/O seams - the directory listing, the ledger read, the ledger write and the
 * execution of one migration - are in memory.
 *
 * Everything else is the production class. pending()'s set arithmetic, the id
 * ordering, the halt on first failure and the status transitions are all the
 * real implementations running against a fake ledger, which is the only way
 * those tests say anything.
 */

require_once __DIR__ . '/MigrationSchemaStubs.php';
require_once APPLIBS . 'Migration/AbstractMigration.php';
require_once APPLIBS . 'Migration/MigrationManager.php';

if (!function_exists('__')) {
    function __($string)
    {
        $args = func_get_args();
        $format = array_shift($args);
        return empty($args) ? $format : vsprintf($format, $args);
    }
}

// -------- migrations to be discovered --------
// Real classes with real names, because the id is derived from the class name
// and half of what is under test is that derivation.

if (!class_exists('Migration_20200101_000000_older_than_the_freeze', false)) {
    /**
     * Deliberately dated long before the others. Under a high-water mark this
     * is the migration that goes missing; under a ledger it cannot.
     */
    class Migration_20200101_000000_older_than_the_freeze extends AbstractMigration
    {
        public $description = 'Authored on a branch that merged late';
    }
}

if (!class_exists('Migration_20260101_000000_add_column', false)) {
    class Migration_20260101_000000_add_column extends AbstractMigration
    {
        public $description = 'Step one: add the new column';
        public $requiresLogout = true;

        public function up(SchemaBuilder $schema)
        {
            $schema->table('events')->addColumn('replacement', 'string', array(
                'null' => true, 'length' => 40
            ));
        }
    }
}

if (!class_exists('Migration_20260102_000000_backfill_column', false)) {
    class Migration_20260102_000000_backfill_column extends AbstractMigration
    {
        public $description = 'Step two: copy the old column into the new one';
    }
}

if (!class_exists('Migration_20260103_000000_drop_old_column', false)) {
    class Migration_20260103_000000_drop_old_column extends AbstractMigration
    {
        public $description = 'Step three: drop the column step two read from';

        public function up(SchemaBuilder $schema)
        {
            $schema->table('events')->dropColumn('legacy');
        }
    }
}

if (!class_exists('Migration_20260104_000000_unrelated', false)) {
    class Migration_20260104_000000_unrelated extends AbstractMigration
    {
        public $description = 'Nothing to do with the three-step change';
    }
}

if (!class_exists('NotAMigration_20260105_000000_wrong_prefix', false)) {
    class NotAMigration_20260105_000000_wrong_prefix
    {
    }
}

if (!class_exists('Migration_20260106_000000_not_a_subclass', false)) {
    class Migration_20260106_000000_not_a_subclass
    {
    }
}

if (!class_exists('Migration_20260107_000000_data_on_both_sides', false)) {
    /**
     * Records the order the manager calls its three parts in. up() declares
     * nothing, so the real execute() can run it with no runner behind it.
     */
    class Migration_20260107_000000_data_on_both_sides extends AbstractMigration
    {
        public $description = 'Data work before and after an empty up()';

        /** @var array The parts called, in order. */
        public static $calls = array();

        /** @var bool|Exception What beforeUp() answers, or throws. */
        public static $beforeUpOutcome = true;

        public static function reset($beforeUpOutcome = true)
        {
            self::$calls = array();
            self::$beforeUpOutcome = $beforeUpOutcome;
        }

        public function beforeUp()
        {
            self::$calls[] = 'beforeUp';
            if (self::$beforeUpOutcome instanceof Exception) {
                throw self::$beforeUpOutcome;
            }
            return self::$beforeUpOutcome;
        }

        public function up(SchemaBuilder $schema)
        {
            self::$calls[] = 'up';
        }

        public function afterUp()
        {
            self::$calls[] = 'afterUp';
            return true;
        }
    }
}

// -------- the manager, with its I/O in memory --------

if (!class_exists('TestMigrationManager', false)) {
    /**
     * A MigrationManager with no model, no datasource and no filesystem.
     *
     * The constructor is not chained on purpose: the parent's only work is to
     * store a model and a directory, and skipping it means no Model class has
     * to be conjured up just to satisfy a type hint that is never reached.
     */
    class TestMigrationManager extends MigrationManager
    {
        /** @var array File names the directory is pretending to hold. */
        public $files = array();

        /** @var array id => row, standing in for the schema_migrations table. */
        public $rows = array();

        /** @var array Ids scripted to fail when executed. */
        public $failing = array();

        /** @var array Ids execute() was actually called for, in order. */
        public $executed = array();

        /** @var int How many times the ledger was read from "storage". */
        public $ledgerReads = 0;

        /** @var int How many times a row was written to "storage". */
        public $ledgerWrites = 0;

        public function __construct(array $files = array(), array $rows = array())
        {
            $this->files = $files;
            $this->rows = $rows;
            $this->directory = '/dev/null/Migrations';
        }

        /**
         * Forget the discovered set, the way a fresh process would start. The
         * ledger needs no forgetting - it is never cached.
         *
         * @return void
         */
        public function forgetDiscovery()
        {
            $this->migrations = null;
        }

        public function ensureLedger()
        {
        }

        protected function migrationFiles()
        {
            return $this->files;
        }

        protected function loadMigrationClass($className)
        {
            // Already declared above; there is nothing to autoload.
        }

        protected function readLedger()
        {
            $this->ledgerReads++;
            return $this->rows;
        }

        protected function persistLedgerRow(array $row)
        {
            $this->ledgerWrites++;
            $this->rows[$row[MigrationManager::LEDGER_KEY]] = $row;
        }

        protected function execute($id, AbstractMigration $migration)
        {
            $this->executed[] = $id;
            if (in_array($id, $this->failing, true)) {
                // Reported the way the real execute() reports it.
                $this->lastError = 'scripted failure of ' . $id;
                return false;
            }
            return true;
        }

        /**
         * A ledger row as the table would hold it.
         *
         * @param string $id
         * @param string $status
         * @return array
         */
        public static function row($id, $status)
        {
            return array(
                MigrationManager::LEDGER_KEY => $id,
                'applied_at' => '2026-08-01 12:00:00',
                'duration_ms' => 12,
                'status' => $status,
                'error' => $status === MigrationManager::STATUS_FAILED ? 'it broke' : null,
            );
        }
    }
}

if (!class_exists('SchemaRenderingMigrationManager', false)) {
    /**
     * The same, but with a connectionless MySQL datasource behind it, so that
     * toSql() can be driven without a database.
     */
    class SchemaRenderingMigrationManager extends TestMigrationManager
    {
        /** @var MigrationTestMysqlExtended */
        private $db;

        public function __construct(array $files = array(), array $rows = array())
        {
            parent::__construct($files, $rows);
            $this->db = new MigrationTestMysqlExtended();
        }

        protected function dataSource()
        {
            return $this->db;
        }
    }
}

if (!class_exists('ExecutingMigrationManager', false)) {
    /**
     * Runs the real execute() - the one that orders beforeUp(), up() and
     * afterUp() and turns a refusal into a failed row - over the connectionless
     * datasource. Only a migration whose up() declares nothing can go through
     * it, since there is no runner behind the statements.
     */
    class ExecutingMigrationManager extends SchemaRenderingMigrationManager
    {
        protected function execute($id, AbstractMigration $migration)
        {
            $this->executed[] = $id;
            return MigrationManager::execute($id, $migration);
        }
    }
}
