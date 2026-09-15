<?php
/**
 * The ledger, and the set arithmetic on top of it.
 *
 * pending() is the whole point of this project in one method. The system it
 * replaces asks "how far did this instance get?" and answers with a single
 * integer, which means a migration that arrives numbered below where an
 * instance already stands is never seen again. The ledger asks "did this
 * particular migration run?", one row per migration, and that question has no
 * way to skip anything.
 *
 * So the assertion that matters most here is testAMigrationOlderThanTheLedgerIsStillPending:
 * a migration dated before ones that have already been applied is still applied.
 * Under a high-water mark that migration is invisible.
 *
 * @see MigrationOrderingTest for what happens when one of them fails.
 * @see MigrationLedgerStubs.php for the migration classes and the in-memory manager.
 */

require_once __DIR__ . '/MigrationLedgerStubs.php';

use PHPUnit\Framework\TestCase;

class MigrationManagerTest extends TestCase
{
    /** All five stub migrations, as a directory listing would give them. */
    private static $allFiles = array(
        'Migration_20200101_000000_older_than_the_freeze.php',
        'Migration_20260101_000000_add_column.php',
        'Migration_20260102_000000_backfill_column.php',
        'Migration_20260103_000000_drop_old_column.php',
        'Migration_20260104_000000_unrelated.php',
    );

    private function manager(array $rows = array(), array $files = null)
    {
        return new TestMigrationManager(
            $files === null ? self::$allFiles : $files,
            $rows
        );
    }

    // -------------------------------------------------------------- pending

    public function testAnEmptyLedgerLeavesEverythingPending()
    {
        $manager = $this->manager();
        $this->assertSame($manager->ids(), array_keys($manager->pending()));
    }

    public function testPendingIsDiscoveredMinusApplied()
    {
        $manager = $this->manager(array(
            '20260101_000000_add_column' => TestMigrationManager::row('20260101_000000_add_column', MigrationManager::STATUS_APPLIED),
            '20260102_000000_backfill_column' => TestMigrationManager::row('20260102_000000_backfill_column', MigrationManager::STATUS_APPLIED),
        ));

        $this->assertSame(
            array(
                '20200101_000000_older_than_the_freeze',
                '20260103_000000_drop_old_column',
                '20260104_000000_unrelated',
            ),
            array_keys($manager->pending())
        );
    }

    /**
     * The regression the ledger exists to remove, asserted directly.
     *
     * A later migration has already been applied. An earlier one has not. Under
     * a single db_version high-water mark the earlier one is below the line and
     * is skipped forever; under the ledger it is simply absent, so it is pending.
     */
    public function testAMigrationOlderThanTheLedgerIsStillPending()
    {
        $manager = $this->manager(array(
            '20260104_000000_unrelated' => TestMigrationManager::row('20260104_000000_unrelated', MigrationManager::STATUS_APPLIED),
        ));

        $pending = $manager->pending();
        $this->assertArrayHasKey('20200101_000000_older_than_the_freeze', $pending);
        $this->assertArrayNotHasKey('20260104_000000_unrelated', $pending);
    }

    public function testAFailedRowLeavesTheMigrationPending()
    {
        $manager = $this->manager(array(
            '20260101_000000_add_column' => TestMigrationManager::row('20260101_000000_add_column', MigrationManager::STATUS_FAILED),
        ));

        $this->assertArrayHasKey('20260101_000000_add_column', $manager->pending());
        $this->assertSame(array('20260101_000000_add_column'), $manager->failed());
        $this->assertSame(array(), $manager->applied());
    }

    public function testALedgerRowWithNoFileBehindItIsReportedButNotPending()
    {
        $manager = $this->manager(array(
            '20251111_111111_reverted_out_of_the_tree' => TestMigrationManager::row('20251111_111111_reverted_out_of_the_tree', MigrationManager::STATUS_APPLIED),
        ));

        $this->assertArrayHasKey('20251111_111111_reverted_out_of_the_tree', $manager->ledger());
        $this->assertSame($manager->ids(), array_keys($manager->pending()));
    }

    /**
     * pending() has the same shape findUpgrades() produces, so that
     * runUpdates() can union the two and keep its single loop.
     */
    public function testPendingCarriesTheRequiresLogoutFlag()
    {
        $pending = $this->manager()->pending();

        $this->assertTrue($pending['20260101_000000_add_column']);
        $this->assertFalse($pending['20260102_000000_backfill_column']);
    }

    // -------------------------------------------------------- status writing

    public function testASuccessfulApplyIsRecordedAsApplied()
    {
        $manager = $this->manager();
        $this->assertTrue($manager->apply('20260101_000000_add_column'));

        $row = $manager->ledger();
        $row = $row['20260101_000000_add_column'];
        $this->assertSame(MigrationManager::STATUS_APPLIED, $row['status']);
        $this->assertNull($row['error']);
        $this->assertIsInt($row['duration_ms']);
        $this->assertArrayNotHasKey('20260101_000000_add_column', $manager->pending());
    }

    public function testAFailedApplyIsRecordedWithItsError()
    {
        $manager = $this->manager();
        $manager->failing = array('20260101_000000_add_column');

        $this->assertFalse($manager->apply('20260101_000000_add_column'));

        $row = $manager->ledger();
        $row = $row['20260101_000000_add_column'];
        $this->assertSame(MigrationManager::STATUS_FAILED, $row['status']);
        $this->assertSame('scripted failure of 20260101_000000_add_column', $row['error']);
        $this->assertSame('scripted failure of 20260101_000000_add_column', $manager->lastError());
    }

    public function testARetrySucceedingClearsTheFailedRow()
    {
        $manager = $this->manager();
        $manager->failing = array('20260101_000000_add_column');
        $manager->apply('20260101_000000_add_column');

        $manager->failing = array();
        $this->assertTrue($manager->apply('20260101_000000_add_column'));

        $row = $manager->ledger();
        $row = $row['20260101_000000_add_column'];
        $this->assertSame(MigrationManager::STATUS_APPLIED, $row['status']);
        $this->assertNull($row['error']);
        $this->assertSame(array('20260101_000000_add_column'), $manager->applied());
        $this->assertSame(array(), $manager->failed());
    }

    public function testAnExceptionOutOfAMigrationIsAFailureNotACrash()
    {
        $manager = new ThrowingMigrationManager(self::$allFiles);

        $this->assertFalse($manager->apply('20260101_000000_add_column'));

        $row = $manager->ledger();
        $row = $row['20260101_000000_add_column'];
        $this->assertSame(MigrationManager::STATUS_FAILED, $row['status']);
        $this->assertSame('the table was not there', $row['error']);
    }

    public function testTheLedgerIsWrittenOncePerApply()
    {
        $manager = $this->manager();
        $manager->apply('20260101_000000_add_column');
        $manager->apply('20260102_000000_backfill_column');

        $this->assertSame(2, $manager->ledgerWrites);
    }

    /**
     * The ledger is never cached, and that is load-bearing rather than lazy.
     *
     * updatesDone(true) polls in a loop while another process applies the
     * migrations, and the fleet diagnostic is polled for the same reason. A
     * ledger read once and remembered turns both into a process that can never
     * observe progress - it would spin forever against a snapshot taken before
     * the work started.
     */
    public function testTheLedgerIsReadFreshSoAnotherProcessesWorkIsVisible()
    {
        $manager = $this->manager();
        $this->assertArrayHasKey('20260101_000000_add_column', $manager->pending());

        // Another process applies it. Nothing tells this manager.
        $manager->rows['20260101_000000_add_column'] =
            TestMigrationManager::row('20260101_000000_add_column', MigrationManager::STATUS_APPLIED);

        $this->assertArrayNotHasKey('20260101_000000_add_column', $manager->pending());
        $this->assertGreaterThan(1, $manager->ledgerReads);
    }

    // ------------------------------------------------------------ beforeUp()

    private function executing()
    {
        return new ExecutingMigrationManager(array('Migration_20260107_000000_data_on_both_sides.php'));
    }

    public function testBeforeUpRunsFirstAndAfterUpLast()
    {
        Migration_20260107_000000_data_on_both_sides::reset();
        $manager = $this->executing();

        $this->assertTrue($manager->apply('20260107_000000_data_on_both_sides'));
        $this->assertSame(
            array('beforeUp', 'up', 'afterUp'),
            Migration_20260107_000000_data_on_both_sides::$calls
        );
    }

    /**
     * A beforeUp() that could not put the rows right stops the migration
     * before any DDL is even rendered: the schema is left exactly as it was,
     * and the ledger says why.
     */
    public function testABeforeUpReportingFailureHaltsBeforeTheDdl()
    {
        Migration_20260107_000000_data_on_both_sides::reset(false);
        $manager = $this->executing();

        $this->assertFalse($manager->apply('20260107_000000_data_on_both_sides'));
        $this->assertSame(array('beforeUp'), Migration_20260107_000000_data_on_both_sides::$calls);

        $row = $manager->ledger();
        $row = $row['20260107_000000_data_on_both_sides'];
        $this->assertSame(MigrationManager::STATUS_FAILED, $row['status']);
        $this->assertSame('beforeUp() reported failure.', $row['error']);
    }

    public function testAnExceptionOutOfBeforeUpIsAFailureNotACrash()
    {
        Migration_20260107_000000_data_on_both_sides::reset(new RuntimeException('the rows could not be merged'));
        $manager = $this->executing();

        $this->assertFalse($manager->apply('20260107_000000_data_on_both_sides'));
        $this->assertSame(array('beforeUp'), Migration_20260107_000000_data_on_both_sides::$calls);

        $row = $manager->ledger();
        $row = $row['20260107_000000_data_on_both_sides'];
        $this->assertSame(MigrationManager::STATUS_FAILED, $row['status']);
        $this->assertSame('the rows could not be merged', $row['error']);
    }

    // ------------------------------------------------------------- rendering

    public function testUpIsRenderedThroughTheGrammarWithoutExecutingAnything()
    {
        $manager = new SchemaRenderingMigrationManager(self::$allFiles);

        $this->assertSame(
            array('ALTER TABLE `events` ADD `replacement` varchar(40) DEFAULT NULL;'),
            $manager->toSql('20260101_000000_add_column')
        );
        $this->assertSame(array(), $manager->executed);
    }

    public function testAMigrationWithNoUpRendersNothing()
    {
        $manager = new SchemaRenderingMigrationManager(self::$allFiles);

        $this->assertSame(array(), $manager->toSql('20260102_000000_backfill_column'));
    }

    /**
     * The ledger keys on an auto-increment integer like every other table,
     * with the migration's own id in a unique varchar column. A ledger in its
     * earlier shape - the migration id as a varchar `id` - is reshaped in
     * place on the next write, keeping its rows; one already in shape gets
     * nothing. The ledger cannot be a migration, so this is its own
     * check-then-act.
     */
    public function testTheLedgerIsCreatedOrReshapedToKeyOnAnIntegerId()
    {
        $manager = new LedgerShapeMigrationManager();

        $manager->inspector->tables = array();
        $sql = $manager->ledgerSchema()->toSql();
        $this->assertCount(1, $sql);
        $this->assertStringStartsWith('CREATE TABLE `schema_migrations` (', $sql[0]);
        $this->assertStringContainsString('`id` int(11) NOT NULL AUTO_INCREMENT', $sql[0]);
        $this->assertStringContainsString('`migration_id` varchar(191) NOT NULL', $sql[0]);
        $this->assertStringContainsString('PRIMARY KEY (`id`)', $sql[0]);
        $this->assertStringContainsString('UNIQUE INDEX `migration_id` (`migration_id`)', $sql[0]);

        $manager->inspector->tables = array('schema_migrations' => array('id', 'applied_at', 'duration_ms', 'status', 'error'));
        $this->assertSame(
            array(
                'ALTER TABLE `schema_migrations` CHANGE `id` `migration_id` varchar(191) NOT NULL;',
                'ALTER TABLE `schema_migrations` ADD UNIQUE INDEX `migration_id` (`migration_id`);',
                'ALTER TABLE `schema_migrations` DROP PRIMARY KEY;',
                'ALTER TABLE `schema_migrations` ADD `id` int(11) NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST;',
            ),
            $manager->ledgerSchema()->toSql(),
            'the earlier shape is reshaped in place, rows kept'
        );

        $manager->inspector->tables = array('schema_migrations' => array('id', 'migration_id', 'applied_at', 'duration_ms', 'status', 'error'));
        $this->assertSame(array(), $manager->ledgerSchema()->toSql(), 'already in shape');
    }

    /**
     * Reads take whichever shape is there: a row from the earlier ledger
     * reports its varchar `id` as the migration id, so an instance between
     * pulling this code and its next write still knows what it applied.
     */
    public function testTheLedgerReadsBothShapes()
    {
        $manager = new LedgerReadingMigrationManager(array(
            array('schema_migrations' => array('id' => '20260101_000000_add_column', 'status' => 'applied')),
            array('schema_migrations' => array('id' => '7', 'migration_id' => '20260102_000000_backfill_column', 'status' => 'failed')),
        ));
        $ledger = $manager->ledger();
        $this->assertSame(
            array('20260101_000000_add_column', '20260102_000000_backfill_column'),
            array_keys($ledger)
        );
        $this->assertSame('20260101_000000_add_column', $ledger['20260101_000000_add_column']['migration_id']);
        $this->assertSame('7', $ledger['20260102_000000_backfill_column']['id']);
    }
}

if (!class_exists('ThrowingMigrationManager', false)) {
    /**
     * A migration whose DDL blows up. The manager has to turn that into a
     * recorded failure - a migration that throws its way past the ledger leaves
     * no trace of having been attempted.
     */
    class ThrowingMigrationManager extends TestMigrationManager
    {
        protected function execute($id, AbstractMigration $migration)
        {
            $this->executed[] = $id;
            throw new RuntimeException('the table was not there');
        }
    }
}

if (!class_exists('LedgerShapeTestInspector', false)) {
    /**
     * A schema inspector with a scripted answer: table => its columns.
     */
    class LedgerShapeTestInspector extends SchemaInspector
    {
        public $tables = array();

        public function __construct()
        {
        }

        public function hasTable($table)
        {
            return isset($this->tables[$table]);
        }

        public function hasColumn($table, $column)
        {
            return isset($this->tables[$table]) && in_array($column, $this->tables[$table], true);
        }
    }

    class LedgerShapeMigrationManager extends SchemaRenderingMigrationManager
    {
        public $inspector;

        public function __construct()
        {
            parent::__construct();
            $this->inspector = new LedgerShapeTestInspector();
        }

        public function inspector()
        {
            return $this->inspector;
        }

        public function ledgerSchema()
        {
            return parent::ledgerSchema();
        }
    }

    class LedgerReadingTestModel
    {
        private $rows;

        public function __construct(array $rows)
        {
            $this->rows = $rows;
        }

        public function query($sql)
        {
            return $this->rows;
        }
    }

    /**
     * The real readLedger() over a scripted query result, so the shape
     * tolerance is exercised rather than stubbed away.
     */
    class LedgerReadingMigrationManager extends SchemaRenderingMigrationManager
    {
        private $inspector;

        public function __construct(array $queryResult)
        {
            parent::__construct();
            $this->inspector = new LedgerShapeTestInspector();
            $this->inspector->tables = array('schema_migrations' => array('id'));
            $property = new ReflectionProperty('MigrationManager', 'model');
            $property->setAccessible(true);
            $property->setValue($this, new LedgerReadingTestModel($queryResult));
        }

        public function inspector()
        {
            return $this->inspector;
        }

        protected function readLedger()
        {
            return MigrationManager::readLedger();
        }
    }
}
