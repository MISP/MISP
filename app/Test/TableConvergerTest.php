<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/MigrationLedgerStubs.php';
require_once APPLIBS . 'Migration/BaselineGenerator.php';
require_once APPLIBS . 'Migration/SchemaTargetGenerator.php';
require_once APPLIBS . 'Migration/TableConverger.php';
require_once APPLIBS . 'Migration/TableMigration.php';
require_once APPLIBS . 'Migration/TablePreflight.php';

if (!class_exists('Migration_20261101_000000_converge_events', false)) {
    class Migration_20261101_000000_converge_events extends TableMigration
    {
        public $description = 'Converge events';

        const TABLE = 'events';

        const TARGET = TableConvergerTest::TARGET;
    }
}

if (!class_exists('Migration_20261101_000001_recreate_events', false)) {
    class Migration_20261101_000001_recreate_events extends TableMigration
    {
        const TABLE = 'events';

        const TARGET = TableConvergerTest::TARGET;

        const RECREATE = true;
    }
}

if (!class_exists('NoteRecordingMigrationManager', false)) {
    /**
     * The real execute(), with the update log kept in memory.
     */
    class NoteRecordingMigrationManager extends ExecutingMigrationManager
    {
        public $logged = array();

        protected function logUpdate($title, array $lines)
        {
            $this->logged[] = array($title, $lines);
        }
    }
}

/**
 * TableConverger against scripted catalogs: each server's view of a table
 * at its target, and the same with drift.
 */
class TableConvergerTest extends TestCase
{
    const TARGET = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'org_id' => array('type' => 'biginteger', 'null' => false),
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII),
            'info' => array('type' => 'text', 'null' => false, 'collate' => Collation::CI),
            'published' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
            'distribution' => array('type' => 'tinyinteger', 'null' => false, 'default' => '0'),
            'sharing_group_id' => array('type' => 'biginteger', 'null' => false),
            'attribute_count' => array('type' => 'integer', 'unsigned' => true, 'null' => true, 'default' => '0'),
            'object_type' => array(
                'type' => 'string',
                'length' => 80,
                'null' => false,
                'collate' => 'ascii_general_ci',
                'charset' => 'ascii',
            ),
            'created_at' => array('type' => 'datetime', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
        ),
        'indexes' => array(
            'idx_events_info_lower' => array(
                'mysql' => false,
                'pgsql' => array('sql' => 'CREATE INDEX %1$s ON %2$s (lower("info"));'),
            ),
            'idx_evt_acl' => array('column' => array('distribution', 'sharing_group_id')),
            'info' => array('column' => array('info'), 'length' => array('info' => 255)),
            'info_search' => array(
                'column' => array('info'),
                'fulltext' => true,
                'pgsql' => array(
                    'name' => 'idx_events_info_search',
                    'sql' => 'CREATE INDEX %1$s ON %2$s USING gin ("info" gin_trgm_ops);',
                    'extension' => 'pg_trgm',
                ),
            ),
            'uuid' => array('column' => array('uuid'), 'unique' => true),
        ),
        'retired' => array('org_id', 'sharing_group_id'),
    );

    const MARIADB = '10.11.14-MariaDB-0ubuntu0.24.04.1';

    const MYSQL = '8.4.6';

    // ------------------------------------------------------------ fixed point

    public function testATableAtItsTargetPlansNothingOnEveryServer()
    {
        foreach (array(self::MARIADB, self::MYSQL) as $version) {
            $inspector = $this->mysqlInspector(self::mysqlLive(self::TARGET, $version), $version);
            $plan = TableConverger::plan($inspector, 'events', self::TARGET);
            $this->assertTrue(TableConverger::isEmpty($plan), $version . ': ' . json_encode($plan));
            $this->assertSame(array(), $plan['notes']);
        }
        $plan = TableConverger::plan($this->pgsqlInspector(self::pgsqlLive('events', self::TARGET)), 'events', self::TARGET);
        $this->assertTrue(TableConverger::isEmpty($plan), json_encode($plan));

        $schema = $this->mysqlSchema();
        TableConverger::converge($this->mysqlInspector(self::mysqlLive(self::TARGET)), $schema, 'events', self::TARGET);
        $this->assertSame(array(), $schema->toSql());
    }

    public function testAnotherServersCollationIsADifference()
    {
        $inspector = $this->mysqlInspector(self::mysqlLive(self::TARGET, self::MARIADB), self::MYSQL);
        $plan = TableConverger::plan($inspector, 'events', self::TARGET);
        $this->assertSame(array('info'), array_keys($plan['change']));
        $this->assertSame(array('collation'), $plan['change']['info']['differs']);
        $this->assertSame(array('collate' => Collation::CI), $plan['options']);
    }

    // ---------------------------------------------------------------- columns

    /**
     * A 2.5-shaped table: 32-bit ids, utf8mb3, COMPACT, an index on the old
     * name and one missing. The rebuild is one statement after the column
     * additions, the key first.
     */
    public function testADriftedTableConvergesInOneRebuild()
    {
        $live = self::mysqlLive(self::TARGET);
        $live['options'] = array('engine' => 'InnoDB', 'row_format' => 'COMPACT', 'collation' => 'utf8mb3_general_ci', 'charset' => 'utf8mb3');
        $live['columns']['id'] = self::mysqlColumn('int(11)', array('increment' => 'auto_increment'));
        $live['columns']['org_id'] = self::mysqlColumn('int(11)');
        $live['columns']['uuid'] = self::mysqlColumn('varchar(40)', array('collation' => 'utf8mb3_bin'));
        $live['columns']['info'] = self::mysqlColumn('text', array('collation' => 'utf8mb3_general_ci'));
        unset($live['columns']['created_at'], $live['columns']['object_type']);
        $live['columns']['legacy'] = self::mysqlColumn('int(11)', array('null' => true));
        unset($live['indexes']['idx_evt_acl']);
        $live['indexes']['org_id'] = self::liveIndex('org_id', array('org_id'));
        $live['indexes']['uuid'] = self::liveIndex('uuid', array('uuid'));
        $live['indexes']['admin_info'] = self::liveIndex('admin_info', array('info'), false, array('info' => 32));

        $schema = $this->mysqlSchema();
        $plan = TableConverger::converge($this->mysqlInspector($live), $schema, 'events', self::TARGET);

        $this->assertSame(array('id', 'org_id', 'uuid', 'info'), array_keys($plan['change']));
        $this->assertSame(array('type'), $plan['change']['id']['differs']);
        $this->assertSame(array('uuid' => 'redefined', 'org_id' => 'retired'), $plan['dropIndexes']);
        $this->assertSame(
            array(
                // Instant, each; the second names the first, so they are two.
                'ALTER TABLE `events` ADD `object_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL AFTER `attribute_count`;',
                'ALTER TABLE `events` ADD `created_at` datetime DEFAULT CURRENT_TIMESTAMP NOT NULL AFTER `object_type`;',
                "ALTER TABLE `events`\n" .
                "    DROP INDEX `uuid`,\n" .
                "    DROP INDEX `org_id`,\n" .
                "    MODIFY `id` bigint(20) NOT NULL AUTO_INCREMENT,\n" .
                "    MODIFY `org_id` bigint(20) NOT NULL,\n" .
                "    MODIFY `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,\n" .
                "    MODIFY `info` text CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL,\n" .
                "    ADD INDEX `idx_evt_acl` (`distribution`, `sharing_group_id`),\n" .
                "    ADD UNIQUE INDEX `uuid` (`uuid`),\n" .
                "    ROW_FORMAT=DYNAMIC,\n" .
                "    DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;",
            ),
            $this->rendered($schema, array(
                'events' => array('definition' => $live),
            ))
        );
        $this->assertSame(
            array(
                'events: column legacy is not in the target; kept',
                'events: index admin_info (info(32)) is not in the target; kept (the target index info starts with the same columns)',
                'events: index uuid is (uuid); the target has it as unique (uuid), so it is rebuilt',
            ),
            self::sorted($schema->notes())
        );
    }

    /**
     * A 3.0 instance on MySQL 8.4: no display widths, the MySQL collations.
     */
    public function testMysqlRendersItsOwnCollations()
    {
        $live = self::mysqlLive(self::TARGET, self::MYSQL);
        $live['columns']['info'] = self::mysqlColumn('text', array('collation' => 'utf8mb4_0900_ai_ci'));
        $live['columns']['org_id'] = self::mysqlColumn('int');

        $schema = new SchemaBuilder(AbstractGrammar::forDataSource(new MigrationTestMysqlExtended(self::MYSQL)));
        TableConverger::converge($this->mysqlInspector($live, self::MYSQL), $schema, 'events', self::TARGET);
        $this->assertSame(
            array(
                "ALTER TABLE `events`\n" .
                "    MODIFY `org_id` bigint NOT NULL,\n" .
                "    MODIFY `info` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci NOT NULL;",
            ),
            $schema->toSql()
        );
    }

    public function testDefaultsAreComparedAsTheServersSpellThem()
    {
        $live = self::mysqlLive(self::TARGET);
        $this->assertSame('current_timestamp()', $live['columns']['created_at']['default']);
        $this->assertSame(array(), TableConverger::plan($this->mysqlInspector($live), 'events', self::TARGET)['change']);

        // correlation_rules.created on a 2.5 instance: an expression default the target replaces.
        $live['columns']['distribution'] = self::mysqlColumn('tinyint(4)', array('default' => 'unix_timestamp()', 'default_expression' => true));
        $live['columns']['published'] = self::mysqlColumn('tinyint(1)', array('default' => null));
        $live['columns']['attribute_count'] = self::mysqlColumn('int(10) unsigned', array('null' => false, 'default' => '0'));
        $plan = TableConverger::plan($this->mysqlInspector($live), 'events', self::TARGET);
        $this->assertSame(array('default'), $plan['change']['distribution']['differs']);
        $this->assertSame(array('default'), $plan['change']['published']['differs']);
        $this->assertSame(array('null'), $plan['change']['attribute_count']['differs']);

        $pg = self::pgsqlLive('events', self::TARGET);
        $this->assertSame('false', $pg['columns']['published']['default']);
        $this->assertSame(array(), TableConverger::plan($this->pgsqlInspector($pg), 'events', self::TARGET)['change']);
    }

    /**
     * A wider type the generator reads as the target's - mediumblob as
     * binary - is not narrowed; a display width is no difference.
     */
    public function testTypesAreReadAsTheGeneratorReadsThem()
    {
        $target = self::TARGET;
        $target['columns']['request'] = array('type' => 'binary', 'null' => true);
        $live = self::mysqlLive($target);
        $live['columns']['request'] = self::mysqlColumn('mediumblob', array('null' => true));
        $live['columns']['org_id'] = self::mysqlColumn('bigint(11)');
        $this->assertTrue(TableConverger::isEmpty(TableConverger::plan($this->mysqlInspector($live), 'events', $target)));

        $live['columns']['request'] = self::mysqlColumn('mediumtext', array('null' => true, 'collation' => 'utf8mb4_bin'));
        $plan = TableConverger::plan($this->mysqlInspector($live), 'events', $target);
        $this->assertSame(array('type'), $plan['change']['request']['differs']);
    }

    // ---------------------------------------------------------------- indexes

    /**
     * A non-unique index over a unique target's columns duplicates it, and
     * the same definition under another name duplicates too. A varchar
     * prefix under the target's name is rebuilt whole.
     */
    public function testDuplicatesAreDroppedAndRedefinitionsRebuilt()
    {
        $target = self::TARGET;
        $target['columns']['object_type']['collate'] = Collation::CI;
        unset($target['columns']['object_type']['charset']);
        $target['indexes']['object_type'] = array('column' => array('object_type'));
        $live = self::mysqlLive($target);
        $live['indexes']['uuid_2'] = self::liveIndex('uuid_2', array('uuid'));
        $live['indexes']['acl_copy'] = self::liveIndex('acl_copy', array('distribution', 'sharing_group_id'));
        $live['indexes']['uuid_unique_copy'] = self::liveIndex('uuid_unique_copy', array('uuid'), true);
        $live['indexes']['object_type'] = self::liveIndex('object_type', array('object_type'), false, array('object_type' => 32));
        $live['indexes']['acl_wider'] = self::liveIndex('acl_wider', array('distribution', 'sharing_group_id', 'id'), true);

        $plan = TableConverger::plan($this->mysqlInspector($live), 'events', $target);
        $this->assertSame(
            array('object_type' => 'redefined', 'uuid_2' => 'duplicate', 'acl_copy' => 'duplicate', 'uuid_unique_copy' => 'duplicate'),
            $plan['dropIndexes']
        );
        $this->assertSame(array(array('column' => array('object_type'), 'options' => array('name' => 'object_type'))), $plan['addIndexes']);
        $this->assertContains('events: index acl_wider unique (distribution, sharing_group_id, id) is not in the target; kept', $plan['notes']);
        $this->assertContains('events: index uuid_2 duplicates the target index uuid; dropped', $plan['notes']);
    }

    public function testRetiredIndexesAreDroppedWhereTheyAre()
    {
        $live = self::mysqlLive(self::TARGET);
        $live['indexes']['sharing_group_id'] = self::liveIndex('sharing_group_id', array('sharing_group_id'));
        $schema = $this->mysqlSchema();
        TableConverger::converge($this->mysqlInspector($live), $schema, 'events', self::TARGET);
        $this->assertSame(array('ALTER TABLE `events` DROP INDEX `sharing_group_id`;'), $schema->toSql());
        $this->assertSame(array('DROP INDEX "idx_events_sharing_group_id";'), $schema->toSql($this->pgsqlGrammar()));
    }

    public function testAPrimaryKeyElsewhereIsABlocker()
    {
        $live = self::mysqlLive(self::TARGET);
        $live['indexes']['PRIMARY']['column'] = array('uuid');
        $plan = TableConverger::plan($this->mysqlInspector($live), 'events', self::TARGET);
        $this->assertFalse(TableConverger::isEmpty($plan));
        $this->assertStringContainsString('the primary key is (uuid) and the target keys on (id)', $plan['blockers'][0]);

        $this->expectException(MigrationDeferredException::class);
        TableConverger::converge($this->mysqlInspector($live), $this->mysqlSchema(), 'events', self::TARGET);
    }

    // ----------------------------------------------------------------- tables

    public function testAMissingTableIsCreatedAtTheTarget()
    {
        $schema = $this->mysqlSchema();
        $plan = TableConverger::converge($this->mysqlInspector(null), $schema, 'events', self::TARGET);
        $this->assertFalse($plan['exists']);
        $sql = $schema->toSql();
        $this->assertCount(4, $sql);
        // The FULLTEXT index is built without InnoDB's stopwords, as the baseline builds it.
        $this->assertSame('SET SESSION innodb_ft_enable_stopword = 0;', $sql[0]);
        $this->assertStringStartsWith("CREATE TABLE `events` (\n    `id` bigint(20) NOT NULL AUTO_INCREMENT,", $sql[1]);
        $this->assertStringEndsWith(') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci ROW_FORMAT=DYNAMIC;', $sql[1]);
        $this->assertSame(
            "ALTER TABLE `events`\n" .
            "    ADD INDEX `idx_evt_acl` (`distribution`, `sharing_group_id`),\n" .
            "    ADD INDEX `info` (`info`(255)),\n" .
            "    ADD FULLTEXT INDEX `info_search` (`info`),\n" .
            "    ADD UNIQUE INDEX `uuid` (`uuid`);",
            $sql[2]
        );
        $this->assertSame('SET SESSION innodb_ft_enable_stopword = DEFAULT;', $sql[3]);

        $pgsql = $schema->toSql($this->pgsqlGrammar());
        $this->assertStringStartsWith("CREATE TABLE \"events\" (\n    \"id\" bigint GENERATED BY DEFAULT AS IDENTITY,", $pgsql[0]);
        $this->assertSame(
            array(
                'CREATE INDEX "idx_events_info_lower" ON "events" (lower("info"));',
                'CREATE INDEX "idx_evt_acl" ON "events" ("distribution", "sharing_group_id");',
                'CREATE INDEX "idx_events_info" ON "events" USING hash ("info");',
                'CREATE EXTENSION IF NOT EXISTS pg_trgm;',
                'CREATE INDEX "idx_events_info_search" ON "events" USING gin ("info" gin_trgm_ops);',
                'CREATE UNIQUE INDEX "idx_events_uuid" ON "events" ("uuid");',
            ),
            array_slice($pgsql, 1)
        );
    }

    public function testRecreateLeavesATableAtItsTargetAlone()
    {
        $schema = $this->mysqlSchema();
        TableConverger::recreate($this->mysqlInspector(self::mysqlLive(self::TARGET)), $schema, 'events', self::TARGET);
        $this->assertTrue($schema->isEmpty());

        $live = self::mysqlLive(self::TARGET);
        $live['columns']['org_id'] = self::mysqlColumn('int(11)');
        $live['indexes']['PRIMARY']['column'] = array('uuid');
        TableConverger::recreate($this->mysqlInspector($live), $schema, 'events', self::TARGET);
        $sql = $schema->toSql();
        $this->assertCount(5, $sql);
        $this->assertSame('DROP TABLE `events`;', $sql[0]);
        $this->assertStringStartsWith('CREATE TABLE `events`', $sql[2]);
        $this->assertStringStartsWith("ALTER TABLE `events`\n    ADD INDEX `idx_evt_acl`", $sql[3]);
        $this->assertSame(array('events: recreated empty at the target'), $schema->notes());
    }

    // ------------------------------------------------------------- postgresql

    /**
     * A serial 32-bit key becomes the bigint identity after the one rewrite;
     * the text prefix index arrives as a hash index, the trigram one with
     * its extension; an old default is dropped before the type changes.
     */
    public function testPostgresConvergesKeysIndexesAndDefaults()
    {
        $live = self::pgsqlLive('events', self::TARGET);
        $live['columns']['id'] = self::pgsqlColumn('integer', array('increment' => 'serial'));
        $live['columns']['org_id'] = self::pgsqlColumn('integer', array('default' => '0'));
        unset($live['indexes']['idx_events_info'], $live['indexes']['idx_events_info_search']);
        $live['indexes']['idx_events_sharing_group_id'] = self::liveIndex('idx_events_sharing_group_id', array('sharing_group_id'));

        $schema = new SchemaBuilder($this->pgsqlGrammar());
        $plan = TableConverger::converge($this->pgsqlInspector($live), $schema, 'events', self::TARGET);
        $this->assertSame(array('sharing_group_id' => 'retired'), $plan['dropIndexes']);
        $sql = $schema->toSql();
        $this->assertSame('DROP INDEX "idx_events_sharing_group_id";', $sql[0]);
        $this->assertSame(
            "ALTER TABLE \"events\"\n" .
            "    ALTER COLUMN \"id\" TYPE bigint USING \"id\"::bigint,\n" .
            "    ALTER COLUMN \"id\" SET NOT NULL,\n" .
            "    ALTER COLUMN \"org_id\" DROP DEFAULT,\n" .
            "    ALTER COLUMN \"org_id\" TYPE bigint USING \"org_id\"::bigint,\n" .
            "    ALTER COLUMN \"org_id\" SET NOT NULL;",
            $sql[1]
        );
        $this->assertSame(
            array(
                'CREATE INDEX "idx_events_info" ON "events" USING hash ("info");',
                'CREATE EXTENSION IF NOT EXISTS pg_trgm;',
                'CREATE INDEX "idx_events_info_search" ON "events" USING gin ("info" gin_trgm_ops);',
            ),
            array_slice($sql, 2, 3)
        );
        $this->assertStringStartsWith('DO $$', $sql[5]);
        $this->assertCount(6, $sql);
    }

    /**
     * A prefix over text in a composite index has no PostgreSQL spelling: the
     * index is MySQL's alone, and a PostgreSQL box that built it as a btree
     * over whole values loses it.
     */
    public function testACompositeTextPrefixIndexIsMysqlOnly()
    {
        $target = self::TARGET;
        $target['indexes']['idx_evt_org_info'] = array('column' => array('org_id', 'info'), 'length' => array('info' => 191));

        $mysql = TableConverger::plan($this->mysqlInspector(self::mysqlLive(self::TARGET)), 'events', $target);
        $this->assertSame(array('org_id', 'info'), $mysql['addIndexes'][0]['column']);
        $this->assertTrue(TableConverger::isEmpty(
            TableConverger::plan($this->pgsqlInspector(self::pgsqlLive('events', $target)), 'events', $target)
        ));

        $live = self::pgsqlLive('events', $target);
        $live['indexes']['idx_evt_org_info'] = self::liveIndex('idx_evt_org_info', array('org_id', 'info'));
        $schema = new SchemaBuilder($this->pgsqlGrammar());
        $plan = TableConverger::converge($this->pgsqlInspector($live), $schema, 'events', $target);
        $this->assertSame(array('idx_evt_org_info' => 'retired'), $plan['dropIndexes']);
        $this->assertSame(array('DROP INDEX "idx_evt_org_info";'), $schema->toSql());

        $schema = $this->mysqlSchema();
        TableConverger::converge($this->mysqlInspector(null), $schema, 'events', $target);
        $this->assertStringContainsString('ADD INDEX `idx_evt_org_info` (`org_id`, `info`(191))', implode("\n", $schema->toSql()));
        $this->assertStringNotContainsString('idx_evt_org_info', implode("\n", $schema->toSql($this->pgsqlGrammar())));
    }

    public function testPostgresComparesAnIndexWithItsOwnStatementByMethod()
    {
        $live = self::pgsqlLive('events', self::TARGET);
        $live['indexes']['idx_events_info_search']['type'] = 'btree';
        $live['indexes']['idx_events_admin'] = self::liveIndex('idx_events_admin', array('lower(info)'), false, array(), 'btree');
        $plan = TableConverger::plan($this->pgsqlInspector($live), 'events', self::TARGET);
        $this->assertSame(array('info_search' => 'redefined'), $plan['dropIndexes']);
        $this->assertContains('events: index idx_events_admin (lower(info)) is not in the target; kept', $plan['notes']);
    }

    // ------------------------------------------------------------- migrations

    public function testATableMigrationConvergesItsTableAndNotesWhatItKeeps()
    {
        $id = '20261101_000000_converge_events';
        $live = self::mysqlLive(self::TARGET);
        $live['columns']['org_id'] = self::mysqlColumn('int(11)');
        $live['columns']['legacy'] = self::mysqlColumn('int(11)', array('null' => true));
        $manager = new SchemaRenderingMigrationManager(array('Migration_' . $id . '.php'));
        $manager->liveSchema = $this->mysqlInspector($live);

        $this->assertSame(
            array(
                "SET SESSION alter_algorithm = 'DEFAULT';",
                'SET SESSION lock_wait_timeout = 300;',
                'ALTER TABLE `events` MODIFY `org_id` bigint(20) NOT NULL;',
                'SET SESSION lock_wait_timeout = DEFAULT;',
            ),
            $manager->toSql($id)
        );
        $this->assertSame(array('events: column legacy is not in the target; kept'), $manager->notes($id));
        $this->assertSame(array(), $manager->lastSkipped());
    }

    public function testARecreatingMigrationDropsAndCreates()
    {
        $id = '20261101_000001_recreate_events';
        $live = self::mysqlLive(self::TARGET);
        $live['columns']['org_id'] = self::mysqlColumn('int(11)');
        $manager = new SchemaRenderingMigrationManager(array('Migration_' . $id . '.php'));
        $manager->liveSchema = $this->mysqlInspector($live);
        $sql = $manager->toSql($id);
        $this->assertSame('DROP TABLE `events`;', $sql[2]);
        $this->assertCount(8, $sql);
    }

    public function testTheSessionLetsTheServerChooseTheAlgorithm()
    {
        $mariadb = TableConverger::session($this->mysqlInspector(null));
        $this->assertSame(
            array("SET SESSION alter_algorithm = 'DEFAULT';", 'SET SESSION lock_wait_timeout = 300;'),
            $mariadb['set']
        );
        $this->assertSame(array('SET SESSION lock_wait_timeout = DEFAULT;'), $mariadb['reset']);
        $mysql = TableConverger::session($this->mysqlInspector(null, '8.4.11'));
        $this->assertSame('SET SESSION old_alter_table = OFF;', $mysql['set'][0]);
        $this->assertSame(array(), TableConverger::session($this->pgsqlInspector(self::pgsqlLive('events', self::TARGET))));
    }

    public function testATableAtItsTargetRunsNoSessionStatements()
    {
        $id = '20261101_000000_converge_events';
        $manager = new SchemaRenderingMigrationManager(array('Migration_' . $id . '.php'));
        $manager->liveSchema = $this->mysqlInspector(self::mysqlLive(self::TARGET));
        $this->assertSame(array(), $manager->toSql($id));
    }

    public function testAnOfflineMigrationIsNotStartedOnALiveInstance()
    {
        $id = '20261101_000000_converge_events';
        $manager = new SchemaRenderingMigrationManager(array('Migration_' . $id . '.php'));
        $live = Configure::read('MISP.live');
        try {
            Configure::write('MISP.live', true);
            $this->assertRegExp('/does not start while the instance is live/', $manager->refusal(array($id)));
            $this->assertNull($manager->refusal(array()));
            Configure::write('MISP.live', false);
            $this->assertNull($manager->refusal(array($id)));
        } finally {
            Configure::write('MISP.live', $live);
        }
    }

    /**
     * An apply logs the notes even when there is nothing to run.
     */
    public function testNotesGoToTheUpdateLog()
    {
        $id = '20261101_000000_converge_events';
        $live = self::mysqlLive(self::TARGET);
        $live['columns']['legacy'] = self::mysqlColumn('int(11)', array('null' => true));
        $manager = new NoteRecordingMigrationManager(array('Migration_' . $id . '.php'));
        $manager->liveSchema = $this->mysqlInspector($live);

        $this->assertTrue($manager->apply($id));
        $this->assertSame(
            array(array('Notes on the migration ' . $id, array('events: column legacy is not in the target; kept'))),
            $manager->logged
        );
        $this->assertSame(array('events: column legacy is not in the target; kept'), $manager->notes($id));
    }

    // ---------------------------------------------------------------- helpers

    private function mysqlSchema()
    {
        return new SchemaBuilder(AbstractGrammar::forDataSource(new MigrationTestMysqlExtended(self::MARIADB)));
    }

    private function pgsqlGrammar()
    {
        return AbstractGrammar::forDataSource(new MigrationTestPostgres());
    }

    /**
     * @param array|null $definition
     * @param string $version
     * @return MigrationTestInspector
     */
    private function mysqlInspector($definition, $version = self::MARIADB)
    {
        $inspector = new MigrationTestInspector(
            SchemaInspector::FLAVOUR_MYSQL,
            $definition === null ? array() : array('events' => array('definition' => $definition))
        );
        $inspector->version = $version;
        return $inspector;
    }

    private function pgsqlInspector(array $definition)
    {
        return new MigrationTestInspector(SchemaInspector::FLAVOUR_PGSQL, array('events' => array('definition' => $definition)));
    }

    /**
     * Render after skipSatisfied(), as the manager does.
     */
    private function rendered(SchemaBuilder $schema, array $live)
    {
        $schema->skipSatisfied(new MigrationTestInspector(SchemaInspector::FLAVOUR_MYSQL, $live));
        return $schema->toSql();
    }

    private static function sorted(array $lines)
    {
        sort($lines);
        return $lines;
    }

    /**
     * A target as information_schema reports it once loaded.
     */
    public static function mysqlLive(array $target, $version = self::MARIADB)
    {
        $mysql = Collation::family($version) === Collation::MYSQL;
        $resolve = function ($collate) use ($version) {
            if (!Collation::isToken($collate)) {
                return $collate;
            }
            $resolved = Collation::forServer($collate, $version);
            return $resolved['collate'];
        };
        $integers = array(
            'biginteger' => array('bigint', 20),
            'integer' => array('int', 11),
            'smallinteger' => array('smallint', 6),
            'tinyinteger' => array('tinyint', 4),
        );
        $columns = array();
        $key = null;
        foreach ($target['columns'] as $name => $spec) {
            $type = $spec['type'];
            if ($type === 'boolean') {
                $columnType = 'tinyint(1)';
            } elseif (isset($integers[$type])) {
                list($base, $width) = $integers[$type];
                $width = $type === 'integer' && !empty($spec['unsigned']) ? 10 : $width;
                $columnType = $mysql ? $base : $base . '(' . $width . ')';
            } elseif ($type === 'string') {
                $columnType = 'varchar(' . $spec['length'] . ')';
            } elseif ($type === 'binary') {
                $columnType = 'blob';
            } else {
                $columnType = $type . (isset($spec['length']) ? '(' . $spec['length'] . ')' : '');
            }
            $columnType .= empty($spec['unsigned']) ? '' : ' unsigned';
            $extra = array('null' => !empty($spec['null']));
            if (isset($spec['key'])) {
                $key = $name;
                $extra['increment'] = 'auto_increment';
            }
            if (isset($spec['default'])) {
                $current = $spec['default'] === 'CURRENT_TIMESTAMP';
                $extra['default'] = $current ? ($mysql ? 'CURRENT_TIMESTAMP' : 'current_timestamp()') : $spec['default'];
                $extra['default_expression'] = $current;
            }
            if (in_array($type, TableConverger::STRING_TYPES, true)) {
                $extra['collation'] = $resolve(isset($spec['collate']) ? $spec['collate'] : $target['options']['collate']);
            }
            $columns[$name] = self::mysqlColumn($columnType, $extra);
        }
        $indexes = array('PRIMARY' => self::liveIndex('PRIMARY', array($key), true));
        foreach ($target['indexes'] as $name => $index) {
            if (isset($index['mysql']) && $index['mysql'] === false) {
                continue;
            }
            $indexes[$name] = self::liveIndex(
                $name,
                $index['column'],
                !empty($index['unique']),
                isset($index['length']) ? $index['length'] : array(),
                empty($index['fulltext']) ? 'btree' : 'fulltext'
            );
        }
        $collation = $resolve($target['options']['collate']);
        return array(
            'options' => array(
                'engine' => 'InnoDB',
                'row_format' => 'DYNAMIC',
                'collation' => $collation,
                'charset' => SchemaInspector::charsetOfCollation($collation),
            ),
            'columns' => $columns,
            'indexes' => $indexes,
        );
    }

    public static function mysqlColumn($columnType, array $extra = array())
    {
        list($base, $length, $scale, $unsigned) = SchemaInspector::splitMysqlType($columnType);
        $column = array_merge(array(
            'type' => $columnType,
            'base' => $base,
            'length' => $length,
            'scale' => $scale,
            'unsigned' => $unsigned,
            'null' => false,
            'default' => null,
            'default_expression' => false,
            'charset' => null,
            'collation' => null,
            'increment' => null,
        ), $extra);
        if ($column['collation'] !== null) {
            $column['charset'] = SchemaInspector::charsetOfCollation($column['collation']);
        }
        return $column;
    }

    /**
     * A target as PostgreSQL's catalog reports it once loaded.
     */
    public static function pgsqlLive($table, array $target)
    {
        $columns = array();
        $key = null;
        foreach ($target['columns'] as $name => $spec) {
            $base = TableConverger::PGSQL_TYPES[$spec['type']];
            $extra = array('null' => !empty($spec['null']));
            if ($spec['type'] === 'string') {
                $extra['length'] = $spec['length'];
            }
            if (isset($spec['key'])) {
                $key = $name;
                $extra['increment'] = 'identity';
            }
            if (isset($spec['default'])) {
                $default = $spec['default'];
                if ($spec['type'] === 'boolean') {
                    $default = $default ? 'true' : 'false';
                }
                $extra['default'] = $default;
                $extra['default_expression'] = $default === 'CURRENT_TIMESTAMP';
            }
            $columns[$name] = self::pgsqlColumn($base, $extra);
        }
        $indexes = array('PRIMARY' => self::liveIndex($table . '_pkey', array($key), true));
        foreach ($target['indexes'] as $name => $index) {
            if (BaselineGenerator::isMysqlOnly(array('column' => isset($index['column']) ? $index['column'] : array($name)) + $index, $target['columns'])) {
                continue;
            }
            $physical = isset($index['pgsql']['name']) ? $index['pgsql']['name']
                : (strpos($name, 'idx_') === 0 ? $name : 'idx_' . $table . '_' . $name);
            $method = 'btree';
            $indexColumns = isset($index['column']) ? $index['column'] : array();
            $unique = !empty($index['unique']);
            if (isset($index['pgsql']['sql'])) {
                $method = preg_match('/USING (\w+)/', $index['pgsql']['sql'], $m) ? $m[1] : 'btree';
                $indexColumns = array('(expression)');
                $unique = (bool)preg_match('/^CREATE UNIQUE /i', $index['pgsql']['sql']);
            } elseif (BaselineGenerator::needsHashRewrite($index, $target['columns'])) {
                $method = 'hash';
            }
            $indexes[$physical] = self::liveIndex($physical, $indexColumns, $unique, array(), $method);
        }
        $indexes['PRIMARY']['primary'] = true;
        return array(
            'options' => array('engine' => null, 'row_format' => null, 'collation' => null, 'charset' => null),
            'columns' => $columns,
            'indexes' => $indexes,
        );
    }

    public static function pgsqlColumn($base, array $extra = array())
    {
        $column = array_merge(array(
            'base' => $base,
            'length' => null,
            'scale' => null,
            'unsigned' => false,
            'null' => false,
            'default' => null,
            'default_expression' => false,
            'charset' => null,
            'collation' => null,
            'increment' => null,
        ), $extra);
        $column['type'] = $base . ($column['length'] === null ? '' : '(' . $column['length'] . ')');
        return $column;
    }

    public static function liveIndex($name, array $columns, $unique = false, array $length = array(), $type = 'btree')
    {
        return array(
            'name' => $name,
            'column' => $columns,
            'unique' => $unique,
            'primary' => $name === 'PRIMARY',
            'length' => $length,
            'type' => $type,
            'expression' => false,
            'definition' => null,
        );
    }
}
