<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/TableConvergerTest.php';

if (!class_exists('StatementRecordingMigrationManager', false)) {
    /**
     * The real execute(), with the statements it would run kept in memory.
     */
    class StatementRecordingMigrationManager extends NoteRecordingMigrationManager
    {
        public $ran = array();

        protected function runner()
        {
            $manager = $this;
            return new class($manager) {
                private $manager;

                public function __construct($manager)
                {
                    $this->manager = $manager;
                }

                public function run($id, array $statements)
                {
                    $this->manager->ran = array_merge($this->manager->ran, $statements);
                    return true;
                }

                public function lastErrors()
                {
                    return array();
                }
            };
        }
    }

    class ReportingStatementManager extends StatementRecordingMigrationManager
    {
        public $reported = array();

        public function collect($event, $id, array $lines)
        {
            $this->reported[] = array($event, $id, $lines);
        }
    }
}

/**
 * TablePreflight against scripted catalogs and scripted answers to its row
 * queries.
 */
class TablePreflightTest extends TestCase
{
    const TARGET = TableConvergerTest::TARGET;

    const TAGS = array(
        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
        'columns' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            'name' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => Collation::CI),
            'org_id' => array('type' => 'biginteger', 'null' => false, 'default' => '0'),
            'exportable' => array('type' => 'boolean', 'null' => false),
        ),
        'indexes' => array(
            'idx_tags_name_lower' => array(
                'unique' => true,
                'mysql' => false,
                'pgsql' => array('sql' => 'CREATE UNIQUE INDEX %1$s ON %2$s (lower("name"));'),
            ),
            'name' => array('column' => array('name'), 'unique' => true),
            'org_name' => array('column' => array('org_id', 'name'), 'unique' => true),
        ),
    );

    const MARIADB = TableConvergerTest::MARIADB;

    const MYSQL = TableConvergerTest::MYSQL;

    // ---------------------------------------------------------------- server

    public function testAServerBelowTheFloorDefersBeforeAnythingIsRead()
    {
        foreach (array('10.6.18-MariaDB' => 'MariaDB 10.6', '8.0.36' => 'MySQL 8.0') as $version => $named) {
            $inspector = $this->mysqlInspector('events', TableConvergerTest::mysqlLive(self::TARGET));
            $inspector->version = $version;
            $checked = TableConverger::preflight($inspector, 'events', self::TARGET);
            $this->assertNull($checked['plan']);
            $this->assertCount(1, $checked['defer']);
            $this->assertStringContainsString('This database server is ' . $named . '.', $checked['defer'][0]);
        }
        $inspector = $this->pgsqlInspector('events', TableConvergerTest::pgsqlLive('events', self::TARGET));
        $inspector->version = '15.8 (Debian 15.8-1.pgdg120+1)';
        $checked = TableConverger::preflight($inspector, 'events', self::TARGET);
        $this->assertSame(array('This database server is PostgreSQL 15.8 (Debian 15.8-1.pgdg120+1). MISP 3.0 needs PostgreSQL 16 or later. Upgrade the database server, then run the update again.'), $checked['defer']);
        $this->assertSame(array(), $inspector->asked);

        $inspector->version = '16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)';
        $this->assertSame(array(), TableConverger::preflight($inspector, 'events', self::TARGET)['defer']);
    }

    public function testATableAtItsTargetReadsNoRows()
    {
        $inspector = $this->mysqlInspector('events', TableConvergerTest::mysqlLive(self::TARGET));
        $checked = TableConverger::preflight($inspector, 'events', self::TARGET);
        $this->assertSame(array(), $checked['defer']);
        $this->assertTrue(TableConverger::isEmpty($checked['plan']));
        $this->assertSame(array(), $inspector->asked);
    }

    public function testABlockerDefersBeforeAnyRowIsRead()
    {
        $live = TableConvergerTest::mysqlLive(self::TARGET);
        $live['indexes']['PRIMARY']['column'] = array('uuid');
        $live['columns']['info']['null'] = true;
        $inspector = $this->mysqlInspector('events', $live);
        $checked = TableConverger::preflight($inspector, 'events', self::TARGET);
        $this->assertCount(1, $checked['defer']);
        $this->assertStringStartsWith('events: the primary key is (uuid)', $checked['defer'][0]);
        $this->assertSame(array(), $inspector->asked);
    }

    // ------------------------------------------------------------- key limit

    public function testKeysAreMeasuredAgainstThePageSize()
    {
        $live = TableConvergerTest::mysqlLive(self::TARGET);
        $live['columns']['legacy_note'] = TableConvergerTest::mysqlColumn('varchar(1000)', array('collation' => 'utf8mb3_general_ci'));
        $live['columns']['legacy_wide'] = TableConvergerTest::mysqlColumn('varchar(800)', array('collation' => 'utf8mb4_general_ci'));
        // 40 + 1000 x 3 bytes: kept as it is, under 3,072.
        $live['indexes']['admin_note'] = TableConvergerTest::liveIndex('admin_note', array('uuid', 'legacy_note'));
        // 800 x 4 bytes.
        $live['indexes']['admin_wide'] = TableConvergerTest::liveIndex('admin_wide', array('legacy_wide'));
        $checked = TableConverger::preflight($this->mysqlInspector('events', $live), 'events', self::TARGET);
        $this->assertSame(
            array('events: the index admin_wide (legacy_wide) is not in the target and is kept, but it would be 3200 bytes once its columns are converted, over the 3072-byte key limit. Drop it or give it a shorter prefix, then run the update again.'),
            $checked['defer']
        );

        $inspector = $this->mysqlInspector('events', TableConvergerTest::mysqlLive(self::TARGET));
        $inspector->variables['innodb_page_size'] = '4096';
        $checked = TableConverger::preflight($inspector, 'events', self::TARGET);
        $this->assertSame(
            array('events: index info is 1020 bytes, over the 768-byte key limit of innodb_page_size = 4096. MISP 3.0 needs innodb_page_size = 16384 (the default) or larger.'),
            $checked['defer']
        );
    }

    // ------------------------------------------------------------------- rows

    /**
     * Each check is a SUM over one scan of the table; the hits are listed.
     */
    public function testRowsThatDoNotFitDeferListingThem()
    {
        $live = TableConvergerTest::mysqlLive(self::TARGET);
        $live['columns']['info'] = TableConvergerTest::mysqlColumn('mediumtext', array('collation' => 'utf8mb4_uca1400_ai_ci', 'null' => true));
        $live['columns']['attribute_count'] = TableConvergerTest::mysqlColumn('bigint(20) unsigned', array('null' => true, 'default' => '0'));
        $live['columns']['object_type'] = TableConvergerTest::mysqlColumn('varchar(255)', array('collation' => 'ascii_general_ci'));
        $inspector = $this->mysqlInspector('events', $live);
        $inspector->probes = array(
            '/^SELECT SUM/' => array(array('n0' => '1', 'n1' => '0', 'n2' => '0', 'n3' => '12')),
            '/WHERE `info` IS NULL/' => array(array('id' => '7')),
            '/WHERE CHAR_LENGTH\(`object_type`\) > 80/' => array_map(function ($id) {
                return array('id' => (string)$id);
            }, range(21, 30)),
        );
        $checked = TableConverger::preflight($inspector, 'events', self::TARGET);
        $this->assertSame(
            'SELECT SUM(CASE WHEN `info` IS NULL THEN 1 ELSE 0 END) AS `n0`,'
                . ' SUM(CASE WHEN LENGTH(`info`) > 65535 THEN 1 ELSE 0 END) AS `n1`,'
                . ' SUM(CASE WHEN (`attribute_count` > 4294967295) THEN 1 ELSE 0 END) AS `n2`,'
                . ' SUM(CASE WHEN CHAR_LENGTH(`object_type`) > 80 THEN 1 ELSE 0 END) AS `n3` FROM `events`;',
            $inspector->asked[0]
        );
        $this->assertSame(
            array(
                'events: in 1 row (id 7), info is NULL, which the target does not allow. Correct those rows, then run the update again.',
                'events: in 12 rows (id 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, ...), object_type is longer than the 80 characters the target allows. Correct those rows, then run the update again.',
            ),
            $checked['defer']
        );
    }

    /**
     * A narrower integer is checked at the ends of an index that leads with
     * the column, and only scanned when a value is out of range.
     */
    public function testARangeIsReadOffTheIndexEnds()
    {
        $live = TableConvergerTest::mysqlLive(self::TARGET);
        $live['columns']['attribute_count'] = TableConvergerTest::mysqlColumn('bigint(20) unsigned', array('null' => true, 'default' => '0'));
        $live['indexes']['attribute_count'] = TableConvergerTest::liveIndex('attribute_count', array('attribute_count', 'distribution'));
        $inspector = $this->mysqlInspector('events', $live);
        $checked = TableConverger::preflight($inspector, 'events', self::TARGET);
        $this->assertSame(
            array('SELECT CASE WHEN (MAX(`attribute_count`) > 4294967295) THEN 1 ELSE 0 END AS outside FROM `events`;'),
            $inspector->asked
        );
        $this->assertSame(array(), $checked['defer']);

        $inspector = $this->mysqlInspector('events', $live);
        $inspector->probes = array('/AS outside/' => array(array('outside' => '1')), '/^SELECT SUM/' => array(array('n0' => '1')));
        $checked = TableConverger::preflight($inspector, 'events', self::TARGET);
        $this->assertSame(
            'SELECT SUM(CASE WHEN (`attribute_count` > 4294967295) THEN 1 ELSE 0 END) AS `n0` FROM `events` FORCE INDEX (`attribute_count`);',
            $inspector->asked[1]
        );
        $this->assertStringContainsString('attribute_count is outside the range 0 to 4294967295 the target allows', $checked['defer'][0]);
    }

    /**
     * An indexed column is read from its narrowest index alone.
     */
    public function testAsciiColumnsAreReadFromTheirIndex()
    {
        $live = TableConvergerTest::mysqlLive(self::TARGET);
        $live['columns']['uuid'] = TableConvergerTest::mysqlColumn('varchar(40)', array('collation' => 'utf8mb3_bin'));
        $live['indexes']['uuid_info'] = TableConvergerTest::liveIndex('uuid_info', array('uuid', 'distribution'));
        $inspector = $this->mysqlInspector('events', $live);
        $inspector->probes = array(
            '/^SELECT SUM/' => array(array('n0' => '2')),
            '/^SELECT `id` AS id FROM `events` FORCE INDEX \(`uuid`\)/' => array(array('id' => '9'), array('id' => '4')),
        );
        $checked = TableConverger::preflight($inspector, 'events', self::TARGET);
        $this->assertSame(
            'SELECT SUM(CASE WHEN LENGTH(CONVERT(`uuid` USING utf8mb4)) <> CHAR_LENGTH(`uuid`) THEN 1 ELSE 0 END) AS `n0` FROM `events` FORCE INDEX (`uuid`);',
            $inspector->asked[0]
        );
        $this->assertSame(
            array('events: in 2 rows (id 4, 9), uuid holds characters outside ASCII, which its target charset cannot store. Correct those rows, then run the update again.'),
            $checked['defer']
        );
        // utf8mb3_bin to ascii_bin compares no two values as equal that it told apart.
        $this->assertCount(2, $inspector->asked);
    }

    public function testPostgresChecksNullsLengthsAndRanges()
    {
        $live = TableConvergerTest::pgsqlLive('events', self::TARGET);
        $live['columns']['uuid'] = TableConvergerTest::pgsqlColumn('character varying', array('length' => 255));
        $live['columns']['distribution'] = TableConvergerTest::pgsqlColumn('integer', array('default' => '0'));
        $inspector = $this->pgsqlInspector('events', $live);
        TableConverger::preflight($inspector, 'events', self::TARGET);
        // idx_evt_acl leads with distribution, so its ends say the values fit.
        $this->assertSame(
            array(
                'SELECT CASE WHEN (MIN("distribution") < -32768 OR MAX("distribution") > 32767) THEN 1 ELSE 0 END AS outside FROM "events";',
                'SELECT SUM(CASE WHEN CHAR_LENGTH("uuid") > 40 THEN 1 ELSE 0 END) AS "n0" FROM "events";',
            ),
            $inspector->asked
        );
    }

    // ----------------------------------------------------------------- latin1

    /**
     * UTF-8 bytes in a latin1 column pass through a binary type, in a
     * statement before the rebuild; the apply declares that plan.
     */
    public function testUtf8StoredAsLatin1PassesThroughBinary()
    {
        $id = '20261101_000000_converge_events';
        $live = TableConvergerTest::mysqlLive(self::TARGET);
        $live['columns']['info'] = TableConvergerTest::mysqlColumn('text', array('collation' => 'latin1_swedish_ci'));
        unset($live['indexes']['info_search']);
        $manager = new StatementRecordingMigrationManager(array('Migration_' . $id . '.php'));
        $manager->liveSchema = $this->mysqlInspector('events', $live);
        $manager->liveSchema->probes = array('/utf8mb4\) USING binary\)/' => array(array('n0' => '3', 'n1' => '0')));

        $this->assertTrue($manager->apply($id), (string)$manager->lastError());
        $this->assertSame(
            'SELECT SUM(CASE WHEN LENGTH(CONVERT(`info` USING utf8mb4)) <> LENGTH(`info`)'
                . ' AND CONVERT(CONVERT(CAST(`info` AS BINARY) USING utf8mb4) USING binary) <=> CAST(`info` AS BINARY) THEN 1 ELSE 0 END) AS `n0`,'
                . ' SUM(CASE WHEN LENGTH(CONVERT(`info` USING utf8mb4)) <> LENGTH(`info`)'
                . ' AND NOT (CONVERT(CONVERT(CAST(`info` AS BINARY) USING utf8mb4) USING binary) <=> CAST(`info` AS BINARY)) THEN 1 ELSE 0 END) AS `n1` FROM `events`;',
            $manager->liveSchema->asked[0]
        );
        $this->assertSame(
            array(
                'SET SESSION alter_algorithm = \'DEFAULT\';',
                'SET SESSION lock_wait_timeout = 300;',
                'SET SESSION innodb_ft_enable_stopword = 0;',
                'ALTER TABLE `events` MODIFY `info` BLOB NOT NULL;',
                "ALTER TABLE `events`\n"
                    . "    MODIFY `info` text CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL,\n"
                    . "    ADD FULLTEXT INDEX `info_search` (`info`);",
                'SET SESSION innodb_ft_enable_stopword = DEFAULT;',
                'SET SESSION lock_wait_timeout = DEFAULT;',
            ),
            $manager->ran
        );
        $this->assertContains(
            'events: info holds UTF-8 stored as latin1 in 3 rows; it passes through BLOB, keeping its bytes, which costs one more rebuild',
            $manager->notes($id)
        );

        // A dry run reads no rows, so it shows the plain conversion.
        $manager->liveSchema->asked = array();
        $this->assertNotContains('ALTER TABLE `events` MODIFY `info` BLOB NOT NULL;', $manager->toSql($id));
        $this->assertSame(array(), $manager->liveSchema->asked);
    }

    public function testLatin1MixedWithUtf8Defers()
    {
        $id = '20261101_000000_converge_events';
        $live = TableConvergerTest::mysqlLive(self::TARGET);
        $live['columns']['info'] = TableConvergerTest::mysqlColumn('text', array('collation' => 'latin1_swedish_ci'));
        $manager = new StatementRecordingMigrationManager(array('Migration_' . $id . '.php'));
        $manager->liveSchema = $this->mysqlInspector('events', $live);
        $manager->liveSchema->probes = array(
            '/^SELECT SUM.*USING binary/' => array(array('n0' => '2', 'n1' => '1')),
            '/^SELECT `id` AS id .* AND CONVERT/' => array(array('id' => '3'), array('id' => '5')),
            '/^SELECT `id` AS id .* AND NOT/' => array(array('id' => '8')),
        );

        $this->assertFalse($manager->apply($id));
        $this->assertSame(MigrationManager::STATUS_DEFERRED, $manager->lastStatus());
        $this->assertSame(
            'events: info holds UTF-8 stored as latin1 in 2 rows (id 3, 5) and latin1 text in 1 row (id 8), and no one conversion is right for both. Correct those rows, then run the update again.',
            $manager->lastError()
        );
        $this->assertSame(array(), $manager->ran);
    }

    // ----------------------------------------------------------------- unique

    /**
     * Under uca1400_ai_ci 'strasse' and 'straße' are one value; a byte
     * comparison and a key already unique on its own cannot clash.
     */
    public function testAUniqueKeyUnderALooserCollationIsProbed()
    {
        $live = TableConvergerTest::mysqlLive(self::TAGS);
        $live['columns']['name'] = TableConvergerTest::mysqlColumn('varchar(255)', array('collation' => 'utf8mb3_general_ci'));
        $inspector = $this->mysqlInspector('tags', $live);
        $inspector->probes = array('/GROUP BY CONVERT/' => array(
            array('k0' => 'strasse', 'n' => '2', 'ids' => '1, 2'),
            array('k0' => 'Bär', 'n' => '3', 'ids' => '4, 6, 9'),
        ));
        $checked = TableConverger::preflight($inspector, 'tags', self::TAGS);
        $this->assertSame(
            array(
                'SELECT CONVERT(`name` USING utf8mb4) COLLATE utf8mb4_uca1400_ai_ci AS `k0`, COUNT(*) AS n,'
                    . " GROUP_CONCAT(`id` ORDER BY `id` SEPARATOR ', ') AS ids FROM `tags`"
                    . ' WHERE CONVERT(`name` USING utf8mb4) COLLATE utf8mb4_uca1400_ai_ci IS NOT NULL'
                    . ' GROUP BY CONVERT(`name` USING utf8mb4) COLLATE utf8mb4_uca1400_ai_ci HAVING COUNT(*) > 1 LIMIT 10;',
                'SELECT `org_id` AS `k0`, CONVERT(`name` USING utf8mb4) COLLATE utf8mb4_uca1400_ai_ci AS `k1`, COUNT(*) AS n,'
                    . " GROUP_CONCAT(`id` ORDER BY `id` SEPARATOR ', ') AS ids FROM `tags`"
                    . ' WHERE `org_id` IS NOT NULL AND CONVERT(`name` USING utf8mb4) COLLATE utf8mb4_uca1400_ai_ci IS NOT NULL'
                    . ' GROUP BY `org_id`, CONVERT(`name` USING utf8mb4) COLLATE utf8mb4_uca1400_ai_ci HAVING COUNT(*) > 1 LIMIT 10;',
            ),
            $inspector->asked
        );
        $this->assertSame(
            'tags: the unique key name compares name under utf8mb4_uca1400_ai_ci from now on, and rows share a value of it: "strasse" in rows id 1, 2; "Bär" in rows id 4, 6, 9. Merge or rename those rows, then run the update again.',
            $checked['defer'][0]
        );
    }

    public function testAnAddedUniqueKeyIsProbedUnlessALiveOneImpliesIt()
    {
        $live = TableConvergerTest::mysqlLive(self::TAGS);
        unset($live['indexes']['name'], $live['indexes']['org_name']);
        $live['indexes']['name'] = TableConvergerTest::liveIndex('name', array('name'), true, array('name' => 191));
        $inspector = $this->mysqlInspector('tags', $live);
        $checked = TableConverger::preflight($inspector, 'tags', self::TAGS);
        // name(191) unique is rebuilt full-column, and implies (org_id, name).
        $this->assertSame(array('name' => 'redefined'), $checked['plan']['dropIndexes']);
        $this->assertSame(array(), $inspector->asked);

        unset($live['indexes']['name']);
        $inspector = $this->mysqlInspector('tags', $live);
        $inspector->probes = array('/GROUP BY `name`/' => array(array('k0' => 'tlp:red', 'n' => '2', 'ids' => '5, 8')));
        $checked = TableConverger::preflight($inspector, 'tags', self::TAGS);
        $this->assertCount(2, $inspector->asked);
        $this->assertSame(
            array('tags: the run adds the unique key name, and rows share a value of it: "tlp:red" in rows id 5, 8. Merge or rename those rows, then run the update again.'),
            $checked['defer']
        );
    }

    public function testRowsSharingAnIdentifierAreToldToKeepOne()
    {
        $target = self::TAGS;
        $target['columns']['uuid'] = array('type' => 'string', 'length' => 40, 'null' => false, 'collate' => Collation::ASCII);
        $target['indexes']['uuid'] = array('column' => array('uuid'), 'unique' => true);
        $target['indexes']['org_uuid'] = array('column' => array('org_id', 'uuid'), 'unique' => true);
        $live = TableConvergerTest::mysqlLive($target);
        unset($live['indexes']['name'], $live['indexes']['uuid'], $live['indexes']['org_uuid']);
        $inspector = $this->mysqlInspector('tags', $live);
        $inspector->probes = array(
            '/GROUP BY `name`/' => array(array('k0' => 'tlp:red', 'n' => '2', 'ids' => '5, 8')),
            '/GROUP BY `uuid`/' => array(array('k0' => 'c99c4e4e-0000-4000-8000-000000000001', 'n' => '2', 'ids' => '3, 4')),
            '/GROUP BY `org_id`, `uuid`/' => array(array('k0' => '1', 'k1' => 'c99c4e4e-0000-4000-8000-000000000001', 'n' => '2', 'ids' => '3, 4')),
        );
        $checked = TableConverger::preflight($inspector, 'tags', $target);
        $this->assertSame(
            array(
                'tags: the run adds the unique key name, and rows share a value of it: "tlp:red" in rows id 5, 8. Merge or rename those rows, then run the update again.',
                'tags: the run adds the unique key uuid, and rows share a value of it: "c99c4e4e-0000-4000-8000-000000000001" in rows id 3, 4. Those rows stand for the same thing: keep one of them and delete the others, then run the update again.',
                'tags: the run adds the unique key org_uuid, and rows share a value of it: ("1", "c99c4e4e-0000-4000-8000-000000000001") in rows id 3, 4. Those rows stand for the same thing: keep one of them and delete the others, then run the update again.',
            ),
            $checked['defer']
        );
    }

    /**
     * A column the run adds holds one value in every row, so a unique key
     * over it alone holds only for a table of one row.
     */
    public function testAUniqueKeyOverAnAddedColumn()
    {
        $target = self::TAGS;
        $target['indexes']['org_only'] = array('column' => array('org_id'), 'unique' => true);
        $live = TableConvergerTest::mysqlLive(self::TAGS);
        unset($live['columns']['org_id'], $live['indexes']['org_name']);
        $inspector = $this->mysqlInspector('tags', $live);
        $inspector->probes = array('/HAVING/' => array(array('n' => '3', 'ids' => '1, 2, 3')));
        $checked = TableConverger::preflight($inspector, 'tags', $target);
        // (org_id, name) is implied by the unique name; org_id alone is not.
        $this->assertSame(
            array("SELECT COUNT(*) AS n, GROUP_CONCAT(`id` ORDER BY `id` SEPARATOR ', ') AS ids FROM `tags` HAVING COUNT(*) > 1 LIMIT 10;"),
            $inspector->asked
        );
        $this->assertSame(
            array('tags: the run adds the unique key org_only, and rows share a value of it: the value the run gives every row in rows id 1, 2, 3. Merge or rename those rows, then run the update again.'),
            $checked['defer']
        );
    }

    public function testPostgresReadsTheKeyOfAnIndexWithItsOwnStatement()
    {
        $live = TableConvergerTest::pgsqlLive('tags', self::TAGS);
        unset($live['indexes']['idx_tags_name_lower']);
        $inspector = $this->pgsqlInspector('tags', $live);
        TableConverger::preflight($inspector, 'tags', self::TAGS);
        $this->assertSame(
            array(
                'SELECT lower("name") AS "k0", COUNT(*) AS n, string_agg("id"::text, \', \' ORDER BY "id") AS ids FROM "tags"'
                    . ' WHERE lower("name") IS NOT NULL GROUP BY lower("name") HAVING COUNT(*) > 1 LIMIT 10;',
            ),
            $inspector->asked
        );
    }

    // ------------------------------------------------------------ additions

    /**
     * PostgreSQL gets the value MySQL fills a NOT NULL column with, as a
     * default it drops again; a temporal column has none, so a table with
     * rows defers.
     */
    public function testNotNullAdditionsWithoutADefault()
    {
        $live = TableConvergerTest::pgsqlLive('tags', self::TAGS);
        unset($live['columns']['exportable']);
        $schema = new SchemaBuilder(AbstractGrammar::forDataSource(new MigrationTestPostgres()));
        TableConverger::converge($this->pgsqlInspector('tags', $live), $schema, 'tags', self::TAGS);
        $this->assertSame(
            array(
                'ALTER TABLE "tags" ADD "exportable" boolean DEFAULT \'FALSE\' NOT NULL;',
                "ALTER TABLE \"tags\"\n"
                    . "    ALTER COLUMN \"exportable\" DROP DEFAULT,\n"
                    . "    ALTER COLUMN \"exportable\" TYPE boolean USING \"exportable\"::boolean,\n"
                    . "    ALTER COLUMN \"exportable\" SET NOT NULL;",
            ),
            $schema->toSql()
        );

        $target = self::TAGS;
        $target['columns']['seen'] = array('type' => 'datetime', 'null' => false);
        foreach (array('pgsql', 'mysql') as $engine) {
            if ($engine === 'pgsql') {
                $inspector = $this->pgsqlInspector('tags', TableConvergerTest::pgsqlLive('tags', self::TAGS));
            } else {
                $inspector = $this->mysqlInspector('tags', TableConvergerTest::mysqlLive(self::TAGS, self::MYSQL));
                $inspector->version = self::MYSQL;
                $inspector->variables['sql_mode'] = 'ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE';
            }
            $inspector->probes = array('/LIMIT 1;/' => array(array('present' => '1')));
            $this->assertSame(
                array('tags: seen is missing, NOT NULL without a default, and the table has rows, which this server has no value to fill with. Add it by hand with a value for the existing rows, then run the update again.'),
                TableConverger::preflight($inspector, 'tags', $target)['defer'],
                $engine
            );
        }
        // A bytea gets the empty value too.
        $target = self::TAGS;
        $target['columns']['hash'] = array('type' => 'varbinary', 'length' => 32, 'null' => false);
        $inspector = $this->pgsqlInspector('tags', TableConvergerTest::pgsqlLive('tags', self::TAGS));
        $inspector->probes = array('/LIMIT 1;/' => array(array('present' => '1')));
        $checked = TableConverger::preflight($inspector, 'tags', $target);
        $this->assertSame(array(), $checked['defer']);
        $schema = new SchemaBuilder(AbstractGrammar::forDataSource(new MigrationTestPostgres()));
        TableConverger::emit($schema, $checked['plan']);
        $this->assertSame('ALTER TABLE "tags" ADD "hash" bytea DEFAULT \'\' NOT NULL;', $schema->toSql()[0]);
        $this->assertSame(array(), $inspector->asked);

        // MariaDB's default sql_mode takes the zero date.
        $target['columns']['seen'] = array('type' => 'datetime', 'null' => false);
        unset($target['columns']['hash']);
        $inspector = $this->mysqlInspector('tags', TableConvergerTest::mysqlLive(self::TAGS));
        $this->assertSame(array(), TableConverger::preflight($inspector, 'tags', $target)['defer']);
        $this->assertSame(array(), $inspector->asked);
    }

    public function testAnExtensionTheUserCannotCreateDefers()
    {
        $live = TableConvergerTest::pgsqlLive('events', self::TARGET);
        unset($live['indexes']['idx_events_info_search']);
        $inspector = $this->pgsqlInspector('events', $live);
        $inspector->probes = array('/pg_extension/' => array(array(
            'installed' => '0', 'available' => '1', 'trusted' => true, 'can_create' => false, 'superuser' => false, 'database_name' => 'misp',
        )));
        $checked = TableConverger::preflight($inspector, 'events', self::TARGET);
        $this->assertSame(
            array('events: the index info_search needs the PostgreSQL extension pg_trgm, which this database user cannot create. Have a superuser run CREATE EXTENSION pg_trgm; in the database misp, then run the update again.'),
            $checked['defer']
        );

        $inspector->probes = array('/pg_extension/' => array(array(
            'installed' => '0', 'available' => '1', 'trusted' => 't', 'can_create' => 't', 'superuser' => 'f', 'database_name' => 'misp',
        )));
        $checked = TableConverger::preflight($inspector, 'events', self::TARGET);
        $this->assertSame(array(), $checked['defer']);
        $this->assertContains('events: creates the PostgreSQL extension pg_trgm for info_search', $checked['plan']['notes']);
    }

    // ------------------------------------------------------------------ space

    /**
     * The new copy is the data, grown by the wider ids, plus the indexes the
     * target has, scaled from what the live ones take.
     */
    public function testTheRebuildNeedsRoomForTheNewCopy()
    {
        $live = TableConvergerTest::mysqlLive(self::TARGET);
        $live['columns']['id'] = TableConvergerTest::mysqlColumn('int(11)', array('increment' => 'auto_increment'));
        $live['columns']['org_id'] = TableConvergerTest::mysqlColumn('int(11)');
        $gb = 1073741824;
        $sizes = array('events' => array('data_in_bytes' => 10 * $gb, 'index_in_bytes' => 4 * $gb, 'row_estimate' => 100000000));

        $inspector = $this->mysqlInspector('events', $live);
        $inspector->sizes = $sizes;
        $inspector->storage = array(
            'datadir' => array('path' => '/var/lib/mysql/', 'free' => 12.0 * $gb, 'device' => 1),
            'tmpdir' => array('path' => '/tmp', 'free' => 20.0 * $gb, 'device' => 2),
        );
        $checked = TableConverger::preflight($inspector, 'events', self::TARGET);
        // 10 GB + 10^8 x 8 B of wider ids + 4 GB x (the entries with 8-byte keys / with 4-byte ones).
        $this->assertCount(1, $checked['defer']);
        $this->assertRegExp(
            '/^events: the rebuild \(a new copy of the table beside the old one\) needs about 15\.\d GB free in \/var\/lib\/mysql\/, and 12\.0 GB is free\. Free up space there, then run the update again\.$/',
            $checked['defer'][0]
        );

        $inspector->storage['datadir']['free'] = 18.0 * $gb;
        $checked = TableConverger::preflight($inspector, 'events', self::TARGET);
        $this->assertSame(array(), $checked['defer']);
        $this->assertStringContainsString('events: the rebuild (a new copy of the table beside the old one) needs about 15.', implode("\n", $checked['plan']['notes']));
        $this->assertStringContainsString('and 18.0 GB is free: close to the estimate', implode("\n", $checked['plan']['notes']));

        $inspector->storage = null;
        $checked = TableConverger::preflight($inspector, 'events', self::TARGET);
        $this->assertStringContainsString("events: free disk not checked, as the database server's directories cannot be read from here", implode("\n", $checked['plan']['notes']));
    }

    /**
     * MariaDB's copy sorts the new indexes in tmpdir, 1.5 x their size; MySQL's
     * copy writes no sort files.
     */
    public function testACopyRebuildOnMariaDbNeedsRoomInTmpdir()
    {
        $live = TableConvergerTest::mysqlLive(self::TARGET);
        $live['columns']['id'] = TableConvergerTest::mysqlColumn('int(11)', array('increment' => 'auto_increment'));
        $live['columns']['org_id'] = TableConvergerTest::mysqlColumn('int(11)');
        $gb = 1073741824;
        $inspector = $this->mysqlInspector('events', $live);
        $inspector->sizes = array('events' => array('data_in_bytes' => 10 * $gb, 'index_in_bytes' => 4 * $gb, 'row_estimate' => 100000000));
        $inspector->storage = array(
            'datadir' => array('path' => '/var/lib/mysql/', 'free' => 100.0 * $gb, 'device' => 1),
            'tmpdir' => array('path' => '/tmp', 'free' => 1.0 * $gb, 'device' => 2),
        );
        $checked = TableConverger::preflight($inspector, 'events', self::TARGET);
        $this->assertCount(1, $checked['defer']);
        $this->assertRegExp(
            "/^events: the rebuild's index sort files needs about [5-9]\\.\\d GB free in \\/tmp, and 1\\.0 GB is free\\./",
            $checked['defer'][0]
        );

        $inspector->storage['tmpdir']['device'] = 1;
        $inspector->storage['datadir']['free'] = 20.0 * $gb;
        $checked = TableConverger::preflight($inspector, 'events', self::TARGET);
        $this->assertCount(1, $checked['defer']);
        $this->assertStringStartsWith('events: the rebuild (a new copy of the table beside the old one) needs about 2', $checked['defer'][0]);

        $inspector->version = '8.4.6';
        $inspector->storage['tmpdir']['device'] = 2;
        $this->assertSame(array(), TableConverger::preflight($inspector, 'events', self::TARGET)['defer']);
    }

    /**
     * Indexes built in place sort in tmpdir; on one filesystem both count.
     */
    public function testNewIndexesNeedRoomWhereTheyAreSorted()
    {
        $live = TableConvergerTest::mysqlLive(self::TARGET);
        unset($live['indexes']['idx_evt_acl']);
        $gb = 1073741824;
        $inspector = $this->mysqlInspector('events', $live);
        $inspector->sizes = array('events' => array('data_in_bytes' => 10 * $gb, 'index_in_bytes' => 4 * $gb, 'row_estimate' => 100000000));
        $inspector->storage = array(
            'datadir' => array('path' => '/var/lib/mysql/', 'free' => 100.0 * $gb, 'device' => 1),
            'tmpdir' => array('path' => '/tmp', 'free' => 0.5 * $gb, 'device' => 2),
        );
        $checked = TableConverger::preflight($inspector, 'events', self::TARGET);
        $this->assertCount(1, $checked['defer']);
        $this->assertStringStartsWith('events: building the new indexes needs about ', $checked['defer'][0]);
        $this->assertStringContainsString(' free in /tmp, and 512.0 MB is free.', $checked['defer'][0]);

        $inspector->storage['tmpdir']['device'] = 1;
        $this->assertSame(array(), TableConverger::preflight($inspector, 'events', self::TARGET)['defer']);
    }

    // ------------------------------------------------------------- migration

    public function testADeferringPreflightLeavesTheMigrationPending()
    {
        $id = '20261101_000000_converge_events';
        $live = TableConvergerTest::mysqlLive(self::TARGET);
        $live['columns']['info']['null'] = true;
        $manager = new StatementRecordingMigrationManager(array('Migration_' . $id . '.php'));
        $manager->liveSchema = $this->mysqlInspector('events', $live);
        $manager->liveSchema->probes = array('/^SELECT SUM/' => array(array('n0' => '4')));

        $this->assertFalse($manager->apply($id));
        $this->assertSame(MigrationManager::STATUS_DEFERRED, $manager->lastStatus());
        $this->assertSame(MigrationManager::STATUS_DEFERRED, $manager->rows[$id]['status']);
        $this->assertSame(array($id), array_keys($manager->pending()));
        $this->assertSame(array(), $manager->ran);

        $manager->liveSchema->probes = array();
        $this->assertTrue($manager->apply($id));
        $this->assertSame(
            array(
                'SET SESSION alter_algorithm = \'DEFAULT\';',
                'SET SESSION lock_wait_timeout = 300;',
                'ALTER TABLE `events` MODIFY `info` text CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci NOT NULL;',
                'SET SESSION lock_wait_timeout = DEFAULT;',
            ),
            $manager->ran
        );
    }

    /**
     * An ALTER an interrupted run left on the server: wait for it or end it,
     * rather than queue behind its lock with a plan made against the old table.
     */
    public function testAnotherConnectionChangingTheTableDefers()
    {
        $id = '20261101_000000_converge_events';
        $live = TableConvergerTest::mysqlLive(self::TARGET);
        $live['columns']['info']['null'] = true;
        $manager = new StatementRecordingMigrationManager(array('Migration_' . $id . '.php'));
        $manager->liveSchema = $this->mysqlInspector('events', $live);
        $manager->liveSchema->ddl = array('events' => array(array('id' => 9, 'seconds' => 84, 'progress' => 'stage 1 of 2, 41.2 %')));

        $this->assertFalse($manager->apply($id));
        $this->assertSame(MigrationManager::STATUS_DEFERRED, $manager->rows[$id]['status']);
        $this->assertSame(
            'events: connection 9 has been changing this table for 84 s (stage 1 of 2, 41.2 %), most likely the statement of an interrupted run, which the database server carries on with. Wait until it is gone from SHOW PROCESSLIST, or end it with KILL 9 to start the table over, then run Console/cake Admin runUpgrade again.',
            $manager->rows[$id]['error']
        );
        $this->assertSame(array(), $manager->ran);

        $manager->liveSchema->ddl = array();
        $this->assertTrue($manager->apply($id));
    }

    public function testAnotherConnectionChangingTheTableIsNamedForPostgres()
    {
        $line = TableMigration::alteredElsewhere('events', array('id' => 4242, 'seconds' => 7, 'progress' => null), SchemaInspector::FLAVOUR_PGSQL);
        $this->assertStringStartsWith('events: connection 4242 has been changing this table for 7 s, most likely', $line);
        $this->assertStringContainsString('gone from pg_stat_activity, or end it with SELECT pg_cancel_backend(4242) to start', $line);
    }

    public function testTheForecastNamesTheWorkAndTheBusySessions()
    {
        $id = '20261101_000000_converge_events';
        $live = TableConvergerTest::mysqlLive(self::TARGET);
        $live['columns']['org_id'] = TableConvergerTest::mysqlColumn('int(11)');
        $inspector = $this->mysqlInspector('events', $live);
        $inspector->sizes = array('events' => array(
            'table' => 'events', 'data_in_bytes' => 1073741824, 'index_in_bytes' => 0,
            'total_in_bytes' => 1073741824, 'reclaimable_in_bytes' => 0, 'row_estimate' => 2000000,
        ));
        $inspector->sessions = array(array('id' => 7, 'user' => 'misp', 'command' => 'Query', 'seconds' => 3, 'state' => ''));
        $manager = new ReportingStatementManager(array('Migration_' . $id . '.php'));
        $manager->liveSchema = $inspector;
        $manager->setReporter(array($manager, 'collect'));

        $this->assertTrue($manager->apply($id), (string)$manager->lastError());
        $events = array_column($manager->reported, 0);
        $this->assertSame(array('start', 'forecast', 'applied'), $events);
        $forecast = $manager->reported[1][2];
        $this->assertRegExp('/about 2000000 rows, 1\.0 GB/', $forecast[0]);
        $this->assertRegExp('/SHOW FULL PROCESSLIST/', $forecast[1]);
        $this->assertRegExp('/1 other session\(s\)/', $forecast[2]);
    }
    // ---------------------------------------------------------------- helpers

    private function mysqlInspector($table, array $definition)
    {
        $inspector = new MigrationTestInspector(SchemaInspector::FLAVOUR_MYSQL, array($table => array('definition' => $definition)));
        $inspector->version = self::MARIADB;
        return $inspector;
    }

    private function pgsqlInspector($table, array $definition)
    {
        $inspector = new MigrationTestInspector(SchemaInspector::FLAVOUR_PGSQL, array($table => array('definition' => $definition)));
        $inspector->version = '16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)';
        return $inspector;
    }
}
