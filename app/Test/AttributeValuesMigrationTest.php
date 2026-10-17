<?php
/**
 * The attribute-values migrations that create or empty a table do so at its
 * 3.0 target, read from the table's schema v3 migration, so that migration
 * finds nothing left to do. The value id columns arrive in their target form
 * and without indexes, which the schema v3 rebuild of their table builds.
 * These render every server's version, without a database.
 */

require_once __DIR__ . '/TableConvergerTest.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20260930_131928_warninglist_entries_list_value_index.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261003_092429_create_attribute_values.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261004_093106_create_value_ip_ranges.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261004_093749_attribute_value_ids.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261009_034014_value_keyed_correlation_counts.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261009_074646_value_group_correlations.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261013_070812_attributes_event_deleted_object.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261013_154619_objects_event_deleted_name.php';

use PHPUnit\Framework\TestCase;

class AttributeValuesMigrationTest extends TestCase
{
    const MIGRATION = 'Migration_20261003_092429_create_attribute_values';

    const VALUE_IDS = 'Migration_20261004_093749_attribute_value_ids';

    /** migration => the tables it creates or empties, in its order */
    const CREATED = array(
        'Migration_20261003_092429_create_attribute_values' => array('attribute_values'),
        'Migration_20261004_093106_create_value_ip_ranges' => array('value_ip_ranges'),
        'Migration_20261009_034014_value_keyed_correlation_counts' => array('over_correlating_values', 'attr_value_counts'),
        'Migration_20261009_074646_value_group_correlations' => array('default_correlations', 'no_acl_correlations'),
    );

    /** table => the schema v3 migration holding its target */
    const TARGETS = array(
        'attribute_values' => 'Migration_20261016_180337_schema_v3_attribute_values',
        'value_ip_ranges' => 'Migration_20261016_180329_schema_v3_value_ip_ranges',
        'over_correlating_values' => 'Migration_20261016_180204_schema_v3_over_correlating_values',
        'attr_value_counts' => 'Migration_20261016_180332_schema_v3_attr_value_counts',
        'default_correlations' => 'Migration_20261016_180202_schema_v3_default_correlations',
        'no_acl_correlations' => 'Migration_20261016_180203_schema_v3_no_acl_correlations',
    );

    /** Their index comes with their table's target. */
    const INDEX_ONLY = array(
        'Migration_20260930_131928_warninglist_entries_list_value_index',
        'Migration_20261013_070812_attributes_event_deleted_object',
        'Migration_20261013_154619_objects_event_deleted_name',
    );

    /**
     * @param string $class
     * @param SchemaInspector $inspector
     * @param DboSource $db
     * @return array
     */
    private function render($class, SchemaInspector $inspector, DboSource $db)
    {
        $migration = new $class();
        $migration->setSchemaInspector($inspector);
        $schema = new SchemaBuilder(AbstractGrammar::forDataSource($db));
        $migration->up($schema);
        return $schema->toSql();
    }

    /**
     * @param string $version
     * @param array $schema
     * @return MigrationTestInspector
     */
    private static function mysqlInspector($version, array $schema = array())
    {
        $inspector = new MigrationTestInspector(SchemaInspector::FLAVOUR_MYSQL, $schema);
        $inspector->version = $version;
        return $inspector;
    }

    /**
     * @param string $table
     * @return array
     */
    private static function target($table)
    {
        $class = self::TARGETS[$table];
        return $class::TARGET;
    }

    public static function supportedServers()
    {
        return array(
            'MariaDB 10.11 (Ubuntu 24.04)' => array('10.11.14-MariaDB-0ubuntu0.24.04.1', 'utf8mb4_uca1400_ai_ci', 'bigint(20)'),
            'MariaDB 11.4' => array('11.4.3-MariaDB-log', 'utf8mb4_uca1400_ai_ci', 'bigint(20)'),
            'MySQL 8.4' => array('8.4.6', 'utf8mb4_unicode_520_ci', 'bigint'),
            'MySQL 9.1' => array('9.1.0', 'utf8mb4_unicode_520_ci', 'bigint'),
        );
    }

    /**
     * @dataProvider supportedServers
     */
    public function testTheMysqlRenderingCarriesTheServersCollation($version, $collation, $key)
    {
        $algorithm = stripos($version, 'mariadb') !== false
            ? "SET SESSION alter_algorithm = 'DEFAULT';"
            : 'SET SESSION old_alter_table = OFF;';
        $this->assertSame(array(
            $algorithm,
            'SET SESSION lock_wait_timeout = 300;',
            'SET SESSION innodb_ft_enable_stopword = 0;',
            "CREATE TABLE `attribute_values` (\n" .
            "    `id` $key NOT NULL AUTO_INCREMENT,\n" .
            "    `value` text CHARACTER SET utf8mb4 COLLATE $collation NOT NULL,\n" .
            "    `hash` varbinary(32) NOT NULL,\n" .
            "    PRIMARY KEY (`id`)\n" .
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=$collation ROW_FORMAT=DYNAMIC;",
            "ALTER TABLE `attribute_values`\n" .
            "    ADD UNIQUE INDEX `hash` (`hash`),\n" .
            "    ADD INDEX `value` (`value`(128)),\n" .
            "    ADD FULLTEXT INDEX `value_search` (`value`);",
            'SET SESSION innodb_ft_enable_stopword = DEFAULT;',
            'SET SESSION lock_wait_timeout = DEFAULT;',
        ), $this->render(self::MIGRATION, self::mysqlInspector($version), new MigrationTestMysqlExtended($version)));
    }

    public static function unsupportedServers()
    {
        return array(
            'MariaDB 10.10' => array('10.10.7-MariaDB'),
            'MariaDB 10.5 (RHEL 9)' => array('10.5.22-MariaDB'),
            'MySQL 8.0 (Ubuntu 24.04)' => array('8.0.43-0ubuntu0.24.04.2'),
            'MySQL 5.7' => array('5.7.44-log'),
        );
    }

    /**
     * @dataProvider unsupportedServers
     */
    public function testAnUnsupportedServerDefersTheCreate($version)
    {
        $this->expectException('MigrationDeferredException');
        $this->expectExceptionMessage('MISP 3.0 needs MariaDB 10.11 or later, or MySQL 8.4 or later.');
        $this->render(self::MIGRATION, self::mysqlInspector($version), new MigrationTestMysqlExtended($version));
    }

    public function testThePostgresRendering()
    {
        $this->assertSame(array(
            "CREATE TABLE \"attribute_values\" (\n" .
            "    \"id\" bigint GENERATED BY DEFAULT AS IDENTITY,\n" .
            "    \"value\" text NOT NULL,\n" .
            "    \"hash\" bytea NOT NULL,\n" .
            "    PRIMARY KEY (\"id\")\n" .
            ");",
            'CREATE UNIQUE INDEX "idx_attribute_values_hash" ON "attribute_values" ("hash");',
            'CREATE INDEX "idx_attribute_values_value" ON "attribute_values" (lower(left("value", 128)));',
            'CREATE EXTENSION IF NOT EXISTS pg_trgm;',
            'CREATE INDEX "idx_attribute_values_value_search" ON "attribute_values" USING gin ("value" gin_trgm_ops);',
        ), $this->render(self::MIGRATION, new MigrationTestInspector(SchemaInspector::FLAVOUR_PGSQL), new MigrationTestPostgres()));
    }

    /**
     * Where the table is missing, each migration declares exactly the
     * creation of its schema v3 target.
     */
    public function testEachTableIsCreatedAtItsSchemaV3Target()
    {
        $version = TableConvergerTest::MARIADB;
        $session = TableConverger::session(self::mysqlInspector($version));
        foreach (self::CREATED as $class => $tables) {
            $expected = new SchemaBuilder(AbstractGrammar::forDataSource(new MigrationTestMysqlExtended($version)));
            foreach ($tables as $table) {
                TableConverger::converge(new MigrationTestInspector(), $expected, $table, self::target($table), $session);
            }
            $this->assertSame(
                $expected->toSql(),
                $this->render($class, self::mysqlInspector($version), new MigrationTestMysqlExtended($version)),
                $class
            );
        }
    }

    /**
     * So a retry, or a database that ran the migration once, declares nothing,
     * and neither does the table's schema v3 migration afterwards.
     */
    public function testATableAtItsTargetIsLeftAlone()
    {
        foreach (self::CREATED as $class => $tables) {
            foreach (array(TableConvergerTest::MARIADB, TableConvergerTest::MYSQL) as $version) {
                $schema = array();
                foreach ($tables as $table) {
                    $schema[$table] = array('definition' => TableConvergerTest::mysqlLive(self::target($table), $version));
                }
                $inspector = self::mysqlInspector($version, $schema);
                $this->assertSame(array(), $this->render($class, $inspector, new MigrationTestMysqlExtended($version)), "$class on $version");
            }
            $schema = array();
            foreach ($tables as $table) {
                $schema[$table] = array('definition' => TableConvergerTest::pgsqlLive($table, self::target($table)));
            }
            $inspector = new MigrationTestInspector(SchemaInspector::FLAVOUR_PGSQL, $schema);
            $this->assertSame(array(), $this->render($class, $inspector, new MigrationTestPostgres()), "$class on PostgreSQL");
        }
    }

    /**
     * A 2.x correlation or count table is dropped and created anew, never
     * converted row by row.
     */
    public function testAnOlderTableIsEmptiedAndCreatedAtItsTarget()
    {
        foreach (array_slice(self::CREATED, 2) as $class => $tables) {
            $schema = array();
            foreach ($tables as $table) {
                $old = self::target($table);
                $old['columns']['value_id'] = array('type' => 'integer', 'unsigned' => true, 'null' => false);
                $schema[$table] = array('definition' => TableConvergerTest::mysqlLive($old));
            }
            $sql = $this->render(
                $class,
                self::mysqlInspector(TableConvergerTest::MARIADB, $schema),
                new MigrationTestMysqlExtended(TableConvergerTest::MARIADB)
            );
            foreach ($tables as $table) {
                $drop = array_search("DROP TABLE `$table`;", $sql, true);
                $this->assertNotFalse($drop, "$class: $table");
                $this->assertStringStartsWith("CREATE TABLE `$table` (", $sql[$drop + 1]);
            }
            $this->assertEmpty(preg_grep('/\bMODIFY\b/', $sql), $class);
        }
    }

    public function testARetryAddsWhatIsMissing()
    {
        $partial = self::target('attribute_values');
        unset($partial['indexes']['value_search']);
        $inspector = self::mysqlInspector(TableConvergerTest::MARIADB, array(
            'attribute_values' => array('definition' => TableConvergerTest::mysqlLive($partial)),
        ));
        $this->assertSame(array(
            "SET SESSION alter_algorithm = 'DEFAULT';",
            'SET SESSION lock_wait_timeout = 300;',
            'SET SESSION innodb_ft_enable_stopword = 0;',
            'ALTER TABLE `attribute_values` ADD FULLTEXT INDEX `value_search` (`value`);',
            'SET SESSION innodb_ft_enable_stopword = DEFAULT;',
            'SET SESSION lock_wait_timeout = DEFAULT;',
        ), $this->render(self::MIGRATION, $inspector, new MigrationTestMysqlExtended(TableConvergerTest::MARIADB)));
    }

    public function testPgTrgmPrecheck()
    {
        $class = self::MIGRATION;
        $this->assertNull($class::pgTrgmProblem(true, true, false));
        $this->assertNull($class::pgTrgmProblem(false, true, true));
        $this->assertStringContainsString('postgresql-contrib', $class::pgTrgmProblem(false, false, true));
        $this->assertStringContainsString('GRANT CREATE ON DATABASE', $class::pgTrgmProblem(false, true, false));
    }

    public function testBeforeUpDoesNothingOnMysql()
    {
        $class = self::MIGRATION;
        $migration = new $class();
        $migration->setSchemaInspector(new MigrationTestInspector());
        $this->assertTrue($migration->beforeUp());
    }

    /**
     * Signed, as the targets have them, and no index: the schema v3 rebuild
     * of each table builds those.
     */
    public function testTheValueIdsRendering()
    {
        $schema = array(
            'attributes' => array('columns' => array('id', 'value1', 'value2', 'timestamp')),
            'shadow_attributes' => array('columns' => array('id', 'value1', 'value2')),
        );
        $this->assertSame(array(
            'ALTER TABLE `attributes` ADD `value1_id` bigint(20) DEFAULT NULL AFTER `value2`;',
            "ALTER TABLE `attributes`\n" .
            "    ADD `value2_id` bigint(20) DEFAULT NULL AFTER `value1_id`,\n" .
            "    ADD `created` bigint(20) DEFAULT 0 NOT NULL AFTER `timestamp`;",
            'ALTER TABLE `shadow_attributes` ADD `value1_id` bigint(20) DEFAULT NULL AFTER `value2`;',
            'ALTER TABLE `shadow_attributes` ADD `value2_id` bigint(20) DEFAULT NULL AFTER `value1_id`;',
        ), $this->render(
            self::VALUE_IDS,
            new MigrationTestInspector(SchemaInspector::FLAVOUR_MYSQL, $schema),
            new MigrationTestMysqlExtended()
        ));
        $this->assertSame(array(
            'ALTER TABLE "attributes" ADD "value1_id" bigint DEFAULT NULL;',
            "ALTER TABLE \"attributes\"\n    ADD \"value2_id\" bigint DEFAULT NULL,\n    ADD \"created\" bigint DEFAULT 0 NOT NULL;",
            'ALTER TABLE "shadow_attributes" ADD "value1_id" bigint DEFAULT NULL;',
            'ALTER TABLE "shadow_attributes" ADD "value2_id" bigint DEFAULT NULL;',
        ), $this->render(
            self::VALUE_IDS,
            new MigrationTestInspector(SchemaInspector::FLAVOUR_PGSQL, $schema),
            new MigrationTestPostgres()
        ));
    }

    public function testAValueIdsRetryDeclaresOnlyWhatIsMissing()
    {
        $schema = array(
            'attributes' => array('columns' => array('id', 'value1', 'value2', 'value1_id', 'value2_id', 'timestamp')),
            'shadow_attributes' => array('columns' => array('id', 'value1', 'value2', 'value1_id')),
        );
        $this->assertSame(array(
            'ALTER TABLE `attributes` ADD `created` bigint(20) DEFAULT 0 NOT NULL AFTER `timestamp`;',
            'ALTER TABLE `shadow_attributes` ADD `value2_id` bigint(20) DEFAULT NULL AFTER `value1_id`;',
        ), $this->render(
            self::VALUE_IDS,
            new MigrationTestInspector(SchemaInspector::FLAVOUR_MYSQL, $schema),
            new MigrationTestMysqlExtended()
        ));

        $schema['attributes']['columns'][] = 'created';
        $schema['shadow_attributes']['columns'][] = 'value2_id';
        $this->assertSame(array(), $this->render(
            self::VALUE_IDS,
            new MigrationTestInspector(SchemaInspector::FLAVOUR_MYSQL, $schema),
            new MigrationTestMysqlExtended()
        ));
    }

    public function testTheIndexOnlyMigrationsDeclareNothing()
    {
        foreach (self::INDEX_ONLY as $class) {
            $this->assertSame(array(), $this->render($class, new MigrationTestInspector(), new MigrationTestMysqlExtended()), $class);
            $this->assertSame(
                array(),
                $this->render($class, new MigrationTestInspector(SchemaInspector::FLAVOUR_PGSQL), new MigrationTestPostgres()),
                $class
            );
        }
    }
}
