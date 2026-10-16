<?php
/**
 * The attribute_values collation follows the server it is rendered for, so
 * a dry run only ever shows one server's. These render all
 * of them, the PostgreSQL half, and the value table migrations' retries,
 * without a database.
 */

require_once __DIR__ . '/MigrationSchemaStubs.php';
require_once APPLIBS . 'Migration/AbstractMigration.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261003_092429_create_attribute_values.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261004_093106_create_value_ip_ranges.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261004_093749_attribute_value_ids.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261010_172929_value_search_without_stopwords.php';

use PHPUnit\Framework\TestCase;

if (!class_exists('AttributeValuesMigrationTestInspector', false)) {
    class AttributeValuesMigrationTestInspector extends SchemaInspector
    {
        /** @var array table => index name => array('column' => ..., 'unique' => ...) */
        public $existing = array();

        /** @var array table => column names */
        public $columns = array();

        public function hasTable($table)
        {
            return isset($this->existing[$table]);
        }

        public function hasColumn($table, $column)
        {
            return isset($this->columns[$table]) && in_array($column, $this->columns[$table], true);
        }

        public function indexes($table)
        {
            if (!isset($this->existing[$table])) {
                return array();
            }
            return $this->existing[$table];
        }
    }
}

class AttributeValuesMigrationTest extends TestCase
{
    const MIGRATION = 'Migration_20261003_092429_create_attribute_values';

    const IP_RANGES = 'Migration_20261004_093106_create_value_ip_ranges';

    const VALUE_IDS = 'Migration_20261004_093749_attribute_value_ids';

    /**
     * @param DboSource $db
     * @param array $existing
     * @param string $class
     * @return array
     */
    private function render(DboSource $db, array $existing = array(), $class = self::MIGRATION, array $columns = array())
    {
        $inspector = new AttributeValuesMigrationTestInspector($db);
        $inspector->existing = $existing;
        $inspector->columns = $columns;
        $migration = new $class();
        $migration->setSchemaInspector($inspector);
        $schema = new SchemaBuilder(AbstractGrammar::forDataSource($db));
        $migration->up($schema);
        return $schema->toSql();
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
        $this->assertSame(array(
            "CREATE TABLE `attribute_values` (\n" .
            "    `id` $key UNSIGNED NOT NULL AUTO_INCREMENT,\n" .
            "    `value` text CHARACTER SET utf8mb4 COLLATE $collation NOT NULL,\n" .
            "    `hash` varbinary(32) NOT NULL,\n" .
            "    PRIMARY KEY (`id`),\n" .
            "    UNIQUE INDEX `hash` (`hash`)\n" .
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=$collation;",
            'ALTER TABLE `attribute_values` ADD INDEX `value` (`value`(128));',
            'ALTER TABLE `attribute_values` ADD FULLTEXT INDEX `value_search` (`value`);',
        ), $this->render(new MigrationTestMysqlExtended($version)));
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
        $this->render(new MigrationTestMysqlExtended($version));
    }

    /**
     * Only the create carries a collation, so a retry that adds a missing
     * index never asks which server it is on.
     */
    public function testARetryRendersOnAnyServer()
    {
        $this->assertSame(
            array('ALTER TABLE `attribute_values` ADD FULLTEXT INDEX `value_search` (`value`);'),
            $this->render(new MigrationTestMysqlExtended('10.5.22-MariaDB'), array(
                'attribute_values' => self::indexes(array('PRIMARY', 'hash', 'value')),
            ))
        );
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
        ), $this->render(new MigrationTestPostgres()));
    }

    public function testARetryDeclaresOnlyWhatIsMissing()
    {
        $this->assertSame(
            array('ALTER TABLE `attribute_values` ADD FULLTEXT INDEX `value_search` (`value`);'),
            $this->render(new MigrationTestMysqlExtended(), array(
                'attribute_values' => self::indexes(array('PRIMARY', 'hash', 'value')),
            ))
        );
        $this->assertSame(array(), $this->render(new MigrationTestMysqlExtended(), array(
            'attribute_values' => self::indexes(array('PRIMARY', 'hash', 'value', 'value_search')),
        )));
        $this->assertSame(array(), $this->render(new MigrationTestPostgres(), array(
            'attribute_values' => self::indexes(array(
                'PRIMARY',
                'idx_attribute_values_hash',
                'idx_attribute_values_value',
                'idx_attribute_values_value_search',
            )),
        )));
    }

    public function testTheSearchIndexIsRebuiltWithoutStopwords()
    {
        $class = 'Migration_20261010_172929_value_search_without_stopwords';
        $existing = array('attribute_values' => self::indexes(array('PRIMARY', 'hash', 'value', 'value_search')));

        $this->assertSame(array(
            'SET SESSION innodb_ft_enable_stopword = 0;',
            'ALTER TABLE `attribute_values` FORCE;',
            'SET SESSION innodb_ft_enable_stopword = DEFAULT;',
        ), $this->render(new MigrationTestMysqlExtended(), $existing, $class));
        $this->assertSame(array(
            'SET SESSION innodb_ft_enable_stopword = 0;',
            'ALTER TABLE `attribute_values` ADD FULLTEXT INDEX `value_search` (`value`);',
            'SET SESSION innodb_ft_enable_stopword = DEFAULT;',
        ), $this->render(new MigrationTestMysqlExtended(), array(
            'attribute_values' => self::indexes(array('PRIMARY', 'hash', 'value')),
        ), $class));
        $this->assertSame(array(), $this->render(new MigrationTestPostgres(), $existing, $class));
    }

    /**
     * @param array $names
     * @return array Index definitions the migrations only look up by name.
     */
    private static function indexes(array $names)
    {
        return array_fill_keys($names, array('column' => 'value', 'unique' => 0));
    }

    public function testTheIpRangesRendering()
    {
        $this->assertSame(array(
            "CREATE TABLE `value_ip_ranges` (\n" .
            "    `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,\n" .
            "    `value_id` bigint(20) UNSIGNED NOT NULL,\n" .
            "    `ip_start` varbinary(16) NOT NULL,\n" .
            "    `ip_end` varbinary(16) NOT NULL,\n" .
            "    `prefix` tinyint(4) UNSIGNED NOT NULL,\n" .
            "    PRIMARY KEY (`id`),\n" .
            "    UNIQUE INDEX `value_id` (`value_id`),\n" .
            "    INDEX `start_end` (`ip_start`, `ip_end`, `value_id`)\n" .
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
        ), $this->render(new MigrationTestMysqlExtended(), array(), self::IP_RANGES));
        $this->assertSame(array(
            "CREATE TABLE \"value_ip_ranges\" (\n" .
            "    \"id\" bigint GENERATED BY DEFAULT AS IDENTITY,\n" .
            "    \"value_id\" bigint NOT NULL,\n" .
            "    \"ip_start\" bytea NOT NULL,\n" .
            "    \"ip_end\" bytea NOT NULL,\n" .
            "    \"prefix\" smallint NOT NULL,\n" .
            "    PRIMARY KEY (\"id\")\n" .
            ");",
            'CREATE UNIQUE INDEX "idx_value_ip_ranges_value_id" ON "value_ip_ranges" ("value_id");',
            'CREATE INDEX "idx_value_ip_ranges_start_end" ON "value_ip_ranges" ("ip_start", "ip_end", "value_id");',
        ), $this->render(new MigrationTestPostgres(), array(), self::IP_RANGES));
    }

    public function testAnIpRangesRetryDeclaresOnlyWhatIsMissing()
    {
        $primary = array('PRIMARY' => array('column' => 'id', 'unique' => 1));
        $valueId = array('idx_value_ip_ranges_value_id' => array('column' => 'value_id', 'unique' => 1));
        $startEnd = array('idx_value_ip_ranges_start_end' => array('column' => array('ip_start', 'ip_end', 'value_id'), 'unique' => 0));

        $this->assertSame(
            array(
                'CREATE UNIQUE INDEX "idx_value_ip_ranges_value_id" ON "value_ip_ranges" ("value_id");',
                'CREATE INDEX "idx_value_ip_ranges_start_end" ON "value_ip_ranges" ("ip_start", "ip_end", "value_id");',
            ),
            $this->render(new MigrationTestPostgres(), array('value_ip_ranges' => $primary), self::IP_RANGES)
        );
        $this->assertSame(
            array('CREATE INDEX "idx_value_ip_ranges_start_end" ON "value_ip_ranges" ("ip_start", "ip_end", "value_id");'),
            $this->render(new MigrationTestPostgres(), array('value_ip_ranges' => $primary + $valueId), self::IP_RANGES)
        );
        $this->assertSame(
            array(),
            $this->render(new MigrationTestPostgres(), array('value_ip_ranges' => $primary + $valueId + $startEnd), self::IP_RANGES)
        );
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
        $inspector = new AttributeValuesMigrationTestInspector(new MigrationTestMysqlExtended());
        $class = self::MIGRATION;
        $migration = new $class();
        $migration->setSchemaInspector($inspector);
        $this->assertTrue($migration->beforeUp());
    }

    public function testTheValueIdsRendering()
    {
        $indexes = array(
            '`idx_attr_vid_combo` (`value1_id`, `value2_id`)',
            '`idx_vid1_source` (`event_id`, `value1_id`, `deleted`, `disable_correlation`, `type`, `id`)',
            '`idx_vid1_target` (`value1_id`, `event_id`, `deleted`, `disable_correlation`, `type`, `id`)',
            '`idx_vid2_source` (`event_id`, `value2_id`, `deleted`, `disable_correlation`, `type`, `id`)',
            '`idx_vid2_target` (`value2_id`, `event_id`, `deleted`, `disable_correlation`, `type`, `id`)',
        );
        $expected = array(
            'ALTER TABLE `attributes` ADD `value1_id` bigint(20) UNSIGNED DEFAULT NULL AFTER `value2`;',
            'ALTER TABLE `attributes` ADD `value2_id` bigint(20) UNSIGNED DEFAULT NULL AFTER `value1_id`;',
            'ALTER TABLE `shadow_attributes` ADD `value1_id` bigint(20) UNSIGNED DEFAULT NULL AFTER `value2`;',
            'ALTER TABLE `shadow_attributes` ADD `value2_id` bigint(20) UNSIGNED DEFAULT NULL AFTER `value1_id`;',
            "ALTER TABLE `shadow_attributes`\n" .
            "    ADD INDEX `value1_id` (`value1_id`),\n" .
            "    ADD INDEX `value2_id` (`value2_id`);",
            "ALTER TABLE `attributes`\n    ADD INDEX " . implode(",\n    ADD INDEX ", $indexes) . ';',
        );
        $this->assertSame($expected, $this->render(new MigrationTestMysqlExtended(), array(), self::VALUE_IDS));

        $pgsql = $this->render(new MigrationTestPostgres(), array(), self::VALUE_IDS);
        $this->assertSame('ALTER TABLE "attributes" ADD "value1_id" bigint DEFAULT NULL;', $pgsql[0]);
        $this->assertSame('CREATE INDEX "idx_shadow_attributes_value1_id" ON "shadow_attributes" ("value1_id");', $pgsql[4]);
        $this->assertSame('CREATE INDEX "idx_vid2_target" ON "attributes" ("value2_id", "event_id", "deleted", "disable_correlation", "type", "id");', $pgsql[10]);
        $this->assertCount(11, $pgsql);
    }

    public function testAValueIdsRetryDeclaresOnlyWhatIsMissing()
    {
        $columns = array(
            'attributes' => array('value1_id', 'value2_id'),
            'shadow_attributes' => array('value1_id'),
        );
        $existing = array(
            'attributes' => array(
                'idx_attr_vid_combo' => array('column' => array('value1_id', 'value2_id'), 'unique' => 0),
                'idx_vid1_source' => array('column' => array('event_id', 'value1_id', 'deleted', 'disable_correlation', 'type', 'id'), 'unique' => 0),
                'idx_vid1_target' => array('column' => array('value1_id', 'event_id', 'deleted', 'disable_correlation', 'type', 'id'), 'unique' => 0),
                'idx_vid2_source' => array('column' => array('event_id', 'value2_id', 'deleted', 'disable_correlation', 'type', 'id'), 'unique' => 0),
                'idx_vid2_target' => array('column' => array('value2_id', 'event_id', 'deleted', 'disable_correlation', 'type', 'id'), 'unique' => 0),
            ),
            'shadow_attributes' => array(
                'value1_id' => array('column' => 'value1_id', 'unique' => 0),
            ),
        );
        $this->assertSame(array(
            'ALTER TABLE `shadow_attributes` ADD `value2_id` bigint(20) UNSIGNED DEFAULT NULL AFTER `value1_id`;',
            'ALTER TABLE `shadow_attributes` ADD INDEX `value2_id` (`value2_id`);',
        ), $this->render(new MigrationTestMysqlExtended(), $existing, self::VALUE_IDS, $columns));

        $columns['shadow_attributes'][] = 'value2_id';
        $existing['shadow_attributes']['value2_id'] = array('column' => 'value2_id', 'unique' => 0);
        $this->assertSame(array(), $this->render(new MigrationTestMysqlExtended(), $existing, self::VALUE_IDS, $columns));
    }

    public function testTheTextPrefixPackDoesNotSatisfyTheIdIndexes()
    {
        $existing = array('attributes' => array(
            'idx_val1_source' => array('column' => array('event_id', 'value1', 'deleted', 'disable_correlation', 'type', 'id'), 'unique' => 0),
        ));
        $columns = array('attributes' => array('value1_id', 'value2_id'), 'shadow_attributes' => array('value1_id', 'value2_id'));
        $sql = $this->render(new MigrationTestMysqlExtended(), $existing, self::VALUE_IDS, $columns);
        $this->assertStringContainsString(
            'ADD INDEX `idx_vid1_source` (`event_id`, `value1_id`, `deleted`, `disable_correlation`, `type`, `id`)',
            implode("\n", $sql)
        );
    }
}
