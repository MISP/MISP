<?php
/**
 * The attribute_values migration picks its collation from the server version
 * it runs against, so a dry run only ever shows one branch. These render all
 * of them, the PostgreSQL half, and the value table migrations' retries,
 * without a database.
 */

require_once __DIR__ . '/MigrationSchemaStubs.php';
require_once APPLIBS . 'Migration/AbstractMigration.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261003_092429_create_attribute_values.php';
require_once APPLIBS . 'Migration/Migrations/Migration_20261004_093106_create_value_ip_ranges.php';

use PHPUnit\Framework\TestCase;

if (!class_exists('AttributeValuesMigrationTestInspector', false)) {
    class AttributeValuesMigrationTestInspector extends SchemaInspector
    {
        /** @var string */
        public $version = '';

        /** @var array table => index name => array('column' => ..., 'unique' => ...) */
        public $existing = array();

        public function hasTable($table)
        {
            return isset($this->existing[$table]);
        }

        public function indexes($table)
        {
            if (!isset($this->existing[$table])) {
                return array();
            }
            return $this->existing[$table];
        }

        protected function fetchRows($sql)
        {
            if ($sql === 'SHOW VARIABLES;') {
                return array(array('Variable_name' => 'version', 'Value' => $this->version));
            }
            return array(array('name' => 'server_version', 'setting' => '16.15'));
        }
    }
}

class AttributeValuesMigrationTest extends TestCase
{
    const MIGRATION = 'Migration_20261003_092429_create_attribute_values';

    const IP_RANGES = 'Migration_20261004_093106_create_value_ip_ranges';

    /**
     * @param DboSource $db
     * @param string $version
     * @param array $existing
     * @param string $class
     * @return array
     */
    private function render(DboSource $db, $version = '', array $existing = array(), $class = self::MIGRATION)
    {
        $inspector = new AttributeValuesMigrationTestInspector($db);
        $inspector->version = $version;
        $inspector->existing = $existing;
        $migration = new $class();
        $migration->setSchemaInspector($inspector);
        $schema = new SchemaBuilder(AbstractGrammar::forDataSource($db));
        $migration->up($schema);
        return $schema->toSql();
    }

    public static function versions()
    {
        return array(
            'MariaDB 10.11 (Ubuntu 24.04)' => array('10.11.14-MariaDB-0ubuntu0.24.04.1', 'utf8mb4_uca1400_ai_ci'),
            'MariaDB 10.10' => array('10.10.7-MariaDB', 'utf8mb4_uca1400_ai_ci'),
            'MariaDB 11.4' => array('11.4.3-MariaDB-log', 'utf8mb4_uca1400_ai_ci'),
            'MariaDB 10.9' => array('10.9.8-MariaDB', 'utf8mb4_unicode_520_ci'),
            'MariaDB 10.5 (RHEL 9)' => array('10.5.22-MariaDB', 'utf8mb4_unicode_520_ci'),
            'MySQL 8.0' => array('8.0.43-0ubuntu0.24.04.2', 'utf8mb4_0900_ai_ci'),
            'MySQL 8.4' => array('8.4.6', 'utf8mb4_0900_ai_ci'),
            'MySQL 5.7' => array('5.7.44-log', 'utf8mb4_unicode_520_ci'),
            'unknown' => array('', 'utf8mb4_unicode_520_ci'),
        );
    }

    /**
     * @dataProvider versions
     */
    public function testTheCollationFollowsTheServer($version, $collation)
    {
        $class = self::MIGRATION;
        $this->assertSame($collation, $class::mysqlCollation($version));
        $this->assertNotSame('utf8mb4_unicode_ci', $class::mysqlCollation($version));
    }

    /**
     * @dataProvider versions
     */
    public function testTheMysqlRenderingCarriesTheCollation($version, $collation)
    {
        $this->assertSame(array(
            "CREATE TABLE `attribute_values` (\n" .
            "    `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,\n" .
            "    `value` text CHARACTER SET utf8mb4 COLLATE $collation NOT NULL,\n" .
            "    `hash` varbinary(16) NOT NULL,\n" .
            "    PRIMARY KEY (`id`),\n" .
            "    UNIQUE INDEX `hash` (`hash`)\n" .
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=$collation;",
            'ALTER TABLE `attribute_values` ADD INDEX `value` (`value`(128));',
            'ALTER TABLE `attribute_values` ADD FULLTEXT INDEX `value_search` (`value`);',
        ), $this->render(new MigrationTestMysqlExtended(), $version));
    }

    public function testThePostgresRendering()
    {
        $this->assertSame(array(
            "CREATE TABLE \"attribute_values\" (\n" .
            "    \"id\" bigserial NOT NULL,\n" .
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
            $this->render(new MigrationTestMysqlExtended(), '10.11.14-MariaDB', array(
                'attribute_values' => self::indexes(array('PRIMARY', 'hash', 'value')),
            ))
        );
        $this->assertSame(array(), $this->render(new MigrationTestMysqlExtended(), '10.11.14-MariaDB', array(
            'attribute_values' => self::indexes(array('PRIMARY', 'hash', 'value', 'value_search')),
        )));
        $this->assertSame(array(), $this->render(new MigrationTestPostgres(), '', array(
            'attribute_values' => self::indexes(array(
                'PRIMARY',
                'idx_attribute_values_hash',
                'idx_attribute_values_value',
                'idx_attribute_values_value_search',
            )),
        )));
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
        ), $this->render(new MigrationTestMysqlExtended(), '10.11.14-MariaDB', array(), self::IP_RANGES));
        $this->assertSame(array(
            "CREATE TABLE \"value_ip_ranges\" (\n" .
            "    \"id\" bigserial NOT NULL,\n" .
            "    \"value_id\" bigint NOT NULL,\n" .
            "    \"ip_start\" bytea NOT NULL,\n" .
            "    \"ip_end\" bytea NOT NULL,\n" .
            "    \"prefix\" smallint NOT NULL,\n" .
            "    PRIMARY KEY (\"id\")\n" .
            ");",
            'CREATE UNIQUE INDEX "idx_value_ip_ranges_value_id" ON "value_ip_ranges" ("value_id");',
            'CREATE INDEX "idx_value_ip_ranges_start_end" ON "value_ip_ranges" ("ip_start", "ip_end", "value_id");',
        ), $this->render(new MigrationTestPostgres(), '', array(), self::IP_RANGES));
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
            $this->render(new MigrationTestPostgres(), '', array('value_ip_ranges' => $primary), self::IP_RANGES)
        );
        $this->assertSame(
            array('CREATE INDEX "idx_value_ip_ranges_start_end" ON "value_ip_ranges" ("ip_start", "ip_end", "value_id");'),
            $this->render(new MigrationTestPostgres(), '', array('value_ip_ranges' => $primary + $valueId), self::IP_RANGES)
        );
        $this->assertSame(
            array(),
            $this->render(new MigrationTestPostgres(), '', array('value_ip_ranges' => $primary + $valueId + $startEnd), self::IP_RANGES)
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
}
