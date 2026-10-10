<?php
/**
 * The install-baseline generator: information_schema rows in, DSL specs and
 * rendered SQL out.
 *
 * Two halves. The mapping - column types, defaults in the three spellings
 * MariaDB and MySQL use, index rows into declarations - is pure and is
 * asserted case by case. The rendering is asserted through the real offline
 * grammars, so what is pinned here is the SQL a `dumpInstallBaseline` run
 * would write, not a stand-in for it.
 *
 * The reading half - the catalog queries and the seed selection - is covered
 * with a stub that answers canned rows and records the SQL it was asked,
 * which is enough to pin what is filtered and in which order without a
 * database.
 *
 * @see MigrationSchemaStubs.php for how the real Cake drivers are loaded without a connection.
 */

require_once __DIR__ . '/MigrationSchemaStubs.php';
require_once APPLIBS . 'Migration/BaselineGenerator.php';

use PHPUnit\Framework\TestCase;

class BaselineGeneratorTestStub extends BaselineGenerator
{
    /** @var array sql pattern => rows */
    public $answers = array();

    /** @var array Every statement fetchRows() was asked. */
    public $asked = array();

    /** @var bool */
    public $mariadb = true;

    protected function fetchRows($sql)
    {
        $this->asked[] = $sql;
        foreach ($this->answers as $needle => $rows) {
            if (stripos($sql, $needle) !== false) {
                return $rows;
            }
        }
        return array();
    }

    protected function quotesLiteralDefaults()
    {
        return $this->mariadb;
    }
}

/**
 * A connectionless PostgreSQL datasource with a fixed schema, shaped the way
 * Postgres::describe() and Postgres::index() shape theirs: boolean defaults
 * as PHP booleans, index columns quoted when the identifier needs it.
 */
class BaselineGeneratorTestLoadedPostgres extends MigrationTestPostgres
{
    public $tables = array('correlations', 'admin_settings', 'roles', 'system_settings', 'leftover');

    public $descriptions = array(
        'correlations' => array(
            'id' => array('type' => 'integer', 'null' => false, 'default' => null, 'length' => 11, 'key' => 'primary'),
            '1_event_id' => array('type' => 'integer', 'null' => false, 'default' => null, 'length' => null),
            'value1' => array('type' => 'text', 'null' => false, 'default' => null, 'length' => null),
            'deleted' => array('type' => 'boolean', 'null' => false, 'default' => false, 'length' => null),
            'created' => array('type' => 'integer', 'null' => false, 'default' => 'floor(EXTRACT(epoch FROM now()))', 'length' => null),
        ),
        'admin_settings' => array(
            'id' => array('type' => 'integer', 'null' => false, 'default' => null, 'length' => 11, 'key' => 'primary'),
            'setting' => array('type' => 'string', 'null' => false, 'default' => null, 'length' => 255),
            'value' => array('type' => 'text', 'null' => false, 'default' => null, 'length' => null),
            'surplus' => array('type' => 'text', 'null' => true, 'default' => null, 'length' => null),
        ),
        'roles' => array(
            'id' => array('type' => 'integer', 'null' => false, 'default' => null, 'length' => 11, 'key' => 'primary'),
            'name' => array('type' => 'string', 'null' => false, 'default' => null, 'length' => 191),
            'created' => array('type' => 'datetime', 'null' => true, 'default' => null, 'length' => null),
            'perm_add' => array('type' => 'boolean', 'null' => false, 'default' => null, 'length' => null),
        ),
        'system_settings' => array(
            'setting' => array('type' => 'string', 'null' => false, 'default' => null, 'length' => 255, 'key' => 'primary'),
            'value' => array('type' => 'binary', 'null' => false, 'default' => null, 'length' => null),
        ),
        'leftover' => array(
            'id' => array('type' => 'integer', 'null' => false, 'default' => null, 'length' => 11, 'key' => 'primary'),
        ),
    );

    public $indexData = array(
        'correlations' => array(
            'PRIMARY' => array('unique' => true, 'column' => 'id'),
            'idx_correlations_1_event_id' => array('unique' => false, 'column' => '"1_event_id"'),
            'idx_correlations_value1' => array('unique' => false, 'column' => 'value1'),
        ),
        'admin_settings' => array(
            'PRIMARY' => array('unique' => true, 'column' => 'id'),
            'idx_admin_settings_setting' => array('unique' => false, 'column' => 'setting'),
            'idx_admin_settings_stray' => array('unique' => false, 'column' => 'value'),
        ),
        'roles' => array(
            'PRIMARY' => array('unique' => true, 'column' => 'id'),
        ),
        'system_settings' => array(
            'PRIMARY' => array('unique' => true, 'column' => 'setting'),
        ),
        'leftover' => array(
            'PRIMARY' => array('unique' => true, 'column' => 'id'),
        ),
    );

    public function listSources($data = null)
    {
        return $this->tables;
    }

    public function describe($model)
    {
        return isset($this->descriptions[$model]) ? $this->descriptions[$model] : array();
    }

    public function index($model)
    {
        return isset($this->indexData[$model]) ? $this->indexData[$model] : array();
    }
}

class BaselineGeneratorTest extends TestCase
{
    /** @var MysqlGrammar */
    private $mysql;

    /** @var PostgresGrammar */
    private $pgsql;

    protected function setUp(): void
    {
        $this->mysql = new MysqlGrammar(new MigrationTestMysqlExtended());
        $this->pgsql = new PostgresGrammar(new MigrationTestPostgres());
    }

    // -------------------------------------------------------------- columns

    /**
     * @dataProvider columnTypes
     */
    public function testColumnTypesMapOntoTheDsl($columnType, array $expected)
    {
        list($spec) = BaselineGenerator::columnSpec(array(
            'COLUMN_NAME' => 'c',
            'COLUMN_TYPE' => $columnType,
            'IS_NULLABLE' => 'NO',
            'COLUMN_DEFAULT' => null,
            'EXTRA' => '',
        ));
        unset($spec['null']);
        $this->assertSame($expected, $spec, $columnType);
    }

    public function columnTypes()
    {
        return array(
            array('int(11)', array('type' => 'integer', 'length' => 11)),
            array('int(10) unsigned', array('type' => 'integer', 'length' => 10, 'unsigned' => true)),
            array('int(15)', array('type' => 'integer', 'length' => 15)),
            array('tinyint(1)', array('type' => 'boolean', 'length' => 1)),
            array('tinyint(4)', array('type' => 'tinyinteger', 'length' => 4)),
            array('smallint(6)', array('type' => 'smallinteger', 'length' => 6)),
            array('bigint(20)', array('type' => 'biginteger', 'length' => 20)),
            array('bigint(20) unsigned', array('type' => 'biginteger', 'length' => 20, 'unsigned' => true)),
            array('varchar(191)', array('type' => 'string', 'length' => 191)),
            array('text', array('type' => 'text')),
            array('mediumtext', array('type' => 'mediumtext')),
            array('longtext', array('type' => 'longtext')),
            array('blob', array('type' => 'binary')),
            array('varbinary(16)', array('type' => 'varbinary', 'length' => 16)),
            array('datetime', array('type' => 'datetime')),
            array('datetime(4)', array('type' => 'datetime', 'length' => 4)),
            array('timestamp', array('type' => 'timestamp')),
            array('date', array('type' => 'date')),
            array('decimal(10,2)', array('type' => 'decimal', 'length' => '10,2')),
        );
    }

    public function testEnumHasNoPortableRendering()
    {
        $this->expectException('InvalidArgumentException');
        $this->expectExceptionMessage('no portable rendering');
        BaselineGenerator::columnSpec(array(
            'COLUMN_NAME' => 'c', 'COLUMN_TYPE' => "enum('a','b')", 'IS_NULLABLE' => 'NO',
            'COLUMN_DEFAULT' => null, 'EXTRA' => '',
        ));
    }

    public function testAnUnknownTypeIsAHardError()
    {
        $this->expectException('InvalidArgumentException');
        $this->expectExceptionMessage('no DSL type');
        BaselineGenerator::columnSpec(array(
            'COLUMN_NAME' => 'c', 'COLUMN_TYPE' => 'geometry', 'IS_NULLABLE' => 'NO',
            'COLUMN_DEFAULT' => null, 'EXTRA' => '',
        ));
    }

    public function testNullabilityIsRead()
    {
        list($yes) = BaselineGenerator::columnSpec(array(
            'COLUMN_NAME' => 'c', 'COLUMN_TYPE' => 'text', 'IS_NULLABLE' => 'YES', 'COLUMN_DEFAULT' => 'NULL', 'EXTRA' => '',
        ));
        list($no) = BaselineGenerator::columnSpec(array(
            'COLUMN_NAME' => 'c', 'COLUMN_TYPE' => 'text', 'IS_NULLABLE' => 'NO', 'COLUMN_DEFAULT' => null, 'EXTRA' => '',
        ));
        $this->assertTrue($yes['null']);
        $this->assertFalse($no['null']);
        // An explicit NULL default is not a default: the grammar emits DEFAULT
        // NULL for a nullable column by itself.
        $this->assertArrayNotHasKey('default', $yes);
    }

    /**
     * @dataProvider defaults
     */
    public function testDefaultsInEveryServerSpelling($default, $extra, $mariadb, array $expected)
    {
        $this->assertSame($expected, BaselineGenerator::parseDefault($default, $extra, $mariadb));
    }

    public function defaults()
    {
        return array(
            // MariaDB: literals quoted, NULL spelled out, expressions bare.
            array(null, '', true, array(false, null, false)),
            array('NULL', '', true, array(false, null, false)),
            array("'basic'", '', true, array(true, 'basic', false)),
            array("''", '', true, array(true, '', false)),
            array("'it''s'", '', true, array(true, "it's", false)),
            array('0', '', true, array(true, '0', false)),
            array('-1', '', true, array(true, '-1', false)),
            array('current_timestamp()', '', true, array(true, 'current_timestamp()', true)),
            array('unix_timestamp()', '', true, array(true, 'unix_timestamp()', true)),
            // MySQL: literals bare, expressions flagged, CURRENT_TIMESTAMP special.
            array('basic', '', false, array(true, 'basic', false)),
            array('', '', false, array(true, '', false)),
            array('CURRENT_TIMESTAMP', '', false, array(true, 'CURRENT_TIMESTAMP', true)),
            array('CURRENT_TIMESTAMP(6)', '', false, array(true, 'CURRENT_TIMESTAMP', true)),
            array('unix_timestamp()', 'default_generated', false, array(true, 'unix_timestamp()', true)),
        );
    }

    public function testCurrentTimestampStaysInlineAndOtherExpressionsAreReturned()
    {
        list($spec, $expression) = BaselineGenerator::columnSpec(array(
            'COLUMN_NAME' => 'created_at', 'COLUMN_TYPE' => 'timestamp', 'IS_NULLABLE' => 'NO',
            'COLUMN_DEFAULT' => 'current_timestamp()', 'EXTRA' => '',
        ));
        $this->assertSame('CURRENT_TIMESTAMP', $spec['default']);
        $this->assertNull($expression);

        list($spec, $expression) = BaselineGenerator::columnSpec(array(
            'COLUMN_NAME' => 'created', 'COLUMN_TYPE' => 'int(11)', 'IS_NULLABLE' => 'NO',
            'COLUMN_DEFAULT' => 'unix_timestamp()', 'EXTRA' => '',
        ));
        $this->assertArrayNotHasKey('default', $spec);
        $this->assertSame('unix_timestamp()', $expression);
    }

    public function testACollationOnlyTravelsWhenItDiffersFromTheTables()
    {
        $row = array(
            'COLUMN_NAME' => 'c', 'COLUMN_TYPE' => 'varchar(255)', 'IS_NULLABLE' => 'NO',
            'COLUMN_DEFAULT' => null, 'EXTRA' => '',
            'CHARACTER_SET_NAME' => 'utf8mb3', 'COLLATION_NAME' => 'utf8mb3_bin',
        );
        list($same) = BaselineGenerator::columnSpec($row, true, 'utf8mb3_bin');
        list($different) = BaselineGenerator::columnSpec($row, true, 'utf8mb4_unicode_ci');
        $this->assertArrayNotHasKey('collate', $same);
        $this->assertSame('utf8mb3_bin', $different['collate']);
        $this->assertSame('utf8mb3', $different['charset']);
    }

    // -------------------------------------------------------------- indexes

    public function testIndexRowsBecomeDeclarationsInSequenceOrder()
    {
        // Deliberately out of order: the second column of the composite
        // index arrives before its first.
        $rows = array(
            array('INDEX_NAME' => 'PRIMARY', 'SEQ_IN_INDEX' => 1, 'COLUMN_NAME' => 'id', 'NON_UNIQUE' => 0, 'SUB_PART' => null, 'INDEX_TYPE' => 'BTREE'),
            array('INDEX_NAME' => 'unique_correlation', 'SEQ_IN_INDEX' => 2, 'COLUMN_NAME' => '1_attribute_id', 'NON_UNIQUE' => 0, 'SUB_PART' => null, 'INDEX_TYPE' => 'BTREE'),
            array('INDEX_NAME' => 'unique_correlation', 'SEQ_IN_INDEX' => 1, 'COLUMN_NAME' => 'attribute_id', 'NON_UNIQUE' => 0, 'SUB_PART' => null, 'INDEX_TYPE' => 'BTREE'),
            array('INDEX_NAME' => 'unique_correlation', 'SEQ_IN_INDEX' => 3, 'COLUMN_NAME' => 'value_id', 'NON_UNIQUE' => 0, 'SUB_PART' => null, 'INDEX_TYPE' => 'BTREE'),
            array('INDEX_NAME' => 'value1', 'SEQ_IN_INDEX' => 1, 'COLUMN_NAME' => 'value1', 'NON_UNIQUE' => 1, 'SUB_PART' => 255, 'INDEX_TYPE' => 'BTREE'),
            array('INDEX_NAME' => 'search', 'SEQ_IN_INDEX' => 1, 'COLUMN_NAME' => 'value1', 'NON_UNIQUE' => 1, 'SUB_PART' => null, 'INDEX_TYPE' => 'FULLTEXT'),
        );
        list($primary, $indexes) = BaselineGenerator::indexDeclarations($rows);
        $this->assertSame('id', $primary);
        $this->assertSame(array('search', 'unique_correlation', 'value1'), array_keys($indexes));
        $this->assertSame(
            array('name' => 'unique_correlation', 'column' => array('attribute_id', '1_attribute_id', 'value_id'), 'unique' => true),
            $indexes['unique_correlation']
        );
        $this->assertSame(
            array('name' => 'value1', 'column' => array('value1'), 'unique' => false, 'length' => array('value1' => 255)),
            $indexes['value1']
        );
        $this->assertTrue($indexes['search']['fulltext']);
        $this->assertFalse($indexes['search']['unique']);
    }

    public function testACompositePrimaryKeyCannotBeDeclared()
    {
        $this->expectException('InvalidArgumentException');
        $this->expectExceptionMessage('composite primary key');
        BaselineGenerator::indexDeclarations(array(
            array('INDEX_NAME' => 'PRIMARY', 'SEQ_IN_INDEX' => 1, 'COLUMN_NAME' => 'a', 'NON_UNIQUE' => 0, 'SUB_PART' => null, 'INDEX_TYPE' => 'BTREE'),
            array('INDEX_NAME' => 'PRIMARY', 'SEQ_IN_INDEX' => 2, 'COLUMN_NAME' => 'b', 'NON_UNIQUE' => 0, 'SUB_PART' => null, 'INDEX_TYPE' => 'BTREE'),
        ));
    }

    /**
     * The PostgreSQL rewrite applies to exactly one shape: a non-unique
     * prefix index over a single text column.
     */
    public function testWhichPrefixIndexesBecomeHashIndexes()
    {
        $columns = array('value1' => array('type' => 'text'), 'name' => array('type' => 'string', 'length' => 255));
        $prefix = array('name' => 'value1', 'column' => array('value1'), 'unique' => false, 'length' => array('value1' => 255));
        $this->assertTrue(BaselineGenerator::needsHashRewrite($prefix, $columns));

        $unique = array_merge($prefix, array('unique' => true));
        $this->assertFalse(BaselineGenerator::needsHashRewrite($unique, $columns), 'a hash index cannot be unique');

        $varchar = array('name' => 'name', 'column' => array('name'), 'unique' => false, 'length' => array('name' => 191));
        $this->assertFalse(BaselineGenerator::needsHashRewrite($varchar, $columns), 'a varchar fits a btree entry');

        $composite = array('name' => 'both', 'column' => array('value1', 'name'), 'unique' => false, 'length' => array('value1' => 255));
        $this->assertFalse(BaselineGenerator::needsHashRewrite($composite, $columns), 'hash indexes are single-column');

        $plain = array('name' => 'value1', 'column' => array('value1'), 'unique' => false);
        $this->assertFalse(BaselineGenerator::needsHashRewrite($plain, $columns), 'no prefix, nothing to rewrite');
    }

    public function testExpressionDefaultsAreTranslatedOrRefused()
    {
        $this->assertSame('UNIX_TIMESTAMP()', BaselineGenerator::expressionDefault('unix_timestamp()', 'mysql', 't', 'c'));
        $this->assertSame(
            'FLOOR(EXTRACT(EPOCH FROM NOW()))::integer',
            BaselineGenerator::expressionDefault('UNIX_TIMESTAMP()', 'pgsql', 't', 'c')
        );
        $this->expectException('InvalidArgumentException');
        $this->expectExceptionMessage('cannot spell');
        BaselineGenerator::expressionDefault('uuid()', 'pgsql', 't', 'c');
    }

    // ------------------------------------------------------------ rendering

    private function fixtureSchema()
    {
        return array(
            'correlations' => array(
                'columns' => array(
                    'id' => array('type' => 'integer', 'length' => 11, 'null' => false, 'key' => 'primary'),
                    '1_event_id' => array('type' => 'integer', 'length' => 11, 'null' => false),
                    'value1' => array('type' => 'text', 'null' => false),
                    'deleted' => array('type' => 'boolean', 'length' => 1, 'null' => false, 'default' => '0'),
                    'created' => array('type' => 'integer', 'length' => 11, 'null' => false),
                ),
                'indexes' => array(
                    '1_event_id' => array('name' => '1_event_id', 'column' => array('1_event_id'), 'unique' => false),
                    'value1' => array('name' => 'value1', 'column' => array('value1'), 'unique' => false, 'length' => array('value1' => 255)),
                ),
                'primary' => 'id',
                'options' => array('engine' => 'InnoDB', 'charset' => 'utf8mb4', 'collate' => 'utf8mb4_unicode_ci'),
                'expressionDefaults' => array('created' => 'unix_timestamp()'),
            ),
            'admin_settings' => array(
                'columns' => array(
                    'id' => array('type' => 'integer', 'length' => 11, 'null' => false, 'key' => 'primary'),
                    'setting' => array('type' => 'string', 'length' => 255, 'null' => false),
                    'value' => array('type' => 'text', 'null' => false),
                ),
                'indexes' => array(
                    'setting' => array('name' => 'setting', 'column' => array('setting'), 'unique' => true),
                ),
                'primary' => 'id',
                'options' => array('engine' => 'InnoDB', 'charset' => 'utf8mb4', 'collate' => 'utf8mb4_unicode_ci'),
                'expressionDefaults' => array(),
            ),
            'roles' => array(
                'columns' => array(
                    'id' => array('type' => 'integer', 'length' => 11, 'null' => false, 'key' => 'primary'),
                    'name' => array('type' => 'string', 'length' => 100, 'null' => false),
                    'created' => array('type' => 'datetime', 'null' => true),
                    'perm_add' => array('type' => 'boolean', 'length' => 1, 'null' => true),
                ),
                'indexes' => array(),
                'primary' => 'id',
                'options' => array('engine' => 'InnoDB'),
                'expressionDefaults' => array(),
            ),
            'system_settings' => array(
                'columns' => array(
                    'setting' => array('type' => 'string', 'length' => 255, 'null' => false, 'key' => 'primary'),
                    'value' => array('type' => 'binary', 'null' => false),
                ),
                'indexes' => array(),
                'primary' => 'setting',
                'options' => array(),
                'expressionDefaults' => array(),
            ),
        );
    }

    private function fixtureSeeds()
    {
        return array(
            'admin_settings' => array(
                array('id' => '1', 'setting' => 'db_version', 'value' => '126'),
                array('id' => '8', 'setting' => 'fix_login', 'value' => '2024-11-18 15:49:16'),
                array('id' => '9', 'setting' => 'default_role', 'value' => '3'),
            ),
            'roles' => array(
                array('id' => '1', 'name' => "admin's", 'created' => '2024-11-18 15:49:16', 'perm_add' => '1'),
                array('id' => '2', 'name' => 'user', 'created' => null, 'perm_add' => '0'),
            ),
        );
    }

    private function generator()
    {
        return new BaselineGeneratorTestStub(new MigrationTestMysqlExtended(), 'reference');
    }

    public function testThePostgresRenderingOfTheHardCases()
    {
        $rendered = $this->generator()->render($this->pgsql, $this->fixtureSchema(), $this->fixtureSeeds(), 159);
        $sql = $rendered['sql'];

        // The whole file is one transaction, with the encoding and the
        // backslash rule pinned first.
        $this->assertStringContainsString("SET client_encoding = 'UTF8';\nSET standard_conforming_strings = on;\nBEGIN;", $sql);
        $this->assertStringEndsWith("COMMIT;\n", $sql);

        // A digit-leading identifier is quoted everywhere it appears.
        $this->assertStringContainsString('"1_event_id" integer NOT NULL', $sql);
        $this->assertStringContainsString('CREATE INDEX "idx_correlations_1_event_id" ON "correlations" ("1_event_id");', $sql);

        // The prefix index on a text column is a hash index, and is reported.
        $this->assertStringContainsString('CREATE INDEX "idx_correlations_value1" ON "correlations" USING hash ("value1");', $sql);
        $this->assertStringNotContainsString('("value1");' . "\n", str_replace('USING hash ("value1");' . "\n", '', $sql));

        // The serial key and the flag.
        $this->assertStringContainsString('"id" serial NOT NULL', $sql);
        $this->assertStringContainsString("\"deleted\" boolean DEFAULT 'FALSE' NOT NULL", $sql);
        $this->assertStringContainsString('PRIMARY KEY ("id")', $sql);

        // The expression default lands after the table exists.
        $this->assertStringContainsString(
            'ALTER TABLE "correlations" ALTER COLUMN "created" SET DEFAULT FLOOR(EXTRACT(EPOCH FROM NOW()))::integer;',
            $sql
        );

        // A string key is NOT NULL plus a PRIMARY KEY clause; no serial.
        $this->assertStringContainsString("\"setting\" varchar(255) NOT NULL,\n    \"value\" bytea NOT NULL,\n    PRIMARY KEY (\"setting\")", $sql);

        // MySQL storage parameters never appear.
        $this->assertStringNotContainsString('ENGINE', $sql);
        $this->assertStringNotContainsString('utf8mb4', $sql);

        // The seed block: marker verbatim, ON CONFLICT, the three rewritten
        // cells, quoting through the driver, datetimes as NOW().
        // Exactly once: misp-wipe finds the seed block by sed-matching it, and
        // a second occurrence higher up would hand it the DDL instead.
        $this->assertStringContainsString("--\n-- Default values for initial installation\n--\n", $sql);
        $this->assertSame(1, substr_count($sql, BaselineGenerator::SEED_MARKER));
        // admin_settings: one single-line statement per row, so that a line
        // filter (misp-wipe's) drops each whole.
        $this->assertStringContainsString(
            "INSERT INTO \"admin_settings\" (\"id\", \"setting\", \"value\") VALUES (1, 'db_version', '159') ON CONFLICT DO NOTHING;\n"
                . "INSERT INTO \"admin_settings\" (\"id\", \"setting\", \"value\") VALUES (8, 'fix_login', FLOOR(EXTRACT(EPOCH FROM NOW()))::bigint::text) ON CONFLICT DO NOTHING;\n"
                . "INSERT INTO \"admin_settings\" (\"id\", \"setting\", \"value\") VALUES (9, 'default_role', '3') ON CONFLICT DO NOTHING;",
            $sql
        );
        $this->assertStringContainsString(
            "INSERT INTO \"roles\" (\"id\", \"name\", \"created\", \"perm_add\") VALUES\n"
                . "(1, 'admin''s', NOW(), 'TRUE'),\n"
                . "(2, 'user', NULL, 'FALSE')\n"
                . "ON CONFLICT DO NOTHING;",
            $sql
        );

        // Explicit ids were seeded, so every serial is caught up.
        $this->assertStringContainsString(
            "SELECT setval(pg_get_serial_sequence('admin_settings', 'id'), COALESCE(MAX(\"id\"), 1), MAX(\"id\") IS NOT NULL) FROM \"admin_settings\";",
            $sql
        );
        $this->assertStringContainsString("pg_get_serial_sequence('roles', 'id')", $sql);
        $this->assertStringNotContainsString("pg_get_serial_sequence('system_settings'", $sql);

        $this->assertCount(1, $rendered['notes']);
        $this->assertStringContainsString('idx_correlations_value1', $rendered['notes'][0]);
        $this->assertStringContainsString('hash index', $rendered['notes'][0]);
    }

    /**
     * The same tool with the other grammar is the MySQL baseline. Nothing is
     * dropped there, so nothing is noted.
     */
    /**
     * What a migration creates through rawSql() on PostgreSQL alone has no
     * column in the MySQL reference to be derived from, and a fresh install
     * seeds that migration as applied - so the PostgreSQL rendering carries
     * the index itself, says so, and the round trip expects it back.
     */
    public function testAPostgresOnlyIndexIsRenderedForItsTableAndExpectedBack()
    {
        $schema = array(
            'tags' => array(
                'columns' => array(
                    'id' => array('type' => 'integer', 'length' => 11, 'null' => false, 'key' => 'primary'),
                    'name' => array('type' => 'string', 'length' => 255, 'null' => false),
                ),
                'indexes' => array(
                    'name' => array('name' => 'name', 'column' => array('name'), 'unique' => true),
                ),
                'primary' => 'id',
                'options' => array('engine' => 'InnoDB', 'charset' => 'utf8mb4', 'collate' => 'utf8mb4_unicode_ci'),
                'expressionDefaults' => array(),
            ),
        );

        $pgsql = $this->generator()->render($this->pgsql, $schema, array(), 159);
        $this->assertStringContainsString('CREATE UNIQUE INDEX "idx_tags_name" ON "tags" ("name");', $pgsql['sql']);
        $this->assertStringContainsString('CREATE UNIQUE INDEX "idx_tags_name_lower" ON "tags" (lower("name"));', $pgsql['sql']);
        $this->assertCount(1, $pgsql['notes']);
        $this->assertStringContainsString('PostgreSQL-only index idx_tags_name_lower added to tags', $pgsql['notes'][0]);

        $mysql = $this->generator()->render($this->mysql, $schema, array(), 159);
        $this->assertStringNotContainsString('idx_tags_name_lower', $mysql['sql']);
        $this->assertSame(array(), $mysql['notes']);

        $db = new BaselineGeneratorTestLoadedPostgres();
        $db->tables = array('tags');
        $db->descriptions = array('tags' => array(
            'id' => array('type' => 'integer', 'null' => false, 'default' => null, 'length' => 11, 'key' => 'primary'),
            'name' => array('type' => 'string', 'null' => false, 'default' => null, 'length' => 255),
        ));
        $db->indexData = array('tags' => array(
            'PRIMARY' => array('unique' => true, 'column' => 'id'),
            'idx_tags_name' => array('unique' => true, 'column' => 'name'),
        ));
        $this->assertSame(
            array('tags: PostgreSQL-only index idx_tags_name_lower missing'),
            $this->generator()->compare(new SchemaInspector($db), $schema)
        );

        $db->indexData['tags']['idx_tags_name_lower'] = array('unique' => true, 'column' => 'lower(name)');
        $this->assertSame(array(), $this->generator()->compare(new SchemaInspector($db), $schema));
    }

    public function testTheMysqlRenderingKeepsEverythingAndNotesNothing()
    {
        $rendered = $this->generator()->render($this->mysql, $this->fixtureSchema(), $this->fixtureSeeds(), 159);
        $sql = $rendered['sql'];

        $this->assertStringContainsString('/*!40101 SET NAMES utf8mb4 */;', $sql);
        $this->assertStringNotContainsString('BEGIN;', $sql);
        $this->assertStringContainsString('`id` int(11) NOT NULL AUTO_INCREMENT', $sql);
        $this->assertStringContainsString('`1_event_id` int(11) NOT NULL', $sql);
        $this->assertStringContainsString('INDEX `value1` (`value1`(255))', $sql);
        $this->assertStringContainsString("`deleted` tinyint(1) DEFAULT '0' NOT NULL", $sql);
        $this->assertStringContainsString(') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;', $sql);
        $this->assertStringContainsString(
            'ALTER TABLE `correlations` ALTER COLUMN `created` SET DEFAULT UNIX_TIMESTAMP();',
            $sql
        );
        // admin_settings one row per single-line statement: misp-wipe.sh
        // replays the seed block after a wipe and filters that table out by
        // line. Every other table stays one multi-row INSERT.
        $this->assertStringContainsString(
            "INSERT IGNORE INTO `admin_settings` (`id`, `setting`, `value`) VALUES (1, 'db_version', '159');\n"
                . "INSERT IGNORE INTO `admin_settings` (`id`, `setting`, `value`) VALUES (8, 'fix_login', UNIX_TIMESTAMP());\n"
                . "INSERT IGNORE INTO `admin_settings` (`id`, `setting`, `value`) VALUES (9, 'default_role', '3');",
            $sql
        );
        $this->assertStringContainsString(
            "INSERT IGNORE INTO `roles` (`id`, `name`, `created`, `perm_add`) VALUES\n"
                . "(1, 'admin''s', NOW(), '1'),\n"
                . "(2, 'user', NULL, '0');",
            $sql
        );
        $this->assertStringNotContainsString('setval', $sql);
        $this->assertSame(array(), $rendered['notes']);
    }

    public function testADefaultOnAKeyColumnIsNotedAsDropped()
    {
        $schema = $this->fixtureSchema();
        $schema['system_settings']['columns']['setting']['default'] = '';
        $rendered = $this->generator()->render($this->mysql, $schema, array(), 159);
        $this->assertStringContainsString('`setting` varchar(255) NOT NULL,', $rendered['sql']);
        $this->assertCount(1, $rendered['notes']);
        $this->assertStringContainsString("Default '' dropped from the primary key column system_settings.setting", $rendered['notes'][0]);
    }

    public function testAUniquePrefixIndexStaysABtreeAndIsNotedAsDropped()
    {
        $schema = $this->fixtureSchema();
        $schema['correlations']['indexes']['value1']['unique'] = true;
        $rendered = $this->generator()->render($this->pgsql, $schema, array(), 159);
        $this->assertStringContainsString('CREATE UNIQUE INDEX "idx_correlations_value1" ON "correlations" ("value1");', $rendered['sql']);
        $this->assertStringNotContainsString('USING hash', $rendered['sql']);
        $this->assertCount(1, $rendered['notes']);
        $this->assertStringContainsString('Prefix length dropped', $rendered['notes'][0]);
    }

    // -------------------------------------------------------------- reading

    public function testTheReferenceHasToBeMysql()
    {
        $this->expectException('InvalidArgumentException');
        new BaselineGenerator(new MigrationTestPostgres(), 'reference');
    }

    public function testTheDatabaseDefaultsToTheConnectionsOwn()
    {
        $generator = new BaselineGenerator(new MigrationTestMysqlExtended());
        $this->assertSame('misp', $generator->database());
        $this->assertSame('reference', $this->generator()->database());
    }

    public function testReadingTheSchemaFiltersOnTheReferenceDatabase()
    {
        $generator = $this->generator();
        $generator->answers = array(
            'information_schema.TABLES' => array(
                array('TABLE_NAME' => 'roles', 'ENGINE' => 'InnoDB', 'TABLE_COLLATION' => 'utf8mb4_unicode_ci'),
            ),
            'information_schema.COLUMNS' => array(
                array('TABLE_NAME' => 'roles', 'COLUMN_NAME' => 'id', 'ORDINAL_POSITION' => 1, 'COLUMN_DEFAULT' => null, 'IS_NULLABLE' => 'NO', 'COLUMN_TYPE' => 'int(11)', 'CHARACTER_SET_NAME' => null, 'COLLATION_NAME' => null, 'EXTRA' => 'auto_increment', 'COLUMN_COMMENT' => ''),
                array('TABLE_NAME' => 'roles', 'COLUMN_NAME' => 'name', 'ORDINAL_POSITION' => 2, 'COLUMN_DEFAULT' => "''", 'IS_NULLABLE' => 'NO', 'COLUMN_TYPE' => 'varchar(100)', 'CHARACTER_SET_NAME' => 'utf8mb3', 'COLLATION_NAME' => 'utf8mb3_bin', 'EXTRA' => '', 'COLUMN_COMMENT' => ''),
                array('TABLE_NAME' => 'roles', 'COLUMN_NAME' => 'created', 'ORDINAL_POSITION' => 3, 'COLUMN_DEFAULT' => 'unix_timestamp()', 'IS_NULLABLE' => 'NO', 'COLUMN_TYPE' => 'int(11)', 'CHARACTER_SET_NAME' => null, 'COLLATION_NAME' => null, 'EXTRA' => '', 'COLUMN_COMMENT' => ''),
                // A column of a table the TABLES query did not list (a view,
                // say) is ignored.
                array('TABLE_NAME' => 'some_view', 'COLUMN_NAME' => 'x', 'ORDINAL_POSITION' => 1, 'COLUMN_DEFAULT' => null, 'IS_NULLABLE' => 'YES', 'COLUMN_TYPE' => 'int(11)', 'CHARACTER_SET_NAME' => null, 'COLLATION_NAME' => null, 'EXTRA' => '', 'COLUMN_COMMENT' => ''),
            ),
            'information_schema.STATISTICS' => array(
                array('TABLE_NAME' => 'roles', 'INDEX_NAME' => 'PRIMARY', 'SEQ_IN_INDEX' => 1, 'COLUMN_NAME' => 'id', 'NON_UNIQUE' => 0, 'SUB_PART' => null, 'INDEX_TYPE' => 'BTREE'),
                array('TABLE_NAME' => 'roles', 'INDEX_NAME' => 'name', 'SEQ_IN_INDEX' => 1, 'COLUMN_NAME' => 'name', 'NON_UNIQUE' => 1, 'SUB_PART' => null, 'INDEX_TYPE' => 'BTREE'),
            ),
        );
        $schema = $generator->readSchema();

        $this->assertSame(array('roles'), array_keys($schema));
        $this->assertSame('id', $schema['roles']['primary']);
        $this->assertSame('primary', $schema['roles']['columns']['id']['key']);
        $this->assertSame(
            array('type' => 'string', 'length' => 100, 'null' => false, 'default' => '', 'collate' => 'utf8mb3_bin', 'charset' => 'utf8mb3'),
            $schema['roles']['columns']['name']
        );
        $this->assertSame(array('created' => 'unix_timestamp()'), $schema['roles']['expressionDefaults']);
        $this->assertSame(array('name'), array_keys($schema['roles']['indexes']));
        $this->assertSame(
            array('engine' => 'InnoDB', 'charset' => 'utf8mb4', 'collate' => 'utf8mb4_unicode_ci'),
            $schema['roles']['options']
        );
        foreach ($generator->asked as $sql) {
            $this->assertStringContainsString("TABLE_SCHEMA = 'reference'", $sql);
        }
    }

    public function testSeedRowsComeOnlyFromSeedTablesAndOnlyTheSettingsAFreshInstallNeeds()
    {
        $generator = $this->generator();
        $schema = $this->fixtureSchema();
        $generator->answers = array(
            '`reference`.`admin_settings`' => array(array('id' => '1', 'setting' => 'db_version', 'value' => '159')),
            '`reference`.`roles`' => array(array('id' => '1', 'name' => 'admin', 'created' => null, 'perm_add' => '1')),
        );
        $seeds = $generator->readSeedRows($schema);

        // correlations is a table, not a seed table; system_settings neither.
        $this->assertSame(array('admin_settings', 'roles'), array_keys($seeds));
        $settingsSql = null;
        foreach ($generator->asked as $sql) {
            if (strpos($sql, '`reference`.`admin_settings`') !== false) {
                $settingsSql = $sql;
            }
            $this->assertStringNotContainsString('`correlations`', $sql);
        }
        $this->assertStringContainsString("WHERE `setting` IN ('db_version', 'default_role', 'fix_login')", $settingsSql);
        $this->assertStringContainsString('ORDER BY `id`', $settingsSql);
    }

    public function testTheReferencesVersionIsRead()
    {
        $generator = $this->generator();
        $this->assertNull($generator->databaseVersion());
        $generator->answers = array('db_version' => array(array('value' => '159')));
        $this->assertSame(159, $generator->databaseVersion());
    }

    // ---------------------------------------------------------- verification

    /**
     * The fixture is the reference; the loaded datasource above deviates from
     * it in exactly six ways, and the comparison names each one - and nothing
     * else, which is the half that matters: the quoted "1_event_id", the
     * boolean default reported as a PHP false, the expression default spelled
     * PostgreSQL's way, the hash-rewritten index and the key column's dropped
     * default are all the round trip being *right*.
     */
    public function testTheRoundTripComparisonNamesEveryDeviationAndNothingElse()
    {
        $inspector = new SchemaInspector(new BaselineGeneratorTestLoadedPostgres());
        $findings = $this->generator()->compare($inspector, $this->fixtureSchema());
        $this->assertSame(array(
            'admin_settings.surplus: column not in the reference',
            'admin_settings: index idx_admin_settings_setting is not unique, expected unique',
            'admin_settings: index idx_admin_settings_stray not in the reference',
            'roles.name: length 191, expected 100',
            'roles.perm_add: not null, expected nullable',
            'leftover: table not in the reference',
        ), $findings);
    }

    public function testAnExactRoundTripHasNoFindings()
    {
        $db = new BaselineGeneratorTestLoadedPostgres();
        $db->tables = array('correlations', 'roles', 'system_settings');
        $db->descriptions['roles']['name']['length'] = 100;
        $db->descriptions['roles']['perm_add']['null'] = true;
        $inspector = new SchemaInspector($db);
        $schema = $this->fixtureSchema();
        unset($schema['admin_settings']);
        $this->assertSame(array(), $this->generator()->compare($inspector, $schema));
    }
}
