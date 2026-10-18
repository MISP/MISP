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

/**
 * The same for a MySQL-family server; its version says which family.
 */
class BaselineGeneratorTestLoadedMysql extends MigrationTestMysqlExtended
{
    public $tables = array();

    public $descriptions = array();

    public $indexData = array();

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

/**
 * What the catalog says beside describe() and index(): tableDefinition() and
 * databaseDefaults() as scripted. A table without a definition gets none of
 * the catalog checks.
 */
class BaselineGeneratorTestLoadedInspector extends SchemaInspector
{
    /** @var array table => tableDefinition() */
    public $definitions = array();

    /** @var array|null */
    public $database;

    /** @var BaselineGeneratorTestLoadedMysql|null What describe() and index() read. */
    public $loadedDb;

    public function tableDefinition($table)
    {
        return isset($this->definitions[$table]) ? $this->definitions[$table] : null;
    }

    public function databaseDefaults()
    {
        return $this->database;
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
            array('mediumblob', array('type' => 'binary')),
            array('longblob', array('type' => 'longblob')),
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

    /**
     * PostgreSQL leaves out a non-unique prefix index over several columns
     * with a text one among them: the rendering notes it, and the comparison
     * does not ask a loaded PostgreSQL database for it.
     */
    public function testACompositeTextPrefixIndexIsLeftOutOnPostgres()
    {
        $columns = array('value1' => array('type' => 'text'), 'name' => array('type' => 'string', 'length' => 255));
        $composite = array('column' => array('name', 'value1'), 'unique' => false, 'length' => array('value1' => 191));
        $this->assertTrue(BaselineGenerator::isMysqlOnly($composite, $columns));
        $unique = array_merge($composite, array('unique' => true));
        $this->assertFalse(BaselineGenerator::isMysqlOnly($unique, $columns), 'a unique key is never left out');
        $varchar = array('column' => array('value1', 'name'), 'unique' => false, 'length' => array('name' => 191));
        $this->assertFalse(BaselineGenerator::isMysqlOnly($varchar, $columns), 'a varchar prefix fits a btree entry');
        $single = array('column' => array('value1'), 'unique' => false, 'length' => array('value1' => 191));
        $this->assertFalse(BaselineGenerator::isMysqlOnly($single, $columns), 'one text column becomes a hash index');

        $schema = $this->fixtureSchema();
        $schema['correlations']['indexes']['idx_corr_evt_value'] = array(
            'name' => 'idx_corr_evt_value',
            'column' => array('1_event_id', 'value1'),
            'unique' => false,
            'length' => array('value1' => 191),
        );
        $mysql = $this->generator()->render($this->mysql, $schema, array(), 159);
        $this->assertStringContainsString('`idx_corr_evt_value` (`1_event_id`, `value1`(191))', $mysql['sql']);
        $pgsql = $this->generator()->render($this->pgsql, $schema, array(), 159);
        $this->assertStringNotContainsString('idx_corr_evt_value', $pgsql['sql']);
        $this->assertContains(
            'Index idx_corr_evt_value on correlations(1_event_id, value1) left out: a prefix over text in a composite index has no PostgreSQL equivalent.',
            $pgsql['notes']
        );

        $inspector = new BaselineGeneratorTestLoadedInspector(new BaselineGeneratorTestLoadedPostgres());
        $this->assertSame(
            $this->generator()->compare($inspector, $this->fixtureSchema()),
            $this->generator()->compare($inspector, $schema)
        );
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

        // The identity key and the flag.
        $this->assertStringContainsString('"id" integer GENERATED BY DEFAULT AS IDENTITY,', $sql);
        $this->assertStringContainsString("\"deleted\" boolean DEFAULT 'FALSE' NOT NULL", $sql);
        $this->assertStringContainsString('PRIMARY KEY ("id")', $sql);

        // The expression default lands after the table exists.
        $this->assertStringContainsString(
            'ALTER TABLE "correlations" ALTER COLUMN "created" SET DEFAULT FLOOR(EXTRACT(EPOCH FROM NOW()))::integer;',
            $sql
        );

        // A string key is NOT NULL plus a PRIMARY KEY clause; no identity.
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

        // Explicit ids were seeded, so every key sequence is caught up.
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
            $this->generator()->compare(new BaselineGeneratorTestLoadedInspector($db), $schema)
        );

        $db->indexData['tags']['idx_tags_name_lower'] = array('unique' => true, 'column' => 'lower(name)');
        $this->assertSame(array(), $this->generator()->compare(new BaselineGeneratorTestLoadedInspector($db), $schema));
    }

    /**
     * attribute_values: the FULLTEXT index has no PostgreSQL rendering and the
     * value(128) prefix index would become a hash index, so the PostgreSQL
     * baseline carries what the migration declares for PostgreSQL, with
     * pg_trgm ahead of it; the MySQL one builds the FULLTEXT index without
     * stopwords, as the migration that creates it.
     */
    private function valueDictionarySchema()
    {
        return array(
            'attribute_values' => array(
                'columns' => array(
                    'id' => array('type' => 'biginteger', 'length' => 20, 'unsigned' => true, 'null' => false, 'key' => 'primary'),
                    'value' => array('type' => 'text', 'null' => false),
                    'hash' => array('type' => 'varbinary', 'length' => 16, 'null' => false),
                ),
                'indexes' => array(
                    'hash' => array('name' => 'hash', 'column' => array('hash'), 'unique' => true),
                    'value' => array('name' => 'value', 'column' => array('value'), 'unique' => false, 'length' => array('value' => 128)),
                    'value_search' => array('name' => 'value_search', 'column' => array('value'), 'unique' => false, 'fulltext' => true),
                ),
                'primary' => 'id',
                // As readSchema() reads a MariaDB reference's utf8mb4_uca1400_ai_ci
                'options' => array('engine' => 'InnoDB', 'collate' => Collation::CI),
                'expressionDefaults' => array(),
            ),
        );
    }

    public function testTheValueDictionaryRendersTheIndexesItsMigrationDeclares()
    {
        $pgsql = $this->generator()->render($this->pgsql, $this->valueDictionarySchema(), array(), 159);
        $sql = $pgsql['sql'];
        $extension = strpos($sql, "BEGIN;\nCREATE EXTENSION IF NOT EXISTS pg_trgm;\n");
        $this->assertNotFalse($extension);
        $this->assertLessThan(strpos($sql, 'CREATE TABLE'), $extension);
        $this->assertStringContainsString('CREATE UNIQUE INDEX "idx_attribute_values_hash" ON "attribute_values" ("hash");', $sql);
        $this->assertStringContainsString('CREATE INDEX "idx_attribute_values_value" ON "attribute_values" (lower(left("value", 128)));', $sql);
        $this->assertStringContainsString('CREATE INDEX "idx_attribute_values_value_search" ON "attribute_values" USING gin ("value" gin_trgm_ops);', $sql);
        $this->assertStringNotContainsString('USING hash', $sql);
        $this->assertCount(3, $pgsql['notes']);
        $this->assertStringContainsString('Extension pg_trgm created', $pgsql['notes'][0]);
        $this->assertStringContainsString('Index value on attribute_values rendered as idx_attribute_values_value', $pgsql['notes'][1]);
        $this->assertStringContainsString('Index value_search on attribute_values rendered as idx_attribute_values_value_search', $pgsql['notes'][2]);

        $mariadb = $this->generator()->render(BaselineGenerator::grammar('mariadb'), $this->valueDictionarySchema(), array(), 159);
        $sql = $mariadb['sql'];
        $this->assertStringNotContainsString('pg_trgm', $sql);
        $this->assertStringContainsString('INDEX `value` (`value`(128))', $sql);
        $this->assertStringContainsString('FULLTEXT INDEX `value_search` (`value`)', $sql);
        $off = strpos($sql, 'SET SESSION innodb_ft_enable_stopword = 0;');
        $back = strpos($sql, 'SET SESSION innodb_ft_enable_stopword = DEFAULT;');
        $this->assertNotFalse($off);
        $this->assertLessThan(strpos($sql, 'CREATE TABLE `attribute_values`'), $off);
        $this->assertGreaterThan(strpos($sql, 'FULLTEXT INDEX'), $back);
        // Each MySQL-family baseline carries its own server's name for the token
        $this->assertStringContainsString('`id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT', $sql);
        $this->assertStringContainsString(') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;', $sql);

        $mysql = $this->generator()->render(BaselineGenerator::grammar('mysql'), $this->valueDictionarySchema(), array(), 159);
        $sql = $mysql['sql'];
        $this->assertStringContainsString('FULLTEXT INDEX `value_search` (`value`)', $sql);
        $this->assertStringContainsString('`id` bigint UNSIGNED NOT NULL AUTO_INCREMENT', $sql);
        $this->assertStringContainsString(') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;', $sql);
        $this->assertStringNotContainsString('uca1400', $sql);

        $other = $this->generator()->render($this->mysql, $this->fixtureSchema(), array(), 159);
        $this->assertStringNotContainsString('innodb_ft_enable_stopword', $other['sql']);
    }

    public function testTheBaselineSetsTheDatabaseDefaultCollation()
    {
        $mariadb = $this->generator()->render(BaselineGenerator::grammar('mariadb'), $this->fixtureSchema(), array(), 159);
        $this->assertStringContainsString('ALTER DATABASE CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci;', $mariadb['sql']);
        $mysql = $this->generator()->render(BaselineGenerator::grammar('mysql'), $this->fixtureSchema(), array(), 159);
        $this->assertStringContainsString('ALTER DATABASE CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci;', $mysql['sql']);
        $pgsql = $this->generator()->render($this->pgsql, $this->fixtureSchema(), array(), 159);
        $this->assertStringNotContainsString('ALTER DATABASE', $pgsql['sql']);
    }

    public function testTheRoundTripReadsTheShapeOfAReplacedIndex()
    {
        $db = new BaselineGeneratorTestLoadedPostgres();
        $db->tables = array('attribute_values');
        $db->descriptions = array('attribute_values' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'default' => null, 'length' => null, 'key' => 'primary'),
            'value' => array('type' => 'text', 'null' => false, 'default' => null, 'length' => null),
            'hash' => array('type' => 'binary', 'null' => false, 'default' => null, 'length' => null),
        ));
        $db->indexData = array('attribute_values' => array(
            'PRIMARY' => array('unique' => true, 'column' => 'id'),
            'idx_attribute_values_hash' => array('unique' => true, 'column' => 'hash'),
            // What the hash rewrite used to create under the expression index's name
            'idx_attribute_values_value' => array('unique' => false, 'column' => 'value'),
        ));
        $schema = $this->valueDictionarySchema();
        $this->assertSame(array(
            'attribute_values: index idx_attribute_values_value over (value), not the index its migration declares',
            'attribute_values: index idx_attribute_values_value_search missing',
        ), $this->generator()->compare(new BaselineGeneratorTestLoadedInspector($db), $schema));

        // As Postgres::index() parses pg_get_indexdef() for the two
        $db->indexData['attribute_values']['idx_attribute_values_value'] = array('unique' => false, 'column' => array('lower("left"(value', '128'));
        $db->indexData['attribute_values']['idx_attribute_values_value_search'] = array('unique' => false, 'column' => 'value gin_trgm_ops');
        $this->assertSame(array(), $this->generator()->compare(new BaselineGeneratorTestLoadedInspector($db), $schema));
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
                . "(1, 'admin\\'s', NOW(), '1'),\n"
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

    /**
     * One reference, three baselines, each named for and rendered for its
     * server; a legacy collation goes through as the reference names it.
     */
    public function testEachEngineGetsItsOwnBaseline()
    {
        $this->assertSame(array('mariadb', 'mysql', 'pgsql'), BaselineGenerator::engines());
        $schema = $this->fixtureSchema();
        $schema['roles']['columns']['name']['collate'] = Collation::CI;
        $schema['roles']['columns']['name']['default'] = '';
        $seeds = array('roles' => array(
            array('id' => '1', 'name' => '%ALLUSERSPROFILE%\\\\', 'created' => null, 'perm_add' => '1'),
        ));
        $rendered = array();
        foreach (BaselineGenerator::engines() as $engine) {
            $rendered[$engine] = $this->generator()->render(BaselineGenerator::grammar($engine), $schema, $seeds, 159)['sql'];
        }

        $this->assertStringStartsWith('-- MISP MariaDB install baseline, equivalent to db_version 159.', $rendered['mariadb']);
        $this->assertStringStartsWith('-- MISP MySQL install baseline, equivalent to db_version 159.', $rendered['mysql']);
        $this->assertStringStartsWith('-- MISP PostgreSQL install baseline, equivalent to db_version 159.', $rendered['pgsql']);

        $this->assertStringContainsString("`name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_uca1400_ai_ci DEFAULT '' NOT NULL", $rendered['mariadb']);
        $this->assertStringContainsString("`name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci DEFAULT '' NOT NULL", $rendered['mysql']);
        $this->assertStringContainsString("\"name\" varchar(100) DEFAULT '' NOT NULL", $rendered['pgsql']);

        $this->assertStringContainsString('`1_event_id` int(11) NOT NULL', $rendered['mariadb']);
        $this->assertStringContainsString('`1_event_id` int NOT NULL', $rendered['mysql']);
        $this->assertStringContainsString("`deleted` tinyint(1) DEFAULT '0' NOT NULL", $rendered['mysql']);
        foreach (array('mariadb', 'mysql') as $engine) {
            $this->assertStringContainsString(') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;', $rendered[$engine]);
            // The value holds two backslashes; MySQL reads each escaped
            $this->assertStringContainsString("(1, '%ALLUSERSPROFILE%\\\\\\\\', NULL, '1')", $rendered[$engine]);
        }
        $this->assertStringContainsString("(1, '%ALLUSERSPROFILE%\\\\', NULL, 'TRUE')", $rendered['pgsql']);
    }

    public function testAnUnknownEngineHasNoBaseline()
    {
        $this->expectException('InvalidArgumentException');
        $this->expectExceptionMessage('Known engines are: mariadb, mysql, pgsql.');
        BaselineGenerator::grammar('mssql');
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
                array('TABLE_NAME' => 'roles', 'ENGINE' => 'InnoDB', 'TABLE_COLLATION' => 'utf8mb4_unicode_ci', 'ROW_FORMAT' => 'Dynamic'),
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
        // The row format stays out of the options createTable() is handed
        $this->assertSame(
            array('engine' => 'InnoDB', 'charset' => 'utf8mb4', 'collate' => 'utf8mb4_unicode_ci'),
            $schema['roles']['options']
        );
        $this->assertSame('DYNAMIC', $schema['roles']['row_format']);
        foreach ($generator->asked as $sql) {
            $this->assertStringContainsString("TABLE_SCHEMA = 'reference'", $sql);
        }
    }

    private static function collationRows($table, array $collations)
    {
        $rows = array();
        $position = 0;
        foreach ($collations as $column => $collation) {
            $rows[] = array(
                'TABLE_NAME' => $table, 'COLUMN_NAME' => $column, 'ORDINAL_POSITION' => ++$position,
                'COLUMN_DEFAULT' => null, 'IS_NULLABLE' => 'NO', 'COLUMN_TYPE' => 'varchar(40)',
                'CHARACTER_SET_NAME' => strstr($collation, '_', true), 'COLLATION_NAME' => $collation,
                'EXTRA' => '', 'COLUMN_COMMENT' => '',
            );
        }
        return $rows;
    }

    /**
     * Only a collation in its server's target form is read as the token;
     * everything else stays as the reference names it.
     */
    public function testATargetCollationIsReadAsItsToken()
    {
        $collations = array(
            'ci' => 'utf8mb4_uca1400_ai_ci',
            'bin' => 'utf8mb4_bin',
            'uuid' => 'ascii_bin',
            'mysql_ci' => 'utf8mb4_unicode_520_ci',
            'legacy' => 'utf8mb3_bin',
            'legacy_ascii' => 'ascii_general_ci',
        );

        $generator = $this->generator();
        $generator->answers = array(
            'information_schema.TABLES' => array(
                array('TABLE_NAME' => 't', 'ENGINE' => 'InnoDB', 'TABLE_COLLATION' => 'utf8mb4_uca1400_ai_ci'),
                array('TABLE_NAME' => 'old', 'ENGINE' => 'InnoDB', 'TABLE_COLLATION' => 'utf8mb3_general_ci'),
            ),
            'information_schema.COLUMNS' => self::collationRows('t', $collations),
        );
        $schema = $generator->readSchema();
        $this->assertSame(array('engine' => 'InnoDB', 'collate' => Collation::CI), $schema['t']['options']);
        $this->assertSame(
            array('engine' => 'InnoDB', 'charset' => 'utf8mb3', 'collate' => 'utf8mb3_general_ci'),
            $schema['old']['options']
        );
        $read = array();
        foreach ($schema['t']['columns'] as $name => $spec) {
            $read[$name] = isset($spec['collate']) ? array($spec['collate'], isset($spec['charset']) ? $spec['charset'] : null) : null;
        }
        $this->assertSame(array(
            // the table's own collation, so the column inherits it
            'ci' => null,
            'bin' => array(Collation::BIN, null),
            'uuid' => array(Collation::ASCII, null),
            'mysql_ci' => array('utf8mb4_unicode_520_ci', 'utf8mb4'),
            'legacy' => array('utf8mb3_bin', 'utf8mb3'),
            'legacy_ascii' => array('ascii_general_ci', 'ascii'),
        ), $read);

        // On a MySQL reference, its own name is the token's
        $generator = new BaselineGeneratorTestStub(new MigrationTestMysqlExtended('8.4.6'), 'reference');
        $generator->mariadb = false;
        $generator->answers = array(
            'information_schema.TABLES' => array(
                array('TABLE_NAME' => 't', 'ENGINE' => 'InnoDB', 'TABLE_COLLATION' => 'utf8mb4_bin'),
            ),
            'information_schema.COLUMNS' => self::collationRows('t', $collations),
        );
        $columns = $generator->readSchema()['t']['columns'];
        $this->assertSame(Collation::CI, $columns['mysql_ci']['collate']);
        $this->assertSame('utf8mb4_uca1400_ai_ci', $columns['ci']['collate']);
        $this->assertSame(array('engine' => 'InnoDB', 'collate' => Collation::BIN), $generator->readSchema()['t']['options']);
    }

    public function testTheReferenceServerHasToBeKnown()
    {
        $generator = new BaselineGeneratorTestStub(new MigrationTestMysql(), 'reference');
        $this->expectException('RuntimeException');
        $this->expectExceptionMessage('does not say whether it is MariaDB or MySQL');
        $generator->readSchema();
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

    public function testTheReferencesAppliedMigrationsAreRead()
    {
        $generator = $this->generator();
        $this->assertSame(array(), $generator->appliedMigrations(), 'no ledger table');
        $this->assertCount(1, $generator->asked, 'the ledger is not read when it does not exist');

        $generator->answers = array(
            'information_schema.TABLES' => array(array('1' => '1')),
            '`schema_migrations`' => array(array('id' => '20261003_092429_create_attribute_values')),
        );
        $this->assertSame(array('20261003_092429_create_attribute_values'), $generator->appliedMigrations());
        $this->assertStringContainsString("WHERE `status` = 'applied'", end($generator->asked));
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
        $inspector = new BaselineGeneratorTestLoadedInspector(new BaselineGeneratorTestLoadedPostgres());
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
        $inspector = new BaselineGeneratorTestLoadedInspector($db);
        $schema = $this->fixtureSchema();
        unset($schema['admin_settings']);
        $this->assertSame(array(), $this->generator()->compare($inspector, $schema));
    }

    /**
     * As readSchema() reads a MariaDB reference: the target collations as
     * tokens, D21's ascii_general_ci by name.
     */
    private function catalogSchema()
    {
        return array(
            'events' => array(
                'columns' => array(
                    'id' => array('type' => 'biginteger', 'length' => 20, 'null' => false, 'key' => 'primary'),
                    'uuid' => array('type' => 'string', 'length' => 36, 'null' => false, 'collate' => Collation::ASCII),
                    'info' => array('type' => 'text', 'null' => false),
                    'object_type' => array('type' => 'string', 'length' => 80, 'null' => false, 'collate' => 'ascii_general_ci', 'charset' => 'ascii'),
                    'counter' => array('type' => 'integer', 'length' => 10, 'unsigned' => true, 'null' => false, 'default' => '0'),
                    'org_id' => array('type' => 'integer', 'length' => 11, 'null' => false),
                ),
                'indexes' => array(
                    'info' => array('name' => 'info', 'column' => array('info'), 'unique' => false, 'length' => array('info' => 255)),
                    'info_search' => array('name' => 'info_search', 'column' => array('info'), 'unique' => false, 'fulltext' => true),
                    'uuid' => array('name' => 'uuid', 'column' => array('uuid'), 'unique' => true),
                ),
                'primary' => 'id',
                'options' => array('engine' => 'InnoDB', 'collate' => Collation::CI),
                'expressionDefaults' => array(),
                'row_format' => 'DYNAMIC',
            ),
        );
    }

    /**
     * A loaded MySQL-family server agreeing with catalogSchema() on what
     * describe() and index() report, and on the catalog as given.
     *
     * @param string $version
     * @param string $ci The server's name for Collation::CI.
     * @return BaselineGeneratorTestLoadedInspector
     */
    private function loadedMysql($version, $ci)
    {
        $db = new BaselineGeneratorTestLoadedMysql($version);
        $db->tables = array('events');
        $db->descriptions = array('events' => array(
            'id' => array('type' => 'biginteger', 'null' => false, 'default' => null, 'length' => 20, 'key' => 'primary'),
            'uuid' => array('type' => 'string', 'null' => false, 'default' => null, 'length' => 36),
            'info' => array('type' => 'text', 'null' => false, 'default' => null, 'length' => null),
            'object_type' => array('type' => 'string', 'null' => false, 'default' => null, 'length' => 80),
            'counter' => array('type' => 'integer', 'null' => false, 'default' => '0', 'length' => 10),
            'org_id' => array('type' => 'integer', 'null' => false, 'default' => null, 'length' => 11),
        ));
        $db->indexData = array('events' => array(
            'PRIMARY' => array('column' => 'id', 'unique' => 1),
            'info' => array('column' => 'info', 'unique' => 0, 'length' => array('info' => 255)),
            'info_search' => array('column' => 'info', 'unique' => 0, 'type' => 'fulltext'),
            'uuid' => array('column' => 'uuid', 'unique' => 1),
        ));
        $column = function ($collation, $unsigned = false) {
            return array('unsigned' => $unsigned, 'collation' => $collation, 'charset' => $collation === null ? null : strstr($collation, '_', true));
        };
        $index = function ($columns, $length = array(), $type = 'btree') {
            return array('column' => $columns, 'length' => $length, 'type' => $type);
        };
        $inspector = new BaselineGeneratorTestLoadedInspector($db);
        $inspector->definitions['events'] = array(
            'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collation' => $ci, 'charset' => 'utf8mb4'),
            'columns' => array(
                'id' => $column(null),
                'uuid' => $column('ascii_bin'),
                'info' => $column($ci),
                'object_type' => $column('ascii_general_ci'),
                'counter' => $column(null, true),
                'org_id' => $column(null),
            ),
            'indexes' => array(
                'PRIMARY' => $index(array('id')),
                'info' => $index(array('info'), array('info' => 255)),
                'info_search' => $index(array('info'), array(), 'fulltext'),
                'uuid' => $index(array('uuid')),
            ),
        );
        $inspector->database = array('charset' => 'utf8mb4', 'collation' => $ci);
        $inspector->loadedDb = $db;
        return $inspector;
    }

    /**
     * A MariaDB reference against a MySQL server: each token is expected
     * under MySQL's name for it, so the two agree by class.
     */
    public function testTheCatalogComparisonNamesWhatDescribeFoldsAway()
    {
        $schema = $this->catalogSchema();
        $database = array('collate' => Collation::CI);
        $inspector = $this->loadedMysql('8.4.6', 'utf8mb4_unicode_520_ci');
        $this->assertSame(array(), $this->generator()->compare($inspector, $schema, $database));

        $events = &$inspector->definitions['events'];
        $events['options'] = array('engine' => 'MyISAM', 'row_format' => 'COMPACT', 'collation' => 'utf8mb3_general_ci', 'charset' => 'utf8mb3');
        $events['columns']['uuid']['collation'] = 'utf8mb4_bin';
        $events['columns']['info']['collation'] = 'utf8mb3_general_ci';
        $events['columns']['counter']['unsigned'] = false;
        $events['columns']['org_id']['unsigned'] = true;
        $events['indexes']['info']['length'] = array('info' => 64);
        $events['indexes']['info_search']['type'] = 'btree';
        $events['indexes']['uuid']['length'] = array('uuid' => 16);
        $inspector->database['collation'] = 'latin1_swedish_ci';
        $this->assertSame(array(
            'database: default collation latin1_swedish_ci, expected utf8mb4_unicode_520_ci (<CI>)',
            'events: engine MyISAM, expected InnoDB',
            'events: row format COMPACT, expected DYNAMIC',
            'events: default collation utf8mb3_general_ci, expected utf8mb4_unicode_520_ci (<CI>)',
            'events.uuid: collation utf8mb4_bin, expected ascii_bin (<ASCII>)',
            'events.info: collation utf8mb3_general_ci, expected utf8mb4_unicode_520_ci (<CI>)',
            'events.counter: signed, expected unsigned',
            'events.org_id: unsigned, expected signed',
            'events: index info over (info(64)), expected (info(255))',
            'events: index info_search is not FULLTEXT, expected FULLTEXT',
            'events: index uuid over (uuid(16)), expected (uuid)',
        ), $this->generator()->compare($inspector, $schema, $database));

        // Without the reference's own default, the database's is not compared
        $this->assertNotContains(
            'database: default collation latin1_swedish_ci, expected utf8mb4_unicode_520_ci (<CI>)',
            $this->generator()->compare($inspector, $schema)
        );
    }

    /**
     * describe() reads every text and blob size as text or binary; the
     * catalog tells them apart, a longblob from a blob among them.
     */
    public function testTheCatalogComparisonNamesTheTextAndBlobTiers()
    {
        $schema = $this->catalogSchema();
        $schema['events']['columns']['payload'] = array('type' => 'longblob', 'null' => true);
        $database = array('collate' => Collation::CI);
        $inspector = $this->loadedMysql('8.4.6', 'utf8mb4_unicode_520_ci');
        $inspector->loadedDb->descriptions['events']['payload'] = array('type' => 'binary', 'null' => true, 'default' => null, 'length' => null);
        $events = &$inspector->definitions['events'];
        $events['columns']['payload'] = array('type' => 'longblob', 'unsigned' => false, 'collation' => null, 'charset' => null);
        $events['columns']['info']['type'] = 'text';
        $this->assertSame(array(), $this->generator()->compare($inspector, $schema, $database));

        $events['columns']['payload']['type'] = 'blob';
        $events['columns']['info']['type'] = 'mediumtext';
        $this->assertSame(array(
            'events.info: mediumtext, expected text',
            'events.payload: blob, expected longblob',
        ), $this->generator()->compare($inspector, $schema, $database));
    }

    /**
     * MariaDB has unicode_520_ci too, but its <CI> is uca1400_ai_ci: by class
     * means the loaded server's own name for the class, not any CI collation.
     */
    public function testACollationIsExpectedUnderTheLoadedServersOwnName()
    {
        $schema = $this->catalogSchema();
        $inspector = $this->loadedMysql('10.11.14-MariaDB', 'utf8mb4_uca1400_ai_ci');
        $this->assertSame(array(), $this->generator()->compare($inspector, $schema));

        $inspector->definitions['events']['columns']['info']['collation'] = 'utf8mb4_unicode_520_ci';
        $inspector->definitions['events']['columns']['object_type']['collation'] = 'ascii_bin';
        $this->assertSame(array(
            'events.info: collation utf8mb4_unicode_520_ci, expected utf8mb4_uca1400_ai_ci (<CI>)',
            'events.object_type: collation ascii_bin, expected ascii_general_ci',
        ), $this->generator()->compare($inspector, $schema));
    }

    public function testTheLoadedServerHasToBeKnown()
    {
        $inspector = $this->loadedMysql('', 'utf8mb4_uca1400_ai_ci');
        $this->expectException('RuntimeException');
        $this->expectExceptionMessage('The loaded server reports its version as ""');
        $this->generator()->compare($inspector, $this->catalogSchema());
    }

    /**
     * PostgreSQL has no collations, charsets, unsigned or row formats to
     * compare: a column must not carry a collation of its own, and a prefix
     * index over text must be the hash index its rendering makes of it.
     */
    public function testOnPostgresTheCatalogHoldsNoCollationAndAPrefixIndexKeepsItsRendering()
    {
        $db = new BaselineGeneratorTestLoadedPostgres();
        $db->tables = array('correlations', 'roles', 'system_settings');
        $db->descriptions['roles']['name']['length'] = 100;
        $db->descriptions['roles']['perm_add']['null'] = true;
        $inspector = new BaselineGeneratorTestLoadedInspector($db);
        $inspector->database = array('charset' => 'utf8mb4', 'collation' => 'utf8mb4_bin');
        $inspector->definitions['correlations'] = array(
            'options' => array('engine' => null, 'row_format' => null, 'collation' => null, 'charset' => null),
            'columns' => array(
                'id' => array('unsigned' => false, 'collation' => null),
                '1_event_id' => array('unsigned' => false, 'collation' => null),
                'value1' => array('unsigned' => false, 'collation' => 'C'),
                'deleted' => array('unsigned' => false, 'collation' => null),
                'created' => array('unsigned' => false, 'collation' => null),
            ),
            'indexes' => array(
                'PRIMARY' => array('column' => array('id'), 'length' => array(), 'type' => 'btree'),
                'idx_correlations_1_event_id' => array('column' => array('1_event_id'), 'length' => array(), 'type' => 'btree'),
                'idx_correlations_value1' => array('column' => array('value1'), 'length' => array(), 'type' => 'btree'),
            ),
        );
        $schema = $this->fixtureSchema();
        unset($schema['admin_settings']);
        $database = array('collate' => Collation::CI);
        $this->assertSame(array(
            'correlations.value1: collation C, expected the database default',
            'correlations: index idx_correlations_value1 is a btree index, expected hash',
        ), $this->generator()->compare($inspector, $schema, $database));

        $inspector->definitions['correlations']['columns']['value1']['collation'] = null;
        $inspector->definitions['correlations']['indexes']['idx_correlations_value1']['type'] = 'hash';
        $this->assertSame(array(), $this->generator()->compare($inspector, $schema, $database));
    }

    public function testTheReferencesDatabaseDefaultIsReadAsItsToken()
    {
        $generator = $this->generator();
        $this->assertNull($generator->readDatabaseDefaults());
        $this->assertStringContainsString("SCHEMA_NAME = 'reference'", $generator->asked[0]);

        $generator->answers = array('information_schema.SCHEMATA' => array(array('collation' => 'utf8mb4_uca1400_ai_ci')));
        $this->assertSame(array('collate' => Collation::CI), $generator->readDatabaseDefaults());
        $generator->answers = array('information_schema.SCHEMATA' => array(array('collation' => 'latin1_swedish_ci')));
        $this->assertSame(array('collate' => 'latin1_swedish_ci'), $generator->readDatabaseDefaults());
    }
}
