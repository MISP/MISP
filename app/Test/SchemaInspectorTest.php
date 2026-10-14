<?php
/**
 * SchemaInspector tests - the check-then-act surface the migration system uses
 * to make its DDL re-runnable, and the cache contract that makes its answers
 * true.
 *
 * The cache contract is the part worth testing without a database, because it
 * is the part that fails silently. CakePHP keeps three caches of the schema and
 * only one of them has a public clear; the lever that actually works is the
 * `cacheSources` flag, which makes listSources()/describe()/_cacheDescription()
 * bypass all three. So these tests assert not just *what* the inspector
 * answers, but that every read was taken with that flag down and that the flag
 * came back up afterwards - including when the read threw.
 *
 * The other thing pinned here is the hasTable() guard on hasColumn(). It is not
 * defensive style: Mysql::describe() throws a CakeException for a table that
 * does not exist rather than returning empty, and "does this column exist on a
 * table that isn't there" is an ordinary question for a migration to ask.
 *
 * @see MigrationSchemaStubs.php for how the real Cake drivers are loaded without a connection.
 */

require_once __DIR__ . '/MigrationSchemaStubs.php';

use PHPUnit\Framework\TestCase;

if (!class_exists('SchemaInspectorTestMysql', false)) {
    /**
     * A connectionless MySQL datasource with a fixed schema, which records the
     * state of cacheSources at the moment each read was taken.
     */
    class SchemaInspectorTestMysql extends MigrationTestMysql
    {
        public $tables = array('events', 'attributes');

        public $descriptions = array(
            'events' => array(
                'id' => array('type' => 'integer', 'null' => false),
                'uuid' => array('type' => 'string', 'null' => false, 'length' => 40),
                'info' => array('type' => 'text', 'null' => true),
            ),
        );

        public $indexData = array(
            'events' => array(
                'PRIMARY' => array('column' => 'id', 'unique' => 1),
                'uuid' => array('column' => 'uuid', 'unique' => 1),
                'info' => array('column' => 'info', 'unique' => 0, 'length' => array('info' => 16)),
                'lookup' => array('column' => array('org_id', 'date'), 'unique' => 0),
                // As Postgres::index() reports a digit-leading column: quoted.
                '1_event_id' => array('column' => '"1_event_id"', 'unique' => 0),
                'pair' => array('column' => array('"1_event_id"', 'event_id'), 'unique' => 0),
            ),
        );

        /** @var array cacheSources as seen inside each read, keyed by method. */
        public $cacheStateDuringRead = array();

        /** @var int */
        public $describeCalls = 0;

        /** @var bool Make the next describe() blow up, to test the finally. */
        public $describeThrows = false;

        public function listSources($data = null)
        {
            $this->cacheStateDuringRead['listSources'] = $this->cacheSources;
            return $this->tables;
        }

        public function describe($model)
        {
            $this->describeCalls++;
            $this->cacheStateDuringRead['describe'] = $this->cacheSources;
            if ($this->describeThrows) {
                throw new RuntimeException('describe blew up');
            }
            // Mirrors Mysql::describe(), which throws rather than returning
            // empty for a table it cannot see.
            if (!isset($this->descriptions[$model])) {
                throw new RuntimeException('Could not describe table for ' . $model);
            }
            return $this->descriptions[$model];
        }

        public function index($model)
        {
            $this->cacheStateDuringRead['index'] = $this->cacheSources;
            return isset($this->indexData[$model]) ? $this->indexData[$model] : array();
        }
    }
}

if (!class_exists('SchemaInspectorTestReader', false)) {
    /**
     * An inspector whose one connection-touching method is replaced.
     *
     * The runtime surface queries the catalog directly rather than through the
     * driver, so - unlike the schema surface above - it cannot be exercised by
     * overriding listSources()/describe()/index() on a connectionless
     * datasource. fetchRows() is the single seam where this class reaches a
     * real connection, so standing in for it leaves the SQL each engine builds
     * and the shaping of the rows both under test, which is the whole of what
     * these methods do.
     */
    class SchemaInspectorTestReader extends SchemaInspector
    {
        /** @var array Every statement fetchRows() was asked to run, in order. */
        public $queries = array();

        /** @var array Canned result sets, handed back one per call. */
        public $results = array();

        /** @var array SQL fragment => result set, tried before $results. */
        public $answers = array();

        protected function fetchRows($sql)
        {
            $this->queries[] = $sql;
            foreach ($this->answers as $needle => $rows) {
                if (strpos($sql, $needle) !== false) {
                    return $rows;
                }
            }
            return empty($this->results) ? array() : array_shift($this->results);
        }
    }
}

class SchemaInspectorTest extends TestCase
{
    /** @var SchemaInspectorTestMysql */
    private $db;

    /** @var SchemaInspector */
    private $inspector;

    protected function setUp(): void
    {
        $this->db = new SchemaInspectorTestMysql();
        $this->inspector = new SchemaInspector($this->db);
    }

    // -------------------------------------------------------------- flavour

    public function testFlavourFollowsTheDriver()
    {
        $this->assertSame(SchemaInspector::FLAVOUR_MYSQL, $this->inspector->flavour());
        $this->assertSame(
            SchemaInspector::FLAVOUR_PGSQL,
            (new SchemaInspector(new MigrationTestPostgres()))->flavour()
        );
    }

    // --------------------------------------------------------------- tables

    public function testHasTable()
    {
        $this->assertTrue($this->inspector->hasTable('events'));
        $this->assertFalse($this->inspector->hasTable('collections'));
    }

    public function testTablesAreReportedAsTheDatabaseSpellsThem()
    {
        $this->assertSame(array('events', 'attributes'), $this->inspector->tables());
    }

    // -------------------------------------------------------------- columns

    public function testHasColumn()
    {
        $this->assertTrue($this->inspector->hasColumn('events', 'uuid'));
        $this->assertFalse($this->inspector->hasColumn('events', 'exposed'));
    }

    /**
     * Mysql::describe() throws for a table it cannot see, so hasColumn() has to
     * ask hasTable() first. Asserted by the absence of a throw *and* by
     * describe() never being reached.
     */
    public function testAskingAboutAColumnOfAMissingTableIsAnAnswerNotAnError()
    {
        $this->assertFalse($this->inspector->hasColumn('collections', 'uuid'));
        $this->assertSame(array(), $this->inspector->columns('collections'));
        $this->assertSame(0, $this->db->describeCalls, 'describe() must not be reached for a missing table');
    }

    public function testColumnReturnsTheDescriptionOrNull()
    {
        $this->assertSame(
            array('type' => 'string', 'null' => false, 'length' => 40),
            $this->inspector->column('events', 'uuid')
        );
        $this->assertNull($this->inspector->column('events', 'exposed'));
        $this->assertNull($this->inspector->column('collections', 'uuid'));
    }

    // -------------------------------------------------------------- indexes

    public function testHasIndexOnASingleColumn()
    {
        $this->assertTrue($this->inspector->hasIndex('events', 'uuid'));
        $this->assertTrue($this->inspector->hasIndex('events', array('uuid')));
        $this->assertFalse($this->inspector->hasIndex('events', 'org_id'));
    }

    /**
     * Column-set matching rather than name matching, because index names diverge
     * between the engines while the column set is the same question on both.
     */
    public function testHasIndexOnACompositeIsOrderSensitive()
    {
        $this->assertTrue($this->inspector->hasIndex('events', array('org_id', 'date')));
        $this->assertFalse($this->inspector->hasIndex('events', array('date', 'org_id')));
        $this->assertFalse($this->inspector->hasIndex('events', 'org_id'));
    }

    public function testHasIndexCanBeConstrainedToUniqueness()
    {
        $this->assertTrue($this->inspector->hasIndex('events', 'uuid', true));
        $this->assertFalse($this->inspector->hasIndex('events', 'uuid', false));
        $this->assertTrue($this->inspector->hasIndex('events', 'info', false));
        $this->assertFalse($this->inspector->hasIndex('events', 'info', true));
        // Unconstrained matches either.
        $this->assertTrue($this->inspector->hasIndex('events', 'info'));
    }

    /**
     * The key is read off the index list, where both drivers report it under
     * the name PRIMARY, because Postgres::describe() does not flag a varchar
     * key as one when the table is described by name.
     */
    public function testPrimaryKeyIsReadOffTheIndexList()
    {
        $this->assertSame(array('id'), $this->inspector->primaryKey('events'));
        $this->assertSame(array(), $this->inspector->primaryKey('nope'));
    }

    /**
     * The key is an index too, so hasIndex() finds it - unless asked not to,
     * which is the question to ask before dropping the key: is the column
     * covered by anything else?
     */
    public function testHasIndexCanLeaveThePrimaryKeyOut()
    {
        $this->assertTrue($this->inspector->hasIndex('events', 'id', true));
        $this->assertFalse($this->inspector->hasIndex('events', 'id', true, false));
    }

    public function testHasNamedIndexTakesTheNameLiterally()
    {
        $this->assertTrue($this->inspector->hasNamedIndex('events', 'lookup'));
        $this->assertTrue($this->inspector->hasNamedIndex('events', 'PRIMARY'));
        $this->assertFalse($this->inspector->hasNamedIndex('events', 'idx_events_lookup'));
    }

    public function testIndexesOfAMissingTableAreEmpty()
    {
        $this->assertSame(array(), $this->inspector->indexes('collections'));
        $this->assertFalse($this->inspector->hasIndex('collections', 'uuid'));
        $this->assertFalse($this->inspector->hasNamedIndex('collections', 'uuid'));
    }

    // -------------------------------------------------- the cache contract

    /**
     * Every read is taken with cacheSources down, so the answer reflects the
     * database as it is now rather than as some earlier model description
     * remembers it.
     */
    public function testReadsAreTakenWithSchemaCachingOff()
    {
        $this->assertTrue($this->db->cacheSources, 'precondition: caching starts on');

        $this->inspector->columns('events');

        $this->assertFalse($this->db->cacheStateDuringRead['listSources']);
        $this->assertFalse($this->db->cacheStateDuringRead['describe']);
    }

    public function testTheFlagIsRestoredAfterARead()
    {
        $this->inspector->columns('events');
        $this->assertTrue($this->db->cacheSources);

        // And a datasource that already had caching off keeps it off.
        $this->db->cacheSources = false;
        $this->inspector->columns('events');
        $this->assertFalse($this->db->cacheSources);
    }

    public function testTheFlagIsRestoredEvenWhenTheReadThrows()
    {
        $this->db->describeThrows = true;
        try {
            $this->inspector->columns('events');
            $this->fail('the read should have propagated its exception');
        } catch (RuntimeException $e) {
            $this->assertSame('describe blew up', $e->getMessage());
        }
        $this->assertTrue($this->db->cacheSources, 'the finally must put the flag back');
    }

    /**
     * The sticky form, for the window after DDL where PHP data work is about to
     * run against the altered table through a model. Deliberately not undone.
     */
    public function testDisableSchemaCacheIsSticky()
    {
        $this->inspector->disableSchemaCache();
        $this->assertFalse($this->db->cacheSources);

        // A subsequent read must not put it back up.
        $this->inspector->columns('events');
        $this->assertFalse($this->db->cacheSources);
    }

    // ------------------------------------------------------- runtime surface

    /**
     * @param array $results Canned result sets, one per fetchRows() call.
     * @return SchemaInspectorTestReader
     */
    private function mysqlReader(array $results = array())
    {
        $reader = new SchemaInspectorTestReader(new MigrationTestMysqlExtended());
        $reader->results = $results;
        return $reader;
    }

    /**
     * @param array $results Canned result sets, one per fetchRows() call.
     * @return SchemaInspectorTestReader
     */
    private function postgresReader(array $results = array())
    {
        $reader = new SchemaInspectorTestReader(new MigrationTestPostgres());
        $reader->results = $results;
        return $reader;
    }

    /**
     * No catalog query of its own: the driver's index() already answers this on
     * both engines. A column inside a composite index counts, which is what the
     * SHOW INDEX loop being replaced did.
     */
    public function testIndexNameForColumn()
    {
        $this->assertSame('uuid', $this->inspector->indexNameForColumn('events', 'uuid'));
        $this->assertSame('lookup', $this->inspector->indexNameForColumn('events', 'org_id'));
        $this->assertSame('lookup', $this->inspector->indexNameForColumn('events', 'date'));
        $this->assertNull($this->inspector->indexNameForColumn('events', 'nothing_indexed'));
        $this->assertNull($this->inspector->indexNameForColumn('no_such_table', 'id'));
    }

    /**
     * The uniqueness filter is what lets checkIndexExists() keep asking the
     * question it always asked - SHOW INDEX ... AND Non_unique = 0/1 - without
     * writing the SQL for it.
     */
    public function testIndexNameForColumnCanBeConstrainedToUniqueness()
    {
        $this->assertSame('uuid', $this->inspector->indexNameForColumn('events', 'uuid', true));
        $this->assertNull($this->inspector->indexNameForColumn('events', 'uuid', false));

        $this->assertSame('lookup', $this->inspector->indexNameForColumn('events', 'org_id', false));
        $this->assertNull($this->inspector->indexNameForColumn('events', 'org_id', true));
    }

    public function testTableRowEstimateReadsInformationSchemaOnMysql()
    {
        $reader = $this->mysqlReader(array(array(array('row_estimate' => '4711'))));
        $this->assertSame(4711, $reader->tableRowEstimate('attributes'));
        $this->assertCount(1, $reader->queries);
        $this->assertStringContainsString('information_schema.TABLES', $reader->queries[0]);
        $this->assertStringContainsString("TABLE_SCHEMA = 'misp'", $reader->queries[0]);
        $this->assertStringContainsString("TABLE_NAME = 'attributes'", $reader->queries[0]);
    }

    public function testTableRowEstimateReadsPgClassOnPostgres()
    {
        $reader = $this->postgresReader(array(array(array('row_estimate' => '4711'))));
        $this->assertSame(4711, $reader->tableRowEstimate('attributes'));
        $this->assertStringContainsString('pg_catalog.pg_class', $reader->queries[0]);
        $this->assertStringContainsString("n.nspname = 'public'", $reader->queries[0]);
        $this->assertStringContainsString("c.relname = 'attributes'", $reader->queries[0]);
    }

    /**
     * MySQL reports NULL for a table it has never looked at and PostgreSQL 13
     * and later report -1. Neither is a row count, and a caller putting the
     * figure in a page header wants neither of them.
     */
    public function testTableRowEstimateHasNoNegativeOrMissingAnswers()
    {
        $this->assertSame(0, $this->mysqlReader(array(array()))->tableRowEstimate('attributes'));
        $this->assertSame(
            0,
            $this->mysqlReader(array(array(array('row_estimate' => null))))->tableRowEstimate('attributes')
        );
        $this->assertSame(
            0,
            $this->postgresReader(array(array(array('row_estimate' => '-1'))))->tableRowEstimate('attributes')
        );
    }

    /**
     * The names and the schema filter are values, and they are quoted through
     * the driver rather than concatenated - which is what the information_schema
     * queries scattered through the tree do today.
     */
    public function testTheCatalogQueriesQuoteWhatTheyInterpolate()
    {
        $reader = $this->mysqlReader();
        $reader->getDataSource()->config['database'] = "mi'sp";
        $reader->tableRowEstimate("att'ributes");
        $this->assertStringContainsString("TABLE_SCHEMA = 'mi''sp'", $reader->queries[0]);
        $this->assertStringContainsString("TABLE_NAME = 'att''ributes'", $reader->queries[0]);
    }

    /**
     * PostgreSQL's namespace is configuration, not a constant, but a datasource
     * that does not name one still has to produce a valid query.
     */
    public function testThePostgresSchemaFallsBackToPublic()
    {
        $reader = $this->postgresReader();
        $reader->getDataSource()->config['schema'] = '';
        $reader->tableRowEstimate('attributes');
        $this->assertStringContainsString("n.nspname = 'public'", $reader->queries[0]);
    }

    /**
     * Two very different catalogs, one entry shape - which is the point of
     * putting this here rather than branching at the call site. The only field
     * that legitimately differs is the reclaimable one: MySQL's DATA_FREE has
     * no PostgreSQL counterpart, so the query hard-codes 0 there.
     */
    public function testTableSizesShapeTheSameOnBothEngines()
    {
        $mysql = $this->mysqlReader(array(array(
            array(
                'table_name' => 'attributes',
                'data_length' => '2048',
                'index_length' => '1024',
                'data_free' => '512',
                'row_estimate' => '17',
            ),
        )));
        $mysqlSizes = $mysql->tableSizes();
        $this->assertSame(
            array(
                'attributes' => array(
                    'table' => 'attributes',
                    'data_in_bytes' => 2048,
                    'index_in_bytes' => 1024,
                    'total_in_bytes' => 3072,
                    'reclaimable_in_bytes' => 512,
                    'row_estimate' => 17,
                ),
            ),
            $mysqlSizes
        );

        $pgsql = $this->postgresReader(array(array(
            array(
                'table_name' => 'attributes',
                'data_length' => '2048',
                'index_length' => '1024',
                'data_free' => '0',
                'row_estimate' => '17',
            ),
        )));
        $pgsqlSizes = $pgsql->tableSizes();
        $this->assertSame(0, $pgsqlSizes['attributes']['reclaimable_in_bytes']);
        $this->assertSame(
            array_keys($mysqlSizes['attributes']),
            array_keys($pgsqlSizes['attributes'])
        );
        unset($mysqlSizes['attributes']['reclaimable_in_bytes'], $pgsqlSizes['attributes']['reclaimable_in_bytes']);
        $this->assertSame($mysqlSizes, $pgsqlSizes);
    }

    /**
     * pg_class holds indexes, sequences and views next to the tables, so the
     * relkind filter is not tidiness - without it the listing is wrong. MySQL
     * gets the same treatment so that both engines answer the same question.
     */
    public function testTableSizesCountOnlyTables()
    {
        $mysql = $this->mysqlReader();
        $mysql->tableSizes();
        $this->assertStringContainsString("TABLE_TYPE = 'BASE TABLE'", $mysql->queries[0]);

        $pgsql = $this->postgresReader();
        $pgsql->tableSizes();
        $this->assertStringContainsString("c.relkind IN ('r', 'p')", $pgsql->queries[0]);
        $this->assertStringContainsString('pg_table_size(c.oid)', $pgsql->queries[0]);
        $this->assertStringContainsString('pg_indexes_size(c.oid)', $pgsql->queries[0]);
    }

    /**
     * A row the catalog answered with no name at all is skipped rather than
     * keyed under the empty string.
     */
    public function testTableSizesIgnoreAnUnnamedRow()
    {
        $reader = $this->mysqlReader(array(array(array('data_length' => '1'))));
        $this->assertSame(array(), $reader->tableSizes());
    }

    public function testServerVariablesFlattenToNameAndValueOnBothEngines()
    {
        $mysql = $this->mysqlReader(array(array(
            array('Variable_name' => 'innodb_buffer_pool_size', 'Value' => '134217728'),
            array('Variable_name' => 'max_allowed_packet', 'Value' => '67108864'),
        )));
        $this->assertSame(
            array('innodb_buffer_pool_size' => '134217728', 'max_allowed_packet' => '67108864'),
            $mysql->serverVariables()
        );
        $this->assertSame(array('SHOW VARIABLES;'), $mysql->queries);

        $pgsql = $this->postgresReader(array(array(
            array('name' => 'shared_buffers', 'setting' => '16384'),
        )));
        $this->assertSame(array('shared_buffers' => '16384'), $pgsql->serverVariables());
        $this->assertStringContainsString('pg_catalog.pg_settings', $pgsql->queries[0]);
    }

    /**
     * MariaDB's STAGE / MAX_STAGE / PROGRESS are what the update-progress screen
     * reads, and there is nothing engine-neutral to rename them to, so the
     * server's own column names come straight through.
     */
    public function testRunningQueriesPassTheServersColumnsThrough()
    {
        $row = array('ID' => '9', 'INFO' => 'ALTER TABLE attributes', 'STATE' => 'copy to tmp table', 'PROGRESS' => '12.5');
        $reader = $this->mysqlReader(array(array($row)));
        $this->assertSame(array($row), $reader->runningQueries());
        $this->assertStringContainsString('information_schema.PROCESSLIST', $reader->queries[0]);
    }

    /**
     * PostgreSQL has no equivalent of the stage-and-progress figures the only
     * caller wants, so it answers with nothing at all - and asks the server
     * nothing, rather than issuing a query whose result would be discarded.
     */
    public function testRunningQueriesAreEmptyOnPostgresAndCostNothing()
    {
        $reader = $this->postgresReader();
        $this->assertSame(array(), $reader->runningQueries());
        $this->assertSame(array(), $reader->queries);
    }

    /**
     * Postgres::index() parses its column names out of pg_get_indexdef(),
     * which quotes an identifier that needs it - and MISP's 1_event_id family
     * needs it. Seen live: the quotes came through, so hasIndex() answered
     * false for an index that was there. The inspector strips them.
     */
    public function testDriverQuotedIndexColumnsAreUnquoted()
    {
        $db = new SchemaInspectorTestMysql();
        $inspector = new SchemaInspector($db);
        $indexes = $inspector->indexes('events');
        $this->assertSame('1_event_id', $indexes['1_event_id']['column']);
        $this->assertSame(array('1_event_id', 'event_id'), $indexes['pair']['column']);
        $this->assertTrue($inspector->hasIndex('events', '1_event_id'));
        $this->assertTrue($inspector->hasIndex('events', array('1_event_id', 'event_id')));
        $this->assertSame('1_event_id', $inspector->indexNameForColumn('events', '1_event_id'));
    }

    // ---------------------------------------------------- definition surface

    /**
     * @return array One information_schema.COLUMNS row of a `tags` table.
     */
    private static function columnRow($name, $type, array $extra = array())
    {
        return array_merge(array(
            'TABLE_NAME' => 'tags', 'COLUMN_NAME' => $name, 'COLUMN_TYPE' => $type,
            'IS_NULLABLE' => 'NO', 'COLUMN_DEFAULT' => null, 'EXTRA' => '',
            'CHARACTER_SET_NAME' => null, 'COLLATION_NAME' => null, 'COLUMN_COMMENT' => '',
        ), $extra);
    }

    /**
     * @return array One information_schema.STATISTICS row of `tags`.
     */
    private static function statisticsRow($index, $seq, $column, $nonUnique, $subPart = null, $type = 'BTREE')
    {
        return array(
            'TABLE_NAME' => 'tags', 'INDEX_NAME' => $index, 'SEQ_IN_INDEX' => (string)$seq,
            'COLUMN_NAME' => $column, 'NON_UNIQUE' => (string)$nonUnique, 'SUB_PART' => $subPart,
            'INDEX_TYPE' => $type,
        );
    }

    /**
     * @param array $columns COLUMNS rows.
     * @param array $statistics STATISTICS rows.
     * @param bool $mariadb
     * @return SchemaInspectorTestReader
     */
    private function mysqlDefinitionReader(array $columns, array $statistics = array(), $mariadb = true)
    {
        $reader = $this->mysqlReader();
        $reader->answers = array(
            'information_schema.TABLES' => array(array(
                'TABLE_NAME' => 'tags', 'ENGINE' => 'InnoDB',
                'TABLE_COLLATION' => 'latin1_swedish_ci', 'ROW_FORMAT' => 'Dynamic',
            )),
            'VERSION()' => array(array('version' => $mariadb ? '10.11.14-MariaDB-0ubuntu0.24.04.1' : '8.4.6')),
            'information_schema.COLUMNS' => $columns,
            'information_schema.STATISTICS' => $statistics,
        );
        return $reader;
    }

    public function testADefinitionOfAMissingTableIsNull()
    {
        $mysql = $this->mysqlReader(array(array()));
        $this->assertNull($mysql->tableDefinition('nothing'));
        $this->assertCount(1, $mysql->queries);
        $this->assertStringContainsString("TABLE_TYPE = 'BASE TABLE'", $mysql->queries[0]);

        $pgsql = $this->postgresReader(array(array()));
        $this->assertNull($pgsql->tableDefinition('nothing'));
        $this->assertCount(1, $pgsql->queries);
        $this->assertStringContainsString("c.relkind IN ('r', 'p')", $pgsql->queries[0]);
    }

    public function testMysqlTableOptions()
    {
        $definition = $this->mysqlDefinitionReader(array())->tableDefinition('tags');
        $this->assertSame(
            array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collation' => 'latin1_swedish_ci', 'charset' => 'latin1'),
            $definition['options']
        );
    }

    /**
     * What describe() folds away: mediumtext reads as text there, and the
     * auto-increment flag is gone.
     */
    public function testMysqlColumnsAreReportedVerbatim()
    {
        $definition = $this->mysqlDefinitionReader(array(
            self::columnRow('id', 'int(11)', array('EXTRA' => 'auto_increment')),
            self::columnRow('name', 'varchar(255)', array('CHARACTER_SET_NAME' => 'utf8mb4', 'COLLATION_NAME' => 'utf8mb4_unicode_ci')),
            self::columnRow('colour', 'varchar(7)', array('COLUMN_DEFAULT' => "'#ffffff'", 'CHARACTER_SET_NAME' => 'utf8mb3', 'COLLATION_NAME' => 'utf8mb3_bin')),
            self::columnRow('created', 'int(10) unsigned', array('COLUMN_DEFAULT' => 'unix_timestamp()')),
            self::columnRow('note', 'mediumtext', array('IS_NULLABLE' => 'YES', 'COLUMN_DEFAULT' => 'NULL', 'CHARACTER_SET_NAME' => 'utf8mb4', 'COLLATION_NAME' => 'utf8mb4_bin')),
            self::columnRow('ratio', 'decimal(10,2)', array('COLUMN_DEFAULT' => '0.00')),
        ))->tableDefinition('tags');

        $this->assertSame(array('id', 'name', 'colour', 'created', 'note', 'ratio'), array_keys($definition['columns']));
        $this->assertSame(array(
            'type' => 'int(11)', 'base' => 'int', 'length' => 11, 'scale' => null, 'unsigned' => false,
            'null' => false, 'default' => null, 'default_expression' => false,
            'charset' => null, 'collation' => null, 'increment' => 'auto_increment',
        ), $definition['columns']['id']);
        $this->assertSame('utf8mb4', $definition['columns']['name']['charset']);
        $this->assertSame('utf8mb4_unicode_ci', $definition['columns']['name']['collation']);
        $this->assertNull($definition['columns']['name']['increment']);
        $this->assertSame('#ffffff', $definition['columns']['colour']['default']);
        $this->assertFalse($definition['columns']['colour']['default_expression']);
        $this->assertTrue($definition['columns']['created']['unsigned']);
        $this->assertSame('unix_timestamp()', $definition['columns']['created']['default']);
        $this->assertTrue($definition['columns']['created']['default_expression']);
        $this->assertSame('mediumtext', $definition['columns']['note']['type']);
        $this->assertTrue($definition['columns']['note']['null']);
        $this->assertNull($definition['columns']['note']['default']);
        $this->assertSame(array(10, 2), array($definition['columns']['ratio']['length'], $definition['columns']['ratio']['scale']));
        $this->assertSame('0.00', $definition['columns']['ratio']['default']);
    }

    /**
     * MySQL shows literal defaults bare where MariaDB quotes them, and 8.0.19
     * and later report integers without a display width.
     */
    public function testMysqlDefaultsAndWidthsAsMysqlSpellsThem()
    {
        $definition = $this->mysqlDefinitionReader(array(
            self::columnRow('id', 'bigint unsigned', array('EXTRA' => 'auto_increment')),
            self::columnRow('auth', 'varchar(64)', array('COLUMN_DEFAULT' => 'basic')),
            self::columnRow('seen', 'datetime', array('COLUMN_DEFAULT' => 'CURRENT_TIMESTAMP', 'EXTRA' => 'DEFAULT_GENERATED')),
        ), array(), false)->tableDefinition('tags');

        $id = $definition['columns']['id'];
        $this->assertSame(array('bigint unsigned', 'bigint', null, true), array($id['type'], $id['base'], $id['length'], $id['unsigned']));
        $this->assertSame(array('basic', false), array($definition['columns']['auth']['default'], $definition['columns']['auth']['default_expression']));
        $this->assertSame(array('CURRENT_TIMESTAMP', true), array($definition['columns']['seen']['default'], $definition['columns']['seen']['default_expression']));
    }

    public function testMysqlIndexesCarryPrefixesTypesAndThePrimaryKey()
    {
        $definition = $this->mysqlDefinitionReader(array(), array(
            self::statisticsRow('lookup', 2, 'user_id', 1),
            self::statisticsRow('PRIMARY', 1, 'id', 0),
            self::statisticsRow('lookup', 1, 'org_id', 1),
            self::statisticsRow('name', 1, 'name', 0),
            self::statisticsRow('info', 1, 'info', 1, '255'),
            self::statisticsRow('info_search', 1, 'info', 1, null, 'FULLTEXT'),
        ))->tableDefinition('tags');

        $indexes = $definition['indexes'];
        $this->assertSame(array('PRIMARY', 'info', 'info_search', 'lookup', 'name'), array_keys($indexes));
        $this->assertSame(array(
            'name' => 'PRIMARY', 'column' => array('id'), 'unique' => true, 'primary' => true,
            'length' => array(), 'type' => 'btree', 'expression' => false, 'definition' => null,
        ), $indexes['PRIMARY']);
        $this->assertSame(array('org_id', 'user_id'), $indexes['lookup']['column']);
        $this->assertFalse($indexes['lookup']['unique']);
        $this->assertTrue($indexes['name']['unique']);
        $this->assertFalse($indexes['name']['primary']);
        $this->assertSame(array('info' => 255), $indexes['info']['length']);
        $this->assertSame('fulltext', $indexes['info_search']['type']);
        $this->assertFalse($indexes['info_search']['unique']);
    }

    /**
     * A MySQL 8 functional key part has no column name, and its text is in a
     * STATISTICS column MariaDB does not have.
     */
    public function testAMysqlFunctionalKeyPartReadsAsAnExpression()
    {
        $indexes = SchemaInspector::mysqlIndexes(array(
            self::statisticsRow('lower_name', 1, null, 0),
            self::statisticsRow('lower_name', 2, 'org_id', 0),
        ));
        $this->assertSame(array(null, 'org_id'), $indexes['lower_name']['column']);
        $this->assertTrue($indexes['lower_name']['expression']);
    }

    public function testTheMysqlDefinitionQueriesFilterOnTheTableAndQuoteIt()
    {
        $reader = $this->mysqlDefinitionReader(array());
        $reader->tableDefinition("ta'gs");
        $catalog = array_values(array_filter($reader->queries, function ($sql) {
            return strpos($sql, 'information_schema') !== false;
        }));
        $this->assertCount(3, $catalog);
        foreach ($catalog as $sql) {
            $this->assertStringContainsString("TABLE_SCHEMA = 'misp' AND", $sql);
            $this->assertStringContainsString("TABLE_NAME = 'ta''gs'", $sql);
        }
    }

    /**
     * Without a table, the same queries read the whole database: that is how
     * BaselineGenerator reads its reference.
     */
    public function testTheMysqlCatalogQueriesCanReadAWholeDatabase()
    {
        $db = new MigrationTestMysqlExtended();
        foreach (array(
            SchemaInspector::mysqlTablesSql($db, 'reference'),
            SchemaInspector::mysqlColumnsSql($db, 'reference'),
            SchemaInspector::mysqlStatisticsSql($db, 'reference'),
        ) as $sql) {
            $this->assertStringContainsString("TABLE_SCHEMA = 'reference'", $sql);
            $this->assertStringNotContainsString('TABLE_NAME =', $sql);
        }
    }

    public function testMariaDbIsDetectedOnceAndNeverOnPostgres()
    {
        $reader = $this->mysqlReader(array(array(array('version' => '10.11.14-MariaDB'))));
        $this->assertTrue($reader->isMariaDb());
        $this->assertTrue($reader->isMariaDb());
        $this->assertCount(1, $reader->queries);

        $this->assertFalse($this->mysqlReader(array(array(array('version' => '8.4.6'))))->isMariaDb());

        $pgsql = $this->postgresReader();
        $this->assertFalse($pgsql->isMariaDb());
        $this->assertSame(array(), $pgsql->queries);
    }

    /**
     * @param array $columns pg_attribute rows.
     * @param array $indexes pg_index rows, one per key part.
     * @return SchemaInspectorTestReader
     */
    private function postgresDefinitionReader(array $columns, array $indexes = array())
    {
        $reader = $this->postgresReader();
        $reader->answers = array(
            'c.relkind IN' => array(array('oid' => '16384')),
            'FROM pg_catalog.pg_attribute a' => $columns,
            'FROM pg_catalog.pg_index i' => $indexes,
        );
        return $reader;
    }

    /**
     * @return array One pg_attribute row as the column query shapes it.
     */
    private static function pgColumnRow($name, $type, $default = null, array $extra = array())
    {
        return array_merge(array(
            'column_name' => $name, 'column_type' => $type, 'not_null' => true,
            'identity' => '', 'column_default' => $default, 'collation_name' => null,
        ), $extra);
    }

    public function testPostgresHasNoTableOptions()
    {
        $definition = $this->postgresDefinitionReader(array())->tableDefinition('tags');
        $this->assertSame(
            array('engine' => null, 'row_format' => null, 'collation' => null, 'charset' => null),
            $definition['options']
        );
    }

    /**
     * Identity and serial are both auto-incrementing; a serial column's
     * nextval() is that, not a default, as on MySQL.
     */
    public function testPostgresColumns()
    {
        $definition = $this->postgresDefinitionReader(array(
            self::pgColumnRow('id', 'bigint', null, array('identity' => 'd')),
            self::pgColumnRow('legacy_id', 'integer', "nextval('tags_legacy_id_seq'::regclass)"),
            self::pgColumnRow('name', 'character varying(255)'),
            self::pgColumnRow('code', 'character varying(64)', null, array('collation_name' => 'C')),
            self::pgColumnRow('flag', 'boolean', 'false', array('not_null' => 't')),
            self::pgColumnRow('colour', 'character varying(7)', "'it''s'::character varying"),
            self::pgColumnRow('level', 'integer', "'-1'::integer"),
            self::pgColumnRow('zero', 'integer', '0'),
            self::pgColumnRow('seen', 'timestamp without time zone', 'now()', array('not_null' => false)),
            self::pgColumnRow('note', 'text', 'NULL::text', array('not_null' => 'f')),
            self::pgColumnRow('ratio', 'numeric(10,2)'),
        ))->tableDefinition('tags');
        $columns = $definition['columns'];

        $this->assertSame(array(
            'type' => 'bigint', 'base' => 'bigint', 'length' => null, 'scale' => null, 'unsigned' => false,
            'null' => false, 'default' => null, 'default_expression' => false,
            'charset' => null, 'collation' => null, 'increment' => 'identity',
        ), $columns['id']);
        $this->assertSame(array('serial', null), array($columns['legacy_id']['increment'], $columns['legacy_id']['default']));
        $this->assertSame(array('character varying', 255), array($columns['name']['base'], $columns['name']['length']));
        $this->assertNull($columns['name']['collation']);
        $this->assertSame('C', $columns['code']['collation']);
        $this->assertSame(array('false', false), array($columns['flag']['default'], $columns['flag']['default_expression']));
        $this->assertFalse($columns['flag']['null']);
        $this->assertSame("it's", $columns['colour']['default']);
        $this->assertSame('-1', $columns['level']['default']);
        $this->assertSame('0', $columns['zero']['default']);
        $this->assertSame(array('now()', true), array($columns['seen']['default'], $columns['seen']['default_expression']));
        $this->assertTrue($columns['seen']['null']);
        $this->assertSame(array(null, false, true), array($columns['note']['default'], $columns['note']['default_expression'], $columns['note']['null']));
        $this->assertSame(array('numeric', 10, 2), array($columns['ratio']['base'], $columns['ratio']['length'], $columns['ratio']['scale']));
    }

    public function testPostgresIndexes()
    {
        $row = function ($name, $column, $attnum, array $extra = array()) {
            return array_merge(array(
                'index_name' => $name, 'is_primary' => false, 'is_unique' => false, 'index_type' => 'btree',
                'definition' => 'CREATE INDEX ' . $name . ' ...', 'attnum' => (string)$attnum, 'column_name' => $column,
            ), $extra);
        };
        $definition = $this->postgresDefinitionReader(array(), array(
            $row('idx_tags_lookup', 'org_id', 5),
            $row('idx_tags_lookup', '1_event_id', 9),
            $row('idx_tags_name_lower', 'lower(name::text)', 0, array('is_unique' => 't')),
            $row('idx_tags_note', 'note', 4, array('index_type' => 'hash')),
            $row('tags_pkey', 'id', 1, array('is_primary' => true, 'is_unique' => true)),
        ))->tableDefinition('tags');
        $indexes = $definition['indexes'];

        $this->assertSame(array('PRIMARY', 'idx_tags_lookup', 'idx_tags_name_lower', 'idx_tags_note'), array_keys($indexes));
        $this->assertSame(array(
            'name' => 'tags_pkey', 'column' => array('id'), 'unique' => true, 'primary' => true,
            'length' => array(), 'type' => 'btree', 'expression' => false, 'definition' => 'CREATE INDEX tags_pkey ...',
        ), $indexes['PRIMARY']);
        $this->assertSame(array('org_id', '1_event_id'), $indexes['idx_tags_lookup']['column']);
        $this->assertSame(array('lower(name::text)'), $indexes['idx_tags_name_lower']['column']);
        $this->assertTrue($indexes['idx_tags_name_lower']['expression']);
        $this->assertTrue($indexes['idx_tags_name_lower']['unique']);
        $this->assertSame('hash', $indexes['idx_tags_note']['type']);
    }

    public function testThePostgresDefinitionQueriesFilterOnTheSchemaAndTheTable()
    {
        $reader = $this->postgresDefinitionReader(array());
        $reader->getDataSource()->config['schema'] = 'pg_temp_3';
        $reader->tableDefinition("ta'gs");
        $this->assertCount(3, $reader->queries);
        $this->assertStringContainsString("n.nspname = 'pg_temp_3' AND c.relname = 'ta''gs'", $reader->queries[0]);
        $this->assertStringContainsString('a.attrelid = 16384', $reader->queries[1]);
        $this->assertStringContainsString('i.indrelid = 16384', $reader->queries[2]);
    }

    /**
     * @dataProvider defaults
     */
    public function testDefaultsInEveryServerSpelling($default, $extra, $mariadb, array $expected)
    {
        $this->assertSame($expected, SchemaInspector::parseMysqlDefault($default, $extra, $mariadb));
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
}
