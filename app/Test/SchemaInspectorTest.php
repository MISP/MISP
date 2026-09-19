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

        protected function fetchRows($sql)
        {
            $this->queries[] = $sql;
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
}
