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
}
