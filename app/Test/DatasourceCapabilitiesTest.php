<?php
/**
 * The $supports vocabulary the datasources declare, and the one property of it
 * that is easy to break by accident.
 *
 * AppModel::checkDbSupport() reads $supports off the datasource, so a
 * capability is only real on the driver that declares it. MysqlObserverExtended
 * is the datasource database.default.php actually ships, and it used to restate
 * the whole array rather than inherit it - which meant a capability added to
 * MysqlExtended silently did not reach the driver every instance runs. The copy
 * is gone; this is what stops it coming back.
 *
 * @see MigrationSchemaStubs.php for how the real Cake drivers are loaded without a connection.
 */

require_once __DIR__ . '/MigrationSchemaStubs.php';
require_once __DIR__ . '/../Model/Datasource/Database/MysqlObserverExtended.php';
require_once __DIR__ . '/../Model/Datasource/Database/PostgresObserverExtended.php';

use PHPUnit\Framework\TestCase;

if (!class_exists('DatasourceTestPostgresObserverExtended', false)) {
    /**
     * The shipped PostgreSQL datasource with the constructor skipped, like
     * the other connectionless stubs, plus a stand-in result set so that
     * fetchResult() can be exercised.
     */
    class DatasourceTestPostgresObserverExtended extends PostgresObserverExtended
    {
        /** @var array table => field => sequence or false: what the catalogue would say */
        public $catalogue = array();

        /** @var array The (table, field) pairs ownedSequence() was asked about */
        public $catalogueAsked = array();

        public function __construct()
        {
            $this->_connection = new DatasourceTestPdo();
            $this->cacheMethods = false;
            $this->config = array('prefix' => '', 'database' => 'misp', 'schema' => 'public');
        }

        protected function ownedSequence($table, $field)
        {
            $this->catalogueAsked[] = "$table.$field";
            return isset($this->catalogue[$table][$field]) ? $this->catalogue[$table][$field] : false;
        }

        public function primeSequenceMap($table, $field, $sequence)
        {
            $this->_sequenceMap[$table][$field] = $sequence;
        }

        /** @var array Every statement handed to the connection, in order. */
        public $executed = array();

        protected function _execute($sql, $params = array(), $prepareOptions = array())
        {
            // Without the observer's "who is running this" comment prefix.
            $this->executed[] = preg_replace('/^\/\*.*?\*\/ /', '', $sql);
            return true;
        }

        public function primeResult(array $map, array $rows)
        {
            $this->map = $map;
            $this->_result = new DatasourceTestResultSet($rows);
        }
    }

    /**
     * Just enough of Cake's Model for order() to ask what a model owns. Named
     * Model because that is the type DboSource::order() declares; no test under
     * app/Test/ loads the real one.
     */
    class Model
    {
        public $alias;

        public $table;

        public $tablePrefix = '';

        public $schemaName = null;

        public $primaryKey = 'id';

        public $data = array();

        public $id = null;

        private $fields;

        public function __construct($alias, array $fields, $table = null)
        {
            $this->alias = $alias;
            $this->fields = $fields;
            $this->table = $table === null ? strtolower($alias) . 's' : $table;
        }

        public function schema($field = false)
        {
            return array();
        }

        public function getColumnType($column)
        {
            return $column === 'id' ? 'integer' : 'string';
        }

        public function setInsertID($id)
        {
            $this->id = $id;
        }

        public function onError()
        {
        }

        public function hasField($name, $checkVirtual = false)
        {
            return in_array($name, $this->fields, true);
        }

        public function isVirtualField($field)
        {
            return false;
        }

        public function getVirtualField($field)
        {
            return null;
        }

        public function __get($name)
        {
            return null;
        }
    }

    /**
     * The offline PDO stand-in, plus what a real one answers to lastInsertId():
     * currval() of the sequence it was given.
     */
    class DatasourceTestPdo extends MigrationTestPdo
    {
        public function lastInsertId($name = null)
        {
            return 'currval(' . $name . ')';
        }
    }

    class DatasourceTestResultSet
    {
        private $rows;

        public function __construct(array $rows)
        {
            $this->rows = $rows;
        }

        public function fetch($mode = null)
        {
            return empty($this->rows) ? false : array_shift($this->rows);
        }

        public function closeCursor()
        {
        }
    }
}

if (!function_exists('pluginSplit')) {
    // DboSource::order() calls this from Cake's basics.php, which the bare
    // suite does not load. Same guard basics.php itself uses.
    function pluginSplit($name, $dotAppend = false, $plugin = null)
    {
        if (strpos($name, '.') !== false) {
            $parts = explode('.', $name, 2);
            if ($dotAppend) {
                $parts[0] .= '.';
            }
            return $parts;
        }
        return array($plugin, $name);
    }
}

class DatasourceCapabilitiesTest extends TestCase
{
    /**
     * The capabilities MISP's own code asks about. Index hints and the join
     * controls are the driver's extended query rendering; the temporary MEMORY
     * table and the fulltext index are engine constructs PostgreSQL has no
     * equivalent for.
     */
    public function testMysqlExtendedDeclaresTheWholeVocabulary()
    {
        $db = new MigrationTestMysqlExtended();
        $this->assertSame(
            array(
                'indexHints',
                'ignoreIndexHints',
                'reverseJoin',
                'straightJoin',
                'insertMulti',
                'temporaryMemoryTable',
                'fulltextIndex',
            ),
            array_keys($db->supports)
        );
        foreach ($db->supports as $capability => $supported) {
            $this->assertTrue($supported, $capability . ' is declared but not enabled');
        }
    }

    /**
     * The one that matters: the shipped default has to answer the same as its
     * parent, without restating it.
     */
    public function testTheShippedDatasourceInheritsThemRatherThanRestatingThem()
    {
        $parent = new ReflectionClass('MysqlExtended');
        $shipped = new ReflectionClass('MysqlObserverExtended');

        $this->assertSame(
            $parent->getDefaultProperties()['supports'],
            $shipped->getDefaultProperties()['supports']
        );
        $this->assertSame(
            'MysqlExtended',
            $shipped->getProperty('supports')->getDeclaringClass()->getName(),
            'MysqlObserverExtended must inherit $supports, not declare its own copy'
        );
    }

    /**
     * upsert is deliberately absent. It looks like it belongs in this list and
     * does not: PostgreSQL has ON CONFLICT, so a probe reading false there
     * would push a caller into a slower read-then-write with a race in it.
     * Upserts go through SqlDialect::upsert(), which renders both engines.
     */
    public function testUpsertIsNotACapabilityProbe()
    {
        $db = new MigrationTestMysqlExtended();
        $this->assertArrayNotHasKey('upsert', $db->supports);
        $this->assertTrue(method_exists('SqlDialect', 'upsert'));
    }

    /**
     * Cake's unmodified Mysql is the baseline, and declaring nothing is the
     * whole of what that means: a call site asks rather than branching, and a
     * legacy instance still pointed at Database/Mysql gets correct results
     * with whatever plan the server picks for itself.
     */
    public function testTheBaselineDriverDeclaresNothing()
    {
        $this->assertFalse(isset((new MigrationTestMysql())->supports));
    }

    // ------------------------------------------------------------ PostgreSQL

    /**
     * The one PostgreSQL datasource answers the whole vocabulary, and answers
     * it for PostgreSQL: multi-row INSERT yes, everything MySQL-specific no -
     * declared, not merely absent, so a reader sees the answer.
     */
    public function testThePostgresDatasourceDeclaresTheSameVocabularyWithPostgresAnswers()
    {
        $mysql = (new ReflectionClass('MysqlExtended'))->getDefaultProperties()['supports'];
        $pgsql = (new ReflectionClass('PostgresObserverExtended'))->getDefaultProperties()['supports'];
        $this->assertSame(array_keys($mysql), array_keys($pgsql));
        $this->assertSame(
            array(
                'indexHints' => false,
                'ignoreIndexHints' => false,
                'reverseJoin' => false,
                'straightJoin' => false,
                'insertMulti' => true,
                'temporaryMemoryTable' => false,
                'fulltextIndex' => false,
            ),
            $pgsql
        );
    }

    /**
     * MISP writes its flags as integers and PHP booleans against columns that
     * are boolean on PostgreSQL. Each shape has to reach the engine as
     * something it accepts for that column - and integers against numeric
     * columns must stay bare, since that is the path every id takes.
     */
    public function testValueRendersFlagsInAFormPostgresAcceptsForTheColumn()
    {
        $db = new DatasourceTestPostgresObserverExtended();

        // Known boolean column: the driver's TRUE / FALSE, from every spelling.
        foreach (array(0, '0', false, '', 'false') as $off) {
            $this->assertSame("'FALSE'", $db->value($off, 'boolean'), var_export($off, true));
        }
        foreach (array(1, '1', true, 'true') as $on) {
            $this->assertSame("'TRUE'", $db->value($on, 'boolean'), var_export($on, true));
        }

        // A PHP boolean against anything else: a quoted digit, which a
        // boolean, an integer and a text column all take.
        $this->assertSame("'1'", $db->value(true, 'integer'));
        $this->assertSame("'0'", $db->value(false, 'string'));
        $this->assertSame("'0'", $db->value(false));

        // Integers: bare for a known column, quoted when the ORM could not
        // resolve one - a join condition on a boolean column is the case.
        $this->assertSame(5, $db->value(5, 'integer'));
        $this->assertSame(0, $db->value(0, 'smallinteger'));
        $this->assertSame("'0'", $db->value(0));
        $this->assertSame("'42'", $db->value(42));

        // Everything else is the driver's own.
        $this->assertSame("'x'", $db->value('x', 'string'));
        $this->assertSame('NULL', $db->value(null, 'integer'));
        $this->assertSame(array("'1'", 7, "'a'"), $db->value(array(true, 7, 'a'), 'integer'));
    }

    /**
     * A bool column comes back as a PHP boolean, or null - which is exactly
     * what Cake's MySQL driver makes of a tinyint(1), through the ORM and
     * through Model::query() alike, and what the API therefore serialises as
     * true/false. bytea comes back as the bytes whether the driver handed
     * over a stream or a string.
     */
    public function testFetchResultReturnsBooleansAsBooleansLikeTheMysqlDriver()
    {
        $db = new DatasourceTestPostgresObserverExtended();
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, 'bytes');
        rewind($stream);
        $db->primeResult(
            array(
                0 => array('Event', 'id', 'int4'),
                1 => array('Event', 'published', 'bool'),
                2 => array('Event', 'deleted', 'bool'),
                3 => array('Event', 'unknown', 'bool'),
                4 => array('Event', 'blob', 'bytea'),
                5 => array('Event', 'blob2', 'bytea'),
            ),
            array(
                array('7', '1', 'f', null, $stream, 'plain'),
            )
        );
        $this->assertSame(
            array('Event' => array(
                'id' => '7',
                'published' => true,
                'deleted' => false,
                'unknown' => null,
                'blob' => 'bytes',
                'blob2' => 'plain',
            )),
            $db->fetchResult()
        );
        $this->assertFalse($db->fetchResult());
    }

    /**
     * Cake's condition quoting hands a raw subquery back with its alias bare
     * - `attributes AS Attribute` - while every reference to it stays quoted.
     * PostgreSQL folds the bare one to lowercase; the datasource quotes it.
     * An alias Cake quoted itself, and the AS inside a CAST, are left alone.
     */
    public function testQuoteFieldsQuotesTheAliasCakeLeftBare()
    {
        $db = new DatasourceTestPostgresObserverExtended();
        $quoteFields = new ReflectionMethod('PostgresObserverExtended', '_quoteFields');
        $quoteFields->setAccessible(true);

        $this->assertSame(
            '"Event"."id" IN (SELECT event_id FROM attributes AS "Attribute"   WHERE "Attribute"."value1" = \'x\')',
            $quoteFields->invoke($db, 'Event.id IN (SELECT event_id FROM attributes AS "Attribute"   WHERE "Attribute"."value1" = \'x\')')
        );
        $this->assertSame(
            'SELECT COUNT(*) FROM "public"."sightings" AS "Sighting" WHERE "Sighting"."id" = 1',
            $quoteFields->invoke($db, 'SELECT COUNT(*) FROM "public"."sightings" AS "Sighting" WHERE "Sighting"."id" = 1'),
            'an alias Cake already quoted is untouched'
        );
        $this->assertSame(
            'CAST("Attribute"."value1" AS integer) > 3',
            $quoteFields->invoke($db, 'CAST(Attribute.value1 AS integer) > 3'),
            'the AS of a CAST is not a table alias'
        );
    }

    /**
     * MySQL resolves an unqualified ORDER BY name against the select list, so
     * `'order' => 'date_created DESC'` on News, which joins User, sorts by
     * News.date_created. PostgreSQL would call that ambiguous - the very error
     * the first login on PostgreSQL produced - so the datasource qualifies a
     * bare field the model owns, in every shape Cake's order() accepts.
     */
    public function testOrderQualifiesABareFieldTheModelOwnsTheWayMysqlResolvesIt()
    {
        $db = new DatasourceTestPostgresObserverExtended();
        $News = new Model('News', array('id', 'date_created', 'user_id'));

        $expected = ' ORDER BY "News"."date_created" DESC';
        $this->assertSame($expected, $db->order('date_created DESC', 'ASC', $News), 'a string');
        $this->assertSame($expected, $db->order(array('date_created DESC'), 'ASC', $News), 'a list');
        $this->assertSame($expected, $db->order(array('date_created' => 'DESC'), 'ASC', $News), 'a map');
        $this->assertSame($expected, $db->order('date_created', 'DESC', $News), 'the direction argument');

        $expected = ' ORDER BY "News"."date_created" DESC, "News"."id" ASC';
        $this->assertSame($expected, $db->order('date_created DESC, id', 'ASC', $News), 'a comma-separated string');
        $this->assertSame($expected, $db->order(array(array('date_created' => 'DESC'), 'id'), 'ASC', $News), 'nested');
    }

    /**
     * Only a bare name of a column the model has is touched. An already
     * qualified key, a joined model's column, an aggregate alias from the
     * select list and a function are what they were - and with no model to
     * ask, order() is Cake's.
     */
    public function testOrderLeavesEverythingTheModelDoesNotOwnAlone()
    {
        $db = new DatasourceTestPostgresObserverExtended();
        $News = new Model('News', array('id', 'date_created', 'user_id'));

        $this->assertSame(' ORDER BY "User"."date_created" DESC', $db->order('User.date_created DESC', 'ASC', $News));
        $this->assertSame(' ORDER BY "email" ASC', $db->order('email', 'ASC', $News));
        $this->assertSame(' ORDER BY "attr_count" DESC', $db->order(array('attr_count DESC'), 'ASC', $News));
        $this->assertSame(' ORDER BY RANDOM() ASC', $db->order('RANDOM()', 'ASC', $News));
        $this->assertSame(' ORDER BY "date_created" DESC', $db->order('date_created DESC'));
    }

    /**
     * After an INSERT, Cake asks the driver for the new id. The Postgres
     * driver names the sequence by convention when describe() has not seen
     * a nextval() default this process, and "bruteforces_id_seq" does not
     * exist - bruteforces has no id column - which is the error the first
     * failed login on PostgreSQL produced. The datasource asks the catalogue
     * instead, once per table, and answers "0" for a key with no sequence,
     * as MySQL does for a table without AUTO_INCREMENT.
     */
    public function testLastInsertIdAsksTheCatalogueOnceAndAnswersZeroForAKeyWithNoSequence()
    {
        $db = new DatasourceTestPostgresObserverExtended();
        $db->catalogue = array(
            'events' => array('id' => 'public.events_id_seq'),
            'bruteforces' => array('id' => false),
        );

        $this->assertSame('currval(public.events_id_seq)', $db->lastInsertId('events', 'id'));
        $this->assertSame('0', $db->lastInsertId('bruteforces', 'id'));
        $this->assertSame('0', $db->lastInsertId('system_settings', 'setting'), 'a table the catalogue does not list at all');

        $db->lastInsertId('events', 'id');
        $db->lastInsertId('bruteforces', 'id');
        $this->assertSame(
            array('events.id', 'bruteforces.id', 'system_settings.setting'),
            $db->catalogueAsked,
            'each pair is looked up once, the answer is remembered - false included'
        );
    }

    /**
     * When describe() did read the nextval() default this process, Cake's own
     * sequence map is the answer and the catalogue is not consulted.
     */
    public function testLastInsertIdTrustsWhatDescribeAlreadyLearned()
    {
        $db = new DatasourceTestPostgresObserverExtended();
        $db->primeSequenceMap('attributes', 'id', 'public.attributes_id_seq');

        $this->assertSame('currval(public.attributes_id_seq)', $db->lastInsertId('attributes', 'id'));
        $this->assertSame(array(), $db->catalogueAsked);
    }
    /**
     * An INSERT that names its own id leaves a PostgreSQL sequence behind
     * the data, where MySQL moves AUTO_INCREMENT past it; User::init()
     * inserts the first role, organisation and user as id 1 that way. The
     * datasource sets the owned sequence to the column's maximum after such
     * an insert, and does nothing extra when the engine assigned the id.
     */
    public function testCreateAdvancesTheSequencePastAnExplicitId()
    {
        $db = new DatasourceTestPostgresObserverExtended();
        $db->catalogue = array('roles' => array('id' => 'public.roles_id_seq'));
        $Role = new Model('Role', array('id', 'name'));

        $this->assertTrue($db->create($Role, array('id', 'name'), array(1, 'Site Admin')));
        $this->assertSame(1, $Role->id);
        $this->assertSame(
            array(
                'INSERT INTO "public"."roles" ("id", "name") VALUES (1, \'Site Admin\')',
                'SELECT setval(\'public.roles_id_seq\', (SELECT MAX("id") FROM "public"."roles"))',
            ),
            $db->executed
        );

        $db->executed = array();
        $this->assertTrue($db->create($Role, array('name'), array('User')));
        $this->assertSame('currval(public.roles_id_seq)', $Role->id, 'the engine assigned it, and was asked for it');
        $this->assertSame(array('INSERT INTO "public"."roles" ("name") VALUES (\'User\')'), $db->executed);

        $db->executed = array();
        $Bruteforce = new Model('Bruteforce', array('ip'), 'bruteforces');
        $this->assertTrue($db->create($Bruteforce, array('id', 'ip'), array(5, '10.0.0.1')));
        $this->assertCount(1, $db->executed, 'no sequence to advance for a key that owns none');
    }

}
