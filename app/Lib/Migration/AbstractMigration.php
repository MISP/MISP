<?php

App::uses('SchemaBuilder', 'Migration');
App::uses('SchemaInspector', 'Migration');

/**
 * The base class every migration under app/Lib/Migration/Migrations/ extends.
 *
 * A migration has three parts, all optional. up() declares DDL against the
 * flavour-agnostic SchemaBuilder; afterUp() runs PHP data work once that DDL has
 * landed; beforeUp() runs the PHP data work the DDL cannot proceed without.
 * Splitting them this way is what lets the updateMISP()-style cases - seeding
 * rows, regenerating correlations, anything that needs models rather than SQL -
 * be expressed natively instead of living in a second switch statement beside
 * the first one.
 *
 *     class Migration_20260826_120000_event_templates_exposed extends AbstractMigration
 *     {
 *         public $description = 'Mark event templates as exposed to anonymous sources';
 *
 *         public function up(SchemaBuilder $schema)
 *         {
 *             $schema->table('event_templates')
 *                 ->addColumn('exposed', 'boolean', array(
 *                     'null' => false, 'default' => 0, 'after' => 'misp_default'
 *                 ))
 *                 ->addIndex('exposed');
 *         }
 *     }
 *
 * ## Identity is derived, never declared
 *
 * The ledger keys a row by the migration's id, and the id is the class name
 * minus the "Migration_" prefix - which, because CakePHP's App::uses() requires
 * class name and file name to agree, makes it the file name as well. A declared
 * $id property would be free to disagree with both, and a migration that
 * disagrees with its own file name applies twice under two different keys.
 *
 * The prefix exists because a PHP class name cannot begin with a digit and the
 * id begins with its timestamp. That timestamp is fixed-width, so sorting ids as
 * strings sorts them chronologically, which is what pending() relies on.
 *
 * ## Data changes go through models
 *
 * beforeUp() and afterUp() should reach for ClassRegistry::init() and
 * save()/updateAll(), not hand-written DML. A Cake write is portable by construction where an INSERT
 * spelled out by hand is not, and nothing in the historic corpus suggests the
 * expressiveness is missed.
 *
 * @see SchemaBuilder
 * @see MigrationManager
 */
abstract class AbstractMigration
{
    /**
     * What every migration's class name starts with, and what its id does not.
     */
    const CLASS_PREFIX = 'Migration_';

    /**
     * The shape of an id: a fixed-width timestamp and a slug.
     *
     * Fixed-width is the load-bearing part - it is what makes a lexicographic
     * sort of ids a chronological one, and therefore what lets pending() order
     * migrations with a plain ksort().
     */
    const ID_PATTERN = '/^(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})_[A-Za-z0-9_]+$/';

    /**
     * One line on what this migration is for. Shown by `cake Admin migrationStatus`.
     *
     * @var string
     */
    public $description = '';

    /**
     * Whether applying this invalidates every session, the way a change to a
     * table the session data is built from does. Carries forward the meaning of
     * the value side of the frozen DB_CHANGES map.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * @var SchemaInspector|null The live schema, handed over by the manager
     *   before up() runs.
     */
    private $schemaInspector;

    /**
     * Declare the schema changes. Default no-op: a data-only migration
     * implements afterUp() alone.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
    }

    /**
     * @param SchemaInspector $inspector
     * @return void
     */
    public function setSchemaInspector(SchemaInspector $inspector)
    {
        $this->schemaInspector = $inspector;
    }

    /**
     * The live schema, for check-then-act in up().
     *
     * A migration's statements are not a transaction on MySQL, so one that
     * stops halfway leaves the first statements applied and the ledger row
     * failed - and the retry runs the whole declaration again. Ask
     * hasColumn(), hasIndex() or primaryKey() and declare only what is still
     * missing, and the retry is a no-op for the part that already landed.
     * A single-statement migration needs none of this.
     *
     * The manager sets it before up() runs, for an apply and for a dry run
     * alike; called with nothing set - a unit test driving up() directly -
     * this is an error, not a guess.
     *
     * @return SchemaInspector
     * @throws LogicException
     */
    protected function inspector()
    {
        if ($this->schemaInspector === null) {
            throw new LogicException(sprintf(
                '%s asked for the schema inspector before the migration manager provided one.',
                get_class($this)
            ));
        }
        return $this->schemaInspector;
    }

    /**
     * PHP data work that has to happen before up()'s statements run.
     *
     * The case this exists for is a constraint the current rows would violate:
     * a unique index over a column that still holds duplicates, a NOT NULL
     * over a column with nulls in it. The rows are put right here, through
     * models, and the DDL that follows then applies cleanly. Anything that can
     * wait until the DDL has landed belongs in afterUp() instead.
     *
     * Same contract as afterUp(): runs once, and returning false or throwing
     * marks the migration failed and halts the run - here before any statement
     * has been issued. The inspector is available, so the work can be guarded
     * the way the DDL is, and a retry finds nothing left to do.
     *
     * @return bool
     */
    public function beforeUp()
    {
        return true;
    }

    /**
     * PHP data work, run after up()'s statements have all succeeded.
     *
     * Returning false marks the migration failed just as an exception would, so
     * a seeding step that cannot complete is not silently recorded as applied.
     *
     * @return bool
     */
    public function afterUp()
    {
        return true;
    }

    /**
     * This migration's ledger id.
     *
     * @return string
     * @throws InvalidArgumentException If the class is not named as a migration must be.
     */
    public function id()
    {
        return self::idFromClassName(get_class($this));
    }

    /**
     * The id a migration class name carries.
     *
     * Malformed names are rejected here rather than skipped during discovery. A
     * skipped file is a migration that silently never runs - the exact failure
     * the ledger exists to remove - so a typo in a file name has to be loud.
     *
     * @param string $className
     * @return string
     * @throws InvalidArgumentException
     */
    public static function idFromClassName($className)
    {
        $prefix = self::CLASS_PREFIX;
        if (strpos($className, $prefix) !== 0) {
            throw new InvalidArgumentException(sprintf(
                'Migration class "%s" must be named %s<timestamp>_<slug>, for example %s20260826_120000_event_templates_exposed. The id is the class name without the prefix, so the name is not cosmetic.',
                $className,
                $prefix,
                $prefix
            ));
        }
        $id = substr($className, strlen($prefix));
        if (!self::isMigrationId($id)) {
            throw new InvalidArgumentException(sprintf(
                'Migration class "%s" yields the id "%s", which is not a valid one. An id is YYYYMMDD_HHMMSS_slug with a real date and time - the fixed-width timestamp is what makes sorting ids as strings sort them chronologically.',
                $className,
                $id
            ));
        }
        return $id;
    }

    /**
     * The class name an id belongs to. The inverse of idFromClassName().
     *
     * @param string $id
     * @return string
     */
    public static function classNameFromId($id)
    {
        return self::CLASS_PREFIX . $id;
    }

    /**
     * Is this a well-formed migration id?
     *
     * Also the test that keeps migration ids and legacy update commands in
     * disjoint key spaces: a legacy command is an integer or a '2.4.x' string,
     * neither of which can match this.
     *
     * @param string $id
     * @return bool
     */
    public static function isMigrationId($id)
    {
        if (!is_string($id) || !preg_match(self::ID_PATTERN, $id, $parts)) {
            return false;
        }
        list(, $year, $month, $day, $hour, $minute, $second) = $parts;
        if (!checkdate((int)$month, (int)$day, (int)$year)) {
            return false;
        }
        return (int)$hour < 24 && (int)$minute < 60 && (int)$second < 60;
    }
}
