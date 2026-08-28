<?php

App::uses('AbstractMigration', 'Migration');
App::uses('MigrationRunner', 'Migration');
App::uses('SchemaBuilder', 'Migration');
App::uses('SchemaInspector', 'Migration');
App::uses('AbstractGrammar', 'Migration/Grammar');
App::uses('Folder', 'Utility');

/**
 * Owns the new-style migrations: finding them, knowing which have run, and
 * running the ones that have not.
 *
 * The counterpart to the frozen legacy corpus. Where that corpus is driven by a
 * single integer high-water mark - db_version - this is driven by a ledger
 * table with one row per migration. The difference is the point of the whole
 * exercise: a high-water mark answers "how far did we get", which silently
 * skips anything that arrives numbered below where an instance already is,
 * while a ledger answers "did this particular migration run", which cannot.
 *
 * ## What it does not do
 *
 * It does not decide when to run. runUpdates() owns the lock, the worker
 * dispatch and the ordering of legacy updates against migrations; this class
 * answers pending() and applies one id at a time. It does not execute SQL
 * either - MigrationRunner does, so a migration is logged, progress-reported
 * and error-tolerated exactly the way a legacy update is.
 *
 * ## Ordering and halting
 *
 * pending() is discovered ids minus ledger ids that are 'applied', in id order.
 * Ids are fixed-width timestamps, so ksort() is chronological order.
 *
 * applyPending() stops at the first failure and leaves every successor pending
 * and untried. That is deliberate and it is the behaviour the legacy path did
 * not have: a three-step change - add a column, backfill it, drop the old one -
 * must not run its third step when its first one failed. The failed migration
 * is retried first on the next run.
 *
 * ## The ledger is written without a model
 *
 * schema_migrations is created and written through plain statements rather than
 * a CakePHP model, for two reasons. It has to be readable in the same call that
 * creates it, before any model could be trusted to have described it; and a
 * portable upsert does not exist across the two engines, where a delete
 * followed by an insert does. Five infrastructure columns are not the place to
 * pay for that.
 *
 * @see AbstractMigration
 * @see MigrationRunner
 * @see SchemaInspector
 */
class MigrationManager
{
    const LEDGER_TABLE = 'schema_migrations';

    const STATUS_APPLIED = 'applied';
    const STATUS_FAILED = 'failed';

    /**
     * App::uses() package the migration classes are resolved from.
     */
    const MIGRATIONS_PACKAGE = 'Migration/Migrations';

    /**
     * The ledger's columns, as the DSL spells them. Rendered through the grammar
     * like any other DDL rather than written out as SQL, so the table arrives on
     * PostgreSQL without a second hand-maintained definition.
     *
     * varchar(191) because 767 bytes of index prefix divided by utf8mb4's four
     * bytes per character is 191 - the same reason the existing schema already
     * has 33 columns of exactly that width.
     *
     * @var array
     */
    private static $ledgerColumns = array(
        'id' => array('type' => 'string', 'length' => 191, 'null' => false, 'key' => 'primary'),
        'applied_at' => array('type' => 'datetime', 'null' => false),
        'duration_ms' => array('type' => 'integer', 'null' => false, 'default' => 0),
        'status' => array('type' => 'string', 'length' => 16, 'null' => false, 'default' => self::STATUS_APPLIED),
        'error' => array('type' => 'text', 'null' => true),
    );

    /**
     * @var array Table parameters MySQL understands and PostgreSQL drops.
     */
    private static $ledgerOptions = array(
        'engine' => 'InnoDB',
        'charset' => 'utf8mb4',
    );

    /**
     * The model the ledger statements and the migrations are run through.
     *
     * @var Model
     */
    private $model;

    /**
     * @var string Absolute path to the directory holding the migration classes.
     */
    protected $directory;

    /** @var MigrationRunner|null */
    private $runner;

    /** @var SchemaInspector|null */
    private $inspector;

    /** @var Log|null */
    private $Log;

    /**
     * @var array|null id => AbstractMigration, in id order. Null until discovered.
     */
    protected $migrations;

    /**
     * @var array|null id => ledger row. Null until read.
     */
    protected $ledger;

    /**
     * @var bool Whether the ledger table has been confirmed to exist this run.
     */
    private $ledgerReady = false;

    /**
     * @var string|null Why the most recent apply() failed. Set by execute().
     */
    protected $lastError;

    /**
     * @param Model $model Supplies the datasource and carries the statements.
     * @param string|null $directory Defaults to app/Lib/Migration/Migrations.
     */
    public function __construct(Model $model, $directory = null)
    {
        $this->model = $model;
        $this->directory = $directory === null
            ? APP . 'Lib' . DS . 'Migration' . DS . 'Migrations'
            : $directory;
    }

    // ------------------------------------------------------------- discovery

    /**
     * Every migration on disk, keyed by id, in id order.
     *
     * @return array id => AbstractMigration
     * @throws InvalidArgumentException On a file that is not a well-formed migration.
     */
    public function migrations()
    {
        if ($this->migrations === null) {
            $this->migrations = $this->discoverMigrations();
        }
        return $this->migrations;
    }

    /**
     * @return array Ids, in order.
     */
    public function ids()
    {
        return array_keys($this->migrations());
    }

    /**
     * @param string $id
     * @return bool
     */
    public function has($id)
    {
        $migrations = $this->migrations();
        return isset($migrations[$id]);
    }

    /**
     * @param string $id
     * @return AbstractMigration
     * @throws InvalidArgumentException If no migration carries that id.
     */
    public function migration($id)
    {
        $migrations = $this->migrations();
        if (!isset($migrations[$id])) {
            throw new InvalidArgumentException(sprintf(
                'No migration with the id "%s". Expected a file named %s.php in %s.',
                $id,
                AbstractMigration::classNameFromId($id),
                $this->directory
            ));
        }
        return $migrations[$id];
    }

    // ---------------------------------------------------------------- ledger

    /**
     * Create the ledger table if it is not there yet.
     *
     * Not itself a migration - a migration system whose ledger is a migration
     * has nowhere to record that it ran.
     *
     * @return void
     */
    public function ensureLedger()
    {
        if ($this->ledgerReady) {
            return;
        }
        if (!$this->inspector()->hasTable(self::LEDGER_TABLE)) {
            $schema = SchemaBuilder::forDataSource($this->dataSource());
            $schema->createTable(self::LEDGER_TABLE, self::$ledgerColumns, self::$ledgerOptions);
            foreach ($schema->toSql() as $statement) {
                $this->model->query($statement);
            }
            // The table did not exist a moment ago, and something is about to
            // read it back in this same call.
            $this->inspector()->disableSchemaCache();
        }
        $this->ledgerReady = true;
    }

    /**
     * The ledger as it stands, keyed by id.
     *
     * May contain ids with no file behind them - a migration that was reverted
     * out of the tree leaves its row. pending() ignores those; migrationStatus
     * reports them.
     *
     * @return array id => array('id', 'applied_at', 'duration_ms', 'status', 'error')
     */
    public function ledger()
    {
        if ($this->ledger === null) {
            $this->ledger = $this->readLedger();
        }
        return $this->ledger;
    }

    /**
     * @return array Ids the ledger records as applied.
     */
    public function applied()
    {
        return array_keys($this->ledgerByStatus(self::STATUS_APPLIED));
    }

    /**
     * @return array Ids the ledger records as failed. Still pending - a failure
     *   is a retry, not a decision.
     */
    public function failed()
    {
        return array_keys($this->ledgerByStatus(self::STATUS_FAILED));
    }

    /**
     * Migrations that have not successfully run, in id order.
     *
     * The shape is deliberately the one findUpgrades() already produces -
     * command => requiresLogout - so that runUpdates() can union the two and
     * keep its single loop.
     *
     * @return array id => bool requiresLogout
     */
    public function pending()
    {
        $applied = $this->ledgerByStatus(self::STATUS_APPLIED);
        $pending = array();
        foreach ($this->migrations() as $id => $migration) {
            if (!isset($applied[$id])) {
                $pending[$id] = (bool)$migration->requiresLogout;
            }
        }
        return $pending;
    }

    // --------------------------------------------------------------- running

    /**
     * Apply one migration and record the outcome.
     *
     * @param string $id
     * @return bool
     */
    public function apply($id)
    {
        $migration = $this->migration($id);
        $this->ensureLedger();
        $this->lastError = null;

        $startedAt = microtime(true);
        try {
            $success = $this->execute($id, $migration);
        } catch (Exception $e) {
            $success = false;
            $this->lastError = $e->getMessage();
        }
        $durationMs = (int)round((microtime(true) - $startedAt) * 1000);

        $this->writeLedger(
            $id,
            $success ? self::STATUS_APPLIED : self::STATUS_FAILED,
            $durationMs,
            $success ? null : $this->lastError
        );
        return $success;
    }

    /**
     * Apply every pending migration in order, stopping at the first failure.
     *
     * The halt is the contract, not an optimisation. A migration that depends on
     * its predecessor - and migrations authored together in one branch routinely
     * do - must not run against a schema its predecessor failed to produce.
     *
     * @return array id => bool, in the order they were attempted. Ends at the
     *   failure; everything after it is absent and stays pending.
     */
    public function applyPending()
    {
        $results = array();
        foreach (array_keys($this->pending()) as $id) {
            $results[$id] = $this->apply($id);
            if (!$results[$id]) {
                break;
            }
        }
        return $results;
    }

    /**
     * The statements a migration would emit, without executing anything.
     *
     * @param string $id
     * @param AbstractGrammar|null $grammar Render for an engine other than the
     *   connected one - what a two-flavour dry run needs.
     * @return array
     */
    public function toSql($id, AbstractGrammar $grammar = null)
    {
        $schema = SchemaBuilder::forDataSource($this->dataSource());
        $this->migration($id)->up($schema);
        return $schema->toSql($grammar);
    }

    /**
     * @return string|null Why the most recent apply() failed.
     */
    public function lastError()
    {
        return $this->lastError;
    }

    /**
     * @return SchemaInspector Shared, so a migration guarding its own DDL reads
     *   the same live schema the manager does.
     */
    public function inspector()
    {
        if ($this->inspector === null) {
            $this->inspector = new SchemaInspector($this->dataSource());
        }
        return $this->inspector;
    }

    // ------------------------------------------------------- seams and guts

    /**
     * Walk the migrations directory and instantiate what it holds.
     *
     * Follows the discovery pattern the rest of the codebase uses for pluggable
     * classes - read the directory, take the file name as the class name,
     * App::uses(), instantiate - with one difference: nothing here is skipped.
     * A file that does not yield a usable migration throws, because a migration
     * that is quietly not discovered is a migration that quietly never runs.
     *
     * @return array id => AbstractMigration, in id order.
     * @throws InvalidArgumentException
     */
    protected function discoverMigrations()
    {
        $migrations = array();
        foreach ($this->migrationFiles() as $file) {
            $className = substr($file, 0, -4);
            $id = AbstractMigration::idFromClassName($className);
            $this->loadMigrationClass($className);
            if (!class_exists($className)) {
                throw new InvalidArgumentException(sprintf(
                    'The migration file %s does not declare a class called "%s". CakePHP resolves a class by its file name, so the two have to agree.',
                    $this->directory . DS . $file,
                    $className
                ));
            }
            $migration = new $className();
            if (!($migration instanceof AbstractMigration)) {
                throw new InvalidArgumentException(sprintf(
                    'The migration class "%s" does not extend AbstractMigration.',
                    $className
                ));
            }
            $migrations[$id] = $migration;
        }
        ksort($migrations);
        return $migrations;
    }

    /**
     * @return array File names, not paths.
     */
    protected function migrationFiles()
    {
        $folder = new Folder($this->directory);
        return $folder->find('.*\.php', true);
    }

    /**
     * @param string $className
     * @return void
     */
    protected function loadMigrationClass($className)
    {
        App::uses($className, self::MIGRATIONS_PACKAGE);
    }

    /**
     * Run one migration's DDL and then its data work.
     *
     * @param string $id
     * @param AbstractMigration $migration
     * @return bool
     */
    protected function execute($id, AbstractMigration $migration)
    {
        $schema = SchemaBuilder::forDataSource($this->dataSource());
        $migration->up($schema);
        $statements = $schema->toSql();
        $this->reportDroppedHints($id, $schema->getGrammar()->takeDroppedHints());

        if (!empty($statements)) {
            // exitOnError, unlike the legacy path: the statements of one
            // migration are a unit, and continuing past a broken one produces a
            // half-applied schema recorded as applied.
            if (!$this->runner()->run($id, $statements, array(), false, true, true)) {
                $errors = $this->runner()->lastErrors();
                $this->lastError = empty($errors)
                    ? __('The migration stopped on an error.')
                    : implode(PHP_EOL, $errors);
                return false;
            }
            // The DDL has landed and afterUp() is about to touch those tables
            // through models. Model::save() filters against a schema description
            // that nothing in CakePHP invalidates, so without this a write to a
            // column added a moment ago is silently dropped.
            $this->inspector()->disableSchemaCache();
        }

        if ($migration->afterUp() === false) {
            $this->lastError = __('afterUp() reported failure.');
            return false;
        }
        return true;
    }

    /**
     * @return array id => ledger row.
     */
    protected function readLedger()
    {
        $this->ensureLedger();
        $db = $this->dataSource();
        $sql = sprintf(
            'SELECT %s FROM %s;',
            implode(', ', array_map(array($db, 'name'), array_keys(self::$ledgerColumns))),
            $db->name(self::LEDGER_TABLE)
        );
        $ledger = array();
        foreach ((array)$this->model->query($sql) as $row) {
            $fields = $this->unwrapRow($row);
            if (isset($fields['id'])) {
                $ledger[$fields['id']] = $fields;
            }
        }
        return $ledger;
    }

    /**
     * Record an outcome, replacing any previous one for the same id, and keep
     * the in-memory view of the ledger in step with it.
     *
     * @param string $id
     * @param string $status
     * @param int $durationMs
     * @param string|null $error
     * @return void
     */
    protected function writeLedger($id, $status, $durationMs, $error = null)
    {
        $this->ensureLedger();
        $row = array(
            'id' => $id,
            'applied_at' => date('Y-m-d H:i:s'),
            'duration_ms' => (int)$durationMs,
            'status' => $status,
            'error' => $error,
        );
        $this->persistLedgerRow($row);
        if ($this->ledger === null) {
            $this->ledger = array();
        }
        $this->ledger[$id] = $row;
    }

    /**
     * Put one row in the ledger table, replacing any row already under that id.
     *
     * Delete-then-insert rather than an upsert: ON DUPLICATE KEY UPDATE is
     * MySQL's spelling alone, and this has to work on both engines.
     *
     * @param array $row Keyed by the ledger's column names.
     * @return void
     */
    protected function persistLedgerRow(array $row)
    {
        $db = $this->dataSource();
        $table = $db->name(self::LEDGER_TABLE);

        $this->model->query(sprintf(
            'DELETE FROM %s WHERE %s = %s;',
            $table,
            $db->name('id'),
            $db->value($row['id'], 'string')
        ));

        $values = array();
        foreach (self::$ledgerColumns as $column => $spec) {
            $value = isset($row[$column]) ? $row[$column] : null;
            $values[] = $value === null ? 'NULL' : $db->value($value, $spec['type']);
        }
        $this->model->query(sprintf(
            'INSERT INTO %s (%s) VALUES (%s);',
            $table,
            implode(', ', array_map(array($db, 'name'), array_keys(self::$ledgerColumns))),
            implode(', ', $values)
        ));
    }

    /**
     * @return MigrationRunner The same executor the legacy path uses.
     */
    protected function runner()
    {
        if ($this->runner === null) {
            $this->runner = new MigrationRunner($this->model);
        }
        return $this->runner;
    }

    /**
     * @return DboSource
     */
    protected function dataSource()
    {
        return $this->model->getDataSource();
    }

    /**
     * A hint the grammar could not express is worth a log line, not silence.
     * Dropping an index prefix length changes what the index indexes.
     *
     * @param string $id
     * @param array $hints
     * @return void
     */
    protected function reportDroppedHints($id, array $hints)
    {
        if (empty($hints)) {
            return;
        }
        if ($this->Log === null) {
            $this->Log = ClassRegistry::init('Log');
        }
        $this->Log->create();
        $this->Log->saveOrFailSilently(array(
            'org' => 'SYSTEM',
            'model' => 'Server',
            'model_id' => 0,
            'email' => 'SYSTEM',
            'action' => 'update_database',
            'user_id' => 0,
            'title' => __('Schema hints dropped while rendering the migration %s', $id),
            'change' => implode(PHP_EOL, $hints),
        ));
    }

    /**
     * @param string $status
     * @return array id => row
     */
    private function ledgerByStatus($status)
    {
        $matching = array();
        foreach ($this->ledger() as $id => $row) {
            if (isset($row['status']) && $row['status'] === $status) {
                $matching[$id] = $row;
            }
        }
        return $matching;
    }

    /**
     * Model::query() nests a raw result under the table it came from, but which
     * key that is depends on the driver, so take the nesting apart by shape
     * rather than by name.
     *
     * @param array $row
     * @return array
     */
    private function unwrapRow($row)
    {
        if (!is_array($row)) {
            return array();
        }
        if (isset($row[self::LEDGER_TABLE]) && is_array($row[self::LEDGER_TABLE])) {
            return $row[self::LEDGER_TABLE];
        }
        if (isset($row['id'])) {
            return $row;
        }
        $first = reset($row);
        return is_array($first) ? $first : array();
    }
}
