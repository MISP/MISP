<?php

App::uses('ConnectionManager', 'Model');

/**
 * Reads the live schema: which tables exist, which columns they carry, which
 * indexes are on them.
 *
 * Two callers share it. The migration system uses it for check-then-act - a
 * migration that guards its own DDL ("only add this column if it is missing")
 * is safe to re-run, which is what makes a failed migration retryable rather
 * than a dead end. Runtime code that today hand-writes information_schema and
 * SHOW queries is routed through here as well, so the two stop having separate,
 * independently-wrong answers to "does this index exist?".
 *
 * ## The cache contract
 *
 * This is the part that is easy to get wrong, so it is spelled out.
 *
 * CakePHP keeps three caches of the schema: the `_cake_model_` file cache, and
 * the datasource's in-memory `DataSource::$_descriptions` and `$_sources`.
 * AppModel::cleanCacheFiles() clears only the first. `$_sources` is nulled by
 * DboSource::reconnect(); nothing in the framework ever clears `$_descriptions`.
 * So within one request, a model whose schema() was already read keeps its
 * pre-DDL description - and because Model::save() filters fields against
 * schema(), a write to a freshly added column is silently dropped.
 *
 * The lever that actually works is the public `cacheSources` flag.
 * DataSource::listSources(), DataSource::describe() and
 * DataSource::_cacheDescription() all early-return null while it is false, so a
 * read taken under it bypasses both in-memory arrays and `_cake_model_` without
 * poisoning either. Every read below is wrapped in that toggle, which is why
 * this class always reports the database as it is right now.
 *
 * disableSchemaCache() is the sticky form of the same lever, for the window
 * where DDL has just been applied and PHP data work is about to run against the
 * altered table. It is deliberately not undone: correctness beats the cost of
 * re-running SHOW FULL COLUMNS for the rest of a request that applied a
 * migration.
 */
class SchemaInspector
{
    const FLAVOUR_MYSQL = 'mysql';
    const FLAVOUR_PGSQL = 'pgsql';

    /**
     * @var DboSource
     */
    private $db;

    /**
     * @param DboSource|null $db Defaults to the 'default' connection.
     */
    public function __construct($db = null)
    {
        $this->db = $db === null ? ConnectionManager::getDataSource('default') : $db;
    }

    /**
     * @return DboSource
     */
    public function getDataSource()
    {
        return $this->db;
    }

    /**
     * Which engine this inspector is reading.
     *
     * Matches AppModel::isMysql()'s test, so MysqlExtended and the observer
     * variants all count as MySQL.
     *
     * @return string One of the FLAVOUR_* constants.
     */
    public function flavour()
    {
        return ($this->db instanceof Mysql) ? self::FLAVOUR_MYSQL : self::FLAVOUR_PGSQL;
    }

    /**
     * @return array Table names, as the database spells them.
     */
    public function tables()
    {
        $db = $this->db;
        return $this->uncached(function () use ($db) {
            $sources = $db->listSources();
            return is_array($sources) ? $sources : array();
        });
    }

    /**
     * @param string $table
     * @return bool
     */
    public function hasTable($table)
    {
        return in_array($table, $this->tables(), true);
    }

    /**
     * Column descriptions for a table, keyed by column name.
     *
     * Guarded by hasTable() on purpose: Mysql::describe() throws a CakeException
     * for a table that does not exist rather than returning empty, and a missing
     * table is an ordinary answer to ask this class about, not an error.
     *
     * Costs a listSources() as well as the describe(), since neither is cached
     * while cacheSources is down. Fine for the handful of check-then-act calls a
     * migration makes; worth batching if a hot runtime path ever needs it per
     * row.
     *
     * @param string $table
     * @return array Empty when the table does not exist.
     */
    public function columns($table)
    {
        if (!$this->hasTable($table)) {
            return array();
        }
        $db = $this->db;
        return $this->uncached(function () use ($db, $table) {
            $described = $db->describe($table);
            return is_array($described) ? $described : array();
        });
    }

    /**
     * @param string $table
     * @param string $column
     * @return bool
     */
    public function hasColumn($table, $column)
    {
        $columns = $this->columns($table);
        return isset($columns[$column]);
    }

    /**
     * A single column's description.
     *
     * @param string $table
     * @param string $column
     * @return array|null Null when the table or the column is missing.
     */
    public function column($table, $column)
    {
        $columns = $this->columns($table);
        return isset($columns[$column]) ? $columns[$column] : null;
    }

    /**
     * Indexes on a table, keyed by the physical index name.
     *
     * Both drivers report `column` (string or array) and `unique`; MySQL adds
     * `length` for prefix indexes and `type` for FULLTEXT. Neither driver caches
     * this - Mysql::index() runs SHOW INDEX and Postgres::index() queries
     * pg_catalog every time - so index answers are always fresh regardless of
     * the toggle.
     *
     * @param string $table
     * @return array Empty when the table does not exist.
     */
    public function indexes($table)
    {
        if (!$this->hasTable($table)) {
            return array();
        }
        $indexes = $this->db->index($table);
        return is_array($indexes) ? $indexes : array();
    }

    /**
     * Is there an index over exactly these columns, in this order?
     *
     * Column-set matching rather than name matching, because index *names*
     * diverge between the engines (MySQL names an index after its column,
     * PostgreSQL needs a schema-globally unique name) while the column set is
     * the same question on both. Ask hasNamedIndex() when the physical name is
     * what you actually care about.
     *
     * @param string $table
     * @param string|array $columns One column, or an ordered list.
     * @param bool|null $unique Constrain to unique/non-unique indexes; null matches either.
     * @return bool
     */
    public function hasIndex($table, $columns, $unique = null)
    {
        $wanted = array_values((array)$columns);
        foreach ($this->indexes($table) as $index) {
            if (!isset($index['column'])) {
                continue;
            }
            if (array_values((array)$index['column']) !== $wanted) {
                continue;
            }
            if ($unique !== null && (bool)$index['unique'] !== (bool)$unique) {
                continue;
            }
            return true;
        }
        return false;
    }

    /**
     * Is there an index physically named this?
     *
     * The name is taken literally - no idx_ prefixing, no normalisation. Naming
     * is the grammar's business (AbstractGrammar::indexName()); this class only
     * reports what the database holds.
     *
     * @param string $table
     * @param string $indexName
     * @return bool
     */
    public function hasNamedIndex($table, $indexName)
    {
        return array_key_exists($indexName, $this->indexes($table));
    }

    /**
     * Stop the datasource caching schema reads for the rest of the process.
     *
     * Call this after DDL and before any PHP that touches the altered table
     * through a model. See the cache contract in the class docblock for why the
     * obvious alternative - clearing the caches - does not work: `$_descriptions`
     * has no public clear, and `cleanCacheFiles()` does not reach it.
     *
     * Sticky by design, and not undone. In CLI that costs nothing; in a web
     * request it means Model::schema() re-reads the table until the request
     * ends, and only on requests that actually applied a migration.
     *
     * @return void
     */
    public function disableSchemaCache()
    {
        $this->db->cacheSources = false;
    }

    /**
     * Drop the `_cake_model_` file cache.
     *
     * Partial on its own - it does not touch the datasource's in-memory
     * descriptions - so it is the companion to disableSchemaCache(), not a
     * replacement for it. Kept separate because a CLI process that is about to
     * exit wants the file cache cleared for the *next* process without paying
     * the sticky flag's cost in this one.
     *
     * @return void
     */
    public function flushSchemaCacheFiles()
    {
        Cache::clear(false, '_cake_model_');
    }

    /**
     * Run a reader with the datasource's schema caching switched off, restoring
     * the flag afterwards even if the reader throws.
     *
     * @param Closure $reader
     * @return mixed Whatever the reader returned.
     */
    private function uncached(Closure $reader)
    {
        $wasCaching = $this->db->cacheSources;
        $this->db->cacheSources = false;
        try {
            return $reader();
        } finally {
            $this->db->cacheSources = $wasCaching;
        }
    }
}
