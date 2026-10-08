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
 * ## Two ways of reading, and why
 *
 * The schema surface - tables(), columns(), indexes() and everything built on
 * them - goes through the driver's own listSources(), describe() and index(),
 * because CakePHP already writes those queries for both engines and writing
 * them again here would only add a second thing to be wrong.
 *
 * The runtime surface - table sizes, row estimates, server variables, the
 * process list - has no driver equivalent, so it queries the catalog directly
 * and every method carries an implementation per engine. That is not a
 * spelling difference: PostgreSQL's answers live in pg_catalog, in different
 * tables, under different names, and one of them (the process list) it does
 * not have at all. Spelling differences belong in SqlDialect; this is where
 * the genuinely structural ones go, so that a call site gets one method rather
 * than a branch.
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
 * poisoning either. Every read that goes through the driver is wrapped in that
 * toggle, which is why this class always reports the database as it is right
 * now. The catalog reads need no toggle - nothing caches them, which is also
 * why fetchRows() goes to the PDO statement rather than DboSource::fetchAll(),
 * whose query cache is on by default.
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
        return $this->isMysql() ? self::FLAVOUR_MYSQL : self::FLAVOUR_PGSQL;
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
        if (!is_array($indexes)) {
            return array();
        }
        // Postgres::index() reads its column names out of pg_get_indexdef(),
        // which quotes any identifier that needs it - MISP's 1_event_id family
        // does - and the quotes come through. Strip them, so a column is
        // spelled here the way the DSL and the MySQL driver spell it and
        // hasIndex() can find it.
        foreach ($indexes as $name => $index) {
            if (!isset($index['column'])) {
                continue;
            }
            $indexes[$name]['column'] = is_array($index['column'])
                ? array_map(array($this, 'unquoteIdentifier'), $index['column'])
                : $this->unquoteIdentifier($index['column']);
        }
        return $indexes;
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
     * @param bool $includePrimary The primary key is an index too, and answers
     *   by default. Pass false when the question is whether the columns are
     *   covered by something *other* than the key - before dropping it.
     * @return bool
     */
    public function hasIndex($table, $columns, $unique = null, $includePrimary = true)
    {
        $wanted = array_values((array)$columns);
        foreach ($this->indexes($table) as $name => $index) {
            if (!isset($index['column'])) {
                continue;
            }
            if (!$includePrimary && $name === 'PRIMARY') {
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
     * The primary key's columns, in order.
     *
     * Read off the index list rather than describe(): both drivers report the
     * key as an index named PRIMARY (Cake's Postgres driver renames the pkey
     * index to that), whereas Postgres::describe() only flags a column as
     * primary when it is serial or is the primary key of the *model* it was
     * handed - a table keyed on a varchar, described by name, shows no key.
     *
     * @param string $table
     * @return array Empty when the table has no primary key, or does not exist.
     */
    public function primaryKey($table)
    {
        $indexes = $this->indexes($table);
        if (!isset($indexes['PRIMARY']['column'])) {
            return array();
        }
        return array_values((array)$indexes['PRIMARY']['column']);
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

    // -------------------------------------------------------- runtime surface

    /**
     * The physical index a column is part of, or null when it is in none.
     *
     * No catalog query of its own - the driver's index() already answers this
     * on both engines, so this is the column-to-name lookup laid over it. A
     * column that appears in several indexes reports the first, which is what
     * the SHOW INDEX loop this replaces did.
     *
     * Membership, not position: an index over (org_id, date) answers for both
     * of its columns. That is deliberately looser than hasIndex(), which asks
     * about an exact ordered column set, and it is the question the callers
     * being replaced were really asking - `SHOW INDEX ... WHERE Column_name`
     * matches a column wherever it sits in the index.
     *
     * @param string $table
     * @param string $column
     * @param bool|null $unique Constrain to unique/non-unique indexes; null matches either.
     * @return string|null
     */
    public function indexNameForColumn($table, $column, $unique = null)
    {
        foreach ($this->indexes($table) as $name => $index) {
            if (!isset($index['column'])) {
                continue;
            }
            if (!in_array($column, (array)$index['column'], true)) {
                continue;
            }
            if ($unique !== null && (bool)$index['unique'] !== (bool)$unique) {
                continue;
            }
            return $name;
        }
        return null;
    }

    /**
     * Roughly how many rows a table holds.
     *
     * An estimate out of the catalog, not a COUNT(*) - which is the point, and
     * why the callers that use it for a page-header row count are happy with
     * it. Both engines keep the figure as a by-product of their statistics, so
     * it is stale by however long it has been since the table was last
     * analysed, and on a large InnoDB table it can be off by a wide margin.
     *
     * A never-analysed table reports NULL on MySQL and -1 on PostgreSQL 13 and
     * later; both come back as 0 here, because "no estimate" is closer to zero
     * than to minus one and no caller wants a negative row count.
     *
     * @param string $table
     * @return int Zero when the table is unknown or has never been analysed.
     */
    public function tableRowEstimate($table)
    {
        if ($this->isMysql()) {
            $sql = sprintf(
                'SELECT TABLE_ROWS AS row_estimate FROM information_schema.TABLES'
                    . ' WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s;',
                $this->db->value($this->databaseName(), 'string'),
                $this->db->value($table, 'string')
            );
        } else {
            $sql = sprintf(
                'SELECT c.reltuples AS row_estimate FROM pg_catalog.pg_class c'
                    . ' JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace'
                    . ' WHERE n.nspname = %s AND c.relname = %s;',
                $this->db->value($this->schemaName(), 'string'),
                $this->db->value($table, 'string')
            );
        }
        $rows = $this->fetchRows($sql);
        if (empty($rows) || !isset($rows[0]['row_estimate'])) {
            return 0;
        }
        return max(0, (int)$rows[0]['row_estimate']);
    }

    /**
     * What every table in the database costs on disk, keyed by table name.
     *
     * One query for the whole database rather than one per table: the three
     * callers this serves either want the total or walk a list, and a
     * per-table round trip inside a loop is what the code being replaced does.
     *
     * Each entry carries `table`, `data_in_bytes`, `index_in_bytes`,
     * `total_in_bytes`, `reclaimable_in_bytes` and `row_estimate`.
     * `total_in_bytes` is data plus indexes, because every caller wants that
     * sum and none of them should be adding it up themselves.
     *
     * `reclaimable_in_bytes` is MySQL's DATA_FREE and is always 0 on
     * PostgreSQL. Not an omission: dead tuples there are reclaimed by
     * autovacuum and the catalog exposes no per-table byte figure for them, so
     * the hand-written branch this replaces reported "0 MB" for the same
     * reason.
     *
     * Views and other non-tables are excluded on both engines. On PostgreSQL
     * that filter is not optional - pg_class holds indexes, sequences and
     * views alongside tables.
     *
     * @return array
     */
    public function tableSizes()
    {
        if ($this->isMysql()) {
            $sql = sprintf(
                'SELECT TABLE_NAME AS table_name, DATA_LENGTH AS data_length,'
                    . ' INDEX_LENGTH AS index_length, DATA_FREE AS data_free,'
                    . ' TABLE_ROWS AS row_estimate'
                    . ' FROM information_schema.TABLES'
                    . " WHERE TABLE_SCHEMA = %s AND TABLE_TYPE = 'BASE TABLE';",
                $this->db->value($this->databaseName(), 'string')
            );
        } else {
            $sql = sprintf(
                'SELECT c.relname AS table_name, pg_table_size(c.oid) AS data_length,'
                    . ' pg_indexes_size(c.oid) AS index_length, 0 AS data_free,'
                    . ' c.reltuples AS row_estimate'
                    . ' FROM pg_catalog.pg_class c'
                    . ' JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace'
                    . " WHERE n.nspname = %s AND c.relkind IN ('r', 'p');",
                $this->db->value($this->schemaName(), 'string')
            );
        }
        $sizes = array();
        foreach ($this->fetchRows($sql) as $row) {
            if (!isset($row['table_name'])) {
                continue;
            }
            $data = isset($row['data_length']) ? (int)$row['data_length'] : 0;
            $index = isset($row['index_length']) ? (int)$row['index_length'] : 0;
            $sizes[$row['table_name']] = array(
                'table' => $row['table_name'],
                'data_in_bytes' => $data,
                'index_in_bytes' => $index,
                'total_in_bytes' => $data + $index,
                'reclaimable_in_bytes' => isset($row['data_free']) ? (int)$row['data_free'] : 0,
                'row_estimate' => max(0, isset($row['row_estimate']) ? (int)$row['row_estimate'] : 0),
            );
        }
        return $sizes;
    }

    /**
     * The engine's configuration, as a flat name => value map.
     *
     * Both engines answer this, and neither vocabulary overlaps the other, so
     * a caller looking for a MySQL tunable simply finds nothing on PostgreSQL
     * - which is the whole reason the diagnostic that uses this needs no
     * branch of its own.
     *
     * @return array
     */
    public function serverVariables()
    {
        $variables = array();
        if ($this->isMysql()) {
            foreach ($this->fetchRows('SHOW VARIABLES;') as $row) {
                if (isset($row['Variable_name'])) {
                    $variables[$row['Variable_name']] = isset($row['Value']) ? $row['Value'] : null;
                }
            }
            return $variables;
        }
        foreach ($this->fetchRows('SELECT name, setting FROM pg_catalog.pg_settings;') as $row) {
            if (isset($row['name'])) {
                $variables[$row['name']] = isset($row['setting']) ? $row['setting'] : null;
            }
        }
        return $variables;
    }

    /**
     * What the server is executing right now, one flat row per connection.
     *
     * MySQL's PROCESSLIST columns are passed through as the server spells
     * them, MariaDB's STAGE / MAX_STAGE / PROGRESS included - that is how the
     * update-progress screen shows a live ALTER working through a large table,
     * and there is nothing engine-neutral to normalise them to.
     *
     * PostgreSQL returns an empty list, deliberately and without querying
     * anything. pg_stat_activity would give running statements, but nothing
     * there corresponds to the stage-and-progress figures the only caller
     * wants, so the screen degrades to no live DDL state rather than erroring
     * or inventing one.
     *
     * @return array
     */
    public function runningQueries()
    {
        if (!$this->isMysql()) {
            return array();
        }
        return $this->fetchRows('SELECT * FROM information_schema.PROCESSLIST;');
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
     * Execute one read-only catalog query and return its rows flat.
     *
     * Deliberately not Model::query() or DboSource::fetchAll(). Both nest each
     * row under a table alias whose key depends on the driver, and split a row
     * across two of them as soon as a column is computed rather than selected
     * - which is why the code being replaced reaches into `[0][0]['size_mb']`
     * for one figure and `['TABLES']['Rows']` for the next. Introspection
     * queries are mostly computed columns, so going through the PDO statement
     * and asking for associative rows removes that whole class of shape bug
     * instead of teaching every caller to work around it. fetchAll() also
     * caches by default, which for a live catalog read would be wrong.
     *
     * Protected rather than private so a test can stand in for the one place
     * this class talks to a real connection.
     *
     * @param string $sql
     * @return array Rows as associative arrays; empty when the query returned
     *   no result set.
     */
    protected function fetchRows($sql)
    {
        $statement = $this->db->rawQuery($sql);
        if (!is_object($statement)) {
            return array();
        }
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        $statement->closeCursor();
        return is_array($rows) ? $rows : array();
    }

    /**
     * Matches AppModel::isMysql(), so MysqlExtended and the observer variants
     * all count as MySQL.
     *
     * @return bool
     */
    private function isMysql()
    {
        return $this->db instanceof Mysql;
    }

    /**
     * @param mixed $identifier
     * @return mixed The identifier without the quotes a driver left on it.
     */
    private function unquoteIdentifier($identifier)
    {
        return is_string($identifier) ? trim($identifier, '"`') : $identifier;
    }

    /**
     * @return string The database MySQL's information_schema queries filter on.
     */
    private function databaseName()
    {
        return isset($this->db->config['database']) ? $this->db->config['database'] : '';
    }

    /**
     * @return string The namespace PostgreSQL's pg_catalog queries filter on.
     */
    private function schemaName()
    {
        if (isset($this->db->config['schema']) && $this->db->config['schema'] !== '') {
            return $this->db->config['schema'];
        }
        return 'public';
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
