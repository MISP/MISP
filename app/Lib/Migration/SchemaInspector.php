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
 * tableDefinition() reads the catalog too: the driver folds mediumtext into
 * text, drops auto-increment, and cannot read a PostgreSQL expression index.
 * Its MySQL queries are the ones BaselineGenerator reads a reference with.
 *
 * ## The cache contract
 *
 * This is the part that is easy to get wrong, so it is spelled out.
 *
 * CakePHP keeps four caches of the schema: the `_cake_model_` file cache, the
 * datasource's in-memory `DataSource::$_descriptions` and `$_sources`, and
 * DboSource's method cache, which holds the column list of a find without a
 * field list. The method cache is loaded from `_cake_core_` on first use and
 * written back whole by every process that added to it, on exit.
 * AppModel::cleanCacheFiles() clears the two file caches. `$_sources` is nulled by
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
 * migration. It also empties the method cache, which `cacheSources` does not
 * reach: a cleared file alone is refilled with the old column lists when this
 * process exits. MISP's datasources key those lists by the columns besides
 * (CurrentColumnListTrait), which covers the processes a migration never sees.
 */
class SchemaInspector
{
    const FLAVOUR_MYSQL = 'mysql';
    const FLAVOUR_PGSQL = 'pgsql';

    /**
     * A table's options on PostgreSQL, which has none of them.
     *
     * @var array
     */
    private static $noOptions = array('engine' => null, 'row_format' => null, 'collation' => null, 'charset' => null);

    /**
     * @var DboSource
     */
    private $db;

    /**
     * @var bool|null Detected lazily; the server does not change under us.
     */
    private $mariaDb;

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

    // ----------------------------------------------------- definition surface

    /**
     * A table as the catalog defines it, with what describe() and index() fold
     * away or cannot read.
     *
     * - `options`: `engine`, `row_format` (the format the table has, upper
     *   case), `collation`, `charset`. All null on PostgreSQL.
     * - `columns`, by name, in table order:
     *   - `type` verbatim in lower case (`int(11) unsigned`; PostgreSQL's
     *     format_type(), `character varying(255)`), split into `base`,
     *     `length` and `scale`. MySQL 8 reports integers without a width.
     *   - `unsigned`, `null`.
     *   - `default`: the literal as a string, or null for none;
     *     `default_expression` when it is an expression. PostgreSQL booleans
     *     read `true`/`false`.
     *   - `charset`, `collation`: null for a non-string column. On PostgreSQL
     *     charset is always null, and collation is null unless the column
     *     sets one of its own.
     *   - `increment`: null, `auto_increment`, `identity` or `serial`. A
     *     serial column's nextval() is reported here, not as its default.
     * - `indexes`, by name, the primary key as `PRIMARY` on both engines:
     *   - `name`: the physical name (PostgreSQL: `<table>_pkey`).
     *   - `column`: in key order, always a list. An expression key part reads
     *     as PostgreSQL prints it, e.g. `lower(name::text)`, and as null on
     *     MySQL 8, whose STATISTICS MariaDB cannot be asked for the text.
     *   - `unique`, `primary`, `expression`.
     *   - `length`: column => prefix length, for prefixed parts only.
     *   - `type`: `btree`, `fulltext`, `hash`, `gin`, ...
     *   - `definition`: pg_get_indexdef(), which carries what the parts above
     *     do not (operator class, predicate). Null on MySQL.
     *
     * @param string $table
     * @return array|null Null when there is no such table.
     */
    public function tableDefinition($table)
    {
        return $this->isMysql() ? $this->mysqlDefinition($table) : $this->postgresDefinition($table);
    }

    /**
     * tableDefinition()'s `options` alone, for one catalog query.
     *
     * @param string $table
     * @return array|null Null when there is no such table.
     */
    public function tableOptions($table)
    {
        if (!$this->isMysql()) {
            return $this->hasTable($table) ? self::$noOptions : null;
        }
        $tables = $this->fetchRows(self::mysqlTablesSql($this->db, $this->databaseName(), $table));
        if (empty($tables)) {
            return null;
        }
        $collation = empty($tables[0]['TABLE_COLLATION']) ? null : $tables[0]['TABLE_COLLATION'];
        return array(
            'engine' => empty($tables[0]['ENGINE']) ? null : $tables[0]['ENGINE'],
            'row_format' => empty($tables[0]['ROW_FORMAT']) ? null : strtoupper($tables[0]['ROW_FORMAT']),
            'collation' => $collation,
            'charset' => $collation === null ? null : self::charsetOfCollation($collation),
        );
    }

    /**
     * @return bool Whether the server is MariaDB; false on PostgreSQL.
     */
    public function isMariaDb()
    {
        if ($this->mariaDb === null) {
            $this->mariaDb = false;
            if ($this->isMysql()) {
                $rows = $this->fetchRows('SELECT VERSION() AS version;');
                $version = isset($rows[0]['version']) ? $rows[0]['version'] : '';
                $this->mariaDb = stripos($version, 'mariadb') !== false;
            }
        }
        return $this->mariaDb;
    }

    /**
     * The base tables of a MySQL database: name, engine, collation, row format.
     *
     * The MySQL catalog queries take the database by name because
     * BaselineGenerator reads a reference beside the connection's own.
     *
     * @param DboSource $db Quotes the values.
     * @param string $database
     * @param string|null $table Only this one; all of them when null.
     * @return string
     */
    public static function mysqlTablesSql(DboSource $db, $database, $table = null)
    {
        return sprintf(
            'SELECT TABLE_NAME, ENGINE, TABLE_COLLATION, ROW_FORMAT FROM information_schema.TABLES'
                . " WHERE TABLE_SCHEMA = %s AND TABLE_TYPE = 'BASE TABLE'%s ORDER BY TABLE_NAME;",
            $db->value($database, 'string'),
            self::tableFilter($db, $table)
        );
    }

    /**
     * @param DboSource $db
     * @param string $database
     * @param string|null $table
     * @return string
     */
    public static function mysqlColumnsSql(DboSource $db, $database, $table = null)
    {
        return sprintf(
            'SELECT TABLE_NAME, COLUMN_NAME, ORDINAL_POSITION, COLUMN_DEFAULT, IS_NULLABLE,'
                . ' COLUMN_TYPE, CHARACTER_SET_NAME, COLLATION_NAME, EXTRA, COLUMN_COMMENT'
                . ' FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = %s%s'
                . ' ORDER BY TABLE_NAME, ORDINAL_POSITION;',
            $db->value($database, 'string'),
            self::tableFilter($db, $table)
        );
    }

    /**
     * @param DboSource $db
     * @param string $database
     * @param string|null $table
     * @return string
     */
    public static function mysqlStatisticsSql(DboSource $db, $database, $table = null)
    {
        return sprintf(
            'SELECT TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX, COLUMN_NAME, NON_UNIQUE, SUB_PART, INDEX_TYPE'
                . ' FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = %s%s'
                . ' ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX;',
            $db->value($database, 'string'),
            self::tableFilter($db, $table)
        );
    }

    /**
     * What a COLUMN_DEFAULT cell means.
     *
     * Three servers, three spellings. MariaDB (10.2.7+) quotes literals,
     * spells an explicit NULL as the word, and shows expressions bare. MySQL
     * shows literals bare and flags expression defaults with
     * DEFAULT_GENERATED in EXTRA, except CURRENT_TIMESTAMP on a datetime,
     * which is bare and unflagged. A SQL NULL means the column has no
     * default on both.
     *
     * @param string|null $default
     * @param string $extra Lower-cased.
     * @param bool $quotedDefaults Whether the server is MariaDB.
     * @return array array(bool $hasDefault, mixed $value, bool $isExpression).
     *   An explicit NULL default comes back as (false, null, false).
     */
    public static function parseMysqlDefault($default, $extra, $quotedDefaults)
    {
        if ($default === null) {
            return array(false, null, false);
        }
        $default = (string)$default;
        if (strpos($extra, 'default_generated') !== false) {
            return array(true, $default, true);
        }
        if ($quotedDefaults) {
            if (strtoupper($default) === 'NULL') {
                return array(false, null, false);
            }
            if (preg_match("/^'(.*)'$/s", $default, $m)) {
                return array(true, str_replace("''", "'", $m[1]), false);
            }
            if (is_numeric($default)) {
                return array(true, $default, false);
            }
            return array(true, $default, true);
        }
        if (preg_match('/^current_timestamp(\(\d*\))?$/i', $default)) {
            return array(true, 'CURRENT_TIMESTAMP', true);
        }
        return array(true, $default, false);
    }

    /**
     * A MySQL COLUMN_TYPE in parts.
     *
     * @param string $columnType
     * @return array|null array($base, $width|null, $scale|null, $unsigned),
     *   or null when it is not a type.
     */
    public static function splitMysqlType($columnType)
    {
        if (!preg_match('/^([a-z]+)(?:\((\d+)(?:,\s*(\d+))?\))?(\s+unsigned)?/', strtolower(trim($columnType)), $m)) {
            return null;
        }
        return array(
            $m[1],
            isset($m[2]) && $m[2] !== '' ? (int)$m[2] : null,
            isset($m[3]) && $m[3] !== '' ? (int)$m[3] : null,
            !empty($m[4]),
        );
    }

    /**
     * One table's information_schema.STATISTICS rows as index definitions,
     * the primary key included, in the shape tableDefinition() reports.
     *
     * @param array $rows INDEX_NAME, SEQ_IN_INDEX, COLUMN_NAME, NON_UNIQUE,
     *   SUB_PART, INDEX_TYPE - any order.
     * @return array name => definition, by name.
     */
    public static function mysqlIndexes(array $rows)
    {
        usort($rows, function ($a, $b) {
            $byName = strcmp($a['INDEX_NAME'], $b['INDEX_NAME']);
            if ($byName !== 0) {
                return $byName;
            }
            return (int)$a['SEQ_IN_INDEX'] - (int)$b['SEQ_IN_INDEX'];
        });

        $indexes = array();
        foreach ($rows as $row) {
            $name = $row['INDEX_NAME'];
            if (!isset($indexes[$name])) {
                $type = isset($row['INDEX_TYPE']) ? strtolower($row['INDEX_TYPE']) : 'btree';
                $indexes[$name] = array(
                    'name' => $name,
                    'column' => array(),
                    'unique' => $type !== 'fulltext' && isset($row['NON_UNIQUE']) && (int)$row['NON_UNIQUE'] === 0,
                    'primary' => $name === 'PRIMARY',
                    'length' => array(),
                    'type' => $type,
                    'expression' => false,
                    'definition' => null,
                );
            }
            $column = isset($row['COLUMN_NAME']) ? $row['COLUMN_NAME'] : null;
            $indexes[$name]['column'][] = $column;
            if ($column === null) {
                $indexes[$name]['expression'] = true;
            } elseif (isset($row['SUB_PART']) && $row['SUB_PART'] !== '') {
                $indexes[$name]['length'][$column] = (int)$row['SUB_PART'];
            }
        }
        return $indexes;
    }

    /**
     * @param string $collation
     * @return string The charset a MySQL collation belongs to - the part
     *   before the first underscore, which is how MySQL names them.
     */
    public static function charsetOfCollation($collation)
    {
        $parts = explode('_', $collation, 2);
        return $parts[0];
    }

    /**
     * @param string $table
     * @return array|null
     */
    private function mysqlDefinition($table)
    {
        $options = $this->tableOptions($table);
        if ($options === null) {
            return null;
        }
        $database = $this->databaseName();

        $quoted = $this->isMariaDb();
        $columns = array();
        foreach ($this->fetchRows(self::mysqlColumnsSql($this->db, $database, $table)) as $row) {
            $type = strtolower(trim($row['COLUMN_TYPE']));
            $parts = self::splitMysqlType($type);
            $extra = isset($row['EXTRA']) ? strtolower($row['EXTRA']) : '';
            list($hasDefault, $default, $isExpression) = self::parseMysqlDefault(
                array_key_exists('COLUMN_DEFAULT', $row) ? $row['COLUMN_DEFAULT'] : null,
                $extra,
                $quoted
            );
            $columns[$row['COLUMN_NAME']] = array(
                'type' => $type,
                'base' => $parts === null ? $type : $parts[0],
                'length' => $parts === null ? null : $parts[1],
                'scale' => $parts === null ? null : $parts[2],
                'unsigned' => $parts !== null && $parts[3],
                'null' => isset($row['IS_NULLABLE']) && strtoupper($row['IS_NULLABLE']) === 'YES',
                'default' => $hasDefault ? (string)$default : null,
                'default_expression' => $hasDefault && $isExpression,
                'charset' => empty($row['CHARACTER_SET_NAME']) ? null : $row['CHARACTER_SET_NAME'],
                'collation' => empty($row['COLLATION_NAME']) ? null : $row['COLLATION_NAME'],
                'increment' => strpos($extra, 'auto_increment') !== false ? 'auto_increment' : null,
            );
        }

        $indexes = self::mysqlIndexes($this->fetchRows(self::mysqlStatisticsSql($this->db, $database, $table)));
        return array('options' => $options, 'columns' => $columns, 'indexes' => $indexes);
    }

    /**
     * @param string $table
     * @return array|null
     */
    private function postgresDefinition($table)
    {
        $found = $this->fetchRows(sprintf(
            'SELECT c.oid AS oid FROM pg_catalog.pg_class c'
                . ' JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace'
                . " WHERE n.nspname = %s AND c.relname = %s AND c.relkind IN ('r', 'p');",
            $this->db->value($this->schemaName(), 'string'),
            $this->db->value($table, 'string')
        ));
        if (empty($found)) {
            return null;
        }
        $oid = (int)$found[0]['oid'];

        $columns = array();
        $rows = $this->fetchRows(
            'SELECT a.attname AS column_name, pg_catalog.format_type(a.atttypid, a.atttypmod) AS column_type,'
                . ' a.attnotnull AS not_null, a.attidentity AS identity,'
                . ' pg_catalog.pg_get_expr(d.adbin, d.adrelid) AS column_default,'
                . " CASE WHEN co.collname <> 'default' THEN co.collname END AS collation_name"
                . ' FROM pg_catalog.pg_attribute a'
                . ' LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum'
                . ' LEFT JOIN pg_catalog.pg_collation co ON co.oid = a.attcollation'
                . ' WHERE a.attrelid = ' . $oid . ' AND a.attnum > 0 AND NOT a.attisdropped'
                . ' ORDER BY a.attnum;'
        );
        foreach ($rows as $row) {
            $type = strtolower($row['column_type']);
            $length = $scale = null;
            $base = $type;
            if (preg_match('/\((\d+)(?:,(\d+))?\)/', $type, $m)) {
                $length = (int)$m[1];
                $scale = isset($m[2]) ? (int)$m[2] : null;
                $base = trim(preg_replace('/\s+/', ' ', str_replace($m[0], '', $type)));
            }
            $increment = null;
            $default = $row['column_default'];
            if (!empty($row['identity'])) {
                $increment = 'identity';
            } elseif ($default !== null && stripos($default, 'nextval(') === 0) {
                $increment = 'serial';
                $default = null;
            }
            list($default, $isExpression) = self::parsePostgresDefault($default);
            $columns[$row['column_name']] = array(
                'type' => $type,
                'base' => $base,
                'length' => $length,
                'scale' => $scale,
                'unsigned' => false,
                'null' => !self::pgBool($row['not_null']),
                'default' => $default,
                'default_expression' => $isExpression,
                'charset' => null,
                'collation' => $row['collation_name'],
                'increment' => $increment,
            );
        }

        $indexes = array();
        $rows = $this->fetchRows(
            'SELECT ic.relname AS index_name, i.indisprimary AS is_primary, i.indisunique AS is_unique,'
                . ' am.amname AS index_type, pg_catalog.pg_get_indexdef(i.indexrelid) AS definition,'
                . ' i.indkey[k.n - 1] AS attnum,'
                . ' CASE WHEN i.indkey[k.n - 1] = 0 THEN pg_catalog.pg_get_indexdef(i.indexrelid, k.n, true)'
                . ' ELSE a.attname END AS column_name'
                . ' FROM pg_catalog.pg_index i'
                . ' JOIN pg_catalog.pg_class ic ON ic.oid = i.indexrelid'
                . ' JOIN pg_catalog.pg_am am ON am.oid = ic.relam'
                . ' CROSS JOIN LATERAL generate_series(1, i.indnkeyatts) AS k(n)'
                . ' LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[k.n - 1]'
                . ' WHERE i.indrelid = ' . $oid
                . ' ORDER BY ic.relname, k.n;'
        );
        foreach ($rows as $row) {
            $primary = self::pgBool($row['is_primary']);
            $key = $primary ? 'PRIMARY' : $row['index_name'];
            if (!isset($indexes[$key])) {
                $indexes[$key] = array(
                    'name' => $row['index_name'],
                    'column' => array(),
                    'unique' => self::pgBool($row['is_unique']),
                    'primary' => $primary,
                    'length' => array(),
                    'type' => $row['index_type'],
                    'expression' => false,
                    'definition' => $row['definition'],
                );
            }
            $indexes[$key]['column'][] = $row['column_name'];
            if ((int)$row['attnum'] === 0) {
                $indexes[$key]['expression'] = true;
            }
        }
        ksort($indexes, SORT_STRING);
        return array(
            'options' => self::$noOptions,
            'columns' => $columns,
            'indexes' => $indexes,
        );
    }

    /**
     * What pg_get_expr() prints for a column default.
     *
     * @param string|null $default
     * @return array array($value|null, bool $isExpression).
     */
    private static function parsePostgresDefault($default)
    {
        if ($default === null || preg_match('/^NULL(::[a-z ]+)?$/i', $default)) {
            return array(null, false);
        }
        if (preg_match("/^'((?:[^']|'')*)'(?:::[a-z_ ]+(?:\(\d+(?:,\d+)?\))?(?:\[\])?)?$/is", $default, $m)) {
            return array(str_replace("''", "'", $m[1]), false);
        }
        if (is_numeric($default) || $default === 'true' || $default === 'false') {
            return array($default, false);
        }
        return array($default, true);
    }

    /**
     * @param mixed $value A PostgreSQL boolean as PDO hands it over.
     * @return bool
     */
    private static function pgBool($value)
    {
        return $value === true || $value === 1 || in_array($value, array('t', 'true', '1'), true);
    }

    /**
     * @param DboSource $db
     * @param string|null $table
     * @return string
     */
    private static function tableFilter(DboSource $db, $table)
    {
        return $table === null ? '' : ' AND TABLE_NAME = ' . $db->value($table, 'string');
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
     * The method cache is emptied rather than disabled: what fills it after
     * the DDL is current, and is what this process writes back on exit.
     *
     * @return void
     */
    public function disableSchemaCache()
    {
        $this->db->cacheSources = false;
        $this->db->flushMethodCache();
    }

    /**
     * Drop the `_cake_model_` and `_cake_core_` file caches.
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
        Cache::clear(false, '_cake_core_');
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
