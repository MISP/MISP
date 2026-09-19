<?php

App::uses('AbstractGrammar', 'Migration/Grammar');
App::uses('SchemaBuilder', 'Migration');
App::uses('SchemaInspector', 'Migration');
App::uses('SqlDialect', 'Migration');

/**
 * Renders an install baseline - the INSTALL/<ENGINE>.sql a fresh instance
 * loads before the upgrade system carries it the rest of the way - from a
 * reference MySQL database.
 *
 * ## Why a generator, and why from MySQL
 *
 * The legacy update corpus is frozen at db_version 159 and is MySQL-only
 * verbatim, so a PostgreSQL instance can never replay it. Its only way in is a
 * schema that is already equivalent to 159, seeded at 159, from which the
 * ledger-tracked migrations - flavour-agnostic by construction - carry it
 * forward alongside every MySQL instance. Hand-authoring a hundred-odd tables
 * for that is not realistic and would drift the first time somebody forgot to
 * mirror a change, so the baseline is generated: read a MySQL database that a
 * fresh install plus the frozen corpus produced, map it onto the schema DSL,
 * render through the grammar for the engine wanted. The MySQL baseline is the
 * same tool with the other grammar.
 *
 * ## Why information_schema rather than the driver
 *
 * The driver's describe() is the right reader for check-then-act, and the
 * wrong one here: it folds mediumtext and longtext into text, loses display
 * widths, and its index() has no notion of a prefix length beyond what it
 * happens to parse. information_schema.COLUMNS carries COLUMN_TYPE verbatim
 * and information_schema.STATISTICS carries SEQ_IN_INDEX, NON_UNIQUE and
 * SUB_PART, which is exactly what composite and prefix indexes need. The
 * reference may be a different database on the same server as the connection
 * - a clean install sitting beside a working one - which is why every query
 * filters on a database name the caller chooses rather than on the
 * connection's own.
 *
 * db_schema.json is deliberately not the source: it records one boolean per
 * indexed column and cannot express a composite index, an index name or a
 * prefix length.
 *
 * ## What is knowingly lost or changed on PostgreSQL
 *
 * - Storage hints - ENGINE, charsets, collations, unsigned, display widths -
 *   vanish, which is correct: PostgreSQL handles encoding per database. The
 *   one semantic consequence is that MySQL's case-insensitive collations do
 *   not survive; PostgreSQL compares text exactly.
 * - A prefix-length index has no PostgreSQL equivalent. On a text column a
 *   full-column btree is not a substitute either: btree entries are capped at
 *   roughly a third of a page, and MISP's attribute values routinely exceed
 *   that, so the index would reject real rows. Those indexes render as hash
 *   indexes instead - equality only, which is how the columns are looked up -
 *   unless the index is unique, since a hash index cannot be, in which case
 *   it becomes a full-column btree. Every such rewrite is reported in the
 *   notes so the list can be reviewed rather than trusted.
 * - Expression defaults are translated from a short table; an expression
 *   this class does not know is a hard error rather than a silent drop.
 *
 * @see PostgresGrammar for the column and index rendering this drives.
 * @see SqlDialect::resetSequence() for the sequence catch-up after seeding.
 */
class BaselineGenerator
{
    /**
     * The comment tools/misp-wipe/misp-wipe.sh locates the seed block by.
     * Verbatim, in both baselines.
     */
    const SEED_MARKER = 'Default values for initial installation';

    /**
     * Indexes the PostgreSQL rendering carries that the MySQL reference has
     * nothing to derive them from: what a migration created through rawSql()
     * on PostgreSQL alone, because MySQL gets the same effect from something
     * the CREATE TABLE already says. A fresh install seeds that migration's
     * ledger row, so the index has to come from the baseline, and the
     * round-trip comparison expects it there and nowhere else.
     *
     * Table => index name => statement, with %1$s the quoted index name and
     * %2$s the quoted table.
     */
    const PGSQL_ONLY_INDEXES = array(
        'tags' => array(
            // 20260915_131521_tags_name_case_insensitive: case-insensitive
            // uniqueness of tags.name, which MySQL has through the column's
            // utf8mb4_unicode_ci collation.
            'idx_tags_name_lower' => 'CREATE UNIQUE INDEX %1$s ON %2$s (lower("name"));',
        ),
    );

    /**
     * The tables a fresh install starts with rows in: the ones MYSQL.sql seeds,
     * in its order, plus dashboards, which a legacy update seeds with the
     * default dashboard templates and which a PostgreSQL instance - never
     * replaying that corpus - would otherwise start without. Whatever the
     * reference holds in these is the seed: it is a clean install, so that is
     * exactly the seed data and nothing else.
     *
     * schema_migrations is the exception in kind: its rows are not data the
     * application wants but the ledger's record of which migrations the dump
     * already contains, and a baseline that omits them makes every fresh
     * install re-run those migrations.
     *
     * @var array
     */
    private static $seedTables = array(
        'admin_settings',
        'feeds',
        'regexp',
        'roles',
        'threat_levels',
        'templates',
        'template_elements',
        'template_element_attributes',
        'template_element_files',
        'template_element_texts',
        'org_blocklists',
        'dashboards',
        'schema_migrations',
    );

    /**
     * The admin_settings a baseline seeds. Everything else in that table on
     * the reference - update progress, lock state, failure counters - is the
     * upgrade system's own bookkeeping and must not be carried into a fresh
     * install.
     *
     * @var array
     */
    private static $seedSettings = array('db_version', 'default_role', 'fix_login');

    /**
     * Column defaults that are expressions rather than literals, and how each
     * engine spells them. MariaDB reports these as `name()` in lower case;
     * MySQL reports CURRENT_TIMESTAMP bare and flags anything else with
     * DEFAULT_GENERATED. Keys are normalised to lower case with no spaces.
     *
     * CURRENT_TIMESTAMP is handled inline by DboSource::buildColumn(), which
     * leaves it unquoted on a datetime or timestamp column; the rest are set
     * with an ALTER after the table exists.
     *
     * @var array
     */
    private static $expressionDefaults = array(
        'unix_timestamp()' => array(
            AbstractGrammar::FLAVOUR_MYSQL => 'UNIX_TIMESTAMP()',
            AbstractGrammar::FLAVOUR_PGSQL => 'FLOOR(EXTRACT(EPOCH FROM NOW()))::integer',
        ),
    );

    /**
     * MySQL column types, by their base word, onto the DSL.
     *
     * tinyint is not here: tinyint(1) is a flag and everything else a small
     * integer, and the two are told apart by width in columnSpec().
     *
     * @var array
     */
    private static $typeMap = array(
        'int' => 'integer',
        'integer' => 'integer',
        'bigint' => 'biginteger',
        'smallint' => 'smallinteger',
        'mediumint' => 'integer',
        'varchar' => 'string',
        'char' => 'string',
        'text' => 'text',
        'tinytext' => 'text',
        'mediumtext' => 'mediumtext',
        'longtext' => 'longtext',
        'blob' => 'binary',
        'tinyblob' => 'binary',
        'mediumblob' => 'binary',
        'longblob' => 'binary',
        'varbinary' => 'varbinary',
        'datetime' => 'datetime',
        'timestamp' => 'timestamp',
        'date' => 'date',
        'time' => 'time',
        'float' => 'float',
        'double' => 'float',
        'decimal' => 'decimal',
    );

    /**
     * DSL types whose rendered column carries a length on MySQL. Everything
     * else has its width dropped even there - `text` has none to keep, and a
     * datetime's fractional-seconds precision is the one exception, handled
     * on its own.
     *
     * @var array
     */
    private static $lengthBearing = array(
        'integer', 'biginteger', 'smallinteger', 'tinyinteger', 'boolean',
        'string', 'varbinary', 'decimal', 'float',
    );

    /**
     * DSL types that are text on every engine - the ones a prefix index has
     * to be rewritten for on PostgreSQL.
     *
     * @var array
     */
    private static $textTypes = array('text', 'mediumtext', 'longtext');

    /**
     * @var DboSource The MySQL connection the reference is read through.
     */
    private $db;

    /**
     * @var string The database on that server to read.
     */
    private $database;

    /**
     * @var bool|null Whether the server quotes literal defaults in
     *   information_schema (MariaDB does, MySQL does not). Detected lazily.
     */
    private $quotedDefaults;

    /**
     * @param DboSource $db A MySQL datasource.
     * @param string|null $database The reference database. Defaults to the
     *   one the connection is configured for.
     * @throws InvalidArgumentException When the connection is not MySQL.
     */
    public function __construct(DboSource $db, $database = null)
    {
        if (!($db instanceof Mysql)) {
            throw new InvalidArgumentException(
                'The reference has to be read from a MySQL or MariaDB connection: information_schema.COLUMNS and STATISTICS are what carries the column widths and index prefixes the baseline needs.'
            );
        }
        $this->db = $db;
        $this->database = $database === null
            ? (isset($db->config['database']) ? $db->config['database'] : '')
            : $database;
    }

    /**
     * @return string
     */
    public function database()
    {
        return $this->database;
    }

    // --------------------------------------------------------------- reading

    /**
     * The reference's db_version, as its admin_settings record it.
     *
     * @return int|null Null when the table or the row is missing.
     */
    public function databaseVersion()
    {
        $rows = $this->fetchRows(sprintf(
            'SELECT %s AS value FROM %s WHERE %s = %s;',
            $this->db->name('value'),
            $this->qualified('admin_settings'),
            $this->db->name('setting'),
            $this->db->value('db_version', 'string')
        ));
        if (empty($rows) || !isset($rows[0]['value'])) {
            return null;
        }
        return (int)$rows[0]['value'];
    }

    /**
     * Every base table in the reference, with its columns, indexes and table
     * parameters mapped onto the DSL.
     *
     * @return array table => array(
     *   'columns' => name => DSL spec,
     *   'indexes' => name => index options (with 'column'),
     *   'primary' => the primary key column, or null,
     *   'options' => table parameters ('engine', 'charset', 'collate'),
     *   'expressionDefaults' => column => the expression as the server spelled it,
     * ), in table-name order.
     */
    public function readSchema()
    {
        $tables = array();
        foreach ($this->fetchRows($this->tablesSql()) as $row) {
            $collation = isset($row['TABLE_COLLATION']) ? (string)$row['TABLE_COLLATION'] : '';
            $options = array();
            if (!empty($row['ENGINE'])) {
                $options['engine'] = $row['ENGINE'];
            }
            if ($collation !== '') {
                $options['charset'] = self::charsetOf($collation);
                $options['collate'] = $collation;
            }
            $tables[$row['TABLE_NAME']] = array(
                'columns' => array(),
                'indexes' => array(),
                'primary' => null,
                'options' => $options,
                'expressionDefaults' => array(),
                'collation' => $collation,
            );
        }

        $quoted = $this->quotesLiteralDefaults();
        foreach ($this->fetchRows($this->columnsSql()) as $row) {
            $table = $row['TABLE_NAME'];
            if (!isset($tables[$table])) {
                continue;
            }
            list($spec, $expression) = self::columnSpec($row, $quoted, $tables[$table]['collation']);
            $tables[$table]['columns'][$row['COLUMN_NAME']] = $spec;
            if ($expression !== null) {
                $tables[$table]['expressionDefaults'][$row['COLUMN_NAME']] = $expression;
            }
        }

        $statistics = array();
        foreach ($this->fetchRows($this->statisticsSql()) as $row) {
            $statistics[$row['TABLE_NAME']][] = $row;
        }
        foreach ($tables as $table => $definition) {
            $rows = isset($statistics[$table]) ? $statistics[$table] : array();
            list($primary, $indexes) = self::indexDeclarations($rows);
            if ($primary !== null) {
                if (!isset($tables[$table]['columns'][$primary])) {
                    throw new RuntimeException(sprintf(
                        'Table %s has a primary key on %s, which is not one of its columns.',
                        $table,
                        $primary
                    ));
                }
                $tables[$table]['columns'][$primary]['key'] = 'primary';
            }
            $tables[$table]['primary'] = $primary;
            $tables[$table]['indexes'] = $indexes;
            unset($tables[$table]['collation']);
        }
        return $tables;
    }

    /**
     * The rows a fresh install starts with, read off the reference.
     *
     * @param array $schema What readSchema() returned, for the column list.
     * @return array table => list of rows (column => value), in seed order.
     *   Tables the reference does not have are absent.
     */
    public function readSeedRows(array $schema)
    {
        $seeds = array();
        foreach (self::$seedTables as $table) {
            if (!isset($schema[$table])) {
                continue;
            }
            $columns = array_keys($schema[$table]['columns']);
            $sql = sprintf(
                'SELECT %s FROM %s',
                implode(', ', array_map(array($this->db, 'name'), $columns)),
                $this->qualified($table)
            );
            if ($table === 'admin_settings') {
                $wanted = array();
                foreach (self::$seedSettings as $setting) {
                    $wanted[] = $this->db->value($setting, 'string');
                }
                $sql .= sprintf(' WHERE %s IN (%s)', $this->db->name('setting'), implode(', ', $wanted));
            }
            if (isset($schema[$table]['primary'])) {
                $sql .= ' ORDER BY ' . $this->db->name($schema[$table]['primary']);
            }
            $seeds[$table] = $this->fetchRows($sql . ';');
        }
        return $seeds;
    }

    // --------------------------------------------------------------- mapping

    /**
     * One information_schema.COLUMNS row as a DSL column spec.
     *
     * @param array $row COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_DEFAULT,
     *   EXTRA, and optionally CHARACTER_SET_NAME / COLLATION_NAME.
     * @param bool $quotedDefaults Whether the server quotes literal defaults
     *   in COLUMN_DEFAULT - MariaDB 10.2.7 and later do, MySQL does not.
     * @param string $tableCollation The table's own collation; a column
     *   matching it carries no charset hint of its own.
     * @return array array($spec, $expressionDefault) - the second element is
     *   the default as the server spelled it when it is an expression this
     *   spec cannot carry inline, else null.
     * @throws InvalidArgumentException On a type with no DSL rendering.
     */
    public static function columnSpec(array $row, $quotedDefaults = true, $tableCollation = '')
    {
        $columnType = isset($row['COLUMN_TYPE']) ? strtolower(trim($row['COLUMN_TYPE'])) : '';
        if (!preg_match('/^([a-z]+)(?:\((\d+)(?:,\s*(\d+))?\))?(\s+unsigned)?/', $columnType, $m)) {
            throw new InvalidArgumentException(sprintf(
                'Column %s: cannot read the type "%s".',
                isset($row['COLUMN_NAME']) ? $row['COLUMN_NAME'] : '?',
                $columnType
            ));
        }
        $base = $m[1];
        $width = isset($m[2]) && $m[2] !== '' ? (int)$m[2] : null;
        $scale = isset($m[3]) && $m[3] !== '' ? (int)$m[3] : null;
        $unsigned = !empty($m[4]);

        if ($base === 'enum' || $base === 'set') {
            throw new InvalidArgumentException(sprintf(
                'Column %s is %s, which has no portable rendering.',
                $row['COLUMN_NAME'],
                $columnType
            ));
        }
        if ($base === 'tinyint') {
            // Cake's own describe() reads tinyint(1) as boolean, and so does
            // every flag column in MISP. Any other width is a small integer.
            $type = $width === 1 ? 'boolean' : 'tinyinteger';
        } elseif (isset(self::$typeMap[$base])) {
            $type = self::$typeMap[$base];
        } else {
            throw new InvalidArgumentException(sprintf(
                'Column %s: no DSL type for "%s".',
                $row['COLUMN_NAME'],
                $columnType
            ));
        }

        $spec = array('type' => $type);
        if ($width !== null) {
            if (in_array($type, self::$lengthBearing, true)) {
                $spec['length'] = $scale === null ? $width : $width . ',' . $scale;
            } elseif ($type === 'datetime' || $type === 'timestamp') {
                // Fractional-seconds precision. MySQL renders it; the
                // PostgreSQL grammar drops it, and a timestamp there carries
                // microseconds regardless.
                $spec['length'] = $width;
            }
        }
        if ($unsigned) {
            $spec['unsigned'] = true;
        }
        $spec['null'] = isset($row['IS_NULLABLE']) && strtoupper($row['IS_NULLABLE']) === 'YES';

        $extra = isset($row['EXTRA']) ? strtolower($row['EXTRA']) : '';
        $expression = null;
        list($hasDefault, $default, $isExpression) = self::parseDefault(
            array_key_exists('COLUMN_DEFAULT', $row) ? $row['COLUMN_DEFAULT'] : null,
            $extra,
            $quotedDefaults
        );
        if ($hasDefault) {
            if ($isExpression) {
                $key = strtolower(str_replace(' ', '', $default));
                if ($key === 'current_timestamp' || $key === 'current_timestamp()') {
                    // buildColumn() leaves this one unquoted on a datetime or
                    // timestamp column, on both engines.
                    $spec['default'] = 'CURRENT_TIMESTAMP';
                } else {
                    $expression = $default;
                }
            } else {
                $spec['default'] = $default;
            }
        }

        if (!empty($row['COLLATION_NAME']) && $row['COLLATION_NAME'] !== $tableCollation) {
            $spec['collate'] = $row['COLLATION_NAME'];
            $spec['charset'] = !empty($row['CHARACTER_SET_NAME'])
                ? $row['CHARACTER_SET_NAME']
                : self::charsetOf($row['COLLATION_NAME']);
        }
        if (!empty($row['COLUMN_COMMENT'])) {
            $spec['comment'] = $row['COLUMN_COMMENT'];
        }
        return array($spec, $expression);
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
     * @param bool $quotedDefaults
     * @return array array(bool $hasDefault, mixed $value, bool $isExpression).
     *   An explicit NULL default comes back as (false, null, false): the
     *   grammar emits DEFAULT NULL for a nullable column on its own, and a
     *   NOT NULL column cannot have one.
     */
    public static function parseDefault($default, $extra, $quotedDefaults)
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
     * One table's information_schema.STATISTICS rows as DSL index
     * declarations, plus its primary key.
     *
     * @param array $rows INDEX_NAME, SEQ_IN_INDEX, COLUMN_NAME, NON_UNIQUE,
     *   SUB_PART, INDEX_TYPE - any order.
     * @return array array($primaryKeyColumn|null, name => options). Each
     *   options entry carries 'column' (an ordered list), 'name', 'unique',
     *   and 'length' (column => prefix) or 'fulltext' when they apply.
     * @throws InvalidArgumentException On a composite primary key, which the
     *   DSL cannot declare.
     */
    public static function indexDeclarations(array $rows)
    {
        usort($rows, function ($a, $b) {
            $byName = strcmp($a['INDEX_NAME'], $b['INDEX_NAME']);
            if ($byName !== 0) {
                return $byName;
            }
            return (int)$a['SEQ_IN_INDEX'] - (int)$b['SEQ_IN_INDEX'];
        });

        $primary = array();
        $indexes = array();
        foreach ($rows as $row) {
            $name = $row['INDEX_NAME'];
            if ($name === 'PRIMARY') {
                $primary[] = $row['COLUMN_NAME'];
                continue;
            }
            if (!isset($indexes[$name])) {
                $indexes[$name] = array(
                    'name' => $name,
                    'column' => array(),
                    'unique' => isset($row['NON_UNIQUE']) && (int)$row['NON_UNIQUE'] === 0,
                );
                if (isset($row['INDEX_TYPE']) && strtoupper($row['INDEX_TYPE']) === 'FULLTEXT') {
                    $indexes[$name]['fulltext'] = true;
                    $indexes[$name]['unique'] = false;
                }
            }
            $indexes[$name]['column'][] = $row['COLUMN_NAME'];
            if (isset($row['SUB_PART']) && $row['SUB_PART'] !== null && $row['SUB_PART'] !== '') {
                if (!isset($indexes[$name]['length'])) {
                    $indexes[$name]['length'] = array();
                }
                $indexes[$name]['length'][$row['COLUMN_NAME']] = (int)$row['SUB_PART'];
            }
        }
        if (count($primary) > 1) {
            throw new InvalidArgumentException(sprintf(
                'A composite primary key (%s) cannot be declared through the DSL.',
                implode(', ', $primary)
            ));
        }
        return array(empty($primary) ? null : $primary[0], $indexes);
    }

    // ------------------------------------------------------------- rendering

    /**
     * The whole baseline for one engine.
     *
     * @param AbstractGrammar $grammar Which engine to render for.
     * @param array $schema From readSchema().
     * @param array $seeds From readSeedRows().
     * @param int $dbVersion What the baseline seeds db_version to.
     * @return array array('sql' => string, 'notes' => array of strings). The
     *   notes are every place the rendering is not the reference's shape:
     *   dropped prefix lengths, hash rewrites, truncated names.
     */
    public function render(AbstractGrammar $grammar, array $schema, array $seeds, $dbVersion)
    {
        $flavour = $grammar->flavour();
        $notes = array();
        $out = array();

        $out[] = $this->header($flavour, $dbVersion);
        $out[] = '';
        foreach ($this->preamble($flavour) as $statement) {
            $out[] = $statement;
        }
        $out[] = '';

        foreach ($schema as $table => $definition) {
            foreach ($this->renderTable($grammar, $table, $definition, $notes) as $statement) {
                $out[] = $statement;
            }
            $out[] = '';
        }

        $out[] = '-- --------------------------------------------------------';
        $out[] = '';
        $out[] = '--';
        $out[] = '-- ' . self::SEED_MARKER;
        $out[] = '--';
        $out[] = '';
        foreach ($this->renderSeeds($grammar, $schema, $seeds, $dbVersion) as $statement) {
            $out[] = $statement;
        }

        foreach ($this->postamble($flavour) as $statement) {
            $out[] = $statement;
        }

        return array(
            'sql' => implode(PHP_EOL, $out) . PHP_EOL,
            'notes' => $notes,
        );
    }

    /**
     * One table: CREATE TABLE, its indexes, and any expression default.
     *
     * @param AbstractGrammar $grammar
     * @param string $table
     * @param array $definition One entry of readSchema().
     * @param array $notes Appended to.
     * @return array Statements.
     */
    protected function renderTable(AbstractGrammar $grammar, $table, array $definition, array &$notes)
    {
        $flavour = $grammar->flavour();
        $columns = $definition['columns'];
        $indexes = $definition['indexes'];
        $hashIndexes = array();

        if ($flavour === AbstractGrammar::FLAVOUR_PGSQL) {
            foreach ($indexes as $name => $options) {
                if (!self::needsHashRewrite($options, $columns)) {
                    continue;
                }
                $hashIndexes[$name] = $options;
                unset($indexes[$name]);
            }
            $this->notePostgresNames($table, array_merge($indexes, $hashIndexes), $grammar, $notes);
        }

        if ($definition['primary'] !== null
            && array_key_exists('default', $columns[$definition['primary']])
        ) {
            // DboSource::buildColumn() renders a key column as NOT NULL and
            // nothing else, so a default on one is lost on both engines.
            $notes[] = sprintf(
                'Default %s dropped from the primary key column %s.%s: a key column is rendered without one.',
                var_export($columns[$definition['primary']]['default'], true),
                $table,
                $definition['primary']
            );
        }

        $schema = new SchemaBuilder($grammar);
        $options = $definition['options'];
        $options['indexes'] = $indexes;
        $schema->createTable($table, $columns, $options);
        $statements = $schema->toSql();

        foreach ($grammar->takeDroppedHints() as $hint) {
            $notes[] = $hint;
        }
        foreach ($hashIndexes as $name => $options) {
            $column = $options['column'][0];
            $indexName = $grammar->indexName($table, $options['column'], $options);
            $statements[] = sprintf(
                'CREATE INDEX %s ON %s USING hash (%s);',
                $grammar->name($indexName),
                $grammar->name($table),
                $grammar->name($column)
            );
            $notes[] = sprintf(
                'Prefix index %s on %s(%s(%d)) rendered as a hash index: a full-column btree over a text column would exceed the btree entry limit on long values. Equality lookups only.',
                $indexName,
                $table,
                $column,
                $options['length'][$column]
            );
        }

        if ($flavour === AbstractGrammar::FLAVOUR_PGSQL && isset(self::PGSQL_ONLY_INDEXES[$table])) {
            foreach (self::PGSQL_ONLY_INDEXES[$table] as $indexName => $template) {
                $statements[] = sprintf($template, $grammar->name($indexName), $grammar->name($table));
                $notes[] = sprintf(
                    'PostgreSQL-only index %s added to %s: a migration creates it through rawSql() on PostgreSQL alone, and a fresh install seeds that migration as applied.',
                    $indexName,
                    $table
                );
            }
        }

        foreach ($definition['expressionDefaults'] as $column => $expression) {
            $statements[] = sprintf(
                'ALTER TABLE %s ALTER COLUMN %s SET DEFAULT %s;',
                $grammar->name($table),
                $grammar->name($column),
                self::expressionDefault($expression, $flavour, $table, $column)
            );
        }
        return $statements;
    }

    /**
     * The seed block: one multi-row INSERT per table, ignoring rows that are
     * already there, followed by whatever the engine needs after rows were
     * inserted with their ids set by hand.
     *
     * @param AbstractGrammar $grammar
     * @param array $schema
     * @param array $seeds
     * @param int $dbVersion
     * @return array Statements.
     */
    protected function renderSeeds(AbstractGrammar $grammar, array $schema, array $seeds, $dbVersion)
    {
        $flavour = $grammar->flavour();
        $dialect = new SqlDialect($grammar->getDataSource());
        $statements = array();
        $sequences = array();

        foreach ($seeds as $table => $rows) {
            if (empty($rows) || !isset($schema[$table])) {
                continue;
            }
            $columns = array_keys($rows[0]);
            $renderedRows = array();
            foreach ($rows as $row) {
                $values = array();
                foreach ($columns as $column) {
                    $spec = isset($schema[$table]['columns'][$column]) ? $schema[$table]['columns'][$column] : array('type' => 'string');
                    $values[] = $this->seedValue($grammar, $table, $column, $row, $spec, $dbVersion);
                }
                $renderedRows[] = '(' . implode(', ', $values) . ')';
            }
            $columnList = implode(', ', array_map(array($grammar, 'name'), $columns));
            // admin_settings goes one row per statement, on one line each:
            // tools/misp-wipe/misp-wipe.sh replays this block after a wipe and
            // drops that table's rows by filtering lines, which would leave a
            // multi-row INSERT in pieces.
            $groups = $table === 'admin_settings'
                ? array_chunk($renderedRows, 1)
                : array($renderedRows);
            foreach ($groups as $group) {
                $single = count($group) === 1;
                $rows = $single ? ' ' . $group[0] : "\n" . implode(",\n", $group);
                if ($flavour === AbstractGrammar::FLAVOUR_MYSQL) {
                    $statements[] = sprintf(
                        'INSERT IGNORE INTO %s (%s) VALUES%s;',
                        $grammar->name($table),
                        $columnList,
                        $rows
                    );
                } else {
                    $statements[] = sprintf(
                        'INSERT INTO %s (%s) VALUES%s%sON CONFLICT DO NOTHING;',
                        $grammar->name($table),
                        $columnList,
                        $rows,
                        $single ? ' ' : "\n"
                    );
                }
            }
            $statements[] = '';

            $primary = $schema[$table]['primary'];
            if ($primary !== null && in_array($primary, $columns, true)
                && self::isAutoIncrement($schema[$table]['columns'][$primary])
            ) {
                $reset = $dialect->resetSequence($table, $primary);
                if ($reset !== null) {
                    $sequences[] = $reset;
                }
            }
        }

        if (!empty($sequences)) {
            $statements[] = '-- The rows above carry explicit ids; bring each sequence past them.';
            foreach ($sequences as $statement) {
                $statements[] = $statement;
            }
            $statements[] = '';
        }
        return $statements;
    }

    /**
     * One seed cell, rendered.
     *
     * Three cells are not what the reference holds. db_version is the
     * baseline's own version, not the reference's. fix_login is the moment
     * of installation as a Unix timestamp - the value EventsController reads
     * it back as - taken at load time. And every datetime is NOW(): a seed
     * row's creation date is the install date, which MYSQL.sql has always
     * expressed the same way.
     *
     * @return string An SQL literal or expression.
     */
    protected function seedValue(AbstractGrammar $grammar, $table, $column, array $row, array $spec, $dbVersion)
    {
        $value = isset($row[$column]) ? $row[$column] : null;
        $flavour = $grammar->flavour();

        if ($table === 'admin_settings' && $column === 'value' && isset($row['setting'])) {
            if ($row['setting'] === 'db_version') {
                return $grammar->value((string)$dbVersion, 'string');
            }
            if ($row['setting'] === 'fix_login') {
                return $flavour === AbstractGrammar::FLAVOUR_MYSQL
                    ? 'UNIX_TIMESTAMP()'
                    : 'FLOOR(EXTRACT(EPOCH FROM NOW()))::bigint::text';
            }
        }
        if ($value === null) {
            return 'NULL';
        }
        if (in_array($spec['type'], array('datetime', 'timestamp'), true)) {
            return 'NOW()';
        }
        $rendered = $grammar->value($value, $spec['type']);
        // MysqlExtended::value() hands integers back unquoted, and the
        // reference's cells arrive as strings; both spellings are fine, the
        // point is only that the result is a string to concatenate.
        return (string)$rendered;
    }

    /**
     * A prefix index the PostgreSQL rendering must not turn into a full
     * btree: every prefixed column is text, and the index is not unique.
     *
     * @param array $options One index declaration.
     * @param array $columns The table's column specs.
     * @return bool
     */
    public static function needsHashRewrite(array $options, array $columns)
    {
        if (empty($options['length']) || !empty($options['unique']) || !empty($options['fulltext'])) {
            return false;
        }
        if (count($options['column']) !== 1) {
            // Hash indexes are single-column. A composite prefix index falls
            // through to the grammar, which renders a btree and notes the
            // dropped prefix.
            return false;
        }
        $column = $options['column'][0];
        if (!isset($columns[$column]['type'])) {
            return false;
        }
        return in_array($columns[$column]['type'], self::$textTypes, true);
    }

    /**
     * @param array $spec
     * @return bool Whether the column is an auto-incrementing key.
     */
    public static function isAutoIncrement(array $spec)
    {
        return isset($spec['key']) && $spec['key'] === 'primary'
            && in_array($spec['type'], array('integer', 'biginteger'), true);
    }

    /**
     * @param string $expression As the server spelled it.
     * @param string $flavour
     * @param string $table For the error message.
     * @param string $column For the error message.
     * @return string
     * @throws InvalidArgumentException On an expression with no translation.
     */
    public static function expressionDefault($expression, $flavour, $table, $column)
    {
        $key = strtolower(str_replace(' ', '', $expression));
        if (!isset(self::$expressionDefaults[$key][$flavour])) {
            throw new InvalidArgumentException(sprintf(
                '%s.%s has the expression default "%s", which this generator cannot spell for %s. Add it to the translation table.',
                $table,
                $column,
                $expression,
                $flavour
            ));
        }
        return self::$expressionDefaults[$key][$flavour];
    }

    // ---------------------------------------------------------- verification

    /**
     * What each driver's describe() reports for a DSL type, once the baseline
     * has been loaded and is read back. Mysql::describe() folds every text
     * tier into text, reads tinyint(1) as boolean, and has no branch for
     * varbinary at all, so that lands on its fall-through - text.
     * Postgres::describe() has no tiers to fold and no widths to keep.
     *
     * @var array flavour => DSL type => reported type
     */
    private static $reportedTypes = array(
        AbstractGrammar::FLAVOUR_MYSQL => array(
            'integer' => 'integer', 'biginteger' => 'biginteger',
            'smallinteger' => 'smallinteger', 'tinyinteger' => 'tinyinteger',
            'boolean' => 'boolean', 'string' => 'string', 'text' => 'text',
            'mediumtext' => 'text', 'longtext' => 'text', 'binary' => 'binary',
            'varbinary' => 'text', 'datetime' => 'datetime', 'timestamp' => 'timestamp',
            'date' => 'date', 'time' => 'time', 'float' => 'float', 'decimal' => 'decimal',
        ),
        AbstractGrammar::FLAVOUR_PGSQL => array(
            'integer' => 'integer', 'biginteger' => 'biginteger',
            'smallinteger' => 'smallinteger', 'tinyinteger' => 'smallinteger',
            'boolean' => 'boolean', 'string' => 'string', 'text' => 'text',
            'mediumtext' => 'text', 'longtext' => 'text', 'binary' => 'binary',
            'varbinary' => 'binary', 'datetime' => 'datetime', 'timestamp' => 'datetime',
            'date' => 'date', 'time' => 'time', 'float' => 'float', 'decimal' => 'decimal',
        ),
    );

    /**
     * Read a loaded baseline back and diff it against the reference's shape.
     *
     * The round trip that makes a generated baseline trustworthy: the schema
     * the reference described, as the DSL saw it, against what the driver's
     * own describe() and index() report from a database the baseline was
     * loaded into. Every column's reported type, nullability, string length
     * and default, every primary key, and every index's column list and
     * uniqueness are compared, in both directions - a column or index the
     * loaded database has that the reference did not is a finding too.
     *
     * What is normalised, and why: the DSL's boolean default is a MySQL 0/1
     * where Postgres::describe() hands back a PHP boolean; a CURRENT_TIMESTAMP
     * default is one Mysql::describe() reports as no default at all; an
     * expression default is compared by presence, since the two engines spell
     * it differently by design; and a default on a key column is dropped by
     * the rendering, so none is expected back. Index names are compared
     * through the grammar, which is what prefixes them on PostgreSQL.
     *
     * @param SchemaInspector $inspector Reading the database the baseline was loaded into.
     * @param array $schema From readSchema(), off the reference.
     * @return array Findings, one line each. Empty means the round trip is exact.
     */
    public function compare(SchemaInspector $inspector, array $schema)
    {
        $grammar = AbstractGrammar::forDataSource($inspector->getDataSource());
        $flavour = $grammar->flavour();
        $reported = self::$reportedTypes[$flavour];
        $findings = array();

        $loadedTables = $inspector->tables();
        foreach ($schema as $table => $definition) {
            if (!in_array($table, $loadedTables, true)) {
                $findings[] = sprintf('%s: table missing', $table);
                continue;
            }

            $columns = $inspector->columns($table);
            foreach ($definition['columns'] as $name => $spec) {
                if (!isset($columns[$name])) {
                    $findings[] = sprintf('%s.%s: column missing', $table, $name);
                    continue;
                }
                $actual = $columns[$name];
                $isKey = !empty($spec['key']);

                $wantType = isset($reported[$spec['type']]) ? $reported[$spec['type']] : $spec['type'];
                if ($actual['type'] !== $wantType) {
                    $findings[] = sprintf(
                        '%s.%s: type %s, expected %s (DSL %s)',
                        $table, $name, $actual['type'], $wantType, $spec['type']
                    );
                }

                $wantNull = !$isKey && !empty($spec['null']);
                if ((bool)$actual['null'] !== $wantNull) {
                    $findings[] = sprintf(
                        '%s.%s: %s, expected %s',
                        $table, $name, $actual['null'] ? 'nullable' : 'not null', $wantNull ? 'nullable' : 'not null'
                    );
                }

                if ($spec['type'] === 'string' && isset($spec['length'])
                    && (int)$actual['length'] !== (int)$spec['length']
                ) {
                    $findings[] = sprintf(
                        '%s.%s: length %s, expected %s',
                        $table, $name, var_export($actual['length'], true), $spec['length']
                    );
                }

                $finding = $this->compareDefault(
                    $spec,
                    $isKey,
                    isset($definition['expressionDefaults'][$name]),
                    isset($actual['default']) ? $actual['default'] : null
                );
                if ($finding !== null) {
                    $findings[] = sprintf('%s.%s: %s', $table, $name, $finding);
                }
            }
            foreach (array_keys($columns) as $name) {
                if (!isset($definition['columns'][$name])) {
                    $findings[] = sprintf('%s.%s: column not in the reference', $table, $name);
                }
            }

            $indexes = $inspector->indexes($table);
            $primary = isset($indexes['PRIMARY']) ? array_values((array)$indexes['PRIMARY']['column']) : null;
            unset($indexes['PRIMARY']);
            if ($definition['primary'] !== null) {
                if ($primary !== array($definition['primary'])) {
                    $findings[] = sprintf(
                        '%s: primary key %s, expected (%s)',
                        $table, $primary === null ? 'missing' : '(' . implode(', ', $primary) . ')', $definition['primary']
                    );
                }
            } elseif ($primary !== null) {
                $findings[] = sprintf('%s: primary key (%s) not in the reference', $table, implode(', ', $primary));
            }

            foreach ($definition['indexes'] as $name => $options) {
                $physical = $grammar->indexName($table, $options['column'], $options);
                if (!isset($indexes[$physical])) {
                    $findings[] = sprintf('%s: index %s missing', $table, $physical);
                    continue;
                }
                $got = $indexes[$physical];
                $gotColumns = array_values((array)$got['column']);
                if ($gotColumns !== array_values($options['column'])) {
                    $findings[] = sprintf(
                        '%s: index %s over (%s), expected (%s)',
                        $table, $physical, implode(', ', $gotColumns), implode(', ', $options['column'])
                    );
                }
                if ((bool)$got['unique'] !== (bool)$options['unique']) {
                    $findings[] = sprintf(
                        '%s: index %s is %s, expected %s',
                        $table, $physical, $got['unique'] ? 'unique' : 'not unique', $options['unique'] ? 'unique' : 'not unique'
                    );
                }
                unset($indexes[$physical]);
            }
            if ($flavour === AbstractGrammar::FLAVOUR_PGSQL && isset(self::PGSQL_ONLY_INDEXES[$table])) {
                foreach (array_keys(self::PGSQL_ONLY_INDEXES[$table]) as $only) {
                    if (!isset($indexes[$only])) {
                        $findings[] = sprintf('%s: PostgreSQL-only index %s missing', $table, $only);
                    }
                    unset($indexes[$only]);
                }
            }
            foreach (array_keys($indexes) as $extra) {
                $findings[] = sprintf('%s: index %s not in the reference', $table, $extra);
            }
        }
        foreach ($loadedTables as $table) {
            if (!isset($schema[$table])) {
                $findings[] = sprintf('%s: table not in the reference', $table);
            }
        }
        return $findings;
    }

    /**
     * @param array $spec The DSL column spec.
     * @param bool $isKey
     * @param bool $isExpression Whether the reference's default was an expression.
     * @param mixed $actual What describe() reported.
     * @return string|null A finding, or null when the defaults agree.
     */
    private function compareDefault(array $spec, $isKey, $isExpression, $actual)
    {
        $actualIsSet = $actual !== null && $actual !== '';
        if ($isKey) {
            // Dropped by the rendering, so nothing is expected back - but a
            // serial's nextval() is reported by neither driver, so only an
            // unexpected literal is worth a line.
            return null;
        }
        if ($isExpression) {
            return $actualIsSet ? null : 'expression default missing';
        }
        if (!array_key_exists('default', $spec)) {
            return $actual === null || $actual === '' && $spec['type'] !== 'string'
                ? null
                : 'default ' . var_export($actual, true) . ', expected none';
        }
        $want = $spec['default'];
        if (is_string($want) && strtoupper($want) === 'CURRENT_TIMESTAMP') {
            // Mysql::describe() reports it as no default; Postgres::describe()
            // hands the expression back.
            if ($actual === null || preg_match('/^current_timestamp(\(\))?$/i', (string)$actual)) {
                return null;
            }
            return 'default ' . var_export($actual, true) . ', expected CURRENT_TIMESTAMP';
        }
        if ($spec['type'] === 'boolean') {
            $wantBool = (bool)(int)$want;
            $actualBool = is_bool($actual) ? $actual : (bool)(int)$actual;
            if ($actual === null || $wantBool !== $actualBool) {
                return 'default ' . var_export($actual, true) . ', expected ' . var_export($wantBool, true);
            }
            return null;
        }
        if ($actual === null || (string)$actual !== (string)$want) {
            return 'default ' . var_export($actual, true) . ', expected ' . var_export($want, true);
        }
        return null;
    }

    // --------------------------------------------------------------- helpers

    /**
     * PostgreSQL truncates an identifier to 63 bytes without complaint, and
     * two index names that differ only past that point collide.
     */
    private function notePostgresNames($table, array $indexes, AbstractGrammar $grammar, array &$notes)
    {
        foreach ($indexes as $options) {
            $name = $grammar->indexName($table, $options['column'], $options);
            if (strlen($name) > 63) {
                $notes[] = sprintf(
                    'Index name %s is %d bytes; PostgreSQL keeps the first 63.',
                    $name,
                    strlen($name)
                );
            }
        }
    }

    /**
     * @param string $flavour
     * @param int $dbVersion
     * @return string
     */
    private function header($flavour, $dbVersion)
    {
        $engine = $flavour === AbstractGrammar::FLAVOUR_MYSQL ? 'MySQL / MariaDB' : 'PostgreSQL';
        return implode(PHP_EOL, array(
            '-- MISP ' . $engine . ' install baseline, equivalent to db_version ' . $dbVersion . '.',
            '--',
            '-- Generated with `Console/cake Admin dumpInstallBaseline` from a reference',
            '-- database; regenerate it the same way rather than editing the DDL by',
            '-- hand. The seed block after the DDL is what a fresh instance starts',
            '-- with; the upgrade system carries it the rest of the way.',
        ));
    }

    /**
     * @param string $flavour
     * @return array Statements that go before the DDL.
     */
    private function preamble($flavour)
    {
        if ($flavour === AbstractGrammar::FLAVOUR_MYSQL) {
            return array('/*!40101 SET NAMES utf8mb4 */;');
        }
        return array(
            "SET client_encoding = 'UTF8';",
            // The seed values quote a backslash as itself. That has been the
            // default since 9.1; stated so that a server configured otherwise
            // still loads the same data.
            'SET standard_conforming_strings = on;',
            'BEGIN;',
        );
    }

    /**
     * @param string $flavour
     * @return array Statements that go after the seed block.
     */
    private function postamble($flavour)
    {
        if ($flavour === AbstractGrammar::FLAVOUR_MYSQL) {
            return array();
        }
        return array('COMMIT;');
    }

    /**
     * @param string $table
     * @return string database.table, quoted.
     */
    private function qualified($table)
    {
        return $this->db->name($this->database) . '.' . $this->db->name($table);
    }

    /**
     * @return string
     */
    private function tablesSql()
    {
        return sprintf(
            'SELECT TABLE_NAME, ENGINE, TABLE_COLLATION FROM information_schema.TABLES'
                . " WHERE TABLE_SCHEMA = %s AND TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME;",
            $this->db->value($this->database, 'string')
        );
    }

    /**
     * @return string
     */
    private function columnsSql()
    {
        return sprintf(
            'SELECT TABLE_NAME, COLUMN_NAME, ORDINAL_POSITION, COLUMN_DEFAULT, IS_NULLABLE,'
                . ' COLUMN_TYPE, CHARACTER_SET_NAME, COLLATION_NAME, EXTRA, COLUMN_COMMENT'
                . ' FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = %s'
                . ' ORDER BY TABLE_NAME, ORDINAL_POSITION;',
            $this->db->value($this->database, 'string')
        );
    }

    /**
     * @return string
     */
    private function statisticsSql()
    {
        return sprintf(
            'SELECT TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX, COLUMN_NAME, NON_UNIQUE, SUB_PART, INDEX_TYPE'
                . ' FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = %s'
                . ' ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX;',
            $this->db->value($this->database, 'string')
        );
    }

    /**
     * MariaDB quotes literal defaults in information_schema; MySQL does not.
     *
     * @return bool
     */
    protected function quotesLiteralDefaults()
    {
        if ($this->quotedDefaults === null) {
            $rows = $this->fetchRows('SELECT VERSION() AS version;');
            $version = isset($rows[0]['version']) ? $rows[0]['version'] : '';
            $this->quotedDefaults = stripos($version, 'mariadb') !== false;
        }
        return $this->quotedDefaults;
    }

    /**
     * @param string $collation
     * @return string The charset a collation belongs to - the part before
     *   the first underscore, which is how MySQL names them.
     */
    private static function charsetOf($collation)
    {
        $parts = explode('_', $collation, 2);
        return $parts[0];
    }

    /**
     * Read-only catalog rows, flat. Same reasoning as
     * SchemaInspector::fetchRows(): Model::query() nests by a driver-chosen
     * key and fetchAll() caches, and neither is wanted for a catalog read.
     *
     * @param string $sql
     * @return array
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
}
