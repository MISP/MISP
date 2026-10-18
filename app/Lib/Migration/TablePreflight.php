<?php

App::uses('AbstractGrammar', 'Migration/Grammar');
App::uses('BaselineGenerator', 'Migration');
App::uses('Collation', 'Migration');
App::uses('MigrationDeferredException', 'Migration');
App::uses('SchemaInspector', 'Migration');
App::uses('SchemaTargetGenerator', 'Migration');
App::uses('TableConverger', 'Migration');

/**
 * What has to hold before TableConverger changes a table, checked against
 * the server and the rows when the migration is applied. A rebuild that would
 * fail hours in, or quietly change data, defers instead, saying what to do
 * first.
 *
 * - The server is a release 3.0 supports.
 * - Every index left after the run fits the server's key limit (MySQL).
 * - PostgreSQL can create the extension an added index needs.
 * - latin1 columns: UTF-8 bytes stored as latin1 pass through a binary type,
 *   so that they are read as utf8mb4 rather than converted a second time; a
 *   column that mixes them with latin1 text defers.
 * - The rows fit their target columns: nothing too long, no NULL where the
 *   target says NOT NULL, no number out of range; a missing NOT NULL column
 *   without a default can be filled.
 * - uuid and hash columns hold ASCII only.
 * - No two rows share a value of a unique key the run adds, or of one whose
 *   new collation compares more values as equal.
 * - The disk holds what the run writes, estimated from the target.
 *
 * A row check reads an index where one covers its column and otherwise shares
 * one scan of the table; a hit names the first rows.
 */
class TablePreflight
{
    const PGSQL_FLOOR = 16;

    /** Types PostgreSQL gets no value for in the rows of an added NOT NULL column. */
    const UNFILLED_TYPES = array('datetime', 'timestamp', 'date', 'time');

    /** InnoDB's key limit under ROW_FORMAT=DYNAMIC on pages under 16 KB; 3,072 bytes otherwise. */
    const KEY_LIMITS = array(4096 => 768, 8192 => 1536);

    /** Free disk under the estimate defers; under it times this, it is a warning. */
    const SPACE_MARGIN = 1.3;

    /** Bytes below which a run on a server whose disk cannot be read goes unmentioned. */
    const SPACE_QUIET = 268435456;

    /** What a string part of an index entry is taken to average, in bytes. */
    const STRING_ENTRY = 40;

    /** Bytes of an index entry besides its parts and the key. */
    const ENTRY_OVERHEAD = 6;

    /** Pages and tree over raw entry bytes, where the catalog has no index size to scale. */
    const PAGE_OVERHEAD = 1.5;

    /** How many rows or values a deferral names. */
    const LISTED = 10;

    const WIDTHS = array(
        'boolean' => 1, 'tinyinteger' => 1, 'smallinteger' => 2, 'integer' => 4, 'biginteger' => 8,
        'float' => 8, 'decimal' => 8, 'date' => 3, 'time' => 3, 'datetime' => 5, 'timestamp' => 4,
    );

    /** Signed minimum, signed maximum, unsigned maximum. */
    const INTEGER_RANGES = array(
        'tinyinteger' => array('-128', '127', '255'),
        'smallinteger' => array('-32768', '32767', '65535'),
        'integer' => array('-2147483648', '2147483647', '4294967295'),
        'biginteger' => array('-9223372036854775808', '9223372036854775807', '18446744073709551615'),
    );

    /** What a MySQL text type holds, in bytes. */
    const TEXT_BYTES = array('tinytext' => 255, 'text' => 65535, 'mediumtext' => 16777215, 'longtext' => 4294967295);

    const CHARSET_BYTES = array('ascii' => 1, 'latin1' => 1, 'binary' => 1, 'ucs2' => 2, 'utf8mb3' => 3, 'utf8' => 3);

    /** The binary type a latin1 column passes through, by its type. */
    const BINARY_TYPES = array(
        'varchar' => 'VARBINARY', 'char' => 'BINARY', 'tinytext' => 'TINYBLOB', 'text' => 'BLOB',
        'mediumtext' => 'MEDIUMBLOB', 'longtext' => 'LONGBLOB',
    );

    const REMEDY = 'Correct those rows, then run the update again.';

    /** @var SchemaInspector */
    private $inspector;

    /** @var string */
    private $table;

    /** @var array */
    private $target;

    /** @var bool */
    private $mysql;

    /** @var AbstractGrammar Quotes for the live engine. */
    private $grammar;

    /** @var string|null The target's key column. */
    private $key;

    /** @var array */
    private $plan;

    /** @var array|null tableDefinition() */
    private $live;

    /** @var array|null */
    private $variables;

    /** @var array */
    private $defer = array();

    /**
     * @param SchemaInspector $inspector
     * @param string $table
     * @param array $target
     */
    public function __construct(SchemaInspector $inspector, $table, array $target)
    {
        $this->inspector = $inspector;
        $this->table = $table;
        $this->target = $target;
        $this->mysql = $inspector->flavour() === AbstractGrammar::FLAVOUR_MYSQL;
        $this->grammar = AbstractGrammar::offline($inspector->flavour());
        foreach ($target['columns'] as $column => $spec) {
            if (isset($spec['key']) && $spec['key'] === 'primary') {
                $this->key = $column;
            }
        }
    }

    /**
     * @return string|null Why 3.0 cannot run on this server, or null.
     */
    public function floor()
    {
        $version = $this->inspector->serverVersion();
        if ($this->mysql) {
            try {
                Collation::server($version);
            } catch (MigrationDeferredException $e) {
                return $e->getMessage();
            }
            return null;
        }
        if (!preg_match('/^(\d+)/', $version, $m) || (int)$m[1] < self::PGSQL_FLOOR) {
            return sprintf(
                'This database server is PostgreSQL %s. MISP 3.0 needs PostgreSQL %d or later. Upgrade the database server, then run the update again.',
                $version,
                self::PGSQL_FLOOR
            );
        }
        return null;
    }

    /**
     * @param array $plan TableConverger::plan()'s, or recreate()'s, without blockers.
     * @return array 'plan', with latin1 columns rerouted and the checks' notes
     *   added, and 'defer' => reasons.
     */
    public function check(array $plan)
    {
        $this->plan = $plan;
        $this->defer = array();
        $this->live = $plan['exists'] ? $this->inspector->tableDefinition($this->table) : null;
        if ($this->mysql) {
            $this->keyLimits();
        } else {
            $this->extensions();
        }
        if ($plan['exists']) {
            if ($this->mysql) {
                $this->latin1();
            }
            $this->rows(array_merge($this->fitChecks(), $this->asciiChecks()));
            $this->unfilledAdditions();
            $this->unique();
            $this->space();
        }
        return array('plan' => $this->plan, 'defer' => $this->defer);
    }

    // ------------------------------------------------------------ key limit

    /**
     * @return void
     */
    private function keyLimits()
    {
        $variables = $this->variables();
        $page = isset($variables['innodb_page_size']) ? (int)$variables['innodb_page_size'] : 16384;
        $limit = isset(self::KEY_LIMITS[$page]) ? self::KEY_LIMITS[$page] : SchemaTargetGenerator::MYSQL_KEY_LIMIT;
        $columns = $this->target['columns'];
        foreach ($this->target['indexes'] as $name => $index) {
            if ((isset($index['mysql']) && $index['mysql'] === false) || !empty($index['fulltext'])) {
                continue;
            }
            $bytes = SchemaTargetGenerator::keyBytes($columns, $index + array('column' => array($name)), AbstractGrammar::FLAVOUR_MYSQL);
            if ($bytes > $limit) {
                $this->defer[] = sprintf(
                    '%s: index %s is %d bytes, over the %d-byte key limit of innodb_page_size = %d. MISP 3.0 needs innodb_page_size = 16384 (the default) or larger.',
                    $this->table,
                    $name,
                    $bytes,
                    $limit,
                    $page
                );
            }
        }
        foreach ($this->plan['kept'] as $physical => $index) {
            if ($index['type'] === 'fulltext') {
                continue;
            }
            $bytes = 0;
            foreach ($index['column'] as $column) {
                $part = $this->partBytes($this->afterRun($column), isset($index['length'][$column]) ? (int)$index['length'][$column] : null);
                if ($part === null) {
                    $bytes = null;
                    break;
                }
                $bytes += $part;
            }
            if ($bytes === null || $bytes > $limit) {
                $this->defer[] = sprintf(
                    '%s: the index %s (%s) is not in the target and is kept, but %s. Drop it or give it a shorter prefix, then run the update again.',
                    $this->table,
                    $physical,
                    implode(', ', $index['column']),
                    $bytes === null
                        ? 'one of its columns becomes text without a prefix'
                        : sprintf('it would be %d bytes once its columns are converted, over the %d-byte key limit', $bytes, $limit)
                );
            }
        }
    }

    /**
     * @param array|null $shape afterRun() or liveShape()
     * @param int|null $prefix
     * @param int|null $cap What a string part counts for at most.
     * @return int|null Null for text without a prefix.
     */
    private function partBytes($shape, $prefix, $cap = null)
    {
        if ($shape === null) {
            return $cap === null ? 0 : $cap;
        }
        $type = $shape['type'];
        if (isset(self::WIDTHS[$type])) {
            return self::WIDTHS[$type];
        }
        if (in_array($type, array('string', 'varbinary', 'binary', 'longblob'), true) || isset(self::TEXT_BYTES[$type])) {
            $chars = $prefix !== null ? $prefix : $shape['length'];
            if ($chars === null) {
                return $cap;
            }
            $bytes = $chars * (in_array($type, array('varbinary', 'binary', 'longblob'), true) ? 1 : $shape['bytesPerChar']);
            return $cap === null ? $bytes : min($bytes, $cap);
        }
        return $cap === null ? 0 : $cap;
    }

    // ------------------------------------------------------------ extension

    /**
     * @return void
     */
    private function extensions()
    {
        $needed = array();
        foreach ($this->plan['addIndexes'] as $index) {
            if (isset($index['options']['pgsql']['extension'])) {
                $needed[$index['options']['pgsql']['extension']][] = $index['options']['name'];
            }
        }
        foreach ($needed as $extension => $indexes) {
            $literal = $this->grammar->value($extension);
            $rows = $this->inspector->probeRows(
                'SELECT (SELECT COUNT(*) FROM pg_catalog.pg_extension WHERE extname = ' . $literal . ') AS installed,'
                    . ' (SELECT COUNT(*) FROM pg_catalog.pg_available_extensions WHERE name = ' . $literal . ') AS available,'
                    . ' (SELECT bool_or(trusted) FROM pg_catalog.pg_available_extension_versions WHERE name = ' . $literal . ') AS trusted,'
                    . " has_database_privilege(current_database(), 'CREATE') AS can_create,"
                    . ' (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user) AS superuser,'
                    . ' current_database() AS database_name;'
            );
            $row = isset($rows[0]) ? $rows[0] : array();
            if (!empty($row['installed'])) {
                continue;
            }
            $creatable = !empty($row['available'])
                && (self::truthy($row, 'superuser') || (self::truthy($row, 'trusted') && self::truthy($row, 'can_create')));
            if ($creatable) {
                $this->plan['notes'][] = sprintf('%s: creates the PostgreSQL extension %s for %s', $this->table, $extension, implode(', ', $indexes));
                continue;
            }
            $this->defer[] = sprintf(
                '%s: the index %s needs the PostgreSQL extension %s, %s. Have a superuser run CREATE EXTENSION %s; in the database %s, then run the update again.',
                $this->table,
                implode(', ', $indexes),
                $extension,
                empty($row['available']) ? 'which this server does not have (it ships with PostgreSQL\'s contrib package)' : 'which this database user cannot create',
                $extension,
                isset($row['database_name']) ? $row['database_name'] : 'of MISP'
            );
        }
    }

    // --------------------------------------------------------------- latin1

    /**
     * latin1 columns going to utf8mb4. Values with no byte over 0x7F convert
     * either way. Where every other value is valid UTF-8, it is UTF-8 that a
     * latin1 connection stored, and MODIFY would encode it a second time; it
     * goes through a binary type instead. Where none is, it is latin1 text,
     * which MODIFY converts. Both at once cannot be told apart per value.
     *
     * @return void
     */
    private function latin1()
    {
        $checks = array();
        foreach ($this->plan['change'] as $column => $change) {
            $collation = $this->targetCollation($column);
            if ($change['from']['charset'] !== 'latin1' || $collation === null || $collation['charset'] !== 'utf8mb4') {
                continue;
            }
            $quoted = $this->grammar->name($column);
            $high = sprintf('LENGTH(CONVERT(%1$s USING utf8mb4)) <> LENGTH(%1$s)', $quoted);
            $utf8 = sprintf('CONVERT(CONVERT(CAST(%1$s AS BINARY) USING utf8mb4) USING binary) <=> CAST(%1$s AS BINARY)', $quoted);
            $checks[$column . '.utf8'] = array('columns' => array($column), 'condition' => $high . ' AND ' . $utf8);
            $checks[$column . '.latin1'] = array('columns' => array($column), 'condition' => $high . ' AND NOT (' . $utf8 . ')');
        }
        if (empty($checks)) {
            return;
        }
        $counts = $this->countRows($checks);
        foreach ($this->plan['change'] as $column => $change) {
            if (!isset($counts[$column . '.utf8'])) {
                continue;
            }
            $utf8 = $counts[$column . '.utf8'];
            $latin1 = $counts[$column . '.latin1'];
            if ($utf8 > 0 && $latin1 > 0) {
                $this->defer[] = sprintf(
                    '%s: %s holds UTF-8 stored as latin1 in %s (%s) and latin1 text in %s (%s), and no one conversion is right for both. %s',
                    $this->table,
                    $column,
                    self::rowCount($utf8),
                    $this->listRows($checks[$column . '.utf8'], $utf8),
                    self::rowCount($latin1),
                    $this->listRows($checks[$column . '.latin1'], $latin1),
                    self::REMEDY
                );
            } elseif ($utf8 > 0) {
                $this->reroute($column, $change['from'], $utf8);
            } elseif ($latin1 > 0) {
                $this->plan['notes'][] = sprintf('%s: %s holds latin1 text in %s; converted to utf8mb4', $this->table, $column, self::rowCount($latin1));
            }
        }
    }

    /**
     * @param string $column
     * @param array $from The live column.
     * @param int $rows
     * @return void
     */
    private function reroute($column, array $from, $rows)
    {
        foreach ($this->live['indexes'] as $index) {
            if ($index['type'] === 'fulltext' && in_array(strtolower($column), array_map('strtolower', $index['column']), true)) {
                $this->defer[] = sprintf(
                    '%s: %s holds UTF-8 stored as latin1 in %s, which converts correctly only through a binary type, and the FULLTEXT index %s over it does not allow one. Drop that index, then run the update again.',
                    $this->table,
                    $column,
                    self::rowCount($rows),
                    $index['name']
                );
                return;
            }
        }
        if (!isset(self::BINARY_TYPES[$from['base']])) {
            $this->defer[] = sprintf(
                '%s: %s holds UTF-8 stored as latin1 in %s, which converts correctly only through a binary type, and a %s column has none. Convert it by hand, then run the update again.',
                $this->table,
                $column,
                self::rowCount($rows),
                $from['base']
            );
            return;
        }
        $type = self::BINARY_TYPES[$from['base']];
        $clause = $from['length'] === null || in_array($from['base'], array('tinytext', 'text', 'mediumtext', 'longtext'), true)
            ? $type
            : sprintf('%s(%d)', $type, $from['length']);
        $clause .= $from['null'] ? ' NULL' : ' NOT NULL';
        if ($from['default'] !== null && empty($from['default_expression']) && strpos($type, 'BLOB') === false) {
            $clause .= ' DEFAULT ' . $this->grammar->value($from['default']);
        }
        $this->plan['reroute'][$column] = $clause;
        $this->plan['notes'][] = sprintf(
            '%s: %s holds UTF-8 stored as latin1 in %s; it passes through %s, keeping its bytes, which costs one more rebuild',
            $this->table,
            $column,
            self::rowCount($rows),
            $type
        );
    }

    // ------------------------------------------------------------------ fit

    /**
     * Rows the target columns cannot hold: NULL in a column becoming NOT NULL,
     * values longer than a narrower type, numbers outside a narrower range.
     *
     * @return array Checks for rows().
     */
    private function fitChecks()
    {
        $checks = array();
        foreach ($this->plan['change'] as $column => $change) {
            $from = $change['from'];
            $spec = $this->target['columns'][$column];
            $type = $spec['type'];
            $quoted = $this->grammar->name($column);
            if (in_array('null', $change['differs'], true) && isset($spec['null']) && $spec['null'] === false) {
                $checks[$column . '.null'] = array(
                    'columns' => array($column),
                    'condition' => $quoted . ' IS NULL',
                    'what' => sprintf('%s is NULL, which the target does not allow', $column),
                );
            }
            if ($type === 'string') {
                $length = isset($spec['length']) ? (int)$spec['length'] : 255;
                $liveLength = $this->liveChars($from);
                if ($liveLength === null || $liveLength > $length) {
                    $checks[$column . '.length'] = array(
                        'columns' => array($column),
                        'condition' => sprintf('CHAR_LENGTH(%s) > %d', $this->characters($column), $length),
                        'what' => sprintf('%s is longer than the %d characters the target allows', $column, $length),
                    );
                }
            } elseif ($this->mysql && isset(self::TEXT_BYTES[$type])) {
                $capacity = self::TEXT_BYTES[$type];
                $liveCapacity = isset(self::TEXT_BYTES[$from['base']]) ? self::TEXT_BYTES[$from['base']] : 0;
                $grows = $from['charset'] === 'latin1' && !isset($this->plan['reroute'][$column]);
                if ($liveCapacity > $capacity || $grows) {
                    $checks[$column . '.bytes'] = array(
                        'columns' => array($column),
                        'condition' => sprintf('LENGTH(%s) > %d', $this->converted($column), $capacity),
                        'what' => sprintf('%s is longer than the %d bytes a %s column holds once converted', $column, $capacity, $type),
                    );
                }
            }
            $range = $this->narrowedRange($spec, $from);
            if ($range !== null) {
                $below = $above = array();
                if ($range['below']) {
                    $below = array($quoted . ' < ' . $range['min'], 'MIN(' . $quoted . ') < ' . $range['min']);
                }
                if ($range['above']) {
                    $above = array($quoted . ' > ' . $range['max'], 'MAX(' . $quoted . ') > ' . $range['max']);
                }
                $parts = array_filter(array($below, $above));
                $checks[$column . '.range'] = array(
                    'columns' => array($column),
                    'condition' => '(' . implode(' OR ', array_column($parts, 0)) . ')',
                    'bounds' => '(' . implode(' OR ', array_column($parts, 1)) . ')',
                    'what' => sprintf('%s is outside the range %s to %s the target allows', $column, $range['min'], $range['max']),
                );
            }
        }
        return $checks;
    }

    /**
     * @param array $from A live column.
     * @return int|null Its length in characters; null when unbounded, 0 for no string.
     */
    private function liveChars(array $from)
    {
        if ($this->mysql) {
            $type = BaselineGenerator::dslType($from['type']);
            if ($type === 'string') {
                return (int)$from['length'];
            }
            return in_array($type, TableConverger::STRING_TYPES, true) ? null : 0;
        }
        if ($from['base'] === 'character varying') {
            return $from['length'] === null ? null : (int)$from['length'];
        }
        return $from['base'] === 'text' ? null : 0;
    }

    /**
     * @param array $spec The target's.
     * @param array $from The live column.
     * @return array|null The target's 'min' and 'max', and whether the live
     *   type reaches 'below' and 'above' them; null when it stays within.
     */
    private function narrowedRange(array $spec, array $from)
    {
        $wanted = $this->integerType($spec['type']);
        if ($this->mysql) {
            $live = BaselineGenerator::dslType($from['type']);
            $live = $live === 'boolean' ? 'tinyinteger' : $live;
        } else {
            $live = array_search($from['base'], array('smallinteger' => 'smallint', 'integer' => 'integer', 'biginteger' => 'bigint'), true);
        }
        if ($wanted === null || !isset(self::INTEGER_RANGES[$live])) {
            return null;
        }
        $target = self::range($wanted, $this->mysql && !empty($spec['unsigned']));
        $current = self::range($live, !empty($from['unsigned']));
        // The bounds are far enough apart for a float to tell them apart.
        $below = (float)$current[0] < (float)$target[0];
        $above = (float)$current[1] > (float)$target[1];
        if (!$below && !$above) {
            return null;
        }
        return array('min' => $target[0], 'max' => $target[1], 'below' => $below, 'above' => $above);
    }

    /**
     * @param string $type A DSL type.
     * @return string|null The integer type it is stored as on this engine.
     */
    private function integerType($type)
    {
        if (!isset(self::INTEGER_RANGES[$type])) {
            return null;
        }
        return !$this->mysql && $type === 'tinyinteger' ? 'smallinteger' : $type;
    }

    /**
     * @param string $type
     * @param bool $unsigned
     * @return array array(min, max)
     */
    private static function range($type, $unsigned)
    {
        list($min, $max, $unsignedMax) = self::INTEGER_RANGES[$type];
        return $unsigned ? array('0', $unsignedMax) : array($min, $max);
    }

    /**
     * A missing NOT NULL column without a default takes the type's implicit
     * value in every row. MySQL's zero date is refused under strict mode
     * with NO_ZERO_DATE, and PostgreSQL gets none for the types fill() does
     * not cover.
     *
     * @return void
     */
    private function unfilledAdditions()
    {
        $refused = $this->mysql ? array('datetime', 'timestamp', 'date') : self::UNFILLED_TYPES;
        if ($this->mysql) {
            $variables = $this->variables();
            $mode = isset($variables['sql_mode']) ? strtoupper($variables['sql_mode']) : '';
            $strict = preg_match('/STRICT_(TRANS|ALL)_TABLES|TRADITIONAL/', $mode) && preg_match('/NO_ZERO_DATE|TRADITIONAL/', $mode);
            if (!$strict) {
                return;
            }
        }
        $columns = array();
        foreach ($this->plan['add'] as $column => $add) {
            $options = $add['options'];
            if (in_array($add['type'], $refused, true) && isset($options['null']) && $options['null'] === false
                && (!array_key_exists('default', $options) || $options['default'] === null)
            ) {
                $columns[] = $column;
            }
        }
        if (empty($columns)) {
            return;
        }
        $rows = $this->inspector->probeRows(sprintf('SELECT 1 AS present FROM %s LIMIT 1;', $this->grammar->name($this->table)));
        if (!empty($rows)) {
            $this->defer[] = sprintf(
                '%s: %s missing, NOT NULL without a default, and the table has rows, which this server has no value to fill with. Add %s by hand with a value for the existing rows, then run the update again.',
                $this->table,
                implode(', ', $columns) . (count($columns) > 1 ? ' are' : ' is'),
                count($columns) > 1 ? 'them' : 'it'
            );
        }
    }

    // ---------------------------------------------------------------- ascii

    /**
     * Columns becoming ascii (uuids and hex hashes) must hold nothing else:
     * strict mode would refuse the rebuild, non-strict would store '?'.
     *
     * @return array Checks for rows().
     */
    private function asciiChecks()
    {
        $checks = array();
        if (!$this->mysql) {
            return $checks;
        }
        foreach ($this->plan['change'] as $column => $change) {
            $collation = $this->targetCollation($column);
            if ($collation === null || $collation['charset'] !== 'ascii' || $change['from']['charset'] === 'ascii'
                || $change['from']['charset'] === null
            ) {
                continue;
            }
            $checks[$column . '.ascii'] = array(
                'columns' => array($column),
                'condition' => sprintf('LENGTH(CONVERT(%1$s USING utf8mb4)) <> CHAR_LENGTH(%1$s)', $this->grammar->name($column)),
                'what' => sprintf('%s holds characters outside ASCII, which its target charset cannot store', $column),
            );
        }
        return $checks;
    }

    // ----------------------------------------------------------------- rows

    /**
     * Count the rows each check finds and defer on every hit.
     *
     * @param array $checks label => array('columns', 'condition', 'what')
     * @return void
     */
    private function rows(array $checks)
    {
        foreach ($checks as $label => $check) {
            // An index that leads with the column answers MIN and MAX without a scan.
            if (isset($check['bounds']) && $this->leads($check['columns'][0])) {
                $rows = $this->inspector->probeRows(sprintf(
                    'SELECT CASE WHEN %s THEN 1 ELSE 0 END AS outside FROM %s;',
                    $check['bounds'],
                    $this->grammar->name($this->table)
                ));
                if (empty($rows[0]['outside'])) {
                    unset($checks[$label]);
                }
            }
        }
        if (empty($checks)) {
            return;
        }
        foreach ($this->countRows($checks) as $label => $count) {
            if ($count > 0) {
                $this->defer[] = sprintf(
                    '%s: in %s (%s), %s. %s',
                    $this->table,
                    self::rowCount($count),
                    $this->listRows($checks[$label], $count),
                    $checks[$label]['what'],
                    self::REMEDY
                );
            }
        }
    }

    /**
     * One query per covering index, so that a check on an indexed column
     * reads that index alone, and one scan of the table for the rest.
     *
     * @param array $checks label => array('columns', 'condition', ...)
     * @return array label => rows found
     */
    private function countRows(array $checks)
    {
        $groups = array();
        foreach ($checks as $label => $check) {
            $index = count($check['columns']) === 1 ? $this->coveringIndex($check['columns'][0]) : null;
            $groups[$index === null ? '' : $index][$label] = $check;
        }
        $counts = array();
        foreach ($groups as $index => $group) {
            $sums = array();
            $n = 0;
            foreach ($group as $check) {
                $sums[] = sprintf('SUM(CASE WHEN %s THEN 1 ELSE 0 END) AS %s', $check['condition'], $this->grammar->name('n' . $n++));
            }
            $rows = $this->inspector->probeRows(sprintf(
                'SELECT %s FROM %s%s;',
                implode(', ', $sums),
                $this->grammar->name($this->table),
                $index === '' ? '' : ' FORCE INDEX (' . $this->grammar->name($index) . ')'
            ));
            $n = 0;
            foreach (array_keys($group) as $label) {
                $counts[$label] = isset($rows[0]['n' . $n]) ? (int)$rows[0]['n' . $n] : 0;
                $n++;
            }
        }
        return $counts;
    }

    /**
     * @param array $check
     * @param int $count
     * @return string The first rows a check found, by key.
     */
    private function listRows(array $check, $count)
    {
        if ($this->key === null) {
            return self::rowCount($count);
        }
        $key = $this->grammar->name($this->key);
        $index = count($check['columns']) === 1 ? $this->coveringIndex($check['columns'][0]) : null;
        $rows = $this->inspector->probeRows(sprintf(
            'SELECT %s AS id FROM %s%s WHERE %s LIMIT %d;',
            $key,
            $this->grammar->name($this->table),
            $index === null ? '' : ' FORCE INDEX (' . $this->grammar->name($index) . ')',
            $check['condition'],
            self::LISTED
        ));
        $ids = array();
        foreach ($rows as $row) {
            $ids[] = $row['id'];
        }
        if (empty($ids)) {
            return self::rowCount($count);
        }
        sort($ids);
        return sprintf('%s %s%s', $this->key, implode(', ', $ids), $count > count($ids) ? ', ...' : '');
    }

    /**
     * The narrowest live index over a column, where reading the index alone
     * serves a check on it; MySQL only, where FORCE INDEX makes it so.
     *
     * @param string $column
     * @return string|null
     */
    private function coveringIndex($column)
    {
        if (!$this->mysql) {
            return null;
        }
        $best = null;
        $width = PHP_INT_MAX;
        foreach ($this->live['indexes'] as $key => $index) {
            if ($key === 'PRIMARY' || $index['type'] === 'fulltext' || $index['expression']) {
                continue;
            }
            foreach ($index['column'] as $part) {
                if (strcasecmp($part, $column) === 0 && !isset($index['length'][$part]) && count($index['column']) < $width) {
                    $best = $index['name'];
                    $width = count($index['column']);
                }
            }
        }
        return $best;
    }

    /**
     * @param string $column
     * @return bool Whether a live index, the key included, starts with it.
     */
    private function leads($column)
    {
        foreach ($this->live['indexes'] as $index) {
            if (!$index['expression'] && $index['type'] !== 'fulltext' && strcasecmp($index['column'][0], $column) === 0) {
                return true;
            }
        }
        return false;
    }

    // --------------------------------------------------------------- unique

    /**
     * Unique keys the rows may break: one the run adds, unless a live unique
     * key over some of its columns already guarantees it, and on MySQL one
     * whose columns move to a collation that may compare more values as
     * equal ('strasse' and 'straße' under uca1400_ai_ci).
     *
     * @return void
     */
    private function unique()
    {
        $added = array();
        foreach ($this->plan['addIndexes'] as $index) {
            $added[$index['options']['name']] = true;
        }
        foreach ($this->target['indexes'] as $name => $index) {
            if (empty($index['unique']) || ($this->mysql && isset($index['mysql']) && $index['mysql'] === false)) {
                continue;
            }
            $ownSql = !$this->mysql && isset($index['pgsql']['sql']);
            if (!$ownSql && !isset($index['column'])) {
                $index['column'] = array($name);
            }
            $loosened = $ownSql ? array() : array_values(array_filter($index['column'], array($this, 'loosens')));
            if (isset($added[$name])) {
                if (!$ownSql && $this->impliedByLive($index)) {
                    continue;
                }
            } elseif (empty($loosened)) {
                continue;
            }
            $this->probeUnique($name, $index, $ownSql, isset($added[$name]), $loosened);
        }
    }

    /**
     * @param string $column
     * @return bool Whether the column's new collation may compare values as
     *   equal that the old one told apart.
     */
    private function loosens($column)
    {
        if (!$this->mysql || !isset($this->plan['change'][$column])
            || !in_array('collation', $this->plan['change'][$column]['differs'], true)
        ) {
            return false;
        }
        $collation = $this->targetCollation($column);
        $live = (string)$this->plan['change'][$column]['from']['collation'];
        // A byte comparison is the strictest there is, unless the old one
        // counted trailing spaces and the new one ignores them.
        $binary = substr($collation['collate'], -4) === '_bin';
        return !$binary || $live === 'binary' || preg_match('/_(0900|nopad)_/', $live);
    }

    /**
     * @param array $index A target unique index.
     * @return bool Whether a live unique key over some of its columns, with
     *   prefixes no longer and collations no looser, already guarantees it.
     */
    private function impliedByLive(array $index)
    {
        $parts = array();
        foreach ($index['column'] as $column) {
            $parts[$this->fold($column)] = isset($index['length'][$column]) ? (int)$index['length'][$column] : null;
        }
        foreach ($this->live['indexes'] as $live) {
            if (!$live['unique'] || $live['expression']) {
                continue;
            }
            $implied = true;
            foreach ($live['column'] as $column) {
                $folded = $this->fold($column);
                $prefix = isset($live['length'][$column]) ? (int)$live['length'][$column] : null;
                if (!array_key_exists($folded, $parts) || $this->loosens($this->targetName($column))
                    || ($parts[$folded] !== null && ($prefix === null || $prefix > $parts[$folded]))
                ) {
                    $implied = false;
                    break;
                }
            }
            if ($implied) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param string $name
     * @param array $index
     * @param bool $ownSql The PostgreSQL index is its own statement.
     * @param bool $adding
     * @param array $loosened Columns whose collation loosens.
     * @return void
     */
    private function probeUnique($name, array $index, $ownSql, $adding, array $loosened)
    {
        $expressions = $ownSql ? self::indexExpressions($index['pgsql']['sql']) : $this->uniqueExpressions($index);
        if ($expressions === null) {
            $this->plan['notes'][] = sprintf('%s: the rows were not checked against the unique key %s', $this->table, $name);
            return;
        }
        if ($expressions === false) {
            return;
        }
        $keys = array();
        $present = array();
        foreach (array_values($expressions) as $n => $expression) {
            $keys[] = $expression . ' AS ' . $this->grammar->name('k' . $n) . ', ';
            $present[] = $expression . ' IS NOT NULL';
        }
        $key = $this->key === null ? null : $this->grammar->name($this->key);
        $ids = $key === null ? "''" : ($this->mysql
            ? sprintf("GROUP_CONCAT(%s ORDER BY %s SEPARATOR ', ')", $key, $key)
            : sprintf("string_agg(%s::text, ', ' ORDER BY %s)", $key, $key));
        $rows = $this->inspector->probeRows(sprintf(
            'SELECT %sCOUNT(*) AS n, %s AS ids FROM %s%s%s HAVING COUNT(*) > 1 LIMIT %d;',
            implode('', $keys),
            $ids,
            $this->grammar->name($this->table),
            empty($present) ? '' : ' WHERE ' . implode(' AND ', $present),
            empty($expressions) ? '' : ' GROUP BY ' . implode(', ', $expressions),
            self::LISTED
        ));
        if (empty($rows)) {
            return;
        }
        $clashes = array();
        foreach ($rows as $row) {
            $values = array();
            for ($n = 0; $n < count($expressions); $n++) {
                $values[] = self::shown($row['k' . $n]);
            }
            $value = empty($values) ? 'the value the run gives every row'
                : (count($values) === 1 ? $values[0] : '(' . implode(', ', $values) . ')');
            $clashes[] = $key === null
                ? sprintf('%s in %d rows', $value, $row['n'])
                : sprintf('%s in rows %s %s', $value, $this->key, $row['ids']);
        }
        if ($adding) {
            $why = sprintf('the run adds the unique key %s', $name);
        } else {
            $collation = $this->targetCollation($loosened[0]);
            $why = sprintf('the unique key %s compares %s under %s from now on', $name, implode(', ', $loosened), $collation['collate']);
        }
        $this->defer[] = sprintf(
            '%s: %s, and rows share a value of it: %s%s. %s, then run the update again.',
            $this->table,
            $why,
            implode('; ', $clashes),
            count($rows) >= self::LISTED ? '; ...' : '',
            $this->keysByIdentifier($index)
                ? 'Those rows stand for the same thing: keep one of them and delete the others'
                : 'Merge or rename those rows'
        );
    }

    /**
     * @param array $index A target unique key.
     * @return bool Whether it keys rows by an identifier (an ascii uuid or
     *   hash column) and by no name or other text.
     */
    private function keysByIdentifier(array $index)
    {
        $identifier = false;
        foreach (isset($index['column']) ? $index['column'] : array() as $column) {
            $spec = $this->target['columns'][$column];
            if (!in_array($spec['type'], TableConverger::STRING_TYPES, true)) {
                continue;
            }
            if (!isset($spec['collate']) || $spec['collate'] !== Collation::ASCII) {
                return false;
            }
            $identifier = true;
        }
        return $identifier;
    }

    /**
     * A column the run adds holds one value in every row, which groups
     * nothing, and when that is NULL no two rows can clash.
     *
     * @param array $index A target unique index with columns.
     * @return array|false The value of each live part as the target will
     *   compare it; false when no two rows can clash.
     */
    private function uniqueExpressions(array $index)
    {
        $expressions = array();
        foreach ($index['column'] as $column) {
            $spec = $this->target['columns'][$column];
            if ($this->liveColumn($column) === null) {
                $nullable = !isset($spec['null']) || $spec['null'] !== false;
                if ($nullable && (!array_key_exists('default', $spec) || $spec['default'] === null)) {
                    return false;
                }
                continue;
            }
            $expression = $this->converted($column);
            if (isset($index['length'][$column])) {
                $expression = sprintf('LEFT(%s, %d)', $expression, $index['length'][$column]);
            }
            $collation = $this->targetCollation($column);
            if ($collation !== null) {
                $expression .= ' COLLATE ' . $collation['collate'];
            }
            $expressions[] = $expression;
        }
        return $expressions;
    }

    /**
     * @param string $sql A PostgreSQL CREATE INDEX with %2$s for the table.
     * @return array|null Its key expressions; null when they cannot be read.
     */
    private static function indexExpressions($sql)
    {
        if (!preg_match('/\bON\s+%2\$s\s+(?:USING\s+\w+\s*)?\((.*)\)\s*;?\s*$/is', $sql, $m)) {
            return null;
        }
        $parts = array();
        $depth = 0;
        $current = '';
        foreach (str_split($m[1]) as $char) {
            $depth += $char === '(' ? 1 : ($char === ')' ? -1 : 0);
            if ($char === ',' && $depth === 0) {
                $parts[] = trim($current);
                $current = '';
                continue;
            }
            $current .= $char;
        }
        $parts[] = trim($current);
        return $parts;
    }

    /**
     * @param mixed $value
     * @return string
     */
    private static function shown($value)
    {
        if ($value === null) {
            return 'NULL';
        }
        $shown = json_encode((string)$value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        return mb_strlen($shown) > 64 ? mb_substr($shown, 0, 63) . '…"' : $shown;
    }

    // ---------------------------------------------------------------- space

    /**
     * Free disk for what the run writes, estimated from the target (the live
     * table may lack indexes the target has): the new copy of a rebuilt table
     * beside the old one, or the new indexes; plus the sort files of an index
     * built in place, in tmpdir. The catalog's index size is scaled by the
     * target's entry bytes over the live ones, which keeps the real width of
     * the strings in it.
     *
     * @return void
     */
    private function space()
    {
        $kind = $this->rebuildKind();
        if ($kind === null) {
            return;
        }
        $sizes = $this->inspector->tableSizes();
        if (!isset($sizes[$this->table])) {
            return;
        }
        $size = $sizes[$this->table];
        $rows = (float)$size['row_estimate'];

        $after = $added = $before = 0.0;
        foreach ($this->target['indexes'] as $name => $index) {
            if (($this->mysql && isset($index['mysql']) && $index['mysql'] === false) || !empty($index['fulltext'])) {
                continue;
            }
            $columns = isset($index['column']) ? $index['column'] : array($name);
            $entry = $this->entryBytes($columns, isset($index['length']) ? $index['length'] : array(), true, 8);
            $after += $entry;
            foreach ($this->plan['addIndexes'] as $declaration) {
                if ($declaration['options']['name'] === $name) {
                    $added += $entry;
                }
            }
        }
        foreach ($this->plan['kept'] as $index) {
            if ($index['type'] !== 'fulltext') {
                $after += $this->entryBytes($index['column'], $index['length'], true, 8);
            }
        }
        $liveKey = isset($this->live['indexes']['PRIMARY']['column'][0]) ? $this->live['indexes']['PRIMARY']['column'][0] : null;
        $liveKeyBytes = $this->partBytes($liveKey === null ? null : $this->liveShape($liveKey), null, self::STRING_ENTRY);
        foreach ($this->live['indexes'] as $key => $index) {
            if ($key !== 'PRIMARY' && $index['type'] !== 'fulltext') {
                $before += $this->entryBytes($index['column'], $index['length'], false, $liveKeyBytes);
            }
        }
        $indexes = $before > 0 && $size['index_in_bytes'] > 0
            ? $size['index_in_bytes'] * $after / $before
            : $rows * $after * self::PAGE_OVERHEAD;
        $newIndexes = $after > 0 ? $indexes * $added / $after : 0.0;
        $copy = $size['data_in_bytes'] + $rows * $this->rowGrowth() + $indexes;

        if ($kind === 'indexes') {
            $need = array('datadir' => $newIndexes, 'tmpdir' => $newIndexes);
            $what = 'building the new indexes';
        } else {
            $need = array('datadir' => $copy, 'tmpdir' => $kind === 'inplace' ? $indexes : 0.0);
            $what = 'the rebuild (a new copy of the table beside the old one)';
        }
        $this->plan['forecast'] = array(
            'kind' => $kind,
            'rows' => (int)$rows,
            'bytes' => $size['data_in_bytes'] + $size['index_in_bytes'],
            'need' => $need['datadir'] + $need['tmpdir'],
        );
        $this->disk($need, $what);
    }

    /**
     * @return string|null 'copy': the rows are converted into a new table;
     *   'inplace': the table is rebuilt in place, its indexes sorted in
     *   tmpdir; 'indexes': indexes are added; null: nothing is written.
     */
    private function rebuildKind()
    {
        $copies = $this->mysql ? array('type', 'length', 'unsigned') : array('type', 'length');
        $kind = null;
        if (!empty($this->plan['reroute'])) {
            return 'copy';
        }
        foreach ($this->plan['change'] as $column => $change) {
            $collation = $this->targetCollation($column);
            $from = $change['from']['charset'];
            // MariaDB widens utf8mb3 to utf8mb4 in place; a real conversion copies.
            $converts = $collation !== null && $from !== null && $from !== $collation['charset']
                && !(in_array($from, array('utf8mb3', 'utf8'), true) && $collation['charset'] === 'utf8mb4');
            if (array_intersect($copies, $change['differs']) || $converts) {
                return 'copy';
            }
            if (array_diff($change['differs'], array('default'))) {
                $kind = 'inplace';
            }
        }
        if (isset($this->plan['options']['engine']) || isset($this->plan['options']['row_format'])) {
            $kind = 'inplace';
        }
        if ($kind === null && !empty($this->plan['addIndexes'])) {
            $kind = 'indexes';
        }
        return $kind;
    }

    /**
     * @param array $columns
     * @param array $prefixes column => prefix
     * @param bool $after Measure the columns as the run leaves them.
     * @param int $keyBytes What the key adds to each entry.
     * @return float
     */
    private function entryBytes(array $columns, array $prefixes, $after, $keyBytes)
    {
        $bytes = self::ENTRY_OVERHEAD + $keyBytes;
        foreach ($columns as $column) {
            $shape = $after ? $this->afterRun($column) : $this->liveShape($column);
            $bytes += $this->partBytes($shape, isset($prefixes[$column]) ? (int)$prefixes[$column] : null, self::STRING_ENTRY);
        }
        return (float)$bytes;
    }

    /**
     * @return int Bytes each row gains from fixed-width columns made wider.
     */
    private function rowGrowth()
    {
        $growth = 0;
        foreach ($this->plan['change'] as $column => $change) {
            $type = $this->target['columns'][$column]['type'];
            $live = $this->liveShape($column);
            if (isset(self::WIDTHS[$type], self::WIDTHS[$live['type']])) {
                $growth += max(0, self::WIDTHS[$type] - self::WIDTHS[$live['type']]);
            }
        }
        return $growth;
    }

    /**
     * @param array $need 'datadir', 'tmpdir' => bytes
     * @param string $what
     * @return void
     */
    private function disk(array $need, $what)
    {
        $storage = $this->inspector->storage();
        if ($storage === null) {
            $total = $need['datadir'] + $need['tmpdir'];
            if ($total >= self::SPACE_QUIET) {
                $this->plan['notes'][] = sprintf(
                    '%s: free disk not checked, as the database server\'s directories cannot be read from here; %s needs about %s there',
                    $this->table,
                    $what,
                    self::bytes($total)
                );
            }
            return;
        }
        $checks = $storage['datadir']['device'] === $storage['tmpdir']['device']
            ? array(array($storage['datadir'], $need['datadir'] + $need['tmpdir']))
            : array(array($storage['datadir'], $need['datadir']), array($storage['tmpdir'], $need['tmpdir']));
        foreach ($checks as $check) {
            list($place, $bytes) = $check;
            if ($bytes <= 0) {
                continue;
            }
            if ($place['free'] < $bytes) {
                $this->defer[] = sprintf(
                    '%s: %s needs about %s free in %s, and %s is free. Free up space there, then run the update again.',
                    $this->table,
                    $what,
                    self::bytes($bytes),
                    $place['path'],
                    self::bytes($place['free'])
                );
            } elseif ($place['free'] < $bytes * self::SPACE_MARGIN) {
                $this->plan['notes'][] = sprintf(
                    '%s: %s needs about %s in %s, and %s is free: close to the estimate',
                    $this->table,
                    $what,
                    self::bytes($bytes),
                    $place['path'],
                    self::bytes($place['free'])
                );
            }
        }
    }

    /**
     * @param int $count
     * @return string
     */
    private static function rowCount($count)
    {
        return $count === 1 ? '1 row' : sprintf('%d rows', $count);
    }

    /**
     * @param float $bytes
     * @return string
     */
    public static function bytes($bytes)
    {
        return $bytes >= 1073741824 ? sprintf('%.1f GB', $bytes / 1073741824) : sprintf('%.1f MB', $bytes / 1048576);
    }

    // -------------------------------------------------------------- columns

    /**
     * @param string $column
     * @return array|null What a column is once the run has passed: the
     *   target's where the target has it, else the live one, kept as it is.
     */
    private function afterRun($column)
    {
        $name = $this->targetName($column);
        if ($name === null) {
            return $this->liveShape($column);
        }
        $spec = $this->target['columns'][$name];
        $charset = null;
        if (in_array($spec['type'], TableConverger::STRING_TYPES, true)) {
            $collation = $this->targetCollation($name);
            $charset = $collation === null ? 'utf8mb4' : $collation['charset'];
        }
        return array(
            'type' => $spec['type'],
            'length' => isset($spec['length']) ? (int)$spec['length'] : ($spec['type'] === 'string' ? 255 : null),
            'bytesPerChar' => self::bytesPerChar($charset),
        );
    }

    /**
     * @param string $column
     * @return array|null
     */
    private function liveShape($column)
    {
        $live = $this->liveColumn($column);
        if ($live === null) {
            return null;
        }
        if ($this->mysql) {
            $type = BaselineGenerator::dslType($live['type']);
        } else {
            $type = array_search($live['base'], TableConverger::PGSQL_TYPES, true);
        }
        return array(
            'type' => $type === false ? null : $type,
            'length' => $live['length'] === null ? null : (int)$live['length'],
            'bytesPerChar' => self::bytesPerChar($live['charset']),
        );
    }

    /**
     * @param string|null $charset
     * @return int
     */
    private static function bytesPerChar($charset)
    {
        return isset(self::CHARSET_BYTES[$charset]) ? self::CHARSET_BYTES[$charset] : 4;
    }

    /**
     * @param string $column
     * @return array|null The live column of that name.
     */
    private function liveColumn($column)
    {
        foreach ($this->live['columns'] as $name => $live) {
            if ($this->fold($name) === $this->fold($column)) {
                return $live;
            }
        }
        return null;
    }

    /**
     * @param string $column
     * @return string|null The target's spelling of a column name.
     */
    private function targetName($column)
    {
        foreach (array_keys($this->target['columns']) as $name) {
            if ($this->fold($name) === $this->fold($column)) {
                return $name;
            }
        }
        return null;
    }

    /**
     * @param string $column A target column.
     * @return array|null 'charset' and 'collate' as this server names them;
     *   null for a column without one, and on PostgreSQL.
     */
    private function targetCollation($column)
    {
        $spec = $this->target['columns'][$column];
        if (!$this->mysql || !in_array($spec['type'], TableConverger::STRING_TYPES, true)) {
            return null;
        }
        $collate = isset($spec['collate']) ? $spec['collate'] : (isset($this->target['options']['collate']) ? $this->target['options']['collate'] : null);
        if ($collate === null) {
            return null;
        }
        if (Collation::isToken($collate)) {
            return Collation::forServer($collate, $this->inspector->serverVersion());
        }
        return array('charset' => SchemaInspector::charsetOfCollation($collate), 'collate' => $collate);
    }

    /**
     * @param string $column
     * @return string The column's characters as the target will count them.
     */
    private function characters($column)
    {
        $quoted = $this->grammar->name($column);
        return isset($this->plan['reroute'][$column]) ? sprintf('CONVERT(CAST(%s AS BINARY) USING utf8mb4)', $quoted) : $quoted;
    }

    /**
     * @param string $column
     * @return string The column's value in its target charset.
     */
    private function converted($column)
    {
        $quoted = $this->grammar->name($column);
        $collation = $this->targetCollation($column);
        if ($collation === null) {
            return $quoted;
        }
        if (isset($this->plan['reroute'][$column])) {
            return sprintf('CONVERT(CAST(%s AS BINARY) USING utf8mb4)', $quoted);
        }
        $live = $this->liveColumn($column);
        return $live !== null && $live['charset'] === $collation['charset']
            ? $quoted
            : sprintf('CONVERT(%s USING %s)', $quoted, $collation['charset']);
    }

    /**
     * @param string $name
     * @return string
     */
    private function fold($name)
    {
        return $this->mysql ? strtolower($name) : $name;
    }

    /**
     * @return array
     */
    private function variables()
    {
        if ($this->variables === null) {
            $this->variables = $this->inspector->serverVariables();
        }
        return $this->variables;
    }

    /**
     * @param array $row
     * @param string $field
     * @return bool A PostgreSQL boolean as PDO returns it.
     */
    private static function truthy(array $row, $field)
    {
        return isset($row[$field]) && in_array($row[$field], array(true, 1, '1', 't', 'true'), true);
    }
}
