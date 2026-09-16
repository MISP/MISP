<?php
App::uses('Postgres', 'Model/Datasource/Database');
App::uses('RedisTool', 'Tools');

/**
 * The PostgreSQL datasource MISP ships, and the only one it offers.
 *
 * The MySQL side has four datasources for historical reasons - a vanilla
 * baseline, the performance extensions, the query-comment observer, and the
 * combination every instance actually runs. There is no PostgreSQL estate to
 * stay compatible with, so that ladder is not recreated: this is the one
 * class, and it does for PostgreSQL what MysqlObserverExtended does for
 * MySQL, in three parts.
 *
 * **What the engine can be asked for.** $supports is read by
 * AppModel::checkDbSupport(), and a caller skips a construct the driver does
 * not declare. PostgreSQL has no index hints, no join-order control, no
 * MEMORY engine and no FULLTEXT index, so those are declared false rather
 * than left undeclared - the vocabulary is the same on both engines, and a
 * reader should see the answer, not an absence. Multi-row INSERT it has.
 *
 * **What the application gets back for a flag.** MISP's flag columns are
 * tinyint(1) on MySQL, and Cake's MySQL driver hands them to the application
 * as PHP booleans - through the ORM and through Model::query() alike, since
 * both read through fetchResult(). On PostgreSQL they are boolean columns
 * and this driver does the same: a bool column is true, false or null, never
 * "1" or "0". (An earlier version returned the strings, on the belief that
 * MySQL did; it does not, and a "0" that MySQL renders as false reached the
 * API as a string that every consumer took for true.) bytea arrives as the
 * bytes whether the driver build hands it over as a stream or a string.
 *
 * The other direction is where the engines differ. MysqlExtended::value() short-circuits
 * PHP integers and booleans before looking at the column type; copying that
 * here would render `deleted = 1` for a boolean column, which PostgreSQL
 * rejects. So a value bound for a boolean column goes through the driver's
 * own TRUE/FALSE rendering, a PHP boolean bound for any other column becomes
 * '1' or '0', and an integer whose column type the ORM could not resolve is
 * quoted rather than bare. PostgreSQL coerces a quoted literal to whatever
 * the column is - boolean, integer or text - where a bare 0 against a
 * boolean column is an error, so quoting is what keeps `'Alias.flag' => 0`
 * working in a join condition Cake cannot type.
 *
 * **What an unqualified ORDER BY means.** MySQL resolves an ORDER BY name
 * against the select list before the tables, so `'order' => 'date_created
 * DESC'` on a find that joins User sorts by the primary model's column even
 * though User has one too. PostgreSQL resolves it against the joined tables
 * and rejects the ambiguity. Cake's order() only quotes such a key; order()
 * here qualifies it with the model's alias when the model has that field,
 * which is what MySQL's rule comes to for the statements Cake writes, since
 * the primary model's fields lead the select list. A key the model does not
 * own - an aggregate alias, a function, a joined model's column - is left
 * alone.
 *
 * **What the inserted id is when there is none.** After an INSERT Cake asks
 * the driver for the new row's id. Cake's Postgres driver asks currval() of
 * the sequence it saw in a nextval() default during describe(), and when
 * the schema came out of the model cache it saw none and names one by
 * convention - "{table}_{field}_seq" - on faith. That name exists for every
 * serial column and for nothing else: bruteforces has no id column at all,
 * system_settings is keyed on a varchar, and PostgreSQL answers both with
 * "relation does not exist". MySQL returns 0 for a table without
 * AUTO_INCREMENT, so lastInsertId() here asks the catalogue which sequence
 * the column owns, once per table, and answers "0" when it owns none.
 *
 * **What a raw subquery's alias looks like.** Cake's condition quoting
 * strips every quote from a raw SQL fragment and re-quotes only the dotted
 * names, then re-quotes an alias only when the table before AS came out
 * quoted. A subquery built by DboSource::buildStatement() from a bare table
 * name - `SELECT event_id FROM attributes AS "Attribute" ...`, the shape
 * AppModel::subQueryGenerator() produces - therefore reaches the engine as
 * `attributes AS Attribute` while every reference to it stays "Attribute".
 * MySQL does not fold identifier case and never notices; PostgreSQL folds
 * the bare alias to `attribute` and reports a missing FROM-clause entry.
 * _quoteFields() here quotes the alias after AS whenever Cake left it bare.
 *
 * **What the operator sees in the logs.** Every statement is prefixed with
 * the user, controller and action the way MysqlObserver's are, timed the
 * same way, and reported to the same slow-query log when benchmarking is on.
 *
 * @see MysqlObserverExtended for the MySQL counterpart.
 * @see AppModel::checkDbSupport()
 */
class PostgresObserverExtended extends Postgres
{
    /**
     * @var array What this driver can be asked to do. Same vocabulary as
     *   MysqlExtended, answered for PostgreSQL.
     */
    public $supports = [
        'indexHints' => false,
        'ignoreIndexHints' => false,
        'reverseJoin' => false,
        'straightJoin' => false,
        'insertMulti' => true,
        'temporaryMemoryTable' => false,
        'fulltextIndex' => false,
    ];

    public static $totalSqlTimeMs = 0;

    protected $Redis;

    /**
     * @var array table => field => the sequence the catalogue says the column
     *   owns, as schema.sequence, or false when it owns none. Kept apart
     *   from Cake's $_sequenceMap, which describe() resets per table and
     *   truncate() iterates as a list of real sequences.
     */
    private $ownedSequences = [];

    /**
     * Same shape as MysqlObserverExtended::execute(): prefix the statement
     * with who is running it, time it only when something will read the
     * timing, count it always.
     *
     * @param string $sql
     * @param array $options
     * @param array $params
     * @return mixed
     */
    public function execute($sql, $options = [], $params = [])
    {
        $log = $options['log'] ?? $this->fullDebug;
        $logQM = false;
        if (Configure::read('Plugin.Benchmarking_enable')) {
            $log = true;
            if (Configure::read('Plugin.Benchmarking_log_query_metrics')) {
                $this->Redis = RedisTool::init();
                $logQM = true;
            }
        }
        $currentController = empty(Configure::read('CurrentController')) ? 'Unknown' : preg_replace('/[^a-zA-Z0-9_]/', '', Configure::read('CurrentController')) . ' :: ';
        $currentAction = empty(Configure::read('CurrentAction')) ? 'Unknown' : preg_replace('/[^a-zA-Z0-9_]/', '', Configure::read('CurrentAction'));
        $comment = sprintf(
            '%s%s%s',
            empty(Configure::read('CurrentUserId')) ? '' : sprintf(
                '[User: %s] ',
                intval(Configure::read('CurrentUserId'))
            ),
            $currentController,
            $currentAction
        );
        $sql = '/* ' . $comment . ' */ ' . $sql;
        if ($log) {
            $t = microtime(true);
            $this->_result = $this->_execute($sql, $params);
            $this->took = round((microtime(true) - $t) * 1000);
            if ($logQM) {
                if ($this->took > (Configure::check('Plugin.Benchmarking_slow_log_threshold') ? Configure::read('Plugin.Benchmarking_slow_log_threshold') : 5000)) {
                    $key = 'misp:slowlog:' . uniqid();
                    $payload = $this->took . '|' . $sql;
                    $this->Redis->set($key, $payload);
                    $this->Redis->expire($key, Configure::check('Plugin.Benchmarking_slow_query_retention') ? Configure::read('Plugin.Benchmarking_slow_query_retention') : 259200);
                }
                self::$totalSqlTimeMs += $this->took;
            }
            $this->numRows = $this->affected = $this->lastAffected();
            $this->logQuery($sql, $params);
        } else {
            $this->_result = $this->_execute($sql, $params);
            $this->_queriesCnt++;
        }

        return $this->_result;
    }

    /**
     * Literal rendering that keeps MISP's integer-flag habits working against
     * boolean columns. See the class docblock for the three rules.
     *
     * {@inheritDoc}
     */
    public function value($data, $column = null, $null = true)
    {
        if (is_array($data) && !empty($data)) {
            $output = [];
            foreach ($data as $d) {
                $output[] = $this->value($d, $column, $null);
            }
            return $output;
        }
        if ($column === 'boolean') {
            // The driver's own rendering: TRUE / FALSE, from any of the
            // spellings MISP uses for a flag, '' and '0' included.
            return parent::value($data, $column, $null);
        }
        if (is_bool($data)) {
            return $data ? "'1'" : "'0'";
        }
        if (is_int($data)) {
            // Bare when the column is known to be numeric; quoted when the
            // ORM could not tell, since a quoted literal is coerced to any
            // column type and a bare one is not.
            return $column === null ? "'" . $data . "'" : $data;
        }
        return parent::value($data, $column, $null);
    }

    /**
     * Rows as MISP reads them on MySQL: a bool column is a PHP boolean (or
     * null), bytea is the bytes.
     *
     * Cake's Postgres::fetchResult() already makes the boolean; what it
     * assumes is that a bytea arrives as a stream, and whether it does
     * depends on the driver build, so both forms are taken.
     *
     * @return array|bool
     */
    public function fetchResult()
    {
        if ($row = $this->_result->fetch(PDO::FETCH_NUM)) {
            $resultRow = [];
            foreach ($this->map as $index => $meta) {
                list($table, $column, $type) = $meta;
                $value = $row[$index];
                switch ($type) {
                    case 'bool':
                        $resultRow[$table][$column] = $value === null ? null : $this->boolean($value);
                        break;
                    case 'binary':
                    case 'bytea':
                        $resultRow[$table][$column] = is_resource($value) ? stream_get_contents($value) : $value;
                        break;
                    default:
                        $resultRow[$table][$column] = $value;
                }
            }
            return $resultRow;
        }
        $this->_result->closeCursor();
        return false;
    }

    /**
     * Cake's quoting of a raw condition fragment, plus the alias after AS
     * when Cake left it bare. See the class docblock.
     *
     * The table before AS is a bare or dotted name; an alias Cake already
     * quoted starts with a quote and does not match. What follows the alias
     * is whitespace, a closing parenthesis, a comma or the end - which is
     * what follows a FROM alias, and not what follows the word AS inside an
     * expression like CAST(x AS integer).
     *
     * @param string $conditions
     * @return string
     */
    protected function _quoteFields($conditions)
    {
        $conditions = parent::_quoteFields($conditions);
        if (!is_string($conditions)) {
            return $conditions;
        }
        return preg_replace(
            '/(\s(?:[a-z0-9_]+\.)?[a-z0-9_]+)\s+AS\s+([a-z0-9_]+)(?=\s|\)|,|$)/i',
            '$1 AS ' . $this->startQuote . '$2' . $this->endQuote,
            $conditions
        );
    }

    /**
     * ORDER BY with MySQL's resolution of an unqualified name. See the class
     * docblock.
     *
     * @param array|string $keys
     * @param string $direction
     * @param Model|null $Model
     * @return string
     */
    public function order($keys, $direction = 'ASC', ?Model $Model = null)
    {
        if ($Model !== null) {
            $keys = $this->qualifyOrderKeys($keys, $Model);
        }
        return parent::order($keys, $direction, $Model);
    }

    /**
     * Walk the shapes Cake's order() accepts - a string, a comma-separated
     * string, a list of 'field DIR' strings, a map of field => DIR, nested
     * arrays of those - and qualify each bare field the model owns.
     *
     * @param mixed $keys
     * @param Model $Model
     * @return mixed The same shape, with qualified keys.
     */
    private function qualifyOrderKeys($keys, Model $Model)
    {
        if (is_string($keys)) {
            // The same split Cake's order() makes, so each part is seen alone.
            if (strpos($keys, ',') !== false && !preg_match('/\(.+\,.+\)/', $keys)) {
                $parts = [];
                foreach (explode(',', $keys) as $part) {
                    $parts[] = $this->qualifyOrderKey(trim($part), $Model);
                }
                return $parts;
            }
            return $this->qualifyOrderKey($keys, $Model);
        }
        if (!is_array($keys)) {
            return $keys; // an expression object
        }
        $qualified = [];
        foreach ($keys as $key => $direction) {
            if (is_numeric($key)) {
                $qualified[$key] = $this->qualifyOrderKeys($direction, $Model);
            } else {
                $qualified[$this->qualifyOrderKey($key, $Model)] = $direction;
            }
        }
        return $qualified;
    }

    /**
     * One 'field' or 'field DIR': prefixed with the model's alias when it is
     * a bare name of a column the model has. Anything else - already
     * qualified, an expression, an alias from the select list, a virtual
     * field - is returned untouched.
     *
     * @param string $key
     * @param Model $Model
     * @return string
     */
    private function qualifyOrderKey($key, Model $Model)
    {
        if (!preg_match('/^\s*([A-Za-z_][A-Za-z0-9_]*)(\s+(?:ASC|DESC))?\s*$/i', $key, $match)) {
            return $key;
        }
        $field = $match[1];
        if (!$Model->hasField($field) || $Model->isVirtualField($field)) {
            return $key;
        }
        return $Model->alias . '.' . trim($key);
    }

    /**
     * INSERT, and when the row named its own key, move the sequence past it.
     *
     * MySQL moves AUTO_INCREMENT past an explicitly inserted id; a PostgreSQL
     * sequence does not know the insert happened. User::init() inserts the
     * first role, organisation and user as id 1, and on a fresh PostgreSQL
     * install the next insert into each of those tables then asked its
     * sequence for 1 and collided. After such an insert the owned sequence
     * is set to the column's maximum, which is what MySQL's behaviour comes
     * to; an insert that let the engine assign the id costs nothing extra.
     *
     * @param Model $Model
     * @param array|null $fields
     * @param array|null $values
     * @return bool
     */
    public function create(Model $Model, $fields = null, $values = null)
    {
        $named = $fields === null ? array_keys((array)$Model->data) : $fields;
        $created = parent::create($Model, $fields, $values);
        if ($created && in_array($Model->primaryKey, $named, true)) {
            $this->advanceSequencePastMax($this->fullTableName($Model, false, false), $Model->primaryKey);
        }
        return $created;
    }

    /**
     * setval() the sequence owned by $table.$field to the column's maximum,
     * if it owns one.
     *
     * @param string $table
     * @param string $field
     * @return void
     */
    protected function advanceSequencePastMax($table, $field)
    {
        $sequence = $this->sequenceFor($table, $field);
        if ($sequence === false) {
            return;
        }
        $this->_execute(sprintf(
            'SELECT setval(%s, (SELECT MAX(%s) FROM %s))',
            $this->value($sequence, 'string'),
            $this->name($field),
            $this->fullTableName($table)
        ));
    }

    /**
     * The sequence behind a key column: what describe() saw in a nextval()
     * default this process, else what the catalogue says, remembered.
     *
     * @param string $table
     * @param string $field
     * @return string|false
     */
    private function sequenceFor($table, $field)
    {
        if (isset($this->_sequenceMap[$table][$field])) {
            return $this->_sequenceMap[$table][$field];
        }
        if (!isset($this->ownedSequences[$table][$field])) {
            $this->ownedSequences[$table][$field] = $this->ownedSequence($table, $field);
        }
        return $this->ownedSequences[$table][$field];
    }

    /**
     * The id PostgreSQL just assigned, or "0" - MySQL's answer - for a key
     * column with no sequence behind it. See the class docblock.
     *
     * @param string|Model|null $source Table name, with prefix, or the model.
     * @param string $field The key column.
     * @return string
     */
    public function lastInsertId($source = null, $field = 'id')
    {
        $table = is_object($source) ? $this->fullTableName($source, false, false) : (string)$source;
        $sequence = $this->sequenceFor($table, $field);
        return $sequence === false ? '0' : $this->_connection->lastInsertId($sequence);
    }

    /**
     * What pg_get_serial_sequence() answers, asked in a way that tolerates a
     * column that does not exist: the sequence a serial or identity column
     * owns, as schema.sequence, or false when there is none.
     *
     * @param string $table
     * @param string $field
     * @return string|false
     */
    protected function ownedSequence($table, $field)
    {
        $statement = $this->_execute(
            "SELECT sn.nspname || '.' || s.relname
            FROM pg_catalog.pg_class t
            JOIN pg_catalog.pg_namespace tn ON tn.oid = t.relnamespace
            JOIN pg_catalog.pg_attribute a ON a.attrelid = t.oid AND a.attname = ? AND NOT a.attisdropped
            JOIN pg_catalog.pg_depend d ON d.refclassid = 'pg_catalog.pg_class'::regclass
                AND d.refobjid = t.oid AND d.refobjsubid = a.attnum
                AND d.classid = 'pg_catalog.pg_class'::regclass AND d.deptype IN ('a', 'i')
            JOIN pg_catalog.pg_class s ON s.oid = d.objid AND s.relkind = 'S'
            JOIN pg_catalog.pg_namespace sn ON sn.oid = s.relnamespace
            WHERE tn.nspname = ? AND t.relname = ?",
            [$field, isset($this->config['schema']) ? $this->config['schema'] : 'public', $table]
        );
        if (!is_object($statement)) {
            return false;
        }
        $sequence = $statement->fetchColumn();
        $statement->closeCursor();
        return is_string($sequence) && $sequence !== '' ? $sequence : false;
    }

    /**
     * Output SHA1 as binary, that is faster and uses less memory.
     *
     * @param string $value
     * @return string
     */
    public function cacheMethodHasher($value)
    {
        return sha1($value, true);
    }
}
