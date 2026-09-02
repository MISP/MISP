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
 * **What the application expects of a flag.** MISP's flag columns are
 * tinyint(1) on MySQL, which the application reads back as the strings "1"
 * and "0" and compares as such in more than a hundred places. On PostgreSQL
 * they are boolean, and Cake's Postgres driver would hand the application a
 * PHP true or false - correct in the abstract, and a strict comparison
 * against '0' fails on every one of them. fetchResult() therefore returns
 * booleans as "1" and "0", which is also what a raw PDO fetch already
 * returns under ATTR_STRINGIFY_FETCHES, so the ORM and the raw paths agree
 * with each other and with MySQL.
 *
 * The other direction matters as much. MysqlExtended::value() short-circuits
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
     * Rows as MISP reads them on MySQL: a boolean is "1" or "0", bytea is
     * the bytes.
     *
     * Cake's Postgres::fetchResult() converts a bool column to a PHP boolean
     * and assumes a bytea arrives as a stream. Under the ATTR_STRINGIFY_FETCHES
     * flag MISP sets, a raw fetch already yields "1"/"0" for a bool, and
     * whether bytea is a stream or a string depends on the driver build - so
     * both are handled either way.
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
                        $resultRow[$table][$column] = $value === null ? null : ($this->boolean($value) ? '1' : '0');
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
