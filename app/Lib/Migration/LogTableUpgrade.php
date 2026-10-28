<?php

App::uses('AbstractGrammar', 'Migration/Grammar');
App::uses('Collation', 'Migration');
App::uses('SchemaBuilder', 'Migration');
App::uses('SchemaInspector', 'Migration');
App::uses('TableConverger', 'Migration');

/**
 * Brings the history tables `logs` and `audit_logs` to their 3.0 layout while
 * the instance stays online, for the instances that choose to; a fresh
 * install starts there.
 *
 * The table is swapped for an empty one at the target in one atomic step,
 * new rows go there from then on, and the old rows are copied back newest
 * first in id ranges. Nothing refers to a log id, so the ids are kept and
 * the log views fill in while the copy runs. Every step can be repeated: the
 * copy resumes from the oldest row already in the new table, and only
 * finish() drops the old one.
 */
class LogTableUpgrade
{
    const LEGACY_SUFFIX = '_legacy';

    const NEW_SUFFIX = '_new';

    /** New ids start this far past the old table's last one (MySQL). */
    const ID_MARGIN = 10000;

    /** Seconds the swap waits for a lock before giving up. */
    const LOCK_WAIT = 5;

    /** The new table is this much larger than the old one: its indexes and 64-bit ids. */
    const SPACE_FACTOR = 1.7;

    const TARGETS = array(
        'logs' => array(
            'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
            'columns' => array(
                'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
                'title' => array('type' => 'text', 'null' => true, 'collate' => Collation::BIN),
                'created' => array('type' => 'datetime', 'null' => false),
                'model' => array('type' => 'string', 'length' => 80, 'null' => false, 'collate' => Collation::BIN),
                'model_id' => array('type' => 'biginteger', 'null' => false),
                'action' => array('type' => 'string', 'length' => 80, 'null' => false, 'collate' => Collation::BIN),
                'user_id' => array('type' => 'biginteger', 'null' => false),
                'change' => array('type' => 'text', 'null' => true, 'collate' => Collation::BIN),
                'email' => array(
                    'type' => 'string',
                    'length' => 255,
                    'null' => false,
                    'default' => '',
                    'collate' => Collation::BIN,
                ),
                'org' => array(
                    'type' => 'string',
                    'length' => 255,
                    'null' => false,
                    'default' => '',
                    'collate' => Collation::BIN,
                ),
                'description' => array('type' => 'text', 'null' => true, 'collate' => Collation::BIN),
                'ip' => array(
                    'type' => 'string',
                    'length' => 45,
                    'null' => false,
                    'default' => '',
                    'collate' => Collation::BIN,
                ),
            ),
            'indexes' => array(
                'idx_logs_action' => array('column' => array('action')),
                'idx_logs_created' => array('column' => array('created')),
                'idx_logs_email' => array('column' => array('email')),
                'idx_logs_model_id' => array('column' => array('model', 'model_id')),
                'idx_logs_org' => array('column' => array('org')),
                'idx_logs_user_id_action' => array('column' => array('user_id', 'action')),
            ),
            'retired' => array(),
        ),
        'audit_logs' => array(
            'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
            'columns' => array(
                'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
                'created' => array('type' => 'datetime', 'null' => false),
                'user_id' => array('type' => 'biginteger', 'null' => false),
                'org_id' => array('type' => 'biginteger', 'null' => false),
                'authkey_id' => array('type' => 'biginteger', 'null' => true),
                'ip' => array('type' => 'varbinary', 'length' => 16, 'null' => true),
                'request_type' => array('type' => 'tinyinteger', 'null' => false),
                'request_id' => array('type' => 'string', 'length' => 255, 'null' => true, 'collate' => Collation::CI),
                'action' => array('type' => 'string', 'length' => 20, 'null' => false, 'collate' => Collation::CI),
                'model' => array('type' => 'string', 'length' => 80, 'null' => false, 'collate' => Collation::CI),
                'model_id' => array('type' => 'biginteger', 'null' => false),
                'model_title' => array('type' => 'text', 'null' => true, 'collate' => Collation::CI),
                'event_id' => array('type' => 'biginteger', 'null' => true),
                'change' => array('type' => 'binary', 'null' => true),
            ),
            'indexes' => array(
                'action' => array('column' => array('action')),
                'authkey_id' => array('column' => array('authkey_id')),
                'created' => array('column' => array('created')),
                'event_id' => array('column' => array('event_id')),
                'model_id' => array('column' => array('model', 'model_id')),
                'org_id' => array('column' => array('org_id')),
                'user_id' => array('column' => array('user_id')),
            ),
            'retired' => array(),
        ),
    );

    /** @var SchemaInspector */
    private $inspector;

    /** @var DboSource */
    private $db;

    /**
     * @param SchemaInspector $inspector
     */
    public function __construct(SchemaInspector $inspector)
    {
        $this->inspector = $inspector;
        $this->db = $inspector->getDataSource();
    }

    /**
     * @param string $table
     * @return string
     */
    public static function legacyName($table)
    {
        return $table . self::LEGACY_SUFFIX;
    }

    /**
     * @param string $table
     * @return void
     * @throws InvalidArgumentException
     */
    public static function assertTable($table)
    {
        if (!isset(self::TARGETS[$table])) {
            throw new InvalidArgumentException(sprintf(
                'Unknown log table "%s"; the tables are %s.',
                $table,
                implode(', ', array_keys(self::TARGETS))
            ));
        }
    }

    /**
     * Where a table stands.
     *
     * @param string $table
     * @return array
     *   'state': 'current' (at the target), 'old' (not upgraded), 'copying'
     *   (swapped, rows left in the legacy table), 'copied' (swapped, nothing
     *   left to copy) or 'conflict' (a legacy table next to a table that is
     *   not at the target);
     *   'rows', 'bytes': the table that holds the old rows (an estimate);
     *   'need': bytes the upgrade needs free, for 'old';
     *   'first', 'last', 'next': the legacy table's id range and where the
     *   copy goes on from (ids below 'next' are left), once swapped.
     */
    public function status($table)
    {
        self::assertTable($table);
        $legacy = self::legacyName($table);
        $swapped = $this->inspector->hasTable($legacy);
        $current = $this->isCurrent($table);
        $sizes = $this->inspector->tableSizes();
        $holder = $swapped ? $legacy : $table;
        $status = array(
            'table' => $table,
            'state' => $current ? 'current' : 'old',
            'rows' => isset($sizes[$holder]) ? $sizes[$holder]['row_estimate'] : 0,
            'bytes' => isset($sizes[$holder]) ? $sizes[$holder]['total_in_bytes'] : 0,
        );
        if (!$swapped) {
            if (!$current) {
                $status['need'] = (int)ceil($status['bytes'] * self::SPACE_FACTOR);
            }
            return $status;
        }
        if (!$current) {
            $status['state'] = 'conflict';
            return $status;
        }
        $status += $this->bounds($table);
        $status['state'] = $this->isCopied($status) ? 'copied' : 'copying';
        return $status;
    }

    /**
     * @param string $table
     * @return bool Whether the table has its 3.0 layout.
     */
    public function isCurrent($table)
    {
        self::assertTable($table);
        if (!$this->inspector->hasTable($table)) {
            return false;
        }
        return TableConverger::isEmpty(TableConverger::plan($this->inspector, $table, self::TARGETS[$table]));
    }

    /**
     * Whether this process holds the lock that keeps two runs apart. Released
     * when the connection ends.
     *
     * @return bool
     */
    public function lock()
    {
        $sql = $this->inspector->flavour() === AbstractGrammar::FLAVOUR_MYSQL
            ? "SELECT GET_LOCK('misp_log_tables', 0) AS got;"
            : "SELECT pg_try_advisory_lock(hashtext('misp_log_tables')) AS got;";
        $rows = $this->inspector->probeRows($sql);
        $got = isset($rows[0]['got']) ? $rows[0]['got'] : null;
        return in_array($got, array(true, 1, '1', 't'), true);
    }

    /**
     * Put an empty table at the target in place of the old one, which stays
     * as the legacy table. The instance writes to the new table from then on.
     *
     * @param string $table
     * @return bool False when there was nothing to swap.
     * @throws RuntimeException When the table is busy or left in a state this
     *   cannot carry on from.
     */
    public function swap($table)
    {
        $status = $this->status($table);
        if ($status['state'] !== 'old') {
            return false;
        }
        if ($this->inspector->flavour() === AbstractGrammar::FLAVOUR_MYSQL) {
            $this->swapMysql($table);
        } else {
            $this->swapPostgres($table);
        }
        $this->inspector->disableSchemaCache();
        $this->inspector->flushSchemaCacheFiles();
        return true;
    }

    /**
     * Copy the legacy table's rows into the new one, newest first, one id
     * range per statement.
     *
     * @param string $table
     * @param int $batch Ids per statement.
     * @param int $pause Milliseconds between statements.
     * @param string|null $since 'Y-m-d H:i:s': stop at the first range whose
     *   rows are all older. Whole ranges are copied, so that every legacy row
     *   from 'next' up is in the new table, which is what a resume and
     *   finish() count on.
     * @param callable|null $progress Called after each statement with the
     *   rows copied so far and bounds() as it then stands.
     * @return int Rows copied.
     */
    public function copy($table, $batch, $pause = 0, $since = null, $progress = null)
    {
        $bounds = $this->bounds($table);
        if ($this->isCopied($bounds)) {
            return 0;
        }
        $batch = max(1, (int)$batch);
        $legacy = self::legacyName($table);
        $columns = array_intersect(
            array_keys(self::TARGETS[$table]['columns']),
            array_keys($this->inspector->columns($legacy))
        );
        $list = implode(', ', array_map(array($this->db, 'name'), $columns));
        $insert = sprintf(
            'INSERT INTO %s (%s) SELECT %s FROM %s WHERE %s >= %%d AND %s < %%d;',
            $this->db->name($table),
            $list,
            $list,
            $this->db->name($legacy),
            $this->db->name('id'),
            $this->db->name('id')
        );
        $newest = sprintf(
            'SELECT MAX(%s) AS newest FROM %s WHERE %s >= %%d AND %s < %%d;',
            $this->db->name('created'),
            $this->db->name($legacy),
            $this->db->name('id'),
            $this->db->name('id')
        );
        $restore = $this->allowZeroDates();
        $copied = 0;
        try {
            while (!$this->isCopied($bounds)) {
                $low = max($bounds['first'], $bounds['next'] - $batch);
                if ($since !== null) {
                    $rows = $this->inspector->probeRows(sprintf($newest, $low, $bounds['next']));
                    if (isset($rows[0]['newest']) && $rows[0]['newest'] < $since) {
                        break;
                    }
                }
                $this->db->rawQuery(sprintf($insert, $low, $bounds['next']));
                $copied += (int)$this->db->lastAffected();
                $bounds['next'] = $low;
                if ($progress !== null) {
                    call_user_func($progress, $copied, $bounds);
                }
                if ($pause > 0) {
                    usleep($pause * 1000);
                }
            }
        } finally {
            if ($restore !== null) {
                $this->db->rawQuery($restore);
            }
        }
        return $copied;
    }

    /**
     * Drop the legacy table.
     *
     * @param string $table
     * @param bool $force Drop it with rows that were not copied.
     * @return int|null Rows dropped without being copied; null when there was
     *   no legacy table.
     * @throws RuntimeException When rows are left and $force is not set.
     */
    public function finish($table, $force = false)
    {
        self::assertTable($table);
        $legacy = self::legacyName($table);
        if (!$this->inspector->hasTable($legacy)) {
            return null;
        }
        $bounds = $this->bounds($table);
        $left = 0;
        if (!$this->isCopied($bounds)) {
            $rows = $this->inspector->probeRows(sprintf(
                'SELECT COUNT(*) AS left_over FROM %s WHERE %s < %d;',
                $this->db->name($legacy),
                $this->db->name('id'),
                $bounds['next']
            ));
            $left = isset($rows[0]['left_over']) ? (int)$rows[0]['left_over'] : 0;
        }
        if ($left > 0 && !$force) {
            throw new RuntimeException(sprintf(
                '%s: %d rows of %s have not been copied. Copy them with Console/cake LogTables upgrade, or drop them with finish --force.',
                $table,
                $left,
                $legacy
            ));
        }
        $this->db->rawQuery(sprintf('DROP TABLE %s;', $this->db->name($legacy)));
        $this->inspector->disableSchemaCache();
        return $left;
    }

    /**
     * The legacy table's id range and where the copy goes on from: the
     * oldest row already copied, since every statement copies a whole range.
     *
     * @param string $table
     * @return array 'first', 'last' (null when the legacy table is empty),
     *   'next' (ids below it are left).
     */
    public function bounds($table)
    {
        self::assertTable($table);
        $id = $this->db->name('id');
        $rows = $this->inspector->probeRows(sprintf(
            'SELECT MIN(%s) AS first_id, MAX(%s) AS last_id FROM %s;',
            $id,
            $id,
            $this->db->name(self::legacyName($table))
        ));
        if (!isset($rows[0]['last_id'])) {
            return array('first' => null, 'last' => null, 'next' => null);
        }
        $first = (int)$rows[0]['first_id'];
        $last = (int)$rows[0]['last_id'];
        $rows = $this->inspector->probeRows(sprintf(
            'SELECT MIN(%s) AS low FROM %s WHERE %s <= %d;',
            $id,
            $this->db->name($table),
            $id,
            $last
        ));
        $next = isset($rows[0]['low']) ? (int)$rows[0]['low'] : $last + 1;
        return array('first' => $first, 'last' => $last, 'next' => $next);
    }

    /**
     * @param array $bounds bounds()
     * @return bool
     */
    private function isCopied(array $bounds)
    {
        return $bounds['first'] === null || $bounds['next'] <= $bounds['first'];
    }

    /**
     * @param string $table The target's.
     * @param string $name What to create it as.
     * @return array Statements for the connected engine.
     */
    private function creation($table, $name)
    {
        $schema = SchemaBuilder::forDataSource($this->db);
        TableConverger::emit($schema, TableConverger::creationPlan($name, self::TARGETS[$table]));
        return $schema->toSql();
    }

    /**
     * MySQL renames both tables in one atomic statement. The new table is
     * created first under another name; writes the old one takes until the
     * rename stay below the new table's first id, by a margin.
     *
     * @param string $table
     * @return void
     * @throws RuntimeException
     */
    private function swapMysql($table)
    {
        $new = $table . self::NEW_SUFFIX;
        $legacy = self::legacyName($table);
        if ($this->inspector->hasTable($new)) {
            $rows = $this->inspector->probeRows(sprintf('SELECT COUNT(*) AS n FROM %s;', $this->db->name($new)));
            if (!empty($rows[0]['n'])) {
                throw new RuntimeException(sprintf('%s exists and holds rows, so it is not one an interrupted run left behind. Rename or drop it first.', $new));
            }
            $this->db->rawQuery(sprintf('DROP TABLE %s;', $this->db->name($new)));
        }
        foreach ($this->creation($table, $new) as $statement) {
            $this->db->rawQuery($statement);
        }
        $start = $this->maxId($table) + self::ID_MARGIN;
        $this->db->rawQuery(sprintf('ALTER TABLE %s AUTO_INCREMENT = %d;', $this->db->name($new), $start));
        $this->db->rawQuery(sprintf('SET SESSION lock_wait_timeout = %d;', self::LOCK_WAIT));
        try {
            $this->db->rawQuery(sprintf(
                'RENAME TABLE %s TO %s, %s TO %s;',
                $this->db->name($table),
                $this->db->name($legacy),
                $this->db->name($new),
                $this->db->name($table)
            ));
        } catch (PDOException $e) {
            throw new RuntimeException(sprintf('%s could not be swapped: %s Another session holds it, most likely a long query; run this again once it is done.', $table, $e->getMessage()));
        } finally {
            $this->db->rawQuery('SET SESSION lock_wait_timeout = DEFAULT;');
        }
        if ($this->maxId($legacy) >= $start) {
            throw new RuntimeException(sprintf('%s took rows up to id %d before the swap, past the new table\'s first id %d. Do not copy it; ask for help.', $legacy, $this->maxId($legacy), $start));
        }
    }

    /**
     * PostgreSQL swaps in one transaction, holding the old table's lock: the
     * old table and its indexes and sequence take the legacy name, and the
     * new table is created under the real one, so that it gets the names a
     * fresh install has (index names share one namespace per schema).
     *
     * @param string $table
     * @return void
     * @throws RuntimeException
     */
    private function swapPostgres($table)
    {
        $legacy = self::legacyName($table);
        $this->db->begin();
        try {
            $this->db->rawQuery(sprintf("SET LOCAL lock_timeout = '%ds';", self::LOCK_WAIT));
            try {
                $this->db->rawQuery(sprintf('LOCK TABLE %s IN ACCESS EXCLUSIVE MODE;', $this->db->name($table)));
            } catch (PDOException $e) {
                throw new RuntimeException(sprintf('%s could not be swapped: %s Another session holds it, most likely a long query; run this again once it is done.', $table, $e->getMessage()));
            }
            $last = $this->maxId($table);
            $this->db->rawQuery(sprintf('ALTER TABLE %s RENAME TO %s;', $this->db->name($table), $this->db->name($legacy)));
            $indexes = $this->inspector->probeRows(sprintf(
                'SELECT i.relname AS name FROM pg_catalog.pg_index x'
                    . ' JOIN pg_catalog.pg_class i ON i.oid = x.indexrelid'
                    . ' JOIN pg_catalog.pg_class t ON t.oid = x.indrelid'
                    . ' WHERE t.oid = %s::regclass;',
                $this->db->value($legacy, 'string')
            ));
            foreach ($indexes as $index) {
                $this->db->rawQuery(sprintf(
                    'ALTER INDEX %s RENAME TO %s;',
                    $this->db->name($index['name']),
                    $this->db->name(substr($index['name'], 0, 63 - strlen(self::LEGACY_SUFFIX)) . self::LEGACY_SUFFIX)
                ));
            }
            $rows = $this->inspector->probeRows(sprintf("SELECT pg_get_serial_sequence(%s, 'id') AS seq;", $this->db->value($legacy, 'string')));
            if (!empty($rows[0]['seq'])) {
                $this->db->rawQuery(sprintf('ALTER SEQUENCE %s RENAME TO %s;', $rows[0]['seq'], $this->db->name($legacy . '_id_seq')));
            }
            foreach ($this->creation($table, $table) as $statement) {
                $this->db->rawQuery($statement);
            }
            if ($last > 0) {
                $this->db->rawQuery(sprintf(
                    "SELECT setval(pg_get_serial_sequence(%s, 'id'), %d);",
                    $this->db->value($table, 'string'),
                    $last
                ));
            }
            $this->db->commit();
        } catch (Exception $e) {
            $this->db->rollback();
            throw $e;
        }
    }

    /**
     * @param string $table
     * @return int 0 for an empty table.
     */
    private function maxId($table)
    {
        $rows = $this->inspector->probeRows(sprintf(
            'SELECT MAX(%s) AS last_id FROM %s;',
            $this->db->name('id'),
            $this->db->name($table)
        ));
        return isset($rows[0]['last_id']) ? (int)$rows[0]['last_id'] : 0;
    }

    /**
     * Let the copy take the zero dates an old MySQL table may hold, which
     * the session's NO_ZERO_DATE would refuse.
     *
     * @return string|null The statement that restores the session's mode.
     */
    private function allowZeroDates()
    {
        if ($this->inspector->flavour() !== AbstractGrammar::FLAVOUR_MYSQL) {
            return null;
        }
        $rows = $this->inspector->probeRows('SELECT @@SESSION.sql_mode AS mode;');
        $mode = isset($rows[0]['mode']) ? (string)$rows[0]['mode'] : '';
        $relaxed = array_diff(explode(',', $mode), array('NO_ZERO_DATE', 'NO_ZERO_IN_DATE', ''));
        $this->db->rawQuery(sprintf('SET SESSION sql_mode = %s;', $this->db->value(implode(',', $relaxed), 'string')));
        return sprintf('SET SESSION sql_mode = %s;', $this->db->value($mode, 'string'));
    }
}
