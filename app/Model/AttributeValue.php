<?php
App::uses('AppModel', 'Model');

/**
 * The attribute value dictionary: one row per exact byte string, referenced
 * by attributes and proposals through value1_id and value2_id.
 *
 * Rows are only ever added. Uniqueness comes from the hash column alone: the
 * value column's collation equates strings that differ in case, accents or
 * trailing spaces, and that is what resolveCi() and resolveLike() rely on.
 * PostgreSQL folds case only: accents, NBSP and trailing spaces stay
 * significant there.
 */
class AttributeValue extends AppModel
{
    const CHUNK = 1000;

    // What a TEXT column holds, and what MispAttribute::maxTextLength allows
    const MAX_BYTES = 65535;

    // Keeps a multi-row statement well inside a 16 MB max_allowed_packet
    const STATEMENT_BYTES = 2097152;

    // Must match the case-insensitive index the dictionary migration creates
    const CI_PREFIX = 128;

    const DEADLOCK_ATTEMPTS = 5;

    public $useTable = 'attribute_values';

    public $recursive = -1;

    /**
     * @param string $value
     * @return string 16 raw bytes
     */
    public function hashOf($value)
    {
        return substr(hash('sha256', $value, true), 0, 16);
    }

    /**
     * @param string $value
     * @return int
     */
    public function intern($value)
    {
        $ids = $this->internMany([$value]);
        return $ids[(string)$value];
    }

    /**
     * Ids for the given values, adding the ones the dictionary does not hold.
     *
     * Existing values are selected first, so only the missing ones are
     * inserted and no auto-increment ids are spent on collisions. Every row
     * read back is checked against the input byte for byte. Outside a
     * transaction a deadlock is retried; inside one it reaches the caller,
     * whose transaction the database has already rolled back.
     *
     * @param array $values Scalars; repeats are collapsed.
     * @return array [value => id]. PHP turns numeric-string keys into ints.
     * @throws InvalidArgumentException For a non-scalar or over-long value.
     * @throws RuntimeException On a hash collision or a row that does not
     *   match its hash.
     */
    public function internMany(array $values)
    {
        $byHash = $this->hashValues($values);
        for ($attempt = 1; ; $attempt++) {
            try {
                return $this->internHashed($byHash);
            } catch (PDOException $e) {
                if ($attempt >= self::DEADLOCK_ATTEMPTS || !$this->isDeadlock($e) || $this->inTransaction()) {
                    throw $e;
                }
                usleep(mt_rand(1000, 10000) * $attempt);
            }
        }
    }

    /**
     * @param array $byHash [hex hash => value]
     * @return array [value => id]
     */
    private function internHashed(array $byHash)
    {
        $ids = [];
        $missing = $this->lookup($byHash, $ids);
        if (empty($missing)) {
            return $ids;
        }
        // The same order in every process makes deadlocks between concurrent inserts rare
        ksort($missing, SORT_STRING);
        foreach ($this->chunks($missing) as $chunk) {
            $this->insertChunk($chunk);
        }
        $missing = $this->lookup($missing, $ids);
        if (!empty($missing) && $this->inTransaction()) {
            // Committed by another session after this transaction's snapshot was taken
            $missing = $this->lookupCurrent($missing, $ids);
        }
        if (!empty($missing)) {
            throw new RuntimeException(sprintf(
                '%d attribute values were neither found nor inserted.',
                count($missing)
            ));
        }
        return $ids;
    }

    /**
     * Ids of every stored variant of each term that the dictionary collation
     * treats as equal.
     *
     * @param array $terms
     * @return array [term => int[]], with an empty list for a term that
     *   matches nothing.
     */
    public function resolveCi(array $terms)
    {
        $result = [];
        foreach ($terms as $term) {
            $result[$this->toValueString($term)] = [];
        }
        $searchable = [];
        foreach (array_keys($result) as $term) {
            $term = (string)$term;
            if (strlen($term) <= self::MAX_BYTES) {
                $searchable[] = $term;
            }
        }
        $db = $this->getDataSource();
        foreach ($this->chunks($searchable) as $chunk) {
            $selects = [];
            foreach ($chunk as $index => $term) {
                $selects[] = sprintf(
                    'SELECT %d AS %s, %s FROM %s WHERE %s',
                    $index,
                    $db->name('term'),
                    $db->name('id'),
                    $this->quotedTable(),
                    $this->ciEquals($term)
                );
            }
            foreach ($this->fetchRows(implode(' UNION ALL ', $selects)) as $row) {
                $result[$searchable[(int)$row['term']]][] = (int)$row['id'];
            }
        }
        return $result;
    }

    /**
     * Ids of the values matching a LIKE pattern in the dictionary collation.
     *
     * @param string $pattern
     * @param int $limit More matches than this is an overflow.
     * @return array ['ids' => int[], 'overflow' => bool]. On overflow the
     *   list is empty, so a caller cannot act on a partial set.
     */
    public function resolveLike($pattern, $limit)
    {
        $limit = (int)$limit;
        if ($limit < 1) {
            throw new InvalidArgumentException('The match limit must be at least 1.');
        }
        $db = $this->getDataSource();
        $sql = sprintf(
            'SELECT %s FROM %s WHERE %s %s %s LIMIT %d',
            $db->name('id'),
            $this->quotedTable(),
            $db->name('value'),
            $this->isMysqlSource() ? 'LIKE' : 'ILIKE',
            $db->value($this->toValueString($pattern), 'string'),
            $limit + 1
        );
        $ids = [];
        foreach ($this->fetchRows($sql) as $row) {
            $ids[] = (int)$row['id'];
        }
        if (count($ids) > $limit) {
            return ['ids' => [], 'overflow' => true];
        }
        sort($ids);
        return ['ids' => $ids, 'overflow' => false];
    }

    /**
     * @param array $ids
     * @return array [id => value] for the ids that exist.
     */
    public function fetchValues(array $ids)
    {
        $wanted = [];
        foreach ($ids as $id) {
            $id = (int)$id;
            if ($id > 0) {
                $wanted[$id] = true;
            }
        }
        $db = $this->getDataSource();
        $values = [];
        foreach (array_chunk(array_keys($wanted), self::CHUNK) as $chunk) {
            $sql = sprintf(
                'SELECT %s, %s FROM %s WHERE %s IN (%s)',
                $db->name('id'),
                $db->name('value'),
                $this->quotedTable(),
                $db->name('id'),
                implode(', ', $chunk)
            );
            foreach ($this->fetchRows($sql) as $row) {
                $values[(int)$row['id']] = (string)$row['value'];
            }
        }
        return $values;
    }

    /**
     * Fill in value, value1 and value2 from the ids, for rows read with
     * callbacks off, then drop the ids.
     *
     * Rows with no value1_id keep whatever value columns they already have,
     * which is the case before the backfill has reached them.
     *
     * @param array $rows Rows as find('all') returns them.
     * @param string $alias The model alias the value columns sit under.
     * @return void
     * @throws RuntimeException When an id is missing from the dictionary.
     */
    public function attachValues(array &$rows, $alias)
    {
        $ids = [];
        foreach ($rows as $row) {
            if (!empty($row[$alias]['value1_id'])) {
                $ids[] = $row[$alias]['value1_id'];
                if (!empty($row[$alias]['value2_id'])) {
                    $ids[] = $row[$alias]['value2_id'];
                }
            }
        }
        $values = empty($ids) ? [] : $this->fetchValues($ids);
        foreach ($rows as &$row) {
            if (!isset($row[$alias]) || !is_array($row[$alias])) {
                continue;
            }
            $data = &$row[$alias];
            if (!empty($data['value1_id'])) {
                $data['value1'] = $this->valueFor($values, $data['value1_id']);
                $data['value2'] = empty($data['value2_id']) ? '' : $this->valueFor($values, $data['value2_id']);
                // 2.x tests value2 = '', which a PAD SPACE collation also holds for spaces
                $data['value'] = rtrim($data['value2'], ' ') === ''
                    ? $data['value1']
                    : $data['value1'] . '|' . $data['value2'];
            }
            unset($data['value1_id'], $data['value2_id']);
            unset($data);
        }
        unset($row);
    }

    /**
     * @param array $values
     * @return array [hex hash => value]
     */
    private function hashValues(array $values)
    {
        $unique = [];
        foreach ($values as $value) {
            $unique[$this->toValueString($value)] = true;
        }
        $byHash = [];
        foreach (array_keys($unique) as $value) {
            $value = (string)$value;
            if (strlen($value) > self::MAX_BYTES) {
                throw new InvalidArgumentException(sprintf(
                    'A value of %d bytes exceeds the %d-byte limit.',
                    strlen($value),
                    self::MAX_BYTES
                ));
            }
            $hash = bin2hex($this->hashOf($value));
            if (isset($byHash[$hash])) {
                throw new RuntimeException('Two different attribute values share a hash.');
            }
            $byHash[$hash] = $value;
        }
        return $byHash;
    }

    /**
     * Select the given hashes, record the ids found and return what is
     * still missing.
     *
     * @param array $byHash [hex hash => value]
     * @param array $ids [value => id], added to.
     * @return array [hex hash => value] not found.
     */
    private function lookup(array $byHash, array &$ids)
    {
        $dialect = $this->getSqlDialect();
        foreach (array_chunk($byHash, self::CHUNK, true) as $chunk) {
            $literals = [];
            foreach (array_keys($chunk) as $hash) {
                $literals[] = $dialect->binaryLiteral(hex2bin($hash));
            }
            $this->collect($this->selectByHash('IN (' . implode(', ', $literals) . ')'), $byHash, $ids);
        }
        return $byHash;
    }

    /**
     * lookup() past a REPEATABLE READ snapshot, as one locking read per
     * value: MariaDB can answer a long IN list on a small table with a full
     * index scan, which as a locking read would lock every row.
     *
     * @param array $byHash [hex hash => value]
     * @param array $ids [value => id], added to.
     * @return array [hex hash => value] not found.
     */
    private function lookupCurrent(array $byHash, array &$ids)
    {
        $dialect = $this->getSqlDialect();
        foreach (array_keys($byHash) as $hash) {
            $sql = $this->selectByHash('= ' . $dialect->binaryLiteral(hex2bin($hash)));
            $this->collect($dialect->currentRead($sql), $byHash, $ids);
        }
        return $byHash;
    }

    /**
     * @param string $condition On the hash column.
     * @return string
     */
    private function selectByHash($condition)
    {
        $db = $this->getDataSource();
        return sprintf(
            'SELECT %s, %s, %s FROM %s WHERE %s %s',
            $db->name('id'),
            $db->name('value'),
            $db->name('hash'),
            $this->quotedTable(),
            $db->name('hash'),
            $condition
        );
    }

    /**
     * Check each row read back against its hash and the input, and record
     * its id.
     *
     * @param string $sql
     * @param array $byHash [hex hash => value], the found ones are removed.
     * @param array $ids [value => id], added to.
     * @return void
     */
    private function collect($sql, array &$byHash, array &$ids)
    {
        foreach ($this->fetchRows($sql) as $row) {
            $value = (string)$row['value'];
            $stored = is_resource($row['hash']) ? stream_get_contents($row['hash']) : (string)$row['hash'];
            if ($this->hashOf($value) !== $stored) {
                throw new RuntimeException(sprintf(
                    'Attribute value %d does not match its stored hash.',
                    $row['id']
                ));
            }
            $hash = bin2hex($stored);
            if (!isset($byHash[$hash]) || $byHash[$hash] !== $value) {
                throw new RuntimeException(sprintf(
                    'Attribute value %d collides with an input value.',
                    $row['id']
                ));
            }
            $ids[$value] = (int)$row['id'];
            unset($byHash[$hash]);
        }
    }

    /**
     * @param array $chunk [hex hash => value]
     * @return void
     */
    private function insertChunk(array $chunk)
    {
        $db = $this->getDataSource();
        $dialect = $this->getSqlDialect();
        $rows = [];
        foreach ($chunk as $hash => $value) {
            $rows[] = sprintf(
                '(%s, %s)',
                $db->value($value, 'string'),
                $dialect->binaryLiteral(hex2bin($hash))
            );
        }
        $insert = sprintf(
            'INSERT INTO %s (%s, %s) VALUES %s',
            $this->quotedTable(),
            $db->name('value'),
            $db->name('hash'),
            implode(', ', $rows)
        );
        $db->rawQuery($dialect->insertIgnore($insert, ['hash']));
    }

    /**
     * Split by row count and by value bytes, keeping the keys.
     *
     * @param array $values
     * @return array[]
     */
    private function chunks(array $values)
    {
        $chunks = [];
        $chunk = [];
        $bytes = 0;
        foreach ($values as $key => $value) {
            $length = strlen($value);
            if (!empty($chunk) && (count($chunk) >= self::CHUNK || $bytes + $length > self::STATEMENT_BYTES)) {
                $chunks[] = $chunk;
                $chunk = [];
                $bytes = 0;
            }
            $chunk[$key] = $value;
            $bytes += $length;
        }
        if (!empty($chunk)) {
            $chunks[] = $chunk;
        }
        return $chunks;
    }

    /**
     * @param string $term
     * @return string
     */
    private function ciEquals($term)
    {
        $db = $this->getDataSource();
        $column = $db->name('value');
        $quoted = $db->value($term, 'string');
        if ($this->isMysqlSource()) {
            return sprintf('%s = %s', $column, $quoted);
        }
        return sprintf(
            'lower(left(%1$s, %3$d)) = lower(left(%2$s, %3$d)) AND lower(%1$s) = lower(%2$s)',
            $column,
            $quoted,
            self::CI_PREFIX
        );
    }

    /**
     * @param array $values [id => value]
     * @param int|string $id
     * @return string
     */
    private function valueFor(array $values, $id)
    {
        if (!isset($values[(int)$id])) {
            throw new RuntimeException(sprintf('Attribute value %d is missing from the dictionary.', $id));
        }
        return $values[(int)$id];
    }

    /**
     * @param mixed $value
     * @return string
     */
    private function toValueString($value)
    {
        if (!is_scalar($value)) {
            throw new InvalidArgumentException('Attribute values must be scalars.');
        }
        return (string)$value;
    }

    /**
     * @return string
     */
    private function quotedTable()
    {
        return $this->getDataSource()->fullTableName($this->useTable, true, false);
    }

    /**
     * @param string $sql
     * @return array
     */
    private function fetchRows($sql)
    {
        $statement = $this->getDataSource()->rawQuery($sql);
        if (!is_object($statement)) {
            return [];
        }
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        $statement->closeCursor();
        return $rows;
    }

    /**
     * @return bool
     */
    protected function inTransaction()
    {
        return $this->getDataSource()->getConnection()->inTransaction();
    }

    /**
     * MySQL reports a deadlock as SQLSTATE 40001, PostgreSQL as 40P01.
     *
     * @param PDOException $e
     * @return bool
     */
    private function isDeadlock(PDOException $e)
    {
        $state = is_array($e->errorInfo) ? $e->errorInfo[0] : $e->getCode();
        return $state === '40001' || $state === '40P01';
    }

    /**
     * @return bool
     */
    private function isMysqlSource()
    {
        return $this->getSqlDialect()->flavour() === SqlDialect::FLAVOUR_MYSQL;
    }
}
