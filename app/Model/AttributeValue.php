<?php
App::uses('AppModel', 'Model');
App::uses('ValueFieldTranslator', 'Tools');
App::uses('ValueConditionRewriter', 'Tools');

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

    // The hash column holds this many leading bytes of SHA-256
    const HASH_BYTES = 16;

    const TEXT_OF_ID = ['value1_id' => 'value1', 'value2_id' => 'value2'];

    public $useTable = 'attribute_values';

    public $recursive = -1;

    /**
     * Whether a value condition that cannot be moved to the ids throws,
     * rather than being logged and left on the text columns. Tests switch
     * it on.
     *
     * @var bool
     */
    public static $strictConditions = false;

    /** @var array [value => id] from prime(), read by assignIds() */
    private $primed = [];

    /**
     * @param string $value
     * @return string 16 raw bytes
     */
    public function hashOf($value)
    {
        return substr(hash('sha256', $value, true), 0, self::HASH_BYTES);
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
        $sql = sprintf('%s LIMIT %d', $this->likeSelect($pattern), $limit + 1);
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
     * A condition on an id column for the values matching a LIKE pattern,
     * with the dictionary read inside the statement rather than ahead of it.
     *
     * @param string $field Alias-qualified id column, e.g. Attribute.value1_id
     * @param string $pattern
     * @param bool $not
     * @return stdClass A Cake expression, for a numeric key in conditions.
     */
    public function likeCondition($field, $pattern, $not = false)
    {
        $db = $this->getDataSource();
        return $db->expression(sprintf(
            '%s %s (%s)',
            $db->name($field),
            $not ? 'NOT IN' : 'IN',
            $this->likeSelect($pattern)
        ));
    }

    /**
     * Whether the empty string, which a NULL value2_id stands for, equals each
     * term (or matches each LIKE pattern) in the dictionary collation.
     *
     * @param array $terms
     * @param bool $like
     * @return array [term => bool]
     */
    public function matchesEmpty(array $terms, $like = false)
    {
        $result = [];
        $ask = [];
        foreach ($terms as $term) {
            $term = $this->toValueString($term);
            $known = $this->emptyMatchKnown($term, $like);
            if ($known === null) {
                $ask[$term] = true;
            }
            $result[$term] = $known === true;
        }
        if (empty($ask)) {
            return $result;
        }
        $db = $this->getDataSource();
        $collation = $this->valueCollation();
        if (!preg_match('/^([a-z0-9]+)_\w+$/i', $collation, $match)) {
            throw new RuntimeException(sprintf('Unexpected collation "%s" on the attribute value column.', $collation));
        }
        $ask = array_map('strval', array_keys($ask));
        $selects = [];
        foreach ($ask as $index => $term) {
            $selects[] = sprintf(
                "SELECT %d AS %s FROM DUAL WHERE _%s'' COLLATE %s %s %s",
                $index,
                $db->name('term'),
                $match[1],
                $collation,
                $like ? 'LIKE' : '=',
                $db->value($term, 'string')
            );
        }
        foreach ($this->fetchRows(implode(' UNION ALL ', $selects)) as $row) {
            $result[$ask[(int)$row['term']]] = true;
        }
        return $result;
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
     * Readies an attribute or proposal find for the dictionary: a field list
     * that names the value field reads the ids instead, and an order on it
     * sorts by the dictionary text. Only for finds whose afterFind runs,
     * since that is what fills the text in.
     *
     * @param array $query A find query, as beforeFind receives it.
     * @param string $alias
     * @return array
     */
    public function prepareFind(array $query, $alias)
    {
        if (!isset($query['callbacks']) || $query['callbacks'] !== true) {
            return $query;
        }
        $translator = new ValueFieldTranslator($this->getDataSource(), $alias, $this->useTable);
        $query = $translator->translate($query);
        if ($translator->keys() !== null) {
            $this->askValueKeys($translator->keys());
        }
        return $query;
    }

    /**
     * Conditions on the value columns of an attribute or proposal alias,
     * moved to the ids. No afterFind is needed for that, so it suits finds
     * with callbacks 'before' and subqueries too.
     *
     * @param mixed $conditions
     * @param string $alias
     * @return mixed
     * @throws ValueConditionException With strict conditions on.
     */
    public function rewriteConditions($conditions, $alias)
    {
        $rewriter = new ValueConditionRewriter($this, $alias, ['strict' => self::$strictConditions]);
        return $rewriter->rewrite($conditions);
    }

    /**
     * Fill in value, value1 and value2 from the ids, then drop the ids.
     *
     * Rows with no value1_id keep whatever value columns they already have,
     * which is the case before the backfill has reached them.
     *
     * @param array $rows Rows as find('all') returns them.
     * @param string $alias The model alias the value columns sit under.
     * @param string[]|null $keys The value keys to add, null for all three.
     *   A value key the row already holds is always filled.
     * @return void
     * @throws RuntimeException When an id is missing from the dictionary.
     */
    public function attachValues(array &$rows, $alias, array $keys = null)
    {
        $ids = [];
        foreach ($rows as $row) {
            if (isset($row[$alias]) && is_array($row[$alias])) {
                $this->rowIds($row[$alias], $ids);
            }
        }
        $values = empty($ids) ? [] : $this->fetchValues(array_keys($ids));
        foreach ($rows as &$row) {
            if (isset($row[$alias]) && is_array($row[$alias])) {
                $this->fillRow($row[$alias], $values, $keys);
            }
        }
        unset($row);
    }

    /**
     * Value text for the rows an afterFind receives; the ids never leave the
     * instance. Cake filters association rows one at a time, so those keep
     * their ids until the find that read them returns (AppModel::find).
     *
     * @param array $results
     * @param string $alias
     * @param bool $primary
     * @return void
     */
    public function attachFound(array &$results, $alias, $primary)
    {
        if ($primary) {
            $this->attachValues($results, $alias, $this->findValueKeys());
        } else if ($this->holdsIdKeys($results) && !$this->deferRows()) {
            $this->attachNested($results);
        }
    }

    /**
     * @param array $node
     * @return bool
     */
    private function holdsIdKeys(array $node)
    {
        if (array_key_exists('value1_id', $node) || array_key_exists('value2_id', $node)) {
            return true;
        }
        foreach ($node as $child) {
            if (is_array($child) && $this->holdsIdKeys($child)) {
                return true;
            }
        }
        return false;
    }

    /**
     * attachValues() for every attribute or proposal row anywhere in $data,
     * whatever the nesting: any array that holds value1_id or value2_id.
     *
     * @param mixed $data
     * @param string[]|null $keys See attachValues().
     * @return void
     * @throws RuntimeException When an id is missing from the dictionary.
     */
    public function attachNested(&$data, array $keys = null)
    {
        if (!is_array($data)) {
            return;
        }
        $ids = [];
        $this->nestedIds($data, $ids);
        $values = empty($ids) ? [] : $this->fetchValues(array_keys($ids));
        $this->fillNested($data, $values, $keys);
    }

    /**
     * @param array $node
     * @param array $ids [id => true]
     * @return void
     */
    private function nestedIds(array $node, array &$ids)
    {
        $this->rowIds($node, $ids);
        foreach ($node as $child) {
            if (is_array($child)) {
                $this->nestedIds($child, $ids);
            }
        }
    }

    /**
     * @param array $node
     * @param array $values [id => value]
     * @param string[]|null $keys
     * @return void
     */
    private function fillNested(array &$node, array $values, $keys)
    {
        $this->fillRow($node, $values, $keys);
        // Not foreach over $node: writing to it mid-loop would copy each child
        foreach (array_keys($node) as $key) {
            if (is_array($node[$key])) {
                $this->fillNested($node[$key], $values, $keys);
            }
        }
    }

    /**
     * @param array $row
     * @param array $ids [id => true]
     * @return void
     */
    private function rowIds(array $row, array &$ids)
    {
        if (!empty($row['value1_id'])) {
            $ids[(int)$row['value1_id']] = true;
            if (!empty($row['value2_id'])) {
                $ids[(int)$row['value2_id']] = true;
            }
        }
    }

    /**
     * @param array $row
     * @param array $values [id => value]
     * @param string[]|null $keys
     * @return void
     */
    private function fillRow(array &$row, array $values, $keys)
    {
        if (!array_key_exists('value1_id', $row) && !array_key_exists('value2_id', $row)) {
            return;
        }
        if (!empty($row['value1_id'])) {
            $value1 = $this->valueFor($values, $row['value1_id']);
            $value2 = empty($row['value2_id']) ? '' : $this->valueFor($values, $row['value2_id']);
            $text = [
                'value1' => $value1,
                'value2' => $value2,
                // 2.x tests value2 = '', which a PAD SPACE collation also holds for spaces
                'value' => rtrim($value2, ' ') === '' ? $value1 : $value1 . '|' . $value2,
            ];
            if ($keys !== null) {
                $text = array_intersect_key($text, array_flip($keys) + $row);
            }
            if (!array_key_exists('value1', $row)) {
                // Without the text columns, the text goes where 2.x had them
                $filled = [];
                foreach ($row as $key => $field) {
                    if (!isset(self::TEXT_OF_ID[$key])) {
                        $filled[$key] = $field;
                    } else if (isset($text[self::TEXT_OF_ID[$key]])) {
                        $filled[self::TEXT_OF_ID[$key]] = $text[self::TEXT_OF_ID[$key]];
                    }
                }
                $row = $filled;
            }
            foreach ($text as $key => $value) {
                if (array_key_exists($key, $row)) {
                    $row[$key] = $value;
                } else {
                    $this->addColumn($row, $key, $value);
                }
            }
        }
        unset($row['value1_id'], $row['value2_id']);
    }

    /**
     * Adds a key where Cake put a virtual field: after the row's columns,
     * before any association row nested in it.
     *
     * @param array $row
     * @param string $key
     * @param string $value
     * @return void
     */
    private function addColumn(array &$row, $key, $value)
    {
        $position = 0;
        foreach ($row as $field) {
            if (is_array($field)) {
                $row = array_slice($row, 0, $position, true) + [$key => $value] + array_slice($row, $position, null, true);
                return;
            }
            $position++;
        }
        $row[$key] = $value;
    }

    /**
     * Point value1_id and value2_id at the dictionary rows of the value
     * columns a save writes. Ids the caller sent are always dropped.
     *
     * An empty value2 has no row, by byte length: a value2 of spaces gets
     * one. A value column the save does not write leaves its id alone.
     *
     * @param array $row The row being saved, after the composite split.
     * @param array $fields The save's field list, empty when it writes every
     *   column.
     * @return void
     */
    public function assignIds(array &$row, array $fields = [])
    {
        unset($row['value1_id'], $row['value2_id']);
        $parts = [];
        foreach (['value1', 'value2'] as $column) {
            if (array_key_exists($column, $row) && (empty($fields) || in_array($column, $fields, true))) {
                $parts[$column] = $row[$column] === null ? '' : $this->toValueString($row[$column]);
            }
        }
        $wanted = [];
        foreach ($parts as $column => $value) {
            if ($column === 'value1' || $value !== '') {
                $wanted[] = $value;
            }
        }
        $ids = [];
        $missing = [];
        foreach ($wanted as $value) {
            if (isset($this->primed[$value])) {
                $ids[$value] = $this->primed[$value];
            } else {
                $missing[] = $value;
            }
        }
        if (!empty($missing)) {
            $ids += $this->internMany($missing);
        }
        foreach ($parts as $column => $value) {
            $row[$column . '_id'] = $column === 'value2' && $value === '' ? null : $ids[$value];
        }
    }

    /**
     * Interns the values a run of saves will write before the saves and any
     * transaction around them, so each save finds its ids without a query.
     * Inside a transaction it only looks them up: the map never holds an id
     * that a rollback could take back.
     *
     * Values already primed cost nothing. A value the dictionary cannot hold
     * is left to the save that refuses it.
     *
     * @param array $values
     * @return array The map before this call, for release().
     */
    public function prime(array $values)
    {
        $previous = $this->primed;
        $wanted = [];
        foreach ($values as $value) {
            $value = $this->toValueString($value);
            if (!isset($this->primed[$value]) && strlen($value) <= self::MAX_BYTES) {
                $wanted[] = $value;
            }
        }
        if (empty($wanted)) {
            return $previous;
        }
        if ($this->inTransaction()) {
            $ids = [];
            $this->lookup($this->hashValues($wanted), $ids);
        } else {
            $ids = $this->internMany($wanted);
        }
        $this->primed = $ids + $this->primed;
        return $previous;
    }

    /**
     * @param array $previous What prime() returned.
     * @return void
     */
    public function release(array $previous)
    {
        $this->primed = $previous;
    }

    /**
     * The ids of the values the dictionary already holds, adding none.
     *
     * @param array $values
     * @return array [value => id], without the values it does not hold.
     */
    public function idsOf(array $values)
    {
        $ids = [];
        $wanted = [];
        foreach ($values as $value) {
            $value = $this->toValueString($value);
            if (isset($this->primed[$value])) {
                $ids[$value] = $this->primed[$value];
            } else if (strlen($value) <= self::MAX_BYTES) {
                $wanted[] = $value;
            }
        }
        if (!empty($wanted)) {
            $this->lookup($this->hashValues($wanted), $ids);
        }
        return $ids;
    }

    /**
     * A save's field list with the id of every value column it writes, so
     * the ids assignIds() set are not dropped. An empty list stays empty.
     *
     * @param array $fields
     * @return array
     */
    public function withIdFields(array $fields)
    {
        foreach (['value1', 'value2'] as $column) {
            if (in_array($column, $fields, true) && !in_array($column . '_id', $fields, true)) {
                $fields[] = $column . '_id';
            }
        }
        return $fields;
    }

    /**
     * A schema with a text column for each value column whose id it holds,
     * so that loggers keep recording the text once the text columns are gone.
     *
     * @param array $schema As Model::schema() returns it.
     * @return array
     */
    public static function withValueColumns(array $schema)
    {
        foreach (['value1', 'value2'] as $column) {
            if (!isset($schema[$column]) && isset($schema[$column . '_id'])) {
                $schema[$column] = ['type' => 'text', 'null' => false];
            }
        }
        return $schema;
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
     * @param string $pattern
     * @return string
     */
    private function likeSelect($pattern)
    {
        $db = $this->getDataSource();
        return sprintf(
            'SELECT %s FROM %s WHERE %s %s %s',
            $db->name('id'),
            $this->quotedTable(),
            $db->name('value'),
            $this->isMysqlSource() ? 'LIKE' : 'ILIKE',
            $db->value($this->toValueString($pattern), 'string')
        );
    }

    /**
     * Decides without the database where it can. Letters and digits are never
     * ignorable, and PostgreSQL compares lower() of both sides, so only a term
     * made of other characters on MySQL is left to the collation.
     *
     * @param string $term
     * @param bool $like
     * @return bool|null
     */
    private function emptyMatchKnown($term, $like)
    {
        if ($like ? preg_match('/^%*$/', $term) : $term === '') {
            return true;
        }
        if (preg_match($like ? '/[A-Za-z0-9_]/' : '/[A-Za-z0-9]/', $term)) {
            return false;
        }
        return $this->isMysqlSource() ? null : false;
    }

    /**
     * @return string
     */
    protected function valueCollation()
    {
        $schema = $this->schema();
        return isset($schema['value']['collate']) ? $schema['value']['collate'] : '';
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
     * @return bool False when no find is in progress to hand the rows to.
     */
    protected function deferRows()
    {
        return AppModel::deferValueRows();
    }

    /**
     * @return string[]|null
     */
    protected function findValueKeys()
    {
        return AppModel::primaryValueKeys();
    }

    /**
     * @param string[] $keys
     * @return void
     */
    protected function askValueKeys(array $keys)
    {
        AppModel::setPrimaryValueKeys($keys);
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
