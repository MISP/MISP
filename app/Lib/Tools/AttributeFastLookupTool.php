<?php

App::uses('FastLookupCache', 'Tools');

/**
 * Literal IOC lookup. Redis holds complete global candidate sets; SQL alone
 * decides which current event IDs the requesting user may receive.
 */
class AttributeFastLookupTool
{
    const MAX_VALUES = 1000;
    const MAX_VALUE_BYTES = 4096;
    const MAX_REQUEST_BYTES = 1048576;
    const BATCH_SIZE = 100;
    const MAX_ROWS = 100000;

    private $attribute;
    private $db;
    private $cache;
    private $columnSchemas;

    public function __construct($attribute, $cache = null)
    {
        $this->attribute = $attribute;
        $this->db = $attribute->getDataSource();
        $this->cache = $cache;
    }

    /**
     * @return stdClass Original IOC => numerically sorted decimal event IDs.
     * @throws InvalidArgumentException Invalid request.
     * @throws OverflowException The complete result exceeds the resource cap.
     */
    public function lookup(array $user, array $request)
    {
        list($originals, $values, $maxAge) = $this->validate($request);
        $result = new stdClass();
        if (!$values) {
            return $result;
        }

        $acl = $this->db->conditions(
            $this->attribute->buildConditions($user), true, false, $this->attribute
        );
        $rowCount = 0;
        $events = [];
        $cacheCandidates = [];
        // Age starts before discovery, including any time spent reading Redis.
        $queriedAt = microtime(true);
        foreach (array_chunk($values, self::BATCH_SIZE, true) as $batch) {
            if ($maxAge === 0) {
                $rows = $this->query($this->branches($batch, $acl), $rowCount);
            } else {
                $candidates = $this->cache()->getMany($batch, $maxAge);
                foreach ($candidates as $ids) {
                    $this->consumeRows(count($ids), $rowCount);
                }
                $missing = array_diff_key($batch, $candidates);
                if ($missing) {
                    $discovered = array_fill_keys(array_keys($missing), []);
                    foreach ($this->query($this->branches($missing), $rowCount) as $row) {
                        $discovered[(int)$row['input_index']][] = (string)$row['attribute_id'];
                    }
                    $candidates += $discovered;
                    $cacheCandidates += $discovered;
                }
                $rows = $this->query($this->branches($batch, $acl, $candidates), $rowCount);
            }
            foreach ($rows as $row) {
                $events[(int)$row['input_index']][(string)$row['event_id']] = true;
            }
        }

        foreach ($originals as $index => $original) {
            if (empty($events[$index])) {
                continue;
            }
            // PHP converts numeric array keys to integers; the wire contract
            // deliberately uses decimal strings for every event ID.
            $ids = array_map('strval', array_keys($events[$index]));
            usort($ids, function ($left, $right) {
                return strlen($left) <=> strlen($right) ?: strcmp($left, $right);
            });
            $result->{$original} = $ids;
        }
        // Never publish a partial candidate set from an aborted request.
        if ($maxAge !== 0 && $cacheCandidates) {
            $this->cache()->storeMany($values, $cacheCandidates, $queriedAt);
        }
        return $result;
    }

    private function validate(array $request)
    {
        if (array_diff(array_keys($request), ['value', 'maxAge'])) {
            throw new InvalidArgumentException('Only value and maxAge are supported.');
        }
        if (!isset($request['value']) || !is_array($request['value'])
            || array_values($request['value']) !== $request['value']
            || count($request['value']) > self::MAX_VALUES
        ) {
            throw new InvalidArgumentException('value must be a list of at most 1000 IOC strings.');
        }
        $configuredTtl = FastLookupCache::configuredTtl();
        $maxAge = array_key_exists('maxAge', $request) ? $request['maxAge'] : $configuredTtl;
        if (!is_int($maxAge) || $maxAge < 0 || $maxAge > $configuredTtl) {
            throw new InvalidArgumentException("maxAge must be an integer between 0 and $configuredTtl.");
        }
        $bytes = 0;
        $originals = [];
        $values = [];
        $seen = [];
        foreach ($request['value'] as $value) {
            if (!is_string($value) || $value === '' || strlen($value) > self::MAX_VALUE_BYTES
                || strpos($value, "\0") !== false || preg_match('//u', $value) !== 1
            ) {
                throw new InvalidArgumentException('Each IOC must be a nonempty UTF-8 string of at most 4096 bytes, without NUL characters.');
            }
            $bytes += strlen($value);
            if ($bytes > self::MAX_REQUEST_BYTES) {
                throw new InvalidArgumentException('The combined IOC size must not exceed 1 MiB.');
            }
            if (isset($seen[$value])) {
                continue;
            }
            $seen[$value] = true;
            $originals[] = $value;
            $values[] = filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)
                ? inet_ntop(inet_pton($value)) : $value;
        }
        return [$originals, $values, $maxAge];
    }

    /**
     * One exact indexed branch per component and original input ordinal lets
     * the database preserve its own collation semantics without PHP rematching.
     * A null ACL means global candidate discovery, including private/deleted rows.
     */
    private function branches(array $values, $acl = null, $candidates = null)
    {
        $db = $this->db;
        $from = $db->fullTableName($this->attribute) . ' ' . $db->name('Attribute');
        $field = 'Attribute.id';
        $fieldAlias = 'attribute_id';
        $common = '';
        if ($acl !== null) {
            $from .= ' INNER JOIN ' . $db->fullTableName($this->attribute->Event)
                . ' ' . $db->name('Event') . ' ON ' . $db->name('Event.id')
                . ' = ' . $db->name('Attribute.event_id');
            $from .= ' LEFT JOIN ' . $db->fullTableName($this->attribute->Object)
                . ' ' . $db->name('Object') . ' ON ' . $db->name('Object.id')
                . ' = ' . $db->name('Attribute.object_id');
            $field = 'Attribute.event_id';
            $fieldAlias = 'event_id';
            $common = ' AND ' . $db->name('Attribute.deleted') . ' = 0 AND (' . $acl . ')';
        }
        $branches = [];
        foreach ($values as $index => $value) {
            $restriction = '';
            if ($candidates !== null) {
                if (empty($candidates[$index])) {
                    continue;
                }
                // IDs originate only from SQL or the strictly validated cache.
                $restriction = ' AND ' . $db->name('Attribute.id')
                    . ' IN (' . implode(',', $candidates[$index]) . ')';
            }
            $literal = $db->value($value, 'string');
            $hasFourByteUtf8 = preg_match('/[\xF0-\xF4]/', $value) === 1;
            foreach (['value1', 'value2'] as $component) {
                if ($hasFourByteUtf8 && $this->isThreeByteUtf8($component)) {
                    // MySQL cannot compare an utf8mb4 literal with an utf8mb3
                    // column when the literal is unrepresentable there. Such a
                    // column cannot contain an exact match; do not substitute
                    // replacement characters or convert the indexed column.
                    continue;
                }
                $branches[] = 'SELECT ' . (int)$index . ' AS ' . $db->name('input_index')
                    . ', ' . $db->name($field) . ' AS ' . $db->name($fieldAlias)
                    . ' FROM ' . $from . ' WHERE ' . $db->name('Attribute.' . $component)
                    . ' = ' . $literal . $common . $restriction;
            }
        }
        return $branches;
    }

    private function columnSchemas()
    {
        if ($this->columnSchemas === null) {
            $this->columnSchemas = [];
            foreach (['value1', 'value2'] as $component) {
                $schema = $this->attribute->schema($component);
                $this->columnSchemas[$component] = [
                    'charset' => strtolower($schema['charset'] ?? ''),
                    'collate' => strtolower($schema['collate'] ?? ''),
                ];
            }
        }
        return $this->columnSchemas;
    }

    private function isThreeByteUtf8($component)
    {
        $schema = $this->columnSchemas()[$component];
        return in_array($schema['charset'], ['utf8', 'utf8mb3'], true)
            || preg_match('/^utf8(?:mb3)?_/', $schema['collate']) === 1;
    }

    /** Fetch one sentinel beyond the remaining budget; never silently truncate. */
    private function query(array $branches, &$rowCount)
    {
        if (!$branches) {
            return [];
        }
        $sql = implode(' UNION ', $branches) . ' LIMIT ' . (self::MAX_ROWS - $rowCount + 1);
        // rawQuery bypasses Cake's per-request result cache and PDO keeps the
        // deliberately tiny projection flat on both MySQL and PostgreSQL.
        $statement = $this->db->rawQuery($sql);
        if (!is_object($statement)) {
            throw new RuntimeException('Could not execute the IOC lookup query.');
        }
        $rows = [];
        try {
            while (($row = $statement->fetch(PDO::FETCH_ASSOC)) !== false) {
                $this->consumeRows(1, $rowCount);
                $rows[] = $row;
            }
        } finally {
            $statement->closeCursor();
        }
        return $rows;
    }

    private function consumeRows($count, &$rowCount)
    {
        $rowCount += $count;
        if ($rowCount > self::MAX_ROWS) {
            throw new OverflowException('The IOC lookup exceeds the 100000-row resource limit; submit fewer values.');
        }
    }

    private function cache()
    {
        if ($this->cache === null) {
            // Select only connection identity fields; never include credentials.
            $identity = array_intersect_key($this->db->config, array_flip([
                'datasource', 'host', 'port', 'database', 'schema', 'prefix', 'unix_socket',
            ]));
            $identity['table'] = $this->db->fullTableName($this->attribute);
            $identity['value_columns'] = $this->columnSchemas();
            ksort($identity);
            $this->cache = new FastLookupCache(json_encode($identity));
        }
        return $this->cache;
    }
}
