<?php
App::uses('FastLookupConfig', 'Tools');
App::uses('FastLookupValueTool', 'Tools');
App::uses('FastLookupIndexManager', 'Tools');

/** Persistent IOC candidate discovery followed by current SQL authorization. */
class AttributeFastLookupTool
{
    const MAX_VALUE_BYTES = 4096;
    const MAX_REQUEST_BYTES = 16777216;
    const BATCH_SIZE = 100;
    const MAX_ROWS = 100000;

    private $attribute;
    private $db;
    private $manager;
    private $valueTool;

    public function __construct($attribute, $manager = null)
    {
        $this->attribute = $attribute;
        $this->db = $attribute->getDataSource();
        $this->manager = $manager;
    }

    /**
     * @return array Scoped status, with results only for a complete current index.
     * @throws InvalidArgumentException Invalid request or configuration.
     * @throws OverflowException Complete results exceed the bounded row budget.
     */
    public function lookup(array $user, array $request)
    {
        $scope = FastLookupConfig::scope($this->attribute);
        list($originals, $values) = $this->validate($request, $scope['max_values']);
        if ($this->manager === null) {
            $this->manager = new FastLookupIndexManager($this->attribute);
        }
        $snapshot = $this->manager->status();
        $snapshot['scope'] = $scope;
        if (($snapshot['status'] ?? '') !== 'ready') {
            unset($snapshot['results']);
            return $snapshot;
        }
        $this->valueTool = new FastLookupValueTool($this->attribute);
        $acl = $this->db->conditions($this->attribute->buildConditions($user), true, false, $this->attribute);
        $rowCount = 0;
        $matches = [];
        foreach (array_chunk($values, self::BATCH_SIZE, true) as $batch) {
            if ($rowCount === self::MAX_ROWS) {
                throw new OverflowException('The IOC lookup exceeds the 100000-row resource limit; submit fewer values.');
            }
            $tokens = $this->valueTool->queryTokens($batch, $scope['attribute_types']);
            $fallback = $this->valueTool->exactFallbackComponents();
            $candidates = $this->manager->index()->candidates($snapshot['generation'], $tokens, self::MAX_ROWS - $rowCount);
            $this->validateCandidates($candidates, $batch, $rowCount);
            $from = $this->fromClause();
            $common = $this->commonConditions($scope, $acl);
            $branches = [];
            foreach ($batch as $index => $value) {
                foreach (['value1', 'value2'] as $component) {
                    if (!$this->valueTool->representable($value, $component)) {
                        continue;
                    }
                    $restriction = '';
                    if (empty($fallback[$index][$component])) {
                        $ids = $candidates[$index]['exact'] ?? [];
                        if (!$ids) {
                            continue;
                        }
                        $restriction = ' AND ' . $this->db->name('Attribute.id') . ' IN (' . implode(',', $ids) . ')';
                    }
                    $branches[] = 'SELECT ' . (int)$index . ' AS ' . $this->db->name('input_index')
                        . ', ' . $this->db->name('Attribute.event_id') . ' AS ' . $this->db->name('event_id')
                        . ' FROM ' . $from . ' WHERE ' . $this->db->name('Attribute.' . $component)
                        . ' = ' . $this->db->value($value, 'string') . $common . $restriction;
                }
            }
            foreach ($this->query($branches, $rowCount) as $row) {
                $matches[(int)$row['input_index']]['events'][(string)$row['event_id']] = true;
            }

            // Fetch each expanded candidate once; ACLs, type, publication and
            // deletion are checked before any current component leaves SQL.
            $expanded = [];
            foreach ($candidates as $index => $groups) {
                foreach (['ip_range', 'domain'] as $kind) {
                    foreach ($groups[$kind] ?? [] as $id) {
                        $expanded[$id][$index][$kind] = true;
                    }
                }
            }
            foreach (array_chunk(array_keys($expanded), 1000) as $ids) {
                $fields = [];
                foreach (['id', 'event_id', 'type', 'value1', 'value2'] as $field) {
                    $fields[] = $this->db->name('Attribute.' . $field) . ' AS ' . $this->db->name($field);
                }
                $sql = 'SELECT ' . implode(', ', $fields) . ' FROM ' . $from
                    . ' WHERE ' . $this->db->name('Attribute.id') . ' IN (' . implode(',', $ids) . ')' . $common;
                foreach ($this->query([$sql], $rowCount) as $row) {
                    foreach ($expanded[$row['id']] ?? [] as $index => $kinds) {
                        $live = $this->valueTool->expandedMatches($batch[$index], $row);
                        foreach (['ip_range' => 'ip_ranges', 'domain' => 'domains'] as $kind => $group) {
                            if (!isset($kinds[$kind])) {
                                continue;
                            }
                            foreach ($live[$group] as $storedValue) {
                                $matches[$index]['events'][(string)$row['event_id']] = true;
                                $matches[$index][$group][$storedValue][(string)$row['event_id']] = true;
                            }
                        }
                    }
                }
            }
        }
        if (!$this->manager->isCurrent($snapshot)) {
            $status = $this->manager->status();
            $status['scope'] = $scope;
            if (($status['status'] ?? '') === 'ready') {
                $status['status'] = 'updating';
            }
            $status['message'] = 'The IOC index changed during this lookup; retry after it is ready.';
            unset($status['results']);
            return $status;
        }
        $results = new stdClass();
        foreach ($originals as $index => $original) {
            if (empty($matches[$index]['events'])) {
                continue;
            }
            $entry = ['event_ids' => self::sortedIds($matches[$index]['events'])];
            foreach (['ip_ranges', 'domains'] as $group) {
                $entry[$group] = new stdClass();
                $groups = $matches[$index][$group] ?? [];
                ksort($groups, SORT_STRING);
                foreach ($groups as $storedValue => $events) {
                    $entry[$group]->{(string)$storedValue} = self::sortedIds($events);
                }
            }
            $results->{$original} = $entry;
        }
        return ['status' => 'ready', 'scope' => $scope, 'results' => $results];
    }

    private function validate(array $request, $maximum)
    {
        if (array_diff(array_keys($request), ['value'])) {
            throw new InvalidArgumentException('Only value is supported; maxAge is no longer available.');
        }
        if (!isset($request['value']) || !is_array($request['value'])
            || array_values($request['value']) !== $request['value'] || count($request['value']) > $maximum) {
            throw new InvalidArgumentException("value must be a list of at most $maximum IOC strings.");
        }
        $bytes = 0;
        $originals = [];
        $values = [];
        $seen = [];
        foreach ($request['value'] as $value) {
            if (!is_string($value) || $value === '' || strlen($value) > self::MAX_VALUE_BYTES
                || strpos($value, "\0") !== false || preg_match('//u', $value) !== 1) {
                throw new InvalidArgumentException('Each IOC must be a nonempty UTF-8 string of at most 4096 bytes, without NUL characters.');
            }
            $bytes += strlen($value);
            if ($bytes > self::MAX_REQUEST_BYTES) {
                throw new InvalidArgumentException('The combined IOC size must not exceed 16 MiB.');
            }
            if (isset($seen[$value])) {
                continue;
            }
            $seen[$value] = true;
            $originals[] = $value;
            $values[] = filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? inet_ntop(inet_pton($value)) : $value;
        }
        return [$originals, $values];
    }

    private function fromClause()
    {
        $db = $this->db;
        return $db->fullTableName($this->attribute) . ' ' . $db->name('Attribute')
            . ' INNER JOIN ' . $db->fullTableName($this->attribute->Event) . ' ' . $db->name('Event')
            . ' ON ' . $db->name('Event.id') . ' = ' . $db->name('Attribute.event_id')
            . ' LEFT JOIN ' . $db->fullTableName($this->attribute->Object) . ' ' . $db->name('Object')
            . ' ON ' . $db->name('Object.id') . ' = ' . $db->name('Attribute.object_id');
    }

    private function commonConditions(array $scope, $acl)
    {
        $types = array_map(function ($type) { return $this->db->value($type, 'string'); }, $scope['attribute_types']);
        return ' AND ' . $this->db->name('Attribute.deleted') . ' = 0 AND (' . ($acl ?: '1=1') . ')'
            . ' AND ' . $this->db->name('Attribute.type') . ' IN (' . implode(',', $types) . ')'
            . ($scope['published_only'] ? ' AND ' . $this->db->name('Event.published') . ' = 1' : '');
    }

    private function validateCandidates(array $candidates, array $batch, &$rowCount)
    {
        foreach ($candidates as $index => $groups) {
            if (!array_key_exists($index, $batch) || !is_array($groups)) {
                throw new RuntimeException('Invalid IOC index candidate response.');
            }
            foreach (['exact', 'ip_range', 'domain'] as $kind) {
                $ids = $groups[$kind] ?? [];
                if (!is_array($ids)) {
                    throw new RuntimeException('Invalid IOC index candidate IDs.');
                }
                $this->consumeRows(count($ids), $rowCount);
                foreach ($ids as $id) {
                    if ((!is_string($id) && !is_int($id)) || !preg_match('/^[1-9][0-9]{0,18}$/D', (string)$id)) {
                        throw new RuntimeException('Invalid IOC index candidate ID.');
                    }
                }
            }
        }
    }

    private function query(array $branches, &$rowCount)
    {
        if (!$branches) {
            return [];
        }
        $sql = implode(' UNION ', $branches) . ' LIMIT ' . (self::MAX_ROWS - $rowCount + 1);
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

    private static function sortedIds(array $events)
    {
        $ids = array_map('strval', array_keys($events));
        usort($ids, function ($left, $right) { return strlen($left) <=> strlen($right) ?: strcmp($left, $right); });
        return $ids;
    }
}
