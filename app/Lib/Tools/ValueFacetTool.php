<?php
App::uses('SqlDialect', 'Migration');

/**
 * The IP facet of the value dictionary: one value_ip_ranges row per value
 * that parses as an IPv4 or IPv6 address or CIDR, whatever the type of the
 * attributes holding it.
 *
 * Facet rows are derived only. They are never turned back into text (MariaDB
 * and PHP format IPv6 differently) and can be rebuilt at any time.
 */
class ValueFacetTool
{
    // Dictionary ids per rebuild window
    const CHUNK = 10000;

    const INSERT_ROWS = 1000;

    // The longest address text (45 characters) with a mask of three digits
    const MAX_TEXT = 49;

    const TABLE = 'value_ip_ranges';

    // Addresses per containing() statement
    const PROBE_ADDRESSES = 500;

    // IPv4 is stored in the v4-mapped block, ::ffff:0:0/96
    const V4_FIRST = "\0\0\0\0\0\0\0\0\0\0\xff\xff\0\0\0\0";
    const V4_LAST = "\0\0\0\0\0\0\0\0\0\0\xff\xff\xff\xff\xff\xff";
    const BEFORE_V4 = "\0\0\0\0\0\0\0\0\0\0\xff\xfe\xff\xff\xff\xff";
    const AFTER_V4 = "\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0";

    /** @var AttributeValue */
    private $AttributeValue;

    /** @var DboSource */
    private $db;

    /** @var SqlDialect */
    private $dialect;

    /**
     * @param AttributeValue $AttributeValue Its table is the dictionary.
     */
    public function __construct(AttributeValue $AttributeValue)
    {
        $this->AttributeValue = $AttributeValue;
        $this->db = $AttributeValue->getDataSource();
        $this->dialect = $AttributeValue->getSqlDialect();
    }

    /**
     * The range an address or CIDR covers, in one 16-byte ordering: IPv4 is
     * v4-mapped (::ffff:a.b.c.d), so an IPv4 mask n becomes 96 + n and a
     * single address of either family has prefix 128. Host bits under the
     * mask are ignored, as 2.x CIDR correlation ignores them.
     *
     * @param string $value
     * @return array|null [start, end, prefix] with 16-byte ends, or null when
     *   the value is not an address or CIDR.
     */
    public static function ipRange($value)
    {
        $value = (string)$value;
        if ($value === '' || strlen($value) > self::MAX_TEXT) {
            return null;
        }
        $mask = null;
        $slash = strpos($value, '/');
        if ($slash !== false) {
            $mask = substr($value, $slash + 1);
            $value = substr($value, 0, $slash);
            if (!ctype_digit($mask)) {
                return null;
            }
            $mask = (int)$mask;
        }
        if (filter_var($value, FILTER_VALIDATE_IP) === false) {
            return null;
        }
        $bytes = inet_pton($value);
        if ($bytes === false) {
            return null;
        }
        $offset = 0;
        if (strlen($bytes) === 4) {
            $bytes = str_repeat("\0", 10) . "\xff\xff" . $bytes;
            $offset = 96;
        }
        if ($mask !== null && $mask > 128 - $offset) {
            return null;
        }
        $prefix = $mask === null ? 128 : $offset + $mask;
        $start = $end = '';
        for ($i = 0; $i < 16; $i++) {
            $bits = max(0, min(8, $prefix - 8 * $i));
            $keep = (0xff << (8 - $bits)) & 0xff;
            $byte = ord($bytes[$i]) & $keep;
            $start .= chr($byte);
            $end .= chr($byte | (~$keep & 0xff));
        }
        return [$start, $end, $prefix];
    }

    /**
     * The starts a range holding the address can have: the address under
     * each mask. An IPv4 address is held only by IPv4 ranges, never by an
     * IPv6 range wider than the v4-mapped block.
     *
     * @param string $address 16 bytes
     * @return string[]
     */
    public static function containingStarts($address)
    {
        $starts = [];
        for ($prefix = self::isIpv4($address) ? 96 : 0; $prefix <= 128; $prefix++) {
            $full = intdiv($prefix, 8);
            if ($full === 16) {
                $starts[] = $address;
                continue;
            }
            $keep = (0xff << (8 - $prefix % 8)) & 0xff;
            $starts[] = substr($address, 0, $full) . chr(ord($address[$full]) & $keep) . str_repeat("\0", 15 - $full);
        }
        return array_values(array_unique($starts));
    }

    /**
     * The spans of a range that can hold IPv4 or IPv6 addresses alike: the
     * range itself, unless it is an IPv6 range wider than the v4-mapped
     * block, which then leaves the block out.
     *
     * @param array $range [start, end, prefix] as ipRange() returns it
     * @return array[] [[start, end], ...]
     */
    public static function memberRanges(array $range)
    {
        list($start, $end) = $range;
        if ($range[2] >= 96 || strcmp($start, self::V4_FIRST) > 0 || strcmp($end, self::V4_LAST) < 0) {
            return [[$start, $end]];
        }
        $ranges = [];
        if (strcmp($start, self::V4_FIRST) < 0) {
            $ranges[] = [$start, self::BEFORE_V4];
        }
        if (strcmp($end, self::V4_LAST) > 0) {
            $ranges[] = [self::AFTER_V4, $end];
        }
        return $ranges;
    }

    /**
     * @param string $address 16 bytes
     * @return bool
     */
    public static function isIpv4($address)
    {
        return strncmp($address, self::V4_FIRST, 12) === 0;
    }

    /**
     * The facet rows holding each address: the ranges around it and the
     * address itself, in any spelling.
     *
     * @param array $addresses [key => 16-byte address]
     * @return array [key => [value id => true for a range wider than one address]]
     */
    public function containing(array $addresses)
    {
        $found = [];
        foreach (array_chunk($addresses, self::PROBE_ADDRESSES, true) as $chunk) {
            $starts = [];
            foreach ($chunk as $key => $address) {
                $found[$key] = [];
                $starts[$key] = self::containingStarts($address);
            }
            $sql = sprintf(
                'SELECT %s, %s, %s FROM %s WHERE %s IN (%s)',
                $this->db->name('value_id'),
                $this->db->name('ip_start'),
                $this->db->name('ip_end'),
                $this->table(),
                $this->db->name('ip_start'),
                implode(', ', array_map([$this->dialect, 'binaryLiteral'], array_values(array_unique(array_merge(...array_values($starts))))))
            );
            $rows = [];
            foreach ($this->fetchRows($sql) as $row) {
                $rows[$this->bytes($row['ip_start'])][] = [(int)$row['value_id'], $this->bytes($row['ip_end'])];
            }
            foreach ($chunk as $key => $address) {
                foreach ($starts[$key] as $start) {
                    foreach ($rows[$start] ?? [] as list($id, $end)) {
                        if (strcmp($end, $address) >= 0) {
                            $found[$key][$id] = $start !== $end;
                        }
                    }
                }
            }
        }
        return $found;
    }

    /**
     * SQL selecting the value ids of the single addresses a range holds.
     *
     * @param array $range [start, end, prefix] as ipRange() returns it
     * @return string
     */
    public function membersQuery(array $range)
    {
        return sprintf(
            '%s AND %s = %s',
            $this->startsQuery([$range]),
            $this->db->name('ip_start'),
            $this->db->name('ip_end')
        );
    }

    /**
     * SQL selecting the value ids of the rows starting in one of the ranges:
     * the rows inside it, and the wider ranges sharing its start.
     *
     * @param array[] $ranges [start, end, prefix] as ipRange() returns them
     * @return string
     */
    public function startsQuery(array $ranges)
    {
        $start = $this->db->name('ip_start');
        $spans = [];
        foreach ($ranges as $range) {
            foreach (self::memberRanges($range) as list($first, $last)) {
                $spans[] = sprintf(
                    '%s BETWEEN %s AND %s',
                    $start,
                    $this->dialect->binaryLiteral($first),
                    $this->dialect->binaryLiteral($last)
                );
            }
        }
        return sprintf(
            'SELECT %s FROM %s WHERE (%s)',
            $this->db->name('value_id'),
            $this->table(),
            implode(' OR ', $spans)
        );
    }

    /**
     * The values whose range overlaps one of the ranges. Two CIDR blocks are
     * either nested or disjoint, so these are the values holding the start
     * of a range and the values starting inside one.
     *
     * @param array[] $ranges [start, end, prefix] as ipRange() returns them
     * @param int $limit More values starting inside the ranges than this is
     *   an overflow.
     * @return array ['ids' => int[], 'starts' => string|null]. On overflow,
     *   'ids' holds the values holding a start and 'starts' selects the rest.
     */
    public function overlapping(array $ranges, $limit)
    {
        $limit = (int)$limit;
        if ($limit < 1) {
            throw new InvalidArgumentException('The match limit must be at least 1.');
        }
        $ids = [];
        foreach ($this->containing(array_column($ranges, 0)) as $held) {
            $ids += $held;
        }
        // A single address starts only the ranges that hold it
        $wide = array_filter($ranges, function (array $range) {
            return $range[2] < 128;
        });
        $starts = null;
        if (!empty($wide)) {
            $sql = $this->startsQuery($wide);
            $inside = [];
            foreach ($this->fetchRows(sprintf('%s LIMIT %d', $sql, $limit + 1)) as $row) {
                $inside[(int)$row['value_id']] = true;
            }
            if (count($inside) > $limit) {
                $starts = $sql;
            } else {
                $ids += $inside;
            }
        }
        $ids = array_keys($ids);
        sort($ids);
        return ['ids' => $ids, 'starts' => $starts];
    }

    /**
     * Facet rows for values just added to the dictionary. A row that is
     * already there is left alone, so a value another session added at the
     * same time is not an error.
     *
     * @param array $ids [value => id]
     * @return int The facet rows written or found.
     */
    public function add(array $ids)
    {
        $rows = [];
        foreach ($ids as $value => $id) {
            $range = self::ipRange((string)$value);
            if ($range !== null) {
                $rows[(int)$id] = $range;
            }
        }
        $this->insert($rows);
        return count($rows);
    }

    /**
     * Bring the facet in line with the dictionary, a window of ids at a time:
     * missing rows are added, rows that differ from what their value parses
     * to are replaced, and rows whose value does not parse or no longer
     * exists are removed. Rows that are already right are only read, so a
     * stopped run is resumed by starting it again.
     *
     * @param int $chunkSize Dictionary ids per window.
     * @param callable|null $progress Called with the totals after each window.
     * @param int $from Start after this dictionary id.
     * @param int|null $to Stop at this dictionary id; null for the end.
     * @return array ['values' => dictionary rows read, 'facets' => values
     *   that parse, 'added', 'removed', 'last_id' => the last id covered]
     */
    public function rebuild($chunkSize = self::CHUNK, ?callable $progress = null, $from = 0, $to = null)
    {
        $chunkSize = (int)$chunkSize;
        if ($chunkSize < 1) {
            throw new InvalidArgumentException('The chunk size must be at least 1.');
        }
        $end = $to === null ? $this->maxId() : (int)$to;
        $totals = ['values' => 0, 'facets' => 0, 'added' => 0, 'removed' => 0, 'last_id' => (int)$from];
        while ($totals['last_id'] < $end) {
            $after = $totals['last_id'];
            $upTo = min($after + $chunkSize, $end);
            $this->rebuildWindow($after, $upTo, $totals);
            $totals['last_id'] = $upTo;
            if ($progress !== null) {
                $progress($totals);
            }
        }
        if ($to === null) {
            $totals['removed'] += $this->removeOrphans($end, null);
        }
        return $totals;
    }

    /**
     * @param int $after
     * @param int $upTo
     * @param array $totals
     * @return void
     */
    private function rebuildWindow($after, $upTo, array &$totals)
    {
        $expected = [];
        $present = [];
        foreach ($this->fetchRows($this->candidates($after, $upTo)) as $row) {
            $id = (int)$row['id'];
            $present[$id] = true;
            $range = $row['value'] === null ? null : self::ipRange((string)$row['value']);
            if ($range !== null) {
                $expected[$id] = $range;
            }
        }
        $totals['values'] += count($present);
        $totals['facets'] += count($expected);

        $stale = [];
        $orphans = false;
        foreach ($this->fetchRows($this->stored($after, $upTo)) as $row) {
            $id = (int)$row['value_id'];
            $stored = [$this->bytes($row['ip_start']), $this->bytes($row['ip_end']), (int)$row['prefix']];
            if (isset($expected[$id]) && $expected[$id] === $stored) {
                unset($expected[$id]);
            } elseif (isset($present[$id])) {
                $stale[] = $id;
            } else {
                $orphans = true;
            }
        }
        if (empty($stale) && empty($expected) && !$orphans) {
            return;
        }
        $this->db->begin();
        try {
            if (!empty($stale)) {
                $this->db->rawQuery(sprintf(
                    'DELETE FROM %s WHERE %s IN (%s)',
                    $this->table(),
                    $this->db->name('value_id'),
                    implode(', ', $stale)
                ));
                $totals['removed'] += count($stale);
            }
            if ($orphans) {
                $totals['removed'] += $this->removeOrphans($after, $upTo);
            }
            $this->insert($expected);
            $totals['added'] += count($expected);
            $this->db->commit();
        } catch (Exception $e) {
            $this->db->rollback();
            throw $e;
        }
    }

    /**
     * Every dictionary id in the window, with the value only where it could
     * be an address.
     *
     * @param int $after
     * @param int $upTo
     * @return string
     */
    private function candidates($after, $upTo)
    {
        $value = $this->db->name('value');
        return sprintf(
            "SELECT %1\$s, CASE WHEN CHAR_LENGTH(%2\$s) <= %3\$d AND (%2\$s LIKE '%%.%%' OR %2\$s LIKE '%%:%%') THEN %2\$s END AS %2\$s FROM %4\$s WHERE %1\$s > %5\$d AND %1\$s <= %6\$d",
            $this->db->name('id'),
            $value,
            self::MAX_TEXT,
            $this->db->fullTableName($this->AttributeValue->useTable, true, false),
            $after,
            $upTo
        );
    }

    /**
     * @param int $after
     * @param int $upTo
     * @return string
     */
    private function stored($after, $upTo)
    {
        return sprintf(
            'SELECT %1$s, %2$s, %3$s, %4$s FROM %5$s WHERE %1$s > %6$d AND %1$s <= %7$d',
            $this->db->name('value_id'),
            $this->db->name('ip_start'),
            $this->db->name('ip_end'),
            $this->db->name('prefix'),
            $this->table(),
            $after,
            $upTo
        );
    }

    /**
     * Facet rows in the range whose dictionary row is gone, checked against
     * the dictionary as it is now so a value added meanwhile keeps its row.
     *
     * @param int $after
     * @param int|null $upTo
     * @return int
     */
    private function removeOrphans($after, $upTo)
    {
        $valueId = $this->db->name('value_id');
        $id = $this->db->name('id');
        $range = sprintf('%s > %d', $valueId, $after) . ($upTo === null ? '' : sprintf(' AND %s <= %d', $valueId, $upTo));
        $dictionaryRange = sprintf('%s > %d', $id, $after) . ($upTo === null ? '' : sprintf(' AND %s <= %d', $id, $upTo));
        $result = $this->db->rawQuery(sprintf(
            'DELETE FROM %s WHERE %s AND %s NOT IN (SELECT %s FROM %s WHERE %s)',
            $this->table(),
            $range,
            $valueId,
            $id,
            $this->db->fullTableName($this->AttributeValue->useTable, true, false),
            $dictionaryRange
        ));
        return is_object($result) ? $result->rowCount() : 0;
    }

    /**
     * @param array $rows [value id => [start, end, prefix]]
     * @return void
     */
    private function insert(array $rows)
    {
        ksort($rows);
        foreach (array_chunk($rows, self::INSERT_ROWS, true) as $chunk) {
            $values = [];
            foreach ($chunk as $id => $range) {
                $values[] = sprintf(
                    '(%d, %s, %s, %d)',
                    $id,
                    $this->dialect->binaryLiteral($range[0]),
                    $this->dialect->binaryLiteral($range[1]),
                    $range[2]
                );
            }
            $insert = sprintf(
                'INSERT INTO %s (%s, %s, %s, %s) VALUES %s',
                $this->table(),
                $this->db->name('value_id'),
                $this->db->name('ip_start'),
                $this->db->name('ip_end'),
                $this->db->name('prefix'),
                implode(', ', $values)
            );
            $this->db->rawQuery($this->dialect->insertIgnore($insert, ['value_id']));
        }
    }

    /**
     * @return int
     */
    private function maxId()
    {
        $rows = $this->fetchRows(sprintf(
            'SELECT MAX(%s) AS %s FROM %s',
            $this->db->name('id'),
            $this->db->name('id'),
            $this->db->fullTableName($this->AttributeValue->useTable, true, false)
        ));
        return isset($rows[0]['id']) ? (int)$rows[0]['id'] : 0;
    }

    /**
     * @param mixed $column A binary column as the driver returns it.
     * @return string
     */
    private function bytes($column)
    {
        return is_resource($column) ? stream_get_contents($column) : (string)$column;
    }

    /**
     * @return string
     */
    private function table()
    {
        return $this->db->fullTableName(self::TABLE, true, false);
    }

    /**
     * @param string $sql
     * @return array
     */
    private function fetchRows($sql)
    {
        $statement = $this->db->rawQuery($sql);
        if (!is_object($statement)) {
            return [];
        }
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        $statement->closeCursor();
        return $rows;
    }
}
