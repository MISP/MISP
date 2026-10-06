<?php
App::uses('SqlDialect', 'Migration');

/**
 * Sets value1_id and value2_id on attributes and shadow_attributes from their
 * text columns, adding the values the dictionary lacks.
 *
 * Rows are taken in id order, a chunk at a time. A chunk adds its missing
 * values with one INSERT ... SELECT, then sets its ids with one UPDATE and
 * checks them byte for byte in the same transaction, so only checked ids are
 * committed. Only rows without a value1_id are touched: a run that stopped is
 * resumed by starting it again.
 *
 * Nothing keeps the ids current when a row's text changes after its backfill;
 * verify() reports such rows.
 */
class AttributeValueBackfillTool
{
    const CHUNK = 5000;

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
     * @param string $table attributes, shadow_attributes, or a table with
     *   the same value columns.
     * @param int $chunkSize Rows per chunk.
     * @param callable|null $progress Called with the totals after each chunk.
     * @return array ['rows' => rows given ids, 'values' => values added,
     *   'last_id' => the last row id read]
     * @throws RuntimeException When a row cannot be given ids or a chunk fails
     *   its check. That chunk's ids are rolled back.
     */
    public function backfill($table, $chunkSize = self::CHUNK, ?callable $progress = null)
    {
        $chunkSize = $this->chunkSize($chunkSize);
        $totals = ['rows' => 0, 'values' => 0, 'last_id' => 0];
        while ($window = $this->window($table, $totals['last_id'], $chunkSize)) {
            $pending = [];
            foreach ($window as $row) {
                if ($row['value1_id'] !== null) {
                    continue;
                }
                if ((int)$row['refused'] === 1) {
                    throw new RuntimeException(sprintf(
                        'Row %d of %s has a NULL value1 or a value over %d bytes, which the dictionary refuses.',
                        $row['id'],
                        $table,
                        AttributeValue::MAX_BYTES
                    ));
                }
                $pending[] = (int)$row['id'];
            }
            if (!empty($pending)) {
                $totals['values'] += $this->addValues($table, $pending);
                $this->setIds($table, $pending);
                $totals['rows'] += count($pending);
            }
            $last = end($window);
            $totals['last_id'] = (int)$last['id'];
            if ($progress !== null) {
                $progress($totals);
            }
        }
        return $totals;
    }

    /**
     * Read-only check of a whole table.
     *
     * @param string $table
     * @param int $chunkSize
     * @param callable|null $progress Called with the counts after each chunk.
     * @return array ['total', 'pending' => rows without ids, 'mismatched' =>
     *   rows whose ids do not give back their text, 'first_mismatch' => id or
     *   null]
     */
    public function verify($table, $chunkSize = self::CHUNK, ?callable $progress = null)
    {
        $sql = sprintf(
            'SELECT COUNT(*) AS total,'
            . ' SUM(CASE WHEN a.value1_id IS NULL THEN 1 ELSE 0 END) AS pending,'
            . ' SUM(CASE WHEN a.value1_id IS NOT NULL AND %1$s THEN 1 ELSE 0 END) AS mismatched,'
            . ' MIN(CASE WHEN a.value1_id IS NOT NULL AND %1$s THEN a.id END) AS first_mismatch'
            . ' FROM %2$s',
            $this->mismatch(),
            $this->checkedRows($table)
        );
        $counts = ['total' => 0, 'pending' => 0, 'mismatched' => 0, 'first_mismatch' => null];
        return $this->verifyInChunks($table, 'a', $sql, $counts, $chunkSize, $progress);
    }

    /**
     * Read-only check that every dictionary row holds the hash of its value.
     *
     * @param int $chunkSize
     * @param callable|null $progress
     * @return array ['total', 'mismatched', 'first_mismatch' => id or null]
     */
    public function verifyDictionary($chunkSize = self::CHUNK, ?callable $progress = null)
    {
        $wrong = sprintf('v.hash <> %s', $this->hashOf('v.value'));
        $sql = sprintf(
            'SELECT COUNT(*) AS total,'
            . ' SUM(CASE WHEN %1$s THEN 1 ELSE 0 END) AS mismatched,'
            . ' MIN(CASE WHEN %1$s THEN v.id END) AS first_mismatch'
            . ' FROM %2$s v',
            $wrong,
            $this->dictionary()
        );
        $counts = ['total' => 0, 'mismatched' => 0, 'first_mismatch' => null];
        return $this->verifyInChunks($this->AttributeValue->useTable, 'v', $sql, $counts, $chunkSize, $progress);
    }

    /**
     * The next rows after an id, with whether each is one the dictionary
     * would refuse.
     *
     * @param string $table
     * @param int $after
     * @param int $limit
     * @return array
     */
    private function window($table, $after, $limit)
    {
        return $this->fetchRows(sprintf(
            'SELECT id, value1_id, CASE WHEN value1 IS NULL OR OCTET_LENGTH(value1) > %1$d'
            . ' OR OCTET_LENGTH(value2) > %1$d THEN 1 ELSE 0 END AS refused'
            . ' FROM %2$s WHERE id > %3$d ORDER BY id LIMIT %4$d',
            AttributeValue::MAX_BYTES,
            $this->table($table),
            $after,
            $limit
        ));
    }

    /**
     * @param string $table
     * @param int[] $ids
     * @return int Values added.
     */
    private function addValues($table, array $ids)
    {
        $in = implode(', ', $ids);
        // Grouped by hash, never by text: the collation equates distinct values
        $insert = sprintf(
            'INSERT INTO %1$s (value, hash) SELECT MIN(s.v), s.h FROM ('
            . 'SELECT a.value1 AS v, %2$s AS h FROM %4$s a WHERE a.id IN (%5$s)'
            . ' UNION ALL SELECT a.value2, %3$s FROM %4$s a WHERE a.id IN (%5$s) AND OCTET_LENGTH(a.value2) > 0'
            . ') s WHERE NOT EXISTS (SELECT 1 FROM %1$s x WHERE x.hash = s.h) GROUP BY s.h ORDER BY s.h',
            $this->dictionary(),
            $this->hashOf('a.value1'),
            $this->hashOf('a.value2'),
            $this->table($table),
            $in
        );
        $result = $this->db->rawQuery($this->dialect->insertIgnore($insert, ['hash']));
        return is_object($result) ? $result->rowCount() : 0;
    }

    /**
     * @param string $table
     * @param int[] $ids
     * @return void
     * @throws RuntimeException When a row's ids do not give back its text.
     */
    private function setIds($table, array $ids)
    {
        $in = implode(', ', $ids);
        $lookup = 'SELECT v.id FROM %s v WHERE v.hash = %s';
        $update = sprintf(
            'UPDATE %1$s AS a SET value1_id = (%2$s),'
            . ' value2_id = CASE WHEN COALESCE(OCTET_LENGTH(a.value2), 0) = 0 THEN NULL ELSE (%3$s) END'
            . ' WHERE a.id IN (%4$s)',
            $this->table($table),
            sprintf($lookup, $this->dictionary(), $this->hashOf('a.value1')),
            sprintf($lookup, $this->dictionary(), $this->hashOf('a.value2')),
            $in
        );
        $check = sprintf(
            'SELECT COUNT(*) AS bad, MIN(a.id) AS first_bad FROM %s WHERE a.id IN (%s) AND %s',
            $this->checkedRows($table),
            $in,
            $this->mismatch()
        );
        $this->db->begin();
        try {
            $this->db->rawQuery($update);
            $result = $this->fetchRows($check)[0];
        } catch (Exception $e) {
            $this->db->rollback();
            throw $e;
        }
        if ((int)$result['bad'] > 0) {
            $this->db->rollback();
            throw new RuntimeException(sprintf(
                '%d rows of %s do not match their dictionary values, the first is %d. Their ids were rolled back.',
                $result['bad'],
                $table,
                $result['first_bad']
            ));
        }
        $this->db->commit();
    }

    /**
     * @param string $table
     * @return string Rows of $table as `a`, with their values as v1 and v2.
     */
    private function checkedRows($table)
    {
        return sprintf(
            '%1$s a LEFT JOIN %2$s v1 ON v1.id = a.value1_id LEFT JOIN %2$s v2 ON v2.id = a.value2_id',
            $this->table($table),
            $this->dictionary()
        );
    }

    /**
     * True for a row whose ids do not give back its text byte for byte, or
     * whose value2_id is not NULL exactly when value2 is empty.
     *
     * @return string
     */
    private function mismatch()
    {
        $length2 = 'COALESCE(OCTET_LENGTH(a.value2), 0)';
        return sprintf(
            '(a.value1 IS NULL OR v1.id IS NULL OR %1$s <> %2$s'
            . ' OR (a.value2_id IS NULL AND %5$s > 0)'
            . ' OR (a.value2_id IS NOT NULL AND (v2.id IS NULL OR %5$s = 0 OR %3$s <> %4$s)))',
            $this->dialect->bytesOf('v1.value'),
            $this->dialect->bytesOf('a.value1'),
            $this->dialect->bytesOf('v2.value'),
            $this->dialect->bytesOf('a.value2'),
            $length2
        );
    }

    /**
     * @param string $table Walked in id order.
     * @param string $alias $table's alias in $sql.
     * @param string $sql Selects the $counts keys over $table, without a WHERE.
     * @param array $counts The counts at zero, with first_mismatch null.
     * @param int $chunkSize
     * @param callable|null $progress
     * @return array $counts summed over the table, first_mismatch the lowest.
     */
    private function verifyInChunks($table, $alias, $sql, array $counts, $chunkSize, ?callable $progress)
    {
        $chunkSize = $this->chunkSize($chunkSize);
        $after = 0;
        while (($upTo = $this->windowEnd($table, $after, $chunkSize)) !== null) {
            $row = $this->fetchRows(sprintf(
                '%1$s WHERE %2$s.id > %3$d AND %2$s.id <= %4$d',
                $sql,
                $alias,
                $after,
                $upTo
            ))[0];
            foreach ($counts as $key => $count) {
                if ($key !== 'first_mismatch') {
                    $counts[$key] += (int)$row[$key];
                }
            }
            if ($counts['first_mismatch'] === null && $row['first_mismatch'] !== null) {
                $counts['first_mismatch'] = (int)$row['first_mismatch'];
            }
            $after = $upTo;
            if ($progress !== null) {
                $progress($counts);
            }
        }
        return $counts;
    }

    /**
     * @param string $table
     * @param int $after
     * @param int $limit
     * @return int|null The id that ends the next chunk, null past the end.
     */
    private function windowEnd($table, $after, $limit)
    {
        $rows = $this->fetchRows(sprintf(
            'SELECT MAX(w.id) AS id FROM (SELECT id FROM %s WHERE id > %d ORDER BY id LIMIT %d) w',
            $this->table($table),
            $after,
            $limit
        ));
        return isset($rows[0]['id']) ? (int)$rows[0]['id'] : null;
    }

    /**
     * @param string $expr
     * @return string
     */
    private function hashOf($expr)
    {
        return $this->dialect->sha256Prefix($expr, AttributeValue::HASH_BYTES);
    }

    /**
     * @param mixed $chunkSize
     * @return int
     */
    private function chunkSize($chunkSize)
    {
        $chunkSize = (int)$chunkSize;
        if ($chunkSize < 1) {
            throw new InvalidArgumentException('The chunk size must be at least 1.');
        }
        return $chunkSize;
    }

    /**
     * @return string
     */
    private function dictionary()
    {
        return $this->table($this->AttributeValue->useTable);
    }

    /**
     * @param string $table
     * @return string
     */
    private function table($table)
    {
        return $this->db->fullTableName($table, true, false);
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
