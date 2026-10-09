<?php
App::uses('SqlDialect', 'Migration');
App::uses('RedisTool', 'Tools');
App::uses('Correlation', 'Model');

/**
 * Points the correlation tables' value_id from correlation_values at the value
 * dictionary: each row gets the key of its value's group, the lowest id among
 * the values the dictionary collation holds equal to it.
 *
 * Only the rows up to the bound the migration recorded are rewritten, in id
 * order, one chunk per transaction together with the progress, so a stopped
 * run resumes where it left off and rows written since keep their ids. A
 * value correlation_values may have cut at 191 characters, and a row whose
 * value is gone from it, is resolved through the row's attributes. MySQL only:
 * no other engine has 2.x correlation tables.
 */
class CorrelationRemapTool
{
    const CHUNK = 50000;

    const TABLES = ['default_correlations', 'no_acl_correlations'];

    // correlation_values id => value group, built once for every table
    const MAP = 'correlation_value_map';

    const CUT = 191;

    /** @var AttributeValue */
    private $AttributeValue;

    /** @var AdminSetting */
    private $AdminSetting;

    /** @var DboSource */
    private $db;

    /**
     * @param AttributeValue $AttributeValue
     */
    public function __construct(AttributeValue $AttributeValue)
    {
        $this->AttributeValue = $AttributeValue;
        $this->AdminSetting = ClassRegistry::init('AdminSetting');
        $this->db = $AttributeValue->getDataSource();
    }

    /**
     * Records the rows a remap has to rewrite: those there now. Keeps a
     * bound already recorded.
     *
     * @param string $table
     * @return void
     */
    public function recordBound($table)
    {
        if ($this->state($table) !== null) {
            return;
        }
        $max = $this->fetchRows(sprintf('SELECT MAX(id) AS max_id FROM %s', $this->table($table)));
        $this->saveState($table, ['bound' => (int)$max[0]['max_id'], 'last' => 0]);
    }

    /**
     * @param string $table
     * @return array|null ['bound' => int, 'last' => int], null before the migration
     */
    public function state($table)
    {
        $state = $this->AdminSetting->getSetting(self::settingName($table));
        if (empty($state)) {
            return null;
        }
        $state = json_decode($state, true);
        return is_array($state) ? ['bound' => (int)$state['bound'], 'last' => (int)$state['last']] : null;
    }

    /**
     * @return bool Whether every table is remapped.
     */
    public function done()
    {
        foreach (self::TABLES as $table) {
            $state = $this->state($table);
            if ($state !== null && $state['last'] < $state['bound']) {
                return false;
            }
        }
        return true;
    }

    /**
     * @param string $table
     * @param int $chunkSize
     * @param callable|null $progress Called with the totals after each chunk.
     * @return array ['rows' => rows remapped, 'by_row' => resolved one by one,
     *   'dropped' => duplicates of a pair already held under the group,
     *   'last_id' => the last row id remapped]
     * @throws RuntimeException When the backfill has not finished or a row
     *   cannot be resolved.
     */
    public function remap($table, $chunkSize = self::CHUNK, ?callable $progress = null)
    {
        $state = $this->state($table);
        $totals = ['rows' => 0, 'by_row' => 0, 'dropped' => 0, 'last_id' => $state === null ? 0 : $state['last']];
        if ($state === null || $state['last'] >= $state['bound']) {
            return $totals;
        }
        if (!empty($this->fetchRows('SELECT id FROM ' . $this->table('attributes') . ' WHERE value1_id IS NULL LIMIT 1'))) {
            throw new RuntimeException('Some attributes have no value ids yet: run the attribute value backfill first.');
        }
        $this->buildMap();
        $chunkSize = max(1, (int)$chunkSize);
        $last = $state['last'];
        while ($last < $state['bound']) {
            $upto = min($last + $chunkSize, $state['bound']);
            $byRow = $this->resolveByRow($table, $last, $upto);
            $this->db->begin();
            try {
                $this->rawQuery(sprintf(
                    'UPDATE %s t JOIN %s m ON m.cv_id = t.value_id SET t.value_id = m.value_id WHERE t.id > %d AND t.id <= %d AND m.value_id IS NOT NULL',
                    $this->table($table),
                    $this->table(self::MAP),
                    $last,
                    $upto
                ));
                $rows = $this->affected();
                foreach ($byRow as $id => $valueId) {
                    $this->rawQuery(sprintf('UPDATE %s SET value_id = %d WHERE id = %d', $this->table($table), $valueId, $id));
                }
                $this->saveState($table, ['bound' => $state['bound'], 'last' => $upto]);
                $this->db->commit();
            } catch (PDOException $e) {
                $this->db->rollback();
                if (!$this->isDuplicate($e)) {
                    throw $e;
                }
                list($rows, $dropped) = $this->remapRowByRow($table, $last, $upto, $byRow, $state['bound']);
                $totals['dropped'] += $dropped;
            }
            $totals['rows'] += $rows + count($byRow);
            $totals['by_row'] += count($byRow);
            $totals['last_id'] = $last = $upto;
            if ($progress) {
                $progress($totals);
            }
        }
        return $totals;
    }

    /**
     * Once every table is remapped: the map goes, and the top correlations,
     * counted by correlation_values id, have to be generated again.
     *
     * @return void
     */
    public function finish()
    {
        if (!$this->done()) {
            return;
        }
        $this->rawQuery('DROP TABLE IF EXISTS ' . $this->table(self::MAP));
        try {
            $redis = RedisTool::init();
            RedisTool::unlink($redis, [Correlation::CACHE_NAME, Correlation::CACHE_AGE]);
        } catch (Exception $e) {
            // No Redis, no cached top list
        }
    }

    /**
     * @param string $table
     * @return string
     */
    public static function settingName($table)
    {
        return 'correlation_remap_' . $table;
    }

    /**
     * Maps every correlation_values row shorter than the cut to its value
     * group, adding the values the dictionary lacks.
     *
     * @return void
     */
    private function buildMap()
    {
        $map = $this->table(self::MAP);
        $values = $this->table('correlation_values');
        $this->rawQuery("CREATE TABLE IF NOT EXISTS $map (cv_id INT UNSIGNED NOT NULL PRIMARY KEY, value_id BIGINT UNSIGNED NULL) ENGINE=InnoDB");
        $this->rawQuery(sprintf(
            'INSERT INTO %1$s (cv_id, value_id) SELECT cv.id, (SELECT MIN(w.id) FROM %2$s w WHERE w.value = cv.value COLLATE %3$s) FROM %4$s cv LEFT JOIN %1$s m ON m.cv_id = cv.id WHERE m.cv_id IS NULL AND CHAR_LENGTH(cv.value) < %5$d',
            $map,
            $this->table('attribute_values'),
            $this->collation(),
            $values,
            self::CUT
        ));
        $missing = $this->fetchRows(sprintf(
            'SELECT m.cv_id, cv.value FROM %s m JOIN %s cv ON cv.id = m.cv_id WHERE m.value_id IS NULL',
            $map,
            $values
        ));
        if (empty($missing)) {
            return;
        }
        $ids = $this->AttributeValue->internMany(array_column($missing, 'value'));
        $groups = $this->AttributeValue->groupIds(array_values($ids));
        foreach ($missing as $row) {
            $this->rawQuery(sprintf(
                'UPDATE %s SET value_id = %d WHERE cv_id = %d',
                $map,
                $groups[(int)$ids[$row['value']]],
                $row['cv_id']
            ));
        }
    }

    /**
     * The groups of the rows the map cannot give one: a value that may have
     * been cut, found again through either attribute, or a row whose value is
     * gone from correlation_values, which takes its first attribute's value1.
     *
     * @param string $table
     * @param int $after
     * @param int $upto
     * @return array [row id => value group]
     */
    private function resolveByRow($table, $after, $upto)
    {
        $collation = $this->collation();
        $matches = [];
        foreach (['a1' => 'a.value1_id', 'a2' => 'a.value2_id', 'b1' => 'b.value1_id', 'b2' => 'b.value2_id'] as $alias => $id) {
            $matches[] = sprintf('WHEN LEFT(%s.value, %d) = cv.value COLLATE %s THEN %s', $alias, self::CUT, $collation, $id);
        }
        $rows = $this->fetchRows(sprintf(
            'SELECT t.id, cv.id AS cv_id, cv.value AS cut_value, CASE WHEN cv.id IS NULL THEN a.value1_id %1$s END AS value_id
            FROM %2$s t
            LEFT JOIN %3$s cv ON cv.id = t.value_id
            LEFT JOIN %4$s a ON a.id = t.attribute_id
            LEFT JOIN %5$s a1 ON a1.id = a.value1_id
            LEFT JOIN %5$s a2 ON a2.id = a.value2_id
            LEFT JOIN %4$s b ON b.id = t.`1_attribute_id`
            LEFT JOIN %5$s b1 ON b1.id = b.value1_id
            LEFT JOIN %5$s b2 ON b2.id = b.value2_id
            WHERE t.id > %6$d AND t.id <= %7$d AND (cv.id IS NULL OR CHAR_LENGTH(cv.value) >= %8$d)',
            implode(' ', $matches),
            $this->table($table),
            $this->table('correlation_values'),
            $this->table('attributes'),
            $this->table('attribute_values'),
            $after,
            $upto,
            self::CUT
        ));
        $unmatched = [];
        foreach ($rows as $row) {
            if ($row['value_id'] === null) {
                if ($row['cv_id'] === null) {
                    throw new RuntimeException(sprintf('Correlation %d in %s has neither a value nor an attribute to take one from.', $row['id'], $table));
                }
                $unmatched[] = $row['cut_value'];
            }
        }
        $interned = empty($unmatched) ? [] : $this->AttributeValue->internMany($unmatched);
        $valueIds = [];
        foreach ($rows as $row) {
            $valueIds[(int)$row['id']] = $row['value_id'] === null ? (int)$interned[$row['cut_value']] : (int)$row['value_id'];
        }
        $groups = $this->AttributeValue->groupIds(array_values($valueIds));
        $byRow = [];
        foreach ($valueIds as $id => $valueId) {
            $byRow[$id] = $groups[$valueId];
        }
        return $byRow;
    }

    /**
     * A chunk in which a remapped row would repeat a pair already held under
     * its group: rows are moved one at a time and the repeats dropped, which
     * leaves the set of correlated pairs as it was.
     *
     * @param string $table
     * @param int $after
     * @param int $upto
     * @param array $byRow
     * @param int $bound
     * @return int[] [rows remapped through the map, rows dropped]
     */
    private function remapRowByRow($table, $after, $upto, array $byRow, $bound)
    {
        $rows = $this->fetchRows(sprintf(
            'SELECT t.id, m.value_id FROM %s t LEFT JOIN %s m ON m.cv_id = t.value_id WHERE t.id > %d AND t.id <= %d',
            $this->table($table),
            $this->table(self::MAP),
            $after,
            $upto
        ));
        $remapped = $dropped = 0;
        $this->db->begin();
        try {
            foreach ($rows as $row) {
                $id = (int)$row['id'];
                $valueId = isset($byRow[$id]) ? $byRow[$id] : (int)$row['value_id'];
                try {
                    $this->rawQuery(sprintf('UPDATE %s SET value_id = %d WHERE id = %d', $this->table($table), $valueId, $id));
                    $remapped += isset($byRow[$id]) ? 0 : 1;
                } catch (PDOException $e) {
                    if (!$this->isDuplicate($e)) {
                        throw $e;
                    }
                    $this->rawQuery(sprintf('DELETE FROM %s WHERE id = %d', $this->table($table), $id));
                    $dropped++;
                }
            }
            $this->saveState($table, ['bound' => $bound, 'last' => $upto]);
            $this->db->commit();
        } catch (Exception $e) {
            $this->db->rollback();
            throw $e;
        }
        return [$remapped, $dropped];
    }

    /**
     * @param string $table
     * @param array $state
     * @return void
     */
    private function saveState($table, array $state)
    {
        $this->AdminSetting->changeSetting(self::settingName($table), json_encode($state));
    }

    /**
     * The dictionary's collation, which correlation_values text is compared in.
     *
     * @return string
     */
    private function collation()
    {
        $rows = $this->fetchRows(
            "SELECT COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'attribute_values' AND COLUMN_NAME = 'value'"
        );
        if (empty($rows) || !preg_match('/^\w+$/', $rows[0]['COLLATION_NAME'])) {
            throw new RuntimeException('The value dictionary was not found.');
        }
        return $rows[0]['COLLATION_NAME'];
    }

    /**
     * @param PDOException $e
     * @return bool
     */
    private function isDuplicate(PDOException $e)
    {
        return isset($e->errorInfo[1]) && (int)$e->errorInfo[1] === 1062;
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
     * @return void
     */
    private function rawQuery($sql)
    {
        // A statement that changed nothing comes back as true
        $this->affectedRows = 0;
        $statement = $this->db->rawQuery($sql);
        if ($statement instanceof PDOStatement) {
            $this->affectedRows = $statement->rowCount();
            $statement->closeCursor();
        }
    }

    /** @var int */
    private $affectedRows = 0;

    /**
     * @return int Rows the last statement changed.
     */
    private function affected()
    {
        return $this->affectedRows;
    }

    /**
     * @param string $sql
     * @return array
     */
    private function fetchRows($sql)
    {
        $statement = $this->db->rawQuery($sql);
        if (!($statement instanceof PDOStatement)) {
            return [];
        }
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        $statement->closeCursor();
        return $rows;
    }
}
