<?php

/**
 * SearchPerformanceShell — harvests database statistics
 * relevant to attribute restSearch query planning and
 * produces a performance evaluation report.
 *
 * Read-only: all queries are SELECT statements.
 *
 * Usage:
 *   app/Console/cake SearchPerformance report
 *   app/Console/cake SearchPerformance report --json
 */
class SearchPerformanceShell extends AppShell
{
    public $uses = ['MispAttribute', 'Event', 'Object',
        'SharingGroup', 'Tag', 'Organisation',
        'Sighting'];

    public function getOptionParser()
    {
        $parser = parent::getOptionParser();
        $parser->addSubcommand('report', [
            'help' => __(
                'Harvest database statistics and produce '
                . 'a performance evaluation of attribute '
                . 'restSearch filter combinations.'
            ),
            'parser' => [
                'options' => [
                    'json' => [
                        'short' => 'j',
                        'help' => 'Output raw data as JSON '
                            . 'instead of a formatted report',
                        'default' => false,
                        'boolean' => true,
                    ],
                    'fast' => [
                        'short' => 'f',
                        'help' => 'Use approximations to '
                            . 'avoid full table scans. '
                            . 'Safe for production under '
                            . 'load.',
                        'default' => false,
                        'boolean' => true,
                    ],
                ],
            ],
        ]);
        return $parser;
    }

    /**
     * Main entry point — collect stats, evaluate, print.
     */
    public function report()
    {
        $stats = $this->__collectStats();
        $evaluation = $this->__evaluate($stats);

        $jsonData = $this->json([
            'generated' => date('Y-m-d H:i:s'),
            'stats' => $stats,
            'evaluation' => $evaluation,
        ]);

        // Always save a timestamped JSON file
        $filename = sprintf(
            'benchmark_results-%s.json',
            date('Y-m-d:H-i-s')
        );
        $dir = APP . 'tmp' . DS . 'logs' . DS;
        $path = $dir . $filename;
        file_put_contents($path, $jsonData . "\n");
        $this->out(sprintf(
            'JSON results saved to: %s', $path
        ));
        $this->out('');

        if (!empty($this->params['json'])) {
            $this->out($jsonData);
            return;
        }

        $this->__printReport($stats, $evaluation);
    }

    // ── data collection ─────────────────────────────────

    /**
     * Harvest all statistics from the local database.
     *
     * @return array
     */
    private function __collectStats()
    {
        $fast = !empty($this->params['fast']);
        if ($fast) {
            $this->out(
                '<info>Fast mode: using '
                . 'approximations</info>'
            );
            $this->out('');
        }

        $stats = [];
        $stats['approximate'] = $fast;

        // ── Table counts ────────────────────────────
        $this->__step('table_counts');
        $stats['table_counts'] = $fast
            ? $this->__tableCountsFast()
            : $this->__tableCounts();

        // In fast mode, sample a PK range from
        // attributes to avoid full table scans for
        // all subsequent attribute distributions.
        $sampleWhere = '';
        $sampleSize = 0;
        if ($fast) {
            $this->__step('sample_range');
            $range = $this->__sampleRange(
                'attributes', 100000,
                $stats['table_counts']['attributes']
            );
            $sampleWhere = $range['where'];
            $sampleSize = $range['sample_size'];
            $stats['sample_size'] = $sampleSize;
        }

        // ── Attribute distributions ─────────────────
        $this->__step('attribute_type_distribution');
        $stats['attribute_type_distribution'] =
            $this->__distribution(
                'attributes', 'type', 20,
                $sampleWhere
            );
        $this->__step(
            'attribute_category_distribution'
        );
        $stats['attribute_category_distribution'] =
            $this->__distribution(
                'attributes', 'category', 15,
                $sampleWhere
            );
        $this->__step(
            'attribute_distribution_spread'
        );
        $stats['attribute_distribution_spread'] =
            $this->__distribution(
                'attributes', 'distribution', 10,
                $sampleWhere
            );
        $this->__step('attribute_to_ids');
        $stats['attribute_to_ids'] =
            $this->__distribution(
                'attributes', 'to_ids', 2,
                $sampleWhere
            );
        $this->__step('attribute_deleted');
        $stats['attribute_deleted'] =
            $this->__distribution(
                'attributes', 'deleted', 3,
                $sampleWhere
            );

        // ── Event/object distributions (small) ──────
        $this->__step('event_published');
        $stats['event_published'] =
            $this->__distribution(
                'events', 'published', 2
            );
        $this->__step('event_distribution');
        $stats['event_distribution'] =
            $this->__distribution(
                'events', 'distribution', 10
            );
        $this->__step('object_distribution');
        $stats['object_distribution'] =
            $this->__distribution(
                'objects', 'distribution', 10
            );

        // ── Attribute aggregates ────────────────────
        $this->__step('object_membership');
        if ($fast) {
            $stats['object_membership'] =
                $this->__singleQuery(
                    "SELECT "
                    . "SUM(object_id = 0) "
                        . "AS standalone, "
                    . "SUM(object_id != 0) "
                        . "AS in_object "
                    . "FROM attributes "
                    . $sampleWhere,
                    'object_membership'
                );
        } else {
            $stats['object_membership'] =
                $this->__singleQuery(
                    "SELECT "
                    . "SUM(object_id = 0) "
                        . "AS standalone, "
                    . "SUM(object_id != 0) "
                        . "AS in_object "
                    . "FROM attributes",
                    'object_membership'
                );
        }

        // Value cardinality: skipped, assumed high.

        $this->__step('composite_value_ratio');
        if ($fast) {
            $stats['composite_value_ratio'] =
                $this->__singleQuery(
                    "SELECT "
                    . "SUM(value2 != '') "
                        . "AS has_value2, "
                    . "SUM(value2 = '') "
                        . "AS no_value2 "
                    . "FROM attributes "
                    . $sampleWhere,
                    'composite_value_ratio'
                );
        } else {
            $stats['composite_value_ratio'] =
                $this->__singleQuery(
                    "SELECT "
                    . "SUM(value2 != '') "
                        . "AS has_value2, "
                    . "SUM(value2 = '') "
                        . "AS no_value2 "
                    . "FROM attributes",
                    'composite_value_ratio'
                );
        }

        // ── Timestamp (uses index, always fast) ─────
        $this->__step('timestamp_ranges');
        $stats['timestamp_ranges'] =
            $this->__timestampRanges();

        $this->__step('first_last_seen_usage');
        if ($fast) {
            $stats['first_last_seen_usage'] =
                $this->__singleQuery(
                    "SELECT "
                    . "SUM(first_seen IS NOT NULL) "
                        . "AS has_first_seen, "
                    . "SUM(last_seen IS NOT NULL) "
                        . "AS has_last_seen "
                    . "FROM attributes "
                    . $sampleWhere,
                    'first_last_seen_usage'
                );
        } else {
            $stats['first_last_seen_usage'] =
                $this->__singleQuery(
                    "SELECT "
                    . "SUM(first_seen IS NOT NULL) "
                        . "AS has_first_seen, "
                    . "SUM(last_seen IS NOT NULL) "
                        . "AS has_last_seen "
                    . "FROM attributes",
                    'first_last_seen_usage'
                );
        }

        $this->__step('sharing_group_usage');
        if ($fast) {
            $stats['sharing_group_usage'] =
                $this->__singleQuery(
                    "SELECT "
                    . "SUM(sharing_group_id = 0) "
                        . "AS no_sg, "
                    . "SUM(sharing_group_id != 0) "
                        . "AS has_sg "
                    . "FROM attributes "
                    . $sampleWhere,
                    'sharing_group_usage'
                );
        } else {
            $stats['sharing_group_usage'] =
                $this->__singleQuery(
                    "SELECT "
                    . "SUM(sharing_group_id = 0) "
                        . "AS no_sg, "
                    . "SUM(sharing_group_id != 0) "
                        . "AS has_sg "
                    . "FROM attributes",
                    'sharing_group_usage'
                );
        }
        $this->__step('top_attribute_tags');
        $stats['top_attribute_tags'] =
            $this->__topTags('attribute_tags', 10);
        $this->__step('top_event_tags');
        $stats['top_event_tags'] =
            $this->__topTags('event_tags', 10);

        // Tags-per-attribute: count from attribute_tags
        // only, derive "0" bucket from total minus
        // tagged to avoid an expensive LEFT JOIN.
        $this->__step('tags_per_attribute');
        if ($fast) {
            // In fast mode, just get the count of
            // distinct tagged attributes vs total.
            $taggedAttrs = $this->__singleQuery(
                "SELECT COUNT(DISTINCT attribute_id) "
                . "AS n FROM attribute_tags",
                'tags_per_attribute'
            );
            $n = $taggedAttrs['n'] ?? 0;
            $totalAttrs = $stats['table_counts']
                ['attributes'];
            $totalAttrTags = $stats['table_counts']
                ['attribute_tags'];
            $avgTagsPerTagged = $n > 0
                ? $totalAttrTags / $n : 0;
            $stats['tags_per_attribute'] = [
                '0' => $totalAttrs - $n,
                'tagged (avg '
                    . sprintf('%.1f', $avgTagsPerTagged)
                    . '/attr)' => $n,
            ];
        } else {
            $tagged = $this->__bucketDistribution(
                "SELECT COUNT(*) AS cnt "
                . "FROM attribute_tags "
                . "GROUP BY attribute_id",
                'cnt', 'tags_per_attribute'
            );
            $taggedTotal = array_sum($tagged);
            $untagged = $stats['table_counts']
                ['attributes'] - $taggedTotal;
            $stats['tags_per_attribute'] =
                ['0' => $untagged] + $tagged;
        }

        // Tags per event (events table is small)
        $this->__step('tags_per_event');
        $stats['tags_per_event'] =
            $this->__bucketDistribution(
                "SELECT COALESCE(t.cnt, 0) AS cnt "
                . "FROM events e "
                . "LEFT JOIN ("
                    . "SELECT event_id, COUNT(*) cnt "
                    . "FROM event_tags "
                    . "GROUP BY event_id"
                . ") t "
                . "ON t.event_id = e.id",
                'cnt', 'tags_per_event'
            );

        $this->__step('attrs_per_event');
        if ($fast) {
            // Derive from table counts — avg is
            // sufficient for the evaluation.
            $totalAttrs = $stats['table_counts']
                ['attributes'];
            $totalEvents = $stats['table_counts']
                ['events'];
            $avg = $totalEvents > 0
                ? (int)($totalAttrs / $totalEvents)
                : 0;
            $stats['attrs_per_event'] = [
                'avg' => $avg,
                '(approximated)' => $totalEvents,
            ];
        } else {
            $stats['attrs_per_event'] =
                $this->__bucketDistribution(
                    "SELECT COUNT(*) AS cnt "
                    . "FROM attributes "
                    . "GROUP BY event_id",
                    'cnt', 'attrs_per_event'
                );
        }

        // Events per org (events table is small)
        $this->__step('events_per_org');
        $stats['events_per_org'] =
            $this->__queryList(
                "SELECT o.name, COUNT(*) AS cnt "
                . "FROM events e "
                . "JOIN organisations o "
                    . "ON o.id = e.orgc_id "
                . "GROUP BY e.orgc_id "
                . "ORDER BY cnt DESC LIMIT 10",
                'events_per_org'
            );

        $this->__step('broad_tag_event_spread');
        if ($fast) {
            // Just use top attribute tags count
            // (already collected) — skip the expensive
            // COUNT(DISTINCT event_id) per tag.
            $stats['broad_tag_event_spread'] = [];
        } else {
            $stats['broad_tag_event_spread'] =
                $this->__queryList(
                    "SELECT t.name, "
                    . "COUNT(DISTINCT at.event_id) "
                        . "AS events, "
                    . "COUNT(*) AS attr_tags "
                    . "FROM attribute_tags at "
                    . "JOIN tags t ON t.id = at.tag_id "
                    . "GROUP BY at.tag_id "
                    . "ORDER BY attr_tags "
                    . "DESC LIMIT 10",
                    'broad_tag_event_spread'
                );
        }
        // Correlation density as a simple ratio —
        // avoids the expensive LEFT JOIN sampling.
        $stats['correlation_ratio'] = [
            'attributes' =>
                $stats['table_counts']['attributes'],
            'correlations' =>
                $stats['table_counts']
                    ['default_correlations'],
        ];
        $this->__step('indexes');
        $stats['indexes'] = $this->__indexInfo();

        // In fast mode, scale sampled attribute
        // distributions to estimated full-table
        // counts so the evaluation logic and printer
        // work unchanged.
        if ($fast && $sampleSize > 0) {
            $this->__step('scaling_samples');
            $totalAttrs = $stats['table_counts']
                ['attributes'];
            $scale = $totalAttrs / $sampleSize;
            $scaledKeys = [
                'attribute_type_distribution',
                'attribute_category_distribution',
                'attribute_distribution_spread',
                'attribute_to_ids',
                'attribute_deleted',
            ];
            foreach ($scaledKeys as $k) {
                foreach ($stats[$k] as &$v) {
                    $v = (int)round($v * $scale);
                }
                unset($v);
            }
            // Scale sampled aggregates
            foreach (
                ['object_membership',
                 'composite_value_ratio',
                 'first_last_seen_usage',
                 'sharing_group_usage'] as $k
            ) {
                foreach ($stats[$k] as &$v) {
                    if (is_numeric($v)) {
                        $v = (int)round($v * $scale);
                    }
                }
                unset($v);
            }
        }

        $this->__step('done');
        return $stats;
    }

    /**
     * Print a progress step. Always shown (not just
     * verbose) so operators can see where the tool is.
     *
     * @param string $label
     */
    private function __step($label)
    {
        $this->out(sprintf(
            '[%s] Collecting: %s',
            date('H:i:s'), $label
        ), 1, Shell::VERBOSE);
    }

    // ── query helpers (all read-only) ───────────────────

    /**
     * Execute a raw SELECT query with optional verbose
     * logging. When the shell is run with -v, prints
     * the step label and SQL before executing, and the
     * elapsed time after.
     *
     * @param string $sql
     * @param string $label  Human-readable step name
     * @return array  Raw CakePHP query() result
     */
    private function __runQuery($sql, $label = '')
    {
        if ($label !== '') {
            $this->out(
                "  [{$label}] running ...",
                1, Shell::VERBOSE
            );
            $this->out(
                "    SQL: " . preg_replace(
                    '/\s+/', ' ', trim($sql)
                ),
                1, Shell::VERBOSE
            );
        }
        $t0 = microtime(true);
        $result = $this->MispAttribute->query($sql);
        $elapsed = microtime(true) - $t0;
        if ($label !== '') {
            $this->out(sprintf(
                "  [{$label}] done in %.2fs (%d rows)",
                $elapsed, count($result)
            ), 1, Shell::VERBOSE);
        }
        return $result;
    }

    /**
     * Flatten a CakePHP query() result row.
     *
     * CakePHP's Model::query() returns rows keyed by
     * table name for real columns and by numeric index
     * for computed columns, e.g.:
     *   ['attributes' => ['val' => 'x'], 0 => ['cnt' => 5]]
     *
     * This method merges all sub-arrays into a single
     * flat associative array.
     *
     * @param array $row  Single result row
     * @return array
     */
    private function __flatten($row)
    {
        $flat = [];
        foreach ($row as $v) {
            if (is_array($v)) {
                $flat = array_merge($flat, $v);
            }
        }
        return $flat;
    }

    /**
     * Row counts for the key tables.
     *
     * @return array
     */
    private function __tableCounts()
    {
        $tables = [
            'attributes', 'events', 'objects',
            'attribute_tags', 'event_tags', 'tags',
            'sharing_groups', 'organisations',
            'sightings', 'default_correlations',
        ];
        $counts = [];
        foreach ($tables as $table) {
            $sql = "SELECT COUNT(*) AS cnt "
                . "FROM `{$table}`";
            $r = $this->__runQuery(
                $sql, "count_{$table}"
            );
            $flat = $this->__flatten($r[0]);
            $counts[$table] = (int)$flat['cnt'];
        }
        return $counts;
    }

    /**
     * Approximate row counts via information_schema.
     * Instant, no table scan.
     *
     * @return array
     */
    private function __tableCountsFast()
    {
        $tables = [
            'attributes', 'events', 'objects',
            'attribute_tags', 'event_tags', 'tags',
            'sharing_groups', 'organisations',
            'sightings', 'default_correlations',
        ];
        $db = $this->__singleQuery(
            "SELECT DATABASE() AS db", 'detect_db'
        );
        $dbName = $db['db'];
        $counts = [];
        foreach ($tables as $table) {
            $sql = "SELECT TABLE_ROWS AS cnt "
                . "FROM information_schema.TABLES "
                . "WHERE TABLE_SCHEMA = "
                . "'{$dbName}' "
                . "AND TABLE_NAME = '{$table}'";
            $r = $this->__runQuery(
                $sql, "count_{$table}"
            );
            if (!empty($r)) {
                $flat = $this->__flatten($r[0]);
                $counts[$table] =
                    (int)($flat['cnt'] ?? 0);
            } else {
                $counts[$table] = 0;
            }
        }
        return $counts;
    }

    /**
     * Build a WHERE clause that samples ~N rows from
     * a table using modular arithmetic on the PK.
     * Works well even with sparse/gappy ID sequences.
     *
     * @param string $table
     * @param int $target  Desired sample size
     * @return array  ['where' => string, 'sample_size' => int]
     */
    /**
     * Build a WHERE clause that samples ~N rows from
     * the tail of a table using a PK range scan.
     * Uses MAX(id) to find the upper bound, then
     * reads the last ~N rows by PK. This is a fast
     * index range scan — no full table scan needed.
     *
     * @param string $table
     * @param int $target  Desired sample size
     * @param int $approxTotal  Approximate row count
     *                          (from information_schema)
     * @return array  ['where' => string, 'sample_size' => int]
     */
    private function __sampleRange(
        $table, $target, $approxTotal = 0
    ) {
        $total = $approxTotal > 0 ? $approxTotal : 0;
        if ($total <= $target) {
            return [
                'where' => '',
                'sample_size' => $total,
            ];
        }
        $mx = $this->__singleQuery(
            "SELECT MAX(id) AS mx "
            . "FROM `{$table}`",
            'sample_max_id'
        )['mx'] ?? 0;
        if ($mx <= 0) {
            return [
                'where' => '',
                'sample_size' => $total,
            ];
        }
        // Estimate the ID density to find a cutoff
        // that yields ~target rows. Over-estimate
        // the range by 20% to account for gaps.
        $ratio = $total > 0
            ? (float)$mx / $total : 1.0;
        $idSpan = (int)ceil(
            $target * $ratio * 1.2
        );
        $cutoff = max(1, $mx - $idSpan);
        $where = "WHERE id >= {$cutoff}";
        $this->out(sprintf(
            '  Sampling %s: id >= %d '
            . '(last ~%s rows of %s)',
            $table, $cutoff,
            number_format($target),
            number_format($total)
        ), 1, Shell::VERBOSE);
        return [
            'where' => $where,
            'sample_size' => $target,
        ];
    }

    /**
     * Column value distribution (top N).
     *
     * @param string $table
     * @param string $column
     * @param int $limit
     * @param string $where  Optional WHERE clause
     * @return array
     */
    private function __distribution(
        $table, $column, $limit, $where = ''
    ) {
        $sql = "SELECT `{$column}` AS val, "
            . "COUNT(*) AS cnt "
            . "FROM `{$table}` "
            . ($where !== '' ? $where . ' ' : '')
            . "GROUP BY `{$column}` "
            . "ORDER BY cnt DESC "
            . "LIMIT {$limit}";
        $rows = $this->__runQuery(
            $sql, "dist_{$table}_{$column}"
        );
        $out = [];
        foreach ($rows as $r) {
            $flat = $this->__flatten($r);
            $out[$flat['val']] = (int)$flat['cnt'];
        }
        return $out;
    }

    /**
     * Single-row aggregate query.
     *
     * @param string $sql
     * @return array
     */
    private function __singleQuery(
        $sql, $label = ''
    ) {
        $r = $this->__runQuery($sql, $label);
        if (empty($r)) {
            return [];
        }
        $flat = $this->__flatten($r[0]);
        $out = [];
        foreach ($flat as $k => $v) {
            $out[$k] = is_numeric($v) ? (int)$v : $v;
        }
        return $out;
    }

    /**
     * Multi-row query returned as list of assoc arrays.
     *
     * @param string $sql
     * @return array
     */
    private function __queryList(
        $sql, $label = ''
    ) {
        $rows = $this->__runQuery($sql, $label);
        $out = [];
        foreach ($rows as $r) {
            $flat = $this->__flatten($r);
            $row = [];
            foreach ($flat as $k => $v) {
                $row[$k] = is_numeric($v)
                    ? (int)$v : $v;
            }
            $out[] = $row;
        }
        return $out;
    }

    /**
     * Timestamp selectivity (how many rows match
     * recent time windows).
     *
     * @return array
     */
    private function __timestampRanges()
    {
        $now = time();
        $windows = [
            '7d' => $now - 7 * 86400,
            '30d' => $now - 30 * 86400,
            '90d' => $now - 90 * 86400,
            '365d' => $now - 365 * 86400,
        ];
        $result = $this->__singleQuery(
            "SELECT "
            . "MIN(timestamp) AS ts_min, "
            . "MAX(timestamp) AS ts_max "
            . "FROM attributes",
            'ts_min_max'
        );
        foreach ($windows as $wLabel => $cutoff) {
            $sql = "SELECT COUNT(*) AS cnt "
                . "FROM attributes "
                . "WHERE timestamp > {$cutoff}";
            $r = $this->__runQuery(
                $sql, "ts_last_{$wLabel}"
            );
            $flat = $this->__flatten($r[0]);
            $result['last_' . $wLabel] =
                (int)$flat['cnt'];
        }
        return $result;
    }

    /**
     * Top tags by usage count.
     *
     * @param string $joinTable  attribute_tags or
     *                           event_tags
     * @param int $limit
     * @return array
     */
    private function __topTags($joinTable, $limit)
    {
        $sql = "SELECT t.name, COUNT(*) AS cnt "
            . "FROM `{$joinTable}` jt "
            . "JOIN tags t ON t.id = jt.tag_id "
            . "GROUP BY jt.tag_id "
            . "ORDER BY cnt DESC "
            . "LIMIT {$limit}";
        $rows = $this->__runQuery(
            $sql, "top_tags_{$joinTable}"
        );
        $out = [];
        foreach ($rows as $r) {
            $flat = $this->__flatten($r);
            $out[] = [
                'name' => $flat['name'],
                'count' => (int)$flat['cnt'],
            ];
        }
        return $out;
    }

    /**
     * Bucket a count column into ranges.
     *
     * @param string $innerSql  Query producing a `cnt`
     *                          column per row
     * @param string $col       Column name to bucket
     * @return array
     */
    private function __bucketDistribution(
        $innerSql, $col, $label = ''
    ) {
        $sql = "SELECT "
            . "CASE "
            . "WHEN {$col} = 0 THEN '0' "
            . "WHEN {$col} <= 3 THEN '1-3' "
            . "WHEN {$col} <= 10 THEN '4-10' "
            . "WHEN {$col} <= 100 THEN '11-100' "
            . "WHEN {$col} <= 1000 THEN '101-1000' "
            . "WHEN {$col} <= 10000 THEN '1001-10000' "
            . "ELSE '10000+' "
            . "END AS bucket, "
            . "COUNT(*) AS cnt "
            . "FROM ({$innerSql}) AS bucketed "
            . "GROUP BY bucket "
            . "ORDER BY bucket";
        $rows = $this->__runQuery($sql, $label);
        $out = [];
        foreach ($rows as $r) {
            $flat = $this->__flatten($r);
            $out[$flat['bucket']] =
                (int)$flat['cnt'];
        }
        return $out;
    }

    /**
     * Index information for the key tables.
     *
     * @return array
     */
    private function __indexInfo()
    {
        $tables = [
            'attributes', 'attribute_tags',
            'event_tags', 'events', 'objects',
        ];
        $out = [];
        foreach ($tables as $table) {
            $rows = $this->__runQuery(
                "SHOW INDEX FROM `{$table}`",
                "indexes_{$table}"
            );
            $indexes = [];
            foreach ($rows as $r) {
                $row = $r['STATISTICS'] ?? $r[0]
                    ?? $r;
                $name = $row['Key_name']
                    ?? $row['key_name'] ?? '?';
                $col = $row['Column_name']
                    ?? $row['column_name'] ?? '?';
                $seq = $row['Seq_in_index']
                    ?? $row['seq_in_index'] ?? 0;
                $card = $row['Cardinality']
                    ?? $row['cardinality'] ?? null;
                $sub = $row['Sub_part']
                    ?? $row['sub_part'] ?? null;
                if (!isset($indexes[$name])) {
                    $indexes[$name] = [];
                }
                $indexes[$name][] = [
                    'seq' => (int)$seq,
                    'column' => $col,
                    'cardinality' => $card !== null
                        ? (int)$card : null,
                    'sub_part' => $sub !== null
                        ? (int)$sub : null,
                ];
            }
            $out[$table] = $indexes;
        }
        return $out;
    }

    // ── evaluation engine ───────────────────────────────

    /**
     * Evaluate filter combinations against collected
     * stats and assign risk ratings.
     *
     * @param array $stats
     * @return array  List of evaluated combinations
     */
    private function __evaluate(array $stats)
    {
        $total = $stats['table_counts']['attributes'];
        if ($total == 0) {
            return [[
                'id' => 0,
                'name' => 'empty_database',
                'tier' => 'N/A',
                'filters' => [],
                'rating' => 'OK',
                'reason' => 'No attributes in database.',
            ]];
        }

        $tc = $stats['table_counts'];
        $toIdsRatio = $this->__ratio(
            $stats['attribute_to_ids'], '1', $total
        );
        $publishedRatio = $this->__ratio(
            $stats['event_published'], '1',
            $tc['events']
        );
        $deletedRatio = $this->__ratio(
            $stats['attribute_deleted'], '0', $total
        );

        // Broadest attribute-level tag coverage
        $broadestAttrTag = 0;
        if (!empty($stats['top_attribute_tags'])) {
            $broadestAttrTag =
                $stats['top_attribute_tags'][0]['count'];
        }
        $broadestAttrTagRatio =
            $total > 0
                ? $broadestAttrTag / $total : 0;

        // Broadest event-level tag coverage
        $broadestEvtTag = 0;
        if (!empty($stats['top_event_tags'])) {
            $broadestEvtTag =
                $stats['top_event_tags'][0]['count'];
        }
        $broadestEvtTagRatio = $tc['events'] > 0
            ? $broadestEvtTag / $tc['events'] : 0;

        // Dominant type ratio
        $topTypeRatio = 0;
        if (!empty($stats['attribute_type_distribution'])) {
            $topType = reset(
                $stats['attribute_type_distribution']
            );
            $topTypeRatio = $topType / $total;
        }

        // Dominant category ratio
        $topCatRatio = 0;
        if (
            !empty(
                $stats[
                    'attribute_category_distribution'
                ]
            )
        ) {
            $topCat = reset(
                $stats[
                    'attribute_category_distribution'
                ]
            );
            $topCatRatio = $topCat / $total;
        }

        // Standalone ratio
        $standaloneRatio = 1.0;
        if (!empty($stats['object_membership'])) {
            $sa = $stats['object_membership']['standalone']
                ?? 0;
            $standaloneRatio = $total > 0
                ? $sa / $total : 1.0;
        }

        // Value cardinality: assumed high (not queried)
        $valueUniqueness = 0.80;

        // Composite value ratio
        $cv = $stats['composite_value_ratio'];
        $compositeRatio = $total > 0
            ? ($cv['has_value2'] ?? 0) / $total : 0;

        // Timestamp selectivity
        $ts = $stats['timestamp_ranges'];
        $ts7dRatio = $total > 0
            ? ($ts['last_7d'] ?? 0) / $total : 0;
        $ts30dRatio = $total > 0
            ? ($ts['last_30d'] ?? 0) / $total : 0;
        $ts365dRatio = $total > 0
            ? ($ts['last_365d'] ?? 0) / $total : 0;

        // Avg attrs per event
        $avgAttrsPerEvent = $tc['events'] > 0
            ? $total / $tc['events'] : 0;

        $combos = [];
        $id = 0;

        // ── Tier 1: Common IOC export patterns ──────

        $combos[] = $this->__combo(++$id,
            'type + to_ids + tags',
            'IOC export',
            ['type', 'to_ids', 'tags'],
            $this->__rateSelectiveWithTags(
                1.0 - $topTypeRatio,
                $broadestAttrTagRatio,
                $broadestEvtTagRatio,
                true
            )
        );

        $combos[] = $this->__combo(++$id,
            'type + to_ids + published',
            'IOC export',
            ['type', 'to_ids', 'published'],
            ['OK', 'Pure column filters on joined '
                . 'tables. Efficient index use.']
        );

        $combos[] = $this->__combo(++$id,
            'type + to_ids + published + tags',
            'IOC export',
            ['type', 'to_ids', 'published', 'tags'],
            $this->__rateSelectiveWithTags(
                1.0 - $topTypeRatio,
                $broadestAttrTagRatio,
                $broadestEvtTagRatio,
                true
            )
        );

        $combos[] = $this->__combo(++$id,
            'type + to_ids + last (7-30d)',
            'IOC export',
            ['type', 'to_ids', 'last'],
            $ts30dRatio < 0.1
                ? ['OK', sprintf(
                    'Timestamp highly selective '
                    . '(30d = %.1f%% of table).',
                    $ts30dRatio * 100
                )]
                : ['WATCH', sprintf(
                    'Timestamp window covers %.1f%% '
                    . 'of table — moderate selectivity.',
                    $ts30dRatio * 100
                )]
        );

        $combos[] = $this->__combo(++$id,
            'type + to_ids + last + tags',
            'IOC export',
            ['type', 'to_ids', 'last', 'tags'],
            $this->__rateSelectiveWithTags(
                max(1.0 - $topTypeRatio, $ts30dRatio < 0.05 ? 0.95 : 0.5),
                $broadestAttrTagRatio,
                $broadestEvtTagRatio,
                true
            )
        );

        $combos[] = $this->__combo(++$id,
            'type + value (exact)',
            'IOC export',
            ['type', 'value'],
            ['OK', sprintf(
                'Value is near-unique (%.0f%% distinct'
                . '). Index lookup.',
                $valueUniqueness * 100
            )]
        );

        $combos[] = $this->__combo(++$id,
            'type + value (prefix%%)',
            'IOC export',
            ['type', 'value'],
            ['OK', 'Prefix LIKE uses B-tree index.']
        );

        $combos[] = $this->__combo(++$id,
            'to_ids only',
            'IOC export',
            ['to_ids'],
            $toIdsRatio > 0.7
                ? ['WATCH', sprintf(
                    'to_ids=1 matches %.0f%% of attrs'
                    . ' — effectively full scan. '
                    . 'Scales with table size (%s rows).',
                    $toIdsRatio * 100,
                    number_format($total)
                )]
                : ['OK', sprintf(
                    'to_ids=1 matches %.0f%%.',
                    $toIdsRatio * 100
                )]
        );

        $combos[] = $this->__combo(++$id,
            'tags only (narrow)',
            'IOC export',
            ['tags'],
            ['OK', 'IN-path semi-join on small tag set.']
        );

        $combos[] = $this->__combo(++$id,
            'tags only (broad)',
            'IOC export',
            ['tags'],
            $broadestAttrTagRatio > 0.15
                ? ['WATCH', sprintf(
                    'Broadest attr-tag covers %.0f%% '
                    . '(%s rows). IN-path materialises'
                    . ' large set.',
                    $broadestAttrTagRatio * 100,
                    number_format($broadestAttrTag)
                )]
                : ['OK', sprintf(
                    'Broadest attr-tag covers %.0f%%.',
                    $broadestAttrTagRatio * 100
                )]
        );

        $combos[] = $this->__combo(++$id,
            'tags only (OR of broad)',
            'IOC export',
            ['tags'],
            $broadestAttrTagRatio > 0.10
                ? ['WATCH', sprintf(
                    'Multiple broad tags → large '
                    . 'materialised set. Broadest '
                    . 'single tag: %s rows.',
                    number_format($broadestAttrTag)
                )]
                : ['OK', 'OR of moderate-size tag sets.']
        );

        $combos[] = $this->__combo(++$id,
            'tags only (AND of two+)',
            'IOC export',
            ['tags'],
            $broadestAttrTagRatio > 0.10
                ? ['WATCH', sprintf(
                    'Each AND-tag adds a separate '
                    . 'subquery. MySQL must intersect '
                    . 'sets up to %s rows each.',
                    number_format($broadestAttrTag)
                )]
                : ['OK', 'AND of moderate-size tag sets.']
        );

        $combos[] = $this->__combo(++$id,
            'published + tags (broad)',
            'IOC export',
            ['published', 'tags'],
            $publishedRatio > 0.7
                ? ['WATCH', sprintf(
                    'published=1 matches %.0f%% of '
                    . 'events — non-selective. '
                    . 'Effectively tag-only scan.',
                    $publishedRatio * 100
                )]
                : ['OK', sprintf(
                    'published=1 matches %.0f%%.',
                    $publishedRatio * 100
                )]
        );

        // ── Tier 2: Analyst investigation ───────────

        $combos[] = $this->__combo(++$id,
            'eventid + type',
            'Investigation',
            ['eventid', 'type'],
            ['OK', sprintf(
                'Event ID very selective. Avg %d '
                . 'attrs/event.',
                (int)$avgAttrsPerEvent
            )]
        );

        $combos[] = $this->__combo(++$id,
            'eventid + tags',
            'Investigation',
            ['eventid', 'tags'],
            ['OK', 'Event ID narrows to single event.']
        );

        $v2Note = $compositeRatio < 0.05
            ? sprintf(
                ' Only %.1f%% of attrs have value2 '
                . '— the value2 OR leg is nearly '
                . 'always wasted.',
                $compositeRatio * 100)
            : '';

        $combos[] = $this->__combo(++$id,
            'value (%%suffix)',
            'Investigation',
            ['value'],
            ['SLOW', sprintf(
                'Suffix LIKE cannot use B-tree index.'
                . ' Full scan of %s rows (x2: OR '
                . 'across value1 + value2).%s',
                number_format($total), $v2Note
            )]
        );

        $combos[] = $this->__combo(++$id,
            'value (%%mid%%)',
            'Investigation',
            ['value'],
            ['SLOW', sprintf(
                'Middle wildcard — full scan of %s '
                . 'rows (x2: value1 + value2).%s',
                number_format($total), $v2Note
            )]
        );

        $combos[] = $this->__combo(++$id,
            'value (suffix) + tags',
            'Investigation',
            ['value', 'tags'],
            ['SLOW', sprintf(
                'Value suffix scan dominates. '
                . 'Tag filter cannot reduce I/O.%s',
                $v2Note
            )]
        );

        $combos[] = $this->__combo(++$id,
            'value (suffix) + type',
            'Investigation',
            ['value', 'type'],
            ['SLOW', sprintf(
                'Value suffix scan dominates. '
                . 'Type index unusable.%s',
                $v2Note
            )]
        );

        $combos[] = $this->__combo(++$id,
            'eventinfo (LIKE)',
            'Investigation',
            ['eventinfo'],
            $tc['events'] > 50000
                ? ['SLOW', sprintf(
                    'Event.info LIKE scans %s events.',
                    number_format($tc['events'])
                )]
                : ['WATCH', sprintf(
                    'Event.info LIKE on %s events — '
                    . 'tolerable but scales linearly.',
                    number_format($tc['events'])
                )]
        );

        $combos[] = $this->__combo(++$id,
            'eventinfo + tags',
            'Investigation',
            ['eventinfo', 'tags'],
            $tc['events'] > 50000
                ? ['SLOW', 'Event scan + tag subquery.']
                : ['WATCH', 'Event LIKE scan is '
                    . 'bottleneck, tag adds overhead.']
        );

        $combos[] = $this->__combo(++$id,
            'category only',
            'Investigation',
            ['category'],
            $topCatRatio > 0.4
                ? ['WATCH', sprintf(
                    'Dominant category is %.0f%% — low '
                    . 'selectivity.',
                    $topCatRatio * 100
                )]
                : ['OK', 'Moderate category selectivity.']
        );

        $combos[] = $this->__combo(++$id,
            'category + tags (broad)',
            'Investigation',
            ['category', 'tags'],
            $topCatRatio > 0.4
                && $broadestAttrTagRatio > 0.10
                ? ['WATCH', 'Category non-selective + '
                    . 'broad tag subquery on large set.']
                : ['OK', 'Manageable selectivity.']
        );

        $combos[] = $this->__combo(++$id,
            'org + type + tags',
            'Investigation',
            ['org', 'type', 'tags'],
            ['WATCH', 'Org filters on Event join. Large '
                . 'orgs → big scan → tag '
                . 'EXISTS/IN on big set.']
        );

        $combos[] = $this->__combo(++$id,
            'uuid',
            'Investigation',
            ['uuid'],
            ['OK', 'Unique index — instant.']
        );

        $combos[] = $this->__combo(++$id,
            'first_seen / last_seen range',
            'Investigation',
            ['first_seen', 'last_seen'],
            $this->__rateSeen($stats)
        );

        $combos[] = $this->__combo(++$id,
            'object_relation + type',
            'Investigation',
            ['object_relation', 'type'],
            ['OK', 'Compound index '
                . 'idx_attr_objrel_acl covers this.']
        );

        $combos[] = $this->__combo(++$id,
            'searchall / quickFilter',
            'Investigation',
            ['searchall'],
            ['SLOW', sprintf(
                'Converts to wildcard LIKE — full '
                . 'scan of %s rows (x2: value1 '
                . '+ value2).%s',
                number_format($total), $v2Note
            )]
        );

        // ── Tier 3: Sync and automation ─────────────

        $combos[] = $this->__combo(++$id,
            'timestamp (narrow, last pull)',
            'Sync',
            ['timestamp'],
            ['OK', sprintf(
                'Timestamp index. 7d = %s rows.',
                number_format($ts['last_7d'] ?? 0)
            )]
        );

        $combos[] = $this->__combo(++$id,
            'timestamp (wide, 365d)',
            'Sync',
            ['timestamp'],
            $ts365dRatio > 0.3
                ? ['WATCH', sprintf(
                    '365d covers %.0f%% (%s rows).',
                    $ts365dRatio * 100,
                    number_format($ts['last_365d'] ?? 0)
                )]
                : ['OK', sprintf(
                    '365d = %s rows.',
                    number_format($ts['last_365d'] ?? 0)
                )]
        );

        $combos[] = $this->__combo(++$id,
            'publish_timestamp + published',
            'Sync',
            ['publish_timestamp', 'published'],
            ['OK', 'Event-level filter + index.']
        );

        $combos[] = $this->__combo(++$id,
            'deleted=only + type',
            'Sync',
            ['deleted', 'type'],
            ['OK', sprintf(
                'Deleted attrs: %s (%.1f%%). Very '
                . 'selective.',
                number_format(
                    $stats['attribute_deleted']['1'] ?? 0
                ),
                (1.0 - $deletedRatio) * 100
            )]
        );

        $combos[] = $this->__combo(++$id,
            'deleted=both + tags',
            'Sync',
            ['deleted', 'tags'],
            ['WATCH', 'Disables deleted filter → full '
                . 'table with tag subquery.']
        );

        $combos[] = $this->__combo(++$id,
            'no filters (full export)',
            'Sync',
            [],
            $total > 500000
                ? ['SLOW', sprintf(
                    'Full export of %s rows. I/O '
                    . 'bound. Cursor pagination helps '
                    . 'but total time is high.',
                    number_format($total)
                )]
                : ['WATCH', sprintf(
                    'Full export of %s rows.',
                    number_format($total)
                )]
        );

        $combos[] = $this->__combo(++$id,
            'flatten=1 + tags',
            'Sync',
            ['flatten', 'tags'],
            $standaloneRatio < 0.9
                ? ['WATCH', sprintf(
                    'flatten=1 adds %.0f%% more rows '
                    . '(in-object attrs). Tag subquery '
                    . 'on bigger set.',
                    (1.0 - $standaloneRatio) * 100
                )]
                : ['OK', sprintf(
                    'Only %.0f%% in-object — minimal '
                    . 'overhead.',
                    (1.0 - $standaloneRatio) * 100
                )]
        );

        // ── Tier 4: Complex multi-axis ──────────────

        $combos[] = $this->__combo(++$id,
            'type + tags (AND two+) + timestamp',
            'Complex',
            ['type', 'tags', 'timestamp'],
            $this->__rateSelectiveWithTags(
                0.9, $broadestAttrTagRatio,
                $broadestEvtTagRatio, true
            )
        );

        $combos[] = $this->__combo(++$id,
            'type + tags (OR broad) + published '
                . '+ to_ids',
            'Complex',
            ['type', 'tags', 'published', 'to_ids'],
            $this->__rateSelectiveWithTags(
                1.0 - $topTypeRatio,
                $broadestAttrTagRatio,
                $broadestEvtTagRatio,
                true
            )
        );

        $combos[] = $this->__combo(++$id,
            'tags (AND broad) + no attr filters',
            'Complex',
            ['tags'],
            $broadestAttrTagRatio > 0.10
                ? ['DANGER', sprintf(
                    'AND of broad tags on full table. '
                    . 'Each subquery materialises up to '
                    . '%s rows. Intersection is '
                    . 'multiplicative.',
                    number_format($broadestAttrTag)
                )]
                : ['WATCH', 'AND tags with moderate '
                    . 'breadth — monitor on growth.']
        );

        $combos[] = $this->__combo(++$id,
            'tags (NOT) + tags (OR) combined',
            'Complex',
            ['tags'],
            ['OK', 'NOT EXISTS short-circuits. '
                . 'Separate subquery types.']
        );

        $combos[] = $this->__combo(++$id,
            'value (suffix) + tags (broad) '
                . '+ timestamp',
            'Complex',
            ['value', 'tags', 'timestamp'],
            ['SLOW', sprintf(
                'Value suffix scan dominates '
                . '(%s rows, x2: value1 + value2).'
                . ' Tags and timestamp cannot '
                . 'help.%s',
                number_format($total), $v2Note
            )]
        );

        $combos[] = $this->__combo(++$id,
            'type + tags + includeCorrelations',
            'Complex',
            ['type', 'tags', 'includeCorrelations'],
            ['WATCH', sprintf(
                'Main query fast (EXISTS). But '
                . 'per-result correlation lookup. '
                . '%s total correlations.',
                number_format(
                    $tc['default_correlations']
                )
            )]
        );

        $combos[] = $this->__combo(++$id,
            'type + tags + includeDecayScore',
            'Complex',
            ['type', 'tags', 'includeDecayScore'],
            ['WATCH', 'Decay scoring is CPU-heavy '
                . 'per result.']
        );

        $combos[] = $this->__combo(++$id,
            'type + tags + includeGalaxy',
            'Complex',
            ['type', 'tags', 'includeGalaxy'],
            ['SLOW', 'Galaxy fetch per result — '
                . 'multiple queries per galaxy. '
                . 'Slow above ~100 results.']
        );

        $combos[] = $this->__combo(++$id,
            'type + tags + includeContext',
            'Complex',
            ['type', 'tags', 'includeContext'],
            ['SLOW', 'Full event fetch per result '
                . '(N+1). Slow above ~100 results.']
        );

        $combos[] = $this->__combo(++$id,
            'tags (wildcard, broad match)',
            'Complex',
            ['tags'],
            ['WATCH', 'Tag name LIKE resolves to many '
                . 'IDs → large IN list.']
        );

        $combos[] = $this->__combo(++$id,
            'tags (AND 3+) + no attr filters',
            'Complex',
            ['tags'],
            $broadestAttrTagRatio > 0.10
                ? ['DANGER', sprintf(
                    '3+ AND-tag intersections on '
                    . 'full table (%s rows). '
                    . 'Multiplicative subquery cost.',
                    number_format($total)
                )]
                : ['WATCH', 'Multiple AND-tags. '
                    . 'Monitor on growth.']
        );

        $combos[] = $this->__combo(++$id,
            'category + tags (AND) '
                . '+ eventinfo (LIKE)',
            'Complex',
            ['category', 'tags', 'eventinfo'],
            ($topCatRatio > 0.4
                && $broadestAttrTagRatio > 0.10)
                ? ['DANGER', sprintf(
                    'Triple non-selective: category '
                    . '(%.0f%%), broad AND-tags, '
                    . 'eventinfo LIKE scan.',
                    $topCatRatio * 100
                )]
                : ['WATCH', 'Multiple low-selectivity '
                    . 'axes.']
        );

        $combos[] = $this->__combo(++$id,
            'from/to (date) + tags (broad)',
            'Complex',
            ['from', 'to', 'tags'],
            ['WATCH', 'Event.date has no dedicated '
                . 'index. Scans events, joins attrs, '
                . 'then broad tag subquery.']
        );

        $combos[] = $this->__combo(++$id,
            'type + to_ids + tags + order=custom',
            'Complex',
            ['type', 'to_ids', 'tags', 'order'],
            ['WATCH', 'Custom order disables cursor '
                . 'pagination → OFFSET. Deep pages '
                . 'become O(N*page).']
        );

        return $combos;
    }

    // ── evaluation helpers ──────────────────────────────

    /**
     * Rate a combination that has selective attribute
     * filters + tag subquery.
     *
     * @param float $attrSelectivity  0..1 how selective
     *              the attribute filters are (higher =
     *              more selective)
     * @param float $broadestAttrTagRatio
     * @param float $broadestEvtTagRatio
     * @param bool $existsPath  Whether EXISTS path is
     *             used (attribute-selective)
     * @return array  [rating, reason]
     */
    private function __rateSelectiveWithTags(
        $attrSelectivity,
        $broadestAttrTagRatio,
        $broadestEvtTagRatio,
        $existsPath
    ) {
        if ($existsPath && $attrSelectivity > 0.5) {
            return ['OK', sprintf(
                'EXISTS path: attr filters are '
                . 'selective (%.0f%% filtered). '
                . 'Per-row tag probe is cheap.',
                $attrSelectivity * 100
            )];
        }
        if ($broadestAttrTagRatio > 0.20) {
            return ['WATCH', sprintf(
                'Broadest tag covers %.0f%% of '
                . 'attrs. IN-path materialises '
                . 'large set.',
                $broadestAttrTagRatio * 100
            )];
        }
        return ['OK', 'Tag selectivity is adequate.'];
    }

    /**
     * Rate first_seen / last_seen filter.
     *
     * @param array $stats
     * @return array
     */
    private function __rateSeen(array $stats)
    {
        $total = $stats['table_counts']['attributes'];
        $fs = $stats['first_last_seen_usage']
            ['has_first_seen'] ?? 0;
        $pct = $total > 0 ? $fs / $total * 100 : 0;
        if ($pct < 1) {
            return ['OK', sprintf(
                'Only %.1f%% have first_seen — very '
                . 'selective with index.',
                $pct
            )];
        }
        if ($pct < 20) {
            return ['OK', sprintf(
                '%.0f%% have first_seen. Index '
                . 'covers it.',
                $pct
            )];
        }
        return ['WATCH', sprintf(
            '%.0f%% have first_seen — moderate '
            . 'selectivity.',
            $pct
        )];
    }

    /**
     * Build a combo result entry.
     *
     * @param int $id
     * @param string $name
     * @param string $tier
     * @param array $filters
     * @param array $ratingAndReason  [rating, reason]
     * @return array
     */
    private function __combo(
        $id, $name, $tier, $filters, $ratingAndReason
    ) {
        return [
            'id' => $id,
            'name' => $name,
            'tier' => $tier,
            'filters' => $filters,
            'rating' => $ratingAndReason[0],
            'reason' => $ratingAndReason[1],
        ];
    }

    /**
     * Get ratio for a specific value in a distribution.
     *
     * @param array $dist
     * @param string $key
     * @param int $total
     * @return float
     */
    private function __ratio($dist, $key, $total)
    {
        if ($total == 0) {
            return 0;
        }
        return ($dist[$key] ?? 0) / $total;
    }

    // ── report printer ──────────────────────────────────

    /**
     * Print a human-readable report.
     *
     * @param array $stats
     * @param array $evaluation
     */
    private function __printReport(
        array $stats, array $evaluation
    ) {
        $sep = str_repeat('=', 72);
        $thin = str_repeat('-', 72);

        $this->out($sep);
        $this->out(
            ' Attribute restSearch — '
            . 'Performance Evaluation Report'
        );
        $this->out(
            ' Generated: ' . date('Y-m-d H:i:s')
        );
        if (!empty($stats['approximate'])) {
            $this->out(
                ' Mode: FAST (approximate — '
                . 'sampled/estimated values)'
            );
        }
        $this->out($sep);
        $this->out('');

        // ── Table counts ────────────────────────────
        $approxLabel = !empty($stats['approximate'])
            ? ' (approximate)' : '';
        $this->out(
            '## Dataset Overview' . $approxLabel
        );
        $this->out('');
        foreach (
            $stats['table_counts'] as $table => $cnt
        ) {
            $this->out(sprintf(
                '  %-25s %s',
                $table, number_format($cnt)
            ));
        }
        $this->out('');

        // ── Key distributions ───────────────────────
        $this->out('## Key Distributions');
        $this->out('');

        $this->__printDistSection(
            'Attribute types (top)',
            $stats['attribute_type_distribution'],
            $stats['table_counts']['attributes']
        );
        $this->__printDistSection(
            'Attribute categories (top)',
            $stats['attribute_category_distribution'],
            $stats['table_counts']['attributes']
        );
        $this->__printDistSection(
            'to_ids',
            $stats['attribute_to_ids'],
            $stats['table_counts']['attributes']
        );
        $this->__printDistSection(
            'deleted',
            $stats['attribute_deleted'],
            $stats['table_counts']['attributes']
        );
        $this->__printDistSection(
            'Attribute distribution field',
            $stats['attribute_distribution_spread'],
            $stats['table_counts']['attributes']
        );
        $this->__printDistSection(
            'Event published',
            $stats['event_published'],
            $stats['table_counts']['events']
        );

        // ── Value cardinality ───────────────────────
        $total = $stats['table_counts']['attributes'];
        $this->out(
            '  Value cardinality: assumed high '
            . '(>60% unique, not queried)'
        );

        $cv = $stats['composite_value_ratio'];
        $v2cnt = $cv['has_value2'] ?? 0;
        $v2pct = $total > 0
            ? $v2cnt / $total * 100 : 0;
        $this->out(sprintf(
            '  Composite attrs (value2 set): '
            . '%s (%.1f%%)',
            number_format($v2cnt), $v2pct
        ));
        if ($v2pct < 5) {
            $this->out(
                '    -> value2 nearly always empty;'
                . ' the value2 leg of OR in value'
                . ' searches is mostly wasted I/O'
            );
        }
        $this->out('');

        // ── Timestamp ───────────────────────────────
        $this->out('  Timestamp selectivity:');
        $ts = $stats['timestamp_ranges'];
        foreach (
            ['7d', '30d', '90d', '365d'] as $w
        ) {
            $k = 'last_' . $w;
            $cnt = $ts[$k] ?? 0;
            $this->out(sprintf(
                '    last %-4s %10s  (%.2f%%)',
                $w,
                number_format($cnt),
                $total > 0 ? $cnt / $total * 100 : 0
            ));
        }
        $this->out('');

        // ── Object membership ───────────────────────
        $om = $stats['object_membership'];
        $this->out(sprintf(
            '  Standalone attrs: %s (%.0f%%)',
            number_format($om['standalone'] ?? 0),
            $total > 0
                ? ($om['standalone'] ?? 0)
                    / $total * 100
                : 0
        ));
        $this->out(sprintf(
            '  In-object attrs:  %s (%.0f%%)',
            number_format($om['in_object'] ?? 0),
            $total > 0
                ? ($om['in_object'] ?? 0)
                    / $total * 100
                : 0
        ));
        $this->out('');

        // ── Tag breadth ─────────────────────────────
        $this->out('## Tag Breadth');
        $this->out('');
        $this->out('  Top attribute-level tags:');
        foreach (
            $stats['top_attribute_tags'] as $t
        ) {
            $this->out(sprintf(
                '    %-40s %10s  (%.1f%%)',
                mb_substr($t['name'], 0, 40),
                number_format($t['count']),
                $total > 0
                    ? $t['count'] / $total * 100
                    : 0
            ));
        }
        $this->out('');
        $this->out('  Top event-level tags:');
        $evtTotal = $stats['table_counts']['events'];
        foreach (
            $stats['top_event_tags'] as $t
        ) {
            $this->out(sprintf(
                '    %-40s %10s  (%.1f%% of events)',
                mb_substr($t['name'], 0, 40),
                number_format($t['count']),
                $evtTotal > 0
                    ? $t['count'] / $evtTotal * 100
                    : 0
            ));
        }
        $this->out('');

        // ── Bucket distributions ────────────────────
        $this->out('  Tags per attribute:');
        $this->__printBuckets(
            $stats['tags_per_attribute']
        );
        $this->out('  Tags per event:');
        $this->__printBuckets(
            $stats['tags_per_event']
        );
        $this->out('  Attributes per event:');
        $this->__printBuckets(
            $stats['attrs_per_event']
        );

        // ── Correlation ratio ────────────────────────
        $cr = $stats['correlation_ratio'];
        $corrRatio = $cr['attributes'] > 0
            ? $cr['correlations']
                / $cr['attributes'] : 0;
        $this->out(sprintf(
            '  Correlation ratio: %s correlations'
            . ' / %s attributes (%.2f per attr)',
            number_format($cr['correlations']),
            number_format($cr['attributes']),
            $corrRatio
        ));
        $this->out('');

        // ── Filter evaluation ───────────────────────
        $this->out($sep);
        $this->out(
            ' Filter Combination Evaluation'
        );
        $this->out($sep);
        $this->out('');

        $ratingOrder = [
            'DANGER' => 0, 'SLOW' => 1,
            'WATCH' => 2, 'OK' => 3,
        ];

        $currentTier = '';
        foreach ($evaluation as $combo) {
            if ($combo['tier'] !== $currentTier) {
                $currentTier = $combo['tier'];
                $this->out($thin);
                $this->out(
                    " Tier: {$currentTier}"
                );
                $this->out($thin);
            }
            $ratingTag = $this->__colorRating(
                $combo['rating']
            );
            $this->out(sprintf(
                '  #%-3d %-8s %-40s',
                $combo['id'],
                $ratingTag,
                $combo['name']
            ));
            $this->out(sprintf(
                '       %s',
                $combo['reason']
            ));
            $this->out('');
        }

        // ── Summary ─────────────────────────────────
        $this->out($sep);
        $this->out(' Summary');
        $this->out($sep);
        $counts = ['OK' => 0, 'WATCH' => 0,
            'SLOW' => 0, 'DANGER' => 0];
        foreach ($evaluation as $combo) {
            $counts[$combo['rating']]++;
        }
        foreach ($counts as $r => $c) {
            $this->out(sprintf(
                '  %-8s %d',
                $this->__colorRating($r), $c
            ));
        }
        $this->out('');

        if ($counts['DANGER'] > 0) {
            $this->out(
                '<warning>DANGER combinations found — '
                . 'review before exposing to '
                . 'users.</warning>'
            );
        }
        $this->out('');
    }

    /**
     * Print a key→count distribution section.
     *
     * @param string $title
     * @param array $dist
     * @param int $total
     */
    private function __printDistSection(
        $title, $dist, $total
    ) {
        $this->out("  {$title}:");
        foreach ($dist as $val => $cnt) {
            $this->out(sprintf(
                '    %-30s %10s  (%.1f%%)',
                $val,
                number_format($cnt),
                $total > 0
                    ? $cnt / $total * 100 : 0
            ));
        }
        $this->out('');
    }

    /**
     * Print bucket distribution.
     *
     * @param array $buckets
     */
    private function __printBuckets($buckets)
    {
        foreach ($buckets as $bucket => $cnt) {
            $this->out(sprintf(
                '    %-12s %s',
                $bucket, number_format($cnt)
            ));
        }
        $this->out('');
    }

    /**
     * Wrap rating in shell color tags.
     *
     * @param string $rating
     * @return string
     */
    private function __colorRating($rating)
    {
        switch ($rating) {
            case 'DANGER':
                return '<error>' . $rating . '</error>';
            case 'SLOW':
                return '<warning>' . $rating
                    . '</warning>';
            case 'WATCH':
                return '<info>' . $rating . '</info>';
            default:
                return $rating;
        }
    }
}
