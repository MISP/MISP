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

        if (!empty($this->params['json'])) {
            $this->out($this->json([
                'stats' => $stats,
                'evaluation' => $evaluation,
            ]));
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
        $stats = [];
        $stats['table_counts'] = $this->__tableCounts();
        $stats['attribute_type_distribution'] =
            $this->__distribution(
                'attributes', 'type', 20
            );
        $stats['attribute_category_distribution'] =
            $this->__distribution(
                'attributes', 'category', 15
            );
        $stats['attribute_distribution_spread'] =
            $this->__distribution(
                'attributes', 'distribution', 10
            );
        $stats['attribute_to_ids'] =
            $this->__distribution(
                'attributes', 'to_ids', 2
            );
        $stats['attribute_deleted'] =
            $this->__distribution(
                'attributes', 'deleted', 3
            );
        $stats['event_published'] =
            $this->__distribution(
                'events', 'published', 2
            );
        $stats['event_distribution'] =
            $this->__distribution(
                'events', 'distribution', 10
            );
        $stats['object_distribution'] =
            $this->__distribution(
                'objects', 'distribution', 10
            );
        $stats['object_membership'] =
            $this->__singleQuery(
                "SELECT "
                . "SUM(object_id = 0) AS standalone, "
                . "SUM(object_id != 0) AS in_object "
                . "FROM attributes"
            );
        $stats['value_cardinality'] =
            $this->__singleQuery(
                "SELECT "
                . "COUNT(DISTINCT value1) "
                    . "AS distinct_value1, "
                . "COUNT(DISTINCT "
                    . "CASE WHEN value2 != '' "
                    . "THEN value2 END) "
                    . "AS distinct_value2"
                . " FROM attributes"
            );
        $stats['timestamp_ranges'] =
            $this->__timestampRanges();
        $stats['first_last_seen_usage'] =
            $this->__singleQuery(
                "SELECT "
                . "SUM(first_seen IS NOT NULL) "
                    . "AS has_first_seen, "
                . "SUM(last_seen IS NOT NULL) "
                    . "AS has_last_seen "
                . "FROM attributes"
            );
        $stats['sharing_group_usage'] =
            $this->__singleQuery(
                "SELECT "
                . "SUM(sharing_group_id = 0) "
                    . "AS no_sg, "
                . "SUM(sharing_group_id != 0) "
                    . "AS has_sg "
                . "FROM attributes"
            );
        $stats['top_attribute_tags'] =
            $this->__topTags('attribute_tags', 10);
        $stats['top_event_tags'] =
            $this->__topTags('event_tags', 10);
        $stats['tags_per_attribute'] =
            $this->__bucketDistribution(
                "SELECT COALESCE(t.cnt, 0) AS cnt "
                . "FROM attributes a "
                . "LEFT JOIN ("
                    . "SELECT attribute_id, "
                    . "COUNT(*) cnt "
                    . "FROM attribute_tags "
                    . "GROUP BY attribute_id"
                . ") t "
                . "ON t.attribute_id = a.id",
                'cnt'
            );
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
                'cnt'
            );
        $stats['attrs_per_event'] =
            $this->__bucketDistribution(
                "SELECT COUNT(*) AS cnt "
                . "FROM attributes "
                . "GROUP BY event_id",
                'cnt'
            );
        $stats['events_per_org'] =
            $this->__queryList(
                "SELECT o.name, COUNT(*) AS cnt "
                . "FROM events e "
                . "JOIN organisations o "
                    . "ON o.id = e.orgc_id "
                . "GROUP BY e.orgc_id "
                . "ORDER BY cnt DESC LIMIT 10"
            );
        $stats['broad_tag_event_spread'] =
            $this->__queryList(
                "SELECT t.name, "
                . "COUNT(DISTINCT at.event_id) "
                    . "AS events, "
                . "COUNT(*) AS attr_tags "
                . "FROM attribute_tags at "
                . "JOIN tags t ON t.id = at.tag_id "
                . "GROUP BY at.tag_id "
                . "ORDER BY attr_tags DESC LIMIT 10"
            );
        $stats['correlation_density'] =
            $this->__correlationDensity();
        $stats['indexes'] = $this->__indexInfo();
        return $stats;
    }

    // ── query helpers (all read-only) ───────────────────

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
            $r = $this->MispAttribute->query(
                "SELECT COUNT(*) AS cnt "
                . "FROM `{$table}`"
            );
            $flat = $this->__flatten($r[0]);
            $counts[$table] = (int)$flat['cnt'];
        }
        return $counts;
    }

    /**
     * Column value distribution (top N).
     *
     * @param string $table
     * @param string $column
     * @param int $limit
     * @return array
     */
    private function __distribution(
        $table, $column, $limit
    ) {
        $rows = $this->MispAttribute->query(
            "SELECT `{$column}` AS val, "
            . "COUNT(*) AS cnt "
            . "FROM `{$table}` "
            . "GROUP BY `{$column}` "
            . "ORDER BY cnt DESC "
            . "LIMIT {$limit}"
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
    private function __singleQuery($sql)
    {
        $r = $this->MispAttribute->query($sql);
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
    private function __queryList($sql)
    {
        $rows = $this->MispAttribute->query($sql);
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
            . "FROM attributes"
        );
        foreach ($windows as $label => $cutoff) {
            $r = $this->MispAttribute->query(
                "SELECT COUNT(*) AS cnt "
                . "FROM attributes "
                . "WHERE timestamp > {$cutoff}"
            );
            $flat = $this->__flatten($r[0]);
            $result['last_' . $label] =
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
        $rows = $this->MispAttribute->query(
            "SELECT t.name, COUNT(*) AS cnt "
            . "FROM `{$joinTable}` jt "
            . "JOIN tags t ON t.id = jt.tag_id "
            . "GROUP BY jt.tag_id "
            . "ORDER BY cnt DESC "
            . "LIMIT {$limit}"
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
        $innerSql, $col
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
        $rows = $this->MispAttribute->query($sql);
        $out = [];
        foreach ($rows as $r) {
            $flat = $this->__flatten($r);
            $out[$flat['bucket']] =
                (int)$flat['cnt'];
        }
        return $out;
    }

    /**
     * Correlation density: how many attributes have
     * correlations and at what depth.
     *
     * Samples up to 200K attributes to avoid a full
     * join on very large instances.
     *
     * @return array
     */
    private function __correlationDensity()
    {
        $total = $this->__singleQuery(
            "SELECT COUNT(*) AS cnt FROM attributes"
        )['cnt'];
        $sample = min($total, 200000);

        $sql = "SELECT "
            . "CASE "
            . "WHEN cnt = 0 THEN '0' "
            . "WHEN cnt <= 5 THEN '1-5' "
            . "WHEN cnt <= 20 THEN '6-20' "
            . "ELSE '20+' "
            . "END AS bucket, "
            . "COUNT(*) AS n "
            . "FROM ("
                . "SELECT a.id, "
                . "COALESCE(c.cnt, 0) AS cnt "
                . "FROM attributes a "
                . "LEFT JOIN ("
                    . "SELECT attribute_id, "
                    . "COUNT(*) cnt "
                    . "FROM default_correlations "
                    . "GROUP BY attribute_id"
                . ") c "
                . "ON c.attribute_id = a.id "
                . "LIMIT {$sample}"
            . ") t "
            . "GROUP BY bucket ORDER BY bucket";
        $rows = $this->MispAttribute->query($sql);
        $out = ['sample_size' => $sample];
        foreach ($rows as $r) {
            $flat = $this->__flatten($r);
            $out[$flat['bucket']] =
                (int)$flat['n'];
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
            $rows = $this->MispAttribute->query(
                "SHOW INDEX FROM `{$table}`"
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

        // Value cardinality ratio
        $valueUniqueness = 0;
        if (!empty($stats['value_cardinality'])) {
            $dv = $stats['value_cardinality']
                ['distinct_value1'];
            $valueUniqueness = $total > 0
                ? $dv / $total : 0;
        }

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

        $combos[] = $this->__combo(++$id,
            'value (%%suffix)',
            'Investigation',
            ['value'],
            ['SLOW', sprintf(
                'Suffix LIKE cannot use B-tree index.'
                . ' Full scan of %s rows.',
                number_format($total)
            )]
        );

        $combos[] = $this->__combo(++$id,
            'value (%%mid%%)',
            'Investigation',
            ['value'],
            ['SLOW', sprintf(
                'Middle wildcard — full scan of %s '
                . 'rows.',
                number_format($total)
            )]
        );

        $combos[] = $this->__combo(++$id,
            'value (suffix) + tags',
            'Investigation',
            ['value', 'tags'],
            ['SLOW', 'Value suffix scan dominates. '
                . 'Tag filter cannot reduce I/O.']
        );

        $combos[] = $this->__combo(++$id,
            'value (suffix) + type',
            'Investigation',
            ['value', 'type'],
            ['SLOW', 'Value suffix scan dominates. '
                . 'Type index unusable.']
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
                . 'scan of %s rows.',
                number_format($total)
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
                . '(%s rows). Tags and timestamp '
                . 'cannot help.',
                number_format($total)
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
        $this->out($sep);
        $this->out('');

        // ── Table counts ────────────────────────────
        $this->out('## Dataset Overview');
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
        $this->out('  Value cardinality:');
        $vc = $stats['value_cardinality'];
        $total = $stats['table_counts']['attributes'];
        $this->out(sprintf(
            '    distinct value1: %s (%.0f%% unique)',
            number_format($vc['distinct_value1'] ?? 0),
            $total > 0
                ? ($vc['distinct_value1'] ?? 0)
                    / $total * 100
                : 0
        ));
        $this->out(sprintf(
            '    distinct value2: %s',
            number_format($vc['distinct_value2'] ?? 0)
        ));
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

        // ── Correlation density ─────────────────────
        $this->out('  Correlation density '
            . '(sampled):');
        $cd = $stats['correlation_density'];
        foreach ($cd as $k => $v) {
            $this->out(sprintf(
                '    %-12s %s',
                $k, number_format($v)
            ));
        }
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
