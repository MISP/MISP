<?php
/**
 * Reduces SQL statements and MariaDB / MySQL JSON plans to what the plans
 * oracle (tests/value_oracle) compares: a statement shape without literals,
 * and per table the access type, key, covering flag and rows examined. Row
 * estimates and timings are left out, they vary from run to run.
 */
class QueryPlanSummary
{
    const VALUE_TABLES = [
        'attributes', 'shadow_attributes', 'default_correlations',
        'no_acl_correlations', 'correlation_values', 'over_correlating_values',
        'attr_value_counts', 'correlation_exclusions', 'attribute_values',
        'value_ip_ranges', 'tmp_source_values',
    ];
    const LARGE_READ_ROWS = 100000;

    /**
     * @param string $sql
     * @param string $database Schema name to drop from qualified table names
     * @return string
     */
    public static function shape($sql, $database = '')
    {
        $sql = self::stripComment($sql);
        if ($database !== '') {
            $sql = str_replace('`' . $database . '`.', '', $sql);
        }
        $sql = preg_replace("~'(?:[^'\\\\]|\\\\.|'')*'~s", '?', $sql);
        $sql = preg_replace(
            '~(?<![\w.`$])-?\b\d+(?:\.\d+)?\b(?![\w`])~',
            '?',
            $sql
        );
        $sql = preg_replace('~\(\s*\?(?:\s*,\s*\?)*\s*\)~', '(?+)', $sql);
        $sql = preg_replace(
            '~(\bVALUES\s*)(\([^()]*\))(?:\s*,\s*\([^()]*\))+~i',
            '$1$2, ...',
            $sql
        );
        return trim(preg_replace('~\s+~', ' ', $sql));
    }

    /**
     * @param string $sql
     * @return string The statement without the comment the MISP datasources
     *  put in front of it
     */
    public static function stripComment($sql)
    {
        return preg_replace('~^\s*/\*.*?\*/\s*~s', '', $sql);
    }

    /**
     * @param string $shape
     * @return string The leading keyword, lower case
     */
    public static function kind($shape)
    {
        preg_match('~^[\s(]*(\w+)~', $shape, $match);
        return strtolower($match[1] ?? '');
    }

    /**
     * @param string $shape
     * @return bool
     */
    public static function touchesValueTables($shape)
    {
        $tables = implode('|', self::VALUE_TABLES);
        return (bool)preg_match(
            '~(?<![\w$])(?:' . $tables . ')(?![\w$])~i',
            $shape
        );
    }

    /**
     * SELECTs are re-run under ANALYZE for the rows they examine; statements
     * that write are only EXPLAINed.
     *
     * @param string $shape
     * @return string|null
     */
    public static function explainVerb($shape)
    {
        $kind = self::kind($shape);
        if ($kind === 'select') {
            return 'ANALYZE';
        }
        if ($kind === 'update' || $kind === 'delete') {
            return 'EXPLAIN';
        }
        $writes = $kind === 'insert' || $kind === 'replace';
        if ($writes && preg_match('~\bSELECT\b~i', $shape)) {
            return 'EXPLAIN';
        }
        return null;
    }

    /**
     * @param array $plan Decoded EXPLAIN / ANALYZE FORMAT=JSON output
     * @return array
     */
    public static function summarise(array $plan)
    {
        $out = ['tables' => [], 'filesort' => false, 'temporary' => false];
        self::walk($plan, $out);
        if (empty($out['notes'])) {
            unset($out['notes']);
        }
        return $out;
    }

    /**
     * Which index each table access used. Kept apart from summarise(): when
     * several indexes serve the same key parts equally well, the choice
     * follows InnoDB's sampled statistics, which change on every reload.
     *
     * @param array $plan Decoded EXPLAIN / ANALYZE FORMAT=JSON output
     * @return array "<table> <index>" per table access, in plan order
     */
    public static function indexes(array $plan)
    {
        $indexes = [];
        foreach (self::tableNodes($plan) as $node) {
            $names = isset($node['index_merge'])
                ? array_column(self::ranges($node['index_merge']), 'key')
                : (isset($node['key']) ? [$node['key']] : []);
            $indexes[] = trim($node['table_name'] . ' ' . implode('+', $names));
        }
        return $indexes;
    }

    /**
     * @param array $statements Summarised statements, in execution order
     * @return array "#<statement> <table> <access> <rows examined>" for every
     *  table access that reads many rows, whatever its access type, and for
     *  full scans of an unknown size (statements that were only EXPLAINed)
     */
    public static function largeReads(array $statements)
    {
        $found = [];
        foreach ($statements as $i => $statement) {
            foreach ($statement['tables'] ?? [] as $table) {
                if ($table['table'][0] === '<') {
                    continue;
                }
                $examined = $table['examined'] ?? null;
                $scan = in_array($table['access'], ['ALL', 'index'], true);
                if (
                    $examined === null ? $scan :
                    $examined >= self::LARGE_READ_ROWS
                ) {
                    $found[] = sprintf(
                        '#%d %s %s %s',
                        $i + 1,
                        $table['table'],
                        $table['access'],
                        $examined === null ? '?' : $examined
                    );
                }
            }
        }
        return $found;
    }

    private static function walk($node, array &$out)
    {
        if (!is_array($node)) {
            return;
        }
        if (isset($node['table_name'], $node['access_type'])) {
            $out['tables'][] = self::table($node);
        } elseif (isset($node['message']) && is_string($node['message'])) {
            // Such as "Impossible WHERE noticed after reading const tables"
            $out['notes'][] = $node['message'];
        }
        foreach ($node as $key => $child) {
            // MariaDB nests the operation, MySQL 8 flags it.
            if ($key === 'filesort' || $key === 'using_filesort') {
                $out['filesort'] = $out['filesort'] || $child !== false;
            }
            $temporary = $key === 'temporary_table' ||
                $key === 'using_temporary_table';
            if ($temporary) {
                $out['temporary'] = $out['temporary'] || $child !== false;
            }
            self::walk($child, $out);
        }
    }

    private static function table(array $node)
    {
        $entry = [
            'table' => $node['table_name'],
            'access' => $node['access_type'],
        ];
        if (isset($node['used_key_parts'])) {
            $entry['key_parts'] = $node['used_key_parts'];
        } elseif (isset($node['key'])) {
            $entry['key'] = $node['key'];
        }
        if (isset($node['index_merge'])) {
            $entry['merged'] = array_map(function ($range) {
                $parts = $range['used_key_parts'] ?? [$range['key']];
                return implode(',', $parts);
            }, self::ranges($node['index_merge']));
        }
        if (!empty($node['using_index'])) {
            $entry['covering'] = true;
        }
        if (isset($node['materialized'])) {
            $entry['materialized'] = true;
        }
        if (isset($node['r_loops'])) {
            $entry['loops'] = (int)$node['r_loops'];
            $entry['examined'] =
                (int)round($node['r_loops'] * ($node['r_rows'] ?? 0));
        }
        return $entry;
    }

    private static function tableNodes($node)
    {
        $found = [];
        if (!is_array($node)) {
            return $found;
        }
        if (isset($node['table_name'], $node['access_type'])) {
            $found[] = $node;
        }
        foreach ($node as $child) {
            $found = array_merge($found, self::tableNodes($child));
        }
        return $found;
    }

    /**
     * @return array The parts of an index_merge, each with its key
     */
    private static function ranges(array $node)
    {
        $ranges = [];
        foreach ($node as $key => $child) {
            if ($key === 'key' && is_string($child)) {
                $ranges[] = $node;
            } elseif (is_array($child)) {
                $ranges = array_merge($ranges, self::ranges($child));
            }
        }
        return $ranges;
    }
}
