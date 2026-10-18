<?php
App::uses('RedisTool', 'Tools');

/**
 * Rows written to a log table per day, read off the id that opens each day.
 * Log ids grow with `created`, so a day costs one binary search on the primary
 * key however large the table is, where counting rows would read all of them.
 * Ids that never became rows (rolled-back writes) count as rows: close enough
 * for an activity map, not for anything else.
 */
class LogActivityTool
{
    const CACHE_PREFIX = 'misp:log_activity:';
    const CACHE_TTL = 604800;

    /**
     * @param Model $model AuditLog or Log
     * @param string $from first day, Y-m-d
     * @param string $to last day, Y-m-d
     * @return array day (Y-m-d) => rows, days without rows left out
     */
    public static function dailyCounts(Model $model, $from, $to)
    {
        $range = $model->find('first', [
            'recursive' => -1,
            'callbacks' => false,
            'fields' => ['MIN(id) AS lo', 'MAX(id) AS hi'],
        ]);
        if (empty($range[0]['hi'])) {
            return [];
        }
        $lo = (int)$range[0]['lo'];
        $hi = (int)$range[0]['hi'];

        $days = [];
        $end = strtotime($to . ' +1 day');
        for ($day = strtotime($from); $day <= $end; $day = strtotime('+1 day', $day)) {
            $days[] = date('Y-m-d', $day);
        }

        // A past day's opener never moves once a later row exists
        $cacheKey = self::CACHE_PREFIX . $model->useTable;
        $cached = [];
        try {
            $redis = RedisTool::init();
            $cached = array_filter($redis->hMGet($cacheKey, $days) ?: []);
            if (!empty($cached) && max(array_map('intval', $cached)) > $hi + 1) {
                // The table was emptied and its ids started over
                $redis->del($cacheKey);
                $cached = [];
            }
        } catch (Exception $e) {
            $redis = null;
        }

        $db = $model->getDataSource();
        $sql = 'SELECT id, created FROM ' . $db->fullTableName($model) . ' WHERE id >= ? ORDER BY id LIMIT 1';
        $today = date('Y-m-d');
        $openers = [];
        $fresh = [];
        foreach ($days as $day) {
            if (isset($cached[$day])) {
                $lo = (int)$cached[$day];
            } else {
                $lo = self::firstIdFrom($db, $sql, $day . ' 00:00:00', $lo, $hi);
                if ($day < $today && $lo <= $hi) {
                    $fresh[$day] = $lo;
                }
            }
            $openers[$day] = $lo;
        }
        if ($redis && !empty($fresh)) {
            try {
                $redis->hMSet($cacheKey, $fresh);
                $redis->expire($cacheKey, self::CACHE_TTL);
            } catch (Exception $e) {
                // Uncached openers are found again next time
            }
        }

        $counts = [];
        for ($i = 0; $i < count($days) - 1; $i++) {
            $rows = $openers[$days[$i + 1]] - $openers[$days[$i]];
            if ($rows > 0) {
                $counts[$days[$i]] = $rows;
            }
        }
        return $counts;
    }

    /**
     * @return int the first id written at or after $time, $hi + 1 if none is
     */
    private static function firstIdFrom(DboSource $db, $sql, $time, $lo, $hi)
    {
        $first = $hi + 1;
        while ($lo <= $hi) {
            $mid = $lo + intdiv($hi - $lo, 2);
            $rows = $db->fetchAll($sql, [$mid], ['cache' => false]);
            if (empty($rows)) {
                $hi = $mid - 1;
                continue;
            }
            // Drivers key the columns by table name or by 0
            $row = array_merge(...array_values($rows[0]));
            if (strcmp(substr($row['created'], 0, 19), $time) >= 0) {
                $first = (int)$row['id'];
                $hi = $mid - 1;
            } else {
                $lo = (int)$row['id'] + 1;
            }
        }
        return $first;
    }
}
