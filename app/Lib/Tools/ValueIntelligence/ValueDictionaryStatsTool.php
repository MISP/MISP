<?php
App::uses('RedisTool', 'Tools');
App::uses('BackgroundJobsTool', 'Tools');

/**
 * Instance-wide counts of the attribute value dictionary for the values
 * index, kept as one snapshot in Redis so no page load ever scans a table.
 *
 * The snapshot holds a total and the highest id it counted. A page adds the
 * rows past that id, capped, and the worker rolls the snapshot forward the
 * same way, recounting in full once a week to absorb deletions.
 */
class ValueDictionaryStatsTool
{
    const KEY = 'misp:value_intelligence:dictionary_stats';

    const LOCK = 'misp:value_intelligence:dictionary_stats:refresh';

    const LOCK_SECONDS = 3600;

    const STALE_SECONDS = 86400;

    const FULL_SECONDS = 604800;

    const DAYS_KEPT = 30;

    const WINDOW_DAYS = 7;

    const LIVE_CAP = 50000;

    const FULL_CHUNK = 1000000;

    const VALUES = 'attribute_values';

    const ATTRIBUTES = 'attributes';

    /** @var DboSource */
    private $db;

    public function __construct(Model $model)
    {
        $this->db = $model->getDataSource();
    }

    /**
     * Rolls the stored snapshot forward, counting in full when there is none,
     * when asked to, or when the last full count is a week old.
     *
     * @param bool $full
     * @param int|null $now
     * @return array The stored snapshot
     */
    public function snapshot($full = false, $now = null)
    {
        $now = $now === null ? time() : (int)$now;
        $state = $this->load();
        $read = [
            'values_max_id' => $this->maxId(self::VALUES),
            'attributes_max_id' => $this->maxId(self::ATTRIBUTES),
            'total' => null,
            'new_values' => null,
            'new_attributes' => null,
        ];
        if ($state !== null) {
            $read['new_values'] = $this->countBetween(self::VALUES, $state['values_max_id'], $read['values_max_id']);
            $read['new_attributes'] = $this->countBetween(self::ATTRIBUTES, $state['attributes_max_id'], $read['attributes_max_id']);
        }
        if ($full || $state === null || $now - $state['full_at'] >= self::FULL_SECONDS) {
            $read['total'] = $this->countUpTo(self::VALUES, $read['values_max_id']);
        }
        $state = self::rollForward($state, $read, $now);
        RedisTool::init()->set(self::KEY, json_encode($state));
        return $state;
    }

    /**
     * What the tiles draw, or null before the first snapshot. Queues a
     * refresh when the snapshot is missing or stale; never throws.
     *
     * @param int|null $now
     * @return array|null As summarise()
     */
    public function forPage($now = null)
    {
        $now = $now === null ? time() : (int)$now;
        try {
            $state = $this->load();
            if ($state === null || $now - $state['counted_at'] >= self::STALE_SECONDS) {
                $this->requestRefresh();
            }
            if ($state === null) {
                return null;
            }
            return self::summarise(
                $state,
                $this->countAfter(self::VALUES, $state['values_max_id']),
                $this->countAfter(self::ATTRIBUTES, $state['attributes_max_id']),
                $now
            );
        } catch (Exception $e) {
            CakeLog::write('warning', 'ValueDictionaryStatsTool::forPage — ' . $e->getMessage());
            return null;
        }
    }

    /**
     * @param array|null $state The previous snapshot
     * @param array $read Max ids, and the total and new counts that were read
     * @param int $now
     * @return array
     */
    public static function rollForward($state, array $read, $now)
    {
        if ($state === null) {
            $state = ['total' => 0, 'started_at' => $now, 'full_at' => $now, 'days' => []];
        }
        $newValues = (int)$read['new_values'];
        $newAttributes = (int)$read['new_attributes'];
        $state['total'] = $read['total'] !== null ? (int)$read['total'] : $state['total'] + $newValues;
        if ($read['total'] !== null) {
            $state['full_at'] = $now;
        }
        if ($newValues > 0 || $newAttributes > 0) {
            $day = gmdate('Y-m-d', $now);
            $bucket = $state['days'][$day] ?? ['values' => 0, 'attributes' => 0];
            $state['days'][$day] = [
                'values' => $bucket['values'] + $newValues,
                'attributes' => $bucket['attributes'] + $newAttributes,
            ];
        }
        $oldest = gmdate('Y-m-d', $now - (self::DAYS_KEPT - 1) * 86400);
        $state['days'] = array_filter($state['days'], function ($day) use ($oldest) {
            return $day >= $oldest;
        }, ARRAY_FILTER_USE_KEY);
        ksort($state['days']);
        $state['values_max_id'] = (int)$read['values_max_id'];
        $state['attributes_max_id'] = (int)$read['attributes_max_id'];
        $state['counted_at'] = $now;
        return $state;
    }

    /**
     * @param array $state
     * @param int $liveValues Values past the snapshot's watermark, capped
     * @param int $liveAttributes Attributes past it, capped
     * @param int $now
     * @return array{total: int, total_floor: bool, recent: array, series: array}
     */
    public static function summarise(array $state, $liveValues, $liveAttributes, $now)
    {
        $valuesFloor = $liveValues > self::LIVE_CAP;
        $floor = $valuesFloor || $liveAttributes > self::LIVE_CAP;
        $liveValues = min($liveValues, self::LIVE_CAP);
        $liveAttributes = min($liveAttributes, self::LIVE_CAP);
        $today = gmdate('Y-m-d', $now);
        $windowStart = gmdate('Y-m-d', $now - (self::WINDOW_DAYS - 1) * 86400);
        $started = gmdate('Y-m-d', (int)$state['started_at']);

        $recent = ['values' => $liveValues, 'attributes' => $liveAttributes];
        foreach ($state['days'] as $day => $bucket) {
            if ($day >= $windowStart) {
                $recent['values'] += $bucket['values'];
                $recent['attributes'] += $bucket['attributes'];
            }
        }
        $recent['floor'] = $floor;
        $recent['since'] = $started > $windowStart ? (int)$state['started_at'] : null;

        $series = [];
        for ($i = self::DAYS_KEPT - 1; $i >= 0; $i--) {
            $day = gmdate('Y-m-d', $now - $i * 86400);
            $values = null;
            if ($day >= $started) {
                $values = $state['days'][$day]['values'] ?? 0;
                if ($day === $today) {
                    $values += $liveValues;
                }
            }
            $series[] = ['day' => $day, 'values' => $values];
        }

        return [
            'total' => (int)$state['total'] + $liveValues,
            'total_floor' => $valuesFloor,
            'recent' => $recent,
            'series' => $series,
        ];
    }

    /**
     * Queues one snapshot job, at most once an hour across all readers.
     *
     * @return bool Whether a job was queued
     */
    public function requestRefresh()
    {
        if (!Configure::read('MISP.background_jobs')) {
            return false;
        }
        if (!RedisTool::init()->set(self::LOCK, time(), ['nx', 'ex' => self::LOCK_SECONDS])) {
            return false;
        }
        /** @var Job $Job */
        $Job = ClassRegistry::init('Job');
        $jobId = $Job->createJob(
            'SYSTEM',
            Job::WORKER_DEFAULT,
            'valueDictionaryStats',
            '',
            __('Counting the attribute value dictionary.')
        );
        $Job->getBackgroundJobsTool()->enqueue(
            BackgroundJobsTool::DEFAULT_QUEUE,
            BackgroundJobsTool::CMD_ADMIN,
            ['valueDictionaryStats', $jobId],
            true,
            $jobId
        );
        return true;
    }

    /**
     * @return array|null
     */
    private function load()
    {
        $raw = RedisTool::init()->get(self::KEY);
        if (!is_string($raw)) {
            return null;
        }
        $state = json_decode($raw, true);
        if (!is_array($state) || !isset($state['total'], $state['values_max_id'], $state['attributes_max_id'], $state['counted_at'], $state['full_at'], $state['started_at'])) {
            return null;
        }
        $state['days'] = isset($state['days']) && is_array($state['days']) ? $state['days'] : [];
        return $state;
    }

    private function maxId($table)
    {
        return $this->number(sprintf('SELECT MAX(%s) AS n FROM %s', $this->db->name('id'), $this->db->fullTableName($table)));
    }

    private function countBetween($table, $after, $upTo)
    {
        if ($upTo <= $after) {
            return 0;
        }
        return $this->number(sprintf(
            'SELECT COUNT(*) AS n FROM %1$s WHERE %2$s > %3$d AND %2$s <= %4$d',
            $this->db->fullTableName($table),
            $this->db->name('id'),
            $after,
            $upTo
        ));
    }

    private function countUpTo($table, $upTo)
    {
        $total = 0;
        for ($after = 0; $after < $upTo; $after += self::FULL_CHUNK) {
            $total += $this->countBetween($table, $after, min($upTo, $after + self::FULL_CHUNK));
        }
        return $total;
    }

    /**
     * Rows past an id, reading at most one more than the cap.
     */
    private function countAfter($table, $after)
    {
        return $this->number(sprintf(
            'SELECT COUNT(*) AS n FROM (SELECT 1 AS one FROM %s WHERE %s > %d LIMIT %d) capped',
            $this->db->fullTableName($table),
            $this->db->name('id'),
            $after,
            self::LIVE_CAP + 1
        ));
    }

    private function number($sql)
    {
        $statement = $this->db->rawQuery($sql);
        $row = $statement->fetch(PDO::FETCH_NUM);
        $statement->closeCursor();
        return $row === false ? 0 : (int)$row[0];
    }
}
