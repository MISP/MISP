<?php

App::uses('RedisTool', 'Tools');

/**
 * Server-side rolling time-series store for the live monitor widgets
 * (DD-30, refining DD-29's client-only buffer). Each handler() call
 * records its current sample into a Redis sorted set and returns the
 * retained window, so the client pre-populates the chart from persisted
 * history — a reload or manual refresh repaints the accumulated series
 * instead of starting empty. Redis is the single source of truth, shared
 * across all viewing admins (CPU/memory are host-wide, not per-user).
 *
 * Storage: one sorted set per metric, key
 *   misp:dashboard_monitor:<metric>
 * score = unix timestamp, member = "<ts>:<value>". Trimmed to the window
 * on every write and given a TTL, so an idle metric self-expires (no
 * sampling happens while no dashboard is polling).
 *
 * Cross-viewer dedup: an append is skipped when the newest sample is
 * younger than ~half the interval, so several admins polling the same
 * metric concurrently don't over-densify the series.
 *
 * Redis-down: degrades to a single-point series (just the current
 * sample), so the widget still renders.
 */
class MonitorSeriesStore
{
    const KEY_PREFIX = 'misp:dashboard_monitor:';
    const MAX_WINDOW = 86400; // hard cap (1 day) on the retained window

    /**
     * Record $value for $metric and return the retained series as an
     * ordered list of [timestamp, value] pairs (oldest first).
     *
     * @param string $metric      short slug, e.g. 'cpu' / 'memory'
     * @param float  $value        current reading
     * @param int    $windowSec    retain this many seconds of history
     * @param int    $intervalSec  sampling cadence (drives the dedup gap)
     * @return array<int, array{0:int,1:float}>
     */
    public static function record($metric, $value, $windowSec, $intervalSec)
    {
        $now = time();
        $value = round((float)$value, 2);
        $window = max(1, min(self::MAX_WINDOW, (int)$windowSec));
        $interval = max(1, (int)$intervalSec);
        $minGap = (int)max(1, floor($interval / 2));

        $redis = self::redis();
        if ($redis === null) {
            return array(array($now, $value));
        }
        $key = self::KEY_PREFIX . preg_replace('/[^a-z0-9_]/', '', strtolower($metric));
        try {
            // Cross-viewer dedup: skip the append when the newest sample is
            // younger than the dedup gap (another admin's poll just wrote).
            $append = true;
            $last = $redis->zRevRange($key, 0, 0, true); // [member => score]
            if (!empty($last)) {
                $lastTs = (int)reset($last);
                if (($now - $lastTs) < $minGap) {
                    $append = false;
                }
            }
            if ($append) {
                $redis->zAdd($key, $now, $now . ':' . $value);
            }
            // Drop anything older than the window, and let an idle key
            // expire on its own.
            $redis->zRemRangeByScore($key, 0, $now - $window);
            $redis->expire($key, $window + $interval);
            $rows = $redis->zRangeByScore($key, $now - $window, '+inf', array('withscores' => true));
        } catch (Exception $e) {
            return array(array($now, $value));
        }
        // $rows: [member => score], ascending by score. Member is
        // "<ts>:<value>"; the score equals that ts, so parse the value
        // from the member and use the score as the timestamp.
        $series = array();
        foreach ($rows as $member => $score) {
            $parts = explode(':', (string)$member, 2);
            $series[] = array((int)$score, isset($parts[1]) ? (float)$parts[1] : 0.0);
        }
        if (empty($series)) {
            $series[] = array($now, $value);
        }
        return $series;
    }

    private static function redis()
    {
        try {
            return RedisTool::init();
        } catch (Exception $e) {
            return null;
        }
    }
}
