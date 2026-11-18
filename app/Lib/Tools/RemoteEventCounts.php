<?php
App::uses('RedisTool', 'Tools');

/**
 * How many attributes and objects the events of a remote source hold — a
 * feed, a remote instance — for its preview index, which the source's own
 * index does not say. Each count is read off the whole event and cached
 * against the event's timestamp, so a changed event is read again.
 */
class RemoteEventCounts
{
    const TTL = 2592000;

    /**
     * @param string $prefix the source's cache key prefix
     * @param array $events key (uuid or remote id) => timestamp
     * @param callable|null $fetch key => MISP-format event, or null to answer
     *  from the cache alone; an exception counts as an event not read
     * @return array key => ['attribute_count' => int, 'object_count' => int],
     *  or null for an event that could not be read; an event neither cached
     *  nor fetched is left out
     */
    public static function read($prefix, array $events, $fetch = null)
    {
        $redis = null;
        try {
            $redis = RedisTool::init();
        } catch (Exception $e) {
            // Without a cache every count is read from the source.
        }
        $key = function ($event, $timestamp) use ($prefix) {
            return $prefix . ':' . $event . ':' . (int)$timestamp;
        };
        $counts = [];
        if ($redis && !empty($events)) {
            $cached = $redis->mget(array_map($key, array_keys($events), $events));
            foreach (array_keys($events) as $i => $event) {
                if (is_string($cached[$i] ?? null) && preg_match('/^(\d+),(\d+)$/', $cached[$i], $match)) {
                    $counts[$event] = ['attribute_count' => (int)$match[1], 'object_count' => (int)$match[2]];
                }
            }
        }
        if ($fetch === null) {
            return $counts;
        }
        foreach ($events as $event => $timestamp) {
            if (array_key_exists($event, $counts)) {
                continue;
            }
            try {
                $body = $fetch($event);
            } catch (Exception $e) {
                $body = null;
            }
            if (!is_array($body) || empty($body['Event'])) {
                $counts[$event] = null;
                continue;
            }
            $counts[$event] = self::of($body['Event']);
            if ($redis) {
                $redis->setex(
                    $key($event, $timestamp),
                    self::TTL,
                    $counts[$event]['attribute_count'] . ',' . $counts[$event]['object_count']
                );
            }
        }
        return $counts;
    }

    /**
     * @param array $event Event row carrying Attribute and Object
     * @return array attribute_count (those in objects included), object_count
     */
    public static function of(array $event)
    {
        $objects = $event['Object'] ?? [];
        $attributes = count($event['Attribute'] ?? []);
        foreach ($objects as $object) {
            $attributes += count($object['Attribute'] ?? []);
        }
        return ['attribute_count' => $attributes, 'object_count' => count($objects)];
    }
}
