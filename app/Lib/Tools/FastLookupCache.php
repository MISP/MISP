<?php
App::uses('RedisTool', 'Tools');

/**
 * Complete, user-independent exact-value candidate sets. Authorization is never
 * cached here: consumers must recheck current values, deletion state and ACLs.
 */
class FastLookupCache
{
    const MAX_AGE = 60;
    const MAX_IDS = 10000;
    const READ_BATCH_SIZE = 100;
    const MAX_RETURN_IDS = 100000;
    const MAX_PAYLOAD_BYTES = 262144;

    private $prefix;
    private $redis;
    private $clock;

    public function __construct($namespace, $redis = null, ?callable $clock = null)
    {
        $this->prefix = 'misp:fast_lookup:v1:' . hash('sha256', $namespace) . ':';
        $this->redis = $redis;
        $this->clock = $clock ?: function () { return microtime(true); };
    }

    /**
     * @param array $values Input index => normalized literal value
     * @param int $maxAge Maximum age in seconds; zero bypasses Redis
     * @return array Input index => complete candidate ID list; [] is a cached miss
     */
    public function getMany(array $values, $maxAge)
    {
        if (!$values || !is_int($maxAge) || $maxAge < 1 || $maxAge > self::MAX_AGE) {
            return [];
        }
        try {
            $hits = [];
            $idCount = 0;
            foreach (array_chunk($values, self::READ_BATCH_SIZE, true) as $batch) {
                $keys = [];
                foreach ($batch as $value) {
                    $keys[] = $this->key($value);
                }
                $entries = $this->connection()->mGet($keys);
                if (!is_array($entries) || count($entries) !== count($keys) ||
                    array_keys($entries) !== range(0, count($keys) - 1)) {
                    return [];
                }
                $now = ($this->clock)();
                foreach (array_keys($batch) as $position => $index) {
                    $entry = $entries[$position];
                    if (!is_string($entry) || strlen($entry) > self::MAX_PAYLOAD_BYTES) {
                        continue;
                    }
                    // Keep JSON objects distinct from lists: ids:{} is invalid,
                    // while ids:[] represents a complete cached negative result.
                    $entry = json_decode($entry);
                    if (!($entry instanceof stdClass) || ($entry->version ?? null) !== 1 ||
                        !isset($entry->created) ||
                        (!is_int($entry->created) && !is_float($entry->created)) ||
                        !is_finite((float)$entry->created) ||
                        $entry->created > $now || $now - $entry->created >= $maxAge) {
                        continue;
                    }
                    $ids = $this->candidateIds($entry->ids ?? null);
                    if ($ids !== null && $idCount + count($ids) <= self::MAX_RETURN_IDS) {
                        $idCount += count($ids);
                        $hits[$index] = $ids;
                    }
                }
            }
            return $hits;
        } catch (Throwable $e) {
            // Cache outages or malformed entries never change lookup semantics.
            return [];
        }
    }

    /**
     * Store only complete sets after all SQL batches have succeeded. Timestamp
     * is taken before discovery, so slow queries cannot extend the freshness
     * window. Reads never refresh expiry.
     */
    public function storeMany(array $values, array $candidates, $queriedAt)
    {
        if ((!is_int($queriedAt) && !is_float($queriedAt)) || !is_finite((float)$queriedAt)) {
            return;
        }
        $now = ($this->clock)();
        $ttl = (int)floor(self::MAX_AGE - ($now - $queriedAt));
        if ($queriedAt > $now || $ttl < 1) {
            return;
        }
        $entries = [];
        foreach ($candidates as $index => $ids) {
            if (!array_key_exists($index, $values)) {
                continue;
            }
            $ids = $this->candidateIds($ids);
            if ($ids === null) {
                continue; // Never cache an oversized or truncated candidate list.
            }
            $payload = json_encode(['version' => 1, 'created' => $queriedAt, 'ids' => $ids]);
            if ($payload !== false && strlen($payload) <= self::MAX_PAYLOAD_BYTES) {
                $entries[$this->key($values[$index])] = $payload;
            }
        }
        if (!$entries) {
            return;
        }
        try {
            $pipe = $this->connection()->pipeline();
            foreach ($entries as $key => $payload) {
                $pipe->setex($key, $ttl, $payload);
            }
            $pipe->exec();
        } catch (Throwable $e) {
            // Successful SQL results remain usable when writing Redis fails.
        }
    }

    private function connection()
    {
        if ($this->redis === null) {
            $this->redis = RedisTool::init();
        }
        return $this->redis;
    }

    private function key($value)
    {
        return $this->prefix . hash('sha256', $value);
    }

    /** @return array|null Validated decimal IDs, or null for an unusable set */
    private function candidateIds($ids)
    {
        if (!is_array($ids) || count($ids) > self::MAX_IDS ||
            ($ids && array_keys($ids) !== range(0, count($ids) - 1))) {
            return null;
        }
        $valid = [];
        foreach ($ids as $id) {
            if ((!is_int($id) && !is_string($id)) ||
                !preg_match('/^[1-9][0-9]{0,18}$/D', (string)$id)) {
                return null;
            }
            $valid[(string)$id] = (string)$id;
        }
        return array_values($valid);
    }
}
