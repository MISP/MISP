<?php

/** Missing, incomplete or corrupt Redis state must never look like a negative lookup. */
class FastLookupIndexUnavailableException extends RuntimeException
{
}

/**
 * Persistent, authorization-free attribute candidates. The manager owns the SQL
 * write lock and durable revision fence; this class owns only its Redis namespace.
 *
 * Posting HASH fields are binary kind+digest tokens; values are comma-terminated
 * decimal ID lists. A fixed number of shards bounds key overhead without requiring
 * keyspace scans for a lookup. Per-event reverse hashes make retries removable.
 * Each posting is limited to 8 MiB and 500,000 IDs; exceeding either fails the
 * build explicitly and leaves it nonready, never publishing a truncated list.
 */
class FastLookupIndex
{
    const SHARDS = 32;
    const BATCH_SIZE = 128;
    const READ_BATCH_SIZE = 1024;
    const MAX_POSTING_BYTES = 8388608;
    const MAX_POSTING_IDS = 500000;
    const MAX_ATTRIBUTES_PER_BATCH = 500;
    const MAX_TOKENS_PER_ATTRIBUTE = 1024;

    private $prefix;
    private $scope;
    private $types;
    private $redis;
    private $typePrefixes = [];
    private $generationKeys = [];

    public function __construct(string $namespace, array $scope, $redis = null)
    {
        if (empty($scope['attribute_types']) || !is_array($scope['attribute_types'])) {
            throw new InvalidArgumentException('The fastLookup type scope must be a nonempty list.');
        }
        $this->types = [];
        foreach ($scope['attribute_types'] as $type) {
            if (!is_string($type) || $type === '' || strlen($type) > 255 || strpos($type, "\0") !== false) {
                throw new InvalidArgumentException('Invalid fastLookup attribute type.');
            }
            $this->types[$type] = true;
        }
        ksort($this->types, SORT_STRING);
        $scope['attribute_types'] = array_keys($this->types);
        $scope['published_only'] = $scope['published_only'] ?? true;
        if (!is_bool($scope['published_only'])) {
            throw new InvalidArgumentException('The fastLookup publication scope must be boolean.');
        }
        $this->scope = $scope;
        $this->prefix = 'misp:fast_lookup:v2:' . hash('sha256', $namespace) . ':';
        $this->redis = $redis;
    }

    public function initialise(string $generation, string $fingerprint, array $progress): void
    {
        $this->identifier($generation);
        $this->identifier($fingerprint);
        $old = $this->call('hGet', [$this->metaKey(), 'generation']);
        if ($old === $generation) {
            throw new InvalidArgumentException('A rebuild must use a fresh generation identifier.');
        }
        // Publish warming first. A crash while installing sentinels cannot leave
        // either the old data or the incomplete new generation apparently ready.
        $this->call('del', [$this->metaKey()]);
        $this->call('hMSet', [$this->metaKey(), [
            'schema' => '2', 'generation' => $generation, 'fingerprint' => $fingerprint,
            'revision' => '0', 'ready' => '0',
            'scope' => $this->json($this->scope), 'progress' => $this->json($progress),
        ]]);
        foreach (array_chunk($this->fixedKeys($generation), self::BATCH_SIZE) as $keys) {
            $this->evaluate(<<<'LUA'
if redis.call('HGET', KEYS[1], 'generation') ~= ARGV[1] then return redis.error_reply('generation changed') end
for i = 2, #KEYS do
    if redis.call('EXISTS', KEYS[i]) ~= 0 then return redis.error_reply('generation keys already exist') end
end
for i = 2, #KEYS do redis.call('HSET', KEYS[i], '!', ARGV[1]) end
return 1
LUA
                , array_merge([$this->metaKey()], $keys), [$generation]);
        }
        $this->deleteOldGenerations($generation);
    }

    /** Includes sentinel checks, so eviction of even an empty shard fails closed. */
    public function metadata(): array
    {
        $meta = $this->call('hGetAll', [$this->metaKey()]);
        if (!is_array($meta) || ($meta['schema'] ?? null) !== '2' ||
            !isset($meta['generation'], $meta['fingerprint'], $meta['revision'], $meta['progress'], $meta['scope']) ||
            !in_array($meta['ready'] ?? null, ['0', '1'], true)) {
            throw new FastLookupIndexUnavailableException('The fastLookup index metadata is missing or invalid.');
        }
        try {
            $this->identifier($meta['generation']);
            $this->identifier($meta['fingerprint']);
            $this->identifier($meta['revision']);
            $progress = json_decode($meta['progress'], true, 32, JSON_THROW_ON_ERROR);
            $scope = json_decode($meta['scope'], true, 32, JSON_THROW_ON_ERROR);
        } catch (Throwable $e) {
            throw new FastLookupIndexUnavailableException('The fastLookup index metadata is corrupt.', 0, $e);
        }
        if (!is_array($progress) || !is_array($scope) ||
            ($scope['attribute_types'] ?? null) !== $this->scope['attribute_types'] ||
            ($scope['published_only'] ?? null) !== $this->scope['published_only']) {
            throw new FastLookupIndexUnavailableException('The fastLookup index scope does not match its configuration.');
        }
        $this->sentinels($meta['generation']);
        $meta['ready'] = $meta['ready'] === '1';
        $meta['progress'] = $progress;
        $meta['scope'] = $scope;
        return $meta;
    }

    public function beginEvent(string $generation, string $eventId): void
    {
        $this->removeEvent($generation, $eventId);
        $this->evaluate($this->fenceScript() . <<<'LUA'
redis.call('HSET', KEYS[1], 'ready', '0')
redis.call('HSET', KEYS[2], ARGV[2], '1')
return 1
LUA
            , [$this->metaKey(), $this->inflightKey($generation)], [$generation, $eventId]);
    }

    /** A caller streams SQL rows; this method never materializes the entire event. */
    public function addAttributes(string $generation, string $eventId, array $preparedAttributes): void
    {
        $this->identifier($generation);
        $this->decimalId($eventId);
        if (count($preparedAttributes) > self::MAX_ATTRIBUTES_PER_BATCH) {
            throw new OverflowException('A fastLookup index write batch exceeds 500 attributes.');
        }
        $groups = []; $attributes = [];
        foreach ($preparedAttributes as $row) {
            if (!is_array($row) || !isset($row['id'], $row['type'], $row['tokens']) ||
                !is_string($row['id']) || !is_array($row['tokens'])) {
                throw new InvalidArgumentException('Malformed prepared fastLookup attribute.');
            }
            $this->decimalId($row['id']);
            $this->attributeType($row['type']);
            $attributes[$row['type']][$row['id']] = $row['id'];
            if (count($row['tokens']) > self::MAX_TOKENS_PER_ATTRIBUTE) {
                throw new OverflowException('An attribute has too many fastLookup index tokens.');
            }
            foreach ($row['tokens'] as $token) {
                $this->token($token);
                $groups[$row['type']][$token][$row['id']] = $row['id'];
            }
        }
        // Empty exact collation weights can intentionally have no Redis token:
        // they still belong to the selected scope and attribute counts.
        foreach ($attributes as $type => $ids) {
            $prefix = $this->typePrefix($generation, $type);
            $this->evaluate($this->fenceScript() . <<<'LUA'
if redis.call('HEXISTS', KEYS[2], ARGV[2]) ~= 1 then return redis.error_reply('event is not open') end
for i = 3, 4 do
    if redis.call('HGET', KEYS[i], '!') ~= ARGV[1] then return redis.error_reply('missing type sentinel') end
end
local registered = redis.call('HEXISTS', KEYS[3], ARGV[2]) == 1
local exists = redis.call('EXISTS', KEYS[5]) == 1
if registered ~= exists then return redis.error_reply('missing event manifest') end
if exists and redis.call('HGET', KEYS[5], '!') ~= ARGV[1] then return redis.error_reply('invalid event manifest') end
redis.call('HSET', KEYS[3], ARGV[2], '1')
redis.call('HSET', KEYS[5], '!', ARGV[1])
for i = 3, #ARGV do
    redis.call('HSET', KEYS[5], 'A' .. ARGV[i], '1')
    redis.call('HSET', KEYS[4], ARGV[i], ARGV[2])
end
return 1
LUA
                , [$this->metaKey(), $this->inflightKey($generation), $prefix . 'events', $prefix . 'owners', $prefix . 'r:' . $eventId],
                array_merge([$generation, $eventId], array_values($ids)));
        }
        foreach ($groups as $type => $tokens) {
            foreach ($tokens as $token => $ids) {
                $typePrefix = $this->typePrefix($generation, $type);
                $this->evaluate($this->fenceScript() . $this->postingParserScript() . <<<'LUA'
-- FAST_LOOKUP_ADD: reverse memberships precede postings even on a lost ACK.
if redis.call('HEXISTS', KEYS[2], ARGV[2]) ~= 1 then return redis.error_reply('event is not open') end
for i = 3, 5 do
    if redis.call('HGET', KEYS[i], '!') ~= ARGV[1] then return redis.error_reply('missing type sentinel') end
end
local registered = redis.call('HEXISTS', KEYS[3], ARGV[2]) == 1
local reverseExists = redis.call('EXISTS', KEYS[6]) == 1
if registered ~= reverseExists then return redis.error_reply('missing event manifest') end
if reverseExists and redis.call('HGET', KEYS[6], '!') ~= ARGV[1] then return redis.error_reply('invalid event manifest') end
local raw = redis.call('HGET', KEYS[5], ARGV[3]) or ''
local ids, seen = parsePosting(raw)
local add = {}
for i = 4, #ARGV do
    if not seen[ARGV[i]] then
        seen[ARGV[i]] = true
        add[#add + 1] = ARGV[i] .. ','
    end
end
local updated = raw .. table.concat(add)
if #updated > MAX_BYTES or #ids + #add > MAX_IDS then return redis.error_reply('posting resource limit exceeded') end
redis.call('HSET', KEYS[3], ARGV[2], '1')
redis.call('HSET', KEYS[6], '!', ARGV[1])
for i = 4, #ARGV do
    redis.call('HSET', KEYS[6], 'A' .. ARGV[i], '1', ARGV[3] .. ARGV[i], '1')
    redis.call('HSET', KEYS[4], ARGV[i], ARGV[2])
end
redis.call('HSET', KEYS[5], ARGV[3], updated)
return 1
LUA
                    , [$this->metaKey(), $this->inflightKey($generation), $typePrefix . 'events',
                        $typePrefix . 'owners', $this->postingKey($generation, $type, $token), $typePrefix . 'r:' . $eventId],
                    array_merge([$generation, $eventId, $token], array_values($ids)));
            }
        }
    }

    public function endEvent(string $generation, string $eventId): void
    {
        $this->identifier($generation);
        $this->decimalId($eventId);
        $this->evaluate($this->fenceScript() . <<<'LUA'
if redis.call('HEXISTS', KEYS[2], ARGV[2]) ~= 1 then return redis.error_reply('event is not open') end
redis.call('HDEL', KEYS[2], ARGV[2])
return 1
LUA
            , [$this->metaKey(), $this->inflightKey($generation)], [$generation, $eventId]);
    }

    public function replaceEvent(string $generation, string $eventId, array $preparedAttributes): void
    {
        $this->beginEvent($generation, $eventId);
        foreach (array_chunk($preparedAttributes, self::MAX_ATTRIBUTES_PER_BATCH) as $batch) {
            $this->addAttributes($generation, $eventId, $batch);
        }
        $this->endEvent($generation, $eventId);
    }

    public function removeEvent(string $generation, string $eventId): void
    {
        $this->identifier($generation);
        $this->decimalId($eventId);
        $this->evaluate($this->fenceScript() . <<<'LUA'
redis.call('HSET', KEYS[1], 'ready', '0')
redis.call('HSET', KEYS[2], ARGV[2], '1')
return 1
LUA
            , [$this->metaKey(), $this->inflightKey($generation)], [$generation, $eventId]);
        foreach (array_keys($this->types) as $type) {
            $typePrefix = $this->typePrefix($generation, $type);
            $registry = $typePrefix . 'events';
            $reverse = $typePrefix . 'r:' . $eventId;
            $exists = $this->evaluate($this->fenceScript() . <<<'LUA'
for i = 3, 4 do
    if redis.call('HGET', KEYS[i], '!') ~= ARGV[1] then return redis.error_reply('missing type sentinel') end
end
local registered = redis.call('HEXISTS', KEYS[3], ARGV[2]) == 1
local exists = redis.call('EXISTS', KEYS[5]) == 1
if registered ~= exists then return redis.error_reply('missing event manifest') end
if exists and redis.call('HGET', KEYS[5], '!') ~= ARGV[1] then return redis.error_reply('invalid event manifest') end
return exists and 1 or 0
LUA
                , [$this->metaKey(), $this->inflightKey($generation), $registry, $typePrefix . 'owners', $reverse], [$generation, $eventId]);
            if (!$exists) {
                continue;
            }
            // Redis SCAN guarantees only fields present for the entire iteration.
            // Repeat from zero until just the sentinel remains; deletion during a
            // pass therefore cannot strand fields when a hash table resizes.
            do {
                $removed = false;
                $batch = [];
                foreach ($this->hashEntries($reverse) as $field => $value) {
                    if ($field === '!') { continue; }
                    if ($value !== '1') { throw new FastLookupIndexUnavailableException('Corrupt reverse membership.'); }
                    $batch[] = $field;
                    if (count($batch) >= self::BATCH_SIZE) {
                        $this->removeReverseBatch($generation, $eventId, $type, $batch);
                        $batch = [];
                    }
                    $removed = true;
                }
                if ($batch) { $this->removeReverseBatch($generation, $eventId, $type, $batch); }
            } while ($removed && $this->call('hLen', [$reverse]) > 1);
            $this->evaluate($this->fenceScript() . <<<'LUA'
if redis.call('HGET', KEYS[3], '!') ~= ARGV[1] or redis.call('HGET', KEYS[4], '!') ~= ARGV[1] or redis.call('HLEN', KEYS[4]) ~= 1 then return redis.error_reply('incomplete event removal') end
redis.call('DEL', KEYS[4])
redis.call('HDEL', KEYS[3], ARGV[2])
return 1
LUA
                , [$this->metaKey(), $this->inflightKey($generation), $registry, $reverse], [$generation, $eventId]);
        }
        $this->endEvent($generation, $eventId);
    }

    public function checkpoint(string $generation, string $revision, array $progress, bool $ready): void
    {
        $this->identifier($generation);
        $this->identifier($revision);
        $this->sentinels($generation);
        $this->evaluate($this->fenceScript() . <<<'LUA'
if ARGV[3] == '1' and redis.call('HLEN', KEYS[2]) ~= 1 then return redis.error_reply('an event update is incomplete') end
redis.call('HSET', KEYS[1], 'revision', ARGV[2], 'ready', ARGV[3], 'progress', ARGV[4])
return 1
LUA
            , [$this->metaKey(), $this->inflightKey($generation)], [$generation, $revision, $ready ? '1' : '0', $this->json($progress)]);
    }

    public function candidates(string $generation, array $queryTokens, int $maximumIds = 100000): array
    {
        $this->identifier($generation);
        if ($maximumIds < 1 || $maximumIds > self::MAX_POSTING_IDS) {
            throw new InvalidArgumentException('Invalid fastLookup candidate budget.');
        }
        $plan = []; $output = [];
        foreach ($queryTokens as $position => $tokens) {
            if (!is_array($tokens)) { throw new InvalidArgumentException('Invalid fastLookup query token list.'); }
            $output[$position] = ['exact' => [], 'ip_range' => [], 'domain' => []];
            foreach ($tokens as $entry) {
                if (!is_array($entry) || !isset($entry['type'], $entry['token'], $entry['kind'])) {
                    throw new InvalidArgumentException('Invalid fastLookup query token.');
                }
                $this->attributeType($entry['type']);
                $this->token($entry['token']);
                $kind = ['E' => 'exact', 'I' => 'ip_range', 'D' => 'domain'][$entry['token'][0]];
                if ($entry['kind'] !== $kind) { throw new InvalidArgumentException('The fastLookup token kind does not match.'); }
                $key = $this->postingKey($generation, $entry['type'], $entry['token']);
                $plan[$key][$entry['token']][] = [$position, $kind];
            }
        }
        $before = $this->metadata();
        if (!$before['ready'] || $before['generation'] !== $generation) {
            throw new FastLookupIndexUnavailableException('The fastLookup index is not ready for this generation.');
        }
        $count = 0;
        $reads = [];
        foreach ($plan as $key => $tokens) {
            foreach ($tokens as $field => $destinations) { $reads[] = [$key, $field, $destinations]; }
        }
        unset($plan);
        foreach (array_chunk($reads, self::READ_BATCH_SIZE) as $batch) {
            $keys = [$this->metaKey()]; $keyIndexes = []; $args = [$generation, $maximumIds * 21];
            foreach ($batch as [$key, $field]) {
                if (!isset($keyIndexes[$key])) {
                    $keys[] = $key;
                    $keyIndexes[$key] = count($keys); // Lua KEYS uses one-based indexes.
                }
                $args[] = $keyIndexes[$key];
                $args[] = $field;
            }
            // Length validation and grouped HMGETs run in one atomic script.
            // Sparse queries span many shards without one round trip per shard.
            $reply = $this->evaluate(<<<'LUA'
if redis.call('HGET', KEYS[1], 'generation') ~= ARGV[1] or redis.call('HGET', KEYS[1], 'ready') ~= '1' then return redis.error_reply('index changed') end
for i = 2, #KEYS do
    if redis.call('HGET', KEYS[i], '!') ~= ARGV[1] then return redis.error_reply('missing posting sentinel') end
end
local bytes, groups, positions, result = 0, {}, {}, {}
for i = 3, #ARGV, 2 do
    local keyIndex = tonumber(ARGV[i])
    bytes = bytes + redis.call('HSTRLEN', KEYS[keyIndex], ARGV[i + 1])
    if bytes > tonumber(ARGV[2]) then return {0} end
    if not groups[keyIndex] then groups[keyIndex], positions[keyIndex] = {}, {} end
    groups[keyIndex][#groups[keyIndex] + 1] = ARGV[i + 1]
    positions[keyIndex][#positions[keyIndex] + 1] = #result + 1
    result[#result + 1] = false
end
for keyIndex, fields in pairs(groups) do
    local values = redis.call('HMGET', KEYS[keyIndex], unpack(fields))
    for i, value in ipairs(values) do result[positions[keyIndex][i]] = value end
end
return {1, result}
LUA
                , $keys, $args);
            if (!is_array($reply) || !isset($reply[0]) || !in_array($reply[0], [0, 1], true)) {
                throw new FastLookupIndexUnavailableException('Invalid fastLookup posting response.');
            }
            if ($reply[0] === 0) {
                throw new OverflowException('The fastLookup candidate payload exceeds the request budget.');
            }
            $rows = $reply[1] ?? null;
            if (!is_array($rows) || count($rows) !== count($batch)) {
                throw new FastLookupIndexUnavailableException('Invalid fastLookup posting response.');
            }
            foreach ($batch as $offset => [$key, $field, $destinations]) {
                if (!array_key_exists($offset, $rows)) { throw new FastLookupIndexUnavailableException('Missing fastLookup posting response.'); }
                if ($rows[$offset] === false) { continue; }
                $ids = $this->parsePosting($rows[$offset], $maximumIds);
                foreach ($destinations as [$position, $kind]) {
                    foreach ($ids as $id) {
                        if (!isset($output[$position][$kind][$id])) {
                            if (++$count > $maximumIds) { throw new OverflowException('The fastLookup candidate count exceeds the request budget.'); }
                            $output[$position][$kind][$id] = $id;
                        }
                    }
                }
            }
        }
        $after = $this->metadata();
        if (!$after['ready'] || $after['generation'] !== $generation || $after['revision'] !== $before['revision']) {
            throw new FastLookupIndexUnavailableException('The fastLookup index changed during the lookup.');
        }
        foreach ($output as &$kinds) {
            foreach ($kinds as &$ids) {
                $ids = array_values($ids);
                usort($ids, static function ($a, $b) { return strlen($a) <=> strlen($b) ?: strcmp($a, $b); });
            }
            unset($ids);
        }
        unset($kinds);
        return $output;
    }

    public function statistics(string $generation): array
    {
        $meta = $this->metadata();
        if ($meta['generation'] !== $generation) { throw new FastLookupIndexUnavailableException('The fastLookup generation changed.'); }
        $reason = null;
        $shared = $this->memory($this->metaKey(), $reason);
        $shared = $this->sumMemory($shared, $this->memory($this->inflightKey($generation), $reason));
        $types = [];
        foreach (array_keys($this->types) as $type) {
            $prefix = $this->typePrefix($generation, $type);
            $bytes = 0; $entries = 0;
            foreach ($this->typeKeys($generation, $type) as $key) {
                $bytes = $this->sumMemory($bytes, $this->memory($key, $reason));
            }
            for ($i = 0; $i < self::SHARDS; ++$i) {
                foreach ($this->hashEntries($prefix . 'b:' . $i) as $field => $value) {
                    if ($field === '!') { continue; }
                    try { $this->token($field); } catch (InvalidArgumentException $e) {
                        throw new FastLookupIndexUnavailableException('Corrupt posting field.', 0, $e);
                    }
                    $entries += count($this->parsePosting($value, self::MAX_POSTING_IDS));
                }
            }
            foreach ($this->hashEntries($prefix . 'events') as $eventId => $value) {
                if ($eventId === '!') { continue; }
                $eventId = (string)$eventId;
                $this->storedId($eventId);
                $reverse = $prefix . 'r:' . $eventId;
                if ($value !== '1' || $this->call('hGet', [$reverse, '!']) !== $generation) {
                    throw new FastLookupIndexUnavailableException('A fastLookup reverse manifest is missing.');
                }
                $bytes = $this->sumMemory($bytes, $this->memory($reverse, $reason));
            }
            $types[] = ['type' => $type, 'attributes' => $this->call('hLen', [$prefix . 'owners']) - 1,
                'entries' => $entries, 'memory_bytes' => $bytes];
        }
        $after = $this->metadata();
        if ($after['generation'] !== $generation || $after['revision'] !== $meta['revision']) {
            throw new FastLookupIndexUnavailableException('The fastLookup index changed during measurement.');
        }
        return ['types' => $types, 'shared_memory_bytes' => $shared, 'measured_at' => gmdate('c'),
            'memory_unavailable_reason' => $reason];
    }

    private function removeReverseBatch($generation, $eventId, $type, array $fields): void
    {
        $prefix = $this->typePrefix($generation, $type);
        $tokens = []; $attributes = [];
        foreach ($fields as $field) {
            if ($field[0] === 'A') {
                $id = substr($field, 1);
                $this->storedId($id);
                $attributes[] = $id;
            } else {
                $token = substr($field, 0, 17);
                $id = substr($field, 17);
                try { $this->token($token); $this->decimalId($id); } catch (InvalidArgumentException $e) {
                    throw new FastLookupIndexUnavailableException('Corrupt reverse membership.', 0, $e);
                }
                $tokens[$token][] = $id;
            }
        }
        foreach ($tokens as $token => $ids) {
            $this->evaluate($this->fenceScript() . $this->postingParserScript() . <<<'LUA'
for i = 3, 5 do
    if redis.call('HGET', KEYS[i], '!') ~= ARGV[1] then return redis.error_reply('missing event state') end
end
local remove = {}
for i = 5, #ARGV do
    local owner = redis.call('HGET', KEYS[3], ARGV[i])
    local keep = false
    if owner and owner ~= ARGV[2] then
        local ownerManifest = ARGV[4] .. owner
        if redis.call('HGET', ownerManifest, '!') ~= ARGV[1] then return redis.error_reply('missing new owner manifest') end
        keep = redis.call('HEXISTS', ownerManifest, ARGV[3] .. ARGV[i]) == 1
    end
    if not keep then remove[ARGV[i]] = true end
end
local raw = redis.call('HGET', KEYS[4], ARGV[3]) or ''
local ids = parsePosting(raw)
local remaining = {}
for _, id in ipairs(ids) do if not remove[id] then remaining[#remaining + 1] = id .. ',' end end
if #remaining == 0 then redis.call('HDEL', KEYS[4], ARGV[3])
else redis.call('HSET', KEYS[4], ARGV[3], table.concat(remaining)) end
for i = 5, #ARGV do redis.call('HDEL', KEYS[5], ARGV[3] .. ARGV[i]) end
return 1
LUA
                , [$this->metaKey(), $this->inflightKey($generation), $prefix . 'owners',
                    $this->postingKey($generation, $type, $token), $prefix . 'r:' . $eventId],
                array_merge([$generation, $eventId, $token, $prefix . 'r:'], $ids));
        }
        if ($attributes) {
            $this->evaluate($this->fenceScript() . <<<'LUA'
if redis.call('HGET', KEYS[3], '!') ~= ARGV[1] or redis.call('HGET', KEYS[4], '!') ~= ARGV[1] then return redis.error_reply('missing event state') end
for i = 3, #ARGV do
    if redis.call('HGET', KEYS[3], ARGV[i]) == ARGV[2] then redis.call('HDEL', KEYS[3], ARGV[i]) end
    redis.call('HDEL', KEYS[4], 'A' .. ARGV[i])
end
return 1
LUA
                , [$this->metaKey(), $this->inflightKey($generation), $prefix . 'owners', $prefix . 'r:' . $eventId],
                array_merge([$generation, $eventId], $attributes));
        }
    }

    private function parsePosting($value, $maximum): array
    {
        if (!is_string($value) || $value === '' || substr($value, -1) !== ',' || strlen($value) > self::MAX_POSTING_BYTES) {
            throw new FastLookupIndexUnavailableException('A fastLookup posting payload is corrupt.');
        }
        if (substr_count($value, ',') > $maximum) { throw new OverflowException('The fastLookup candidate count exceeds the request budget.'); }
        $ids = explode(',', substr($value, 0, -1));
        $seen = [];
        foreach ($ids as $id) {
            $this->storedId($id);
            if (isset($seen[$id])) { throw new FastLookupIndexUnavailableException('A fastLookup posting contains duplicate identifiers.'); }
            $seen[$id] = true;
        }
        return $ids;
    }

    private function hashEntries($key): Generator
    {
        $cursor = null;
        do {
            try { $rows = $this->connection()->hScan($key, $cursor, null, self::BATCH_SIZE); } catch (Throwable $e) {
                throw new FastLookupIndexUnavailableException('Could not scan the fastLookup index.', 0, $e);
            }
            if ($rows !== false && !is_array($rows)) { throw new FastLookupIndexUnavailableException('Invalid fastLookup scan response.'); }
            foreach ($rows ?: [] as $field => $value) { yield $field => $value; }
            if (!is_int($cursor) || $cursor < 0) { throw new FastLookupIndexUnavailableException('Invalid fastLookup scan cursor.'); }
        } while ($cursor !== 0);
    }

    private function sentinels($generation): void
    {
        foreach (array_chunk($this->fixedKeys($generation), self::READ_BATCH_SIZE) as $keys) {
            $this->evaluate(<<<'LUA'
if redis.call('HGET', KEYS[1], 'generation') ~= ARGV[1] then return redis.error_reply('generation changed') end
for i = 2, #KEYS do
    if redis.call('HGET', KEYS[i], '!') ~= ARGV[1] then return redis.error_reply('missing index sentinel') end
end
return 1
LUA
                , array_merge([$this->metaKey()], $keys), [$generation]);
        }
    }

    private function deleteOldGenerations($currentGeneration): void
    {
        $cursor = null;
        $currentPrefix = $this->generationPrefix($currentGeneration);
        do {
            try { $keys = $this->connection()->scan($cursor, $this->prefix . 'g:*', self::BATCH_SIZE); } catch (Throwable $e) {
                throw new FastLookupIndexUnavailableException('Could not reclaim the old fastLookup generation.', 0, $e);
            }
            if ($keys) {
                $keys = array_values(array_filter($keys, static function ($key) use ($currentPrefix) { return strpos($key, $currentPrefix) !== 0; }));
                foreach (array_chunk($keys, self::BATCH_SIZE) as $batch) { $this->call('del', [$batch]); }
            }
            if (!is_int($cursor) || $cursor < 0) { throw new FastLookupIndexUnavailableException('Invalid fastLookup cleanup cursor.'); }
        } while ($cursor !== 0);
    }

    private function memory($key, &$reason): ?int
    {
        if ($reason !== null) { return null; }
        try {
            $bytes = $this->connection()->rawCommand('MEMORY', 'USAGE', $key, 'SAMPLES', 0);
            if (!is_int($bytes) || $bytes < 0) { throw new RuntimeException('MEMORY USAGE did not return a size.'); }
            return $bytes;
        } catch (Throwable $e) {
            $reason = 'Redis MEMORY USAGE is unavailable or not permitted.';
            return null;
        }
    }

    private function sumMemory($a, $b): ?int { return $a === null || $b === null ? null : $a + $b; }
    private function metaKey(): string { return $this->prefix . 'metadata'; }
    private function generationPrefix($generation): string { return $this->prefix . 'g:' . $generation . ':'; }
    private function inflightKey($generation): string { return $this->generationPrefix($generation) . 'inflight'; }
    private function typePrefix($generation, $type): string
    {
        if (!isset($this->typePrefixes[$generation][$type])) {
            $this->typePrefixes[$generation][$type] = $this->generationPrefix($generation) . 't:' . hash('sha256', $type) . ':';
        }
        return $this->typePrefixes[$generation][$type];
    }
    private function postingKey($generation, $type, $token): string { return $this->typePrefix($generation, $type) . 'b:' . (ord($token[1]) % self::SHARDS); }
    private function typeKeys($generation, $type): array
    {
        $prefix = $this->typePrefix($generation, $type);
        $keys = [$prefix . 'events', $prefix . 'owners'];
        for ($i = 0; $i < self::SHARDS; ++$i) { $keys[] = $prefix . 'b:' . $i; }
        return $keys;
    }
    private function fixedKeys($generation): array
    {
        if (!isset($this->generationKeys[$generation])) {
            $keys = [$this->inflightKey($generation)];
            foreach (array_keys($this->types) as $type) { $keys = array_merge($keys, $this->typeKeys($generation, $type)); }
            $this->generationKeys[$generation] = $keys;
        }
        return $this->generationKeys[$generation];
    }
    private function identifier($value): void
    {
        if (!is_string($value) || !preg_match('/\A[A-Za-z0-9_-]{1,128}\z/D', $value)) { throw new InvalidArgumentException('Invalid fastLookup generation, revision or fingerprint.'); }
    }
    private function decimalId($value): void
    {
        if (!is_string($value) || !preg_match('/\A[1-9][0-9]{0,19}\z/D', $value)) { throw new InvalidArgumentException('Invalid fastLookup decimal identifier.'); }
    }
    private function storedId($value): void
    {
        try { $this->decimalId($value); } catch (InvalidArgumentException $e) { throw new FastLookupIndexUnavailableException('A fastLookup identifier is corrupt.', 0, $e); }
    }
    private function attributeType($type): void
    {
        if (!is_string($type) || !isset($this->types[$type])) { throw new InvalidArgumentException('Attribute type is outside the fastLookup scope.'); }
    }
    private function token($token): void
    {
        if (!is_string($token) || strlen($token) !== 17 || !in_array($token[0], ['E', 'I', 'D'], true)) { throw new InvalidArgumentException('Invalid fastLookup binary token.'); }
    }
    private function json(array $value): string { return json_encode($value, JSON_THROW_ON_ERROR); }
    private function connection()
    {
        if ($this->redis === null) {
            try {
                if (!class_exists('RedisTool')) { App::uses('RedisTool', 'Tools'); }
                $this->redis = RedisTool::init();
            } catch (Throwable $e) { throw new FastLookupIndexUnavailableException('Redis is unavailable for fastLookup.', 0, $e); }
        }
        return $this->redis;
    }
    private function call($method, array $args)
    {
        try { return $this->connection()->{$method}(...$args); } catch (FastLookupIndexUnavailableException $e) { throw $e; } catch (Throwable $e) {
            throw new FastLookupIndexUnavailableException('Redis could not complete a fastLookup operation.', 0, $e);
        }
    }
    private function evaluate($script, array $keys, array $args)
    {
        try {
            $result = $this->call('eval', [$script, array_merge($keys, $args), count($keys)]);
        } catch (FastLookupIndexUnavailableException $e) {
            $cause = $e->getPrevious();
            if ($cause && strpos($cause->getMessage(), 'posting resource limit exceeded') !== false) {
                throw new OverflowException('A fastLookup token exceeds the posting limit of 8 MiB or 500000 attribute IDs.', 0, $e);
            }
            throw $e;
        }
        if ($result === false) {
            $error = $this->call('getLastError', []);
            if (is_string($error) && strpos($error, 'posting resource limit exceeded') !== false) {
                throw new OverflowException('A fastLookup token exceeds the posting limit of 8 MiB or 500000 attribute IDs.');
            }
            throw new FastLookupIndexUnavailableException('Redis refused a fastLookup index operation.');
        }
        return $result;
    }
    private function fenceScript(): string
    {
        return <<<'LUA'
if redis.call('HGET', KEYS[1], 'generation') ~= ARGV[1] or redis.call('HGET', KEYS[2], '!') ~= ARGV[1] then return redis.error_reply('generation changed or index missing') end

LUA;
    }
    private function postingParserScript(): string
    {
        return 'local MAX_BYTES = ' . self::MAX_POSTING_BYTES . "\nlocal MAX_IDS = " . self::MAX_POSTING_IDS . "\n" . <<<'LUA'
local function parsePosting(raw)
    if #raw > MAX_BYTES or (#raw > 0 and string.sub(raw, -1) ~= ',') then error('corrupt posting payload') end
    local ids, seen = {}, {}
    for id in string.gmatch(raw, '([^,]*),') do
        if #id > 20 or not string.match(id, '^[1-9][0-9]*$') or seen[id] then error('corrupt posting identifier') end
        seen[id] = true
        ids[#ids + 1] = id
        if #ids > MAX_IDS then error('posting resource limit exceeded') end
    end
    return ids, seen
end

LUA;
    }
}
