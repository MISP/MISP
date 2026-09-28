<?php

/** Missing, incomplete or corrupt Redis state must never look like a negative lookup. */
class FastLookupIndexUnavailableException extends RuntimeException
{
}

/**
 * Redis side of fast lookup: one RedisBloom filter per generation holding every
 * token, plus append-only postings for IP-range and domain tokens.
 *
 * The filter only proves absence. SQL answers exact tokens that may be present;
 * range and domain tokens read postings whose attribute IDs SQL re-verifies.
 * Deleted or edited attributes leave stale entries that SQL filters out; a
 * rebuild clears them. BF.MEXISTS reports absence for a missing key and BF.MADD
 * creates a default filter, so every command runs in a script that first checks
 * the filter and the generation sentinel, and fails closed.
 *
 * Postings are spread over listpack-sized bucket hashes; one longer than a
 * listpack value moves to '<bucket>:<hex token>' holding '<generation>|<ids>'
 * and leaves '*' in the bucket, so a popular value never inflates its bucket.
 */
class FastLookupFilter
{
    const SCHEMA = 'bloom-1';
    const PREFIX = 'misp:fast_lookup:bf1:';
    const LEGACY_PREFIX = 'misp:fast_lookup:v3:';
    const BLOOM_TYPE = 'MBbloom--';
    const TOKEN_BYTES = 9;
    const MIN_CAPACITY = 1000000;
    const BUCKET_FIELDS = 64;
    const MAX_BUCKETS = 4194304;
    /** Redis's default hash-max-listpack-value. */
    const INLINE_POSTING_BYTES = 64;
    const MAX_POSTING_BYTES = 8388608;
    const MAX_POSTING_IDS = 500000;
    const MAX_TOKENS_PER_ATTRIBUTE = 1024;
    const FILTER_BATCH = 1000;
    const POSTING_BATCH = 128;
    const READ_BATCH_SIZE = 1024;
    const DELETE_BATCH = 500;

    private $prefix;
    private $legacyPrefix;
    private $scope;
    private $redis;

    public function __construct(string $namespace, array $scope, $redis = null)
    {
        if (empty($scope['attribute_types']) || !is_array($scope['attribute_types'])) {
            throw new InvalidArgumentException('The fastLookup type scope must be a nonempty list.');
        }
        $types = [];
        foreach ($scope['attribute_types'] as $type) {
            if (!is_string($type) || $type === '' || strlen($type) > 255 || strpos($type, "\0") !== false) {
                throw new InvalidArgumentException('Invalid fastLookup attribute type.');
            }
            $types[$type] = true;
        }
        ksort($types, SORT_STRING);
        $published = $scope['published_only'] ?? true;
        if (!is_bool($published)) {
            throw new InvalidArgumentException('The fastLookup publication scope must be boolean.');
        }
        $this->scope = ['attribute_types' => array_keys($types), 'published_only' => $published];
        $hash = hash('sha256', $namespace);
        $this->prefix = self::PREFIX . $hash . ':';
        $this->legacyPrefix = self::LEGACY_PREFIX . $hash . ':';
        $this->redis = $redis;
    }

    public static function bucketsFor(int $entries): int
    {
        return min(self::MAX_BUCKETS, max(1, intdiv($entries + self::BUCKET_FIELDS - 1, self::BUCKET_FIELDS)));
    }

    /** RedisBloom sizing: -ln(p)/ln(2)^2 bits and ceil(-log2(p)) hashes per entry. */
    public static function estimatedFalsePositiveRate(int $capacity, float $rate, int $inserted): float
    {
        $hashes = (int)ceil(-log($rate) / log(2));
        $bits = -log($rate) / (log(2) ** 2) * max(1, $capacity);
        return (1 - exp(-$hashes * $inserted / $bits)) ** $hashes;
    }

    public function moduleAvailable(): bool
    {
        try {
            $info = $this->connection()->rawCommand('COMMAND', 'INFO', 'BF.MEXISTS');
        } catch (Throwable $e) {
            return false;
        }
        return is_array($info) && isset($info[0]) && is_array($info[0]);
    }

    public function metadata(): array
    {
        $meta = $this->call('hGetAll', [$this->metaKey()]);
        if (!is_array($meta) || ($meta['schema'] ?? null) !== self::SCHEMA
            || !isset($meta['live'], $meta['building'], $meta['fingerprint'], $meta['building_fingerprint'], $meta['revision'], $meta['scope'])
            || !in_array($meta['ready'] ?? null, ['0', '1'], true)) {
            throw new FastLookupIndexUnavailableException('The fastLookup index metadata is missing or invalid.');
        }
        try {
            $this->identifier($meta['revision']);
            foreach (['live', 'building', 'fingerprint', 'building_fingerprint'] as $field) {
                if ($meta[$field] !== '') { $this->identifier($meta[$field]); }
            }
            $scope = json_decode($meta['scope'], true, 32, JSON_THROW_ON_ERROR);
        } catch (Throwable $e) {
            throw new FastLookupIndexUnavailableException('The fastLookup index metadata is corrupt.', 0, $e);
        }
        if ($scope !== $this->scope) {
            throw new FastLookupIndexUnavailableException('The fastLookup index scope does not match its configuration.');
        }
        $generations = [];
        if ($meta['live'] !== '') { $generations[$meta['live']] = $this->generationInfo($meta['live']); }
        if ($meta['building'] !== '') {
            // A broken build must never take the live generation down: omit
            // it, and the manager fails only the build (prepareBuild).
            try {
                $generations[$meta['building']] = $this->generationInfo($meta['building']);
            } catch (FastLookupIndexUnavailableException $e) {
            }
        }
        return [
            'live' => $meta['live'] === '' ? null : $meta['live'],
            'building' => $meta['building'] === '' ? null : $meta['building'],
            'fingerprint' => $meta['fingerprint'] === '' ? null : $meta['fingerprint'],
            'building_fingerprint' => $meta['building_fingerprint'] === '' ? null : $meta['building_fingerprint'],
            'revision' => $meta['revision'],
            'ready' => $meta['ready'] === '1',
            'generations' => $generations,
        ];
    }

    public function reserve(string $generation, string $fingerprint, int $capacity, float $rate, int $rangeEntries): void
    {
        $this->identifier($generation);
        $this->identifier($fingerprint);
        if ($capacity < 1 || $rate <= 0 || $rate >= 1 || $rangeEntries < 0) {
            throw new InvalidArgumentException('Invalid fastLookup filter sizing.');
        }
        $buckets = self::bucketsFor($rangeEntries);
        try {
            $live = $this->metadata()['live'];
        } catch (FastLookupIndexUnavailableException $e) {
            // Unusable metadata cannot be served anyway; start a clean namespace.
            $live = null;
            $this->call('del', [$this->metaKey()]);
            $this->call('hMSet', [$this->metaKey(), ['schema' => self::SCHEMA, 'live' => '', 'building' => '',
                'fingerprint' => '', 'building_fingerprint' => '', 'revision' => '0', 'ready' => '0',
                'scope' => json_encode($this->scope, JSON_THROW_ON_ERROR)]]);
        }
        $this->evaluate(<<<'LUA'
if redis.call('HGET', KEYS[1], 'live') == ARGV[1] then return redis.error_reply('a rebuild must use a fresh generation') end
if redis.call('EXISTS', KEYS[2]) ~= 0 or redis.call('EXISTS', KEYS[3]) ~= 0 then return redis.error_reply('generation keys already exist') end
redis.call('BF.RESERVE', KEYS[3], ARGV[4], ARGV[3], 'NONSCALING')
redis.call('HSET', KEYS[2], '!', ARGV[1], 'capacity', ARGV[3], 'rate', ARGV[4], 'inserted', '0', 'stale', '0', 'buckets', ARGV[5], 'cursor', '0')
redis.call('HSET', KEYS[1], 'building', ARGV[1], 'building_fingerprint', ARGV[2])
return 1
LUA
            , [$this->metaKey(), $this->infoKey($generation), $this->bloomKey($generation)],
            [$generation, $fingerprint, (string)$capacity, rtrim(sprintf('%.10F', $rate), '0'), (string)$buckets]);
        $keys = [];
        for ($i = 0; $i < $buckets; ++$i) {
            $keys[] = $this->generationPrefix($generation) . 'x:' . $i;
            if (count($keys) === self::POSTING_BATCH || $i === $buckets - 1) {
                $this->evaluate(<<<'LUA'
if redis.call('HGET', KEYS[1], 'building') ~= ARGV[1] then return redis.error_reply('generation changed') end
for i = 2, #KEYS do
    if redis.call('EXISTS', KEYS[i]) ~= 0 then return redis.error_reply('generation keys already exist') end
    redis.call('HSET', KEYS[i], '!', ARGV[1])
end
return 1
LUA
                    , array_merge([$this->metaKey()], $keys), [$generation]);
                $keys = [];
            }
        }
        $this->deleteGenerations(array_values(array_filter([$live, $generation])));
    }

    public function add(string $generation, array $prepared): void
    {
        $this->identifier($generation);
        $tokens = []; $postings = [];
        foreach ($prepared as $row) {
            if (!is_array($row) || !isset($row['id'], $row['tokens']) || !is_string($row['id']) || !is_array($row['tokens'])) {
                throw new InvalidArgumentException('Malformed prepared fastLookup attribute.');
            }
            $this->decimalId($row['id']);
            if (count($row['tokens']) > self::MAX_TOKENS_PER_ATTRIBUTE) {
                throw new OverflowException('An attribute has too many fastLookup index tokens.');
            }
            foreach ($row['tokens'] as $token) {
                $this->token($token);
                $tokens[$token] = true;
                if ($token[0] !== 'E') { $postings[$token][$row['id']] = $row['id']; }
            }
        }
        $fence = [$this->metaKey(), $this->infoKey($generation), $this->bloomKey($generation)];
        foreach (array_chunk(array_map('strval', array_keys($tokens)), self::FILTER_BATCH) as $chunk) {
            $this->evaluate($this->fenceScript() . <<<'LUA'
local added = redis.call('BF.MADD', KEYS[3], unpack(ARGV, 2))
local count = 0
for _, flag in ipairs(added) do if flag == 1 then count = count + 1 end end
redis.call('HINCRBY', KEYS[2], 'inserted', count)
return count
LUA
                , $fence, array_merge([$generation], $chunk));
        }
        if (!$postings) {
            return;
        }
        $buckets = $this->bucketCount($generation);
        foreach (array_chunk($postings, self::POSTING_BATCH, true) as $chunk) {
            $keys = $fence; $args = [$generation];
            foreach ($chunk as $token => $ids) {
                $token = (string)$token;
                array_push($args, $this->keyIndex($keys, $this->postingKey($generation, $token, $buckets)), $token, count($ids));
                foreach ($ids as $id) { $args[] = $id; }
            }
            $this->evaluate($this->fenceScript() . $this->postingScript() . <<<'LUA'
local i = 2
while i <= #ARGV do
    local bucket, token, count = KEYS[tonumber(ARGV[i])], ARGV[i + 1], tonumber(ARGV[i + 2])
    if redis.call('HGET', bucket, '!') ~= ARGV[1] then return redis.error_reply('missing posting bucket') end
    local overflow = bucket .. ':' .. hex(token)
    local raw, spilled = readPosting(bucket, overflow, token, ARGV[1])
    local ids, seen = parsePosting(raw)
    local add = {}
    for j = i + 3, i + 2 + count do
        if not seen[ARGV[j]] then
            seen[ARGV[j]] = true
            add[#add + 1] = ARGV[j] .. ','
        end
    end
    local updated = raw .. table.concat(add)
    if #updated > MAX_BYTES or #ids + #add > MAX_IDS then return redis.error_reply('posting resource limit exceeded') end
    writePosting(bucket, overflow, token, ARGV[1], updated, spilled)
    i = i + 3 + count
end
return 1
LUA
                , $keys, $args);
        }
    }

    public function markStale(string $generation, int $count): void
    {
        $this->identifier($generation);
        if ($count < 1) { return; }
        $this->evaluate($this->fenceScript() . "redis.call('HINCRBY', KEYS[2], 'stale', ARGV[2])\nreturn 1",
            [$this->metaKey(), $this->infoKey($generation), $this->bloomKey($generation)], [$generation, (string)$count]);
    }

    public function setCursor(string $generation, string $cursor): void
    {
        $this->identifier($generation);
        if ($cursor !== '0') { $this->decimalId($cursor); }
        $this->evaluate($this->fenceScript() . "redis.call('HSET', KEYS[2], 'cursor', ARGV[2])\nreturn 1",
            [$this->metaKey(), $this->infoKey($generation), $this->bloomKey($generation)], [$generation, $cursor]);
    }

    public function checkpoint(string $revision, bool $ready): void
    {
        $this->identifier($revision);
        $this->evaluate(<<<'LUA'
if redis.call('HGET', KEYS[1], 'schema') ~= ARGV[3] then return redis.error_reply('index missing') end
if ARGV[2] == '1' and redis.call('HGET', KEYS[1], 'live') == '' then return redis.error_reply('no live generation') end
redis.call('HSET', KEYS[1], 'revision', ARGV[1], 'ready', ARGV[2])
return 1
LUA
            , [$this->metaKey()], [$revision, $ready ? '1' : '0', self::SCHEMA]);
    }

    public function activate(string $generation, string $fingerprint): void
    {
        $this->identifier($generation);
        $this->identifier($fingerprint);
        $this->evaluate($this->fenceScript() . <<<'LUA'
if redis.call('HGET', KEYS[1], 'building') ~= ARGV[1] or redis.call('HGET', KEYS[1], 'building_fingerprint') ~= ARGV[2] then return redis.error_reply('generation changed') end
redis.call('HSET', KEYS[1], 'live', ARGV[1], 'fingerprint', ARGV[2], 'building', '', 'building_fingerprint', '', 'ready', '0')
return 1
LUA
            , [$this->metaKey(), $this->infoKey($generation), $this->bloomKey($generation)], [$generation, $fingerprint]);
        $this->deleteGenerations([$generation]);
        $this->deleteMatching($this->legacyPrefix . '*', null);
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
            $output[$position] = ['exact' => false, 'ip_range' => [], 'domain' => []];
            foreach ($tokens as $entry) {
                if (!is_array($entry) || !isset($entry['token'], $entry['kind'])) {
                    throw new InvalidArgumentException('Invalid fastLookup query token.');
                }
                $this->token($entry['token']);
                $kind = ['E' => 'exact', 'I' => 'ip_range', 'D' => 'domain'][$entry['token'][0]];
                if ($entry['kind'] !== $kind) { throw new InvalidArgumentException('The fastLookup token kind does not match.'); }
                $plan[$entry['token']][] = [$position, $kind];
            }
        }
        $before = $this->metadata();
        if (!$before['ready'] || $before['live'] !== $generation) {
            throw new FastLookupIndexUnavailableException('The fastLookup index is not ready for this generation.');
        }
        $buckets = $before['generations'][$generation]['buckets'];
        $count = 0;
        foreach (array_chunk(array_map('strval', array_keys($plan)), self::READ_BATCH_SIZE) as $batch) {
            $keys = [$this->metaKey(), $this->infoKey($generation), $this->bloomKey($generation)];
            $args = [$generation, (string)($maximumIds * 21)];
            foreach ($batch as $token) {
                array_push($args, $token[0] === 'E' ? 0 : $this->keyIndex($keys, $this->postingKey($generation, $token, $buckets)), $token);
            }
            $reply = $this->evaluate($this->postingScript() . <<<'LUA'
if redis.call('HGET', KEYS[1], 'live') ~= ARGV[1] or redis.call('HGET', KEYS[1], 'ready') ~= '1' then return redis.error_reply('index changed') end
if redis.call('HGET', KEYS[2], '!') ~= ARGV[1] then return redis.error_reply('missing generation state') end
if redis.call('EXISTS', KEYS[3]) ~= 1 or redis.call('TYPE', KEYS[3]).ok ~= BLOOM_TYPE then return redis.error_reply('missing Bloom filter') end
local tokens = {}
for i = 4, #ARGV, 2 do tokens[#tokens + 1] = ARGV[i] end
local present = redis.call('BF.MEXISTS', KEYS[3], unpack(tokens))
local bytes, result = 0, {}
for n, flag in ipairs(present) do
    local keyIndex, token = tonumber(ARGV[1 + 2 * n]), ARGV[2 + 2 * n]
    if flag ~= 1 then
        result[n] = false
    elseif keyIndex == 0 then
        result[n] = '1'
    else
        local bucket = KEYS[keyIndex]
        if redis.call('HGET', bucket, '!') ~= ARGV[1] then return redis.error_reply('missing posting bucket') end
        local raw = readPosting(bucket, bucket .. ':' .. hex(token), token, ARGV[1])
        bytes = bytes + #raw
        if bytes > tonumber(ARGV[2]) then return {0} end
        result[n] = raw
    end
end
return {1, result}
LUA
                , $keys, $args);
            if (!is_array($reply) || !isset($reply[0]) || !in_array($reply[0], [0, 1], true)) {
                throw new FastLookupIndexUnavailableException('Invalid fastLookup filter response.');
            }
            if ($reply[0] === 0) {
                throw new OverflowException('The fastLookup candidate payload exceeds the request budget.');
            }
            $rows = $reply[1] ?? null;
            if (!is_array($rows) || count($rows) !== count($batch)) {
                throw new FastLookupIndexUnavailableException('Invalid fastLookup filter response.');
            }
            foreach ($batch as $offset => $token) {
                $row = $rows[$offset];
                if ($row === false || $row === null || $row === '') { continue; }
                if ($token[0] === 'E') {
                    if ($row !== '1') { throw new FastLookupIndexUnavailableException('Invalid fastLookup filter response.'); }
                    foreach ($plan[$token] as [$position]) { $output[$position]['exact'] = true; }
                    continue;
                }
                $ids = $this->parsePosting($row, $maximumIds);
                foreach ($plan[$token] as [$position, $kind]) {
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
        if (!$after['ready'] || $after['live'] !== $generation || $after['revision'] !== $before['revision']) {
            throw new FastLookupIndexUnavailableException('The fastLookup index changed during the lookup.');
        }
        foreach ($output as &$kinds) {
            foreach (['ip_range', 'domain'] as $kind) {
                $ids = array_values($kinds[$kind]);
                usort($ids, static function ($a, $b) { return strlen($a) <=> strlen($b) ?: strcmp($a, $b); });
                $kinds[$kind] = $ids;
            }
        }
        unset($kinds);
        return $output;
    }

    public function statistics(string $generation): array
    {
        $meta = $this->metadata();
        if (!isset($meta['generations'][$generation])) {
            throw new FastLookupIndexUnavailableException('The fastLookup generation changed.');
        }
        $info = $meta['generations'][$generation];
        $reason = null;
        $shared = $this->sumMemory($this->memory($this->metaKey(), $reason), $this->memory($this->infoKey($generation), $reason));
        $filterBytes = $this->memory($this->bloomKey($generation), $reason);
        $postingBytes = 0; $entries = 0;
        for ($i = 0; $i < $info['buckets']; ++$i) {
            $bucket = $this->generationPrefix($generation) . 'x:' . $i;
            $postingBytes = $this->sumMemory($postingBytes, $this->memory($bucket, $reason));
            $sentinel = false;
            foreach ($this->hashEntries($bucket) as $field => $value) {
                if ($field === '!') { $sentinel = $value === $generation; continue; }
                try { $this->token((string)$field); } catch (InvalidArgumentException $e) {
                    throw new FastLookupIndexUnavailableException('Corrupt posting field.', 0, $e);
                }
                if ($value === '*') {
                    $overflow = $bucket . ':' . bin2hex((string)$field);
                    $stored = $this->call('get', [$overflow]);
                    if (!is_string($stored) || strpos($stored, $generation . '|') !== 0) {
                        throw new FastLookupIndexUnavailableException('A fastLookup overflow posting is missing.');
                    }
                    $postingBytes = $this->sumMemory($postingBytes, $this->memory($overflow, $reason));
                    $value = substr($stored, strlen($generation) + 1);
                }
                $entries += count($this->parsePosting($value, self::MAX_POSTING_IDS));
            }
            if (!$sentinel) { throw new FastLookupIndexUnavailableException('A fastLookup posting bucket is missing.'); }
        }
        $after = $this->metadata();
        if (!isset($after['generations'][$generation]) || $after['revision'] !== $meta['revision']) {
            throw new FastLookupIndexUnavailableException('The fastLookup index changed during measurement.');
        }
        return [
            'capacity' => $info['capacity'], 'rate' => $info['rate'], 'inserted' => $info['inserted'], 'stale' => $info['stale'],
            'estimated_false_positive_rate' => self::estimatedFalsePositiveRate($info['capacity'], $info['rate'], $info['inserted']),
            'filter_bytes' => $filterBytes, 'posting_bytes' => $postingBytes, 'posting_entries' => $entries,
            'shared_memory_bytes' => $shared, 'measured_at' => gmdate('c'), 'memory_unavailable_reason' => $reason,
        ];
    }

    private function generationInfo(string $generation): array
    {
        $reply = $this->evaluate(<<<'LUA'
if redis.call('HGET', KEYS[1], '!') ~= ARGV[1] then return redis.error_reply('missing generation state') end
if redis.call('EXISTS', KEYS[2]) ~= 1 or redis.call('TYPE', KEYS[2]).ok ~= ARGV[2] then return redis.error_reply('missing Bloom filter') end
return redis.call('HMGET', KEYS[1], 'capacity', 'rate', 'inserted', 'stale', 'buckets', 'cursor')
LUA
            , [$this->infoKey($generation), $this->bloomKey($generation)], [$generation, self::BLOOM_TYPE]);
        if (!is_array($reply) || count($reply) !== 6) {
            throw new FastLookupIndexUnavailableException('Invalid fastLookup generation state.');
        }
        [$capacity, $rate, $inserted, $stale, $buckets, $cursor] = $reply;
        foreach ([$capacity, $inserted, $stale, $buckets, $cursor] as $number) {
            if (!is_string($number) || !ctype_digit($number)) {
                throw new FastLookupIndexUnavailableException('Invalid fastLookup generation state.');
            }
        }
        if (!is_string($rate) || !is_numeric($rate)) {
            throw new FastLookupIndexUnavailableException('Invalid fastLookup generation state.');
        }
        return ['capacity' => (int)$capacity, 'rate' => (float)$rate, 'inserted' => (int)$inserted,
            'stale' => (int)$stale, 'buckets' => (int)$buckets, 'cursor' => $cursor];
    }

    private function bucketCount(string $generation): int
    {
        $buckets = $this->call('hGet', [$this->infoKey($generation), 'buckets']);
        if (!is_string($buckets) || !ctype_digit($buckets) || (int)$buckets < 1) {
            throw new FastLookupIndexUnavailableException('The fastLookup generation state is missing.');
        }
        return (int)$buckets;
    }

    /** Deletes every generation of this namespace except $keep. */
    private function deleteGenerations(array $keep): void
    {
        $prefixes = array_map([$this, 'generationPrefix'], $keep);
        $this->deleteMatching($this->prefix . 'g:*', $prefixes);
    }

    private function deleteMatching(string $pattern, ?array $keepPrefixes): void
    {
        $cursor = null;
        do {
            try { $keys = $this->connection()->scan($cursor, $pattern, self::DELETE_BATCH); } catch (Throwable $e) {
                throw new FastLookupIndexUnavailableException('Could not reclaim old fastLookup keys.', 0, $e);
            }
            if ($keys) {
                $keys = array_values(array_filter($keys, static function ($key) use ($keepPrefixes) {
                    foreach ($keepPrefixes ?? [] as $prefix) { if (strpos($key, $prefix) === 0) { return false; } }
                    return true;
                }));
                foreach (array_chunk($keys, self::DELETE_BATCH) as $batch) { $this->call('unlink', [$batch]); }
            }
            if (!is_int($cursor) || $cursor < 0) { throw new FastLookupIndexUnavailableException('Invalid fastLookup cleanup cursor.'); }
        } while ($cursor !== 0);
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
            try { $this->decimalId($id); } catch (InvalidArgumentException $e) {
                throw new FastLookupIndexUnavailableException('A fastLookup identifier is corrupt.', 0, $e);
            }
            if (isset($seen[$id])) { throw new FastLookupIndexUnavailableException('A fastLookup posting contains duplicate identifiers.'); }
            $seen[$id] = true;
        }
        return $ids;
    }

    private function hashEntries($key): Generator
    {
        $cursor = null;
        do {
            try { $rows = $this->connection()->hScan($key, $cursor, null, self::POSTING_BATCH); } catch (Throwable $e) {
                throw new FastLookupIndexUnavailableException('Could not scan the fastLookup index.', 0, $e);
            }
            if ($rows !== false && !is_array($rows)) { throw new FastLookupIndexUnavailableException('Invalid fastLookup scan response.'); }
            foreach ($rows ?: [] as $field => $value) { yield $field => $value; }
            if (!is_int($cursor) || $cursor < 0) { throw new FastLookupIndexUnavailableException('Invalid fastLookup scan cursor.'); }
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
    private function infoKey($generation): string { return $this->generationPrefix($generation) . 'info'; }
    private function bloomKey($generation): string { return $this->generationPrefix($generation) . 'bf'; }
    private function postingKey($generation, string $token, int $buckets): string
    {
        return $this->generationPrefix($generation) . 'x:' . (unpack('N', $token, 1)[1] % $buckets);
    }
    /** Appends $key to a Lua KEYS list once and returns its one-based index. */
    private function keyIndex(array &$keys, string $key): int
    {
        $index = array_search($key, $keys, true);
        if ($index === false) {
            $keys[] = $key;
            $index = count($keys) - 1;
        }
        return $index + 1;
    }
    private function identifier($value): void
    {
        if (!is_string($value) || !preg_match('/\A[A-Za-z0-9_-]{1,128}\z/D', $value)) { throw new InvalidArgumentException('Invalid fastLookup generation, revision or fingerprint.'); }
    }
    private function decimalId($value): void
    {
        if (!is_string($value) || !preg_match('/\A[1-9][0-9]{0,19}\z/D', $value)) { throw new InvalidArgumentException('Invalid fastLookup decimal identifier.'); }
    }
    private function token($token): void
    {
        if (!is_string($token) || strlen($token) !== self::TOKEN_BYTES || !in_array($token[0], ['E', 'I', 'D'], true)) { throw new InvalidArgumentException('Invalid fastLookup binary token.'); }
    }
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
                throw new OverflowException('A fastLookup posting exceeds the limit of 8 MiB or 500000 attribute IDs.', 0, $e);
            }
            throw $e;
        }
        if ($result === false) {
            $error = $this->call('getLastError', []);
            if (is_string($error) && strpos($error, 'posting resource limit exceeded') !== false) {
                throw new OverflowException('A fastLookup posting exceeds the limit of 8 MiB or 500000 attribute IDs.');
            }
            throw new FastLookupIndexUnavailableException('Redis refused a fastLookup index operation.');
        }
        return $result;
    }
    /** KEYS[1..3] = metadata, generation state, filter; ARGV[1] = a live or building generation. */
    private function fenceScript(): string
    {
        return "local BLOOM_TYPE = '" . self::BLOOM_TYPE . "'\n" . <<<'LUA'
if ARGV[1] ~= redis.call('HGET', KEYS[1], 'live') and ARGV[1] ~= redis.call('HGET', KEYS[1], 'building') then return redis.error_reply('generation changed') end
if redis.call('HGET', KEYS[2], '!') ~= ARGV[1] then return redis.error_reply('missing generation state') end
if redis.call('EXISTS', KEYS[3]) ~= 1 or redis.call('TYPE', KEYS[3]).ok ~= BLOOM_TYPE then return redis.error_reply('missing Bloom filter') end

LUA;
    }
    private function postingScript(): string
    {
        return "local BLOOM_TYPE = '" . self::BLOOM_TYPE . "'\nlocal MAX_BYTES = " . self::MAX_POSTING_BYTES
            . "\nlocal MAX_IDS = " . self::MAX_POSTING_IDS . "\nlocal INLINE_BYTES = " . self::INLINE_POSTING_BYTES . "\n" . <<<'LUA'
local function hex(s)
    return (string.gsub(s, '.', function (c) return string.format('%02x', string.byte(c)) end))
end

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

local function readPosting(bucket, overflow, field, generation)
    local raw = redis.call('HGET', bucket, field)
    if raw ~= '*' then return raw or '', false end
    local stored = redis.call('GET', overflow)
    local prefix = generation .. '|'
    if not stored or string.sub(stored, 1, #prefix) ~= prefix then error('missing overflow posting') end
    return string.sub(stored, #prefix + 1), true
end

local function writePosting(bucket, overflow, field, generation, value, spilled)
    if #value > INLINE_BYTES then
        redis.call('SET', overflow, generation .. '|' .. value)
        redis.call('HSET', bucket, field, '*')
        return
    end
    if spilled then redis.call('DEL', overflow) end
    if value == '' then redis.call('HDEL', bucket, field) else redis.call('HSET', bucket, field, value) end
end

LUA;
    }
}
