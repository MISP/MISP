<?php

/** Missing, incomplete or corrupt Redis state must never look like a negative lookup. */
class FastLookupIndexUnavailableException extends RuntimeException
{
}

/**
 * Redis answered, and the index state it holds is missing or invalid. Only
 * this may reset the namespace or drop a generation: a transport or server
 * error (timeout, BUSY, LOADING, a refused command) is merely unavailable and
 * must never be taken for a lost index.
 */
class FastLookupIndexCorruptException extends FastLookupIndexUnavailableException
{
}

/** The set of indexed IP prefix lengths changed after the caller read it. */
class FastLookupPrefixesChangedException extends FastLookupIndexUnavailableException
{
}

/** Candidate work exceeds its cap; never a result-size limit. */
class FastLookupResourceLimitException extends RuntimeException
{
}

/**
 * A generation's filter is full and refused tokens: the write failed, and the
 * generation cannot take them until it is rebuilt larger.
 */
class FastLookupIndexFullException extends FastLookupIndexUnavailableException
{
    public $generation;

    public function __construct(string $generation, ?Throwable $previous = null)
    {
        parent::__construct('The fastLookup filter is full.', 0, $previous);
        $this->generation = $generation;
    }
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
    /**
     * Stamped when a generation with IP prefix masks is reserved. Code that
     * knows only LEGACY_SCHEMA fails closed on it rather than adding ranges
     * without updating the masks; a legacy namespace keeps being served.
     */
    const SCHEMA = 'bloom-2';
    const LEGACY_SCHEMA = 'bloom-1';
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
    /** Posting bytes per budgeted candidate ID. */
    const CANDIDATE_BYTES_PER_ID = 21;
    const MAX_TOKENS_PER_ATTRIBUTE = 1024;
    const FILTER_BATCH = 1000;
    const POSTING_BATCH = 128;
    const READ_BATCH_SIZE = 1024;
    const DELETE_BATCH = 500;
    /** The add script's error reply; its ARGV[1] names the full generation. */
    const FULL_ERROR = 'Bloom filter is full';

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

    /**
     * A filter at its capacity may have lost tokens: an earlier release did
     * not report the adds a full filter refused.
     */
    public static function filterFull(int $capacity, int $inserted): bool
    {
        return $inserted >= $capacity;
    }

    public function moduleAvailable(): bool
    {
        return $this->moduleState() === 'available';
    }

    /**
     * 'available'; 'missing' when Redis answered without the BF commands;
     * 'unreachable' when Redis could not be asked or refused the question.
     */
    public function moduleState(): string
    {
        try {
            $info = $this->connection()->rawCommand('COMMAND', 'INFO', 'BF.MEXISTS');
        } catch (Throwable $e) {
            return 'unreachable';
        }
        if (is_array($info) && isset($info[0]) && is_array($info[0])) {
            return 'available';
        }
        // phpredis returns [false] (a nil element) for an unknown command; an
        // error reply makes the whole result false.
        return is_array($info) && count($info) === 1 && ($info[0] === false || $info[0] === null) ? 'missing' : 'unreachable';
    }

    public function metadata(): array
    {
        $meta = $this->call('hGetAll', [$this->metaKey()]);
        if (!is_array($meta)) {
            // A refused read is not a lost index, unless the key is no hash.
            $error = $this->call('getLastError', []);
            if (is_string($error) && strpos($error, 'WRONGTYPE') === 0) {
                throw new FastLookupIndexCorruptException('The fastLookup index metadata is invalid.');
            }
            throw new FastLookupIndexUnavailableException('Redis could not read the fastLookup index metadata.');
        }
        if (!in_array($meta['schema'] ?? null, [self::SCHEMA, self::LEGACY_SCHEMA], true)
            || !isset($meta['live'], $meta['building'], $meta['fingerprint'], $meta['building_fingerprint'], $meta['revision'], $meta['scope'])
            || !in_array($meta['ready'] ?? null, ['0', '1'], true)) {
            throw new FastLookupIndexCorruptException('The fastLookup index metadata is missing or invalid.');
        }
        try {
            $this->identifier($meta['revision']);
            foreach (['live', 'building', 'fingerprint', 'building_fingerprint'] as $field) {
                if ($meta[$field] !== '') { $this->identifier($meta[$field]); }
            }
            $scope = json_decode($meta['scope'], true, 32, JSON_THROW_ON_ERROR);
        } catch (Throwable $e) {
            throw new FastLookupIndexCorruptException('The fastLookup index metadata is corrupt.', 0, $e);
        }
        if ($scope !== $this->scope) {
            throw new FastLookupIndexCorruptException('The fastLookup index scope does not match its configuration.');
        }
        $generations = [];
        if ($meta['live'] !== '') { $generations[$meta['live']] = $this->generationInfo($meta['live']); }
        if ($meta['building'] !== '') {
            // A broken build must never take the live generation down: omit
            // it, and the manager fails only the build (prepareBuild). A
            // transport error is no broken build and propagates.
            try {
                $generations[$meta['building']] = $this->generationInfo($meta['building']);
            } catch (FastLookupIndexCorruptException $e) {
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
        } catch (FastLookupIndexCorruptException $e) {
            // Missing or invalid metadata cannot be served anyway; start a
            // clean namespace. Any other failure propagates: a transient
            // Redis error must never delete the live generation.
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
redis.call('HSET', KEYS[2], '!', ARGV[1], 'capacity', ARGV[3], 'rate', ARGV[4], 'inserted', '0', 'stale', '0', 'buckets', ARGV[5], 'cursor', '0',
    'p4', string.rep('0', 33), 'p6', string.rep('0', 129), 'pv', '0')
redis.call('HSET', KEYS[1], 'building', ARGV[1], 'building_fingerprint', ARGV[2], 'schema', ARGV[6])
return 1
LUA
            , [$this->metaKey(), $this->infoKey($generation), $this->bloomKey($generation)],
            [$generation, $fingerprint, (string)$capacity, rtrim(sprintf('%.10F', $rate), '0'), (string)$buckets, self::SCHEMA]);
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
        $tokens = []; $postings = []; $lengths = [4 => [], 6 => []];
        foreach ($prepared as $row) {
            if (!is_array($row) || !isset($row['id'], $row['tokens']) || !is_string($row['id']) || !is_array($row['tokens'])
                || (isset($row['networks']) && !is_array($row['networks']))) {
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
            foreach ($row['networks'] ?? [] as $network) {
                if (!is_array($network) || count($network) !== 2 || !isset($network[0], $network[1])
                    || !is_int($network[0]) || !is_int($network[1]) || !in_array($network[0], [4, 6], true)
                    || $network[1] < 0 || $network[1] > ($network[0] === 4 ? 32 : 128)) {
                    throw new InvalidArgumentException('Malformed prepared fastLookup attribute.');
                }
                $lengths[$network[0]][$network[1]] = true;
            }
        }
        $fence = [$this->metaKey(), $this->infoKey($generation), $this->bloomKey($generation)];
        // Before any token of this call is visible: a range token's length must always be in the mask.
        if ($lengths[4] || $lengths[6]) {
            $this->evaluate($this->fenceScript() . <<<'LUA'
local p4, p6 = redis.call('HGET', KEYS[2], 'p4'), redis.call('HGET', KEYS[2], 'p6')
local pv = redis.call('HGET', KEYS[2], 'pv')
if not p4 and not p6 and not pv then return 0 end
if not p4 or not p6 or not pv or not string.match(pv, '^%d+$') or #p4 ~= 33 or #p6 ~= 129 or string.find(p4, '[^01]') or string.find(p6, '[^01]') then
    return redis.error_reply('corrupt prefix mask')
end
local function merge(mask, list)
    local bytes, changed = {string.byte(mask, 1, #mask)}, false
    for n in string.gmatch(list, '%d+') do
        local i = tonumber(n) + 1
        if bytes[i] ~= 49 then bytes[i] = 49; changed = true end
    end
    return string.char(unpack(bytes)), changed
end
local n4, c4 = merge(p4, ARGV[2])
local n6, c6 = merge(p6, ARGV[3])
if not (c4 or c6) then return 0 end
redis.call('HSET', KEYS[2], 'p4', n4, 'p6', n6)
redis.call('HINCRBY', KEYS[2], 'pv', 1)
return 1
LUA
                , $fence, [$generation, implode(',', array_keys($lengths[4])), implode(',', array_keys($lengths[6]))]);
        }
        foreach (array_chunk(array_map('strval', array_keys($tokens)), self::FILTER_BATCH) as $chunk) {
            $this->evaluate($this->fenceScript() . <<<'LUA'
local added = redis.call('BF.MADD', KEYS[3], unpack(ARGV, 2))
local count = 0
for _, flag in ipairs(added) do
    -- A full NONSCALING filter answers an error for the rest of the batch.
    if type(flag) == 'table' and flag.err then
        redis.call('HINCRBY', KEYS[2], 'inserted', count)
        return redis.error_reply('Bloom filter is full')
    end
    if flag == 1 then count = count + 1 end
end
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
                array_push($args, $this->keyIndex($keys, $this->postingKey($generation, $token, $buckets)), $token, bin2hex($token), count($ids));
                foreach ($ids as $id) { $args[] = $id; }
            }
            $this->evaluate($this->fenceScript() . $this->postingScript() . <<<'LUA'
local i = 2
local checked = {}
while i <= #ARGV do
    local bucket, token, count = KEYS[tonumber(ARGV[i])], ARGV[i + 1], tonumber(ARGV[i + 3])
    if not checked[bucket] then
        if redis.call('HGET', bucket, '!') ~= ARGV[1] then return redis.error_reply('missing posting bucket') end
        checked[bucket] = true
    end
    if #ARGV[i + 2] ~= 2 * #token then return redis.error_reply('malformed posting request') end
    local overflow = bucket .. ':' .. ARGV[i + 2]
    local raw, spilled = readPosting(bucket, overflow, token, ARGV[1])
    local ids, seen = parsePosting(raw)
    local add = {}
    for j = i + 4, i + 3 + count do
        if not seen[ARGV[j]] then
            seen[ARGV[j]] = true
            add[#add + 1] = ARGV[j] .. ','
        end
    end
    local updated = raw .. table.concat(add)
    if #updated > MAX_BYTES or #ids + #add > MAX_IDS then return redis.error_reply('posting resource limit exceeded') end
    writePosting(bucket, overflow, token, ARGV[1], updated, spilled)
    i = i + 4 + count
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
local schema = redis.call('HGET', KEYS[1], 'schema')
if schema ~= ARGV[3] and schema ~= ARGV[4] then return redis.error_reply('index missing') end
if ARGV[2] == '1' and redis.call('HGET', KEYS[1], 'live') == '' then return redis.error_reply('no live generation') end
redis.call('HSET', KEYS[1], 'revision', ARGV[1], 'ready', ARGV[2])
return 1
LUA
            , [$this->metaKey()], [$revision, $ready ? '1' : '0', self::SCHEMA, self::LEGACY_SCHEMA]);
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

    /**
     * The IP prefix lengths a generation's range tokens use, and the version of
     * that set; 'lengths' is null for a generation built without masks.
     */
    public function prefixLengths(string $generation): array
    {
        $this->identifier($generation);
        $reply = $this->evaluate($this->guardScript() . <<<'LUA'
local failure = requireGeneration(KEYS[1], KEYS[2], ARGV[1])
if failure then return failure end
return redis.call('HMGET', KEYS[1], 'p4', 'p6', 'pv')
LUA
            , [$this->infoKey($generation), $this->bloomKey($generation)], [$generation]);
        if (!is_array($reply) || count($reply) !== 3) {
            throw new FastLookupIndexCorruptException('The fastLookup IP prefix state is corrupt.');
        }
        [$p4, $p6, $pv] = array_values($reply);
        if (!self::validPrefixState($p4, $p6, $pv)) {
            throw new FastLookupIndexCorruptException('The fastLookup IP prefix state is corrupt.');
        }
        if ($p4 === false || $p4 === null) {
            return ['version' => '', 'lengths' => null];
        }
        $lengths = [4 => [], 6 => []];
        foreach ([4 => $p4, 6 => $p6] as $family => $mask) {
            for ($n = 0, $size = strlen($mask); $n < $size; ++$n) {
                if ($mask[$n] === '1') {
                    $lengths[$family][$n] = true;
                }
            }
        }
        return ['version' => $pv, 'lengths' => $lengths];
    }

    /**
     * $maximumIds bounds this call's candidates and their posting bytes.
     * A non-null $prefixVersion fails when the prefix set has moved on.
     */
    public function candidates(
        string $generation,
        array $queryTokens,
        int $maximumIds = self::MAX_POSTING_IDS,
        ?string $prefixVersion = null
    ): array
    {
        $this->identifier($generation);
        if ($prefixVersion !== null && $prefixVersion !== '' && !ctype_digit($prefixVersion)) {
            throw new InvalidArgumentException('Invalid fastLookup prefix version.');
        }
        if ($maximumIds < 0 || $maximumIds > self::MAX_POSTING_IDS) {
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
        $info = $before['generations'][$generation];
        if (self::filterFull($info['capacity'], $info['inserted'])) {
            throw new FastLookupIndexFullException($generation);
        }
        $buckets = $info['buckets'];
        $count = 0;
        $bytes = $maximumIds * self::CANDIDATE_BYTES_PER_ID;
        foreach (array_chunk(array_map('strval', array_keys($plan)), self::READ_BATCH_SIZE) as $batch) {
            $keys = [$this->metaKey(), $this->infoKey($generation), $this->bloomKey($generation)];
            $args = [$generation, (string)$bytes, $prefixVersion ?? '-'];
            foreach ($batch as $token) {
                array_push($args, $token[0] === 'E' ? 0 : $this->keyIndex($keys, $this->postingKey($generation, $token, $buckets)), $token);
            }
            $reply = $this->evaluate($this->guardScript() . $this->postingScript() . <<<'LUA'
if redis.call('HGET', KEYS[1], 'live') ~= ARGV[1] or redis.call('HGET', KEYS[1], 'ready') ~= '1' then return redis.error_reply('index changed') end
local failure = requireGeneration(KEYS[2], KEYS[3], ARGV[1])
if failure then return failure end
if ARGV[3] ~= '-' and (redis.call('HGET', KEYS[2], 'pv') or '') ~= ARGV[3] then return {2} end
local tokens = {}
for i = 5, #ARGV, 2 do tokens[#tokens + 1] = ARGV[i] end
local present = redis.call('BF.MEXISTS', KEYS[3], unpack(tokens))
local bytes, result = 0, {}
for n, flag in ipairs(present) do
    local keyIndex, token = tonumber(ARGV[2 + 2 * n]), ARGV[3 + 2 * n]
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
            if (!is_array($reply) || !isset($reply[0]) || !in_array($reply[0], [0, 1, 2], true)) {
                throw new FastLookupIndexUnavailableException('Invalid fastLookup filter response.');
            }
            if ($reply[0] === 2) {
                throw new FastLookupPrefixesChangedException('The fastLookup IP prefix set changed during the lookup.');
            }
            if ($reply[0] === 0) {
                throw new FastLookupResourceLimitException('The fastLookup candidate payload exceeds the per-request resource cap.');
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
                $bytes -= is_string($row) ? strlen($row) : 0;
                if ($bytes < 0) {
                    throw new FastLookupResourceLimitException('The fastLookup candidate payload exceeds the per-request resource cap.');
                }
                $ids = $this->parsePosting($row, $maximumIds);
                foreach ($plan[$token] as [$position, $kind]) {
                    foreach ($ids as $id) {
                        if (!isset($output[$position][$kind][$id])) {
                            if (++$count > $maximumIds) {
                                throw new FastLookupResourceLimitException('The fastLookup candidate IDs exceed the per-request resource cap.');
                            }
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

    /**
     * Worker exclusion across every MISP server sharing this Redis: a lease is
     * one key holding its owner's token with a TTL, so a dead worker's lease
     * expires by itself. Only the token's owner can renew or release it.
     */
    public function acquireLease(string $token, int $ttlMs): bool
    {
        $this->leaseArguments($token, $ttlMs);
        $this->call('clearLastError', []);
        $acquired = $this->call('set', [$this->leaseKey(), $token, ['nx', 'px' => $ttlMs]]);
        if ($acquired === false) {
            // SET NX answers false when another worker holds the lease; a
            // refused command must not pass for that.
            $error = $this->call('getLastError', []);
            if (is_string($error) && $error !== '') {
                throw new FastLookupIndexUnavailableException('Redis refused the fastLookup worker lease.');
            }
            return false;
        }
        return $acquired === true;
    }

    public function renewLease(string $token, int $ttlMs): bool
    {
        $this->leaseArguments($token, $ttlMs);
        return $this->evaluate(<<<'LUA'
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return 1
LUA
            , [$this->leaseKey()], [$token, (string)$ttlMs]) === 1;
    }

    /** Never deletes another worker's lease. Redis errors throw like every other call. */
    public function releaseLease(string $token): void
    {
        $this->identifier($token);
        $this->evaluate(<<<'LUA'
if redis.call('GET', KEYS[1]) == ARGV[1] then redis.call('DEL', KEYS[1]) end
return 1
LUA
            , [$this->leaseKey()], [$token]);
    }

    private function leaseArguments(string $token, int $ttlMs): void
    {
        $this->identifier($token);
        if ($ttlMs < 1 || $ttlMs > 86400000) {
            throw new InvalidArgumentException('Invalid fastLookup worker lease duration.');
        }
    }

    private function generationInfo(string $generation): array
    {
        $reply = $this->evaluate($this->guardScript() . <<<'LUA'
local failure = requireGeneration(KEYS[1], KEYS[2], ARGV[1])
if failure then return failure end
return redis.call('HMGET', KEYS[1], 'capacity', 'rate', 'inserted', 'stale', 'buckets', 'cursor', 'p4', 'p6', 'pv')
LUA
            , [$this->infoKey($generation), $this->bloomKey($generation)], [$generation]);
        if (!is_array($reply) || count($reply) !== 9) {
            throw new FastLookupIndexCorruptException('Invalid fastLookup generation state.');
        }
        [$capacity, $rate, $inserted, $stale, $buckets, $cursor, $p4, $p6, $pv] = array_values($reply);
        if (!self::validPrefixState($p4, $p6, $pv)) {
            throw new FastLookupIndexCorruptException('The fastLookup IP prefix state is corrupt.');
        }
        foreach ([$capacity, $inserted, $stale, $buckets, $cursor] as $number) {
            if (!is_string($number) || !ctype_digit($number)) {
                throw new FastLookupIndexCorruptException('Invalid fastLookup generation state.');
            }
        }
        if (!is_string($rate) || !is_numeric($rate)) {
            throw new FastLookupIndexCorruptException('Invalid fastLookup generation state.');
        }
        return ['capacity' => (int)$capacity, 'rate' => (float)$rate, 'inserted' => (int)$inserted,
            'stale' => (int)$stale, 'buckets' => (int)$buckets, 'cursor' => $cursor];
    }

    /** All three prefix fields absent (a legacy generation) or all well formed. */
    private static function validPrefixState($p4, $p6, $pv): bool
    {
        [$p4, $p6, $pv] = array_map(static function ($field) { return $field === null ? false : $field; }, [$p4, $p6, $pv]);
        if ($p4 === false && $p6 === false && $pv === false) {
            return true;
        }
        return is_string($p4) && preg_match('/\A[01]{33}\z/', $p4) && is_string($p6) && preg_match('/\A[01]{129}\z/', $p6)
            && is_string($pv) && ctype_digit($pv);
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
        if (substr_count($value, ',') > $maximum) {
            throw new FastLookupResourceLimitException('The fastLookup candidate IDs exceed the per-request resource cap.');
        }
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
    private function leaseKey(): string { return $this->prefix . 'worker'; }
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
            $this->call('clearLastError', []);
            $result = $this->call('eval', [$script, array_merge($keys, $args), count($keys)]);
        } catch (FastLookupIndexUnavailableException $e) {
            $cause = $e->getPrevious();
            if ($cause && strpos($cause->getMessage(), self::FULL_ERROR) !== false) {
                throw new FastLookupIndexFullException((string)$args[0], $e);
            }
            if ($cause && strpos($cause->getMessage(), 'posting resource limit exceeded') !== false) {
                throw new OverflowException('A fastLookup posting exceeds the limit of 8 MiB or 500000 attribute IDs.', 0, $e);
            }
            if ($cause && self::guardFailure($cause->getMessage())) {
                throw new FastLookupIndexCorruptException('A fastLookup generation is missing.', 0, $e);
            }
            if ($cause && $cause->getMessage() === 'corrupt prefix mask') {
                throw new FastLookupIndexCorruptException('The fastLookup IP prefix state is corrupt.', 0, $e);
            }
            throw $e;
        }
        if ($result === false) {
            $error = $this->call('getLastError', []);
            if (is_string($error) && strpos($error, self::FULL_ERROR) !== false) {
                throw new FastLookupIndexFullException((string)$args[0]);
            }
            if (is_string($error) && strpos($error, 'posting resource limit exceeded') !== false) {
                throw new OverflowException('A fastLookup posting exceeds the limit of 8 MiB or 500000 attribute IDs.');
            }
            if (is_string($error) && self::guardFailure($error)) {
                throw new FastLookupIndexCorruptException('A fastLookup generation is missing.');
            }
            if ($error === 'corrupt prefix mask') {
                throw new FastLookupIndexCorruptException('The fastLookup IP prefix state is corrupt.');
            }
            throw new FastLookupIndexUnavailableException('Redis refused a fastLookup index operation.');
        }
        return $result;
    }

    /** The error replies requireGeneration() gives: Redis answered, the generation is gone. */
    private static function guardFailure(string $error): bool
    {
        return in_array($error, ['missing generation state', 'missing Bloom filter'], true);
    }
    /** KEYS[1..3] = metadata, generation state, filter; ARGV[1] = a live or building generation. */
    private function fenceScript(): string
    {
        return $this->guardScript() . <<<'LUA'
if ARGV[1] ~= redis.call('HGET', KEYS[1], 'live') and ARGV[1] ~= redis.call('HGET', KEYS[1], 'building') then return redis.error_reply('generation changed') end
local failure = requireGeneration(KEYS[2], KEYS[3], ARGV[1])
if failure then return failure end

LUA;
    }
    /**
     * The one fail-closed generation guard: BF.MEXISTS reports absence for a
     * missing key and BF.MADD creates a default filter, so every script checks
     * the state sentinel and the filter's type first. Returns an error reply,
     * or nil when the generation is intact.
     */
    private function guardScript(): string
    {
        return "local BLOOM_TYPE = '" . self::BLOOM_TYPE . "'\n" . <<<'LUA'
local function requireGeneration(infoKey, bloomKey, generation)
    if redis.call('HGET', infoKey, '!') ~= generation then return redis.error_reply('missing generation state') end
    if redis.call('EXISTS', bloomKey) ~= 1 or redis.call('TYPE', bloomKey).ok ~= BLOOM_TYPE then return redis.error_reply('missing Bloom filter') end
    return nil
end

LUA;
    }
    private function postingScript(): string
    {
        return "local MAX_BYTES = " . self::MAX_POSTING_BYTES
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
