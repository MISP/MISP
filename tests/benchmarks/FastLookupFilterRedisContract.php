<?php
/** Run against a disposable Redis 8 Unix socket; touches only random test namespaces. */
declare(strict_types=1);

require_once __DIR__ . '/../../app/Lib/Tools/FastLookupFilter.php';
if (!class_exists('Redis') || empty($argv[1])) {
    throw new RuntimeException('Usage: php FastLookupFilterRedisContract.php /disposable/redis.sock (phpredis required)');
}

class FastLookupFilterContractProxy
{
    public $redis;
    public $noMemory = false;
    public $noModule = false;
    /** Renames BF.* calls inside scripts, so real Redis rejects them as unknown commands. */
    public $noBloomCommands = false;
    public $maximumReplyBytes = 0;
    /** Redis cannot be reached at all. */
    public $down = false;
    /** method => error message: the next such call fails like a timeout or BUSY reply. */
    public $failNext = [];
    public function __construct($redis) { $this->redis = $redis; }
    public function __call($name, $args)
    {
        $lower = strtolower($name);
        if ($this->down) {
            throw new RedisException('Connection refused');
        }
        if (isset($this->failNext[$lower])) {
            $message = $this->failNext[$lower];
            unset($this->failNext[$lower]);
            throw new RedisException($message);
        }
        if ($lower === 'rawcommand' && $this->noMemory && strtolower($args[0]) === 'memory') {
            throw new RuntimeException('ERR unknown command MEMORY');
        }
        if ($lower === 'rawcommand' && $this->noModule && strtolower($args[0]) === 'command') {
            // What phpredis returns for COMMAND INFO on an unknown command.
            return $this->redis->rawCommand('COMMAND', 'INFO', 'BF.UNLOADEDMEXISTS');
        }
        if ($lower === 'eval' && $this->noBloomCommands) {
            $args[0] = str_replace("'BF.", "'BF.UNLOADED", $args[0]);
        }
        $result = $this->redis->{$name}(...$args);
        if ($lower === 'eval' && isset($result[1]) && is_array($result[1])) {
            $this->maximumReplyBytes = max($this->maximumReplyBytes, array_sum(array_map(static function ($v) { return is_string($v) ? strlen($v) : 0; }, $result[1])));
        }
        return $result;
    }
    public function hScan($key, &$cursor, $pattern = null, $count = 0) { return $this->redis->hScan($key, $cursor, $pattern, $count); }
    public function scan(&$cursor, $pattern = null, $count = 0) { return $this->redis->scan($cursor, $pattern, $count); }
}

$redis = new Redis();
$redis->connect($argv[1]);
$proxy = new FastLookupFilterContractProxy($redis);
$namespace = 'contract-' . bin2hex(random_bytes(16));
$prefix = FastLookupFilter::PREFIX . hash('sha256', $namespace) . ':';
$legacy = FastLookupFilter::LEGACY_PREFIX . hash('sha256', $namespace) . ':';
$scope = ['attribute_types' => ['domain', 'ip-src'], 'published_only' => true];
$filter = new FastLookupFilter($namespace, $scope, $proxy);
$fullNamespace = 'contract-full-' . bin2hex(random_bytes(16));
$fullPrefix = FastLookupFilter::PREFIX . hash('sha256', $fullNamespace) . ':';
$tiny = new FastLookupFilter($fullNamespace, $scope, $proxy);
$assertions = 0;
$assert = static function ($condition, $message) use (&$assertions) {
    ++$assertions;
    if (!$condition) { throw new RuntimeException($message); }
};
$throws = static function ($call, $class, $message) use ($assert) {
    try { $call(); } catch (Throwable $e) {
        $assert($e instanceof $class, $message . ': got ' . get_class($e) . ' ' . $e->getMessage());
        return;
    }
    $assert(false, $message . ': no exception');
};
$token = static function ($kind, $value) { return $kind . substr(hash('sha256', $value, true), 0, 8); };
$keys = static function ($pattern) use ($redis) {
    $all = []; $cursor = null;
    do { $batch = $redis->scan($cursor, $pattern, 500); if ($batch) { $all = array_merge($all, $batch); } } while ($cursor !== 0);
    return $all;
};
$exact = $token('E', 'example.org');
$domain = $token('D', 'example.org');
$range = $token('I', '192.0.2.0/24');
$query = [7 => [['token' => $exact, 'kind' => 'exact']], 11 => [['token' => $domain, 'kind' => 'domain']],
    13 => [['token' => $range, 'kind' => 'ip_range']], 17 => [['token' => $token('E', 'absent.example'), 'kind' => 'exact']]];

try {
    $assert($filter->moduleAvailable() && $filter->moduleState() === 'available', 'RedisBloom is detected');
    $proxy->noModule = true;
    $assert(!$filter->moduleAvailable() && $filter->moduleState() === 'missing', 'A missing RedisBloom module is detected');
    $proxy->noModule = false;
    $proxy->down = true;
    $assert(!$filter->moduleAvailable() && $filter->moduleState() === 'unreachable', 'Unreachable Redis is not a missing module');
    $proxy->down = false;
    $throws(static function () use ($filter) { $filter->metadata(); }, FastLookupIndexCorruptException::class, 'Missing index fails closed as corrupt');

    $redis->set($legacy . 'metadata', 'old');
    $filter->reserve('first', str_repeat('a', 64), 1000, 0.001, 128);
    $meta = $filter->metadata();
    $assert($meta['live'] === null && $meta['building'] === 'first' && $meta['ready'] === false, 'Reserve creates a building generation');
    $assert($redis->hGet($prefix . 'metadata', 'schema') === 'bloom-2', 'A reset namespace carries the current schema');
    $assert($meta['generations']['first']['capacity'] === 1000 && $meta['generations']['first']['buckets'] === 2, 'Generation state records sizing');
    $assert($redis->eval("return redis.call('TYPE', KEYS[1]).ok", [$prefix . 'g:first:bf'], 1) === FastLookupFilter::BLOOM_TYPE, 'The filter is a RedisBloom filter');
    $throws(static function () use ($filter) { $filter->reserve('first', str_repeat('a', 64), 1000, 0.001, 128); }, FastLookupIndexUnavailableException::class, 'A generation is reserved once');

    $filter->add('first', [
        ['id' => '12', 'type' => 'domain', 'tokens' => [$exact, $domain]],
        ['id' => '13', 'type' => 'domain', 'tokens' => [$exact]],
        ['id' => '14', 'type' => 'ip-src', 'tokens' => [$range]],
    ]);
    $filter->add('first', [['id' => '12', 'type' => 'domain', 'tokens' => [$exact, $domain]]]);
    $assert($filter->metadata()['generations']['first']['inserted'] === 3, 'Re-adding counts only new filter entries');
    $filter->markStale('first', 2);
    $filter->setCursor('first', '14');
    $info = $filter->metadata()['generations']['first'];
    $assert($info['stale'] === 2 && $info['cursor'] === '14', 'Stale count and scan cursor are stored');
    $throws(static function () use ($filter, $query) { $filter->candidates('first', $query); }, FastLookupIndexUnavailableException::class, 'A building generation never answers');

    $filter->checkpoint('r1', false);
    $filter->activate('first', str_repeat('a', 64));
    $filter->checkpoint('r2', true);
    $assert(!$redis->exists($legacy . 'metadata'), 'Activation reclaims the legacy v3 index keys');
    $result = $filter->candidates('first', $query);
    $assert($result[7]['exact'] === true && $result[7]['ip_range'] === [] && $result[7]['domain'] === [], 'Exact tokens report maybe-present without IDs');
    $assert($result[11]['domain'] === ['12'], 'Domain postings are deduplicated');
    $assert($result[13]['ip_range'] === ['14'], 'Range postings keep their kind and position');
    $assert($result[17]['exact'] === false, 'An absent value is excluded by the filter');
    $throws(static function () use ($filter, $query) { $filter->candidates('other', $query); }, FastLookupIndexUnavailableException::class, 'Another generation is refused');
    $throws(static function () use ($filter) { $filter->candidates('first', [[['token' => $GLOBALS['exact'], 'kind' => 'domain']]]); }, InvalidArgumentException::class, 'Token kind mismatch is invalid');

    // No false negatives, and a false-positive rate near the configured one.
    $filter->reserve('second', str_repeat('b', 64), 100000, 0.01, 1);
    $inserted = [];
    for ($i = 0; $i < 100000; $i += 1000) {
        $rows = [];
        for ($j = $i; $j < $i + 1000; ++$j) { $rows[] = ['id' => (string)($j + 1), 'type' => 'domain', 'tokens' => [$inserted[] = $token('E', 'present-' . $j)]]; }
        $filter->add('second', $rows);
    }
    $filter->checkpoint('r3', false);
    $filter->activate('second', str_repeat('b', 64));
    $filter->checkpoint('r4', true);
    $assert(!$keys($prefix . 'g:first:*'), 'Activation removes the previous generation');
    $present = [];
    foreach ($inserted as $i => $t) { $present[$i] = [['token' => $t, 'kind' => 'exact']]; }
    $missing = 0;
    foreach (array_chunk($present, 5000, true) as $chunk) {
        foreach ($filter->candidates('second', $chunk) as $row) { $missing += $row['exact'] ? 0 : 1; }
    }
    $assert($missing === 0, 'No false negatives across 100,000 tokens');
    $absent = [];
    for ($i = 0; $i < 20000; ++$i) { $absent[$i] = [['token' => $token('E', 'absent-' . $i), 'kind' => 'exact']]; }
    $positives = 0;
    foreach (array_chunk($absent, 5000, true) as $chunk) {
        foreach ($filter->candidates('second', $chunk) as $row) { $positives += $row['exact'] ? 1 : 0; }
    }
    $assert($positives / 20000 <= 0.02, 'False-positive rate stays within twice the configured 1%: ' . ($positives / 20000));

    // Long postings overflow, stay listpack-encoded, and fail closed when evicted.
    $filter->reserve('third', str_repeat('c', 64), 1000, 0.001, 1);
    $rows = [];
    for ($id = 1000; $id < 1600; ++$id) { $rows[] = ['id' => (string)$id, 'type' => 'domain', 'tokens' => [$domain]]; }
    $filter->add('third', $rows);
    $filter->checkpoint('r5', false);
    $filter->activate('third', str_repeat('c', 64));
    $filter->checkpoint('r6', true);
    $overflow = array_values(array_filter($keys($prefix . 'g:third:x:*'), static function ($key) { return preg_match('/:x:\d+:[0-9a-f]{18}$/', $key) === 1; }));
    $assert(count($overflow) === 1, 'A long posting moves to one overflow key');
    $assert($redis->object('encoding', $prefix . 'g:third:x:0') === 'listpack', 'The bucket stays listpack-encoded');
    $assert(count($filter->candidates('third', [[['token' => $domain, 'kind' => 'domain']]])[0]['domain']) === 600, 'Overflow postings return every ID');
    $throws(static function () use ($filter, $domain) { $filter->candidates('third', [[['token' => $domain, 'kind' => 'domain']]], 10); }, OverflowException::class, 'The candidate budget never truncates');
    $stored = $redis->get($overflow[0]);
    $redis->del($overflow[0]);
    $throws(static function () use ($filter, $domain) { $filter->candidates('third', [[['token' => $domain, 'kind' => 'domain']]]); }, FastLookupIndexUnavailableException::class, 'An evicted overflow posting fails closed');
    $redis->set($overflow[0], $stored);
    $bucket = $redis->dump($prefix . 'g:third:x:0');
    $redis->del($prefix . 'g:third:x:0');
    $throws(static function () use ($filter, $domain) { $filter->candidates('third', [[['token' => $domain, 'kind' => 'domain']]]); }, FastLookupIndexUnavailableException::class, 'An evicted posting bucket fails closed');
    $throws(static function () use ($filter, $domain) { $filter->add('third', [['id' => '5', 'type' => 'domain', 'tokens' => [$domain]]]); }, FastLookupIndexUnavailableException::class, 'A write to an evicted bucket fails closed');
    $redis->restore($prefix . 'g:third:x:0', 0, $bucket);

    // The worker lease is exclusive, only its owner renews or releases it, and it expires.
    $lease = $prefix . 'worker';
    $assert($filter->acquireLease('owner', 60000), 'A free lease is acquired');
    $assert(!$filter->acquireLease('intruder', 60000), 'A held lease is exclusive');
    $assert(!$filter->renewLease('intruder', 120000) && $redis->pttl($lease) <= 60000, 'Another token cannot renew the lease');
    $filter->releaseLease('intruder');
    $assert($redis->get($lease) === 'owner', 'Another token cannot release the lease');
    $assert($filter->renewLease('owner', 120000) && $redis->pttl($lease) > 60000, 'The owner renews the lease');
    $filter->releaseLease('owner');
    $assert(!$redis->exists($lease), 'The owner releases the lease');
    $assert($filter->acquireLease('short', 200), 'A short lease is acquired');
    $assert($redis->pttl($lease) > 0 && $redis->pttl($lease) <= 200, 'The lease carries its TTL');
    usleep(300000);
    $assert(!$redis->exists($lease), 'The lease expires after its TTL');
    $assert(!$filter->renewLease('short', 60000), 'An expired lease cannot be renewed');
    $assert($filter->acquireLease('next', 60000), 'An expired lease is taken over');
    $filter->releaseLease('short');
    $assert($redis->get($lease) === 'next', "A stale owner's release leaves the new lease alone");
    $throws(static function () use ($filter) { $filter->acquireLease('not a token', 1000); }, InvalidArgumentException::class, 'A malformed lease token is refused');
    $throws(static function () use ($filter) { $filter->acquireLease('owner', 0); }, InvalidArgumentException::class, 'A lease needs a positive TTL');

    // Statistics measure every key the namespace owns; the held lease is not index data.
    $stats = $filter->statistics('third');
    $assert($stats['inserted'] === 1 && $stats['posting_entries'] === 600, 'Statistics count filter entries and posting memberships');
    $actual = 0;
    foreach ($keys($prefix . '*') as $key) {
        $assert(strpos($key, 'example.org') === false, 'Keys never contain IOCs');
        if ($key === $lease) {
            $assert($redis->pttl($key) > 0, 'The worker lease always carries a TTL');
            continue;
        }
        $actual += $redis->rawCommand('MEMORY', 'USAGE', $key, 'SAMPLES', 0);
        $assert($redis->ttl($key) === -1, 'Index keys have no TTL');
    }
    $assert(in_array($lease, $keys($prefix . '*'), true), 'The lease was checked while held');
    $filter->releaseLease('next');
    $assert($stats['shared_memory_bytes'] + $stats['filter_bytes'] + $stats['posting_bytes'] === $actual, 'Statistics include every key: ' . json_encode([$stats, $actual]));
    $redis->hSet($lease, 'corrupt', '1');
    $throws(static function () use ($filter) { $filter->renewLease('next', 1000); }, FastLookupIndexUnavailableException::class, 'A corrupt lease key fails closed');
    $redis->del($lease);
    $proxy->noMemory = true;
    $unmeasured = $filter->statistics('third');
    $assert($unmeasured['filter_bytes'] === null && !empty($unmeasured['memory_unavailable_reason']), 'Unsupported MEMORY is reported, never zero');
    $proxy->noMemory = false;

    // An evicted filter must not turn into "absent" answers or a fresh default filter.
    $redis->del($prefix . 'g:third:bf');
    $throws(static function () use ($filter) { $filter->metadata(); }, FastLookupIndexCorruptException::class, 'An evicted filter invalidates metadata');
    $throws(static function () use ($filter, $exact) { $filter->add('third', [['id' => '9', 'type' => 'domain', 'tokens' => [$exact]]]); }, FastLookupIndexUnavailableException::class, 'BF.MADD never recreates an evicted filter');
    $assert(!$redis->exists($prefix . 'g:third:bf'), 'No default filter was created');

    // An evicted *building* filter fails only that build; the live one serves.
    $filter->reserve('fifth', str_repeat('e', 64), 1000, 0.001, 1);
    $filter->add('fifth', [['id' => '1', 'type' => 'domain', 'tokens' => [$exact]]]);
    $filter->activate('fifth', str_repeat('e', 64));
    $filter->checkpoint('r5', true);
    $filter->reserve('sixth', str_repeat('f', 64), 1000, 0.001, 1);
    $redis->del($prefix . 'g:sixth:bf');
    $meta = $filter->metadata();
    $assert($meta['live'] === 'fifth' && $meta['building'] === 'sixth' && !isset($meta['generations']['sixth']), 'A broken building generation is omitted, not fatal');
    $assert($filter->candidates('fifth', [[['token' => $exact, 'kind' => 'exact']]])[0]['exact'] === true, 'The live filter still answers');
    $proxy->noBloomCommands = true;
    $throws(static function () use ($filter, $exact) { $filter->candidates('fifth', [[['token' => $exact, 'kind' => 'exact']]]); }, FastLookupIndexUnavailableException::class, 'Unavailable BF commands fail closed');
    $proxy->noBloomCommands = false;

    // A transient Redis error during reserve() never resets the namespace or deletes the live generation.
    $transient = static function ($method, $message) use ($filter, $proxy, $redis, $prefix, $assert, $exact) {
        $proxy->failNext = [$method => $message];
        try {
            $filter->reserve('seventh', str_repeat('g', 64), 1000, 0.001, 1);
            $assert(false, "reserve() failed to fail on $message");
        } catch (FastLookupIndexUnavailableException $e) {
            $assert(!$e instanceof FastLookupIndexCorruptException, "$message is not corruption");
        }
        $proxy->failNext = [];
        $assert($redis->exists($prefix . 'g:fifth:bf') === 1 && $redis->exists($prefix . 'g:fifth:info') === 1, "$message leaves the live generation's keys");
        $assert(!$redis->exists($prefix . 'g:seventh:bf'), "$message reserves nothing");
        $meta = $filter->metadata();
        $assert($meta['live'] === 'fifth' && $meta['ready'] === true, "$message leaves the live metadata");
        $assert($filter->candidates('fifth', [[['token' => $exact, 'kind' => 'exact']]])[0]['exact'] === true, "$message: the live filter still answers");
    };
    $transient('hgetall', 'read error on connection');
    $transient('eval', 'BUSY Redis is busy running a script. You can only call SCRIPT KILL or SHUTDOWN NOSCRIPT.');

    // Posting caps fail explicitly.
    $filter->reserve('fourth', str_repeat('d', 64), 1000, 0.001, 1);
    $redis->set($prefix . 'g:fourth:x:0:' . bin2hex($domain), 'fourth|' . implode(',', range(1, 500000)) . ',');
    $redis->hSet($prefix . 'g:fourth:x:0', $domain, '*');
    $throws(static function () use ($filter, $domain) { $filter->add('fourth', [['id' => '999999999', 'type' => 'domain', 'tokens' => [$domain]]]); }, OverflowException::class, 'The posting cap is an explicit resource failure');

    // IP prefix masks: set before their tokens become visible, versioned, legacy generations left alone.
    $info = $prefix . 'g:eighth:info';
    $bf = $prefix . 'g:eighth:bf';
    $redis->hSet($prefix . 'metadata', 'schema', 'bloom-1');
    $assert($filter->metadata()['live'] !== null, 'A legacy schema namespace is served');
    $filter->reserve('eighth', str_repeat('h', 64), 1000, 0.001, 1);
    $assert($redis->hMGet($prefix . 'metadata', ['schema', 'building']) === ['schema' => 'bloom-2', 'building' => 'eighth'], 'Reserving a masked generation stamps the current schema');
    $assert($filter->prefixLengths('eighth') === ['version' => '0', 'lengths' => [4 => [], 6 => []]], 'A new generation starts with empty masks at version 0');
    $r24 = $token('I', '198.51.100.0/24');
    $filter->add('eighth', [['id' => '21', 'type' => 'ip-src', 'tokens' => [$r24], 'networks' => [[4, 24]]]]);
    $assert($redis->hGet($info, 'p4')[24] === '1' && $filter->prefixLengths('eighth')['version'] === '1', 'A new length sets its bit and bumps the version');
    $assert($redis->rawCommand('BF.MEXISTS', $bf, $r24) === [1] && isset($filter->prefixLengths('eighth')['lengths'][4][24]), 'A visible range token has its length in the mask');
    $filter->add('eighth', [['id' => '22', 'type' => 'ip-src', 'tokens' => [$r24], 'networks' => [[4, 24]]]]);
    $assert($filter->prefixLengths('eighth')['version'] === '1', 'A known length leaves the version alone');
    $filter->add('eighth', [['id' => '23', 'type' => 'ip-src', 'tokens' => [$token('E', '198.51.100.7')]]]);
    $assert($filter->prefixLengths('eighth')['version'] === '1', 'Rows without networks leave the version alone');
    $filter->checkpoint('r7', false);
    $filter->activate('eighth', str_repeat('h', 64));
    $filter->checkpoint('r8', true);
    $rangeQuery = [[['token' => $r24, 'kind' => 'ip_range']]];
    $assert($filter->candidates('eighth', $rangeQuery, 100000, '1')[0]['ip_range'] === ['21', '22'], 'A current prefix version answers');
    $r32 = $token('I', '198.51.100.7/32');
    $r64 = $token('I', '2001:db8::/64');
    $filter->add('eighth', [['id' => '24', 'type' => 'ip-src', 'tokens' => [$r32, $r64], 'networks' => [[4, 32], [6, 64]]]]);
    $lengths = $filter->prefixLengths('eighth');
    $assert($lengths === ['version' => '2', 'lengths' => [4 => [24 => true, 32 => true], 6 => [64 => true]]], 'New lengths in both families bump the version once: ' . json_encode($lengths));
    $assert($redis->rawCommand('BF.MEXISTS', $bf, $r32, $r64) === [1, 1], 'The new range tokens are visible with their lengths set');
    $throws(static function () use ($filter, $rangeQuery) { $filter->candidates('eighth', $rangeQuery, 100000, '1'); }, FastLookupPrefixesChangedException::class, 'A stale prefix version fails the lookup');
    $throws(static function () use ($filter, $rangeQuery) { $filter->candidates('eighth', $rangeQuery, 100000, ''); }, FastLookupPrefixesChangedException::class, 'A legacy expectation fails on a masked generation');
    $assert($filter->candidates('eighth', $rangeQuery, 100000, '2')[0]['ip_range'] === ['21', '22'], 'The current prefix version answers');
    $assert($filter->candidates('eighth', $rangeQuery)[0]['ip_range'] === ['21', '22'], 'No prefix version skips the check');

    $masks = $redis->hMGet($info, ['p4', 'p6', 'pv']);
    $redis->hDel($info, 'p4', 'p6', 'pv');
    $r13 = $token('I', '192.0.0.0/13');
    $filter->add('eighth', [['id' => '25', 'type' => 'ip-src', 'tokens' => [$r13], 'networks' => [[4, 13]]]]);
    $assert($redis->hMGet($info, ['p4', 'p6', 'pv']) === ['p4' => false, 'p6' => false, 'pv' => false], 'add() never creates masks on a legacy generation');
    $assert($filter->prefixLengths('eighth') === ['version' => '', 'lengths' => null], 'A legacy generation has no lengths');
    $assert($filter->candidates('eighth', [[['token' => $r13, 'kind' => 'ip_range']]], 100000, '')[0]['ip_range'] === ['25'], 'A legacy generation matches an empty prefix version');
    // What an older release leaves behind: a legacy schema over an unmasked live generation.
    $redis->hSet($prefix . 'metadata', 'schema', 'bloom-1');
    $filter->checkpoint('r9', true);
    $assert($filter->metadata()['generations']['eighth']['capacity'] === 1000, 'A legacy namespace with a legacy live generation is valid');
    $assert($filter->candidates('eighth', [[['token' => $r13, 'kind' => 'ip_range']]], 100000, '')[0]['ip_range'] === ['25'], 'A legacy namespace keeps serving range lookups');
    $assert($redis->hGet($prefix . 'metadata', 'schema') === 'bloom-1', 'Serving never rewrites the schema');
    $redis->hSet($prefix . 'metadata', 'schema', 'bloom-3');
    $throws(static function () use ($filter) { $filter->metadata(); }, FastLookupIndexCorruptException::class, 'An unknown schema fails closed');
    $throws(static function () use ($filter) { $filter->checkpoint('r10', true); }, FastLookupIndexUnavailableException::class, 'checkpoint() refuses an unknown schema');
    $redis->hSet($prefix . 'metadata', 'schema', 'bloom-2');

    $redis->hMSet($info, $masks);
    $redis->hDel($info, 'p6');
    $throws(static function () use ($filter) { $filter->prefixLengths('eighth'); }, FastLookupIndexCorruptException::class, 'A partial prefix state is corrupt');
    $throws(static function () use ($filter) { $filter->metadata(); }, FastLookupIndexCorruptException::class, 'A live generation with a partial prefix state is corrupt');
    $r16 = $token('I', '203.0.0.0/16');
    $throws(static function () use ($filter, $r16) { $filter->add('eighth', [['id' => '26', 'type' => 'ip-src', 'tokens' => [$r16], 'networks' => [[4, 16]]]]); }, FastLookupIndexCorruptException::class, 'add() fails closed on a partial prefix state');
    $redis->hMSet($info, $masks);
    $redis->hSet($info, 'p4', str_repeat('0', 32));
    $throws(static function () use ($filter) { $filter->metadata(); }, FastLookupIndexCorruptException::class, 'A live generation with a malformed IPv4 mask is corrupt');
    $throws(static function () use ($filter, $r16) { $filter->add('eighth', [['id' => '26', 'type' => 'ip-src', 'tokens' => [$r16], 'networks' => [[4, 16]]]]); }, FastLookupIndexCorruptException::class, 'add() reports a malformed IPv4 mask as corrupt');
    $assert($redis->rawCommand('BF.MEXISTS', $bf, $r16) === [0], 'A refused mask update publishes none of its tokens');
    $redis->hMSet($info, $masks);
    foreach (['missing' => null, 'non-decimal' => 'x'] as $case => $version) {
        $redis->hMSet($info, $masks);
        if ($version === null) { $redis->hDel($info, 'pv'); } else { $redis->hSet($info, 'pv', $version); }
        $throws(static function () use ($filter, $r16) { $filter->add('eighth', [['id' => '26', 'type' => 'ip-src', 'tokens' => [$r16], 'networks' => [[4, 16]]]]); }, FastLookupIndexCorruptException::class, "add() fails closed on a $case prefix version");
        $after = $redis->hMGet($info, ['p4', 'p6', 'pv']);
        $assert($after['p4'] === $masks['p4'] && $after['p6'] === $masks['p6'] && $after['pv'] === ($version ?? false), "A $case prefix version leaves the masks and version untouched");
        $assert($redis->rawCommand('BF.MEXISTS', $bf, $r16) === [0], "A $case prefix version publishes none of the tokens");
    }
    $throws(static function () use ($filter) { $filter->prefixLengths('ninth'); }, FastLookupIndexCorruptException::class, 'A missing generation has no prefix state');

    // A full NONSCALING filter refuses tokens: the add fails as full, and nothing it took before reads absent.
    $tiny->reserve('full', str_repeat('u', 64), 40, 0.01, 1);
    $accepted = [];
    $full = null;
    for ($i = 0; $i < 1000 && $full === null; ++$i) {
        $t = $token('E', 'full-' . $i);
        try {
            $tiny->add('full', [['id' => (string)($i + 1), 'type' => 'domain', 'tokens' => [$t]]]);
            $accepted[] = $t;
        } catch (FastLookupIndexUnavailableException $e) {
            $full = $e;
        }
    }
    $assert($full instanceof FastLookupIndexFullException && $full->generation === 'full', 'A full filter fails the add as full: ' . ($full ? get_class($full) . ' ' . $full->getMessage() : 'never full'));
    $assert(!$full instanceof FastLookupIndexCorruptException, 'A full filter is not corruption');
    $fullInserted = $tiny->metadata()['generations']['full']['inserted'];
    $assert($fullInserted >= 1 && $fullInserted <= count($accepted) + 1, "The tokens stored before the refusal are counted: $fullInserted");
    $flags = $redis->rawCommand('BF.MEXISTS', $fullPrefix . 'g:full:bf', ...$accepted);
    $assert(count($accepted) > 0 && $flags === array_fill(0, count($accepted), 1), 'No token taken before the refusal reads absent');
    // A filter at its capacity never answers, since it may have refused tokens.
    $assert($fullInserted === 40, "The full filter reached its capacity: $fullInserted");
    $tiny->checkpoint('full-r1', false);
    $tiny->activate('full', str_repeat('u', 64));
    $tiny->checkpoint('full-r2', true);
    $throws(static function () use ($tiny, $accepted) { $tiny->candidates('full', [[['token' => $accepted[0], 'kind' => 'exact']]]); },
        FastLookupIndexFullException::class, 'A full filter fails the lookup as full');

    // A filter an earlier release filled may have dropped tokens silently: at its capacity it never answers.
    $tiny->reserve('oldfull', str_repeat('v', 64), 1000, 0.01, 1);
    $oldProbe = [[['token' => $token('E', 'old-full'), 'kind' => 'exact']]];
    $tiny->add('oldfull', [['id' => '1', 'type' => 'domain', 'tokens' => [$oldProbe[0][0]['token']]]]);
    $tiny->checkpoint('of-r1', false);
    $tiny->activate('oldfull', str_repeat('v', 64));
    $tiny->checkpoint('of-r2', true);
    $assert($tiny->candidates('oldfull', $oldProbe)[0]['exact'] === true, 'A filter below its capacity answers');
    $redis->hSet($fullPrefix . 'g:oldfull:info', 'inserted', '1000');
    try {
        $tiny->candidates('oldfull', $oldProbe);
        $assert(false, 'A filter at its capacity must never answer');
    } catch (FastLookupIndexFullException $e) {
        $assert($e->generation === 'oldfull', 'A filter at its capacity fails the lookup as full');
    }

    echo json_encode(['assertions' => $assertions, 'redis_version' => $redis->info('server')['redis_version'], 'status' => 'passed'], JSON_PRETTY_PRINT), "\n";
} finally {
    foreach (array_chunk(array_merge($keys($prefix . '*'), $keys($legacy . '*'), $keys($fullPrefix . '*')), 500) as $batch) { $redis->del($batch); }
}
