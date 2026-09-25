<?php
/** Run against a disposable Redis Unix socket; touches only a random test namespace. */
declare(strict_types=1);

$implementation = __DIR__ . '/../../app/Lib/Tools/FastLookupIndex.php';
if (is_file($implementation)) {
    require_once $implementation;
}
if (!class_exists('FastLookupIndex')) {
    throw new RuntimeException('Persistent FastLookupIndex is not implemented.');
}
if (!class_exists('Redis') || empty($argv[1])) {
    throw new RuntimeException('Usage: php FastLookupIndexRedisContract.php /disposable/redis.sock (phpredis required)');
}

class FastLookupContractRedisProxy
{
    public $redis;
    public $failAfterAdd = false;
    public $emptyScan = false;
    public $noMemory = false;
    public $hmgetCalls = 0;
    public $maximumReplyBytes = 0;
    public $raceAfterLengths;
    public $postingRemovalCalls = 0;
    public $readCalls = 0;
    private $emptyInjected = false;
    private $emptyKeyScanInjected = false;
    public function __construct($redis) { $this->redis = $redis; }
    public function __call($name, $args)
    {
        if (strtolower($name) === 'hmget') { ++$this->hmgetCalls; }
        if (strtolower($name) === 'rawcommand' && $this->noMemory && strtolower($args[0]) === 'memory') {
            throw new RuntimeException('ERR unknown command MEMORY');
        }
        $result = $this->redis->{$name}(...$args);
        if ($name === 'eval' && strpos($args[0], 'parsePosting(raw)') !== false && strpos($args[0], 'FAST_LOOKUP_ADD') === false) {
            ++$this->postingRemovalCalls;
        }
        if (strtolower($name) === 'hmget') {
            $this->maximumReplyBytes = max($this->maximumReplyBytes, array_sum(array_map(static function ($value) { return is_string($value) ? strlen($value) : 0; }, $result)));
        }
        if ($name === 'eval' && strpos($args[0], "'HMGET'") !== false) {
            ++$this->hmgetCalls;
            ++$this->readCalls;
            if (isset($result[1]) && is_array($result[1])) {
                $this->maximumReplyBytes = max($this->maximumReplyBytes, array_sum(array_map(static function ($value) { return is_string($value) ? strlen($value) : 0; }, $result[1])));
            }
        }
        if ($name === 'eval' && strpos($args[0], 'HSTRLEN') !== false && $this->raceAfterLengths) {
            [$metaKey, $postingKey, $field] = $this->raceAfterLengths;
            $this->raceAfterLengths = null;
            $this->redis->hSet($metaKey, 'ready', '0');
            $this->redis->hSet($postingKey, $field, str_repeat('12345678901234567890,', 100001));
        }
        if ($name === 'eval' && $this->failAfterAdd && strpos($args[0], 'FAST_LOOKUP_ADD') !== false) {
            $this->failAfterAdd = false;
            throw new RuntimeException('Connection lost after accepted write.');
        }
        return $result;
    }
    public function hScan($key, &$cursor, $pattern = null, $count = 0)
    {
        if ($this->emptyScan && !$this->emptyInjected && $cursor === null) {
            $this->emptyInjected = true;
            $cursor = 987654321;
            return [];
        }
        if ($cursor === 987654321) { $cursor = null; }
        return $this->redis->hScan($key, $cursor, $pattern, $count);
    }
    public function scan(&$cursor, $pattern = null, $count = 0)
    {
        if ($this->emptyScan && !$this->emptyKeyScanInjected && $cursor === null) {
            $this->emptyKeyScanInjected = true;
            $cursor = 987654321;
            return false;
        }
        if ($cursor === 987654321) { $cursor = null; }
        return $this->redis->scan($cursor, $pattern, $count);
    }
}

$redis = new Redis();
$redis->connect($argv[1]);
$proxy = new FastLookupContractRedisProxy($redis);
$namespace = 'contract-' . bin2hex(random_bytes(16));
$prefix = 'misp:fast_lookup:v2:' . hash('sha256', $namespace) . ':';
$scope = ['attribute_types' => ['domain', 'ip-src'], 'published_only' => true, 'max_values' => 10000];
$index = new FastLookupIndex($namespace, $scope, $proxy);
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
$token = static function ($kind, $value) { return $kind . substr(hash('sha256', $value, true), 0, 16); };
$exact = $token('E', 'example.org');
$domain = $token('D', 'example.org');
$ip = $token('I', '192.0.2.0/24');
$query = [7 => [['type' => 'domain', 'token' => $exact, 'kind' => 'exact']],
    11 => [['type' => 'domain', 'token' => $domain, 'kind' => 'domain']],
    13 => [['type' => 'ip-src', 'token' => $ip, 'kind' => 'ip_range']]];
$keys = static function () use ($redis, $prefix) {
    $all = []; $cursor = null;
    do {
        $batch = $redis->scan($cursor, $prefix . '*', 100);
        if ($batch) { $all = array_merge($all, $batch); }
    } while ($cursor !== 0);
    return $all;
};

try {
    $throws(static function () use ($index) { $index->metadata(); }, FastLookupIndexUnavailableException::class, 'Missing index must fail closed');
    $index->initialise('first', str_repeat('a', 64), ['processed_events' => 0, 'total_events' => 2]);
    $assert($index->metadata()['ready'] === false, 'Initial index must be warming');
    $throws(static function () use ($index, $query) { $index->candidates('first', $query); }, FastLookupIndexUnavailableException::class, 'Warming index cannot return empty answers');
    $index->replaceEvent('first', '2', [
        ['id' => '12', 'type' => 'domain', 'tokens' => [$exact, $domain, $domain]],
        ['id' => '13', 'type' => 'domain', 'tokens' => [$exact]],
        ['id' => '14', 'type' => 'ip-src', 'tokens' => [$ip]],
        ['id' => '15', 'type' => 'domain', 'tokens' => []],
    ]);
    $index->checkpoint('first', 'r1', ['processed_events' => 2, 'total_events' => 2], true);
    $result = $index->candidates('first', $query);
    $assert($result[7]['exact'] === ['12', '13'], 'Exact token returns complete decimal IDs');
    $assert($result[11]['domain'] === ['12'], 'Repeated token produces one candidate');
    $assert($result[13]['ip_range'] === ['14'], 'IP candidates preserve query position and kind');
    $assert($proxy->hmgetCalls > 0, 'Primary candidates use direct bulk HASH retrieval');
    $scattered = [];
    for ($i = 0; $i < 129; ++$i) {
        $scattered[$i] = [['type' => $i % 2 ? 'domain' : 'ip-src', 'token' => $token('E', 'missing-' . $i), 'kind' => 'exact']];
    }
    $readsBefore = $proxy->readCalls;
    $assert(count($index->candidates('first', $scattered)) === 129, 'Scattered misses preserve every original position');
    $assert($proxy->readCalls - $readsBefore <= 2, 'Scattered tokens share bounded read batches across shards');
    $bulkMisses = [];
    for ($i = 0; $i < 1025; ++$i) {
        $bulkMisses[$i] = [['type' => $i % 2 ? 'domain' : 'ip-src', 'token' => $token('E', 'bulk-missing-' . $i), 'kind' => 'exact']];
    }
    $readsBefore = $proxy->readCalls;
    $assert(count($index->candidates('first', $bulkMisses)) === 1025, 'Bulk misses preserve all positions');
    $assert($proxy->readCalls - $readsBefore <= 2, 'Bulk missing IOC lookup requires at most two bounded Redis reads per 1025 tokens');
    $throws(static function () use ($index, $query) { $index->candidates('first', $query, 2); }, OverflowException::class, 'Candidate budget never truncates');
    $throws(static function () use ($index, $query) { $index->candidates('other', $query); }, FastLookupIndexUnavailableException::class, 'Generation mismatch refuses lookup');
    $throws(static function () use ($index, $exact) { $index->candidates('first', [[['type' => 'domain', 'token' => $exact, 'kind' => 'domain']]]); }, InvalidArgumentException::class, 'Token kind mismatch is invalid');
    $stats = $index->statistics('first');
    $byType = array_column($stats['types'], null, 'type');
    $assert($byType['domain']['attributes'] === 3 && $byType['domain']['entries'] === 3, 'Counters include scoped attributes without Redis tokens');
    $assert($byType['ip-src']['attributes'] === 1 && $byType['ip-src']['entries'] === 1, 'Per-type counts are isolated');
    $measured = $stats['shared_memory_bytes'] + array_sum(array_column($stats['types'], 'memory_bytes'));
    $actual = 0;
    foreach ($keys() as $key) {
        $actual += $redis->rawCommand('MEMORY', 'USAGE', $key, 'SAMPLES', 0);
        $assert($redis->ttl($key) === -1, 'Persistent index keys have no TTL');
        $assert(strpos($key, 'example.org') === false && strpos($key, '192.0.2') === false, 'Redis keys do not expose IOCs');
    }
    $assert($measured === $actual, 'Per-type memory plus shared memory includes every own key: ' . json_encode(['measured' => $measured, 'actual' => $actual, 'statistics' => $stats]));
    $proxy->emptyScan = true;
    $assert($index->statistics('first')['types'] === $stats['types'], 'Empty nonterminal SCAN page cannot truncate statistics');
    $proxy->noMemory = true;
    $unmeasured = $index->statistics('first');
    $assert($unmeasured['shared_memory_bytes'] === null && $unmeasured['types'][0]['memory_bytes'] === null, 'Unsupported MEMORY is unavailable rather than zero');
    $assert(!empty($unmeasured['memory_unavailable_reason']), 'Unsupported MEMORY has an explanation');
    $proxy->noMemory = false;

    $proxy->failAfterAdd = true;
    $throws(static function () use ($index, $domain) {
        $index->replaceEvent('first', '2', [['id' => '25', 'type' => 'domain', 'tokens' => [$domain]]]);
    }, FastLookupIndexUnavailableException::class, 'Lost write acknowledgement reports unavailable');
    $assert($index->metadata()['ready'] === false, 'Partial event replacement disables ready flag');
    $index->replaceEvent('first', '2', [['id' => '30', 'type' => 'domain', 'tokens' => [$exact]]]);
    $index->checkpoint('first', 'r2', [], true);
    $result = $index->candidates('first', $query);
    $assert($result[7]['exact'] === ['30'] && $result[11]['domain'] === [] && $result[13]['ip_range'] === [], 'Retry removes every partial old posting');
    $byType = array_column($index->statistics('first')['types'], null, 'type');
    $assert($byType['domain']['attributes'] === 1 && $byType['domain']['entries'] === 1, 'Retry leaves no orphan memberships');

    $index->beginEvent('first', '3');
    $index->addAttributes('first', '3', [['id' => '30', 'type' => 'domain', 'tokens' => [$exact, $domain]]]);
    $index->endEvent('first', '3');
    $index->removeEvent('first', '2');
    $index->checkpoint('first', 'r3', [], true);
    $assert($index->candidates('first', $query)[7]['exact'] === ['30'], 'Deleting old event after reparenting preserves new membership');
    $index->removeEvent('first', '3');
    $index->checkpoint('first', 'r4', [], true);
    $assert($index->candidates('first', $query)[7]['exact'] === [], 'Event removal removes final membership');

    $large = [];
    for ($id = 1000; $id < 1600; ++$id) { $large[] = ['id' => (string)$id, 'type' => 'domain', 'tokens' => [$exact]]; }
    $index->replaceEvent('first', '8', $large);
    $index->checkpoint('first', 'large', [], true);
    $assert(count($index->candidates('first', $query)[7]['exact']) === 600, 'Streaming event writes keep all shared-token candidates');
    $removalsBefore = $proxy->postingRemovalCalls;
    $index->removeEvent('first', '8');
    $assert($proxy->postingRemovalCalls - $removalsBefore <= 20, 'Shared-token removal batches memberships instead of rewriting each posting for every attribute');
    $index->checkpoint('first', 'large-removed', [], true);
    $assert($index->candidates('first', $query)[7]['exact'] === [], 'Large event removal is complete');

    $index->beginEvent('first', '4');
    $throws(static function () use ($index) { $index->checkpoint('first', 'r5', [], true); }, FastLookupIndexUnavailableException::class, 'Open event cannot become ready');
    $index->endEvent('first', '4');
    $index->checkpoint('first', 'r6', [], true);
    $index->replaceEvent('first', '5', [['id' => '40', 'type' => 'domain', 'tokens' => [$exact]]]);
    $index->checkpoint('first', 'r7', [], true);
    $postingKey = null;
    foreach ($keys() as $key) {
        if ($redis->type($key) === Redis::REDIS_HASH && $redis->hExists($key, $exact)) { $postingKey = $key; break; }
    }
    $assert($postingKey !== null, 'Token is held as a fixed binary HASH field');
    $proxy->raceAfterLengths = [$prefix . 'metadata', $postingKey, $exact];
    $throws(static function () use ($index, $query) { $index->candidates('first', $query); }, RuntimeException::class, 'Concurrent write refuses the response');
    $assert($proxy->maximumReplyBytes <= 2100000, 'Payload limit is checked atomically with transfer even when a writer grows a posting');
    $redis->hSet($prefix . 'metadata', 'ready', '1');
    $redis->hSet($postingKey, $exact, 'invalid,');
    $throws(static function () use ($index, $query) { $index->candidates('first', $query); }, FastLookupIndexUnavailableException::class, 'Corrupt posting does not become an empty result');
    $redis->del($postingKey);
    $throws(static function () use ($index) { $index->metadata(); }, FastLookupIndexUnavailableException::class, 'Evicted posting shard invalidates metadata');
    $redis->hSet($prefix . 'g:older-interrupted:inflight', '!', 'older-interrupted');
    $index->initialise('second', str_repeat('b', 64), []);
    $assert($index->metadata()['generation'] === 'second', 'Fresh generation recovers from missing shards');
    foreach ($keys() as $key) { $assert(strpos($key, ':g:first:') === false, 'Previous generation keys are reclaimed'); }
    $assert(!$redis->exists($prefix . 'g:older-interrupted:inflight'), 'Cleanup also reclaims generations left by an interrupted older rebuild');
    $throws(static function () use ($index) { $index->removeEvent('first', '5'); }, FastLookupIndexUnavailableException::class, 'Stale writer cannot change new generation');
    $index->replaceEvent('second', '99', [['id' => '41', 'type' => 'domain', 'tokens' => [$exact]]]);
    foreach ($keys() as $key) {
        if ($redis->type($key) === Redis::REDIS_HASH && $redis->hExists($key, $exact)) { $postingKey = $key; break; }
    }
    $redis->hSet($postingKey, $exact, implode(',', range(1, 500000)) . ',');
    $index->beginEvent('second', '100');
    $throws(static function () use ($index, $exact) {
        $index->addAttributes('second', '100', [['id' => '99999999', 'type' => 'domain', 'tokens' => [$exact]]]);
    }, OverflowException::class, 'Posting write cap is an explicit resource failure');
    $assert($index->metadata()['ready'] === false, 'Posting overflow never promotes an incomplete index');
    $redis->del($prefix . 'metadata');
    $redis->set($prefix . 'metadata', 'corrupt metadata type');
    $index->initialise('third', str_repeat('c', 64), []);
    $assert($index->metadata()['generation'] === 'third' && $index->metadata()['ready'] === false, 'An explicit rebuild recovers even when metadata has the wrong Redis type');
    echo json_encode(['assertions' => $assertions, 'redis_version' => $redis->info('server')['redis_version'], 'status' => 'passed'], JSON_PRETTY_PRINT) . "\n";
} finally {
    foreach (array_chunk($keys(), 128) as $batch) { $redis->del($batch); }
}
