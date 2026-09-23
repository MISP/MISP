<?php
use PHPUnit\Framework\TestCase;

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package) {}
    }
}

class FastLookupCacheRedisFake
{
    public $data = [];
    public $reads = [];
    public $writes = [];
    public $pipelines = 0;
    public $failReads = false;
    public $failWrites = false;
    public $malformedReply = false;

    public function mGet($keys)
    {
        $this->reads[] = $keys;
        if ($this->failReads) {
            throw new RuntimeException('Redis is unavailable');
        }
        if ($this->malformedReply) {
            return [false];
        }
        return array_map(function ($key) { return $this->data[$key] ?? false; }, $keys);
    }

    public function pipeline()
    {
        $this->pipelines++;
        if ($this->failWrites) {
            throw new RuntimeException('Redis is unavailable');
        }
        return $this;
    }

    public function setex($key, $ttl, $value)
    {
        $this->writes[] = [$key, $ttl, $value];
        $this->data[$key] = $value;
        return $this;
    }

    public function exec() { return []; }
}

class FastLookupCacheTest extends TestCase
{
    private $redis;
    private $now;
    private $cache;

    protected function setUp(): void
    {
        $this->redis = new FastLookupCacheRedisFake();
        $this->now = 1000.0;
        if (is_file(__DIR__ . '/../Lib/Tools/FastLookupCache.php')) {
            require_once __DIR__ . '/../Lib/Tools/FastLookupCache.php';
        }
    }

    private function cache($namespace = 'database-one')
    {
        $this->assertTrue(class_exists('FastLookupCache'), 'The fast lookup cache adapter exists');
        return new FastLookupCache($namespace, $this->redis, function () { return $this->now; });
    }

    public function testBulkPositiveAndNegativeEntriesPreserveInputPositions()
    {
        $cache = $this->cache();
        $values = [4 => 'example.org', 9 => 'missing.example', 12 => 'unknown.example'];
        $cache->storeMany($values, [4 => ['12', 13, '12'], 9 => []], 1000.0);
        $this->assertSame([4 => ['12', '13'], 9 => []], $cache->getMany($values, 60));
        $this->assertCount(1, $this->redis->reads);
        $this->assertCount(3, $this->redis->reads[0]);
        $this->assertSame(1, $this->redis->pipelines);
        $this->assertCount(2, $this->redis->writes);
    }

    public function testAgeStartsBeforeDiscoveryAndHitsDoNotRefreshIt()
    {
        $cache = $this->cache();
        $this->now = 1012.1;
        $cache->storeMany(['example.org'], [['12']], 1000.0);
        $this->assertSame(47, $this->redis->writes[0][1]);
        $this->now = 1059.0;
        $this->assertSame([['12']], $cache->getMany(['example.org'], 60));
        $this->now = 1060.0;
        $this->assertSame([], $cache->getMany(['example.org'], 60));
        $this->assertCount(1, $this->redis->writes);
    }

    public function testCallerCanRequireNewerDataOrBypassCache()
    {
        $cache = $this->cache();
        $cache->storeMany(['example.org'], [['12']], 1000.0);
        $this->now = 1010.0;
        $this->assertSame([], $cache->getMany(['example.org'], 5));
        $this->assertSame([['12']], $cache->getMany(['example.org'], 30));
        $reads = count($this->redis->reads);
        $this->assertSame([], $cache->getMany(['example.org'], 0));
        $this->assertSame($reads, count($this->redis->reads));
    }

    public function testExpiredOrFutureDiscoveriesAreNotStored()
    {
        $cache = $this->cache();
        $cache->storeMany(['old'], [['12']], 940.0);
        $cache->storeMany(['future'], [['12']], 1001.0);
        $this->assertSame([], $this->redis->writes);
    }

    public function testOversizedOrInvalidCandidateSetsAreNeverTruncatedOrCached()
    {
        $cache = $this->cache();
        $cache->storeMany(['large', 'invalid', 'okay'], [range(1, 10001), ['1 OR 1=1'], ['2']], 1000.0);
        $this->assertSame([2 => ['2']], $cache->getMany(['large', 'invalid', 'okay'], 60));
        $this->assertCount(1, $this->redis->writes);
    }

    public function testNamespacesAndLiteralValuesDoNotCollide()
    {
        $cache = $this->cache();
        $cache->storeMany(['Example.org', 'example.org', 'a|b'], [['1'], ['2'], ['3']], 1000.0);
        $this->assertSame([['1'], ['2'], ['3']], $cache->getMany(['Example.org', 'example.org', 'a|b'], 60));
        $this->assertSame([], $this->cache('database-two')->getMany(['Example.org'], 60));
        foreach ($this->redis->writes as $write) {
            $this->assertStringNotContainsString('example.org', $write[0]);
            $this->assertStringStartsWith('misp:fast_lookup:v1:', $write[0]);
        }
    }

    public function testLargeRequestsReadRedisInBoundedBatches()
    {
        $cache = $this->cache();
        $values = array_map(function ($i) { return "missing-$i.example"; }, range(0, 204));
        $cache->storeMany($values, array_fill(0, 205, []), 1000.0);
        $this->assertCount(205, $cache->getMany($values, 60));
        $this->assertCount(3, $this->redis->reads);
        foreach ($this->redis->reads as $batch) {
            $this->assertLessThanOrEqual(100, count($batch));
        }
    }

    /** @dataProvider corruptEntries */
    public function testCorruptEntriesAreMisses($payload)
    {
        $cache = $this->cache();
        $cache->storeMany(['example.org'], [['12']], 1000.0);
        $key = $this->redis->writes[0][0];
        $this->redis->data[$key] = $payload;
        $this->assertSame([], $cache->getMany(['example.org'], 60));
    }

    public function corruptEntries()
    {
        return [
            ['not JSON'], ['false'], ['{}'],
            [json_encode(['version' => 2, 'created' => 1000, 'ids' => ['1']])],
            [json_encode(['version' => 1, 'created' => '1000', 'ids' => ['1']])],
            [json_encode(['version' => 1, 'created' => 1001, 'ids' => ['1']])],
            [json_encode(['version' => 1, 'created' => 1000, 'ids' => ['0']])],
            [json_encode(['version' => 1, 'created' => 1000, 'ids' => [-1]])],
            [json_encode(['version' => 1, 'created' => 1000, 'ids' => [1.5]])],
            [json_encode(['version' => 1, 'created' => 1000, 'ids' => ['1,2']])],
            [json_encode(['version' => 1, 'created' => 1000, 'ids' => ['x' => 1]])],
            [json_encode(['version' => 1, 'created' => 1000, 'ids' => new stdClass()])],
            [json_encode(['version' => 1, 'created' => 1000, 'ids' => range(1, 10001)])],
        ];
    }

    public function testRedisFailuresAndMalformedBulkRepliesFallBackToMisses()
    {
        $cache = $this->cache();
        $this->redis->failReads = true;
        $this->assertSame([], $cache->getMany(['one', 'two'], 60));
        $this->redis->failReads = false;
        $this->redis->malformedReply = true;
        $this->assertSame([], $cache->getMany(['one', 'two'], 60));
        $this->redis->failWrites = true;
        $cache->storeMany(['one'], [['1']], 1000.0);
        $this->assertSame([], $this->redis->writes);
    }
}
