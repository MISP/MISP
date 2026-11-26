<?php
/**
 * Rewrites values in MISP's Redis database that were stored PHP-serialized
 * (`s:6:"bit.ly";`) by a request whose connection had been switched to the PHP
 * serializer, back to the raw form every other reader expects. Running it
 * again finds nothing left to do.
 */
class RedisSerializerRepairTool
{
    const BATCH = 1000;

    // Collections up to this size are read whole, in the batch's pipeline;
    // larger ones are scanned, which keeps a batch's memory bounded.
    const SMALL = 100;

    // Scrapbook's browscap cache is PHP-serialized by design.
    const SKIP_PREFIX = 'browscap.';

    // Each script changes the value only if it is still the one that was read.
    // Members are added before the old one is removed, so that a key never
    // empties and loses its TTL.
    const SCRIPT_STRING = "if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
local ttl = redis.call('PTTL', KEYS[1])
if ttl > 0 then redis.call('SET', KEYS[1], ARGV[2], 'PX', ttl) else redis.call('SET', KEYS[1], ARGV[2]) end
return 1";
    const SCRIPT_SET = "if redis.call('SISMEMBER', KEYS[1], ARGV[1]) == 0 then return 0 end
redis.call('SADD', KEYS[1], ARGV[2])
redis.call('SREM', KEYS[1], ARGV[1])
return 1";
    const SCRIPT_ZSET = "local score = redis.call('ZSCORE', KEYS[1], ARGV[1])
if not score then return 0 end
redis.call('ZINCRBY', KEYS[1], score, ARGV[2])
redis.call('ZREM', KEYS[1], ARGV[1])
return 1";
    const SCRIPT_HASH = "if redis.call('HGET', KEYS[1], ARGV[1]) ~= ARGV[2] then return 0 end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[3])
return 1";
    const SCRIPT_LIST = "if redis.call('LINDEX', KEYS[1], ARGV[1]) ~= ARGV[2] then return 0 end
redis.call('LSET', KEYS[1], ARGV[1], ARGV[3])
return 1";

    /** @var Redis */
    private $redis;

    /** @var bool */
    private $dryRun;

    /** @var array */
    private $stats = [
        'checked' => 0,
        'skipped' => 0,
        'keys' => 0,
        'values' => 0,
    ];

    /**
     * @param Redis $redis A connection with no serializer set, such as
     *   RedisTool::connect() returns
     * @param bool $dryRun Count what would be repaired, change nothing
     */
    public function __construct(Redis $redis, $dryRun = false)
    {
        $this->redis = $redis;
        $this->dryRun = $dryRun;
    }

    /**
     * The raw form of a PHP-serialized scalar.
     *
     * @param mixed $value
     * @return string|null null when $value is not exactly a serialized scalar
     */
    public static function unwrap($value)
    {
        if (!is_string($value) || !isset($value[3]) || $value[1] !== ':' || strpos('sidb', $value[0]) === false) {
            return null;
        }
        $result = @unserialize($value, ['allowed_classes' => false]);
        if (!is_scalar($result) || serialize($result) !== $value) {
            return null;
        }
        if (is_bool($result)) {
            return $result ? '1' : '';
        }
        return (string)$result;
    }

    /**
     * @param callable|null $progress function(int $checked, int $total)
     * @return array checked, skipped, keys (repaired), values (repaired)
     * @throws RedisException
     */
    public function run(?callable $progress = null)
    {
        $total = (int)$this->redis->dbSize();
        $iterator = null;
        while (($keys = $this->redis->scan($iterator, null, self::BATCH)) !== false) {
            $this->batch($keys);
            if ($progress) {
                $progress($this->stats['checked'], $total);
            }
            if ($iterator === 0) {
                break;
            }
        }
        return $this->stats;
    }

    /**
     * @param array $keys
     * @return void
     * @throws RedisException
     */
    private function batch(array $keys)
    {
        $this->stats['checked'] += count($keys);
        $byType = [];
        $types = $this->pipeline($keys, function ($pipe, $key) {
            $pipe->type($key);
        });
        foreach ($keys as $i => $key) {
            if (strpos($key, self::SKIP_PREFIX) === 0) {
                $this->stats['skipped']++;
                continue;
            }
            $byType[$types[$i]][] = $key;
        }

        if (!empty($byType[Redis::REDIS_STRING])) {
            $strings = $byType[Redis::REDIS_STRING];
            $values = $this->pipeline($strings, function ($pipe, $key) {
                $pipe->get($key);
            });
            $repairs = [];
            foreach ($strings as $i => $key) {
                $raw = self::unwrap($values[$i]);
                if ($raw !== null) {
                    $repairs[] = [self::SCRIPT_STRING, $key, [$values[$i], $raw]];
                }
            }
            $this->stats['keys'] += count($this->repair($repairs));
        }
        $collections = [
            Redis::REDIS_SET => ['sCard', 'sMembers'],
            Redis::REDIS_ZSET => ['zCard', 'zRange'],
            Redis::REDIS_HASH => ['hLen', 'hGetAll'],
            Redis::REDIS_LIST => ['lLen', 'lRange'],
        ];
        foreach ($collections as $type => $commands) {
            if (empty($byType[$type])) {
                continue;
            }
            list($size, $fetch) = $commands;
            $sizes = $this->pipeline($byType[$type], function ($pipe, $key) use ($size) {
                $pipe->$size($key);
            });
            $small = [];
            foreach ($byType[$type] as $i => $key) {
                if ($sizes[$i] <= self::SMALL) {
                    $small[] = $key;
                } else {
                    $this->large($type, $key, (int)$sizes[$i]);
                }
            }
            $contents = $this->pipeline($small, function ($pipe, $key) use ($fetch) {
                if ($fetch === 'zRange' || $fetch === 'lRange') {
                    $pipe->$fetch($key, 0, -1);
                } else {
                    $pipe->$fetch($key);
                }
            });
            foreach ($small as $i => $key) {
                $repaired = $this->repair($this->collectionRepairs($type, $key, (array)$contents[$i]));
                $this->stats['keys'] += count($repaired);
            }
        }
    }

    /**
     * @param int $type
     * @param string $key
     * @param int $size
     * @return void
     * @throws RedisException
     */
    private function large($type, $key, $size)
    {
        $repaired = false;
        if ($type === Redis::REDIS_LIST) {
            for ($start = 0; $start < $size; $start += self::BATCH) {
                $items = $this->redis->lRange($key, $start, $start + self::BATCH - 1);
                $repaired = $this->repair($this->collectionRepairs($type, $key, $items, $start)) || $repaired;
            }
            $this->stats['keys'] += (int)$repaired;
            return;
        }
        $scan = [Redis::REDIS_SET => 'sScan', Redis::REDIS_ZSET => 'zScan', Redis::REDIS_HASH => 'hScan'][$type];
        $iterator = null;
        while (($chunk = $this->redis->$scan($key, $iterator, null, self::BATCH)) !== false) {
            // zScan answers member => score; only the members matter here.
            if ($type === Redis::REDIS_ZSET) {
                $chunk = array_keys($chunk);
            }
            $repaired = $this->repair($this->collectionRepairs($type, $key, $chunk)) || $repaired;
            if ($iterator === 0) {
                break;
            }
        }
        $this->stats['keys'] += (int)$repaired;
    }

    /**
     * @param int $type
     * @param string $key
     * @param array $content Members, or field => value for a hash
     * @param int $offset Index of the first list item in $content
     * @return array
     */
    private function collectionRepairs($type, $key, array $content, $offset = 0)
    {
        $repairs = [];
        foreach ($content as $index => $value) {
            $raw = self::unwrap($value);
            if ($raw === null) {
                continue;
            }
            switch ($type) {
                case Redis::REDIS_SET:
                    $repairs[] = [self::SCRIPT_SET, $key, [$value, $raw]];
                    break;
                case Redis::REDIS_ZSET:
                    $repairs[] = [self::SCRIPT_ZSET, $key, [$value, $raw]];
                    break;
                case Redis::REDIS_HASH:
                    $repairs[] = [self::SCRIPT_HASH, $key, [(string)$index, $value, $raw]];
                    break;
                case Redis::REDIS_LIST:
                    $repairs[] = [self::SCRIPT_LIST, $key, [(string)($offset + $index), $value, $raw]];
                    break;
            }
        }
        return $repairs;
    }

    /**
     * @param array $repairs [script, key, args]
     * @return array key => number of values repaired in it
     * @throws RedisException
     */
    private function repair(array $repairs)
    {
        if (empty($repairs)) {
            return [];
        }
        if ($this->dryRun) {
            $results = array_fill(0, count($repairs), 1);
        } else {
            $results = $this->pipeline($repairs, function ($pipe, $repair) {
                list($script, $key, $args) = $repair;
                $pipe->eval($script, array_merge([$key], $args), 1);
            });
        }
        $repaired = [];
        foreach ($repairs as $i => $repair) {
            if ($results[$i] === 1) {
                $this->stats['values']++;
                $repaired[$repair[1]] = ($repaired[$repair[1]] ?? 0) + 1;
            }
        }
        return $repaired;
    }

    /**
     * @param array $items
     * @param callable $queue function(Redis $pipe, mixed $item)
     * @return array Replies, in the order of $items
     * @throws RedisException
     */
    private function pipeline(array $items, callable $queue)
    {
        if (empty($items)) {
            return [];
        }
        $pipe = $this->redis->pipeline();
        foreach ($items as $item) {
            $queue($pipe, $item);
        }
        return $pipe->exec();
    }
}
