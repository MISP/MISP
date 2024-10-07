<?php
class RedisTool
{
    const COMPRESS_MIN_LENGTH = 256,
        BROTLI_HEADER = "\xce\xb2\xcf\x81",
        ZSTD_HEADER = "\x28\xb5\x2f\xfd";

    /** @var Redis|null */
    private static $connection;

    /** @var string */
    private static $serializer;

    /**
     * @return Redis
     * @throws Exception
     */
    public static function init()
    {
        if (self::$connection) {
            return self::$connection;
        }

        $redisVersion = phpversion('redis');
        if ($redisVersion === false) {
            throw new Exception("Redis extension is not installed. Please install redis extension for PHP.");
        }

        $host = Configure::read('MISP.redis_host') ?: '127.0.0.1';
        $port = Configure::read('MISP.redis_port') ?: 6379;
        $database = Configure::read('MISP.redis_database') ?: 13;
        $pass = Configure::read('MISP.redis_password');
        $persistent = Configure::read('MISP.redis_persistent_connection');

        if ($redisVersion[0] >= 6) {
            $options = [
                'host' => $host,
                'port' => $port,
                'persistent' => $persistent,
            ];
            if (!empty($pass)) {
                $options['auth'] = $pass;
            }
            $redis = new Redis($options);
        } else {
            $redis = new Redis();
            $connection = $persistent ? $redis->pconnect($host, $port) : $redis->connect($host, $port);
            if (!$connection) {
                throw new Exception("Could not connect to Redis: {$redis->getLastError()}");
            }
            if (!empty($pass)) {
                if (!$redis->auth($pass)) {
                    throw new Exception("Could not authenticate to Redis: {$redis->getLastError()}");
                }
            }
        }

        if (!$redis->select($database)) {
            throw new Exception("Could not select Redis database $database: {$redis->getLastError()}");
        }
        // By default retry scan if empty results are returned
        $redis->setOption(Redis::OPT_SCAN, Redis::SCAN_RETRY);
        // Set client name so it is possible to distinguish redis connections
        $redis->client('setname', 'misp-' . PHP_SAPI);
        self::$connection = $redis;
        return $redis;
    }

    /**
     * @param Redis $redis
     * @param string|array $pattern
     * @return Generator<string>
     * @throws RedisException
     */
    public static function keysByPattern(Redis $redis, $pattern)
    {
        if (is_string($pattern)) {
            $pattern = [$pattern];
        }

        foreach ($pattern as $p) {
            $iterator = null;
            while (false !== ($keys = $redis->scan($iterator, $p, 1000))) {
                foreach ($keys as $key) {
                    yield $key;
                }
            }
        }
    }

    /**
     * @param Redis $redis
     * @param string|array $pattern
     * @return int|Redis Number of deleted keys or instance of Redis if used in MULTI mode
     * @throws RedisException
     */
    public static function deleteKeysByPattern(Redis $redis, $pattern)
    {
        $allKeys = iterator_to_array(self::keysByPattern($redis, $pattern));
        if (empty($allKeys)) {
            return 0;
        }

        return self::unlink($redis, $allKeys);
    }

    /**
     * Unlink is non blocking way how to delete keys from Redis, but it must be supported by PHP extension and Redis itself
     *
     * @param Redis $redis
     * @param string|array $keys
     * @return int|Redis Number of deleted keys or instance of Redis if used in MULTI mode
     * @throws RedisException
     */
    public static function unlink(Redis $redis, $keys)
    {
        static $unlinkSupported;
        if ($unlinkSupported === null) {
            // Check if unlink is supported
            $unlinkSupported = method_exists($redis, 'unlink') && $redis->unlink(null) === 0;
        }
        return $unlinkSupported ? $redis->unlink($keys) : $redis->del($keys);
    }

    /**
     * @param Redis $redis
     * @param string $prefix
     * @return array[int, int]
     * @throws RedisException
     */
    public static function sizeByPrefix(Redis $redis, $prefix)
    {
        $keyCount = 0;
        $size = 0;
        $it = null;
        while ($keys = $redis->scan($it, $prefix, 1000)) {
            $redis->pipeline();
            foreach ($keys as $key) {
                $redis->rawCommand("memory", "usage", $key);
            }
            $result = $redis->exec();
            $keyCount += count($keys);
            $size += array_sum($result);
        }
        return [$keyCount, $size];
    }

    /**
     * @param mixed $data
     * @return string
     * @throws JsonException
     */
    public static function serialize($data)
    {
        if (self::$serializer === null) {
            self::$serializer = Configure::read('MISP.redis_serializer') ?: false;
        }

        if (self::$serializer === 'igbinary') {
            return igbinary_serialize($data);
        } else {
            return JsonTool::encode($data);
        }
    }

    /**
     * @param string $string
     * @return mixed
     * @throws JsonException
     */
    public static function deserialize($string)
    {
        if ($string === false) {
            return false;
        }

        if ($string[0] === "\x00") {
            return igbinary_unserialize($string);
        } else {
            return JsonTool::decode($string);
        }
    }

    /**
     * @param string $data
     * @return string
     */
    public static function compress($data)
    {
        if (strlen($data) >= self::COMPRESS_MIN_LENGTH) {
            if (function_exists('zstd_compress')) {
                return zstd_compress($data, 1);
            } elseif (function_exists('brotli_compress')) {
                return self::BROTLI_HEADER . brotli_compress($data, 0);
            }
        }
        return $data;
    }

    /**
     * @param string|false $data
     * @return string
     */
    public static function decompress($data)
    {
        if ($data === false) {
            return false;
        }

        $magic = substr($data, 0, 4);
        if ($magic === self::ZSTD_HEADER) {
           $data = zstd_uncompress($data);
           if ($data === false) {
               throw new RuntimeException('Could not decompress');
           }
        } elseif ($magic === self::BROTLI_HEADER) {
            $data = brotli_uncompress(substr($data, 4));
            if ($data === false) {
                throw new RuntimeException('Could not decompress');
            }
        }
        return $data;
    }
}
