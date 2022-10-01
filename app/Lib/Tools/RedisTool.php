<?php
class RedisTool
{
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

        if (!class_exists('Redis')) {
            throw new Exception("Class Redis doesn't exists. Please install redis extension for PHP.");
        }

        $host = Configure::read('MISP.redis_host') ?: '127.0.0.1';
        $port = Configure::read('MISP.redis_port') ?: 6379;
        $database = Configure::read('MISP.redis_database') ?: 13;
        $pass = Configure::read('MISP.redis_password');

        $redis = new Redis();
        if (!$redis->connect($host, (int) $port)) {
            throw new Exception("Could not connect to Redis: {$redis->getLastError()}");
        }
        if (!empty($pass)) {
            if (!$redis->auth($pass)) {
                throw new Exception("Could not authenticate to Redis: {$redis->getLastError()}");
            }
        }
        if (!$redis->select($database)) {
            throw new Exception("Could not select Redis database $database: {$redis->getLastError()}");
        }
        self::$connection = $redis;
        return $redis;
    }

    /**
     * @param Redis $redis
     * @param string $pattern
     * @return int|Redis Number of deleted keys or instance of Redis if used in MULTI mode
     * @throws RedisException
     */
    public static function deleteKeysByPattern(Redis $redis, $pattern)
    {
        $iterator = null;
        $allKeys = [];
        while (false !== ($keys = $redis->scan($iterator, $pattern))) {
            foreach ($keys as $key) {
                $allKeys[] = $key;
            }
        }

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

        if (self::$serializer === null) {
            self::$serializer = Configure::read('MISP.redis_serializer') ?: false;
        }

        if (self::$serializer === 'igbinary') {
            return igbinary_unserialize($string);
        } else {
            return JsonTool::decode($string);
        }
    }
}
