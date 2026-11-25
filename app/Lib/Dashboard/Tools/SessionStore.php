<?php

/**
 * PHP→Redis session store reader/purger for the dashboard's user
 * widgets (DD-34/DD-35/DD-36). Single source of truth for "which
 * Redis keys are user X's sessions", so the read path
 * (LoggedInUsersWidget's tally) and the purge path
 * (DashboardsController::invalidateUserSessions) agree by construction.
 *
 * Scope (deliberately narrow, unchanged from DD-34): only the
 * **PHP → Redis** session engine (`session.save_handler = redis`, the
 * phpredis native handler) is supported. There is no engine-agnostic
 * way to enumerate sessions — PHP's SessionHandlerInterface /
 * CakeSession are per-id (read/write/destroy a known id, never "list
 * all"), and some backends (memcached, apcu) cannot enumerate at all.
 * Callers check isSupported() and degrade to an "unsupported engine"
 * message for any other handler.
 *
 * Connection: parse `session.save_path` (tcp://host:port, optional
 * ?database=/?prefix=/?auth=) and open a direct `new Redis()` — NOT
 * MISP's RedisTool, which targets MISP's own DB-13, whereas sessions
 * live in the php save_path's redis (db0 by default). Only the
 * authenticated user id is read out of each session blob (CakePHP
 * stores it at Auth.User.id); no token or payload is exposed.
 */
class SessionStore
{
    /** phpredis' default session key prefix. */
    const DEFAULT_PREFIX = 'PHPREDIS_SESSION:';
    /** Safety cap on how many session keys to walk in one sweep. */
    const SCAN_CAP = 20000;

    /** @var Redis|null */
    private $redis = null;
    /** @var string */
    private $prefix = self::DEFAULT_PREFIX;

    /**
     * Is the PHP→Redis session engine in use and the phpredis
     * extension available? Cheap, no connection — callers gate on this.
     *
     * @return bool
     */
    public static function isSupported()
    {
        return strtolower((string)ini_get('session.save_handler')) === 'redis'
            && class_exists('Redis');
    }

    /**
     * Current session handler name (for the "unsupported engine"
     * message), or 'unknown' when ini reports nothing.
     *
     * @return string
     */
    public static function handlerName()
    {
        $h = strtolower((string)ini_get('session.save_handler'));
        return $h !== '' ? $h : 'unknown';
    }

    /**
     * Open a connection to the session store. Returns true on success;
     * on failure the instance is left unusable (tally/keysForUser/
     * destroy return empty). Safe to call only after isSupported().
     *
     * @return bool
     */
    public function connect()
    {
        $conn = $this->parseSavePath((string)ini_get('session.save_path'));
        $this->prefix = $conn['prefix'];
        try {
            $redis = new Redis();
            if (!$redis->connect($conn['host'], $conn['port'], 2.0)) {
                return false;
            }
            if (!empty($conn['auth'])) {
                $redis->auth($conn['auth']);
            }
            if (!empty($conn['database'])) {
                $redis->select($conn['database']);
            }
            $this->redis = $redis;
            return true;
        } catch (Exception $e) {
            $this->redis = null;
            return false;
        }
    }

    /**
     * Tally active sessions per authenticated user id. Anonymous
     * sessions (no Auth.User) are skipped.
     *
     * @return array<string,int> user id => session count
     */
    public function tally()
    {
        $counts = array();
        $this->eachSession(function ($key, $uid) use (&$counts) {
            $counts[$uid] = (isset($counts[$uid]) ? $counts[$uid] : 0) + 1;
        });
        return $counts;
    }

    /**
     * The session keys belonging to one authenticated user id.
     *
     * @param string|int $userId
     * @return string[] redis keys (already prefixed)
     */
    public function keysForUser($userId)
    {
        $target = (string)$userId;
        $hits = array();
        $this->eachSession(function ($key, $uid) use ($target, &$hits) {
            if ($uid === $target) {
                $hits[] = $key;
            }
        });
        return $hits;
    }

    /**
     * Delete the given session keys. Returns the number actually
     * removed (DEL's reply), 0 when nothing matched / no connection.
     *
     * @param string[] $keys
     * @return int
     */
    public function destroy(array $keys)
    {
        if ($this->redis === null || empty($keys)) {
            return 0;
        }
        try {
            return (int)$this->redis->del($keys);
        } catch (Exception $e) {
            return 0;
        }
    }

    /**
     * Walk every authenticated session once, invoking
     * $cb($key, $userId) for each. SCAN_RETRY + a hard cap keep the
     * sweep bounded; a mid-sweep failure stops early (callers keep
     * whatever was gathered).
     *
     * @param callable $cb function(string $key, string $userId): void
     * @return void
     */
    private function eachSession(callable $cb)
    {
        if ($this->redis === null) {
            return;
        }
        $processed = 0;
        try {
            $this->redis->setOption(Redis::OPT_SCAN, Redis::SCAN_RETRY);
            $it = null;
            while (($keys = $this->redis->scan($it, $this->prefix . '*', 500)) !== false) {
                $remaining = self::SCAN_CAP - $processed;
                if ($remaining <= 0) {
                    return;
                }
                // Trim the page to the remaining cap *before* fetching, so the
                // mid-page truncation semantics stay identical to the old
                // per-key walk (exactly SCAN_CAP keys are ever inspected).
                $page = count($keys) > $remaining ? array_slice($keys, 0, $remaining) : $keys;
                if (empty($page)) {
                    continue;
                }
                $processed += count($page);
                // One MGET per SCAN page instead of one GET per key. phpredis
                // returns values aligned to the input order, false for keys
                // that vanished between the SCAN and the MGET.
                $values = $this->redis->mget($page);
                if (!is_array($values)) {
                    return;
                }
                foreach ($page as $i => $key) {
                    $uid = $this->extractUserId(isset($values[$i]) ? $values[$i] : false);
                    if ($uid !== null) {
                        $cb($key, $uid);
                    }
                }
                if (count($page) < count($keys)) {
                    return;
                }
            }
        } catch (Exception $e) {
            // Stop on failure; the caller uses whatever was gathered.
        }
    }

    /**
     * Pull the authenticated user id out of a PHP-serialised session
     * blob, or null when the session is anonymous / unparseable.
     * CakePHP stores the login at Auth.User with id first:
     *   Auth|a:1:{s:4:"User";a:N:{s:2:"id";(s:M:"<id>"|i:<id>)…
     *
     * @param mixed $data
     * @return string|null
     */
    private function extractUserId($data)
    {
        if (!is_string($data) || strpos($data, 'Auth|') === false) {
            return null;
        }
        if (preg_match(
            '/Auth\|a:\d+:\{s:4:"User";a:\d+:\{s:2:"id";(?:s:\d+:"(\d+)"|i:(\d+))/',
            $data,
            $m
        )) {
            return ($m[1] !== '') ? $m[1] : $m[2];
        }
        return null;
    }

    /**
     * Parse a phpredis `session.save_path` into connection parts. Takes
     * the first server when several are given (failover lists are space
     * separated). Falls back to sensible phpredis defaults.
     *
     * @param string $savePath
     * @return array{host:string,port:int,database:int,prefix:string,auth:?string}
     */
    private function parseSavePath($savePath)
    {
        $parts = preg_split('/\s+/', trim($savePath), -1, PREG_SPLIT_NO_EMPTY);
        $first = !empty($parts) ? $parts[0] : 'tcp://127.0.0.1:6379';
        $noScheme = preg_replace('#^tcp://#', '', $first);
        $query = array();
        if (strpos($noScheme, '?') !== false) {
            list($hostport, $q) = explode('?', $noScheme, 2);
            parse_str($q, $query);
        } else {
            $hostport = $noScheme;
        }
        list($host, $port) = array_pad(explode(':', $hostport, 2), 2, 6379);
        return array(
            'host'     => $host !== '' ? $host : '127.0.0.1',
            'port'     => (int)$port,
            'database' => isset($query['database']) ? (int)$query['database'] : 0,
            'prefix'   => isset($query['prefix']) && $query['prefix'] !== '' ? $query['prefix'] : self::DEFAULT_PREFIX,
            'auth'     => isset($query['auth']) ? $query['auth'] : null,
        );
    }
}
