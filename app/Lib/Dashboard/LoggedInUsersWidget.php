<?php

/**
 * Logged-in users widget (dashboard v2).
 *
 * Lists the users that currently hold an active session, with how many
 * sessions each one has. "Currently logged in" is read from the live
 * session store — there is no engine-agnostic way to enumerate sessions
 * (PHP's SessionHandlerInterface / CakeSession are per-id: read/write/
 * destroy a known id, never "list all"), so enumeration is necessarily
 * backend-specific.
 *
 * Scope (deliberately narrow): only the **PHP → Redis** session engine
 * (`session.save_handler = redis`, the phpredis native handler) is
 * supported. For any other engine (files, database, memcached, apcu, a
 * Cake cache/database handler) the widget reports that the engine is
 * unsupported rather than guessing. Redis is the one store this MISP is
 * configured for and the one cleanly + safely enumerable here.
 *
 * Mechanism: parse `session.save_path` (tcp://host:port, optional
 * ?database=/?prefix=/?auth=), connect with the phpredis extension,
 * SCAN the session-key prefix, and for each session blob extract the
 * authenticated user id (CakePHP stores it at Auth.User.id in the
 * PHP-serialised session data). Tally sessions per user id, then load
 * those users for display. Only the user id is read out of the blob; no
 * session token or payload is exposed.
 *
 * Site-admin only (it reveals who is logged in across the instance).
 */
class LoggedInUsersWidget
{
    public $title = 'Logged-in users';
    public $category = 'users';
    public $render = 'SimpleList';
    public $width = 3;
    public $height = 4;
    public $params = array();
    public $schema = array();
    public $description = 'Users that currently hold an active session, with their session count. Requires the PHP → Redis session engine.';
    // Live view; let the board re-scan once a minute (a SCAN + GET per
    // session is cheap, but not free — don't hammer it).
    public $autoRefreshDelay = 60;

    /** phpredis' default session key prefix. */
    const DEFAULT_PREFIX = 'PHPREDIS_SESSION:';
    /** Safety cap on how many session keys to walk in one render. */
    const SCAN_CAP = 20000;

    private $User = null;

    public function handler($user, $options = array())
    {
        $handler = strtolower((string)ini_get('session.save_handler'));
        if ($handler !== 'redis' || !class_exists('Redis')) {
            return array(array(
                'title' => __('Unsupported session engine'),
                // Raw values only — the SimpleList renderer escapes
                // title/value once; pre-escaping here double-escapes.
                'value' => sprintf(
                    __('this widget requires the PHP → Redis session engine (current: %s)'),
                    $handler !== '' ? $handler : __('unknown')
                ),
            ));
        }

        $conn = $this->parseSavePath((string)ini_get('session.save_path'));
        $redis = $this->connect($conn);
        if ($redis === null) {
            return array(array(
                'title' => __('Session store unreachable'),
                'value' => __('could not connect to the Redis session store'),
            ));
        }

        $counts = $this->tallySessions($redis, $conn['prefix']);
        if (empty($counts)) {
            return array(array(
                'title' => __('Logged-in users'),
                'value' => __('none — no active sessions'),
            ));
        }

        return $this->buildRows($counts);
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

    /**
     * Open a phpredis connection to the session store, or null on failure.
     */
    private function connect(array $conn)
    {
        try {
            $redis = new Redis();
            if (!$redis->connect($conn['host'], $conn['port'], 2.0)) {
                return null;
            }
            if (!empty($conn['auth'])) {
                $redis->auth($conn['auth']);
            }
            if (!empty($conn['database'])) {
                $redis->select($conn['database']);
            }
            return $redis;
        } catch (Exception $e) {
            return null;
        }
    }

    /**
     * SCAN the session keys and tally sessions per authenticated user id.
     * Anonymous sessions (no Auth.User) are skipped.
     *
     * @return array<string,int> user id => session count
     */
    private function tallySessions($redis, $prefix)
    {
        $counts = array();
        $processed = 0;
        try {
            $redis->setOption(Redis::OPT_SCAN, Redis::SCAN_RETRY);
            $it = null;
            while (($keys = $redis->scan($it, $prefix . '*', 500)) !== false) {
                foreach ($keys as $key) {
                    if ($processed++ >= self::SCAN_CAP) {
                        return $counts;
                    }
                    $data = $redis->get($key);
                    if (!is_string($data) || strpos($data, 'Auth|') === false) {
                        continue;
                    }
                    // CakePHP stores the login at Auth.User, with id first
                    // (the user DB row): Auth|a:1:{s:4:"User";a:N:{s:2:"id";...
                    if (preg_match(
                        '/Auth\|a:\d+:\{s:4:"User";a:\d+:\{s:2:"id";(?:s:\d+:"(\d+)"|i:(\d+))/',
                        $data,
                        $m
                    )) {
                        $id = ($m[1] !== '') ? $m[1] : $m[2];
                        $counts[$id] = (isset($counts[$id]) ? $counts[$id] : 0) + 1;
                    }
                }
            }
        } catch (Exception $e) {
            // Return whatever was tallied before the failure.
        }
        return $counts;
    }

    /**
     * Turn the per-user session tally into SimpleList rows: a summary
     * line, then one row per user (most sessions first), each linking to
     * the user's admin view.
     */
    private function buildRows(array $counts)
    {
        $this->User = ClassRegistry::init('User');
        $users = $this->User->find('all', array(
            'recursive' => -1,
            'contain' => array('Organisation.name', 'Role.name'),
            'fields' => array('User.id', 'User.email', 'User.disabled'),
            'conditions' => array('User.id' => array_keys($counts)),
        ));
        $byId = array();
        foreach ($users as $u) {
            $byId[$u['User']['id']] = $u;
        }

        // Most sessions first, then by id for stability.
        uksort($counts, function ($a, $b) use ($counts) {
            if ($counts[$a] !== $counts[$b]) {
                return $counts[$b] - $counts[$a];
            }
            return (int)$a - (int)$b;
        });

        $totalSessions = array_sum($counts);
        $rows = array(
            array(
                'title' => __('Online now'),
                'value' => sprintf(
                    __('%d user%s · %d session%s'),
                    count($counts),
                    count($counts) === 1 ? '' : 's',
                    $totalSessions,
                    $totalSessions === 1 ? '' : 's'
                ),
            ),
            array('type' => 'gap'),
        );

        foreach ($counts as $id => $count) {
            if (!isset($byId[$id])) {
                // A session for a user that no longer exists (e.g. deleted).
                $rows[] = array(
                    'title' => sprintf(__('User #%s (removed)'), $id),
                    'value' => sprintf('%d session%s', $count, $count === 1 ? '' : 's'),
                );
                continue;
            }
            $u = $byId[$id];
            $org = !empty($u['Organisation']['name']) ? $u['Organisation']['name'] : '—';
            $role = !empty($u['Role']['name']) ? $u['Role']['name'] : '—';
            // Raw values only — SimpleList escapes title/value once (a
            // malicious org/role name is rendered as inert text there).
            $rows[] = array(
                'title' => $u['User']['email'],
                'value' => sprintf(
                    '%s · %s · %d session%s',
                    $org,
                    $role,
                    $count,
                    $count === 1 ? '' : 's'
                ),
                'drilldown' => '/admin/users/view/' . (int)$id,
            );
        }
        return $rows;
    }

    public function checkPermissions($user)
    {
        return !empty($user['Role']['perm_site_admin']);
    }
}
