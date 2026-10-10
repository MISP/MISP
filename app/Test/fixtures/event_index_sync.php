<?php
/**
 * Isolated regression harness for the real controller/model/cache methods.
 * Run without Composer: php app/Test/fixtures/event_index_sync.php [scenario]
 * The PHPUnit wrapper invokes each scenario in a separate PHP process so these
 * minimal framework doubles cannot conflict with other model test stubs.
 */
set_error_handler(function ($severity, $message, $file, $line) {
    if (error_reporting() & $severity) {
        throw new ErrorException($message, 0, $severity, $file, $line);
    }
});
class App
{
    public static function uses($name, $package) {}
}
class AppModel {}
class Controller {}
class AppController extends Controller {}
class Component {}
class ClassRegistry
{
    public static function init($name)
    {
        return new class {
            public function removeBlockedEvents(&$events) { $events = []; }
        };
    }
}
class BadRequestException extends Exception {}
class Configure
{
    public static $values = ['Security.salt' => 'fixture-salt'];
    public static function read($name) { return self::$values[$name] ?? null; }
}
class CakeRequest
{
    public $data = [];
    public $params = ['named' => []];
    public static $version = '2.5.49';
    public static function header($name)
    {
        return $name === 'misp-version' ? self::$version : 'MISP test';
    }
    public function is($name) { return false; }
}
class CakeResponse
{
    public $body = '';
    public $code = 200;
    public $headers = [];
    public function __construct(array $options = [])
    {
        $this->body = $options['body'] ?? '';
        $this->code = $options['status'] ?? 200;
    }
    public function type() { return 'application/json'; }
    public function header($name, $value = null)
    {
        if (is_array($name)) {
            foreach ($name as $key => $item) { $this->header($key, $item); }
        } else {
            $this->headers[strtolower($name)] = $value;
        }
    }
    public function getHeader($name)
    {
        return $this->headers[strtolower($name)] ?? false;
    }
    public function isNotModified() { return $this->code === 304; }
    public function json() { return JsonTool::decode($this->body); }
}
class FixtureRedis
{
    public $values = [];
    public $writes = 0;
    public function get($key) { return $this->values[$key] ?? false; }
    public function setex($key, $ttl, $value)
    {
        ++$this->writes;
        $this->values[$key] = $value;
    }
}
class RedisTool
{
    public static $redis;
    public static function init() { return self::$redis; }
    public static function compress($value) { return gzcompress($value); }
    public static function decompress($value)
    {
        $result = @gzuncompress($value);
        if ($result === false) { throw new RuntimeException('Corrupt cache'); }
        return $result;
    }
}

require_once __DIR__ . '/../../Lib/Tools/JsonTool.php';
require_once __DIR__ . '/../../Lib/Tools/EventIndexSyncTool.php';
require_once __DIR__ . '/../../Lib/Tools/ServerSyncTool.php';
require_once __DIR__ . '/../../Model/CryptographicKey.php';
require_once __DIR__ . '/../../Model/Server.php';
require_once __DIR__ . '/../../Controller/Component/RestResponseComponent.php';
require_once __DIR__ . '/../../Controller/EventsController.php';

function same($expected, $actual, $message = '')
{
    if ($expected !== $actual) {
        throw new RuntimeException($message . ' expected ' .
            json_encode($expected) . ', got ' . json_encode($actual));
    }
}
function throws($class, callable $callback)
{
    try { $callback(); } catch (Throwable $e) {
        if ($e instanceof $class) { return; }
        throw $e;
    }
    throw new RuntimeException('Expected ' . $class);
}
function invoke($object, $method, ...$args)
{
    $reflection = new ReflectionMethod($object, $method);
    $reflection->setAccessible(true);
    return $reflection->invokeArgs($object, $args);
}
function rows($count, array $protected = [], array $keyed = [])
{
    $result = [];
    for ($id = 1; $id <= $count; ++$id) {
        $result[] = [
            'Event' => [
                'id' => $id, 'uuid' => 'event-' . $id, 'published' => 1,
                'timestamp' => 100, 'sighting_timestamp' => 100,
                'protected' => in_array($id, $protected, true) ? 1 : 0,
            ],
            'Orgc' => ['uuid' => 'org-1'],
            'allowed_key' => in_array($id, $keyed, true),
        ];
    }
    return $result;
}
class FixtureDataSource
{
    public $options;
    public function fullTableName($model) { return $model->table; }
    public function buildStatement($options, $model)
    {
        $this->options = $options;
        $fingerprint = str_replace("'", "''",
            $options['conditions']['CryptographicKey.fingerprint']);
        return "SELECT CryptographicKey.parent_id FROM cryptographic_keys " .
            "AS CryptographicKey WHERE CryptographicKey.parent_type = 'Event' " .
            "AND CryptographicKey.fingerprint = '$fingerprint' " .
            'AND CryptographicKey.parent_id = Event.id';
    }
}
class FixtureCryptographicKey extends CryptographicKey
{
    public $rows = [];
    public $fingerprint = 'fixture-key';
    public $fail = false;
    public $table = 'cryptographic_keys';
    public $db;
    public function __construct() { $this->db = new FixtureDataSource(); }
    public function ingestInstanceKey()
    {
        if ($this->fail) { throw new RuntimeException('No signing key'); }
        return $this->fingerprint;
    }
    public function getDataSource() { return $this->db; }
    public function find($type, $options)
    {
        same('column', $type);
        if (!$options['conditions']['CryptographicKey.fingerprint']) { return []; }
        $ids = $options['conditions']['CryptographicKey.parent_id'];
        return array_values(array_map(function ($row) {
            return $row['Event']['id'];
        }, array_filter($this->rows, function ($row) use ($ids) {
            return $row['allowed_key'] &&
                in_array($row['Event']['id'], $ids, true);
        })));
    }
}
class FixtureEvent
{
    public $rows;
    public $queries = [];
    public $CryptographicKey;
    public $EventReport;
    public $ignorePage = false;
    public $ignoreLimit = false;
    public function __construct(array $rows)
    {
        $this->rows = $rows;
        $this->CryptographicKey = new FixtureCryptographicKey();
        $this->CryptographicKey->rows = $rows;
        $this->EventReport = (object)['table' => 'event_reports'];
    }
    public function schema()
    {
        return array_fill_keys(['id', 'uuid', 'timestamp', 'published',
            'sighting_timestamp', 'protected'], []);
    }
    private function matches($row, $conditions)
    {
        if (is_string($conditions)) {
            // The production key predicate is emitted by the real model.
            return strpos($conditions, 'EXISTS (') === 0 ?
                $row['allowed_key'] : true;
        }
        foreach ($conditions as $field => $value) {
            if ($field === 'AND' || is_int($field)) {
                foreach ($field === 'AND' ? $value : [$value] as $condition) {
                    if (!$this->matches($row, $condition)) { return false; }
                }
            } elseif ($field === 'OR') {
                $any = false;
                foreach ($value as $condition) {
                    $any = $any || $this->matches($row, $condition);
                }
                if (!$any) { return false; }
            } elseif ($field === 'Event.protected') {
                if ($row['Event']['protected'] !== $value) { return false; }
            } elseif ($field === 'Event.id >') {
                if ($row['Event']['id'] <= $value) { return false; }
            } elseif ($field === 'Event.id <=') {
                if ($row['Event']['id'] > $value) { return false; }
            } elseif ($field === 'Event.id') {
                if ($row['Event']['id'] !== $value) { return false; }
            }
        }
        return true;
    }
    public function find($type, array $options)
    {
        $this->queries[] = [$type, $options];
        $rows = array_values(array_filter($this->rows, function ($row) use ($options) {
            return $this->matches($row, $options['conditions'] ?? []);
        }));
        if ($type === 'count') { return count($rows); }
        if (($options['order']['Event.id'] ?? 'ASC') === 'DESC') {
            $rows = array_reverse($rows);
        }
        if ($type === 'first') { return $rows[0] ?? []; }
        $limit = $this->ignoreLimit ? count($rows) : ($options['limit'] ?? count($rows));
        $page = $this->ignorePage ? 1 : ($options['page'] ?? 1);
        return array_slice($rows, ($page - 1) * $limit, $limit);
    }
}
class FixtureEventsController extends EventsController
{
    public $Event;
    public $Auth;
    public $request;
    public $response;
    public $RestResponse;
    public $passedArgs = [];
    public $userRole = ['perm_sync' => true];
    public function __construct(FixtureEvent $event)
    {
        $this->Event = $event;
        $this->request = new CakeRequest();
        $this->response = new CakeResponse();
        $this->Auth = new class {
            public function user($key = null) { return $key === 'id' ? 42 : []; }
        };
        $this->RestResponse = new RestResponseComponent();
        $this->RestResponse->initialize($this);
    }
    public function _isSiteAdmin() { return true; }
    public function _isRest() { return true; }
    public function loadModel($name) {}
    public function respond(array $request)
    {
        $this->request->data = $request;
        $this->paginate['conditions'] = [];
        return $this->index(); // exercises POST argument harvesting too
    }
}
class FixtureSync extends ServerSyncTool
{
    public $cursorSupported;
    public $controller;
    public $requests = [];
    public $statuses = [];
    public $countHeader = true;
    public $force304 = 0;
    public function __construct($cursorSupported, FixtureEventsController $controller)
    {
        $this->cursorSupported = $cursorSupported;
        $this->controller = $controller;
    }
    public function info()
    {
        return ['version' => '2.5.49',
            'event_index_cursor_v1' => $this->cursorSupported];
    }
    public function server()
    {
        return ['Server' => ['url' => 'https://fixture.invalid',
            'authkey' => 'fixture-key', 'pull_rules' => '', 'internal' => false]];
    }
    public function serverId() { return 17; }
    public function debug($message) {}
    public function eventIndex($params = [], $etag = null)
    {
        $this->requests[] = [$params, $etag];
        if ($this->force304 > 0) {
            --$this->force304;
            $response = new CakeResponse(['status' => 304]);
        } else {
            $_SERVER['HTTP_IF_NONE_MATCH'] = $etag;
            $response = $this->controller->respond($params);
            if (!$this->countHeader) {
                unset($response->headers['x-result-count']);
            }
        }
        $this->statuses[] = $response->code;
        return $response;
    }
}
class FixtureServer extends Server
{
    public $EventBlocklist;
    public $OrgBlocklist;
    public function __construct() {}
    public function getEventIndexPageFromServer(ServerSyncTool $sync, $ignoreFilterRules = false, array $pagination = [], &$remoteTotal = null, $fresh = false)
    {
        return parent::getEventIndexPageFromServer(
            $sync, $ignoreFilterRules, $pagination, $remoteTotal, $fresh
        );
    }
    public function collect(ServerSyncTool $sync, $all = true)
    {
        return invoke($this, 'getEventIdsFromServer', $sync, $all, true, true);
    }
}
function fixture($data, $cursor = true)
{
    RedisTool::$redis = new FixtureRedis();
    Configure::$values = ['Security.salt' => 'fixture-salt',
        'MISP.event_index_pull_chunk_size' => 3,
        'MISP.event_index_cursor_pagination' => true,
        'MISP.enableEventBlocklisting' => false,
        'MISP.enableOrgBlocklisting' => false];
    CakeRequest::$version = '2.5.49';
    $event = new FixtureEvent($data);
    $controller = new FixtureEventsController($event);
    return [new FixtureServer(), new FixtureSync($cursor, $controller), $event];
}
function legacySource(FixtureSync $sync)
{
    // An unchanged older server filters protected events AFTER LIMIT/OFFSET.
    $sync->controller->Event->CryptographicKey = new class extends FixtureCryptographicKey {
        public function eventIndexConditions() { return []; }
    };
    $sync->controller->Event->CryptographicKey->rows = $sync->controller->Event->rows;
}

$scenarios = [];
$scenarios['cursor-filtered-pages-and-cache'] = function () {
    [$server, $sync, $event] = fixture(rows(13, range(1, 9)));
    same(['event-10', 'event-11', 'event-12', 'event-13'], $server->collect($sync));
    same(5, count($sync->requests));
    same(1, count(array_filter($event->queries, function ($q) { return $q[0] === 'first'; })));
    same(0, count(array_filter($event->queries, function ($q) { return $q[0] === 'count'; })));
    foreach ($event->queries as [$type, $options]) {
        if ($type === 'all') {
            same(4, $options['limit']);
            same(false, isset($options['page']));
        }
    }
    $sync->statuses = [];
    same(['event-10', 'event-11', 'event-12', 'event-13'], $server->collect($sync));
    same([304, 304, 304, 304, 304], $sync->statuses);
};
$scenarios['cursor-all-filtered'] = function () {
    [$server, $sync] = fixture(rows(10, range(1, 10)));
    same([], $server->collect($sync));
    same(4, count($sync->requests));
};
$scenarios['cursor-disabled-uses-compatible-pages'] = function () {
    [$server, $sync] = fixture(rows(7, [1, 2, 3]));
    Configure::$values['MISP.event_index_cursor_pagination'] = false;
    same(['event-4', 'event-5', 'event-6', 'event-7'], $server->collect($sync));
    foreach ($sync->requests as [$params]) {
        same(false, isset($params['sync_cursor']));
    }
};
$scenarios['cursor-local-filters-do-not-stop-scan'] = function () {
    [$server, $sync] = fixture(rows(10));
    Configure::$values['MISP.enableEventBlocklisting'] = true;
    same([], $server->collect($sync, false));
    same(4, count($sync->requests));
};
$scenarios['cursor-exact-boundary'] = function () {
    [$server, $sync] = fixture(rows(6));
    same(array_map(function ($id) { return 'event-' . $id; }, range(1, 6)), $server->collect($sync));
    same(2, count($sync->requests));
};
$scenarios['cursor-empty-source'] = function () {
    [$server, $sync] = fixture([]);
    same([], $server->collect($sync));
    same(1, count($sync->requests));
};
$scenarios['cursor-new-sweep-insert'] = function () {
    [$server, $sync, $event] = fixture(rows(3, [1, 2, 3]));
    same([], $server->collect($sync));
    $event->rows = rows(4, [1, 2, 3]);
    $event->CryptographicKey->rows = $event->rows;
    $sync->statuses = [];
    same(['event-4'], $server->collect($sync));
    same([200, 200], $sync->statuses);
};
$scenarios['cursor-cache-slots-reused-across-bounds'] = function () {
    [$server, $sync, $event] = fixture(rows(7));
    same(7, count($server->collect($sync)));
    same(3, count(RedisTool::$redis->values));
    $event->rows = rows(8);
    $event->CryptographicKey->rows = $event->rows;
    same(8, count($server->collect($sync)));
    same(3, count(RedisTool::$redis->values));
};
$scenarios['cursor-key-eligibility'] = function () {
    [$server, $sync] = fixture(rows(5, [1, 2, 3, 4], [2, 4]));
    same(['event-2', 'event-4', 'event-5'], $server->collect($sync));
};
$scenarios['cursor-bindings-and-tampering'] = function () {
    [$server, $sync] = fixture(rows(5));
    $total = null;
    $first = $server->getEventIndexPageFromServer($sync, true,
        ['sync_cursor' => 1, 'limit' => 3, 'cursor' => null], $total);
    $cursor = $first['pagination']['next_cursor'];
    throws(BadRequestException::class, function () use ($server, $sync, $cursor) {
        $server->getEventIndexPageFromServer($sync, true,
            ['sync_cursor' => 1, 'limit' => 2, 'cursor' => $cursor]);
    });
    throws(BadRequestException::class, function () use ($server, $sync, $cursor) {
        $server->getEventIndexPageFromServer($sync, true,
            ['sync_cursor' => 1, 'limit' => 3, 'cursor' => $cursor . 'x']);
    });
};
$scenarios['cursor-high-water-and-deletion'] = function () {
    [$server, $sync, $event] = fixture(rows(7));
    $total = null;
    $first = $server->getEventIndexPageFromServer($sync, true,
        ['sync_cursor' => 1, 'limit' => 3, 'cursor' => null], $total);
    $event->rows = array_slice(rows(8), 1); // delete id 1 and append id 8
    $second = $server->getEventIndexPageFromServer($sync, true,
        ['sync_cursor' => 1, 'limit' => 3,
            'cursor' => $first['pagination']['next_cursor']], $total);
    same([4, 5, 6], array_column($second['events'], 'id'));
    same(7, $second['pagination']['upper_bound']);
};
$scenarios['legacy-fully-filtered-middle-and-cache'] = function () {
    [$server, $sync] = fixture(rows(10, [4, 5, 6]), false);
    legacySource($sync);
    $expected = ['event-1', 'event-2', 'event-3', 'event-7', 'event-8', 'event-9', 'event-10'];
    same($expected, $server->collect($sync));
    same(4, count($sync->requests));
    $sync->statuses = [];
    same($expected, $server->collect($sync));
    same([200, 304, 304, 304], $sync->statuses);
};
$scenarios['legacy-first-and-consecutive-empty'] = function () {
    [$server, $sync] = fixture(rows(10, range(1, 9)), false);
    legacySource($sync);
    same(['event-10'], $server->collect($sync));
    same(4, count($sync->requests));
};
$scenarios['legacy-partial-first-page'] = function () {
    [$server, $sync] = fixture(rows(7, [2]), false);
    legacySource($sync);
    same(['event-1', 'event-3', 'event-4', 'event-5', 'event-6', 'event-7'],
        $server->collect($sync));
    same(3, count($sync->requests));
};
$scenarios['legacy-fresh-count-on-next-pull'] = function () {
    [$server, $sync, $event] = fixture(rows(3), false);
    legacySource($sync);
    same(['event-1', 'event-2', 'event-3'], $server->collect($sync));
    $event->rows = rows(4);
    $event->CryptographicKey->rows = $event->rows;
    same(['event-1', 'event-2', 'event-3', 'event-4'], $server->collect($sync));
};
$scenarios['legacy-no-count-fallback'] = function () {
    [$server, $sync] = fixture(rows(7, [1, 2, 3]), false);
    legacySource($sync);
    $sync->countHeader = false;
    same(['event-4', 'event-5', 'event-6', 'event-7'], $server->collect($sync));
    same(2, count($sync->requests));
    same(false, isset($sync->requests[1][0]['page']));
};
$scenarios['legacy-ignores-page'] = function () {
    [$server, $sync, $event] = fixture(rows(7), false);
    legacySource($sync);
    $event->ignorePage = true;
    same(array_map(function ($id) { return 'event-' . $id; }, range(1, 7)), $server->collect($sync));
    same(3, count($sync->requests));
};
$scenarios['legacy-ignores-limit'] = function () {
    [$server, $sync, $event] = fixture(rows(7), false);
    legacySource($sync);
    $event->ignoreLimit = true;
    same(array_map(function ($id) { return 'event-' . $id; }, range(1, 7)), $server->collect($sync));
    same(1, count($sync->requests));
};
$scenarios['old-client-new-server-full-pages'] = function () {
    [$server, $sync] = fixture(rows(8, [1, 2, 3, 4], [2]), false);
    $response = $sync->controller->respond(['minimal' => 1, 'published' => 1,
        'page' => 1, 'limit' => 3, 'sort' => 'id', 'direction' => 'asc']);
    same([2, 5, 6], array_column($response->json(), 'id'));
    same(5, $response->getHeader('X-Result-Count'));
    same(false, isset($response->json()['pagination']));
};
$scenarios['legacy-null-protection-and-cache'] = function () {
    // The schema defaults protected to NULL; PHP treats these events as
    // unprotected, and the pre-LIMIT SQL predicate must do the same.
    $data = rows(8, [1, 2, 3, 4], [2]);
    foreach ([4, 6, 7] as $index) { $data[$index]['Event']['protected'] = null; }
    foreach (['fixture-key', false] as $fingerprint) {
        [$server, $sync] = fixture($data, false);
        $sync->controller->Event->CryptographicKey->fingerprint = $fingerprint;
        $expected = $fingerprint ? [2, 5, 6, 7, 8] : [5, 6, 7, 8];
        foreach ([false, true] as $cached) {
            $sync->statuses = [];
            same(array_map(function ($id) { return 'event-' . $id; }, $expected),
                $server->collect($sync));
            same($cached ? [200, 304] : [200, 200], $sync->statuses);
        }
        $response = $sync->controller->respond(['minimal' => 1, 'limit' => 3,
            'page' => 1, 'sort' => 'id', 'direction' => 'asc']);
        same(array_slice($expected, 0, 3), array_column($response->json(), 'id'));
        same(count($expected), $response->getHeader('X-Result-Count'));
    }
};
$scenarios['old-version-protected-mode'] = function () {
    [$server, $sync] = fixture(rows(4, [1, 2, 3], [2]), false);
    CakeRequest::$version = '2.4.155';
    same(['event-4'], $server->collect($sync));
};
$scenarios['cache-missing-304-retry'] = function () {
    [$server, $sync] = fixture(rows(2));
    $sync->force304 = 1;
    same(['event-1', 'event-2'], $server->collect($sync));
    same([304, 200], $sync->statuses);
};
$scenarios['cache-missing-repeated-304-fails'] = function () {
    [$server, $sync] = fixture(rows(2));
    $sync->force304 = 2;
    throws(UnexpectedValueException::class, function () use ($server, $sync) {
        $server->collect($sync);
    });
};
$scenarios['cache-corrupt-record-recovers'] = function () {
    [$server, $sync] = fixture(rows(2));
    same(['event-1', 'event-2'], $server->collect($sync));
    foreach (RedisTool::$redis->values as &$value) { $value = 'broken'; }
    unset($value);
    $sync->statuses = [];
    same(['event-1', 'event-2'], $server->collect($sync));
    same([200], $sync->statuses);
};
$scenarios['cache-request-isolation'] = function () {
    [$server, $sync] = fixture(rows(7));
    $total = null;
    $server->getEventIndexPageFromServer($sync, true,
        ['sync_cursor' => 1, 'limit' => 3, 'cursor' => null], $total);
    $server->getEventIndexPageFromServer($sync, true,
        ['sync_cursor' => 1, 'limit' => 2, 'cursor' => null], $total);
    $server->getEventIndexPageFromServer($sync, true,
        ['page' => 1, 'limit' => 3], $total);
    same(3, count(RedisTool::$redis->values));
};
$scenarios['pagination-malformed-and-nonadvancing'] = function () {
    $page = ['events' => [], 'pagination' => ['version' => 1, 'limit' => 3,
        'after' => 3, 'upper_bound' => 10, 'has_more' => true,
        'next_cursor' => 'cursor']];
    throws(UnexpectedValueException::class, function () use ($page) {
        EventIndexSyncTool::validatePage($page, 3, 10);
    });
    throws(UnexpectedValueException::class, function () use ($page) {
        EventIndexSyncTool::validatePage($page, 0, 11);
    });
    $page['pagination']['has_more'] = 'true';
    throws(UnexpectedValueException::class, function () use ($page) {
        EventIndexSyncTool::validatePage($page, 0);
    });
};
$scenarios['result-count-validation'] = function () {
    same(0, EventIndexSyncTool::resultCount('0'));
    same(12, EventIndexSyncTool::resultCount('12'));
    foreach ([false, null, '-1', '1.2', 'unknown', (string)PHP_INT_MAX . '0'] as $value) {
        same(null, EventIndexSyncTool::resultCount($value));
    }
};
$scenarios['protected-predicate-fails-closed'] = function () {
    $crypto = new FixtureCryptographicKey();
    $conditions = $crypto->eventIndexConditions();
    same(true, strpos($conditions['OR'][1], 'EXISTS (') === 0);
    same('Event', $crypto->db->options['conditions']['CryptographicKey.parent_type']);
    $crypto->fingerprint = false;
    $unprotected = ['OR' => [
        ['Event.protected' => 0], ['Event.protected' => null],
    ]];
    same($unprotected, $crypto->eventIndexConditions());
    $crypto->fail = true;
    same($unprotected, $crypto->eventIndexConditions());
};
$scenarios['capability-absent-and-opt-in-validation'] = function () {
    [$server, $sync] = fixture(rows(2), false);
    same(false, $sync->isSupported(ServerSyncTool::FEATURE_EVENT_INDEX_CURSOR));
    $sync->cursorSupported = true;
    same(true, $sync->isSupported(ServerSyncTool::FEATURE_EVENT_INDEX_CURSOR));
    $sync->controller->userRole['perm_sync'] = false;
    throws(BadRequestException::class, function () use ($sync) {
        $sync->controller->respond(['minimal' => 1, 'sync_cursor' => 1]);
    });
};
$scenarios['response-etag-covers-pagination-and-304'] = function () {
    [$server, $sync] = fixture(rows(4, [1, 2, 3, 4]));
    $_SERVER['HTTP_IF_NONE_MATCH'] = '""';
    $first = $sync->controller->respond(['minimal' => 1, 'sync_cursor' => 1, 'limit' => 3]);
    $firstPage = $first->json();
    same([], $firstPage['events']);
    $_SERVER['HTTP_IF_NONE_MATCH'] = $first->getHeader('etag');
    $samePage = $sync->controller->respond(['minimal' => 1, 'sync_cursor' => 1, 'limit' => 3]);
    same(304, $samePage->code);
    same($first->getHeader('etag'), $samePage->getHeader('etag'));
    $second = $sync->controller->respond(['minimal' => 1, 'sync_cursor' => 1,
        'limit' => 3, 'cursor' => $firstPage['pagination']['next_cursor']]);
    same([], $second->json()['events']);
    same(200, $second->code);
    same(false, $first->getHeader('etag') === $second->getHeader('etag'));
};

$requested = $argv[1] ?? null;
if ($requested === '--list') {
    echo json_encode(array_keys($scenarios)), "\n";
    exit(0);
}
foreach ($scenarios as $name => $scenario) {
    if ($requested !== null && $requested !== $name) { continue; }
    unset($_SERVER['HTTP_IF_NONE_MATCH']);
    $scenario();
    echo 'PASS ', $name, "\n";
}
if ($requested !== null && !isset($scenarios[$requested])) {
    throw new RuntimeException('Unknown scenario: ' . $requested);
}
