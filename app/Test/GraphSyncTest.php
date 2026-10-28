<?php
/**
 * Analyst graph sync: feature negotiation, the indexMinimal opt-in, the
 * receiver's push filter, byte-budgeted pulls, metadata-only push
 * collection and batched push, driven against fake peers that predate graphs
 * or carry them.
 *
 * Pure PHPUnit, no CakePHP bootstrap and no database. The framework classes
 * touched are stubbed below, each guarded so that a full-suite run sharing
 * one process keeps whichever stub loaded first; the test classes override
 * every model method they rely on, so any of those stubs will do.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}

if (!class_exists('Configure', false)) {
    class Configure
    {
        private static $values = array();

        public static function read($key)
        {
            return isset(self::$values[$key]) ? self::$values[$key] : null;
        }

        public static function check($key)
        {
            return isset(self::$values[$key]);
        }

        public static function write($key, $value)
        {
            self::$values[$key] = $value;
        }
    }
}

if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $instances = array();

        public static function init($name)
        {
            if (!isset(self::$instances[$name])) {
                throw new RuntimeException("No fake registered for $name.");
            }
            return self::$instances[$name];
        }
    }
}

if (!function_exists('__')) {
    function __($string)
    {
        $args = func_get_args();
        $format = array_shift($args);
        return empty($args) ? $format : vsprintf($format, $args);
    }
}

if (!class_exists('AppModel', false)) {
    class AppModel
    {
        public $id = false;
        public $data = array();
        public $validationErrors = array();
    }
}

if (!class_exists('JsonTool', false)) {
    require_once __DIR__ . '/../Lib/Tools/JsonTool.php';
}

require_once __DIR__ . '/../Lib/Tools/ServerSyncTool.php';
require_once __DIR__ . '/../Lib/Tools/AnalystGraphDocumentTool.php';
require_once __DIR__ . '/../Model/AnalystData.php';
require_once __DIR__ . '/../Model/Graph.php';

class GraphSyncTestResponse
{
    private $data;

    public function __construct($data)
    {
        $this->data = $data;
    }

    public function json()
    {
        return $this->data;
    }
}

/**
 * A remote peer behind the ServerSyncTool interface. An old peer ignores the
 * `types` opt-in, lists no graphs, and fails on a Graph key in a push filter,
 * as a real one does.
 */
class GraphSyncTestSync extends ServerSyncTool
{
    public $requests = array();
    private $peerInfo;
    private $serverRow;
    private $remote;
    private $old;

    public function __construct(array $info, array $server, array $remote = array())
    {
        $this->peerInfo = $info;
        $this->serverRow = $server;
        $this->remote = $remote + array('index' => array(), 'records' => array());
        $this->old = empty($info['analyst_graph']);
    }

    public function info()
    {
        return $this->peerInfo;
    }

    public function server()
    {
        return $this->serverRow;
    }

    public function serverId()
    {
        return $this->serverRow['Server']['id'];
    }

    public function debug($message)
    {
    }

    public function pullRules()
    {
        return array();
    }

    public function cachedUserInfo()
    {
        return array('Role' => array('perm_sync_internal' => false));
    }

    public function fetchIndexMinimal(array $rules)
    {
        $this->requests[] = array('indexMinimal', $rules);
        $index = $this->remote['index'];
        $asked = $this->old ? null : ($rules['types'] ?? null);
        $types = is_array($asked) ? $asked : AnalystData::ANALYST_DATA_TYPES;
        return new GraphSyncTestResponse(array_intersect_key($index, array_flip($types)));
    }

    public function fetchAnalystData($type, array $uuids)
    {
        $this->requests[] = array('fetch', $type, $uuids);
        $records = array();
        foreach ($uuids as $uuid) {
            $records[] = array($type => $this->remote['records'][$type][$uuid]);
        }
        return new GraphSyncTestResponse($records);
    }

    public function filterAnalystDataForPush(array $candidates)
    {
        $this->requests[] = array('filter', $candidates);
        if ($this->old && isset($candidates['Graph'])) {
            throw new RuntimeException('Undefined index: Graph');
        }
        return new GraphSyncTestResponse($candidates);
    }

    public function pushAnalystData($type, array $analystData)
    {
        $this->requests[] = array('push', $type, $analystData);
        return new GraphSyncTestResponse(array('saved' => true));
    }

    /** @var callable|null fn(array $records) → response body; throws to fail the request */
    public $batchReply;

    public function pushAnalystDataBatch(array $records)
    {
        $this->requests[] = array('batch', $records);
        if ($this->batchReply) {
            return new GraphSyncTestResponse(call_user_func($this->batchReply, $records));
        }
        $results = array();
        foreach ($records as $record) {
            $type = key($record);
            $results[] = array('type' => $type, 'uuid' => $record[$type]['uuid'], 'result' => 'imported', 'errors' => array());
        }
        return new GraphSyncTestResponse(array('results' => $results));
    }

    public function requestsOf($kind)
    {
        return array_values(array_filter($this->requests, function ($request) use ($kind) {
            return $request[0] === $kind;
        }));
    }
}

class GraphSyncTestServer
{
    public function filterAnalystDataForPush(ServerSyncTool $serverSync, array $candidates = array())
    {
        return $serverSync->filterAnalystDataForPush($candidates)->json();
    }
}

class GraphSyncTestModel
{
    public $alias;
    public $rows = array();
    public $finds = array();

    public function __construct($alias, array $rows = array())
    {
        $this->alias = $alias;
        $this->rows = $rows;
    }

    public function find($type, $options = array())
    {
        $this->finds[] = array($type, $options);
        $rows = $this->rows;
        $uuids = $options['conditions']["{$this->alias}.uuid"] ?? $options['conditions']['uuid'] ?? null;
        if ($uuids !== null) {
            $rows = array_values(array_filter($rows, function ($row) use ($uuids) {
                return in_array($row['uuid'], (array)$uuids, true);
            }));
        }
        if ($type === 'list') {
            return array_column($rows, 'modified', 'uuid');
        }
        $alias = $this->alias;
        return array_map(function ($row) use ($alias) {
            return array($alias => $row);
        }, $rows);
    }
}

/**
 * What a push keeps of a graph's module answers, for each server: here,
 * everything, and which server it was asked for.
 */
class GraphSyncTestAnswers
{
    public $servers = array();

    public function documentForServer(array $document, array $server)
    {
        $this->servers[] = $server['Server']['id'];
        return $document;
    }
}

class GraphSyncTestGraph extends Graph
{
    public $alias = 'Graph';
    public $name = 'Graph';
    public $rows = array();
    public $finds = array();
    /** @var callable|null Run once, before the first content read */
    public $beforeContentRead;

    public function __construct(array $rows = array())
    {
        $this->rows = $rows;
    }

    public function schema($field = false)
    {
        return array_fill_keys(array(
            'id', 'uuid', 'object_uuid', 'object_type', 'authors', 'org_uuid',
            'orgc_uuid', 'created', 'modified', 'distribution',
            'sharing_group_id', 'locked', 'name', 'description', 'content',
            'content_size', 'node_count', 'revision', 'forked_from_uuid',
        ), array());
    }

    public function find($type = 'first', $query = array())
    {
        $this->finds[] = array($type, $query);
        if (isset($query['conditions']['Graph.id'])) {
            if ($this->beforeContentRead) {
                $hook = $this->beforeContentRead;
                $this->beforeContentRead = null;
                $hook($this);
            }
            foreach ($this->rows as $row) {
                if ($row['id'] == $query['conditions']['Graph.id']) {
                    return array('Graph' => array(
                        'content' => $row['content'],
                        'modified' => $row['modified'],
                    ));
                }
            }
            return array();
        }
        $result = (new GraphSyncTestModel('Graph', array_values($this->rows)))->find($type, $query);
        if ($type !== 'list' && isset($query['fields'])) {
            $columns = array_map(function ($field) {
                return preg_replace('/^Graph\./', '', $field);
            }, $query['fields']);
            foreach ($result as &$row) {
                $row['Graph'] = array_intersect_key($row['Graph'], array_flip($columns));
            }
        }
        return $result;
    }
}

class GraphSyncTestEvent
{
    public function checkDistributionForPush($object, $server, $context = 'Event')
    {
        return $object[$context]['distribution'] >= 2;
    }
}

class GraphSyncTestSharingGroup
{
    public function find($type, $options = array())
    {
        return array();
    }
}

class GraphSyncTestOrganisation
{
    public function find($type, $options = array())
    {
        return array('Organisation' => array('id' => 5, 'uuid' => 'cccccccc-0000-4000-8000-000000000005'));
    }
}

class GraphSyncTestLog
{
    public $entries = array();

    public function createLogEntry($user, $action, $model, $modelId, $title, $change = null)
    {
        $this->entries[] = compact('action', 'model', 'modelId', 'title', 'change');
    }
}

class GraphSyncTestAnalystData extends AnalystData
{
    public $alias = 'AnalystData';
    public $captured = array();
    /** @var bool Keep exceptions in $exceptions rather than throwing them */
    public $keepExceptions = false;
    public $exceptions = array();
    /** @var array uuid → capture result, or an Exception to throw */
    public $captureReplies = array();
    public $logModel;

    public function __construct()
    {
        $this->Org = new GraphSyncTestOrganisation();
        $this->logModel = new GraphSyncTestLog();
    }

    public function log($message, $type = LOG_ERR, $scope = null)
    {
        return true;
    }

    public function logException($message, Exception $exception, $type = LOG_ERR)
    {
        if (!$this->keepExceptions) {
            throw $exception;
        }
        $this->exceptions[] = $message;
    }

    public function loadLog()
    {
        return $this->logModel;
    }

    public function jsonDecode($json)
    {
        return json_decode($json, true);
    }

    public function captureAnalystData(array $user, array $analystData, $fromPull = false, $orgUUId = false, $server = false, $fromPre30 = null): array
    {
        $this->captured[] = $analystData;
        $record = reset($analystData);
        $reply = $this->captureReplies[$record['uuid'] ?? ''] ?? null;
        if ($reply instanceof Exception) {
            throw $reply;
        }
        return $reply ?: array('success' => true, 'imported' => 1, 'ignored' => 0, 'failed' => 0, 'errors' => array());
    }
}

/** Batches of at most 3 records or 1,000 bytes. */
class GraphSyncTestSmallBatchAnalystData extends GraphSyncTestAnalystData
{
    const PUSH_BATCH_BYTES = 1000,
        PUSH_BATCH_COUNT = 3;
}

class GraphSyncTest extends TestCase
{
    const MB = 1048576;

    private $admin = array(
        'id' => 1,
        'Role' => array('perm_site_admin' => true, 'perm_sync' => true),
        'Organisation' => array('id' => 1, 'uuid' => 'aaaaaaaa-0000-4000-8000-000000000001'),
    );

    private $server = array('Server' => array(
        'id' => 7,
        'name' => 'peer',
        'org_id' => 5,
        'remote_org_id' => 5,
        'internal' => false,
        'push_analyst_data' => true,
        'pull_analyst_data' => true,
        'push_rules' => '[]',
        'pull_rules' => '[]',
    ));

    private $saved = array();

    protected function setUp(): void
    {
        $this->saved = ClassRegistry::$instances;
        ClassRegistry::$instances = array();
    }

    protected function tearDown(): void
    {
        ClassRegistry::$instances = $this->saved;
    }

    private function info($graphs, $batch = false)
    {
        $info = array('version' => '2.5.42', 'perm_sync' => true, 'perm_analyst_data' => true);
        if ($graphs) {
            $info['analyst_graph'] = true;
        }
        if ($batch) {
            $info['analyst_data_batch_push'] = true;
        }
        return $info;
    }

    private function uuid($n)
    {
        return sprintf('%08x-0000-4000-8000-%012x', $n, $n);
    }

    private function graphRow($n, $distribution = 2, array $extra = array())
    {
        return $extra + array(
            'id' => $n,
            'uuid' => $this->uuid($n),
            'object_uuid' => $this->uuid(9000),
            'object_type' => 'Collection',
            'orgc_uuid' => 'aaaaaaaa-0000-4000-8000-000000000001',
            'distribution' => $distribution,
            'sharing_group_id' => null,
            'locked' => false,
            'name' => "graph $n",
            'content' => '{"version":1,"nodes":[{"type":"Event","uuid":"' . $this->uuid(9000) . '"}],"hidden_edges":[],"view":{}}',
            'content_size' => 100,
            'modified' => '2026-10-01 10:00:00',
            'Orgc' => array('uuid' => 'aaaaaaaa-0000-4000-8000-000000000001'),
        );
    }

    private function registerPushFakes(array $notes, array $graphs)
    {
        ClassRegistry::$instances = array(
            'Server' => new GraphSyncTestServer(),
            'SharingGroup' => new GraphSyncTestSharingGroup(),
            'Event' => new GraphSyncTestEvent(),
            'Note' => new GraphSyncTestModel('Note', $notes),
            'Opinion' => new GraphSyncTestModel('Opinion'),
            'Relationship' => new GraphSyncTestModel('Relationship'),
            'Graph' => new GraphSyncTestGraph($graphs),
            'AnalystGraphData' => new GraphSyncTestAnswers(),
        );
    }

    private function noteRow($n, $distribution = 2)
    {
        return array(
            'id' => $n,
            'uuid' => $this->uuid($n),
            'distribution' => $distribution,
            'modified' => '2026-10-01 09:00:00',
            'Orgc' => array('uuid' => 'aaaaaaaa-0000-4000-8000-000000000001'),
        );
    }

    // ---- negotiation --------------------------------------------------------

    public function testFeatureSupportedOnlyWhenAdvertised()
    {
        $new = new GraphSyncTestSync($this->info(true), $this->server);
        $old = new GraphSyncTestSync($this->info(false), $this->server);
        $off = new GraphSyncTestSync($this->info(false) + array('analyst_graph' => false), $this->server);
        $this->assertTrue($new->isSupported(ServerSyncTool::FEATURE_ANALYST_GRAPH));
        $this->assertFalse($old->isSupported(ServerSyncTool::FEATURE_ANALYST_GRAPH));
        $this->assertFalse($off->isSupported(ServerSyncTool::FEATURE_ANALYST_GRAPH));
    }

    // ---- syncTypes ------------------------------------------------------------

    public function testSyncTypesDefaultToTheEmbeddedTypes()
    {
        $this->assertSame(AnalystData::ANALYST_DATA_TYPES, AnalystData::syncTypes(null));
        $this->assertSame(AnalystData::ANALYST_DATA_TYPES, AnalystData::syncTypes('Graph'));
        $this->assertNotContains('Graph', AnalystData::syncTypes(null));
    }

    public function testSyncTypesKeepOnlyKnownNamedTypes()
    {
        $this->assertSame(array('Graph'), AnalystData::syncTypes(array('Graph')));
        $this->assertSame(
            array('Note', 'Graph'),
            AnalystData::syncTypes(array('Graph', 'Widget', array('Note'), 'Note'))
        );
        $this->assertSame(array(), AnalystData::syncTypes(array()));
    }

    // ---- indexMinimal ---------------------------------------------------------

    public function testIndexMinimalListsGraphsWithTheirSizeWhenAsked()
    {
        $graph = new GraphSyncTestGraph(array($this->graphRow(1, 2, array('content_size' => 4321))));
        $note = new GraphSyncTestModel('Note', array($this->noteRow(2)));
        $opinion = new GraphSyncTestModel('Opinion');
        ClassRegistry::$instances = array('Graph' => $graph, 'Note' => $note, 'Opinion' => $opinion);

        $index = (new GraphSyncTestAnalystData())->indexMinimal($this->admin, array(), array('Note', 'Graph'));

        $this->assertSame(array(
            'Note' => array($this->uuid(2) => '2026-10-01 09:00:00'),
            'Graph' => array($this->uuid(1) => array('modified' => '2026-10-01 10:00:00', 'size' => 4321)),
        ), $index);
        $this->assertSame(array('uuid', 'modified', 'locked', 'content_size'), $graph->finds[0][1]['fields']);
        $this->assertSame(array('uuid', 'modified', 'locked'), $note->finds[0][1]['fields']);
        $this->assertEmpty($opinion->finds);
    }

    public function testIndexMinimalLeavesGraphsOutByDefault()
    {
        $graph = new GraphSyncTestGraph(array($this->graphRow(1)));
        ClassRegistry::$instances = array(
            'Graph' => $graph,
            'Note' => new GraphSyncTestModel('Note', array($this->noteRow(2))),
            'Opinion' => new GraphSyncTestModel('Opinion'),
            'Relationship' => new GraphSyncTestModel('Relationship'),
        );

        $index = (new GraphSyncTestAnalystData())->indexMinimal($this->admin);

        $this->assertArrayNotHasKey('Graph', $index);
        $this->assertArrayHasKey('Note', $index);
        $this->assertEmpty($graph->finds);
    }

    // ---- the receiver's push filter ---------------------------------------------

    public function testPushFilterAcceptsGraphsAndSkipsUnknownTypes()
    {
        ClassRegistry::$instances = array(
            'Note' => new GraphSyncTestModel('Note'),
            'Graph' => new GraphSyncTestGraph(array(
                $this->graphRow(2, 2, array('locked' => false)),
                $this->graphRow(3, 2, array('locked' => true, 'modified' => '2026-10-02 00:00:00')),
                $this->graphRow(4, 2, array('locked' => true, 'modified' => '2026-09-01 00:00:00')),
            )),
        );
        $incoming = array(
            'Note' => array($this->uuid(10) => '2026-10-01 10:00:00'),
            'Graph' => array(
                $this->uuid(1) => '2026-10-01 10:00:00',
                $this->uuid(2) => '2026-10-01 10:00:00',
                $this->uuid(3) => '2026-10-01 10:00:00',
                $this->uuid(4) => '2026-10-01 10:00:00',
            ),
            'Widget' => array($this->uuid(20) => '2026-10-01 10:00:00'),
        );

        $accepted = (new GraphSyncTestAnalystData())->filterAnalystDataForPush($incoming);

        $this->assertSame(
            array($this->uuid(1), $this->uuid(4)),
            array_keys($accepted['Graph']),
            'new and older-here graphs are accepted; a local original or a newer copy is not'
        );
        $this->assertSame(array($this->uuid(10)), array_keys($accepted['Note']));
        $this->assertSame(array(), $accepted['Opinion']);
        $this->assertSame(array(), $accepted['Relationship']);
        $this->assertArrayNotHasKey('Widget', $accepted);
        $this->assertArrayNotHasKey('Widget', ClassRegistry::$instances);
    }

    // ---- pull ------------------------------------------------------------------

    public function testReadRemoteIndexReadsBothShapesAndOnlyKnownTypes()
    {
        $index = AnalystData::readRemoteIndex(array(
            'Note' => array($this->uuid(1) => '2026-10-01 10:00:00'),
            'Graph' => array(
                $this->uuid(2) => array('modified' => '2026-10-01 10:00:00', 'size' => 2048),
                $this->uuid(3) => '2026-10-01 10:00:00',
                $this->uuid(4) => array('modified' => '2026-10-01 10:00:00', 'size' => -5),
                $this->uuid(5) => array('modified' => '2026-10-01 10:00:00', 'size' => 'big'),
                $this->uuid(6) => array('size' => 10),
            ),
            'Widget' => array($this->uuid(7) => '2026-10-01 10:00:00'),
        ));

        $this->assertSame(array('Note', 'Graph'), array_keys($index));
        $this->assertSame(array('modified' => '2026-10-01 10:00:00', 'size' => null), $index['Note'][$this->uuid(1)]);
        $this->assertSame(2048, $index['Graph'][$this->uuid(2)]['size']);
        $this->assertNull($index['Graph'][$this->uuid(3)]['size']);
        $this->assertNull($index['Graph'][$this->uuid(4)]['size']);
        $this->assertNull($index['Graph'][$this->uuid(5)]['size']);
        $this->assertArrayNotHasKey($this->uuid(6), $index['Graph'], 'an entry without modified is skipped');
    }

    public function testPlanPullFetchesMissingAndNewerOnly()
    {
        $remote = array('Graph' => array(
            $this->uuid(1) => array('modified' => '2026-10-01 10:00:00', 'size' => 10),
            $this->uuid(2) => array('modified' => '2026-10-01 10:00:00', 'size' => 20),
            $this->uuid(3) => array('modified' => '2026-10-01 10:00:00', 'size' => 30),
            $this->uuid(4) => array('modified' => '2026-10-01 10:00:00', 'size' => null),
        ));
        $local = array('Graph' => array(
            $this->uuid(2) => '2026-09-30 10:00:00',
            $this->uuid(3) => '2026-10-01 10:00:00',
        ));

        $this->assertSame(
            array('Graph' => array($this->uuid(1) => 10, $this->uuid(2) => 20, $this->uuid(4) => null)),
            AnalystData::planPull($remote, $local)
        );
    }

    public function testSizedBatchesCapCountAndBytes()
    {
        $sizes = array();
        for ($i = 0; $i < 250; $i++) {
            $sizes["k$i"] = 10;
        }
        $batches = AnalystData::sizedBatches($sizes, 8 * self::MB, 100);
        $this->assertSame(array(100, 100, 50), array_map('count', $batches));

        $batches = AnalystData::sizedBatches(
            array('a' => 3 * self::MB, 'b' => 3 * self::MB, 'c' => 2 * self::MB, 'd' => 1),
            8 * self::MB,
            100
        );
        $this->assertSame(array(array('a', 'b', 'c'), array('d')), $batches, 'exactly the budget fits');
    }

    public function testSizedBatchesGiveOversizedAndUnknownTheirOwn()
    {
        $batches = AnalystData::sizedBatches(
            array('a' => 5 * self::MB, 'b' => 4 * self::MB, 'big' => 20 * self::MB, 'unknown' => null, 'c' => 1),
            8 * self::MB,
            100
        );
        $this->assertSame(array(array('a'), array('big'), array('unknown'), array('b', 'c')), $batches);
    }

    public function testPullFetchesGraphsInByteBudgetedBatches()
    {
        $index = array('Note' => array(), 'Graph' => array());
        $records = array('Note' => array(), 'Graph' => array());
        $sizes = array(1 => 5 * self::MB, 2 => 4 * self::MB, 3 => 20 * self::MB);
        for ($n = 1; $n <= 153; $n++) {
            $uuid = $this->uuid($n);
            $index['Graph'][$uuid] = array('modified' => '2026-10-01 10:00:00', 'size' => $sizes[$n] ?? 1024);
            $records['Graph'][$uuid] = $this->graphRow($n, $n % 2 ? 2 : 1);
        }
        $index['Graph'][$this->uuid(4)] = '2026-10-01 10:00:00';
        for ($n = 1001; $n <= 1150; $n++) {
            $index['Note'][$this->uuid($n)] = '2026-10-01 10:00:00';
            $records['Note'][$this->uuid($n)] = $this->noteRow($n);
        }
        $local = array($this->graphRow(153, 2, array('modified' => '2026-10-01 10:00:00')));
        ClassRegistry::$instances = array(
            'Server' => new GraphSyncTestServer(),
            'Note' => new GraphSyncTestModel('Note'),
            'Opinion' => new GraphSyncTestModel('Opinion'),
            'Relationship' => new GraphSyncTestModel('Relationship'),
            'Graph' => new GraphSyncTestGraph($local),
        );
        $sync = new GraphSyncTestSync($this->info(true), $this->server, compact('index', 'records'));
        $analystData = new GraphSyncTestAnalystData();

        $pulled = $analystData->pull($this->admin, $sync);

        $this->assertSame(AnalystData::TYPES, $sync->requestsOf('indexMinimal')[0][1]['types']);
        $graphFetches = array_map(function ($request) {
            return count($request[2]);
        }, array_values(array_filter($sync->requestsOf('fetch'), function ($request) {
            return $request[1] === 'Graph';
        })));
        // 5 MB alone (4 MB would overflow it), 20 MB and the unknown size alone,
        // then 4 MB + 99 small, then the remaining 49 small; graph 153 is current
        $this->assertSame(array(1, 1, 1, 100, 49), $graphFetches);
        $noteFetches = array_values(array_filter($sync->requestsOf('fetch'), function ($request) {
            return $request[1] === 'Note';
        }));
        $this->assertSame(array(100, 50), array_map(function ($request) {
            return count($request[2]);
        }, $noteFetches));
        $this->assertSame(152 + 150, $pulled);

        $graphs = array_values(array_filter($analystData->captured, function ($record) {
            return isset($record['Graph']);
        }));
        $byUuid = array_column(array_column($graphs, 'Graph'), null, 'uuid');
        $this->assertTrue($byUuid[$this->uuid(1)]['locked']);
        $this->assertSame('1', $byUuid[$this->uuid(1)]['distribution'], 'connected communities arrive as community');
        $this->assertSame('0', $byUuid[$this->uuid(2)]['distribution'], 'community arrives as organisation only');
        $this->assertArrayNotHasKey($this->uuid(153), $byUuid);
    }

    public function testPullFromAnOldPeerFetchesNoGraphs()
    {
        $index = array(
            'Note' => array($this->uuid(1001) => '2026-10-01 10:00:00'),
            'Graph' => array($this->uuid(1) => array('modified' => '2026-10-01 10:00:00', 'size' => 10)),
        );
        $records = array('Note' => array($this->uuid(1001) => $this->noteRow(1001)));
        ClassRegistry::$instances = array(
            'Server' => new GraphSyncTestServer(),
            'Note' => new GraphSyncTestModel('Note'),
            'Opinion' => new GraphSyncTestModel('Opinion'),
            'Relationship' => new GraphSyncTestModel('Relationship'),
            'Graph' => new GraphSyncTestGraph(),
        );
        $sync = new GraphSyncTestSync($this->info(false), $this->server, compact('index', 'records'));

        $pulled = (new GraphSyncTestAnalystData())->pull($this->admin, $sync);

        $this->assertSame(1, $pulled);
        $this->assertSame(array('Note'), array_unique(array_map(function ($request) {
            return $request[1];
        }, $sync->requestsOf('fetch'))));
    }

    // ---- push ------------------------------------------------------------------

    public function testMetadataFieldsLeaveTheDocumentOut()
    {
        $fields = (new GraphSyncTestGraph())->metadataFields();
        $this->assertNotContains('Graph.content', $fields);
        $this->assertContains('Graph.content_size', $fields);
        $this->assertContains('Graph.modified', $fields);
        $this->assertSame(18, count($fields));
    }

    public function testPushToAnOldPeerLeavesGraphsOut()
    {
        $this->registerPushFakes(array($this->noteRow(1001)), array($this->graphRow(1)));
        $sync = new GraphSyncTestSync($this->info(false), $this->server);

        $pushed = (new GraphSyncTestAnalystData())->push($this->admin, $sync);

        $this->assertCount(1, $pushed);
        $filter = $sync->requestsOf('filter')[0][1];
        $this->assertArrayNotHasKey('Graph', $filter);
        $this->assertSame(array($this->uuid(1001)), array_keys($filter['Note']));
        $this->assertSame(array('Note'), array_column($sync->requestsOf('push'), 1));
        $this->assertEmpty(ClassRegistry::$instances['Graph']->finds, 'graphs are not even read');
    }

    public function testPushCollectsGraphMetadataAndReadsContentAtUpload()
    {
        $this->registerPushFakes(
            array($this->noteRow(1001)),
            array($this->graphRow(1, 2), $this->graphRow(2, 2), $this->graphRow(3, 1))
        );
        $graph = ClassRegistry::$instances['Graph'];
        $graph->beforeContentRead = function ($graph) {
            // Graph 2 is saved again between collection and upload
            $graph->rows[1]['modified'] = '2026-10-01 11:00:00';
            $graph->rows[1]['content'] = '{"version":1,"nodes":[],"hidden_edges":[],"view":{}}';
        };
        $sync = new GraphSyncTestSync($this->info(true), $this->server);
        $analystData = new GraphSyncTestAnalystData();

        $pushed = $analystData->push($this->admin, $sync);

        $collect = $graph->finds[0][1];
        $this->assertNotContains('Graph.content', $collect['fields']);
        $filter = $sync->requestsOf('filter')[0][1];
        $this->assertSame(
            array($this->uuid(1) => '2026-10-01 10:00:00', $this->uuid(2) => '2026-10-01 10:00:00'),
            $filter['Graph'],
            'community-only graph 3 is not offered'
        );

        $uploads = array_column(array_filter($sync->requestsOf('push'), function ($request) {
            return $request[1] === 'Graph';
        }), 2);
        $this->assertCount(2, $uploads);
        $this->assertSame(
            array($this->server['Server']['id'], $this->server['Server']['id']),
            ClassRegistry::$instances['AnalystGraphData']->servers,
            'each graph keeps the module answers that server may receive'
        );
        $first = $uploads[0]['Graph'];
        $this->assertSame($this->uuid(9000), $first['content']['nodes'][0]['uuid']);
        $this->assertTrue($first['locked']);
        $this->assertSame(1, $first['distribution'], 'connected communities go out as community');
        $this->assertArrayNotHasKey('id', $first);
        $second = $uploads[1]['Graph'];
        $this->assertSame(array(), $second['content']['nodes']);
        $this->assertSame('2026-10-01 11:00:00', $second['modified'], 'modified matches the content sent');
        $this->assertCount(3, $pushed);
    }

    public function testPushSkipsAGraphDeletedBeforeUpload()
    {
        $this->registerPushFakes(array(), array($this->graphRow(1), $this->graphRow(2)));
        $graph = ClassRegistry::$instances['Graph'];
        $sync = new GraphSyncTestSync($this->info(true), $this->server);
        $analystData = new GraphSyncTestAnalystData();

        $collected = $analystData->collectDataForPush($this->server, array('Graph'));
        unset($graph->rows[0]);
        $results = array();
        foreach ($collected['Graph'] as $entry) {
            $results[] = $analystData->uploadEntryToServer('Graph', $entry, $this->server, $sync, $this->admin);
        }

        $this->assertNotSame('Success', $results[0]);
        $this->assertSame('Success', $results[1]);
        $this->assertCount(1, $sync->requestsOf('push'));
    }

    // ---- batched push ------------------------------------------------------------

    private function notes($from, $count)
    {
        $notes = array();
        for ($n = $from; $n < $from + $count; $n++) {
            $notes[] = $this->noteRow($n);
        }
        return $notes;
    }

    public function testBatchFeatureSupportedOnlyWhenAdvertised()
    {
        $batch = new GraphSyncTestSync($this->info(true, true), $this->server);
        $plain = new GraphSyncTestSync($this->info(true), $this->server);
        $this->assertTrue($batch->isSupported(ServerSyncTool::FEATURE_ANALYST_DATA_BATCH));
        $this->assertFalse($plain->isSupported(ServerSyncTool::FEATURE_ANALYST_DATA_BATCH));
    }

    public function testPushToAPeerWithoutBatchesSendsOneRecordPerRequest()
    {
        $this->registerPushFakes($this->notes(1001, 3), array());
        $sync = new GraphSyncTestSync($this->info(true), $this->server);

        $pushed = (new GraphSyncTestAnalystData())->push($this->admin, $sync);

        $this->assertCount(3, $pushed);
        $this->assertCount(3, $sync->requestsOf('push'));
        $this->assertEmpty($sync->requestsOf('batch'));
    }

    public function testPushToABatchPeerSendsUpToTheRecordCap()
    {
        $this->registerPushFakes(
            $this->notes(1001, 150),
            array($this->graphRow(1, 2), $this->graphRow(2, 3), $this->graphRow(3, 1))
        );
        $sync = new GraphSyncTestSync($this->info(true, true), $this->server);

        $pushed = (new GraphSyncTestAnalystData())->push($this->admin, $sync);

        $this->assertEmpty($sync->requestsOf('push'));
        $batches = $sync->requestsOf('batch');
        $this->assertSame(array(100, 52), array_map(function ($request) {
            return count($request[1]);
        }, $batches), 'notes and graphs share batches; community-only graph 3 is not offered');
        $last = $batches[1][1];
        $graph = $last[50]['Graph'];
        $this->assertSame($this->uuid(1), $graph['uuid']);
        $this->assertSame($this->uuid(9000), $graph['content']['nodes'][0]['uuid'], 'a graph goes out with its document');
        $this->assertTrue($graph['locked']);
        $this->assertSame(1, $graph['distribution']);
        $this->assertArrayNotHasKey('id', $graph);
        $this->assertSame($this->uuid(1001), $batches[0][1][0]['Note']['uuid']);
        $this->assertCount(152, $pushed);
    }

    public function testBatchesRespectTheByteBudgetAndAnOversizedRecordGoesAlone()
    {
        $huge = '{"version":1,"nodes":[],"hidden_edges":["' . str_repeat('y', 1500) . '"],"view":{}}';
        $this->registerPushFakes($this->notes(1001, 5), array(
            $this->graphRow(1, 2),
            $this->graphRow(2, 2, array('content' => $huge)),
            $this->graphRow(3, 2),
            $this->graphRow(4, 2),
        ));
        $sync = new GraphSyncTestSync($this->info(true, true), $this->server);

        $pushed = (new GraphSyncTestSmallBatchAnalystData())->push($this->admin, $sync);

        $batches = array_column($sync->requestsOf('batch'), 1);
        $size = function (array $record) {
            return strlen(JsonTool::encode($record));
        };
        $bytes = function (array $batch) use ($size) {
            return array_sum(array_map($size, $batch));
        };
        $sent = array();
        foreach ($batches as $i => $batch) {
            $this->assertLessThanOrEqual(3, count($batch));
            if (count($batch) > 1) {
                $this->assertLessThanOrEqual(1000, $bytes($batch), "batch $i is over the byte budget");
            }
            if (isset($batches[$i + 1])) {
                $this->assertTrue(
                    count($batch) === 3 || $bytes($batch) + $size($batches[$i + 1][0]) > 1000,
                    "batch $i could have taken the next record"
                );
            }
            foreach ($batch as $record) {
                $type = key($record);
                $sent[] = $record[$type]['uuid'];
                if ($type === 'Graph' && $record['Graph']['uuid'] === $this->uuid(2)) {
                    $this->assertCount(1, $batch, 'the oversized graph goes alone');
                    $this->assertGreaterThan(1000, $size($record));
                }
            }
        }
        $this->assertContains(2, array_map('count', $batches), 'small records do share a batch');
        $this->assertCount(9, $sent);
        $this->assertCount(9, array_unique($sent));
        $this->assertCount(9, $pushed);
    }

    public function testBatchesRespectTheRecordCap()
    {
        $this->registerPushFakes($this->notes(1001, 7), array());
        $sync = new GraphSyncTestSync($this->info(true, true), $this->server);

        (new GraphSyncTestSmallBatchAnalystData())->push($this->admin, $sync);

        $this->assertSame(array(3, 3, 1), array_map(function ($request) {
            return count($request[1]);
        }, $sync->requestsOf('batch')));
    }

    public function testABatchReportCountsImportsAndLogsWhatFailed()
    {
        $this->registerPushFakes($this->notes(1001, 4), array());
        $sync = new GraphSyncTestSync($this->info(true, true), $this->server);
        $uuid = function ($n) {
            return $this->uuid($n);
        };
        $sync->batchReply = function (array $records) use ($uuid) {
            return array('imported' => 1, 'ignored' => 1, 'failed' => 1, 'results' => array(
                array('type' => 'Note', 'uuid' => strtoupper($uuid(1001)), 'result' => 'imported', 'errors' => array()),
                array('type' => 'Note', 'uuid' => $uuid(1002), 'result' => 'ignored', 'errors' => array('not newer')),
                array('type' => 'Note', 'uuid' => $uuid(1003), 'result' => 'failed', 'errors' => array('Blocked an edit')),
                array('type' => 'Note', 'uuid' => $uuid(9999), 'result' => 'imported', 'errors' => array()),
            ));
        };
        $analystData = new GraphSyncTestAnalystData();

        $pushed = $analystData->push($this->admin, $sync);

        $this->assertSame(array('AnalystData ' . $this->uuid(1001)), $pushed);
        $logged = $analystData->logModel->entries;
        $this->assertSame(array(1003, 1004), array_column($logged, 'modelId'), 'the refusal and the record reported under another uuid');
        $this->assertSame('Blocked an edit', $logged[0]['change']);
        $this->assertSame('push', $logged[0]['action']);
    }

    public function testAFailedBatchRequestIsSentAgainOneRecordAtATime()
    {
        $this->registerPushFakes($this->notes(1001, 2), array($this->graphRow(1, 2)));
        $sync = new GraphSyncTestSync($this->info(true, true), $this->server);
        $sync->batchReply = function () {
            throw new RuntimeException('413 Request Entity Too Large');
        };
        $analystData = new GraphSyncTestAnalystData();
        $analystData->keepExceptions = true;

        $pushed = $analystData->push($this->admin, $sync);

        $this->assertCount(1, $sync->requestsOf('batch'));
        $singles = $sync->requestsOf('push');
        $this->assertSame(array('Note', 'Note', 'Graph'), array_column($singles, 1));
        $this->assertSame($this->uuid(9000), $singles[2][2]['Graph']['content']['nodes'][0]['uuid']);
        $this->assertTrue($singles[2][2]['Graph']['locked'], 'the prepared record is sent, not prepared again');
        $this->assertCount(3, $pushed);
        $this->assertCount(1, $analystData->exceptions);
        $finds = array_filter(ClassRegistry::$instances['Graph']->finds, function ($find) {
            return isset($find[1]['conditions']['Graph.id']);
        });
        $this->assertCount(1, $finds, 'the content is read once');
    }

    public function testABatchToAPeerWithoutThePermissionSendsNothing()
    {
        $this->registerPushFakes($this->notes(1001, 2), array());
        $info = $this->info(true, true);
        $info['perm_analyst_data'] = false;
        $sync = new GraphSyncTestSync($info, $this->server);

        $pushed = (new GraphSyncTestAnalystData())->push($this->admin, $sync);

        $this->assertSame(array(), $pushed);
        $this->assertEmpty($sync->requestsOf('batch'));
        $this->assertEmpty($sync->requestsOf('push'));
    }

    // ---- the receiver's batch ------------------------------------------------------

    public function testCaptureBatchReportsEachRecordInOrder()
    {
        $analystData = new GraphSyncTestAnalystData();
        $analystData->keepExceptions = true;
        $analystData->captureReplies = array(
            $this->uuid(2) => array('success' => false, 'imported' => 0, 'ignored' => 1, 'failed' => 0, 'errors' => array('not newer')),
            $this->uuid(3) => array('success' => false, 'imported' => 0, 'ignored' => 0, 'failed' => 1, 'errors' => array('invalid document')),
            $this->uuid(4) => new RuntimeException('SQLSTATE[HY000]: secret detail'),
        );

        $report = $analystData->captureBatch($this->admin, array(
            array('Note' => array('uuid' => $this->uuid(1))),
            array('Graph' => array('uuid' => $this->uuid(2))),
            array('Graph' => array('uuid' => $this->uuid(3)), 'Widget' => array()),
            array('Opinion' => array('uuid' => $this->uuid(4))),
            array('Widget' => array('uuid' => $this->uuid(5))),
            'not a record',
            array('Relationship' => array('uuid' => $this->uuid(7))),
        ));

        $this->assertSame(array('imported' => 2, 'ignored' => 1, 'failed' => 4), array_intersect_key($report, array_flip(array('imported', 'ignored', 'failed'))));
        $this->assertSame(
            array('imported', 'ignored', 'failed', 'failed', 'failed', 'failed', 'imported'),
            array_column($report['results'], 'result')
        );
        $this->assertSame(array('Note', 'Graph', 'Graph', 'Opinion', null, null, 'Relationship'), array_column($report['results'], 'type'));
        $this->assertSame($this->uuid(2), $report['results'][1]['uuid']);
        $this->assertSame(array('invalid document'), $report['results'][2]['errors']);
        $this->assertSame(array('The record could not be captured.'), $report['results'][3]['errors'], 'an exception is not echoed to the peer');
        $this->assertCount(1, $analystData->exceptions);
        $this->assertSame(array('Graph' => array('uuid' => $this->uuid(3))), $analystData->captured[2], 'only the record\'s own type is captured');
        $this->assertCount(5, $analystData->captured, 'the malformed ones never reach capture');
    }
}
