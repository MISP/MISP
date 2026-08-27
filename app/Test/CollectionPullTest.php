<?php
/**
 * Collection::pull() unit tests (T3.5 — PRD §9).
 *
 * The pull-side companion to CollectionCaptureTest. captureCollection (the shared
 * sink) is already covered branch-by-branch there; here we cover the pull
 * orchestration that sits on top of it:
 *   - feature-negotiation early-return (skip a peer without the capability);
 *   - the `{uuid: modified}` dedup (missing-locally / strictly-newer-remote /
 *     skip-on-equal — D6) that decides which UUIDs to fetch;
 *   - chunked fetch (array_chunk 100) → RAW passthrough to captureCollection
 *     (no pre-downgrade — the sink owns the downgrade + locked=1);
 *   - buildPullFilterRules OR/NOT → orgc_name shaping.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB — the convention used by every other
 * test under app/Test/ (see CollectionCaptureTest / ServerSyncCollectionNegotiationTest).
 * We stub the framework classes at the top (guarded with class_exists so a
 * full-suite run shares whichever file loaded them first), load the real
 * ServerSyncTool.php + Collection.php, then drive pull() through:
 *   - CollectionPullTestServerSync: a ServerSyncTool subclass that bypasses the
 *     socket-building constructor and returns injected index/fetch/user payloads;
 *   - CollectionPullTestable: a Collection subclass whose find() returns the
 *     injected local rows and whose captureCollection() is replaced by a recorder
 *     (captureCollection's own logic is tested in CollectionCaptureTest), so we
 *     assert exactly which RAW collections reach the sink and with what flags.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

// -------- framework stubs (must exist BEFORE the models load) --------
// Same guarded contracts as CollectionCaptureTest; in a full-suite run whichever
// file loads first wins for everyone, so the contracts must stay compatible.

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

        public static function reset()
        {
            self::$values = array();
        }
    }
}

if (!class_exists('CakeText', false)) {
    class CakeText
    {
        private static $counter = 0;

        public static function uuid()
        {
            self::$counter++;
            return sprintf('00000000-0000-4000-8000-%012d', self::$counter);
        }
    }
}


if (!class_exists('CollectionTestFakeModel', false)) {
    class CollectionTestFakeModel
    {
        public $responses = array();

        public function find($type, $opts = array())
        {
            return empty($this->responses) ? array() : array_shift($this->responses);
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
        public $alias = 'Collection';
        public $id = false;
        public $data = array();
        public $validationErrors = array();

        public function create($data = array())
        {
            $this->id = false;
        }

        public function save($data = null, $validate = true, $fieldList = array())
        {
            return true;
        }

        public function find($type, $options = array())
        {
            return array();
        }
    }
}

require_once __DIR__ . '/../Lib/Tools/ServerSyncTool.php';
require_once __DIR__ . '/../Model/Collection.php';

use PHPUnit\Framework\TestCase;

/** Minimal HttpSocketResponseExtended stand-in: ->json() returns injected data. */
class CollectionPullFakeResponse
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
 * ServerSyncTool with the HTTP layer removed. The constructor is bypassed (no
 * socket); the collection index/fetch calls and the negotiation/context getters
 * return injected values. collectionIndexMinimal/fetchCollections can be told to
 * throw, to exercise pull()'s try/catch return-0 paths.
 */
class CollectionPullTestServerSync extends ServerSyncTool
{
    public $supported = true;
    public $serverData = array('Server' => array('id' => 7, 'name' => 'Peer', 'internal' => 0, 'org_id' => 3, 'pull_rules' => '[]'));
    public $userInfoData = array('Role' => array('perm_sync_internal' => 0));
    public $indexData = array();
    public $fetchMap = array();          // uuid => full collection payload
    public $throwOnIndex = false;
    public $throwOnFetch = false;
    public $fetchCallCount = 0;
    public $fetchedChunks = array();

    public function __construct()
    {
        // Deliberately does not call parent::__construct (which builds an HttpSocket).
    }

    public function isSupported($flag)
    {
        return $this->supported;
    }

    public function server()
    {
        return $this->serverData;
    }

    public function cachedUserInfo()
    {
        return $this->userInfoData;
    }

    public function collectionIndexMinimal(array $rules)
    {
        if ($this->throwOnIndex) {
            throw new Exception('boom-index');
        }
        return new CollectionPullFakeResponse($this->indexData);
    }

    public function fetchCollections(array $uuids)
    {
        $this->fetchCallCount++;
        $this->fetchedChunks[] = $uuids;
        if ($this->throwOnFetch) {
            throw new Exception('boom-fetch');
        }
        $out = array();
        foreach ($uuids as $uuid) {
            if (isset($this->fetchMap[$uuid])) {
                $out[] = $this->fetchMap[$uuid];
            }
        }
        return new CollectionPullFakeResponse($out);
    }
}

/**
 * Collection with the DB + sink replaced. find() returns the injected local rows
 * (the dedup lookup); captureCollection() is a recorder (its real logic lives in
 * CollectionCaptureTest) so we can assert exactly which RAW payloads reach it.
 * jsonDecode/logException are overridden so we do not depend on the AppModel stub
 * providing them (a full-suite run may bind a leaner AppModel stub from a sibling
 * test file).
 */
class CollectionPullTestable extends Collection
{
    public $localRows = array();          // what the dedup find('all') returns
    public $captureCalls = array();       // recorded [user, collection, server, permSyncInternal]
    public $captureResults = null;        // queue of results to return; null ⇒ default success
    public $lastException = null;

    public function find($type, $options = array())
    {
        return $this->localRows;
    }

    public function captureCollection(array $user, array $collection, $server = false, $remotePermSyncInternal = false): array
    {
        $this->captureCalls[] = array(
            'user' => $user,
            'collection' => $collection,
            'server' => $server,
            'permSyncInternal' => $remotePermSyncInternal,
        );
        if (is_array($this->captureResults) && !empty($this->captureResults)) {
            return array_shift($this->captureResults);
        }
        return array('success' => true, 'imported' => 1, 'ignored' => 0, 'failed' => 0, 'errors' => array());
    }

    public function jsonDecode($json)
    {
        return json_decode($json, true);
    }

    public function logException($message, $e, $level = 0)
    {
        $this->lastException = $message;
    }
}

class CollectionPullTest extends TestCase
{
    private $collection;
    private $sync;

    protected function setUp(): void
    {
        Configure::reset();
        ClassRegistry::reset();
        ClassRegistry::$factory = function ($name) { return new CollectionTestFakeModel(); };
        $this->collection = new CollectionPullTestable();
        $this->sync = new CollectionPullTestServerSync();
    }

    private function user()
    {
        return array('id' => 5, 'org_id' => 9, 'Organisation' => array('id' => 9));
    }

    /** A full remote collection payload (shape captureCollection would receive). */
    private function remoteCollection($uuid, $modified, $distribution = 2)
    {
        return array(
            'Collection' => array(
                'uuid' => $uuid,
                'name' => 'Remote ' . $uuid,
                'type' => 'default',
                'description' => 'd',
                'distribution' => $distribution,
                'modified' => $modified,
            ),
        );
    }

    private function localRow($uuid, $modified)
    {
        return array('Collection' => array('uuid' => $uuid, 'modified' => $modified));
    }

    // ---------------- negotiation gate ----------------

    public function testUnsupportedPeerReturnsZeroWithoutAnyFetch(): void
    {
        $this->sync->supported = false;
        $this->sync->indexData = array('a' => '2026-01-01 00:00:00'); // would be fetched if reached

        $result = $this->collection->pull($this->user(), $this->sync);

        $this->assertSame(0, $result);
        $this->assertSame(0, $this->sync->fetchCallCount, 'no index/fetch when the peer lacks the capability');
        $this->assertSame(array(), $this->collection->captureCalls);
    }

    // ---------------- empty / error index ----------------

    public function testEmptyRemoteIndexReturnsZero(): void
    {
        $this->sync->indexData = array();
        $this->assertSame(0, $this->collection->pull($this->user(), $this->sync));
        $this->assertSame(0, $this->sync->fetchCallCount);
    }

    public function testIndexFetchExceptionReturnsZeroAndLogs(): void
    {
        $this->sync->throwOnIndex = true;
        $this->assertSame(0, $this->collection->pull($this->user(), $this->sync));
        $this->assertNotNull($this->collection->lastException, 'index failure is logged, not thrown');
    }

    // ---------------- dedup (D6) ----------------

    public function testMissingLocallyIsFetched(): void
    {
        $this->sync->indexData = array('u-new' => '2026-01-01 00:00:00');
        $this->sync->fetchMap = array('u-new' => $this->remoteCollection('u-new', '2026-01-01 00:00:00'));
        $this->collection->localRows = array(); // nothing local

        $result = $this->collection->pull($this->user(), $this->sync);

        $this->assertSame(1, $result);
        $this->assertSame(array('u-new'), $this->sync->fetchedChunks[0]);
        $this->assertCount(1, $this->collection->captureCalls);
    }

    public function testStrictlyNewerRemoteIsFetched(): void
    {
        $this->sync->indexData = array('u1' => '2026-06-01 00:00:00');
        $this->sync->fetchMap = array('u1' => $this->remoteCollection('u1', '2026-06-01 00:00:00'));
        $this->collection->localRows = array($this->localRow('u1', '2026-01-01 00:00:00'));

        $this->assertSame(1, $this->collection->pull($this->user(), $this->sync));
        $this->assertSame(array('u1'), $this->sync->fetchedChunks[0]);
    }

    public function testEqualModifiedIsSkipped(): void
    {
        $this->sync->indexData = array('u1' => '2026-01-01 00:00:00');
        $this->collection->localRows = array($this->localRow('u1', '2026-01-01 00:00:00'));

        $this->assertSame(0, $this->collection->pull($this->user(), $this->sync), 'skip-on-equal (D6)');
        $this->assertSame(0, $this->sync->fetchCallCount, 'nothing to fetch when equal');
    }

    public function testOlderRemoteIsSkipped(): void
    {
        $this->sync->indexData = array('u1' => '2025-01-01 00:00:00');
        $this->collection->localRows = array($this->localRow('u1', '2026-01-01 00:00:00'));

        $this->assertSame(0, $this->collection->pull($this->user(), $this->sync));
        $this->assertSame(0, $this->sync->fetchCallCount);
    }

    public function testMixedIndexFetchesOnlyMissingAndNewer(): void
    {
        // A: older local ⇒ fetch; B: equal ⇒ skip; C: missing ⇒ fetch; D: newer local ⇒ skip.
        $this->sync->indexData = array(
            'A' => '2026-06-01 00:00:00',
            'B' => '2026-01-01 00:00:00',
            'C' => '2026-01-01 00:00:00',
            'D' => '2020-01-01 00:00:00',
        );
        $this->sync->fetchMap = array(
            'A' => $this->remoteCollection('A', '2026-06-01 00:00:00'),
            'C' => $this->remoteCollection('C', '2026-01-01 00:00:00'),
        );
        $this->collection->localRows = array(
            $this->localRow('A', '2026-01-01 00:00:00'),
            $this->localRow('B', '2026-01-01 00:00:00'),
            $this->localRow('D', '2026-01-01 00:00:00'),
        );

        $result = $this->collection->pull($this->user(), $this->sync);

        $this->assertSame(2, $result);
        $fetched = $this->sync->fetchedChunks[0];
        sort($fetched);
        $this->assertSame(array('A', 'C'), $fetched, 'only missing (C) + strictly-newer (A) are fetched');
    }

    // ---------------- RAW passthrough to the sink ----------------

    public function testRawPayloadAndContextPassedToCapture(): void
    {
        // dist=2 must reach the sink UN-downgraded (the sink owns the downgrade).
        $this->sync->userInfoData = array('Role' => array('perm_sync_internal' => 1));
        $raw = $this->remoteCollection('u1', '2026-01-01 00:00:00', 2);
        $this->sync->indexData = array('u1' => '2026-01-01 00:00:00');
        $this->sync->fetchMap = array('u1' => $raw);
        $this->collection->localRows = array();

        $this->collection->pull($this->user(), $this->sync);

        $call = $this->collection->captureCalls[0];
        $this->assertSame(2, $call['collection']['Collection']['distribution'], 'RAW: pull does NOT pre-downgrade');
        $this->assertSame($raw, $call['collection'], 'the exact remote payload reaches the sink');
        $this->assertSame($this->sync->serverData, $call['server'], 'server context forwarded');
        $this->assertTrue($call['permSyncInternal'], 'remotePermSyncInternal read from cachedUserInfo');
        $this->assertSame(5, $call['user']['id']);
    }

    public function testPermSyncInternalFalseWhenRemoteLacksIt(): void
    {
        $this->sync->userInfoData = array('Role' => array('perm_sync_internal' => 0));
        $this->sync->indexData = array('u1' => '2026-01-01 00:00:00');
        $this->sync->fetchMap = array('u1' => $this->remoteCollection('u1', '2026-01-01 00:00:00'));
        $this->collection->localRows = array();

        $this->collection->pull($this->user(), $this->sync);

        $this->assertFalse($this->collection->captureCalls[0]['permSyncInternal']);
    }

    // ---------------- counting ----------------

    public function testOnlySuccessfulImportsAreCounted(): void
    {
        $this->sync->indexData = array('u1' => '2026-01-01 00:00:00', 'u2' => '2026-01-01 00:00:00');
        $this->sync->fetchMap = array(
            'u1' => $this->remoteCollection('u1', '2026-01-01 00:00:00'),
            'u2' => $this->remoteCollection('u2', '2026-01-01 00:00:00'),
        );
        $this->collection->localRows = array();
        // u1 imports 1; u2 blocked (locked) ⇒ success=false, not counted.
        $this->collection->captureResults = array(
            array('success' => true, 'imported' => 1, 'ignored' => 0, 'failed' => 0, 'errors' => array()),
            array('success' => false, 'imported' => 0, 'ignored' => 0, 'failed' => 1, 'errors' => array('blocked')),
        );

        $this->assertSame(1, $this->collection->pull($this->user(), $this->sync));
        $this->assertCount(2, $this->collection->captureCalls, 'both are attempted');
    }

    public function testFetchExceptionSkipsChunkButContinues(): void
    {
        $this->sync->throwOnFetch = true;
        $this->sync->indexData = array('u1' => '2026-01-01 00:00:00');
        $this->sync->fetchMap = array('u1' => $this->remoteCollection('u1', '2026-01-01 00:00:00'));
        $this->collection->localRows = array();

        $this->assertSame(0, $this->collection->pull($this->user(), $this->sync));
        $this->assertNotNull($this->collection->lastException);
        $this->assertSame(0, count($this->collection->captureCalls), 'a failed chunk captures nothing');
    }

    // ---------------- chunking (array_chunk 100) ----------------

    public function testFetchIsChunkedAt100(): void
    {
        $index = array();
        $fetchMap = array();
        for ($i = 0; $i < 101; $i++) {
            $uuid = sprintf('u%03d', $i);
            $index[$uuid] = '2026-01-01 00:00:00';
            $fetchMap[$uuid] = $this->remoteCollection($uuid, '2026-01-01 00:00:00');
        }
        $this->sync->indexData = $index;
        $this->sync->fetchMap = $fetchMap;
        $this->collection->localRows = array(); // all missing ⇒ all fetched

        $result = $this->collection->pull($this->user(), $this->sync);

        $this->assertSame(101, $result);
        $this->assertSame(2, $this->sync->fetchCallCount, '101 UUIDs ⇒ 2 chunks of ≤100');
        $this->assertCount(100, $this->sync->fetchedChunks[0]);
        $this->assertCount(1, $this->sync->fetchedChunks[1]);
    }

    // ---------------- buildPullFilterRules (orgc_name OR/NOT) ----------------

    private function buildRules(array $server)
    {
        $m = new ReflectionMethod('Collection', 'buildPullFilterRules');
        $m->setAccessible(true);
        return $m->invoke($this->collection, $server);
    }

    public function testBuildPullFilterRulesEmptyWhenNoRules(): void
    {
        $rules = $this->buildRules(array('Server' => array('pull_rules' => '[]')));
        $this->assertSame(array('orgc_name' => array()), $rules);
    }

    public function testBuildPullFilterRulesOrOnly(): void
    {
        $server = array('Server' => array('pull_rules' => json_encode(array('orgs' => array('OR' => array('OrgA', 'OrgB'))))));
        $rules = $this->buildRules($server);
        $this->assertSame(array('OrgA', 'OrgB'), $rules['orgc_name']);
    }

    public function testBuildPullFilterRulesNotPrefixedWithBang(): void
    {
        $server = array('Server' => array('pull_rules' => json_encode(array('orgs' => array('NOT' => array('Evil'))))));
        $rules = $this->buildRules($server);
        $this->assertSame(array('!Evil'), $rules['orgc_name']);
    }

    public function testBuildPullFilterRulesOrAndNotMerged(): void
    {
        $server = array('Server' => array('pull_rules' => json_encode(array(
            'orgs' => array('OR' => array('Good'), 'NOT' => array('Bad')),
        ))));
        $rules = $this->buildRules($server);
        $this->assertSame(array('Good', '!Bad'), $rules['orgc_name']);
    }
}
