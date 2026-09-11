<?php
/**
 * Collection::push() chain unit tests (T4.5 — PRD §9).
 *
 * The push-side companion to CollectionPullTest / CollectionCaptureTest. Covers
 * the push orchestration and its helpers:
 *   - push(): negotiation early-return; empty-collect / empty-wanted -> 0; the
 *     {uuid: modified} candidate -> remote filter -> per-wanted upload loop; the
 *     ['response'] unwrap; the Success count;
 *   - filterCollectionsForPush(): the RECEIVE-side dedup (missing / locked=1+newer
 *     wanted; locked=0 authoritative-local and equal/older dropped — D6);
 *   - isPushableForServerSyncRules(): orgc OR/NOT push-rules;
 *   - prepareForPushToServer(): id strip, NO downgrade (RAW passthrough — the
 *     remote sink owns it), dist=4 SG-membership 403, checkDistributionForPush 403;
 *   - collectDataForPush(): post-find filtering (checkDistributionForPush +
 *     push-rules) and the Orgc/SharingGroup/CollectionElement corpus nesting.
 *     (The SQL-level dist eligibility lives in the find() WHERE and is exercised
 *     live at T4.4/T6.1, not here — the find() is stubbed with injected rows.)
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB (convention: see CollectionCaptureTest /
 * CollectionPullTest). Framework classes are stubbed at the top (guarded), the real
 * ServerSyncTool.php + Collection.php are loaded, and push() is driven through a
 * ServerSyncTool subclass (socket-less) + a Collection subclass whose DB/HTTP
 * touch-points are injected. Unique class names avoid full-suite stub collisions.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

// -------- framework stubs (guarded; shared contracts across the app/Test files) --------

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
class CollectionPushFakeResponse
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
 * ServerSyncTool with the HTTP layer removed. isSupported() is answered from an
 * injected per-flag map (defaults to supported), and the two push endpoints
 * (filterCollectionsForPush / pushCollection) return injected payloads or throw.
 */
class CollectionPushTestServerSync extends ServerSyncTool
{
    public $supportedFlags = array();      // flag => bool; missing ⇒ true
    public $serverData = array('Server' => array('id' => 7, 'name' => 'Peer'));
    public $wanted = array();              // filterCollectionsForPush reply
    public $throwOnFilter = false;
    public $pushedCollections = array();   // recorded pushCollection() payloads

    public function __construct()
    {
        // No parent::__construct — do not build an HttpSocket.
    }

    public function isSupported($flag)
    {
        return array_key_exists($flag, $this->supportedFlags) ? $this->supportedFlags[$flag] : true;
    }

    public function server()
    {
        return $this->serverData;
    }

    public function serverId()
    {
        return $this->serverData['Server']['id'];
    }

    public function filterCollectionsForPush(array $candidates)
    {
        if ($this->throwOnFilter) {
            throw new Exception('boom-filter');
        }
        return new CollectionPushFakeResponse($this->wanted);
    }

    public function pushCollection(array $collection)
    {
        $this->pushedCollections[] = $collection;
        return new CollectionPushFakeResponse(array('saved' => true));
    }
}

/** Event double: checkDistributionForPush returns an injected (optionally per-uuid) verdict. */
class CollectionPushFakeEvent
{
    public $checkResult = true;
    public $checkByUuid = array();     // collection uuid => bool override
    public $checkCalls = array();

    public function checkDistributionForPush($object, $server, $context = 'Event')
    {
        $uuid = isset($object['Collection']['uuid']) ? $object['Collection']['uuid'] : null;
        $this->checkCalls[] = $uuid;
        if ($uuid !== null && array_key_exists($uuid, $this->checkByUuid)) {
            return $this->checkByUuid[$uuid];
        }
        return $this->checkResult;
    }
}

/** SharingGroup double: find('all') feeds collectValidSharingGroupIDs; find('first') the enrichment. */
class CollectionPushFakeSharingGroup
{
    public $allResult = array();
    public $firstResult = null;
    public $serverInSg = false;

    public function find($type, $opts = array())
    {
        return $type === 'first' ? $this->firstResult : $this->allResult;
    }

    public function checkIfServerInSG($sg, $server)
    {
        return $this->serverInSg;
    }
}

/**
 * Collection with DB + HTTP touch-points injected. find() returns $findAllResult
 * (the collectDataForPush corpus query OR the filterCollectionsForPush local
 * lookup — a given test drives only one). collectDataForPush and
 * uploadCollectionToServer fall back to the REAL implementation unless an injected
 * override is set, so the same subclass serves both the orchestration tests (which
 * stub them) and the direct helper tests (which exercise them).
 */
class CollectionPushTestable extends Collection
{
    public $findAllResult = array();
    public $collectDataForPushReturn = null;   // null ⇒ run the real method
    public $uploadResults = null;              // queue of return strings; null ⇒ real method
    public $uploadCalls = array();
    public $lastException = null;

    public function find($type, $options = array())
    {
        return $this->findAllResult;
    }

    public function collectDataForPush(array $server): array
    {
        if ($this->collectDataForPushReturn !== null) {
            return $this->collectDataForPushReturn;
        }
        return parent::collectDataForPush($server);
    }

    public function uploadCollectionToServer(array $collection, array $server, ServerSyncTool $serverSync, array $user)
    {
        if ($this->uploadResults !== null) {
            $this->uploadCalls[] = $collection;
            return empty($this->uploadResults) ? 'Success' : array_shift($this->uploadResults);
        }
        return parent::uploadCollectionToServer($collection, $server, $serverSync, $user);
    }

    public function jsonDecode($json)
    {
        return json_decode($json, true);
    }

    public function logException($message, $e, $level = 0)
    {
        $this->lastException = $message;
    }

    public function loadLog()
    {
        return new CollectionPushFakeLog();
    }
}

class CollectionPushFakeLog
{
    public function createLogEntry($user, $action, $model, $id, $title, $change = '')
    {
    }
}

class CollectionPushTest extends TestCase
{
    private $collection;
    private $sync;

    protected function setUp(): void
    {
        Configure::reset();
        ClassRegistry::reset();
        ClassRegistry::$factory = function ($name) { return new CollectionTestFakeModel(); };
        $this->collection = new CollectionPushTestable();
        $this->sync = new CollectionPushTestServerSync();
    }

    private function user()
    {
        return array('id' => 5, 'org_id' => 9, 'Organisation' => array('id' => 9, 'name' => 'Local'));
    }

    private function nested($uuid, $modified, $overrides = array())
    {
        return array('Collection' => array_merge(array(
            'id' => 111,
            'uuid' => $uuid,
            'name' => 'C ' . $uuid,
            'distribution' => 2,
            'modified' => $modified,
            'Orgc' => array('uuid' => 'orgc-uuid'),
            'CollectionElement' => array(),
        ), $overrides));
    }

    // ============ push() orchestration ============

    public function testPushUnsupportedPeerReturnsZero(): void
    {
        $this->sync->supportedFlags = array(ServerSyncTool::FEATURE_COLLECTION_SYNC => false);
        $this->collection->collectDataForPushReturn = array($this->nested('u1', '2026-01-01 00:00:00'));

        $this->assertSame(0, $this->collection->push($this->user(), $this->sync));
        $this->assertSame(array(), $this->collection->uploadCalls);
    }

    public function testPushNothingEligibleReturnsZero(): void
    {
        $this->collection->collectDataForPushReturn = array();
        $this->assertSame(0, $this->collection->push($this->user(), $this->sync));
    }

    public function testPushRemoteWantsNothingReturnsZero(): void
    {
        $this->collection->collectDataForPushReturn = array($this->nested('u1', '2026-01-01 00:00:00'));
        $this->sync->wanted = array();                 // remote already has it (D6 drop)
        $this->collection->uploadResults = array();    // record uploads, default Success

        $this->assertSame(0, $this->collection->push($this->user(), $this->sync));
        $this->assertSame(array(), $this->collection->uploadCalls, 'no upload when remote wants nothing');
    }

    public function testPushUploadsOnlyWantedSubset(): void
    {
        $this->collection->collectDataForPushReturn = array(
            $this->nested('u1', '2026-01-01 00:00:00'),
            $this->nested('u2', '2026-01-01 00:00:00'),
            $this->nested('u3', '2026-01-01 00:00:00'),
        );
        $this->sync->wanted = array('u1' => '2026-01-01 00:00:00', 'u3' => '2026-01-01 00:00:00');
        $this->collection->uploadResults = array('Success', 'Success');

        $this->assertSame(2, $this->collection->push($this->user(), $this->sync));
        $uploaded = array_map(function ($c) {
            return $c['Collection']['uuid'];
        }, $this->collection->uploadCalls);
        $this->assertSame(array('u1', 'u3'), $uploaded, 'u2 not wanted ⇒ not uploaded');
    }

    public function testPushUnwrapsResponseKey(): void
    {
        // ServerSyncTool sometimes returns the reply nested under 'response'.
        $this->collection->collectDataForPushReturn = array($this->nested('u1', '2026-01-01 00:00:00'));
        $this->sync->wanted = array('response' => array('u1' => '2026-01-01 00:00:00'));
        $this->collection->uploadResults = array('Success');

        $this->assertSame(1, $this->collection->push($this->user(), $this->sync));
    }

    public function testPushCountsOnlySuccessfulUploads(): void
    {
        $this->collection->collectDataForPushReturn = array(
            $this->nested('u1', '2026-01-01 00:00:00'),
            $this->nested('u2', '2026-01-01 00:00:00'),
        );
        $this->sync->wanted = array('u1' => '2026-01-01 00:00:00', 'u2' => '2026-01-01 00:00:00');
        $this->collection->uploadResults = array('Success', '403');   // u2 blocked

        $this->assertSame(1, $this->collection->push($this->user(), $this->sync));
    }

    public function testPushFilterExceptionReturnsZero(): void
    {
        $this->collection->collectDataForPushReturn = array($this->nested('u1', '2026-01-01 00:00:00'));
        $this->sync->throwOnFilter = true;
        $this->collection->uploadResults = array();

        $this->assertSame(0, $this->collection->push($this->user(), $this->sync));
        $this->assertNotNull($this->collection->lastException);
    }

    // ============ filterCollectionsForPush() — receive dedup (D6) ============

    public function testFilterMissingLocallyIsWanted(): void
    {
        $this->collection->findAllResult = array();   // nothing local
        $wanted = $this->collection->filterCollectionsForPush(array('u1' => '2026-01-01 00:00:00'));
        $this->assertSame(array('u1' => '2026-01-01 00:00:00'), $wanted);
    }

    public function testFilterEmptyCandidatesReturnsEmpty(): void
    {
        $this->assertSame(array(), $this->collection->filterCollectionsForPush(array()));
    }

    public function testFilterLockedZeroLocalIsDroppedEvenIfNewer(): void
    {
        // A locally-created (locked=0) collection is authoritative ⇒ never overwritten.
        $this->collection->findAllResult = array(
            array('Collection' => array('uuid' => 'u1', 'modified' => '2000-01-01 00:00:00', 'locked' => 0)),
        );
        $wanted = $this->collection->filterCollectionsForPush(array('u1' => '2030-01-01 00:00:00'));
        $this->assertSame(array(), $wanted, 'locked=0 local dropped despite a much newer candidate');
    }

    public function testFilterLockedOneNewerCandidateIsWanted(): void
    {
        $this->collection->findAllResult = array(
            array('Collection' => array('uuid' => 'u1', 'modified' => '2026-01-01 00:00:00', 'locked' => 1)),
        );
        $wanted = $this->collection->filterCollectionsForPush(array('u1' => '2026-06-01 00:00:00'));
        $this->assertArrayHasKey('u1', $wanted);
    }

    public function testFilterLockedOneEqualCandidateIsDropped(): void
    {
        $this->collection->findAllResult = array(
            array('Collection' => array('uuid' => 'u1', 'modified' => '2026-01-01 00:00:00', 'locked' => 1)),
        );
        $wanted = $this->collection->filterCollectionsForPush(array('u1' => '2026-01-01 00:00:00'));
        $this->assertSame(array(), $wanted, 'equal modified ⇒ not wanted (skip-on-equal)');
    }

    public function testFilterLockedOneOlderCandidateIsDropped(): void
    {
        $this->collection->findAllResult = array(
            array('Collection' => array('uuid' => 'u1', 'modified' => '2026-06-01 00:00:00', 'locked' => 1)),
        );
        $wanted = $this->collection->filterCollectionsForPush(array('u1' => '2026-01-01 00:00:00'));
        $this->assertSame(array(), $wanted);
    }

    public function testFilterMixedCandidateSet(): void
    {
        // missing ⇒ wanted; locked0 ⇒ dropped; locked1-newer ⇒ wanted; locked1-equal ⇒ dropped.
        $this->collection->findAllResult = array(
            array('Collection' => array('uuid' => 'l0', 'modified' => '2000-01-01 00:00:00', 'locked' => 0)),
            array('Collection' => array('uuid' => 'l1new', 'modified' => '2026-01-01 00:00:00', 'locked' => 1)),
            array('Collection' => array('uuid' => 'l1eq', 'modified' => '2026-01-01 00:00:00', 'locked' => 1)),
        );
        $wanted = $this->collection->filterCollectionsForPush(array(
            'missing' => '2026-01-01 00:00:00',
            'l0' => '2030-01-01 00:00:00',
            'l1new' => '2026-06-01 00:00:00',
            'l1eq' => '2026-01-01 00:00:00',
        ));
        $keys = array_keys($wanted);
        sort($keys);
        $this->assertSame(array('l1new', 'missing'), $keys);
    }

    // ============ isCandidateValidForPush() (D6 gate, via reflection) ============

    private function candidateValid($candidateModified, array $existing)
    {
        $m = new ReflectionMethod('Collection', 'isCandidateValidForPush');
        $m->setAccessible(true);
        return $m->invoke($this->collection, $candidateModified, $existing);
    }

    public function testCandidateValidFalseForLockedZero(): void
    {
        $this->assertFalse($this->candidateValid('2030-01-01 00:00:00', array('modified' => '2000-01-01 00:00:00', 'locked' => 0)));
    }

    public function testCandidateValidFalseForEqualOrOlder(): void
    {
        $this->assertFalse($this->candidateValid('2026-01-01 00:00:00', array('modified' => '2026-01-01 00:00:00', 'locked' => 1)));
        $this->assertFalse($this->candidateValid('2025-01-01 00:00:00', array('modified' => '2026-01-01 00:00:00', 'locked' => 1)));
    }

    public function testCandidateValidTrueForLockedOneNewer(): void
    {
        $this->assertTrue($this->candidateValid('2026-06-01 00:00:00', array('modified' => '2026-01-01 00:00:00', 'locked' => 1)));
    }

    // ============ isPushableForServerSyncRules() (push-rules, via reflection) ============

    private function pushable(array $collection, array $server)
    {
        $m = new ReflectionMethod('Collection', 'isPushableForServerSyncRules');
        $m->setAccessible(true);
        return $m->invoke($this->collection, $collection, $server);
    }

    private function serverWithPushRules(array $rules)
    {
        return array('Server' => array('id' => 7, 'push_rules' => json_encode($rules)));
    }

    public function testPushRulesNoRulesAllows(): void
    {
        $this->assertTrue($this->pushable(array('Orgc' => array('uuid' => 'x')), $this->serverWithPushRules(array())));
    }

    public function testPushRulesOrMatchAllows(): void
    {
        $server = $this->serverWithPushRules(array('orgs' => array('OR' => array('good-uuid'))));
        $this->assertTrue($this->pushable(array('Orgc' => array('uuid' => 'good-uuid')), $server));
    }

    public function testPushRulesOrMissAllows(): void
    {
        $server = $this->serverWithPushRules(array('orgs' => array('OR' => array('good-uuid'))));
        $this->assertFalse($this->pushable(array('Orgc' => array('uuid' => 'other-uuid')), $server), 'orgc not in OR list ⇒ blocked');
    }

    public function testPushRulesNotMatchBlocks(): void
    {
        $server = $this->serverWithPushRules(array('orgs' => array('NOT' => array('bad-uuid'))));
        $this->assertFalse($this->pushable(array('Orgc' => array('uuid' => 'bad-uuid')), $server));
    }

    public function testPushRulesNotMissAllows(): void
    {
        $server = $this->serverWithPushRules(array('orgs' => array('NOT' => array('bad-uuid'))));
        $this->assertTrue($this->pushable(array('Orgc' => array('uuid' => 'fine-uuid')), $server));
    }

    // ============ prepareForPushToServer() (via reflection) ============

    private function prepare(array $collection, array $server)
    {
        ClassRegistry::$instances['Event'] = new CollectionPushFakeEvent();
        $m = new ReflectionMethod('Collection', 'prepareForPushToServer');
        $m->setAccessible(true);
        return $m->invoke($this->collection, $collection, $server);
    }

    private function server()
    {
        return array('Server' => array('id' => 7));
    }

    public function testPrepareStripsLocalIdAndKeepsDistribution(): void
    {
        // RAW passthrough: prepare must NOT downgrade (the remote sink owns it).
        $collection = array('Collection' => array('id' => 111, 'uuid' => 'u1', 'distribution' => 2));
        $prepared = $this->prepare($collection, $this->server());

        $this->assertArrayNotHasKey('id', $prepared['Collection'], 'local id stripped (mass-assignment discipline)');
        $this->assertSame(2, $prepared['Collection']['distribution'], 'distribution NOT downgraded on push (RAW)');
    }

    public function testPrepareBlockedByCheckDistribution(): void
    {
        ClassRegistry::$instances['Event'] = new CollectionPushFakeEvent();
        ClassRegistry::$instances['Event']->checkResult = false;
        $m = new ReflectionMethod('Collection', 'prepareForPushToServer');
        $m->setAccessible(true);
        $result = $m->invoke($this->collection, array('Collection' => array('id' => 1, 'uuid' => 'u1', 'distribution' => 1)), $this->server());
        $this->assertSame(403, $result);
    }

    public function testPrepareDist4NotInSharingGroupServerBlocked(): void
    {
        $collection = array('Collection' => array(
            'id' => 1, 'uuid' => 'u1', 'distribution' => 4,
            'SharingGroup' => array('SharingGroupServer' => array(array('server_id' => 999))),
        ));
        $this->assertSame(403, $this->prepare($collection, $this->server()), 'dist=4, server not a SG member ⇒ 403');
    }

    public function testPrepareDist4InSharingGroupServerAllowed(): void
    {
        $collection = array('Collection' => array(
            'id' => 1, 'uuid' => 'u1', 'distribution' => 4,
            'SharingGroup' => array('SharingGroupServer' => array(array('server_id' => 7))),
        ));
        $prepared = $this->prepare($collection, $this->server());
        $this->assertIsArray($prepared);
        $this->assertArrayNotHasKey('id', $prepared['Collection']);
    }

    public function testPrepareDist4NonRoamingNoServersBlocked(): void
    {
        $collection = array('Collection' => array(
            'id' => 1, 'uuid' => 'u1', 'distribution' => 4,
            'SharingGroup' => array('roaming' => false),
        ));
        $this->assertSame(403, $this->prepare($collection, $this->server()));
    }

    // ============ collectDataForPush() — post-find filtering + corpus nesting ============

    private function collectServer()
    {
        return array('Server' => array('id' => 7, 'push_rules' => '[]'));
    }

    private function corpusRow($uuid, $overrides = array())
    {
        return array(
            'Collection' => array_merge(array('id' => 1, 'uuid' => $uuid, 'distribution' => 2, 'modified' => '2026-01-01 00:00:00'), $overrides),
            'Orgc' => array('uuid' => 'orgc-uuid'),
            'SharingGroup' => array(),
            'CollectionElement' => array(array('uuid' => 'e1', 'element_uuid' => 'ev1', 'element_type' => 'Event')),
        );
    }

    public function testCollectNestsCorpusUnderCollection(): void
    {
        ClassRegistry::$instances['Event'] = new CollectionPushFakeEvent();
        ClassRegistry::$instances['SharingGroup'] = new CollectionPushFakeSharingGroup();
        $this->collection->findAllResult = array($this->corpusRow('u1'));

        $out = $this->collection->collectDataForPush($this->collectServer());

        $this->assertCount(1, $out);
        $c = $out[0]['Collection'];
        $this->assertSame('orgc-uuid', $c['Orgc']['uuid'], 'Orgc nested under Collection');
        $this->assertArrayHasKey('CollectionElement', $c, 'element corpus nested under Collection');
        $this->assertSame('ev1', $c['CollectionElement'][0]['element_uuid']);
    }

    public function testCollectExcludedByCheckDistribution(): void
    {
        $event = new CollectionPushFakeEvent();
        $event->checkResult = false;                 // distribution rule blocks it
        ClassRegistry::$instances['Event'] = $event;
        ClassRegistry::$instances['SharingGroup'] = new CollectionPushFakeSharingGroup();
        $this->collection->findAllResult = array($this->corpusRow('u1'));

        $this->assertSame(array(), $this->collection->collectDataForPush($this->collectServer()));
    }

    public function testCollectExcludedByPushRules(): void
    {
        ClassRegistry::$instances['Event'] = new CollectionPushFakeEvent();
        ClassRegistry::$instances['SharingGroup'] = new CollectionPushFakeSharingGroup();
        $this->collection->findAllResult = array($this->corpusRow('u1'));
        // OR rule that the row's orgc-uuid does not satisfy.
        $server = array('Server' => array('id' => 7, 'push_rules' => json_encode(array('orgs' => array('OR' => array('someone-else'))))));

        $this->assertSame(array(), $this->collection->collectDataForPush($server));
    }

    public function testCollectEnrichesDist4SharingGroup(): void
    {
        $event = new CollectionPushFakeEvent();
        ClassRegistry::$instances['Event'] = $event;
        $sg = new CollectionPushFakeSharingGroup();
        $sg->firstResult = array(
            'SharingGroup' => array('id' => 55, 'uuid' => 'sg-uuid'),
            'Organisation' => array('id' => 3, 'uuid' => 'org-uuid'),
            'SharingGroupOrg' => array(),
            'SharingGroupServer' => array(array('server_id' => 7)),
        );
        ClassRegistry::$instances['SharingGroup'] = $sg;

        $row = $this->corpusRow('u1', array('distribution' => 4));
        $row['SharingGroup'] = array('id' => 55);      // triggers enrichment via find('first')
        $this->collection->findAllResult = array($row);

        $out = $this->collection->collectDataForPush($this->collectServer());

        $this->assertCount(1, $out);
        $sgOut = $out[0]['Collection']['SharingGroup'];
        $this->assertSame('sg-uuid', $sgOut['uuid'], 'SG enriched from find(first)');
        $this->assertArrayHasKey('SharingGroupServer', $sgOut, 'SG carries the full org/server struct for remote captureSG');
    }
}
