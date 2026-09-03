<?php
/**
 * Collection::captureCollection() unit tests (T2.2 — PRD §9.1).
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB — the convention used by every
 * other test under app/Test/ (see DashboardURLValidatorTest). captureCollection
 * is a Collection model method, so we stub its framework dependencies
 * (App/Configure/CakeText/ClassRegistry/__/AppModel) at the top of this file,
 * then load the real Collection.php and drive it through a TestableCollection
 * subclass that overrides find()/save()/create() with an in-memory simulation.
 *
 * This works because captureCollection pins every identity/security field
 * (uuid/org/orgc/user_id/locked) and applies the distribution downgrade BEFORE
 * calling save(), so asserting on the captured save payload verifies the real
 * logic without a database (and sidesteps the schema-cache false-pass trap
 * entirely — the live sink is exercised for real at the T3/T4 sync E2E).
 */

require_once __DIR__ . '/../Vendor/autoload.php';

// -------- framework stubs (must exist BEFORE Collection.php loads) --------

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

// NB: ClassRegistry is also stubbed by PewPewMapWidgetTest. Both files guard
// with class_exists(), so in a full-suite run whichever loads first wins for
// everyone. We therefore keep the SAME contract PewPew relies on — init()
// auto-creates a find()/responses fake for any unregistered name (never null) —
// so a shared-process run doesn't break PewPew. Our own needs are met by
// pre-registering the Event double into $instances before init() is reached.

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

require_once __DIR__ . '/../Model/Collection.php';

use PHPUnit\Framework\TestCase;

/**
 * A minimal captureOrg double: records the org array it was handed and returns
 * a fixed local id (mirrors Organisation::captureOrg's default return type).
 */
class StubOrgc
{
    public $captured = null;
    public $returnId = 42;

    public function captureOrg($org, array $user, $force = false, $returnUUID = false)
    {
        $this->captured = $org;
        return $this->returnId;
    }
}

/**
 * Event::captureSGForElement double: SharingGroup present ⇒ resolves to a fixed
 * sharing_group_id; otherwise unresolvable ⇒ distribution forced to 0, sg 0
 * (the real method's contract).
 */
class StubEvent
{
    public $resolvedSgId = 77;

    public function captureSGForElement($element, $user, $server = false)
    {
        if (isset($element['SharingGroup'])) {
            unset($element['SharingGroup']);
            $element['sharing_group_id'] = $this->resolvedSgId;
        } else {
            $element['sharing_group_id'] = 0;
            $element['distribution'] = 0;
        }
        return $element;
    }
}

/** CollectionElement::captureElements double: records the corpus it was handed. */
class StubCollectionElement
{
    public $capturedData = null;
    public $callCount = 0;

    public function captureElements($data)
    {
        $this->callCount++;
        $this->capturedData = $data;
        return $data;
    }
}

/**
 * Collection with the DB layer replaced by an in-memory simulation.
 * find() #1 returns the (injected) existing row; every later find() returns the
 * last-saved payload stamped with a local id (what captureCollection re-fetches
 * to hand the element corpus).
 */
class TestableCollection extends Collection
{
    public $existingRow = null;   // what the uuid lookup returns (null ⇒ create)
    public $saveReturn = true;    // simulate save success/failure
    public $savedData = null;     // captured save() payload
    public $savedFieldList = null;
    public $saveCallCount = 0;
    private $findCallCount = 0;

    public function find($type, $options = array())
    {
        $this->findCallCount++;
        if ($this->findCallCount === 1) {
            return $this->existingRow;
        }
        $saved = isset($this->savedData['Collection']) ? $this->savedData['Collection'] : array();
        $saved['id'] = 123;
        return array('Collection' => $saved);
    }

    public function create($data = array())
    {
        $this->id = false;
    }

    public function save($data = null, $validate = true, $fieldList = array())
    {
        $this->saveCallCount++;
        $this->savedData = $data;
        $this->savedFieldList = $fieldList;
        return $this->saveReturn;
    }
}

class CollectionCaptureTest extends TestCase
{
    private $collection;
    private $orgc;
    private $event;
    private $element;

    protected function setUp(): void
    {
        Configure::reset();
        ClassRegistry::reset();
        ClassRegistry::$factory = function ($name) { return new CollectionTestFakeModel(); };

        $this->collection = new TestableCollection();
        $this->orgc = new StubOrgc();
        $this->event = new StubEvent();
        $this->element = new StubCollectionElement();

        // Wire the associated-model doubles the sink reaches for.
        $this->collection->Orgc = $this->orgc;
        $this->collection->CollectionElement = $this->element;
        ClassRegistry::$instances['Event'] = $this->event;
    }

    private function syncUser()
    {
        return array(
            'id' => 5,
            'org_id' => 9,
            'Organisation' => array('id' => 9, 'uuid' => 'user-org-uuid'),
            'Role' => array(
                'perm_sync' => 1,
                'perm_site_admin' => 0,
                'perm_sync_internal' => 0,
            ),
        );
    }

    /** A well-formed incoming collection payload with an Orgc and no SG. */
    private function incoming(array $overrides = array())
    {
        $base = array(
            'uuid' => 'col-uuid-0001',
            'name' => 'Remote collection',
            'type' => 'default',
            'description' => 'desc',
            'distribution' => 1,
            'modified' => '2026-01-01 00:00:00',
            'Orgc' => array('uuid' => 'orgc-uuid', 'name' => 'Creator Org'),
            'CollectionElement' => array(),
        );
        return array('Collection' => array_merge($base, $overrides));
    }

    private function externalServer()
    {
        return array('Server' => array('internal' => 0, 'org_id' => 3));
    }

    private function internalServer()
    {
        return array('Server' => array('internal' => 1, 'org_id' => 9));
    }

    // ---------------- 1. create ----------------

    public function testCreatePinsIdentityAndDowngrades(): void
    {
        $res = $this->collection->captureCollection(
            $this->syncUser(),
            $this->incoming(array('distribution' => 1)),
            $this->externalServer()
        );

        $this->assertTrue($res['success']);
        $this->assertSame(1, $res['imported']);
        $this->assertSame(0, $res['failed']);

        $saved = $this->collection->savedData['Collection'];
        $this->assertSame(1, $saved['locked'], 'synced-in ⇒ locked=1');
        $this->assertSame(5, $saved['user_id'], 'user_id neutralised to sync user (D7)');
        $this->assertSame(9, $saved['org_id'], 'org_id = sync user org');
        $this->assertSame(42, $saved['orgc_id'], 'orgc_id resolved via captureOrg');
        $this->assertSame(0, $saved['distribution'], 'community(1) downgraded to org-only(0)');
        $this->assertSame('col-uuid-0001', $saved['uuid']);
        $this->assertArrayNotHasKey('Orgc', $saved, 'Orgc consumed by captureOrganisationAndSG');
        $this->assertArrayNotHasKey('id', $saved, 'payload id never persisted on create');
        $this->assertSame(array('uuid' => 'orgc-uuid', 'name' => 'Creator Org'), $this->orgc->captured);
    }

    public function testCreateNoOrgcFallsBackToSyncUserOrg(): void
    {
        $incoming = $this->incoming();
        unset($incoming['Collection']['Orgc']);

        $this->collection->captureCollection($this->syncUser(), $incoming, $this->externalServer());

        $this->assertSame(9, $this->collection->savedData['Collection']['orgc_id']);
        $this->assertNull($this->orgc->captured, 'captureOrg not called without an Orgc');
    }

    // ---------------- 2. update by modified ----------------

    public function testUpdateWhenRemoteNewer(): void
    {
        $this->collection->existingRow = array('Collection' => array(
            'id' => 50, 'locked' => 1, 'modified' => '2025-01-01 00:00:00'
        ));

        $res = $this->collection->captureCollection(
            $this->syncUser(),
            $this->incoming(array('modified' => '2026-06-01 00:00:00')),
            $this->externalServer()
        );

        $this->assertSame(1, $res['imported']);
        $this->assertSame(50, $this->collection->savedData['Collection']['id'], 'updates the existing row id');
    }

    public function testSkipWhenRemoteOlder(): void
    {
        $this->collection->existingRow = array('Collection' => array(
            'id' => 50, 'locked' => 1, 'modified' => '2026-06-01 00:00:00'
        ));

        $res = $this->collection->captureCollection(
            $this->syncUser(),
            $this->incoming(array('modified' => '2026-01-01 00:00:00')),
            $this->externalServer()
        );

        $this->assertSame(1, $res['ignored']);
        $this->assertSame(0, $res['imported']);
        $this->assertFalse($res['success']);
        $this->assertSame(0, $this->collection->saveCallCount, 'no save on older remote');
    }

    public function testSkipWhenModifiedEqual(): void
    {
        $this->collection->existingRow = array('Collection' => array(
            'id' => 50, 'locked' => 1, 'modified' => '2026-01-01 00:00:00'
        ));

        $res = $this->collection->captureCollection(
            $this->syncUser(),
            $this->incoming(array('modified' => '2026-01-01 00:00:00')),
            $this->externalServer()
        );

        $this->assertSame(1, $res['ignored'], 'skip-on-equal (second-resolution tie)');
        $this->assertSame(0, $this->collection->saveCallCount);
    }

    // ---------------- 3. locked block (D6) ----------------

    public function testLockedBlockOnLocalOriginalFromExternal(): void
    {
        $this->collection->existingRow = array('Collection' => array(
            'id' => 50, 'locked' => 0, 'modified' => '2000-01-01 00:00:00'
        ));

        $res = $this->collection->captureCollection(
            $this->syncUser(),
            $this->incoming(array('modified' => '2030-01-01 00:00:00')),
            $this->externalServer()
        );

        $this->assertSame(1, $res['failed']);
        $this->assertSame(0, $res['imported']);
        $this->assertSame(0, $this->collection->saveCallCount, 'locally-created original never overwritten by external');
        $this->assertNotEmpty($res['errors']);
    }

    public function testLockedBlockBypassedForInternalServer(): void
    {
        $this->collection->existingRow = array('Collection' => array(
            'id' => 50, 'locked' => 0, 'modified' => '2000-01-01 00:00:00'
        ));

        $res = $this->collection->captureCollection(
            $this->syncUser(),
            $this->incoming(array('modified' => '2030-01-01 00:00:00')),
            $this->internalServer()
        );

        $this->assertSame(1, $res['imported'], 'internal server may overwrite a local original');
    }

    // ---------------- 4. distribution downgrade ----------------

    public function testDowngradeConnectedToCommunity(): void
    {
        $this->collection->captureCollection(
            $this->syncUser(),
            $this->incoming(array('distribution' => 2)),
            $this->externalServer()
        );
        $this->assertSame(1, $this->collection->savedData['Collection']['distribution']);
    }

    public function testDistribution3Unchanged(): void
    {
        $this->collection->captureCollection(
            $this->syncUser(),
            $this->incoming(array('distribution' => 3)),
            $this->externalServer()
        );
        $this->assertSame(3, $this->collection->savedData['Collection']['distribution']);
    }

    public function testNoDowngradeForInternalWithPermSyncInternal(): void
    {
        // Guard skips downgrade only when ALL hold: host_org_id set, server
        // internal, host_org_id == server org, remote perm_sync_internal.
        Configure::write('MISP.host_org_id', 9);
        $server = array('Server' => array('internal' => 1, 'org_id' => 9));

        $this->collection->captureCollection(
            $this->syncUser(),
            $this->incoming(array('distribution' => 2)),
            $server,
            true // remotePermSyncInternal
        );

        $this->assertSame(2, $this->collection->savedData['Collection']['distribution'], 'internal peer keeps connected-communities');
    }

    public function testDowngradeStillAppliesWhenHostOrgMismatch(): void
    {
        // Internal + perm_sync_internal but host_org_id != server org ⇒ downgrade.
        Configure::write('MISP.host_org_id', 999);
        $server = array('Server' => array('internal' => 1, 'org_id' => 9));

        $this->collection->captureCollection(
            $this->syncUser(),
            $this->incoming(array('distribution' => 2)),
            $server,
            true
        );

        $this->assertSame(1, $this->collection->savedData['Collection']['distribution']);
    }

    // ---------------- 5. dist=4 sharing-group capture ----------------

    public function testDist4WithSharingGroupResolves(): void
    {
        $incoming = $this->incoming(array(
            'distribution' => 4,
            'SharingGroup' => array('uuid' => 'sg-uuid', 'name' => 'SG'),
        ));

        $this->collection->captureCollection($this->syncUser(), $incoming, $this->externalServer());

        $saved = $this->collection->savedData['Collection'];
        $this->assertSame(4, $saved['distribution'], 'dist=4 not downgraded');
        $this->assertSame(77, $saved['sharing_group_id']);
    }

    public function testDist4UnresolvableSharingGroupForcedToOrgOnly(): void
    {
        // dist=4 with no SharingGroup ⇒ captureSGForElement forces dist 0, then
        // the sink nulls sharing_group_id for any non-4 distribution.
        $incoming = $this->incoming(array('distribution' => 4));
        unset($incoming['Collection']['SharingGroup']);

        $this->collection->captureCollection($this->syncUser(), $incoming, $this->externalServer());

        $saved = $this->collection->savedData['Collection'];
        $this->assertSame(0, $saved['distribution']);
        $this->assertNull($saved['sharing_group_id']);
    }

    public function testNonSgDistributionNullsSharingGroupId(): void
    {
        $this->collection->captureCollection(
            $this->syncUser(),
            $this->incoming(array('distribution' => 3, 'sharing_group_id' => 88)),
            $this->externalServer()
        );
        $this->assertNull($this->collection->savedData['Collection']['sharing_group_id']);
    }

    // ---------------- 6. element corpus (D5) ----------------

    public function testElementsCapturedWithLocalId(): void
    {
        $elements = array(
            array('uuid' => 'e1', 'element_uuid' => 'ev1', 'element_type' => 'Event', 'description' => ''),
            array('uuid' => 'e2', 'element_uuid' => 'gc1', 'element_type' => 'GalaxyCluster', 'description' => ''),
        );
        $this->collection->captureCollection(
            $this->syncUser(),
            $this->incoming(array('CollectionElement' => $elements)),
            $this->externalServer()
        );

        $this->assertSame(1, $this->element->callCount);
        $this->assertSame(123, $this->element->capturedData['Collection']['id'], 'elements captured against the local collection id');
        $this->assertSame($elements, $this->element->capturedData['Collection']['CollectionElement']);
    }

    public function testEmptyElementSetCullsAll(): void
    {
        // present-but-empty ⇒ authoritative empty corpus (captureElements culls all).
        $this->collection->captureCollection(
            $this->syncUser(),
            $this->incoming(array('CollectionElement' => array())),
            $this->externalServer()
        );

        $this->assertSame(1, $this->element->callCount);
        $this->assertSame(array(), $this->element->capturedData['Collection']['CollectionElement']);
    }

    public function testAbsentElementKeyLeavesElementsUntouched(): void
    {
        $incoming = $this->incoming();
        unset($incoming['Collection']['CollectionElement']);

        $this->collection->captureCollection($this->syncUser(), $incoming, $this->externalServer());

        $this->assertSame(0, $this->element->callCount, 'no CollectionElement key ⇒ corpus left untouched');
    }

    public function testElementsNotCapturedWhenSaveFails(): void
    {
        $this->collection->saveReturn = false;
        $res = $this->collection->captureCollection(
            $this->syncUser(),
            $this->incoming(),
            $this->externalServer()
        );

        $this->assertSame(1, $res['failed']);
        $this->assertSame(0, $this->element->callCount);
    }

    // ---------------- 7. mass-assignment guards ----------------

    public function testPayloadIdentityFieldsIgnored(): void
    {
        // A hostile/confused payload tries to set every server-derived field.
        $incoming = $this->incoming(array(
            'id' => 999,
            'org_id' => 1,
            'orgc_id' => 2,
            'user_id' => 3,
            'locked' => 0,
        ));

        $this->collection->captureCollection($this->syncUser(), $incoming, $this->externalServer());

        $saved = $this->collection->savedData['Collection'];
        $this->assertArrayNotHasKey('id', $saved);
        $this->assertSame(9, $saved['org_id']);
        $this->assertSame(42, $saved['orgc_id']);
        $this->assertSame(5, $saved['user_id']);
        $this->assertSame(1, $saved['locked']);
    }

    public function testSaveFieldListExcludesIdAndCoversIdentity(): void
    {
        $this->collection->captureCollection($this->syncUser(), $this->incoming(), $this->externalServer());

        $fieldList = $this->collection->savedFieldList;
        $this->assertNotContains('id', $fieldList, 'id never in the save whitelist');
        foreach (array('uuid', 'org_id', 'orgc_id', 'user_id', 'locked', 'modified', 'distribution', 'sharing_group_id') as $field) {
            $this->assertContains($field, $fieldList);
        }
    }

    public function testModifiedPreservedInSavePayload(): void
    {
        // The remote modified must reach save() verbatim (dedup depends on it;
        // CakePHP then preserves a whitelisted, present date field — verified
        // against Model.php:1847 in the T2.1 findings).
        $this->collection->captureCollection(
            $this->syncUser(),
            $this->incoming(array('modified' => '2026-05-05 12:34:56')),
            $this->externalServer()
        );
        $this->assertSame('2026-05-05 12:34:56', $this->collection->savedData['Collection']['modified']);
    }

    // ---------------- structural normalisation ----------------

    public function testAcceptsSiblingRelatedData(): void
    {
        // find()-shaped payload: Orgc / CollectionElement as siblings of Collection.
        $payload = array(
            'Collection' => array(
                'uuid' => 'col-uuid-sib',
                'name' => 'n', 'type' => 'default', 'description' => 'd',
                'distribution' => 1, 'modified' => '2026-01-01 00:00:00',
            ),
            'Orgc' => array('uuid' => 'orgc-uuid', 'name' => 'Creator Org'),
            'CollectionElement' => array(
                array('uuid' => 'e1', 'element_uuid' => 'ev1', 'element_type' => 'Event', 'description' => ''),
            ),
        );

        $res = $this->collection->captureCollection($this->syncUser(), $payload, $this->externalServer());

        $this->assertSame(1, $res['imported']);
        $this->assertSame(42, $this->collection->savedData['Collection']['orgc_id'], 'sibling Orgc hoisted and resolved');
        $this->assertSame(1, $this->element->callCount, 'sibling CollectionElement hoisted and captured');
    }
}
