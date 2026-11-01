<?php
/**
 * OrgBlocklist / SightingBlocklist alias and redis key unit tests.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB — the convention used by every
 * other test under app/Test/ (see CollectionCaptureTest). Both models are
 * loaded for real on top of a stubbed AppModel, and only the callbacks that
 * never reach CakePHP's model lifecycle are exercised, so the test survives
 * whichever AppModel stub wins the class_exists() race in a full-suite run.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

// -------- framework stubs (must exist BEFORE the models load) --------

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}

// Same shape as the AppModel stub in CollectionCaptureTest: whichever file
// loads first wins for everyone in a shared-process run, so this one has to be
// usable by the model tests that do drive create()/save()/find().
if (!class_exists('AppModel', false)) {
    class AppModel
    {
        public $alias = '';
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

/** Records every key the models read, and never returns a value. */
if (!class_exists('BlocklistTestFakeRedis', false)) {
    class BlocklistTestFakeRedis
    {
        public $reads = array();

        public function get($key)
        {
            $this->reads[] = $key;
            return false;
        }
    }
}

if (!class_exists('RedisTool', false)) {
    class RedisTool
    {
        public static $redis = false;

        public static function init()
        {
            return self::$redis;
        }
    }
}

require_once __DIR__ . '/../Model/OrgUuidBlocklist.php';
require_once __DIR__ . '/../Model/OrgBlocklist.php';
require_once __DIR__ . '/../Model/SightingBlocklist.php';

use PHPUnit\Framework\TestCase;

/** CakePHP sets the alias from the class name; the stub cannot, so pin it. */
class TestableOrgBlocklist extends OrgBlocklist
{
    public $alias = 'OrgBlocklist';
    public $data = array();
}

class TestableSightingBlocklist extends SightingBlocklist
{
    public $alias = 'SightingBlocklist';
    public $data = array();
}

class OrgUuidBlocklistAliasTest extends TestCase
{
    const ORG_UUID = '58d38339-7b24-4386-b4b4-4c0f950d210f';

    /** @var BlocklistTestFakeRedis */
    private $redis;

    protected function setUp(): void
    {
        parent::setUp();
        $this->redis = new BlocklistTestFakeRedis();
        RedisTool::$redis = $this->redis;
    }

    protected function tearDown(): void
    {
        RedisTool::$redis = false;
        parent::tearDown();
    }

    public function testAfterFindPopulatesBlockedDataUnderTheOrgBlocklistAlias()
    {
        $model = new TestableOrgBlocklist();
        $results = $model->afterFind(array(
            array('OrgBlocklist' => array('org_uuid' => self::ORG_UUID)),
        ));
        $this->assertArrayHasKey('blocked_data', $results[0]['OrgBlocklist']);
    }

    public function testAfterFindPopulatesBlockedDataUnderTheSightingBlocklistAlias()
    {
        $model = new TestableSightingBlocklist();
        $results = $model->afterFind(array(
            array('SightingBlocklist' => array('org_uuid' => self::ORG_UUID)),
        ));
        $this->assertArrayHasKey('blocked_data', $results[0]['SightingBlocklist']);
        $this->assertArrayNotHasKey('OrgBlocklist', $results[0]);
    }

    public function testOrgBlocklistKeepsItsExistingRedisKeys()
    {
        $model = new TestableOrgBlocklist();
        $model->getBlockedData(self::ORG_UUID);
        $this->assertSame(
            array(
                'misp:blocklist_blocked_amount:' . self::ORG_UUID,
                'misp:blocklist_blocked_last_time:' . self::ORG_UUID,
            ),
            $this->redis->reads
        );
    }

    public function testSightingBlocklistUsesItsOwnRedisKeys()
    {
        $model = new TestableSightingBlocklist();
        $model->getBlockedData(self::ORG_UUID);
        $this->assertSame(
            array(
                'misp:sighting_blocklist_blocked_amount:' . self::ORG_UUID,
                'misp:sighting_blocklist_blocked_last_time:' . self::ORG_UUID,
            ),
            $this->redis->reads
        );
    }
}
