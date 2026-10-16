<?php
/**
 * AnalystData::captureAnalystData: a create the model rejects is reported as
 * failed, with its validation errors, not as imported.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB (the app/Test convention).
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!defined('APP')) {
    define('APP', __DIR__ . '/../');
}
if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }

        public static function import($type = null, $name = null, $parent = true)
        {
        }
    }
}
if (!class_exists('AppModel', false)) {
    class AppModel
    {
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
// Same contract as the other stubs: init() never returns null
if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $instances = array();

        public static function init($name)
        {
            if (!isset(self::$instances[$name])) {
                self::$instances[$name] = new SyncAnalystDataFallbackModel();
            }
            return self::$instances[$name];
        }

        public static function reset()
        {
            self::$instances = array();
        }
    }
}
if (!class_exists('SyncAnalystDataFallbackModel', false)) {
    class SyncAnalystDataFallbackModel
    {
        public $responses = array();

        public function find($type, $opts = array())
        {
            return empty($this->responses) ? array() : array_shift($this->responses);
        }
    }
}

require_once __DIR__ . '/../Model/AnalystData.php';

class SyncAnalystDataCaptureProbe extends AnalystData
{
    public $AnalystDataBlocklist;

    public function __construct()
    {
    }
}

class SyncAnalystDataFakeModel
{
    public $OrgBlocklist;

    public $validationErrors = [];

    public $saveResult = true;

    public $saved = [];

    public function captureOrganisationAndSG($element, $model, $user)
    {
        return $element;
    }

    public function find($type, $opts = [])
    {
        return [];
    }

    public function create()
    {
        $this->validationErrors = [];
    }

    public function save($data)
    {
        if (!$this->saveResult) {
            $this->validationErrors = ['object_uuid' => ['Please provide a valid RFC 4122 UUID']];
            return false;
        }
        $this->saved[] = $data;
        return $data;
    }

    public function checkIfBlocked($uuid)
    {
        return false;
    }

    public function hasAny($conditions)
    {
        return false;
    }
}

class SyncAnalystDataCaptureTest extends TestCase
{
    const NAMES = ['Note', 'Opinion', 'Relationship', 'AnalystDataBlocklist', 'OrgBlocklist'];

    /** @var SyncAnalystDataFakeModel */
    private $note;

    /** @var array */
    private $previous = [];

    protected function setUp(): void
    {
        foreach (self::NAMES as $name) {
            $this->previous[$name] = ClassRegistry::$instances[$name] ?? null;
            ClassRegistry::$instances[$name] = new SyncAnalystDataFakeModel();
        }
        $this->note = ClassRegistry::$instances['Note'];
    }

    protected function tearDown(): void
    {
        foreach ($this->previous as $name => $instance) {
            if ($instance === null) {
                unset(ClassRegistry::$instances[$name]);
            } else {
                ClassRegistry::$instances[$name] = $instance;
            }
        }
    }

    private function capture()
    {
        $user = [
            'Organisation' => ['uuid' => '5f8a3c4e-1b2d-4e6f-8a9b-0c1d2e3f4a5b'],
            'Role' => ['perm_sync' => 1, 'perm_site_admin' => 0],
        ];
        $probe = new SyncAnalystDataCaptureProbe();
        return $probe->captureAnalystData($user, ['Note' => [
            'uuid' => 'bdfc376c-be54-44be-bc54-53cb08832a65',
            'note' => 'x',
            'object_type' => 'Event',
            'object_uuid' => 'not-a-uuid',
        ]]);
    }

    public function testRejectedCreateIsCountedAsFailed()
    {
        $this->note->saveResult = false;
        $result = $this->capture();
        $this->assertFalse($result['success']);
        $this->assertSame(0, $result['imported']);
        $this->assertSame(1, $result['failed']);
        $this->assertSame(['Please provide a valid RFC 4122 UUID'], $result['errors']);
    }

    public function testSavedCreateIsCountedAsImported()
    {
        $result = $this->capture();
        $this->assertTrue($result['success']);
        $this->assertSame(1, $result['imported']);
        $this->assertSame(0, $result['failed']);
        $this->assertCount(1, $this->note->saved);
    }

    private function pulledAttribute()
    {
        return [
            'uuid' => 'a1b2c3d4-0000-4000-8000-000000000001',
            'distribution' => 1,
            'Note' => [['uuid' => 'n1', 'distribution' => 1, 'Opinion' => [['uuid' => 'o1', 'distribution' => 2]]]],
            'Relationship' => [['uuid' => 'r1', 'distribution' => 3, 'locked' => false]],
        ];
    }

    public function testPulledNestedAnalystDataIsLockedAndDowngraded()
    {
        $attribute = AnalystData::updatePulledNested($this->pulledAttribute(), true);
        $this->assertSame(1, $attribute['distribution']);
        $this->assertSame('0', $attribute['Note'][0]['distribution']);
        $this->assertTrue($attribute['Note'][0]['locked']);
        $this->assertSame('1', $attribute['Note'][0]['Opinion'][0]['distribution']);
        $this->assertTrue($attribute['Note'][0]['Opinion'][0]['locked']);
        $this->assertSame(3, $attribute['Relationship'][0]['distribution']);
        $this->assertTrue($attribute['Relationship'][0]['locked']);
    }

    public function testPulledNestedAnalystDataKeepsDistributionOverAnInternalLink()
    {
        $attribute = AnalystData::updatePulledNested($this->pulledAttribute(), false);
        $this->assertSame(1, $attribute['Note'][0]['distribution']);
        $this->assertSame(2, $attribute['Note'][0]['Opinion'][0]['distribution']);
        $this->assertTrue($attribute['Note'][0]['locked']);
        $this->assertTrue($attribute['Note'][0]['Opinion'][0]['locked']);
    }
}
