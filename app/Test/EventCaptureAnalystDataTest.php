<?php
/**
 * Event::captureAnalystData: which target a nested note, opinion or
 * relationship ends up with when its payload leaves the target out.
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
// Same contract as the other stubs: init() never returns null
if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $instances = array();

        public static function init($name)
        {
            if (!isset(self::$instances[$name])) {
                self::$instances[$name] = new EventCaptureFallbackModel();
            }
            return self::$instances[$name];
        }

        public static function reset()
        {
            self::$instances = array();
        }
    }
}
if (!class_exists('EventCaptureFallbackModel', false)) {
    class EventCaptureFallbackModel
    {
        public $responses = array();

        public function find($type, $opts = array())
        {
            return empty($this->responses) ? array() : array_shift($this->responses);
        }
    }
}

require_once __DIR__ . '/../Model/Event.php';

class EventCaptureAnalystDataProbe extends Event
{
    public $Note;
    public $Opinion;
    public $Relationship;
}

class EventCaptureAnalystDataRecorder
{
    const ANALYST_DATA_TYPES = ['Note', 'Opinion', 'Relationship'];

    public $captured = [];

    public function captureAnalystData($user, $analystData)
    {
        $this->captured[] = $analystData;
        return [];
    }
}

class EventCaptureAnalystDataTest extends TestCase
{
    const PARENT_UUID = '28635464-d6d0-499a-8467-47a06c447d63';

    const OTHER_UUID = 'bdfc376c-be54-44be-bc54-53cb08832a65';

    /** @var EventCaptureAnalystDataRecorder[] */
    private $recorders = [];

    /** @var array */
    private $saved = [];

    protected function setUp(): void
    {
        foreach (EventCaptureAnalystDataRecorder::ANALYST_DATA_TYPES as $type) {
            $this->saved[$type] = ClassRegistry::$instances[$type] ?? null;
            $this->recorders[$type] = new EventCaptureAnalystDataRecorder();
            ClassRegistry::$instances[$type] = $this->recorders[$type];
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->saved as $type => $instance) {
            if ($instance === null) {
                unset(ClassRegistry::$instances[$type]);
            } else {
                ClassRegistry::$instances[$type] = $instance;
            }
        }
    }

    private function capture(array $note)
    {
        $event = new EventCaptureAnalystDataProbe();
        $event->captureAnalystData(['id' => 1], ['Note' => [$note]], 'Attribute', self::PARENT_UUID);
        $this->assertCount(1, $this->recorders['Note']->captured);
        return $this->recorders['Note']->captured[0];
    }

    public function testNoTargetTakesTheParent()
    {
        $row = $this->capture(['note' => 'x']);
        $this->assertSame('Attribute', $row['object_type']);
        $this->assertSame(self::PARENT_UUID, $row['object_uuid']);
    }

    public function testParentTypeWithoutUuidTakesTheParentUuid()
    {
        $row = $this->capture(['note' => 'x', 'object_type' => 'Attribute']);
        $this->assertSame(self::PARENT_UUID, $row['object_uuid']);
    }

    public function testOtherTypeWithoutUuidIsNotPairedWithTheParentUuid()
    {
        $row = $this->capture(['note' => 'x', 'object_type' => 'Event', 'object_uuid' => '']);
        $this->assertSame('Event', $row['object_type']);
        $this->assertSame('', $row['object_uuid']);

        $this->recorders['Note']->captured = [];
        $row = $this->capture(['note' => 'x', 'object_type' => 'Event']);
        $this->assertArrayNotHasKey('object_uuid', $row);
    }

    public function testGivenTargetIsKept()
    {
        $row = $this->capture(['note' => 'x', 'object_type' => 'Event', 'object_uuid' => self::OTHER_UUID]);
        $this->assertSame('Event', $row['object_type']);
        $this->assertSame(self::OTHER_UUID, $row['object_uuid']);
    }

    public function testEveryAnalystDataTypeIsRouted()
    {
        $event = new EventCaptureAnalystDataProbe();
        $event->captureAnalystData(['id' => 1], [
            'Opinion' => [['opinion' => 80]],
            'Relationship' => [['relationship_type' => 'related-to', 'object_type' => 'Event']],
        ], 'Attribute', self::PARENT_UUID);
        $this->assertSame(self::PARENT_UUID, $this->recorders['Opinion']->captured[0]['object_uuid']);
        $this->assertSame('Opinion', $this->recorders['Opinion']->captured[0]['note_type_name']);
        $this->assertArrayNotHasKey('object_uuid', $this->recorders['Relationship']->captured[0]);
    }
}
