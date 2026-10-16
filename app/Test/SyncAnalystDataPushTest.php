<?php
/**
 * AnalystData::push: rows addressed by a value's SHA-256 are neither offered
 * nor uploaded to a MISP older than 3.0.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB (the app/Test convention).
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!defined('APP')) {
    define('APP', __DIR__ . '/../');
}
if (!function_exists('__')) {
    function __($singular, $args = null)
    {
        return vsprintf($singular, array_slice(func_get_args(), 1));
    }
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
                self::$instances[$name] = new stdClass();
            }
            return self::$instances[$name];
        }

        public static function reset()
        {
            self::$instances = array();
        }
    }
}

require_once __DIR__ . '/../Lib/Tools/ServerSyncTool.php';
require_once __DIR__ . '/../Model/AnalystData.php';

class SyncAnalystDataPushServerSync extends ServerSyncTool
{
    private $version;

    public function __construct($version)
    {
        $this->version = $version;
    }

    public function info()
    {
        return ['version' => $this->version];
    }

    public function server()
    {
        return ['Server' => ['id' => 7, 'push_analyst_data' => true]];
    }

    public function debug($message)
    {
    }
}

class SyncAnalystDataPushProbe extends AnalystData
{
    public $Server;

    public $collected = [];

    public $offered = [];

    public $uploaded = [];

    public function __construct()
    {
    }

    public function collectDataForPush(array $server): array
    {
        return $this->collected;
    }

    public function identifyUUIDsForPush(ServerSyncTool $serverSync, array $localAnalystData = [], array $conditions = []): array
    {
        $this->offered = $conditions;
        return $localAnalystData;
    }

    public function uploadEntryToServer($type, array $analystData, array $server, ServerSyncTool $serverSync, array $user)
    {
        $this->uploaded[] = $analystData[$type]['uuid'];
        return 'Success';
    }
}

class SyncAnalystDataPushTest extends TestCase
{
    const EVENT = 'b2c3d4e5-f607-4182-93a4-b5c6d7e8f922';

    const ATTRIBUTE = 'c3d4e5f6-0718-4293-a4b5-c6d7e8f90a33';

    const VALUE = '3cbad7bc936718f07fa8665bc64ce46986142bea60f86fd0c05cd2a4a8ea2bc4';

    private $instances;

    protected function setUp(): void
    {
        $this->instances = ClassRegistry::$instances;
    }

    protected function tearDown(): void
    {
        ClassRegistry::$instances = $this->instances;
    }

    private function row($uuid, $objectType, $object, $relatedType = null, $related = null)
    {
        $row = ['uuid' => $uuid, 'modified' => '2026-10-16 08:00:00', 'object_type' => $objectType];
        $row[AnalystData::addressColumn($objectType, 'object')] = $object;
        if ($relatedType !== null) {
            $row['related_object_type'] = $relatedType;
            $row[AnalystData::addressColumn($relatedType, 'related_object')] = $related;
        }
        return $row;
    }

    private function push($version)
    {
        $probe = new SyncAnalystDataPushProbe();
        $probe->collected = [
            'Note' => [
                ['Note' => $this->row('note-event', 'Event', self::EVENT)],
                ['Note' => $this->row('note-value', 'AttributeValue', self::VALUE)],
            ],
            'Opinion' => [
                ['Opinion' => $this->row('opinion-value', 'AttributeValue', self::VALUE)],
            ],
            'Relationship' => [
                ['Relationship' => $this->row('rel-uuids', 'Event', self::EVENT, 'Attribute', self::ATTRIBUTE)],
                ['Relationship' => $this->row('rel-from-value', 'AttributeValue', self::VALUE, 'Attribute', self::ATTRIBUTE)],
                ['Relationship' => $this->row('rel-to-value', 'Attribute', self::ATTRIBUTE, 'AttributeValue', self::VALUE)],
            ],
        ];
        $probe->push(['id' => 1], new SyncAnalystDataPushServerSync($version));
        return $probe;
    }

    public function testNoValueRowsToAMispOlderThan30()
    {
        $probe = $this->push('2.5.50');
        $this->assertSame(['Note' => ['note-event'], 'Relationship' => ['rel-uuids']], $probe->offered);
        $this->assertSame(['note-event', 'rel-uuids'], $probe->uploaded);
    }

    public function testEveryRowToMisp30()
    {
        $probe = $this->push('3.0.0');
        $this->assertSame([
            'Note' => ['note-event', 'note-value'],
            'Opinion' => ['opinion-value'],
            'Relationship' => ['rel-uuids', 'rel-from-value', 'rel-to-value'],
        ], $probe->offered);
        $this->assertSame([
            'note-event', 'note-value', 'opinion-value', 'rel-uuids', 'rel-from-value', 'rel-to-value',
        ], $probe->uploaded);
    }
}
