<?php
/** Pure contract and feed-selection tests; no CakePHP bootstrap, DB or network. */
require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!defined('DS')) { define('DS', DIRECTORY_SEPARATOR); }
if (!defined('APP')) { define('APP', dirname(__DIR__) . DS); }

if (!class_exists('App', false)) {
    class App { public static function uses($class, $package) {} }
}
if (!class_exists('AppModel', false)) {
    class AppModel
    {
        public $data = [];
        public $validationErrors = [];
        public function find($type = 'first', $options = []) { return []; }
        public function beforeValidate($options = []) { return true; }
        public function invalidate($field, $message) { $this->validationErrors[$field] = $message; }
    }
}
if (!class_exists('Configure', false)) {
    class Configure
    {
        private static $values = [];
        public static function read($key) { return self::$values[$key] ?? null; }
        public static function write($key, $value) { self::$values[$key] = $value; }
    }
}
if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $instances = [];
        public static function init($name) { return self::$instances[$name]; }
    }
}
if (!class_exists('NotFoundException', false)) {
    class NotFoundException extends RuntimeException {}
}
if (!class_exists('Validation', false)) {
    class Validation
    {
        public static function uuid($value) { return preg_match('/^[0-9a-f-]{36}$/i', $value); }
    }
}
if (!function_exists('__')) {
    function __($text, ...$args) { return $args ? vsprintf($text, $args) : $text; }
}
if (!class_exists('JsonTool', false)) {
    require_once __DIR__ . '/../Lib/Tools/JsonTool.php';
}
require_once __DIR__ . '/../Lib/Tools/GatheringFeedTool.php';
require_once __DIR__ . '/../Model/Module.php';
require_once __DIR__ . '/../Model/Feed.php';

class GatheringTestModule extends Module
{
    public $calls = [];
    public $answer;
    public $descriptors = [];

    public function getModules($moduleFamily = 'Enrichment', $throwException = false)
    {
        return $this->descriptors;
    }

    public function queryModuleServer(array $postData, $hover = false, $moduleFamily = 'Enrichment', $throwException = false, $triggerData = [], $skipTrigger = false)
    {
        $this->calls[] = compact('postData', 'moduleFamily');
        return $this->answer;
    }
}

class GatheringTestEvents
{
    public $rows = [];
    public $added = [];
    public $edited = [];
    public function find($type = 'first', $options = []) { return $this->rows; }
    public function _add($event, $fromXml, $user)
    {
        $this->added[] = $event;
        $this->rows = [$event];
        return true;
    }
    public function _edit($event, $user, $uuid, $jobId)
    {
        $this->edited[] = $event;
        $this->rows = [$event];
        return true;
    }
}

class GatheringTestFeed extends Feed
{
    public $record;
    public function find($type = 'first', $options = []) { return $this->record; }
    public function logException($message, $exception, $type = LOG_ERR) { throw $exception; }
}

class GatheringFeedTest extends TestCase
{
    const UUID = '3889452b-acb4-5fa5-8094-f950bdce20bb';

    private function bundle($timestamp = '1790856000')
    {
        $metadata = [
            'info' => 'Example gathered configuration',
            'date' => '2026-10-01',
            'timestamp' => $timestamp,
            'Orgc' => ['name' => 'Example source', 'uuid' => '55172297-0240-5b08-b452-b0466a829b1e'],
        ];
        return [
            'gathering_version' => 1,
            'source_format' => 'misp',
            'manifest' => [self::UUID => $metadata],
            'events' => [self::UUID => ['Event' => ['uuid' => self::UUID] + $metadata]],
        ];
    }

    private function feed($module = 'withaname')
    {
        return ['Feed' => [
            'id' => 123,
            'url' => 'misp-modules://' . $module,
            'input_source' => 'misp-modules',
            'source_format' => 'misp',
            'rules' => 'null',
            'settings' => ['gathering' => ['module' => $module, 'parameters' => '{"max_events":20}']],
        ]];
    }

    private function module($name = 'withaname')
    {
        Configure::write('Plugin.Gathering_' . $name . '_enabled', true);
        Configure::write('Plugin.Gathering_' . $name . '_restrict', 0);
        $module = new GatheringTestModule();
        $module->descriptors = [[
            'name' => $name,
            'meta' => ['module-type' => ['gathering'], 'config' => []],
            'mispattributes' => ['gathering_version' => 1],
        ]];
        $module->answer = $this->bundle();
        return $module;
    }

    public function testModuleContractWorksForFutureProducersAsWell()
    {
        foreach (['withaname', 'another_source'] as $name) {
            $module = $this->module($name);
            $answer = $module->queryGathering($name, ['max_events' => 20], ['id' => 1, 'Role' => ['perm_site_admin' => 1]]);
            $this->assertSame($this->bundle(), $answer);
            $this->assertSame('Gathering', $module->calls[0]['moduleFamily']);
            $payload = $module->calls[0]['postData'];
            $this->assertSame($name, $payload['module']);
            $this->assertSame('prepare', $payload['operation']);
            $this->assertSame('{"max_events":20}', json_encode($payload['parameters']));
            $this->assertSame('{}', json_encode($payload['config']));
        }
    }

    public function testDisabledAndRestrictedModulesAreNotExecuted()
    {
        $module = $this->module();
        Configure::write('Plugin.Gathering_withaname_enabled', false);
        try {
            $module->queryGathering('withaname', [], ['id' => 1, 'Role' => ['perm_site_admin' => 1]]);
            $this->fail('Disabled module was executed');
        } catch (InvalidArgumentException $e) {
            $this->assertSame([], $module->calls);
        }
        Configure::write('Plugin.Gathering_withaname_enabled', true);
        Configure::write('Plugin.Gathering_withaname_restrict', 42);
        $this->expectException(InvalidArgumentException::class);
        $module->queryGathering('withaname', [], ['id' => 1, 'org_id' => 7, 'Role' => ['perm_site_admin' => 0]]);
    }

    public function testExistingFeedSelectionAddsSkipsAndUpdatesUsingOneSnapshot()
    {
        $module = $this->module();
        $events = new GatheringTestEvents();
        ClassRegistry::$instances['Module'] = $module;
        ClassRegistry::$instances['Event'] = $events;
        $feed = new Feed();
        $property = new ReflectionProperty(Feed::class, 'gatheringUser');
        $property->setAccessible(true);
        $property->setValue($feed, ['id' => 1, 'Role' => ['perm_site_admin' => 1]]);
        $this->assertSame(['add' => [self::UUID], 'edit' => []], $feed->getNewEventUuids($this->feed()));
        $events->rows = [['Event' => ['uuid' => self::UUID, 'timestamp' => '1790856000']]];
        $this->assertSame(['add' => [], 'edit' => []], $feed->getNewEventUuids($this->feed()));
        $events->rows[0]['Event']['timestamp'] = '1790855999';
        $this->assertSame(['add' => [], 'edit' => [self::UUID]], $feed->getNewEventUuids($this->feed()));
        $this->assertCount(1, $module->calls);
        $read = new ReflectionMethod(Feed::class, 'feedGetUri');
        $read->setAccessible(true);
        $json = $read->invoke($feed, $this->feed(), 'misp-modules://withaname/' . self::UUID . '.json');
        $this->assertSame($this->bundle()['events'][self::UUID], json_decode($json, true));
        $this->assertCount(1, $module->calls);
    }

    public function testContractCanConsumeAnActualPythonGeneratedBundle()
    {
        $path = getenv('GATHERING_TEST_BUNDLE');
        if (!$path) {
            $this->markTestSkipped('Set GATHERING_TEST_BUNDLE for the cross-repository contract check.');
        }
        $bundle = json_decode(file_get_contents($path), true);
        $this->assertSame($bundle, GatheringFeedTool::validateBundle($bundle));
        foreach ($bundle['events'] as $uuid => $event) {
            $this->assertSame($event, json_decode(GatheringFeedTool::file($bundle, '/' . $uuid . '.json'), true));
        }
    }

    public function testImportJobsRegenerateAndUseTheExistingAddAndEditPaths()
    {
        $module = $this->module();
        $events = new GatheringTestEvents();
        ClassRegistry::$instances['Module'] = $module;
        ClassRegistry::$instances['Event'] = $events;
        $feed = new GatheringTestFeed();
        ClassRegistry::$instances['MispAttribute'] = new stdClass();
        $feed->record = $this->feed();
        $feed->record['Feed'] += ['distribution' => 0, 'sharing_group_id' => 0, 'tag_id' => 0, 'tag_collection_id' => 0];
        $feed->record['Feed']['rules'] = '';
        $feed->record['Feed']['settings'] = json_encode($feed->record['Feed']['settings']);
        $user = ['id' => 1, 'Role' => ['perm_site_admin' => 1]];
        $feed->downloadFromFeedInitiator(123, $user);
        $this->assertCount(1, $events->added);
        $this->assertSame(true, $feed->downloadFromFeedInitiator(123, $user));
        $this->assertCount(1, $events->added);
        $module->answer = $this->bundle('1790856001');
        $feed->downloadFromFeedInitiator(123, $user);
        $this->assertCount(1, $events->edited);
        $this->assertCount(3, $module->calls);
    }

    public function testParameterObjectsAndEmptyObjectsRoundTrip()
    {
        $this->assertSame(['module' => 'another_source', 'parameters' => []],
            GatheringFeedTool::settings(['gathering' => ['module' => 'another_source', 'parameters' => '{}']]));
        $options = GatheringFeedTool::settings(json_encode($this->feed()['Feed']['settings']));
        $this->assertSame(['max_events' => 20], $options['parameters']);
    }

    public function invalidSettings()
    {
        return [[null], [[]], [['gathering' => ['module' => '../source']]],
            [['gathering' => ['module' => 'withaname', 'parameters' => '[]']]],
            [['gathering' => ['module' => 'withaname', 'parameters' => '{invalid']]],
            [['gathering' => ['module' => 'withaname', 'parameters' => true]]]];
    }

    /** @dataProvider invalidSettings */
    public function testInvalidSettingsAreRejected($settings)
    {
        $this->expectException(InvalidArgumentException::class);
        GatheringFeedTool::settings($settings);
    }

    public function invalidBundles()
    {
        $wrongVersion = $this->bundle();
        $wrongVersion['gathering_version'] = 2;
        $missing = $this->bundle();
        $missing['events'] = [];
        $mismatch = $this->bundle();
        $mismatch['events'][self::UUID]['Event']['timestamp'] = '2';
        $identity = $this->bundle();
        $identity['events'][self::UUID]['Event']['uuid'] = 'different';
        $duplicate = $this->bundle();
        $duplicate['events'][self::UUID]['Event']['Attribute'] = [['uuid' => self::UUID]];
        $missingAttributeUuid = $this->bundle();
        $missingAttributeUuid['events'][self::UUID]['Event']['Attribute'] = [['value' => 'example.org']];
        return [[false], [['error' => 'provider body']], [$wrongVersion], [$missing], [$mismatch], [$identity],
            [$duplicate], [$missingAttributeUuid]];
    }

    /** @dataProvider invalidBundles */
    public function testIncompleteAndInconsistentBundlesFailBeforeImport($bundle)
    {
        $this->expectException(UnexpectedValueException::class);
        GatheringFeedTool::validateBundle($bundle);
    }

    public function testOnlyFilesFromTheSelectedSnapshotAreReadable()
    {
        $this->expectException(NotFoundException::class);
        GatheringFeedTool::file($this->bundle(), '/../manifest.json');
    }
}
