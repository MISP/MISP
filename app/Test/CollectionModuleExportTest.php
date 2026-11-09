<?php
/** Collection module exports: real controller/model, no DB or module network. */
use PHPUnit\Framework\TestCase;

if (!class_exists(TestCase::class)) {
    require_once __DIR__ . '/../Vendor/autoload.php';
}
if (!class_exists('App', false)) {
    class App { public static function uses($class, $package) {} }
}
if (!class_exists('AppModel', false)) {
    class AppModel {}
}
if (!class_exists('AppController', false)) {
    class AppController {}
}
if (!class_exists('NotFoundException', false)) {
    class NotFoundException extends RuntimeException {}
}
if (!class_exists('Validation', false)) {
    class Validation {
        public static function uuid($value) {
            return is_string($value) && preg_match('/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/Di', $value);
        }
    }
}
if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry {
        public static $module;
        public static function init($name) { return self::$module; }
    }
}
if (!class_exists('Configure', false)) {
    class Configure { public static function read($key) { return null; } }
}
if (!function_exists('__')) {
    function __($text, ...$args) { return $args ? vsprintf($text, $args) : $text; }
}
require_once __DIR__ . '/../Controller/EventsController.php';
require_once __DIR__ . '/../Model/Event.php';
require_once __DIR__ . '/../Lib/Tools/JSONConverterTool.php';

class CollectionExportTestModule
{
    public $allowed = true;
    public $sources = ['event', 'event-collection'];
    public $reply;
    public $payload;
    public $user;
    public $listing;
    public function __construct() { $this->reply = ['data' => base64_encode('ZIP fixture')]; }
    public function getEnabledModule($name, $type, $user)
    {
        $this->user = $user;
        if (!$this->allowed || $name !== 'misp_feed') { return 'Disabled or restricted'; }
        return ['name' => $name, 'meta' => ['module-type' => ['export'], 'name' => 'MISP Feed Export',
            'require_standard_format' => true, 'fetch_options' => ['includeAttachments' => true, 'eventid' => [999]]],
            'mispattributes' => ['inputSource' => $this->sources, 'responseType' => 'application/zip', 'outputFileExtension' => 'zip']];
    }
    public function getEnabledModules($user, $type, $family)
    {
        return $this->listing ?? ['modules' => [$this->getEnabledModule('misp_feed', 'Export', $user),
            ['name' => 'single', 'meta' => ['name' => 'Single event'], 'mispattributes' => ['inputSource' => ['event']]]]];
    }
    public function queryModuleServer($payload, $hover, $family) { $this->payload = $payload; return $this->reply; }
}

#[AllowDynamicProperties]
class CollectionExportTestEvent extends Event
{
    public $fetches = [];
    public $exports = [];
    public function __construct() {}
    public function fetchEvent($user, $options = [], $useCache = false)
    {
        $this->fetches[] = [$user, $options];
        return [['Event' => ['uuid' => '11111111-1111-4111-8111-111111111111', 'info' => 'Selected event'],
            'Orgc' => ['uuid' => '22222222-2222-4222-8222-222222222222', 'name' => 'Creator'],
            'Attribute' => []]];
    }
    public function export(array $user, $module, array $options = [])
    {
        $this->exports[] = [$user, $module, $options];
        return parent::export($user, $module, $options);
    }
}

class CollectionExportTestResponse
{
    public $content;
    public $mime;
    public $filename;
    public function body($value) { $this->content = $value; }
    public function type($value) { $this->mime = $value; }
    public function download($value) { $this->filename = $value; }
}

#[AllowDynamicProperties]
class CollectionExportTestController extends EventsController
{
    public $values = [];
    public function __construct($module)
    {
        $this->Module = $module;
        ClassRegistry::$module = $module;
        $this->Event = new CollectionExportTestEvent();
        $this->Auth = new class { public function user() { return ['id' => 7, 'org_id' => 2]; } };
        $this->response = new CollectionExportTestResponse();
    }
    public function loadModel($modelClass = null, $id = null) { return true; }
    public function set($one, $two = null) { $this->values[$one] = $two; }
    public function render($view = null, $layout = null) { return null; }
    protected function _jsonDecode($dataToDecode) { return json_decode($dataToDecode, true); }
}

class CollectionModuleExportTest extends TestCase
{
    public function testSelectionDialogIncludesCollectionModulesBesideBuiltinFormats()
    {
        $controller = new CollectionExportTestController(new CollectionExportTestModule());
        $controller->restSearchExport('[1,2]');
        $this->assertSame([1,2], $controller->values['idList']);
        $this->assertSame('MISP Feed Export (module)', $controller->values['exportFormats']['module_misp_feed']);
        $this->assertArrayHasKey('json', $controller->values['exportFormats']);
        $this->assertArrayNotHasKey('module_single', $controller->values['exportFormats']);
    }

    public function testModuleServiceUnavailableStillOffersBuiltinFormats()
    {
        $module = new CollectionExportTestModule();
        $module->listing = 'Module service unavailable';
        $controller = new CollectionExportTestController($module);
        $controller->restSearchExport('[1,2]');
        $this->assertArrayHasKey('json', $controller->values['exportFormats']);
        $this->assertArrayNotHasKey('module_misp_feed', $controller->values['exportFormats']);
    }

    public function testSelectedEventsReachRealModelExportAndNativeConverterWithAuthenticatedUser()
    {
        $module = new CollectionExportTestModule();
        $controller = new CollectionExportTestController($module);
        $response = $controller->restSearchExport('[1,2,1]', 'module_misp_feed');
        $this->assertSame(['id' => 7, 'org_id' => 2], $module->user);
        $this->assertSame([1,2], $controller->Event->fetches[0][1]['eventid']);
        $this->assertSame([true,false], $controller->Event->fetches[0][1]['published']);
        $this->assertTrue($controller->Event->fetches[0][1]['includeAttachments']);
        $this->assertSame('misp_feed', $module->payload['module']);
        $this->assertSame('Creator', $module->payload['data'][0]['Event']['Orgc']['name']);
        $this->assertSame('ZIP fixture', $response->content);
        $this->assertSame('application/zip', $response->mime);
        $this->assertSame('misp.events.misp_feed.export.zip', $response->filename);
    }

    /** @dataProvider invalidSelections */
    public function testInvalidOrEmptySelectionNeverFetchesEvents($selection)
    {
        $controller = new CollectionExportTestController(new CollectionExportTestModule());
        try {
            $controller->restSearchExport($selection, 'module_misp_feed');
            $this->fail('Selection should have been rejected');
        } catch (NotFoundException $e) {
            $this->assertSame([], $controller->Event->fetches);
        }
    }
    public static function invalidSelections(): array
    {
        return [[null], ['[]'], ['{}'], ['[0]'], ['[true]'], ['[[1]]'], ['["1 OR 1=1"]'], ['{"id":1}'], ['not-json']];
    }

    /** @dataProvider unavailableModules */
    public function testDisabledRestrictedOrSingleEventModulesCannotBeInvoked($allowed, $sources)
    {
        $module = new CollectionExportTestModule();
        $module->allowed = $allowed;
        $module->sources = $sources;
        $controller = new CollectionExportTestController($module);
        try {
            $controller->restSearchExport('[1,2]', 'module_misp_feed');
            $this->fail('Module should have been rejected');
        } catch (NotFoundException $e) {
            $this->assertSame([], $controller->Event->fetches);
        }
    }
    public static function unavailableModules(): array { return [[false, ['event-collection']], [true, ['event']], [true, 'bad']]; }

    /** @dataProvider errorReplies */
    public function testFailedModuleDoesNotDownloadAnEmptyFile($reply)
    {
        $module = new CollectionExportTestModule();
        $module->reply = $reply;
        $controller = new CollectionExportTestController($module);
        try {
            $controller->restSearchExport('[1,2]', 'module_misp_feed');
            $this->fail('Module failure should have been rejected');
        } catch (RuntimeException $e) {
            $this->assertNull($controller->response->content);
            $this->assertNull($controller->response->filename);
        }
    }
    public static function errorReplies(): array { return [[false], [['error' => 'No events pass filters']], [[]], [['data' => []]], [['data' => 'bad%base64']]]; }

    public function testPythonGeneratedFeedArchiveSurvivesTheControllerByteForByte()
    {
        $path = getenv('MISP_FEED_TEST_ARTIFACT');
        if (!$path) { $this->markTestSkipped('Set MISP_FEED_TEST_ARTIFACT to a Python-generated module response JSON.'); }
        $module = new CollectionExportTestModule();
        $module->reply = json_decode(file_get_contents($path), true);
        $controller = new CollectionExportTestController($module);
        $response = $controller->restSearchExport('[1,2]', 'module_misp_feed');
        $this->assertSame(base64_decode($module->reply['data']), $response->content);
        $this->assertSame("PK\x03\x04", substr($response->content, 0, 4));
        $this->assertSame('application/zip', $response->mime);
    }
}
