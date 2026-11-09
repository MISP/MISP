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
        // Match the shared stub used by the collection and widget tests.
        public static $instances = [];
        public static function init($name) {
            if (!isset(self::$instances[$name])) {
                self::$instances[$name] = new CollectionTestFakeModel();
            }
            return self::$instances[$name];
        }
        public static function reset() { self::$instances = []; }
    }
}
if (!class_exists('CollectionTestFakeModel', false)) {
    class CollectionTestFakeModel {
        public $responses = [];
        public function find($type, $options = []) {
            return empty($this->responses) ? [] : array_shift($this->responses);
        }
    }
}
if (!class_exists('Configure', false)) {
    class Configure {
        private static $values = [];
        public static function read($key) { return self::$values[$key] ?? null; }
        public static function write($key, $value) { self::$values[$key] = $value; }
    }
}
if (!function_exists('__')) {
    function __($text, ...$args) { return $args ? vsprintf($text, $args) : $text; }
}
if (!class_exists('MethodNotAllowedException', false)) { class MethodNotAllowedException extends RuntimeException {} }
if (!class_exists('BackgroundJobsTool', false)) { class BackgroundJobsTool { const CACHE_QUEUE = 'cache', CMD_EVENT = 'event'; } }
require_once __DIR__ . '/../Lib/Tools/ModuleFeedExportTool.php';
require_once __DIR__ . '/../Model/Job.php';
require_once __DIR__ . '/../Controller/EventsController.php';
require_once __DIR__ . '/../Model/Event.php';
require_once __DIR__ . '/../Lib/Tools/JSONConverterTool.php';

class CollectionExportTestModule
{
    public $allowed = true;
    public $feed = false;
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
            'collection_export' => $this->feed ? 'misp-feed-v1' : null, 'require_standard_format' => true, 'fetch_options' => ['includeAttachments' => true, 'eventid' => [999]]],
            'mispattributes' => ['inputSource' => $this->sources, 'responseType' => 'application/zip', 'outputFileExtension' => 'zip']];
    }
    public function getEnabledModules($user, $type, $family)
    {
        return $this->listing ?? ['modules' => [$this->getEnabledModule('misp_feed', 'Export', $user),
            ['name' => 'single', 'meta' => ['name' => 'Single event'], 'mispattributes' => ['inputSource' => ['event']]]]];
    }
    public function queryModuleServer($payload, $hover, $family, $throw = false) { $this->payload = $payload; return $this->reply; }
}

#[AllowDynamicProperties]
class CollectionExportTestEvent extends Event
{
    public $fetches = [];
    public $rows;
    public $exports = [];
    public $background;
    public function __construct() { $this->background = new CollectionExportTestBackgroundJobs(); }
    public function getBackgroundJobsTool(): BackgroundJobsTool { return $this->background; }
    public function fetchEvent($user, $options = [], $useCache = false)
    {
        $this->fetches[] = [$user, $options];
        return $this->rows ?? [['Event' => ['uuid' => '11111111-1111-4111-8111-111111111111', 'info' => 'Selected event'],
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
    public $code;
    public $filePath;
    public function statusCode($code) { $this->code = $code; }
    public function header($name, $value) {}
    public function file($path, $options = []) { $this->filePath = $path; }
    public function body($value) { $this->content = $value; }
    public function type($value) { $this->mime = $value; }
    public function download($value) { $this->filename = $value; }
}

#[AllowDynamicProperties]
class CollectionExportTestController extends EventsController
{
    public $values = [];
    public $tool;
    public $rest = false;
    public function __construct($module)
    {
        $this->Module = $module;
        ClassRegistry::$instances['Module'] = $module;
        $this->Event = new CollectionExportTestEvent();
        $this->Auth = new class { public function user() { return ['id' => 7, 'org_id' => 2]; } };
        $this->response = new CollectionExportTestResponse();
        $this->request = new class {
            public $post = false;
            public $data = [];
            public $base = '';
            public function is($type) { return $type === 'post' && $this->post; }
        };
        $this->Job = new CollectionExportTestJob();
    }
    protected function moduleFeedTool() { return $this->tool; }
    public function _isRest() { return $this->rest; }
    public function redirect($url, $status = null, $exit = true) { return $url; }
    public function loadModel($modelClass = null, $id = null) { return true; }
    public function set($one, $two = null) { $this->values[$one] = $two; }
    public function render($view = null, $layout = null) { return null; }
    protected function _jsonDecode($dataToDecode) { return json_decode($dataToDecode, true); }
}

class CollectionExportTestBackgroundJobs extends BackgroundJobsTool
{
    public $calls = [];
    public function __construct() {}
    public function enqueue(string $queue, string $command, array $args = [], $trackStatus = null,
        int $jobId = null, array $metadata = []): string
    {
        $this->calls[] = [$queue, $command, $args];
        return 'queued';
    }
}

class CollectionExportTestJob
{
    public function createJob($user, $queue, $type, $input, $message) { return 101; }
    public function saveStatus($id, $success, $message) {}
    public function find($type, $options) { return []; }
}

class CollectionModuleExportTest extends TestCase
{
    private $registry;
    private $backgroundJobs;

    protected function setUp(): void
    {
        $this->registry = ClassRegistry::$instances;
        $this->backgroundJobs = Configure::read('MISP.background_jobs');
    }

    protected function tearDown(): void
    {
        ClassRegistry::$instances = $this->registry;
        Configure::write('MISP.background_jobs', $this->backgroundJobs);
    }

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
        return [[null], ['[]'], ['{}'], ['[0]'], ['[true]'], ['[[1]]'], ['["1 OR 1=1"]'], ['{"id":1}'], ['not-json'], ['["11111111-1111-4111-8111-111111111111"]']];
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

    public function testBackgroundFeedSubmissionDoesNotFetchOrSerializeEvents()
    {
        Configure::write('MISP.background_jobs', true);
        $module = new CollectionExportTestModule(); $module->feed = true;
        $controller = new CollectionExportTestController($module);
        $root = sys_get_temp_dir() . '/feed-queue-' . bin2hex(random_bytes(8));
        $controller->tool = new ModuleFeedExportTool($root);
        $controller->rest = true;
        $controller->request->post = true;
        $selection = range(1, 5000);
        $controller->request->data = ['Event' => ['eventid' => json_encode($selection), 'returnFormat' => 'module_misp_feed']];
        try {
            $response = $controller->restSearchExport();
            $this->assertSame(202, $response->code);
            $this->assertSame('queued', json_decode($response->content, true)['status']);
            $this->assertSame([], $controller->Event->fetches);
            $this->assertNull($module->payload);
            $this->assertSame([['cache', 'event', ['exportModuleFeed', 7, 101]]], $controller->Event->background->calls);
            $this->assertSame($selection, $controller->tool->request(101)['selection']);
        } finally {
            foreach (glob($root . '/101/*') ?: [] as $file) { unlink($file); }
            rmdir($root . '/101'); rmdir($root);
            Configure::write('MISP.background_jobs', false);
        }
    }

    public function testLargeSelectionDialogAcceptsPostBodyInsteadOfLongUrl()
    {
        $controller = new CollectionExportTestController(new CollectionExportTestModule());
        $controller->request->post = true;
        $controller->request->data = ['eventid' => range(1, 5000)];
        $controller->restSearchExport();
        $this->assertCount(5000, $controller->values['idList']);
        $this->assertSame([], $controller->Event->fetches);
    }

    public function testFeedQueueRequiresPostAndBackgroundWorkers()
    {
        Configure::write('MISP.background_jobs', false);
        $module = new CollectionExportTestModule(); $module->feed = true;
        $controller = new CollectionExportTestController($module);
        foreach ([false, true] as $post) {
            $controller->request->post = $post;
            try {
                $controller->restSearchExport('[1,2]', 'module_misp_feed');
                $this->fail('Feed submission must not fall back to synchronous generation.');
            } catch (MethodNotAllowedException $e) { $this->assertSame([], $controller->Event->fetches); }
        }
    }

    public function testWorkerRequestsOnlyOneSelectedEventPerModuleCall()
    {
        $module = new CollectionExportTestModule();
        $controller = new CollectionExportTestController($module);
        $controller->Event->Module = $module;
        $desc = $module->getEnabledModule('misp_feed', 'Export', ['id' => 7]);
        $controller->Event->exportFeedPart(['id' => 7], $desc, 123);
        $this->assertSame(123, $controller->Event->fetches[0][1]['eventid']);
        $this->assertTrue($module->payload['feed_chunk']);
        $this->assertCount(1, $module->payload['data']);
    }

    public function testFeedTransportPreservesAssociationLocalFlags()
    {
        $module = new CollectionExportTestModule();
        $controller = new CollectionExportTestController($module);
        $controller->Event->Module = $module;
        $controller->Event->rows = [['Event' => ['uuid' => '11111111-1111-4111-8111-111111111111'],
            'EventTag' => [['local' => true, 'Tag' => ['name' => 'local-event']]],
            'Attribute' => [['AttributeTag' => [['local' => true, 'Tag' => ['name' => 'local-attribute']]]]]]];
        $desc = $module->getEnabledModule('misp_feed', 'Export', ['id' => 7]);
        $desc['meta']['require_standard_format'] = false;
        $controller->Event->exportFeedPart(['id' => 7], $desc, 1);
        $this->assertTrue($module->payload['data'][0]['EventTag'][0]['local']);
        $this->assertTrue($module->payload['data'][0]['Attribute'][0]['AttributeTag'][0]['local']);
    }

    public function testProgressIsSmallAndDownloadUsesFileStreaming()
    {
        $path = getenv('MISP_FEED_TEST_PART');
        if (!$path) { $this->markTestSkipped('Set MISP_FEED_TEST_PART for native part integration.'); }
        $module = new CollectionExportTestModule();
        $controller = new CollectionExportTestController($module);
        $root = sys_get_temp_dir() . '/feed-download-' . bin2hex(random_bytes(8));
        $controller->tool = new ModuleFeedExportTool($root);
        $controller->tool->create(102, ['id' => 7], 'misp_feed', [1]);
        try {
            $controller->tool->generate(102, function () use ($controller, $path) {
                $status = $controller->moduleExportStatus(102);
                $this->assertSame('running', json_decode($status->content, true)['status']);
                $this->assertLessThan(4096, strlen($status->content));
                return json_decode(file_get_contents($path), true);
            });
            $controller->response = new CollectionExportTestResponse();
            $download = $controller->downloadModuleExport(102);
            $this->assertFileExists($download->filePath);
            $this->assertNull($download->content);
            $this->assertSame('application/zip', $download->mime);
            $controller->Auth = new class { public function user() { return ['id' => 8]; } };
            try { $controller->downloadModuleExport(102); $this->fail('Another user must not download this feed'); }
            catch (RuntimeException $e) { $this->assertStringContainsString('not found', $e->getMessage()); }
        } finally {
            foreach (glob($root . '/102/*') ?: [] as $file) { unlink($file); }
            rmdir($root . '/102'); rmdir($root);
        }
    }

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
