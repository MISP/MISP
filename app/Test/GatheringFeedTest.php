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

if (!class_exists('FileAccessTool', false)) {
    require_once __DIR__ . '/../Lib/Tools/FileAccessTool.php';
}

class GatheringTestModule extends Module
{
    public $calls = [];
    public $answer;
    public $descriptors = [];
    public $archivePath;
    public $released = [];
    public $statuses = [];
    public function getModules($moduleFamily = 'Enrichment', $throwException = false) { return $this->descriptors; }
    public function queryModuleServer(array $postData, $hover = false, $moduleFamily = 'Enrichment', $throwException = false, $triggerData = [], $skipTrigger = false)
    {
        $this->calls[] = compact('postData', 'moduleFamily');
        return $this->answer;
    }
    public function gatheringJobStatus($identifier) { return $this->statuses ? array_shift($this->statuses) : $this->answer; }
    public function downloadGatheringArchive($identifier, $destination, $size) { copy($this->archivePath, $destination); }
    public function releaseGatheringJob($identifier) { $this->released[] = $identifier; }
}

class GatheringTestEvents
{
    public $rows = [];
    public $added = [];
    public $edited = [];
    public function find($type = 'first', $options = [])
    {
        return $this->rows[$options['conditions']['Event.uuid']] ?? [];
    }
    private function remember($event)
    {
        $this->rows[$event['Event']['uuid']] = ['Event' => array_intersect_key($event['Event'], array_flip(['uuid', 'timestamp']))];
    }
    public function _add($event, $fromXml, $user) { $this->added[] = $event['Event']['uuid']; $this->remember($event); return true; }
    public function _edit($event, $user, $uuid = null, $jobId = null) { $this->edited[] = $event['Event']['uuid']; $this->remember($event); return true; }
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
    private $temporary;

    protected function setUp(): void
    {
        $this->temporary = sys_get_temp_dir() . '/gathering-test-' . bin2hex(random_bytes(12));
        mkdir($this->temporary, 0700);
        if (!is_dir(APP . 'tmp')) { mkdir(APP . 'tmp', 0700, true); }
    }
    protected function tearDown(): void { GatheringFeedWorkspace::removeDirectory($this->temporary); }

    private function event($timestamp = '1790856000', $uuid = self::UUID)
    {
        return ['Event' => ['uuid' => $uuid, 'info' => 'Gathered configuration', 'date' => '2026-10-01',
            'timestamp' => $timestamp, 'distribution' => '0', 'Orgc' => ['name' => 'Example', 'uuid' => '55172297-0240-5b08-b452-b0466a829b1e']]];
    }
    private function archive($timestamp = '1790856000', $entries = null)
    {
        $path = $this->temporary . '/source-' . bin2hex(random_bytes(6)) . '.zip';
        $zip = new ZipArchive();
        $this->assertTrue($zip->open($path, ZipArchive::CREATE) === true);
        $entries = $entries ?? ['manifest.json' => '{}', self::UUID . '.json' => json_encode($this->event($timestamp))];
        foreach ($entries as $name => $contents) { $zip->addFromString($name, $contents); }
        $zip->close();
        return $path;
    }
    private function descriptor($path, $status = 'ready')
    {
        return ['gathering_version' => 2, 'source_format' => 'misp', 'job_id' => str_repeat('a', 64),
            'status' => $status, 'archive_size' => filesize($path), 'sha256' => hash_file('sha256', $path)];
    }
    private function options($name = 'withaname') { return ['module' => $name, 'parameters' => ['max_events' => 0]]; }
    private function user() { return ['id' => 1, 'Role' => ['perm_site_admin' => 1]]; }
    private function module($name = 'withaname', $timestamp = '1790856000')
    {
        Configure::write('Plugin.Gathering_' . $name . '_enabled', true);
        Configure::write('Plugin.Gathering_' . $name . '_restrict', 0);
        $module = new GatheringTestModule();
        $module->descriptors = [['name' => $name, 'meta' => ['module-type' => ['gathering'], 'config' => []],
            'mispattributes' => ['gathering_version' => 2]]];
        $module->archivePath = $this->archive($timestamp);
        $module->answer = $this->descriptor($module->archivePath);
        return $module;
    }
    private function feed($module)
    {
        ClassRegistry::$instances['Module'] = $module;
        ClassRegistry::$instances['MispAttribute'] = new stdClass();
        $feed = new GatheringTestFeed();
        $feed->record = ['Feed' => ['id' => 123, 'url' => 'misp-modules://withaname', 'input_source' => 'misp-modules',
            'source_format' => 'misp', 'rules' => '', 'distribution' => 0, 'sharing_group_id' => 0,
            'tag_id' => 0, 'tag_collection_id' => 0, 'settings' => json_encode(['gathering' => $this->options()])]];
        return $feed;
    }
    public function testContractWorksForFutureProducersAndUsesSmallJobResponses()
    {
        foreach (['withaname', 'another_source'] as $name) {
            $module = $this->module($name);
            $answer = $module->queryGathering($name, [], $this->user());
            $this->assertSame('ready', GatheringFeedTool::job($answer)['status']);
            $this->assertSame('Gathering', $module->calls[0]['moduleFamily']);
            $this->assertSame($name, $module->calls[0]['postData']['module']);
            $this->assertSame('{}', json_encode($module->calls[0]['postData']['parameters']));
            $this->assertArrayNotHasKey('events', $answer);
        }
    }
    public function testDisabledAndRestrictedModulesCannotExecute()
    {
        $module = $this->module();
        Configure::write('Plugin.Gathering_withaname_enabled', false);
        try { $module->queryGathering('withaname', [], $this->user()); $this->fail('Disabled module executed'); }
        catch (InvalidArgumentException $e) { $this->assertSame([], $module->calls); }
        Configure::write('Plugin.Gathering_withaname_enabled', true);
        Configure::write('Plugin.Gathering_withaname_restrict', 42);
        $this->expectException(InvalidArgumentException::class);
        $module->queryGathering('withaname', [], ['id' => 1, 'org_id' => 7, 'Role' => ['perm_site_admin' => 0]]);
    }
    public function testPreparePollsExtractsAndCleansBothEnds()
    {
        $module = $this->module();
        $ready = $module->answer;
        $module->answer['status'] = 'queued';
        $module->statuses = [array_replace($ready, ['status' => 'running']), $ready];
        $workspace = GatheringFeedTool::prepare($module, $this->options(), $this->user(), $this->temporary, 5, function () {});
        $directory = $workspace->directory;
        $this->assertFileExists($workspace->feedDirectory . '/' . self::UUID . '.json');
        $this->assertFileDoesNotExist($directory . '/feed.zip');
        $workspace->close();
        $workspace->close();
        $this->assertDirectoryDoesNotExist($directory);
        $this->assertSame([str_repeat('a', 64)], $module->released);
    }
    public function testSuccessiveJobsUseExistingAddEditSkipPathsAndDoNotCreateFeedRows()
    {
        $module = $this->module();
        $events = new GatheringTestEvents();
        ClassRegistry::$instances['Event'] = $events;
        $feed = $this->feed($module);
        $first = $feed->downloadFromFeedInitiator(123, $this->user());
        $this->assertSame(1, $first['added']);
        $this->assertSame(1, $feed->downloadFromFeedInitiator(123, $this->user())['unchanged']);
        $module->archivePath = $this->archive('1790856001');
        $module->answer = $this->descriptor($module->archivePath);
        $this->assertSame(1, $feed->downloadFromFeedInitiator(123, $this->user())['updated']);
        $this->assertCount(1, $events->added);
        $this->assertCount(1, $events->edited);
        $this->assertCount(3, $module->released);
        $this->assertSame('misp-modules', $feed->record['Feed']['input_source']);
        $this->assertSame([], glob(APP . 'tmp/gathering-*'));
    }
    public function testChecksumFailureRemovesTemporaryFilesAndReleasesArtifact()
    {
        $module = $this->module();
        $module->answer['sha256'] = str_repeat('0', 64);
        try { GatheringFeedTool::prepare($module, $this->options(), $this->user(), $this->temporary); $this->fail('Bad checksum accepted'); }
        catch (UnexpectedValueException $e) {
            $this->assertSame([], glob($this->temporary . '/gathering-*'));
            $this->assertCount(1, $module->released);
        }
    }
    public function testTimeoutCancelsTheJobAndRemovesTemporaryFiles()
    {
        $module = $this->module();
        $module->answer['status'] = 'running';
        try { GatheringFeedTool::prepare($module, $this->options(), $this->user(), $this->temporary, 0); $this->fail('Expected timeout'); }
        catch (RuntimeException $e) {
            $this->assertSame([], glob($this->temporary . '/gathering-*'));
            $this->assertCount(1, $module->released);
        }
    }
    public function testGenerationFailureIsNotImported()
    {
        $module = $this->module();
        $module->answer['status'] = 'failed';
        $this->expectException(RuntimeException::class);
        GatheringFeedTool::prepare($module, $this->options(), $this->user(), $this->temporary);
    }
    public function invalidEntries()
    {
        return [[['../outside.json' => '{}']], [['/absolute.json' => '{}']], [['nested/event.json' => '{}']],
            [['manifest.json' => '{}', 'unexpected.exe' => 'payload']], [[self::UUID . '.json' => '{}']]];
    }
    /** @dataProvider invalidEntries */
    public function testUnsafeOrIncompleteArchivesAreRejected($entries)
    {
        $archive = $this->archive('1790856000', $entries);
        $this->expectException(UnexpectedValueException::class);
        GatheringFeedTool::extractArchive($archive, $this->temporary . '/feed');
    }
    public function testSymlinksAreRejected()
    {
        $archive = $this->archive();
        $zip = new ZipArchive(); $zip->open($archive);
        $zip->setExternalAttributesName(self::UUID . '.json', ZipArchive::OPSYS_UNIX, 0120777 << 16);
        $zip->close();
        $this->expectException(UnexpectedValueException::class);
        GatheringFeedTool::extractArchive($archive, $this->temporary . '/feed');
    }
    public function testParametersRemainGenericJsonObjects()
    {
        $this->assertSame(['module' => 'another_source', 'parameters' => []],
            GatheringFeedTool::settings(['gathering' => ['module' => 'another_source', 'parameters' => '{}']]));
        $this->expectException(InvalidArgumentException::class);
        GatheringFeedTool::settings(['gathering' => ['module' => 'withaname', 'parameters' => '[]']]);
    }
    public function testExpandedBudgetFailureCleansUpAndReleasesArtifact()
    {
        $module = $this->module();
        Configure::write('Plugin.Gathering_max_expanded_bytes', 1);
        try {
            GatheringFeedTool::prepare($module, $this->options(), $this->user(), $this->temporary);
            $this->fail('Expanded-size budget ignored');
        } catch (UnexpectedValueException $e) {
            $this->assertSame([], glob($this->temporary . '/gathering-*'));
            $this->assertCount(1, $module->released);
        } finally {
            Configure::write('Plugin.Gathering_max_expanded_bytes', null);
        }
    }
    public function testJanitorPreservesLiveWorkspacesAndReclaimsAbandonedOnes()
    {
        $module = $this->module();
        $workspace = GatheringFeedTool::prepare($module, $this->options(), $this->user(), $this->temporary);
        GatheringFeedWorkspace::reap($this->temporary, -1);
        $this->assertDirectoryExists($workspace->directory);
        $workspace->close();
        $abandoned = $this->temporary . '/gathering-' . str_repeat('b', 32);
        mkdir($abandoned, 0700); touch($abandoned . '/.lock'); touch($abandoned, time() - 200000);
        GatheringFeedWorkspace::reap($this->temporary);
        $this->assertDirectoryDoesNotExist($abandoned);
    }
    public function testPythonProducedArchiveCanBeIngested()
    {
        $path = getenv('GATHERING_TEST_ARCHIVE');
        if (!$path) { $this->markTestSkipped('Set GATHERING_TEST_ARCHIVE for the cross-repository check.'); }
        $module = $this->module(); $module->archivePath = $path; $module->answer = $this->descriptor($path);
        $events = new GatheringTestEvents(); ClassRegistry::$instances['Event'] = $events;
        $result = $this->feed($module)->downloadFromFeedInitiator(123, $this->user());
        $this->assertGreaterThan(0, $result['added']);
        $this->assertSame(0, $result['failed']);
    }

    /** @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testMoreThan32MiBAnd100EventsImportsWithin40MiBMemoryLimit()
    {
        ini_set('memory_limit', '40M');
        $module = $this->module();
        $path = $this->temporary . '/large.zip';
        $zip = new ZipArchive(); $zip->open($path, ZipArchive::CREATE);
        $manifest = fopen($this->temporary . '/manifest.json', 'wb');
        fwrite($manifest, '{');
        $total = 0;
        for ($index = 0; $index < 160; ++$index) {
            $uuid = sprintf('00000000-0000-5000-8000-%012d', $index);
            $event = $this->event('1790856000', $uuid);
            $metadata = $event['Event']; unset($metadata['uuid']);
            fwrite($manifest, ($index ? ',' : '') . json_encode($uuid) . ':' . json_encode($metadata));
            $event['Event']['Attribute'] = [['uuid' => sprintf('00000001-0000-5000-8000-%012d', $index),
                'type' => 'text', 'category' => 'Other', 'value' => str_repeat('x', 262144), 'to_ids' => false]];
            $file = $this->temporary . '/' . $uuid . '.json';
            file_put_contents($file, json_encode($event));
            $total += filesize($file);
            $zip->addFile($file, $uuid . '.json');
        }
        fwrite($manifest, '}'); fclose($manifest);
        $zip->addFile($this->temporary . '/manifest.json', 'manifest.json'); $zip->close();
        unset($event, $metadata);
        $module->archivePath = $path; $module->answer = $this->descriptor($path);
        ClassRegistry::$instances['Event'] = new GatheringTestEvents();
        $result = $this->feed($module)->downloadFromFeedInitiator(123, $this->user());
        $this->assertGreaterThan(33554432, $total);
        $this->assertSame(160, $result['added']);
        $this->assertSame(0, $result['failed']);
    }
}
