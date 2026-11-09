<?php
use PHPUnit\Framework\TestCase;
if (!class_exists(TestCase::class)) { require_once __DIR__ . '/../Vendor/autoload.php'; }
require_once __DIR__ . '/../Lib/Tools/ModuleFeedExportTool.php';

class ModuleFeedExportToolTest extends TestCase
{
    private $root;
    private $tool;
    private $user = ['id' => 7];

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/feed-tool-' . bin2hex(random_bytes(8));
        $this->tool = new ModuleFeedExportTool($this->root);
    }
    protected function tearDown(): void
    {
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($this->root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($iterator as $item) { $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname()); }
        rmdir($this->root);
    }
    private function part($number, $value = 'example.org')
    {
        $uuid = sprintf('00000000-0000-4000-8000-%012x', $number);
        $path = $this->root . '/part-' . $number . '.zip';
        $zip = new ZipArchive(); $zip->open($path, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        $zip->addFromString($uuid . '.json', json_encode(['Event' => ['uuid' => $uuid, 'info' => 'Event',
            'Attribute' => [['type' => 'domain', 'value' => $value]]]]));
        $zip->addFromString('manifest.json', json_encode([$uuid => ['info' => 'Event', 'timestamp' => 1]]));
        $zip->addFromString('hashes.csv', md5($value) . ',' . $uuid . "\n");
        $zip->close(); $raw = file_get_contents($path); unlink($path);
        return ['data' => base64_encode($raw), 'feed_limits' => ['max_events' => 0, 'max_size_mb' => 10240]];
    }
    private function create($selection = [1,2]) { $this->tool->create(1, $this->user, 'misp_feed', $selection); }

    public function testGeneratesOneEventAtATimeAndPublishesOnlyAfterCompletion()
    {
        $this->create();
        $progress = [];
        $this->tool->generate(1, function ($id) {
            $status = $this->tool->status(1, $this->user);
            $this->assertSame('running', $status['status']);
            $this->assertFileDoesNotExist($this->root . '/1/feed.zip');
            return $this->part($id);
        }, function ($done) use (&$progress) { $progress[] = $done; });
        $path = $this->tool->artifact(1, $this->user);
        $status = $this->tool->status(1, $this->user);
        $this->assertSame('ready', $status['status']);
        $this->assertSame(2, $status['events']);
        $this->assertSame(hash_file('sha256', $path), $status['sha256']);
        $zip = new ZipArchive(); $zip->open($path);
        $manifest = json_decode($zip->getFromName('manifest.json'), true);
        $this->assertCount(2, $manifest);
        foreach ($manifest as $uuid => $metadata) { $this->assertSame($uuid, json_decode($zip->getFromName($uuid . '.json'), true)['Event']['uuid']); }
        $this->assertSame(4, $zip->numFiles); $zip->close();
        $this->assertFileDoesNotExist($this->root . '/1/request.json');
        $this->assertDirectoryDoesNotExist($this->root . '/1/work');
        $this->assertSame([1,2,2], $progress);
    }

    public function testSkipsEventsThatAreNoLongerVisible()
    {
        $this->create();
        $this->tool->generate(1, function ($id) { return $id === 1 ? null : $this->part($id); });
        $this->assertSame(1, $this->tool->status(1, $this->user)['events']);
        $this->assertSame(2, $this->tool->status(1, $this->user)['done']);
    }

    public function testOwnerIsolationForStatusAndDownload()
    {
        $this->create([1]);
        $this->tool->generate(1, fn($id) => $this->part($id));
        foreach (['status', 'artifact'] as $method) {
            try { $this->tool->$method(1, ['id' => 8]); $this->fail('Another user must not access this export'); }
            catch (RuntimeException $e) { $this->assertStringContainsString('not found', $e->getMessage()); }
        }
    }

    public function testFailureDoesNotPublishAPartialArchiveAndDeletesStagingFiles()
    {
        $this->create();
        try {
            $this->tool->generate(1, function ($id) { if ($id === 2) { throw new RuntimeException('Synthetic failure'); } return $this->part($id); });
            $this->fail('Generation should fail');
        } catch (RuntimeException $e) { $this->assertSame('Synthetic failure', $e->getMessage()); }
        $this->assertSame('failed', $this->tool->status(1, $this->user)['status']);
        $this->assertFileDoesNotExist($this->root . '/1/feed.zip');
        $this->assertDirectoryDoesNotExist($this->root . '/1/work');
        $this->assertFileDoesNotExist($this->root . '/1/feed.partial.zip');
    }

    public function testWholeSelectionCountAndSizeLimitsAreEnforcedAcrossParts()
    {
        foreach (['count', 'size'] as $kind) {
            $this->create();
            try {
                $this->tool->generate(1, function ($id) use ($kind) {
                    $part = $this->part($id, $kind === 'size' ? str_repeat('x', 600000) : 'example.org');
                    $part['feed_limits'] = ['max_events' => $kind === 'count' ? 1 : 0, 'max_size_mb' => $kind === 'size' ? 1 : 10240];
                    return $part;
                });
                $this->fail('Aggregate budget must not be reset for every event');
            } catch (RuntimeException $e) { $this->assertStringContainsString('budget', $e->getMessage()); }
            $this->assertFileDoesNotExist($this->root . '/1/feed.zip');
            foreach (glob($this->root . '/1/*') as $file) { unlink($file); } rmdir($this->root . '/1');
        }
    }

    public function testExpiryRemovesReadyArtifact()
    {
        $this->create([1]); $this->tool->generate(1, fn($id) => $this->part($id));
        $path = $this->root . '/1/status.json';
        $meta = json_decode(file_get_contents($path), true); $meta['expires'] = time() - 1;
        file_put_contents($path, json_encode($meta));
        $this->assertSame('expired', $this->tool->status(1, $this->user)['status']);
        $this->assertFileDoesNotExist($this->root . '/1/feed.zip');
    }

    public function testDuplicateWorkerDoesNotRegenerateOrDeleteCompletedExport()
    {
        $this->create([1]); $this->tool->generate(1, fn($id) => $this->part($id));
        $this->assertTrue($this->tool->generate(1, function () { $this->fail('Should not serialize twice'); }));
        $this->assertFileExists($this->tool->artifact(1, $this->user));
    }

    public function testSecondWorkerAndExpiryCleanupCannotTouchAnActiveJob()
    {
        $this->create([1]);
        $this->tool->generate(1, function ($id) {
            $this->assertFalse($this->tool->generate(1, function () { $this->fail('Another worker already owns this job'); }));
            $this->assertFalse($this->tool->fail(1, 'Must not remove an active job'));
            $this->assertSame('running', $this->tool->status(1, $this->user)['status']);
            return $this->part($id);
        });
    }

    public function testUnavailableEventsNeverPublishAnEmptyFeed()
    {
        $this->create();
        try { $this->tool->generate(1, fn() => null); $this->fail('No visible events'); }
        catch (RuntimeException $e) { $this->assertStringContainsString('No selected', $e->getMessage()); }
        $this->assertFileDoesNotExist($this->root . '/1/feed.zip');
    }

    public function testDuplicateEventPartFailsWithoutPublishing()
    {
        $this->create();
        $reply = $this->part(1);
        try { $this->tool->generate(1, fn() => $reply); $this->fail('Duplicate event identity'); }
        catch (RuntimeException $e) { $this->assertStringContainsString('Duplicate', $e->getMessage()); }
        $this->assertSame('failed', $this->tool->status(1, $this->user)['status']);
        $this->assertFileDoesNotExist($this->root . '/1/feed.zip');
    }

    public function testInterruptedJobCannotAdvertiseOrResumeAPartialFeed()
    {
        $this->create([1]);
        $path = $this->root . '/1/status.json';
        $meta = json_decode(file_get_contents($path), true); $meta['status'] = 'running';
        file_put_contents($path, json_encode($meta));
        try { $this->tool->generate(1, function () { $this->fail('Interrupted jobs require a new submission'); }); }
        catch (RuntimeException $e) { $this->assertStringContainsString('interrupted', $e->getMessage()); }
        $this->assertSame('failed', $this->tool->status(1, $this->user)['status']);
    }

    public function testPythonGeneratedPartsAreAccepted()
    {
        $path = getenv('MISP_FEED_TEST_PART');
        if (!$path) { $this->markTestSkipped('Set MISP_FEED_TEST_PART to a Python-generated one-event feed chunk.'); }
        $this->create([1]);
        $reply = json_decode(file_get_contents($path), true);
        $this->tool->generate(1, fn() => $reply);
        $this->assertFileExists($this->tool->artifact(1, $this->user));
    }
}
