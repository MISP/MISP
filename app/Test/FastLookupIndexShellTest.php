<?php
use PHPUnit\Framework\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class FastLookupIndexShellTest extends TestCase
{
    protected function setUp(): void
    {
        require_once __DIR__ . '/fixtures/FastLookupLifecycleStubs.php';
        require_once __DIR__ . '/fixtures/FastLookupLifecycleShellStubs.php';
        require_once __DIR__ . '/../Lib/Tools/FastLookupIndexManager.php';
        require_once __DIR__ . '/../Console/Command/AdminShell.php';
    }

    public function testCliRebuildDrainsBackfillAndReportsReady()
    {
        $attribute = new FastLookupLifecycleAttribute();
        $attribute->db->events = ['1' => true, '9' => true];
        ClassRegistry::$attribute = $attribute;
        $shell = new AdminShell();
        $shell->MispAttribute = $attribute;
        $shell->Job = new Job();
        $shell->args = ['5', '1'];
        $this->assertTrue(method_exists($shell, 'rebuildFastLookup'), 'The admin shell exposes persistent IOC backfill.');
        $shell->rebuildFastLookup();
        $status = json_decode(end($shell->output), true);
        $this->assertSame('ready', $status['status']);
        $this->assertSame(2, $status['progress']['processed_events']);
        $this->assertTrue($shell->Job->success);
    }

    public function testPendingWorkerRequeuesRemainderInsteadOfSilentlyLeavingDirtyEvents()
    {
        $attribute = new FastLookupLifecycleAttribute();
        $attribute->db->events = ['1' => true, '9' => true];
        ClassRegistry::$attribute = $attribute;
        $manager = new FastLookupIndexManager($attribute);
        $manager->startRebuild();
        $manager->runBatch(3);
        FastLookupIndexManager::recordChange($attribute, '1');
        FastLookupIndexManager::recordChange($attribute, '9');
        Configure::$values['MISP.background_jobs'] = true;
        $shell = new AdminShell();
        $shell->MispAttribute = $attribute;
        $shell->Job = new Job();
        $shell->args = ['7', '1'];
        $this->assertTrue(method_exists($shell, 'processFastLookup'), 'The admin shell exposes bounded IOC updates.');
        $shell->processFastLookup();
        $this->assertSame(['processFastLookup', 7, 1], $shell->Job->tool->queued[0][2]);
        $this->assertNull($shell->Job->success);
    }
}
