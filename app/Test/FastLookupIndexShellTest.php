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
        $attribute->db->attributes = [
            ['id' => '11', 'event_id' => '1', 'type' => 'domain', 'value1' => 'one.test', 'value2' => '', 'deleted' => false],
            ['id' => '19', 'event_id' => '9', 'type' => 'domain', 'value1' => 'nine.test', 'value2' => '', 'deleted' => false],
        ];
        ClassRegistry::$attribute = $attribute;
        $shell = new AdminShell();
        $shell->MispAttribute = $attribute;
        $shell->Job = new Job();
        $shell->args = ['5', '1'];
        $this->assertTrue(method_exists($shell, 'rebuildFastLookup'), 'The admin shell exposes persistent IOC backfill.');
        $shell->rebuildFastLookup();
        $status = json_decode(end($shell->output), true);
        $this->assertSame('ready', $status['status']);
        $this->assertSame(2, $status['progress']['processed_attributes']);
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

    private function brokenLiveDuringBuild()
    {
        $attribute = new FastLookupLifecycleAttribute();
        $attribute->db->events = ['1' => true];
        $attribute->db->attributes = [['id' => '11', 'event_id' => '1', 'type' => 'domain', 'value1' => 'one.test', 'value2' => '', 'deleted' => false]];
        ClassRegistry::$attribute = $attribute;
        $manager = new FastLookupIndexManager($attribute);
        $manager->startRebuild();
        $manager->runBatch(1);
        $manager->startRebuild();
        // Redis restored from an older snapshot: the live checkpoint no longer matches.
        $filter = new FastLookupFilter();
        $filter->meta['revision'] = 'restored';
        return $attribute;
    }

    public function testResumeStopsOnErrorWhileBuildIsActive()
    {
        $attribute = $this->brokenLiveDuringBuild();
        $shell = new AdminShell();
        $shell->MispAttribute = $attribute;
        $shell->Job = new Job();
        $shell->args = ['5', '1'];
        try {
            $shell->resumeFastLookup();
            $this->fail('A failing index must fail the job.');
        } catch (RuntimeException $e) {
            $this->assertNotSame('The IOC index loop did not stop.', $e->getMessage());
        }
        $this->assertFalse($shell->Job->success);
        $this->assertLessThan(3, $shell->Job->progress);
    }

    public function testResumeStopsWhenRedisIsUnreachableDuringFirstBuild()
    {
        $attribute = new FastLookupLifecycleAttribute();
        $attribute->db->events = ['1' => true];
        $attribute->db->attributes = [['id' => '11', 'event_id' => '1', 'type' => 'domain', 'value1' => 'one.test', 'value2' => '', 'deleted' => false]];
        ClassRegistry::$attribute = $attribute;
        (new FastLookupIndexManager($attribute))->startRebuild();
        $redis = new FastLookupFilter();
        $redis->available = false;
        $before = $attribute->db->settings;
        $shell = new AdminShell();
        $shell->MispAttribute = $attribute;
        $shell->Job = new Job();
        $shell->args = ['5', '1'];
        try {
            $shell->resumeFastLookup();
            $this->fail('An unreachable Redis must fail the job.');
        } catch (RuntimeException $e) {
            $this->assertNotSame('The IOC index loop did not stop.', $e->getMessage());
        }
        $this->assertFalse($shell->Job->success);
        $this->assertLessThan(3, $shell->Job->progress);
        $this->assertSame($before, $attribute->db->settings, 'No SQL state is written without the lease.');
    }

    private function refusedLease(bool $live)
    {
        $attribute = new FastLookupLifecycleAttribute();
        $attribute->db->events = ['1' => true];
        $attribute->db->attributes = [['id' => '11', 'event_id' => '1', 'type' => 'domain', 'value1' => 'one.test', 'value2' => '', 'deleted' => false]];
        ClassRegistry::$attribute = $attribute;
        $manager = new FastLookupIndexManager($attribute);
        $manager->startRebuild();
        if ($live) {
            $manager->runBatch(1);
            $manager->startRebuild();
            FastLookupIndexManager::recordChange($attribute, '1');
        }
        $redis = new FastLookupFilter();
        $redis->refuseLeaseWrites = true;
        return $attribute;
    }

    /** @dataProvider liveCases */
    public function testResumeStopsWhenRedisRefusesTheLease(bool $live)
    {
        $attribute = $this->refusedLease($live);
        $before = $attribute->db->settings;
        $shell = new AdminShell();
        $shell->MispAttribute = $attribute;
        $shell->Job = new Job();
        $shell->args = ['5', '1'];
        try {
            $shell->resumeFastLookup();
            $this->fail('A refused lease must fail the job.');
        } catch (RuntimeException $e) {
            $this->assertNotSame('The IOC index loop did not stop.', $e->getMessage());
        }
        $this->assertFalse($shell->Job->success);
        $this->assertLessThan(3, $shell->Job->progress);
        $this->assertSame($before, $attribute->db->settings);
    }

    /** @dataProvider liveCases */
    public function testPendingWorkerDoesNotRequeueWhenRedisRefusesTheLease(bool $live)
    {
        $attribute = $this->refusedLease($live);
        Configure::$values['MISP.background_jobs'] = true;
        $before = $attribute->db->settings;
        $shell = new AdminShell();
        $shell->MispAttribute = $attribute;
        $shell->Job = new Job();
        $shell->args = ['7', '1'];
        try {
            $shell->processFastLookup();
            $this->fail('A refused lease must fail the job.');
        } catch (RuntimeException $e) {
        }
        $this->assertSame([], $shell->Job->tool->queued, 'The job never requeues itself behind a refused lease.');
        $this->assertFalse($shell->Job->success);
        $this->assertSame($before, $attribute->db->settings);
    }

    public function liveCases(): array
    {
        return ['first build' => [false], 'rebuild beside a live generation' => [true]];
    }

    public function testPendingWorkerDoesNotRequeueOnErrorWhileBuildIsActive()
    {
        $attribute = $this->brokenLiveDuringBuild();
        Configure::$values['MISP.background_jobs'] = true;
        $shell = new AdminShell();
        $shell->MispAttribute = $attribute;
        $shell->Job = new Job();
        $shell->args = ['7', '1'];
        try {
            $shell->processFastLookup();
            $this->fail('A failing index must fail the job.');
        } catch (RuntimeException $e) {
        }
        $this->assertSame([], $shell->Job->tool->queued);
        $this->assertFalse($shell->Job->success);
    }
}
