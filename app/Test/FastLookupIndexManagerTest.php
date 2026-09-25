<?php
use PHPUnit\Framework\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class FastLookupIndexManagerTest extends TestCase
{
    private $attribute;
    private $index;
    private $manager;

    protected function setUp(): void
    {
        require_once __DIR__ . '/fixtures/FastLookupLifecycleStubs.php';
        if (is_file(__DIR__ . '/../Lib/Tools/FastLookupIndexManager.php')) {
            require_once __DIR__ . '/../Lib/Tools/FastLookupIndexManager.php';
        }
        $this->attribute = new FastLookupLifecycleAttribute();
        $this->index = new FastLookupLifecycleIndex();
    }

    private function manager()
    {
        $this->assertTrue(class_exists('FastLookupIndexManager'), 'The persistent index lifecycle manager exists.');
        return $this->manager ?? ($this->manager = new FastLookupIndexManager($this->attribute, $this->index));
    }

    private function seed()
    {
        $this->attribute->db->events = ['1' => true, '4' => true, '8' => false];
        $this->attribute->db->attributes = [
            ['id' => '10', 'event_id' => '1', 'type' => 'domain', 'value1' => 'one.test', 'value2' => '', 'deleted' => false],
            ['id' => '20', 'event_id' => '4', 'type' => 'domain', 'value1' => 'two.test', 'value2' => '', 'deleted' => false],
        ];
    }

    private function ready()
    {
        $this->seed();
        $manager = $this->manager();
        $manager->startRebuild();
        for ($i = 0; $i < 5 && $manager->status()['status'] !== 'ready'; $i++) {
            $manager->runBatch(2);
        }
        $this->assertSame('ready', $manager->status()['status']);
        return $manager;
    }

    public function testMissingIndexRequiresBackfillInsteadOfReturningReady()
    {
        $status = $this->manager()->status();
        $this->assertSame('unavailable', $status['status']);
        $this->assertSame(['domain'], $status['scope']['attribute_types']);
    }

    public function testBackfillResumesByEventIdAndOnlyReadiesCompleteScope()
    {
        $this->seed();
        $manager = $this->manager();
        $this->assertSame('warming', $manager->startRebuild()['status']);
        $first = $manager->runBatch(1);
        $this->assertSame('warming', $first['status']);
        $this->assertSame(1, $first['progress']['processed_events']);
        $this->assertSame(2, $first['progress']['total_events']);
        $manager->runBatch(1);
        $status = $manager->runBatch(1);
        $this->assertSame('ready', $status['status']);
        $this->assertSame(['10'], array_column($this->index->events['1'], 'id'));
        $this->assertSame(['20'], array_column($this->index->events['4'], 'id'));
        $this->assertArrayNotHasKey('8', $this->index->events);
    }

    public function testOutboxRollsBackWithCallerAndNeverCommitsCallerTransaction()
    {
        $manager = $this->ready();
        $db = $this->attribute->db;
        $db->beginTransaction();
        FastLookupIndexManager::recordChange($this->attribute, '1');
        $this->assertTrue($db->inTransaction());
        $this->assertSame('updating', $manager->status()['status']);
        $db->rollBack();
        $this->assertSame('ready', $manager->status()['status']);
    }

    public function testChangesRemainDurableWhenRedisIsUnavailableAndEndpointDisabled()
    {
        $manager = $this->ready();
        Configure::$values['MISP.fast_lookup_enabled'] = false;
        $this->index->available = false;
        FastLookupIndexManager::recordChange($this->attribute, '1');
        $this->index->available = true;
        $this->assertSame('updating', $manager->status()['status']);
        unset($this->attribute->db->events['1']);
        $this->assertSame('ready', $manager->processPending()['status']);
        $this->assertArrayNotHasKey('1', $this->index->events);
    }

    public function testRestoredOldRedisCheckpointRefusesResultsAndIncrementalRepair()
    {
        $manager = $this->ready();
        $old = $this->index->meta;
        FastLookupIndexManager::recordChange($this->attribute, '1');
        $manager->processPending();
        $this->index->meta = $old;
        $this->assertNotSame('ready', $manager->status()['status']);
        $this->assertNotSame('ready', $manager->processPending()['status']);
    }

    public function testInterruptedBatchCanResumeWithoutLosingCompletedBackfillProgress()
    {
        $this->seed();
        $manager = $this->manager();
        $manager->startRebuild();
        $manager->runBatch(1);
        $this->index->failNextWrite = true;
        $this->assertNotSame('ready', $manager->runBatch(1)['status']);
        $this->assertSame(1, $manager->status()['progress']['processed_events']);
        $manager->runBatch(1);
        $this->assertSame('ready', $manager->runBatch(1)['status']);
        $this->assertCount(2, $this->index->events);
    }

    public function testInterruptedInitialisationResumesWithFreshGeneration()
    {
        $this->seed();
        $manager = $this->manager();
        $this->index->failInitialise = true;
        $this->assertSame('error', $manager->startRebuild()['status']);
        $partialGeneration = $this->index->meta['generation'];
        $this->assertSame('ready', $manager->runBatch(3)['status']);
        $this->assertNotSame($partialGeneration, $this->index->meta['generation']);
    }

    public function testBackfillMetricsRemainAvailableBeforeReadiness()
    {
        $this->seed();
        $manager = $this->manager();
        $manager->startRebuild();
        $status = $manager->status(true);
        $this->assertSame('warming', $status['status']);
        $this->assertArrayHasKey('statistics', $status);
        $this->index->failNextWrite = true;
        $manager->runBatch(1);
        $status = $manager->status(true);
        $this->assertSame('error', $status['status']);
        $this->assertArrayHasKey('statistics', $status);
    }

    public function testNewDirtyRevisionIsNotAcknowledgedByOlderRefresh()
    {
        $manager = $this->ready();
        FastLookupIndexManager::recordChange($this->attribute, '1');
        $this->index->afterWrite = function () {
            $this->index->afterWrite = null;
            FastLookupIndexManager::recordChange($this->attribute, '1');
        };
        $this->assertSame('updating', $manager->processPending(1)['status']);
        $this->assertSame('ready', $manager->processPending(1)['status']);
    }

    public function testScopeMismatchRequiresNewBackfillAndSnapshotFenceDetectsChange()
    {
        $manager = $this->ready();
        $snapshot = $manager->status();
        $this->assertTrue($manager->isCurrent($snapshot));
        FastLookupConfig::$fingerprint = 'new-scope';
        $this->assertFalse($manager->isCurrent($snapshot));
        $this->assertNotSame('ready', $manager->status()['status']);
    }

    public function testWorkerRefusesCallerTransactionWithoutCommittingIt()
    {
        $manager = $this->ready();
        $this->attribute->db->beginTransaction();
        try {
            $manager->runBatch();
            $this->fail('A worker must not run inside an unrelated transaction.');
        } catch (LogicException $e) {
            $this->assertTrue($this->attribute->db->inTransaction());
        } finally {
            $this->attribute->db->rollBack();
        }
    }

    public function testEventSaveCallbackRecordsDirectPublicationAndUnpublication()
    {
        $manager = $this->ready();
        require_once __DIR__ . '/fixtures/FastLookupLifecycleModelStubs.php';
        Configure::$values['MISP.completely_disable_correlation'] = true;
        $event = new Event();
        $event->db = $this->attribute->db;
        $event->data = ['Event' => ['id' => '1', 'published' => 1, 'unpublishAction' => true]];
        $event->afterSave(false);
        $this->assertSame('updating', $manager->status()['status']);
        $manager->processPending();
        $event->data['Event']['published'] = 0;
        $event->afterSave(false);
        $this->assertSame('updating', $manager->status()['status']);
    }

    public function testEventDeleteCallbackCoversQuickDeleteWithoutAttributeCallbacks()
    {
        $manager = $this->ready();
        require_once __DIR__ . '/fixtures/FastLookupLifecycleModelStubs.php';
        $event = new Event();
        $event->db = $this->attribute->db;
        $event->id = '1';
        $event->data = ['Event' => ['id' => '1']];
        $this->assertTrue(method_exists($event, 'afterDelete'), 'Event deletion queues removal after successful persistence.');
        $event->afterDelete();
        $this->assertSame('updating', $manager->status()['status']);
    }

    public function testAttributeCallbacksRecordChangesEvenDuringFastUpdate()
    {
        $manager = $this->ready();
        require_once __DIR__ . '/fixtures/FastLookupLifecycleModelStubs.php';
        $attribute = (new ReflectionClass(MispAttribute::class))->newInstanceWithoutConstructor();
        $attribute->db = $this->attribute->db;
        $attribute->fast_update = true;
        $attribute->data = ['Attribute' => ['id' => '10', 'uuid' => 'test', 'type' => 'domain', 'event_id' => '1']];
        $attribute->afterSave(false);
        $this->assertSame('updating', $manager->status()['status']);
        $manager->processPending();
        $attribute->data = ['Attribute' => ['type' => 'domain', 'event_id' => '1', 'deleted' => true]];
        $attribute->afterDelete();
        $this->assertSame('updating', $manager->status()['status']);
    }
}
