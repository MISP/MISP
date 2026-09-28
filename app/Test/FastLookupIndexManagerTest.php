<?php
use PHPUnit\Framework\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class FastLookupIndexManagerTest extends TestCase
{
    private $attribute;
    private $filter;
    private $manager;

    protected function setUp(): void
    {
        require_once __DIR__ . '/fixtures/FastLookupLifecycleStubs.php';
        // Only for FastLookupFilter::MIN_CAPACITY; the manager runs on the fake.
        require_once __DIR__ . '/../Lib/Tools/FastLookupFilter.php';
        require_once __DIR__ . '/../Lib/Tools/FastLookupIndexManager.php';
        $this->attribute = new FastLookupLifecycleAttribute();
        $this->filter = new FastLookupLifecycleFilter();
    }

    private function manager()
    {
        return $this->manager ?? ($this->manager = new FastLookupIndexManager($this->attribute, $this->filter));
    }

    private function seed()
    {
        $this->attribute->db->events = ['1' => true, '4' => true, '8' => false];
        $this->attribute->db->attributes = [
            ['id' => '10', 'event_id' => '1', 'type' => 'domain', 'value1' => 'one.test', 'value2' => '', 'deleted' => false],
            ['id' => '20', 'event_id' => '4', 'type' => 'domain', 'value1' => 'two.test', 'value2' => '', 'deleted' => false],
            ['id' => '30', 'event_id' => '8', 'type' => 'domain', 'value1' => 'draft.test', 'value2' => '', 'deleted' => false],
            ['id' => '40', 'event_id' => '1', 'type' => 'domain', 'value1' => 'gone.test', 'value2' => '', 'deleted' => true],
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

    private function liveInfo()
    {
        return $this->filter->metadata()['generations'][$this->filter->meta['live']];
    }

    public function testMissingIndexRequiresBackfillInsteadOfReturningReady()
    {
        $status = $this->manager()->status();
        $this->assertSame('unavailable', $status['status']);
        $this->assertSame(['domain'], $status['scope']['attribute_types']);
    }

    public function testFirstBuildScansPublishedAttributesAndBecomesReady()
    {
        $this->seed();
        $manager = $this->manager();
        $this->assertSame('warming', $manager->startRebuild()['status']);
        $status = $manager->runBatch(1);
        $this->assertSame('ready', $status['status']);
        $this->assertSame(['10', '20'], $this->filter->liveIds());
        $this->assertSame(2, $status['progress']['processed_attributes']);
        $this->assertSame(100, $status['progress']['percent']);
        $this->assertSame(FastLookupIndexManager::MIN_CAPACITY, $this->filter->reserved[0]['capacity']);
        $this->assertSame(0.001, $this->filter->reserved[0]['rate']);
        $this->assertSame(4, $this->filter->reserved[0]['rangeEntries'], 'Domain attributes, deleted ones included, size the postings.');
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
        $this->filter->available = false;
        FastLookupIndexManager::recordChange($this->attribute, '1');
        $this->filter->available = true;
        $this->assertSame('updating', $manager->status()['status']);
        unset($this->attribute->db->events['1']);
        $this->assertSame('ready', $manager->processPending()['status']);
        $this->assertSame(1, $this->liveInfo()['stale'], 'A removed event leaves stale entries for SQL to reject.');
    }

    public function testRestoredOldRedisCheckpointRefusesResultsAndIncrementalRepair()
    {
        $manager = $this->ready();
        $old = $this->filter->meta;
        FastLookupIndexManager::recordChange($this->attribute, '1');
        $manager->processPending();
        $this->filter->meta = $old;
        $this->assertNotSame('ready', $manager->status()['status']);
        $this->assertNotSame('ready', $manager->processPending()['status']);
    }

    public function testRedisSnapshotFromBetweenBatchEventsNeverBecomesReady()
    {
        $manager = $this->ready();
        FastLookupIndexManager::recordChange($this->attribute, '1');
        FastLookupIndexManager::recordChange($this->attribute, '4');
        $snapshot = null;
        $this->filter->afterWrite = function () use (&$snapshot) {
            $this->filter->afterWrite = null;
            $snapshot = [$this->filter->meta, $this->filter->generations];
        };
        $this->assertSame('ready', $manager->processPending(2)['status']);
        // Restore the Redis state from after the first of the two events.
        [$this->filter->meta, $this->filter->generations] = $snapshot;
        $this->assertNotSame('ready', $manager->status()['status']);
        $this->assertNotSame('ready', $manager->processPending()['status']);
        $this->assertNotSame('ready', $manager->status()['status']);
    }

    public function testCrashAfterFinalRedisCheckpointResumesStagedBatch()
    {
        $manager = $this->ready();
        FastLookupIndexManager::recordChange($this->attribute, '1');
        $calls = 0;
        $this->filter->afterCheckpoint = function () use (&$calls) {
            if (++$calls === 2) {
                $this->filter->afterCheckpoint = null;
                throw new RuntimeException('Interrupted before the SQL commit');
            }
        };
        $this->assertSame('error', $manager->processPending()['status']);
        $this->assertSame('ready', $manager->processPending()['status']);
    }

    public function testFailedBuildWaitsForResumeThenRestartsInFreshGeneration()
    {
        $this->seed();
        $manager = $this->manager();
        $manager->startRebuild();
        $first = $this->filter->meta['building'];
        $this->filter->failNextWrite = true;
        $this->assertSame('error', $manager->runBatch(1)['status']);
        $status = $manager->runBatch(1);
        $this->assertSame('error', $status['status'], 'A failed build waits for an operator.');
        $this->assertSame(FastLookupIndexManager::BUILD_FAILED, $status['build']['error']);
        $manager->resume();
        $manager->runBatch(1);
        $this->assertSame('ready', $manager->runBatch(1)['status']);
        $this->assertNotSame($first, $this->filter->meta['live']);
        $this->assertSame(['10', '20'], $this->filter->liveIds());
    }

    public function testInterruptedReservationRestartsInFreshGeneration()
    {
        $this->seed();
        $manager = $this->manager();
        $this->filter->failReserve = true;
        $this->assertSame('error', $manager->startRebuild()['status']);
        $manager->resume();
        $manager->runBatch(1);
        $this->assertSame('ready', $manager->runBatch(1)['status']);
        $this->assertNotSame($this->filter->reserved[0]['generation'], $this->filter->meta['live']);
    }

    public function testBackfillMetricsAreAvailableWhileWarming()
    {
        $this->seed();
        $manager = $this->manager();
        $manager->startRebuild();
        $status = $manager->status(true);
        $this->assertSame('warming', $status['status']);
        $this->assertArrayHasKey('statistics', $status);
        $this->assertSame(FastLookupIndexManager::MIN_CAPACITY, $status['statistics']['capacity']);
    }

    public function testNewDirtyRevisionIsNotAcknowledgedByOlderRefresh()
    {
        $manager = $this->ready();
        FastLookupIndexManager::recordChange($this->attribute, '1');
        $this->filter->afterWrite = function () {
            $this->filter->afterWrite = null;
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

    public function testLiveGenerationServesWhileRebuildScans()
    {
        $manager = $this->ready();
        $live = $this->filter->meta['live'];
        $status = $manager->startRebuild();
        $this->assertSame('ready', $status['status']);
        $this->assertNotNull($status['build']);
        $revision = $status['revision'];
        $manager->runBatch(1);
        $status = $manager->status();
        $this->assertSame('ready', $status['status']);
        $this->assertSame($revision, $status['revision'], 'Scan batches never invalidate in-flight lookups.');
        $status = $manager->runBatch(1);
        $this->assertSame('ready', $status['status']);
        $this->assertNull($status['build']);
        $this->assertNotSame($live, $this->filter->meta['live']);
        $this->assertArrayNotHasKey($live, $this->filter->generations);
    }

    public function testAttributeAddedDuringRebuildIsInNewGeneration()
    {
        $manager = $this->ready();
        $manager->startRebuild();
        $this->attribute->db->attributes[] = ['id' => '50', 'event_id' => '1', 'type' => 'domain', 'value1' => 'new.test', 'value2' => '', 'deleted' => false];
        FastLookupIndexManager::recordChange($this->attribute, '1');
        $manager->processPending();
        $this->assertContains('50', $this->filter->liveIds(), 'The live generation receives the change.');
        for ($i = 0; $i < 3 && $manager->status()['build'] !== null; ++$i) {
            $manager->runBatch(1);
        }
        $this->assertNull($manager->status()['build']);
        $this->assertContains('50', $this->filter->liveIds(), 'The rebuilt generation received it too.');
    }

    public function testRedisRestoreDuringBuildNeverActivatesIncompleteGeneration()
    {
        $manager = $this->ready();
        $manager->startRebuild();
        $building = $this->filter->meta['building'];
        $manager->runBatch(1);
        // Redis restored from a snapshot taken before the scan.
        $this->filter->generations[$building]['info']['cursor'] = '0';
        $manager->runBatch(1);
        $status = $manager->runBatch(1);
        $this->assertSame('ready', $status['status'], 'The live generation keeps serving.');
        $this->assertSame(FastLookupIndexManager::BUILD_FAILED, $status['build']['error']);
        $this->assertNotSame($building, $this->filter->meta['live']);
    }

    public function testEvictedBuildingFilterFailsOnlyTheBuild()
    {
        $manager = $this->ready();
        $manager->startRebuild();
        $building = $this->filter->meta['building'];
        $manager->runBatch(1);
        unset($this->filter->generations[$building]);
        FastLookupIndexManager::recordChange($this->attribute, '1');
        $failed = $manager->runBatch(1);
        $this->assertSame(FastLookupIndexManager::BUILD_FAILED, $failed['build']['error']);
        $this->assertNotSame('error', $failed['status'], 'No global update error.');
        // The pending dirty event still drains into the live generation.
        $status = $manager->runBatch(1);
        $this->assertSame('ready', $status['status'], 'The live generation keeps serving.');
        $this->assertSame(FastLookupIndexManager::BUILD_FAILED, $status['build']['error']);
        $this->assertNotSame($building, $this->filter->meta['live']);
    }

    public function testCapacityOrStaleShareSchedulesRebuild()
    {
        $manager = $this->ready();
        $live = $this->filter->meta['live'];
        $this->filter->generations[$live]['info']['inserted'] = 20000;
        $this->filter->generations[$live]['info']['stale'] = 2000;
        FastLookupIndexManager::recordChange($this->attribute, '4');
        $status = $manager->processPending();
        $this->assertSame('ready', $status['status']);
        $this->assertNotNull($status['build'], 'A 10% stale share schedules a rebuild.');

        $this->manager = null;
        $this->filter = new FastLookupLifecycleFilter();
        $this->attribute = new FastLookupLifecycleAttribute();
        $manager = $this->ready();
        $live = $this->filter->meta['live'];
        $this->filter->generations[$live]['info']['inserted'] = (int)(0.8 * FastLookupIndexManager::MIN_CAPACITY);
        FastLookupIndexManager::recordChange($this->attribute, '4');
        $this->assertNotNull($manager->processPending()['build'], 'Reaching 80% of capacity schedules a rebuild.');
    }

    public function testSmallIndexesDoNotRebuildForStaleEntries()
    {
        $manager = $this->ready();
        FastLookupIndexManager::recordChange($this->attribute, '4');
        $this->assertNull($manager->processPending()['build']);
    }

    public function testMissingRedisBloomModuleIsReported()
    {
        $manager = $this->ready();
        $this->filter->available = false;
        $this->filter->moduleAvailable = false;
        $status = $manager->status();
        $this->assertSame('unavailable', $status['status']);
        $this->assertStringContainsString('RedisBloom', $status['message']);
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

    private function sqlState()
    {
        return json_decode($this->attribute->db->settings[FastLookupIndexManager::STATE_SETTING], true);
    }

    public function testRebuildAfterLiveFilterEvictionRunsAsFirstBuild()
    {
        $manager = $this->ready();
        $old = $this->filter->meta['live'];
        unset($this->filter->generations[$old]);
        $this->assertSame('unavailable', $manager->status()['status']);
        $status = $manager->startRebuild();
        $this->assertSame('warming', $status['status'], 'Nothing is served until the new generation is complete.');
        $this->assertNull($status['generation']);
        for ($i = 0; $i < 3 && $manager->status()['status'] !== 'ready'; ++$i) {
            $manager->runBatch(1);
        }
        $this->assertSame('ready', $manager->status()['status']);
        $this->assertNotSame($old, $this->filter->meta['live']);
        $this->assertSame(['10', '20'], $this->filter->liveIds());
    }

    public function testRebuildAfterRestoredRedisCheckpointRunsAsFirstBuild()
    {
        $manager = $this->ready();
        $old = $this->filter->meta['live'];
        $restored = $this->filter->meta;
        FastLookupIndexManager::recordChange($this->attribute, '1');
        $manager->processPending();
        $this->filter->meta = $restored;
        $status = $manager->startRebuild();
        $this->assertSame('warming', $status['status']);
        $this->assertNull($this->sqlState()['generation']);
        $this->assertSame($old, $this->filter->meta['live'], 'Redis still holds the unserved old generation.');
        $manager->runBatch(1);
        $this->assertSame('ready', $manager->status()['status']);
        $this->assertNotSame($old, $this->filter->meta['live']);
        $this->assertArrayNotHasKey($old, $this->filter->generations);
        $this->assertSame(['10', '20'], $this->filter->liveIds());
    }

    public function testRebuildKeepsLiveGenerationWhenRedisIsUnreachable()
    {
        $manager = $this->ready();
        $live = $this->filter->meta['live'];
        $this->filter->available = false;
        $this->filter->moduleAvailable = false;
        try {
            $manager->startRebuild();
            $this->fail('A rebuild cannot start without Redis.');
        } catch (RuntimeException $e) {
        }
        $this->assertSame($live, $this->sqlState()['generation']);
        $this->assertNull($this->sqlState()['build']);
        $this->filter->available = true;
        $this->assertSame('ready', $manager->status()['status']);
    }

    public function testCrashAfterActivationBeforeSqlCommitCompletesActivation()
    {
        $manager = $this->ready();
        $manager->startRebuild();
        $building = $this->filter->meta['building'];
        $manager->runBatch(1);
        $calls = 0;
        $this->filter->afterCheckpoint = function () use (&$calls) {
            if (++$calls === 2) {
                $this->filter->afterCheckpoint = null;
                throw new RuntimeException('Interrupted after the swap, before the SQL commit');
            }
        };
        $this->assertSame('error', $manager->runBatch(1)['status']);
        $this->assertSame($building, $this->filter->meta['live'], 'Redis already swapped.');
        $status = $manager->runBatch(1);
        $this->assertSame('ready', $status['status']);
        $this->assertSame($building, $status['generation']);
        $this->assertNull($status['build']);
        $this->assertSame(['10', '20'], $this->filter->liveIds());
    }

    public function testActivationCleanupFailureAfterSwapCompletesActivation()
    {
        $manager = $this->ready();
        $manager->startRebuild();
        $building = $this->filter->meta['building'];
        $manager->runBatch(1);
        $this->filter->afterActivate = function () {
            $this->filter->afterActivate = null;
            throw new RuntimeException('Could not reclaim old fastLookup keys.');
        };
        $this->assertSame('error', $manager->runBatch(1)['status']);
        $status = $manager->runBatch(1);
        $this->assertSame('ready', $status['status']);
        $this->assertSame($building, $status['generation']);
        $this->assertNull($status['build']);
    }

    public function testFirstBuildCrashAfterActivationCompletesActivation()
    {
        $this->seed();
        $manager = $this->manager();
        $manager->startRebuild();
        $building = $this->filter->meta['building'];
        $this->filter->afterActivate = function () {
            $this->filter->afterActivate = null;
            throw new RuntimeException('Interrupted after the swap');
        };
        $this->assertNotSame('ready', $manager->runBatch(1)['status']);
        $this->assertNull($this->sqlState()['generation']);
        $status = $manager->runBatch(1);
        $this->assertSame('ready', $status['status']);
        $this->assertSame($building, $status['generation']);
        $this->assertSame(['10', '20'], $this->filter->liveIds());
    }

    public function testScanRunsOutsideCheckpointTransactionUnderWorkerLock()
    {
        $this->seed();
        $manager = $this->manager();
        $db = $this->attribute->db;
        $manager->startRebuild();
        $this->assertSame('ready', $manager->runBatch(1)['status']);
        $manager->startRebuild();
        FastLookupIndexManager::recordChange($this->attribute, '4');
        $this->assertSame('ready', $manager->processPending()['status']);
        $manager->runBatch(1);
        $this->assertNull($manager->status()['build']);
        $this->assertCount(2, $db->scans, 'The first build and the rebuild each scanned.');
        foreach ($db->scans as $scan) {
            $this->assertFalse($scan['transaction'], 'The scan holds no checkpoint row lock.');
            $this->assertTrue($scan['worker_lock'], 'The worker lock keeps the scan exclusive.');
        }
        $this->assertNotEmpty($db->refreshes);
        foreach ($db->refreshes as $refresh) {
            $this->assertTrue($refresh['transaction'], 'Dirty events drain under the checkpoint row lock.');
        }
        $this->assertSame(0, $db->workerLocks, 'Every batch releases the worker lock.');
    }

    public function testLiveRevisionIsCommittedBeforeRebuildScan()
    {
        $manager = $this->ready();
        $manager->startRebuild();
        FastLookupIndexManager::recordChange($this->attribute, '1');
        $this->attribute->db->scans = [];
        $during = null;
        $this->filter->afterWrite = function () use (&$during, $manager) {
            if ($this->attribute->db->scans && $during === null) {
                $during = $manager->status()['status'];
            }
        };
        $this->assertSame('ready', $manager->processPending()['status']);
        $this->filter->afterWrite = null;
        $this->assertCount(1, $this->attribute->db->scans);
        $this->assertSame('ready', $during, 'Lookups keep being served while the rebuild scans.');
    }

    public function testBusyWorkerLockSkipsBatchWithoutTouchingState()
    {
        $this->seed();
        $manager = $this->manager();
        $manager->startRebuild();
        $before = $this->attribute->db->settings;
        $this->attribute->db->workerLockBusy = true;
        $this->assertSame('warming', $manager->runBatch(1)['status']);
        $this->assertSame($before, $this->attribute->db->settings);
        $this->assertSame([], $this->attribute->db->scans);
        try {
            $manager->startRebuild();
            $this->fail('A rebuild must not replace a build another worker is scanning.');
        } catch (RuntimeException $e) {
        }
        $this->assertSame($before, $this->attribute->db->settings);
        $this->attribute->db->workerLockBusy = false;
        $this->assertSame('ready', $manager->runBatch(1)['status']);
    }

    public function testLegacyStateRowIsDeletedOnFirstActivation()
    {
        $this->seed();
        $this->attribute->db->settings[FastLookupIndexManager::LEGACY_STATE_SETTING] = '{"generation":"old"}';
        $manager = $this->manager();
        $manager->startRebuild();
        $this->assertArrayHasKey(FastLookupIndexManager::LEGACY_STATE_SETTING, $this->attribute->db->settings, 'The old index serves until the new one activates.');
        $manager->runBatch(1);
        $this->assertArrayNotHasKey(FastLookupIndexManager::LEGACY_STATE_SETTING, $this->attribute->db->settings);
    }

    public function testFirstBuildUpdateFailureIsReportedAsError()
    {
        $this->seed();
        $manager = $this->manager();
        $manager->startRebuild();
        $this->filter->available = false;
        $this->assertSame('error', $manager->runBatch(1)['status'], 'A failing first build must not look like progress.');
        $this->filter->available = true;
        $this->assertSame('ready', $manager->runBatch(1)['status']);
    }

    public function testRebuildAfterInterruptedActivationKeepsServingTheActivatedBuild()
    {
        $manager = $this->ready();
        $manager->startRebuild();
        $building = $this->filter->meta['building'];
        $manager->runBatch(1);
        $this->filter->afterActivate = function () {
            $this->filter->afterActivate = null;
            throw new RuntimeException('Interrupted after the swap');
        };
        $this->assertSame('error', $manager->runBatch(1)['status']);
        $status = $manager->startRebuild();
        $this->assertSame($building, $status['generation'], 'The rebuild completes the activation instead of starting from scratch.');
        $this->assertNotNull($status['build']);
        $this->assertSame('ready', $manager->processPending()['status']);
        $this->assertSame($building, $this->filter->meta['live']);
    }

    public function testMinimumCapacityComesFromTheFilter()
    {
        $this->assertSame(FastLookupFilter::MIN_CAPACITY, FastLookupIndexManager::MIN_CAPACITY);
    }
}
