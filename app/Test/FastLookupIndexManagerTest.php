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
        require_once __DIR__ . '/fixtures/FastLookupPausingManager.php';
        $this->attribute = new FastLookupLifecycleAttribute();
        $this->filter = new FastLookupLifecycleFilter();
        $this->attribute->db->leaseFilter = $this->filter;
    }

    private function manager()
    {
        return $this->manager ?? ($this->manager = new FastLookupPausingManager($this->attribute, $this->filter));
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

    /** F14 fix: the cheap live-generation counters must be present without
     *  ?metrics=1, so the dashboard can warn about over-capacity/stale
     *  filters without an expensive memory measurement. */
    public function testStatusWithoutMetricsCarriesCheapFilterCountersForTheLiveGeneration()
    {
        $manager = $this->ready();
        $status = $manager->status();
        $this->assertArrayNotHasKey('statistics', $status, 'No metrics were requested.');
        $this->assertArrayHasKey('filter', $status);
        $this->assertSame([
            'capacity' => $this->liveInfo()['capacity'],
            'rate' => $this->liveInfo()['rate'],
            'inserted' => $this->liveInfo()['inserted'],
            'stale' => $this->liveInfo()['stale'],
        ], $status['filter']);
    }

    /** A never-built index has no live generation, so status() carries no
     *  counters at all (and does not attempt to read any). */
    public function testStatusOmitsFilterCountersWithoutALiveGeneration()
    {
        $status = $this->manager()->status();
        $this->assertSame('unavailable', $status['status']);
        $this->assertArrayNotHasKey('filter', $status);
    }

    /** A metadata() failure while the cheap counters are being fetched for
     *  an early-return status (here: a pending batch) must be swallowed:
     *  the reported status/message stand, `filter` is simply left off. */
    public function testStatusSwallowsFilterMetadataFailureDuringPendingRevision()
    {
        $manager = $this->ready();
        $key = FastLookupIndexManager::STATE_SETTING;
        $state = json_decode($this->attribute->db->settings[$key], true);
        $state['pending_revision'] = $state['revision'];
        $this->attribute->db->settings[$key] = json_encode($state);
        $this->filter->available = false;
        $status = $manager->status();
        $this->assertSame('updating', $status['status']);
        $this->assertArrayNotHasKey('filter', $status);
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

    public function testScanRunsOutsideCheckpointTransactionUnderWorkerLease()
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
            $this->assertTrue($scan['worker_lease'], 'The worker lease keeps the scan exclusive.');
        }
        $this->assertNotEmpty($db->refreshes);
        foreach ($db->refreshes as $refresh) {
            $this->assertTrue($refresh['transaction'], 'Dirty events drain under the checkpoint row lock.');
        }
        $this->assertGreaterThan(0, $this->filter->leaseRenewals, 'The scan renews its lease.');
        $this->assertFalse($this->filter->leaseHeld(), 'Every batch releases the worker lease.');
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

    public function testBusyWorkerLeaseSkipsBatchWithoutTouchingState()
    {
        $this->seed();
        $manager = $this->manager();
        $manager->startRebuild();
        $before = $this->attribute->db->settings;
        $this->filter->holdLease('other-worker');
        $this->assertSame('warming', $manager->runBatch(1)['status']);
        $this->assertSame($before, $this->attribute->db->settings);
        $this->assertSame([], $this->attribute->db->scans);
        $this->assertSame(FastLookupIndexManager::WORKER_LOCK_WAIT * 1000, array_sum($manager->pauses), 'A rebuild batch waits its turn, then gives up.');
        try {
            $manager->startRebuild();
            $this->fail('A rebuild must not replace a build another worker is scanning.');
        } catch (RuntimeException $e) {
        }
        $this->assertSame($before, $this->attribute->db->settings);
        $this->assertSame('other-worker', $this->filter->lease['token'], "Another worker's lease is never released.");
        $this->filter->lease = null;
        $this->assertSame('ready', $manager->runBatch(1)['status']);
    }

    public function testPendingWorkerNeverWaitsForBusyWorkerLease()
    {
        $manager = $this->ready();
        $manager->startRebuild();
        FastLookupIndexManager::recordChange($this->attribute, '1');
        $db = $this->attribute->db;
        $this->filter->holdLease('other-worker');
        $this->filter->leaseAttempts = [];
        $manager->pauses = [];
        $before = $db->settings;
        $this->assertSame('updating', $manager->processPending()['status'], 'The marker stays queued for the next dispatch.');
        $this->assertCount(1, $this->filter->leaseAttempts, 'Request-shutdown dispatch tries the lease once.');
        $this->assertSame([], $manager->pauses, 'Request-shutdown dispatch must not block behind a rebuild scan.');
        $this->assertSame($before, $db->settings);
        $manager->runBatch(1);
        $retries = FastLookupIndexManager::WORKER_LOCK_WAIT * 1000 / FastLookupIndexManager::WORKER_LEASE_RETRY_MS;
        $this->assertCount(2 + $retries, $this->filter->leaseAttempts, 'Rebuild batches still wait their turn.');
        $this->assertCount($retries, $manager->pauses);
        $this->filter->lease = null;
        $this->assertSame('ready', $manager->processPending()['status']);
    }

    public function testBatchRunsOnceAnotherWorkerReleasesItsLease()
    {
        $this->seed();
        $manager = $this->manager();
        $manager->startRebuild();
        $this->filter->holdLease('other-worker');
        $this->filter->releaseOtherLeaseAfter = 3;
        $this->assertSame('ready', $manager->runBatch(1)['status']);
        $this->assertSame([FastLookupIndexManager::WORKER_LEASE_RETRY_MS, FastLookupIndexManager::WORKER_LEASE_RETRY_MS, FastLookupIndexManager::WORKER_LEASE_RETRY_MS], $manager->pauses);
        $this->assertFalse($this->filter->leaseHeld());
    }

    public function testExpiredWorkerLeaseIsTakenOver()
    {
        $this->seed();
        $manager = $this->manager();
        $manager->startRebuild();
        // A worker died holding the lease; it lapses after its TTL.
        $this->filter->holdLease('dead-worker');
        $this->filter->clock += FastLookupIndexManager::WORKER_LEASE_TTL_MS;
        $this->assertSame('ready', $manager->runBatch(1)['status']);
        $this->assertSame([], $manager->pauses);
    }

    /** Another worker takes the lease once the scan has added its first rows. */
    private function loseLeaseDuringScan(?Throwable $failure = null, bool $redisDown = false)
    {
        $this->attribute->db->scans = [];
        $this->filter->afterWrite = function () use ($failure, $redisDown) {
            if (!$this->attribute->db->scans) { return; }
            $this->filter->afterWrite = null;
            $this->filter->clock += FastLookupIndexManager::WORKER_LEASE_TTL_MS;
            $this->filter->holdLease('other-worker');
            if ($redisDown) { $this->filter->available = false; }
            if ($failure) { throw $failure; }
        };
    }

    public function testLeaseLostDuringRebuildScanStopsBeforeRecordingProgress()
    {
        $manager = $this->ready();
        $manager->startRebuild();
        $building = $this->filter->meta['building'];
        $before = $this->sqlState()['build'];
        $this->loseLeaseDuringScan();
        $status = $manager->runBatch(1);
        $this->assertSame('ready', $status['status'], 'The live generation keeps serving.');
        $build = $this->sqlState()['build'];
        $this->assertSame($building, $build['generation']);
        $this->assertSame($before['cursor'], $build['cursor'], 'A worker without the lease never records scan progress.');
        $this->assertSame($before['processed'], $build['processed']);
        $this->assertFalse($build['scan_complete']);
        $this->assertNull($build['error'], "Another worker's build is not failed.");
        $this->assertEmpty($this->sqlState()['error'] ?? null);
        $this->assertSame('0', $this->filter->generations[$building]['info']['cursor'], 'The Redis cursor is not advanced either.');
        $this->assertSame('other-worker', $this->filter->lease['token'], "The new holder's lease is left alone.");
        $this->filter->lease = null;
        $manager->runBatch(1);
        $this->assertSame('ready', $manager->runBatch(1)['status']);
        $this->assertSame($building, $this->filter->meta['live'], 'Later batches rescan from the SQL cursor and activate.');
        $this->assertSame(['10', '20'], $this->filter->liveIds());
    }

    public function testLeaseLostDuringFirstBuildScanNeverActivates()
    {
        $this->seed();
        $manager = $this->manager();
        $manager->startRebuild();
        $this->loseLeaseDuringScan();
        $this->assertSame('warming', $manager->runBatch(1)['status']);
        $this->assertNull($this->filter->meta['live'], 'A worker without the lease never activates a generation.');
        $this->assertFalse($this->sqlState()['build']['scan_complete']);
        $this->filter->lease = null;
        $this->assertSame('ready', $manager->runBatch(1)['status']);
        $this->assertSame(['10', '20'], $this->filter->liveIds());
    }

    public function testWorkerThatLostItsLeaseNeverRecordsAFailure()
    {
        $manager = $this->ready();
        $manager->startRebuild();
        $this->loseLeaseDuringScan(new RuntimeException('Generation changed'));
        $manager->runBatch(1);
        $state = $this->sqlState();
        $this->assertNull($state['build']['error'], 'Only the lease holder may fail the build.');
        $this->assertTrue($state['build']['reserved']);
        $this->assertEmpty($state['error'] ?? null);
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

    public function testFirstBuildWithUnreachableRedisIsReportedUnavailableWithoutSqlWrites()
    {
        $this->seed();
        $manager = $this->manager();
        $manager->startRebuild();
        $before = $this->attribute->db->settings;
        $this->filter->available = false;
        $this->assertSame('unavailable', $manager->runBatch(1)['status'], 'A failing first build must not look like progress.');
        $this->assertSame($before, $this->attribute->db->settings, 'A worker without the lease writes nothing to SQL.');
        $this->filter->available = true;
        $this->assertSame('ready', $manager->runBatch(1)['status']);
    }

    /** @dataProvider leaseRefusalCases */
    public function testRefusedLeaseWriteIsTerminalWithoutSqlWrites(bool $live)
    {
        $this->seed();
        $manager = $live ? $this->ready() : $this->manager();
        $manager->startRebuild();
        $before = $this->attribute->db->settings;
        $this->filter->refuseLeaseWrites = true;
        foreach ([$manager->runBatch(1), $manager->processPending()] as $status) {
            $this->assertSame('unavailable', $status['status'], 'Reads still work, so only the refused lease can stop the CLI loops.');
            $this->assertNotNull($status['build']);
            $this->assertStringNotContainsString('OOM', $status['message']);
        }
        $this->assertSame($before, $this->attribute->db->settings, 'A worker without the lease writes nothing to SQL.');
        $this->filter->refuseLeaseWrites = false;
        $this->assertNotSame('unavailable', $manager->runBatch(1)['status']);
    }

    public function leaseRefusalCases(): array
    {
        return ['first build' => [false], 'rebuild beside a live generation' => [true]];
    }

    public function testWorkerThatLostItsLeaseToARedisOutageNeverRecordsAFailure()
    {
        $manager = $this->ready();
        $manager->startRebuild();
        $this->loseLeaseDuringScan(new RuntimeException('Redis timed out'), true);
        $manager->runBatch(1);
        $state = $this->sqlState();
        $this->assertNull($state['build']['error'], 'Past its lease deadline a worker cannot tell whether it still holds the lease.');
        $this->assertTrue($state['build']['reserved']);
        $this->assertEmpty($state['error'] ?? null);
    }

    public function testRedisFailureWithinTheLeaseIsRecorded()
    {
        $manager = $this->ready();
        $manager->startRebuild();
        $this->attribute->db->scans = [];
        $this->filter->afterWrite = function () {
            if (!$this->attribute->db->scans) { return; }
            $this->filter->afterWrite = null;
            $this->filter->available = false;
            throw new RuntimeException('Redis timed out');
        };
        $manager->runBatch(1);
        $this->assertSame(FastLookupIndexManager::BUILD_FAILED, $this->sqlState()['build']['error']);
    }

    public function testStaleFailureNeverFailsABuildAnotherHolderAdvanced()
    {
        $manager = $this->ready();
        $manager->startRebuild();
        $this->attribute->db->scans = [];
        $this->filter->afterWrite = function () {
            if (!$this->attribute->db->scans) { return; }
            $this->filter->afterWrite = null;
            // Another holder recorded progress; this worker still believes
            // its lease is current (it slipped past its last renewal).
            $state = $this->sqlState();
            $state['build']['cursor'] = '15';
            $this->attribute->db->settings[FastLookupIndexManager::STATE_SETTING] = json_encode($state);
            throw new RuntimeException('Generation changed');
        };
        $manager->runBatch(1);
        $build = $this->sqlState()['build'];
        $this->assertNull($build['error'], "A failure is recorded only against the build the failed step started from.");
        $this->assertSame('15', $build['cursor']);
    }

    public function testBuildFailureIsRecordedAgainstTheUnchangedBuild()
    {
        $manager = $this->ready();
        $manager->startRebuild();
        $this->attribute->db->scans = [];
        $this->filter->afterWrite = function () {
            if (!$this->attribute->db->scans) { return; }
            $this->filter->afterWrite = null;
            throw new RuntimeException('Interrupted write');
        };
        $manager->runBatch(1);
        $build = $this->sqlState()['build'];
        $this->assertSame(FastLookupIndexManager::BUILD_FAILED, $build['error']);
        $this->assertFalse($build['reserved']);
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
