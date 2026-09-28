<?php
App::uses('FastLookupConfig', 'Tools');
App::uses('FastLookupFilter', 'Tools');
App::uses('FastLookupValueTool', 'Tools');

/**
 * SQL owns the index checkpoint and mutation queue; Redis holds a derived Bloom
 * pre-filter (FastLookupFilter).
 *
 * Model callbacks write the queue on their existing connection/transaction,
 * under a share lock on the singleton SQL state row. Workers exclude each other
 * with a SQL session lock held for a whole batch, and take the state row FOR
 * UPDATE only while they drain the queue, checkpoint or activate: the rebuild
 * scan runs outside the row lock with an attribute ID cursor, so it never holds
 * writers back. Batches that change what lookups see (dirty events, a first
 * build, an activation) first commit a pending and a distinct next revision,
 * so a Redis snapshot from mid-batch never matches the committed checkpoint.
 * A rebuild writes a building generation beside the live one. Its scan batches
 * leave the live revision alone and are fenced by the attribute cursor stored
 * with the generation, so a restored Redis snapshot cannot activate an
 * incomplete filter. Dirty events go to both generations until activation.
 */
class FastLookupIndexManager
{
    const STATE_SETTING = 'fastLookupIndex:state:v3';
    const LEGACY_STATE_SETTING = 'fastLookupIndex:state:v2';
    const DIRTY_PREFIX = 'fastLookupIndex:dirty:v2:';
    const ATTRIBUTE_BATCH_SIZE = 500;
    const SCAN_BATCH_SIZE = 100;
    const PENDING_BATCH_SIZE = 25;
    /** One batch unit is one dirty event or this many scanned attributes. */
    const SCAN_ATTRIBUTES_PER_UNIT = 1000;
    const MIN_CAPACITY = FastLookupFilter::MIN_CAPACITY;
    /** Most attributes carry one or two tokens. */
    const TOKENS_PER_ATTRIBUTE = 2;
    const CAPACITY_HEADROOM = 1.5;
    /** Share of IP attributes assumed to be ranges when sizing postings. */
    const IP_RANGE_SHARE = 0.05;
    const REBUILD_AT_CAPACITY = 0.8;
    const REBUILD_AT_STALE = 0.1;
    /** Below this, stale entries cost too little to justify a rebuild. */
    const REBUILD_MIN_INSERTED = 10000;
    const IP_TYPES = ['ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port', 'domain|ip'];
    const DOMAIN_TYPES = ['domain', 'domain|ip'];
    /** Seconds a worker waits for another worker's batch before giving up. */
    const WORKER_LOCK_WAIT = 5;
    const BUILD_FAILED = 'The IOC index rebuild failed. Resume to restart it from the beginning, or start a new rebuild.';

    private $attribute;
    private $db;
    private $connection;
    private $settingsTable;
    private $filter;
    private static $dispatchModels = [];
    private static $shutdownRegistered = false;

    public function __construct($attribute = null, $filter = null)
    {
        $this->attribute = $attribute ?: ClassRegistry::init('MispAttribute');
        $this->db = $this->attribute->getDataSource();
        $this->connection = $this->db->getConnection();
        $this->settingsTable = $this->db->fullTableName('admin_settings');
        $this->filter = $filter;
    }

    public function filter()
    {
        if ($this->filter === null) {
            $this->filter = new FastLookupFilter(
                FastLookupConfig::namespaceFor($this->attribute),
                FastLookupConfig::scope($this->attribute)
            );
        }
        return $this->filter;
    }

    public function status(bool $metrics = false): array
    {
        $result = [
            'status' => 'unavailable',
            'scope' => FastLookupConfig::scope($this->attribute),
            'progress' => $this->progress([]),
            'generation' => null,
            'revision' => null,
            'build' => null,
        ];
        $measure = null;
        try {
            $state = $this->readState();
            $build = $state['build'] ?? null;
            if (!$state || (empty($state['generation']) && !$build)) {
                $result['message'] = 'The IOC index requires an administrator to start a backfill.';
                return $result;
            }
            $fingerprint = FastLookupConfig::fingerprint($this->attribute);
            if ($build) {
                $result['build'] = ['generation' => $build['generation'], 'progress' => $this->progress($build), 'error' => $build['error'] ?? null];
                $result['progress'] = $result['build']['progress'];
                $measure = empty($build['reserved']) ? null : $build['generation'];
            }
            if (empty($state['generation']) || $state['fingerprint'] !== $fingerprint) {
                if ($build && $build['fingerprint'] === $fingerprint) {
                    // A failing first build must not look like progress.
                    $failure = $build['error'] ?? $state['error'] ?? null;
                    $result['status'] = $failure === null ? 'warming' : 'error';
                    $result['message'] = $failure ?? 'The IOC index is being built.';
                } else {
                    $result['message'] = empty($state['generation'])
                        ? 'The IOC index requires an administrator to start a backfill.'
                        : 'The configured IOC scope has changed. A new backfill is required.';
                }
                return $this->includeStatistics($result, $metrics, $measure);
            }
            $result['generation'] = $state['generation'];
            $result['revision'] = $state['revision'];
            $measure = $state['generation'];
            if (!$build) {
                $result['progress'] = $this->progress($state['last_build'] ?? ['scan_complete' => true]);
            }
            if (!empty($state['error'])) {
                $result['status'] = 'error';
                $result['message'] = $state['error'];
                return $this->includeStatistics($result, $metrics, $measure);
            }
            if (!empty($state['pending_revision'])) {
                $result['status'] = 'updating';
                $result['message'] = 'An IOC index batch is in progress or awaiting resume.';
                return $this->includeStatistics($result, $metrics, $measure);
            }
            $metadata = $this->filter()->metadata();
            if (!$this->checkpointMatches($state, $metadata)) {
                $result['message'] = 'The Redis index does not match its SQL checkpoint. Rebuild the index.';
                return $this->includeStatistics($result, $metrics, $measure);
            }
            if ($this->dirtyCount() > 0) {
                $result['status'] = 'updating';
            } elseif ($metadata['ready']) {
                $result['status'] = 'ready';
            }
        } catch (Throwable $e) {
            $result['status'] = 'unavailable';
            $result['message'] = $this->moduleMissing()
                ? 'Fast lookup requires the RedisBloom module (Redis 8 or Redis Stack).'
                : 'The IOC index is unavailable. Its SQL queue has been retained.';
            $this->logFailure($e);
            return $result;
        }
        return $this->includeStatistics($result, $metrics, $measure);
    }

    public function isCurrent(array $snapshot): bool
    {
        $current = $this->status();
        return $current['status'] === 'ready' && ($snapshot['status'] ?? null) === 'ready'
            && $current['generation'] === ($snapshot['generation'] ?? null)
            && $current['revision'] === ($snapshot['revision'] ?? null);
    }

    public function startRebuild(): array
    {
        $this->requireIdleConnection();
        // Sizing only needs an estimate, so it is counted outside every lock:
        // a full count must not hold attribute writers or workers back.
        $sizing = $this->sizing(FastLookupConfig::scope($this->attribute));
        if (!$this->acquireWorkerLock()) {
            // Never replace a build another worker may be scanning.
            throw new RuntimeException('Another IOC index worker is busy. Start the rebuild again once its batch has finished.');
        }
        try {
            $this->connection->beginTransaction();
            try {
                self::insertStateIfAbsent($this->connection, $this->settingsTable);
                $state = ($this->readState(true) ?: []) + ['generation' => null, 'fingerprint' => null, 'revision' => '0',
                    'pending_revision' => null, 'next_revision' => null, 'error' => null];
                $this->discardUnservableGeneration($state);
                $state['build'] = $this->newBuild($sizing);
                $this->writeState($state);
                $this->connection->commit();
            } catch (Throwable $e) {
                $this->rollbackOwnedTransaction();
                throw $e;
            }
            // Reserving the filter is resumable too: the build is committed first.
            $this->work(0, false);
        } finally {
            $this->releaseWorkerLock();
        }
        return $this->status();
    }

    /** Clears a failed rebuild so the next batch restarts it in a fresh generation. */
    public function resume(): array
    {
        $this->requireIdleConnection();
        $this->connection->beginTransaction();
        try {
            $state = $this->readState(true);
            if ($state && !empty($state['build']['error'])) {
                $state['build']['error'] = null;
                $this->writeState($state);
            }
            $this->connection->commit();
        } catch (Throwable $e) {
            $this->rollbackOwnedTransaction();
            throw $e;
        }
        return $this->status();
    }

    public function runBatch(int $limit = self::SCAN_BATCH_SIZE): array
    {
        return $this->runBatchInternal(self::boundedLimit($limit), false);
    }

    public function processPending(int $limit = self::PENDING_BATCH_SIZE): array
    {
        return $this->runBatchInternal(self::boundedLimit($limit), true);
    }

    private function runBatchInternal(int $limit, bool $pendingOnly): array
    {
        $this->requireIdleConnection();
        // A busy lock means another worker is running a batch: leave it be.
        if ($this->acquireWorkerLock()) {
            try {
                $this->work($limit, $pendingOnly);
            } finally {
                $this->releaseWorkerLock();
            }
        }
        return $this->status();
    }

    /** One batch. The caller holds the worker lock; failures are recorded, not thrown. */
    private function work(int $limit, bool $pendingOnly): void
    {
        $phase = 'update';
        try {
            $this->sizeStagedBuild();
            // Commit intent separately. A crash during the next transaction must
            // not erase the revision that identifies its partial Redis writes.
            $this->connection->beginTransaction();
            $state = $this->readState(true);
            if (!$this->canWork($state)) {
                $this->connection->commit();
                return;
            }
            $build = $state['build'] ?? null;
            $buildActive = $build && !empty($build['reserved']) && empty($build['error']);
            // A first build and an activation change what lookups see; plain
            // rebuild scans do not, so they leave the live revision alone.
            $visible = $this->dirtyCount() > 0
                || ($buildActive && (empty($state['generation']) || !empty($build['scan_complete'])));
            if ($visible && empty($state['pending_revision'])) {
                if ($this->hasRedisState($state) && !$this->checkpointMatches($state, $this->filter()->metadata())) {
                    throw new RuntimeException('The index checkpoint is stale; start a new backfill.');
                }
                $this->stageRevisions($state);
            }
            if ($build && empty($build['reserved'])) {
                // An interrupted reservation may have left keys behind: retry in
                // a fresh generation; the next reservation reclaims the old one.
                $state['build']['generation'] = bin2hex(random_bytes(16));
            }
            $this->writeState($state);
            $this->connection->commit();

            // Under the state row lock: reserve or verify the build, drain dirty
            // events into every generation and settle the batch's revision.
            $this->connection->beginTransaction();
            $state = $this->readState(true);
            if (!$this->canWork($state)) {
                $this->connection->commit();
                return;
            }
            $scope = FastLookupConfig::scope($this->attribute);
            $metadata = $this->hasRedisState($state) ? $this->filter()->metadata() : null;
            if ($metadata !== null) {
                $this->recoverActivation($state, $metadata);
                if (!$this->checkpointMatches($state, $metadata, true)) {
                    throw new RuntimeException('The index checkpoint is stale; start a new backfill.');
                }
            }
            if (!empty($state['build']) && empty($state['build']['error'])) {
                $phase = 'build';
                $this->prepareBuild($state, $metadata);
                $phase = 'update';
            }
            $staged = !empty($state['pending_revision']);
            if ($staged && $this->hasRedisState($state)) {
                $this->filter()->checkpoint($state['pending_revision'], false);
            }
            $targets = $this->targets($state);
            $remaining = $limit;
            if ($staged && $remaining > 0 && $targets) {
                $dirty = $this->query("SELECT setting, value FROM {$this->settingsTable} WHERE setting LIKE ? ORDER BY id LIMIT $remaining", [self::DIRTY_PREFIX . '%'])->fetchAll(PDO::FETCH_ASSOC);
                foreach ($dirty as $row) {
                    $this->refreshEvent($targets, substr($row['setting'], strlen(self::DIRTY_PREFIX)), $scope);
                    // Never erase a newer mutation, including a change emitted by
                    // a callback invoked while processing the current batch.
                    $this->query("DELETE FROM {$this->settingsTable} WHERE setting = ? AND value = ?", [$row['setting'], $row['value']]);
                    --$remaining;
                }
            }
            $build = $state['build'] ?? null;
            $scan = $build && !empty($build['reserved']) && empty($build['error']) && empty($build['scan_complete'])
                && $limit > 0 && (!$pendingOnly || !empty($state['generation']));
            // Nothing is served during a first build, so its revision stays
            // staged across the scan and it activates right after it. Beside a
            // live generation the batch settles first, so a scan never holds
            // lookups back.
            $deferred = $scan && $staged && empty($state['generation']);
            if (!$deferred) {
                $this->finishBatch($state, $staged);
            }
            $this->writeState($state);
            $this->connection->commit();
            if (!$scan) {
                return;
            }

            // Outside the state row lock, so event and attribute writers are
            // never held back by the scan; the worker lock keeps it exclusive.
            // Redis's cursor is written after the rows it covers and may run
            // ahead of SQL's after a crash, never behind it (prepareBuild).
            $phase = 'build';
            $scanned = $state['build'];
            $this->scanAttributes($scanned, $limit * self::SCAN_ATTRIBUTES_PER_UNIT, $scope);

            $phase = 'update';
            $this->connection->beginTransaction();
            $current = $this->readState(true);
            $build = $current['build'] ?? null;
            if (!$build || $build['generation'] !== $scanned['generation'] || empty($build['reserved']) || !empty($build['error'])
                || $build['cursor'] !== $state['build']['cursor']
                || ($current['pending_revision'] ?? null) !== ($state['pending_revision'] ?? null)) {
                // The build changed meanwhile, which the worker lock should
                // prevent: its SQL progress is not ours to record.
                $this->connection->commit();
                return;
            }
            $current['build'] = array_merge($build, array_intersect_key($scanned, array_flip(['cursor', 'processed', 'total', 'scan_complete'])));
            $this->writeState($current);
            $this->connection->commit();
            if (!$deferred) {
                return;
            }

            // The first build settles in a transaction of its own, so an
            // interrupted activation finds the completed scan in SQL.
            $this->connection->beginTransaction();
            $state = $this->readState(true);
            if (!$this->canWork($state) || empty($state['pending_revision'])) {
                $this->connection->commit();
                return;
            }
            $metadata = $this->filter()->metadata();
            if (!$this->checkpointMatches($state, $metadata, true)) {
                throw new RuntimeException('The index checkpoint is stale; start a new backfill.');
            }
            $phase = 'build';
            $this->prepareBuild($state, $metadata);
            $phase = 'update';
            $this->finishBatch($state, true);
            $this->writeState($state);
            $this->connection->commit();
        } catch (Throwable $e) {
            $this->rollbackOwnedTransaction();
            $this->saveFailure($e, $phase);
        }
    }

    /** Activates a complete build and commits a staged revision, under the state row lock. */
    private function finishBatch(array &$state, bool $staged): void
    {
        $build = $state['build'] ?? null;
        if ($staged && $build && !empty($build['reserved']) && !empty($build['scan_complete'])
            && empty($build['error']) && $this->dirtyCount() === 0) {
            // Redis swaps and deletes the old generation before SQL commits;
            // recoverActivation() completes the swap if that commit never lands.
            $this->filter()->activate($build['generation'], $build['fingerprint']);
            $this->completeActivation($state);
        }
        if ($staged) {
            // Never publish the in-progress revision as committed: a Redis
            // snapshot from mid-batch still carries it and must stay stale.
            $committed = $state['next_revision'];
            $state['revision'] = $committed;
            $state['pending_revision'] = null;
            $state['next_revision'] = null;
            if ($this->hasRedisState($state)) {
                $ready = !empty($state['generation'])
                    && $state['fingerprint'] === FastLookupConfig::fingerprint($this->attribute)
                    && $this->dirtyCount() === 0;
                $this->filter()->checkpoint($committed, $ready);
            }
        }
        if (!empty($state['generation']) && empty($state['build'])) {
            $this->scheduleRebuildIfNeeded($state);
        }
        $state['error'] = null;
    }

    private function completeActivation(array &$state): void
    {
        $build = $state['build'];
        $state['generation'] = $build['generation'];
        $state['fingerprint'] = $build['fingerprint'];
        $state['last_build'] = array_intersect_key($build, array_flip(['processed', 'total', 'scan_complete', 'started_at']));
        $state['build'] = null;
        // The first activation retires the previous index format; activate()
        // already removed its Redis keys.
        $this->query("DELETE FROM {$this->settingsTable} WHERE setting = ?", [self::LEGACY_STATE_SETTING]);
    }

    /**
     * activate() swaps Redis to the build and deletes the old generation before
     * SQL commits. If that commit never happened, or the old-key cleanup threw
     * after the swap, Redis already serves the build the staged batch was
     * activating: complete the activation in SQL instead of failing forever.
     */
    private function recoverActivation(array &$state, array $metadata): void
    {
        $build = $state['build'] ?? null;
        if (empty($state['pending_revision']) || !$build || empty($build['reserved'])
            || empty($build['scan_complete']) || !empty($build['error'])
            || ($metadata['live'] ?? null) !== $build['generation']
            || ($metadata['fingerprint'] ?? null) !== $build['fingerprint']
            || ($metadata['building'] ?? null) !== null
            || !in_array($metadata['revision'] ?? null, [$state['pending_revision'], $state['next_revision'] ?? null], true)) {
            return;
        }
        $this->completeActivation($state);
        $this->attribute->log('Completed an interrupted fast lookup index activation.', LOG_INFO);
    }

    /**
     * A rebuild cannot run beside a live generation Redis has lost or holds at
     * another checkpoint: every batch would fail on it. Drop it from SQL and
     * build from scratch; lookups answer 503 until the new generation is ready.
     */
    private function discardUnservableGeneration(array &$state): void
    {
        if (empty($state['generation'])) {
            return;
        }
        try {
            $metadata = $this->filter()->metadata();
        } catch (Throwable $e) {
            if (!$this->filter()->moduleAvailable()) {
                // Redis is unreachable or lacks RedisBloom: nothing can be
                // built now, and the live generation may well be intact.
                throw $e;
            }
            $metadata = null;
        }
        if ($metadata !== null) {
            $this->recoverActivation($state, $metadata);
            // The build is being replaced, so only the live checkpoint counts.
            if ($this->checkpointMatches(['build' => null] + $state, $metadata, true)) {
                return;
            }
        }
        $this->attribute->log('The fast lookup index no longer matches its Redis state and is rebuilt from scratch.', LOG_WARNING);
        $state['generation'] = null;
        $state['fingerprint'] = null;
        $state['error'] = null;
        unset($state['last_build']);
    }

    /** Workers exclude each other for a whole batch without holding the state row. */
    private function acquireWorkerLock(): bool
    {
        if ($this->postgres()) {
            $deadline = microtime(true) + self::WORKER_LOCK_WAIT;
            while (true) {
                if ((int)$this->query('SELECT CASE WHEN pg_try_advisory_lock(hashtext(?)) THEN 1 ELSE 0 END', [$this->workerLockName()])->fetchColumn() === 1) {
                    return true;
                }
                if (microtime(true) >= $deadline) {
                    return false;
                }
                usleep(100000);
            }
        }
        $acquired = $this->query('SELECT GET_LOCK(?, ?)', [$this->workerLockName(), self::WORKER_LOCK_WAIT])->fetchColumn();
        if ($acquired === null || $acquired === false) {
            throw new RuntimeException('Could not take the IOC index worker lock.');
        }
        return (int)$acquired === 1;
    }

    private function releaseWorkerLock(): void
    {
        try {
            $this->query($this->postgres() ? 'SELECT pg_advisory_unlock(hashtext(?))' : 'SELECT RELEASE_LOCK(?)', [$this->workerLockName()]);
        } catch (Throwable $e) {
            // A lost session has released its lock already.
            $this->logFailure($e);
        }
    }

    /** Session locks are server-wide: name the lock after this database. */
    private function workerLockName(): string
    {
        return 'misp_fast_lookup:' . substr(hash('sha256', FastLookupConfig::namespaceFor($this->attribute)), 0, 40);
    }

    private function postgres(): bool
    {
        return $this->connection->getAttribute(PDO::ATTR_DRIVER_NAME) === 'pgsql';
    }

    private function canWork($state): bool
    {
        if (!$state) {
            return false;
        }
        $fingerprint = FastLookupConfig::fingerprint($this->attribute);
        return (!empty($state['generation']) && $state['fingerprint'] === $fingerprint)
            || (!empty($state['build']) && $state['build']['fingerprint'] === $fingerprint);
    }

    private function hasRedisState(array $state): bool
    {
        return !empty($state['generation']) || !empty($state['build']['reserved']);
    }

    /** Generations a dirty event is written to. */
    private function targets(array $state): array
    {
        $fingerprint = FastLookupConfig::fingerprint($this->attribute);
        $targets = [];
        if (!empty($state['generation']) && $state['fingerprint'] === $fingerprint) {
            $targets[] = $state['generation'];
        }
        $build = $state['build'] ?? null;
        if ($build && !empty($build['reserved']) && empty($build['error']) && $build['fingerprint'] === $fingerprint) {
            $targets[] = $build['generation'];
        }
        return $targets;
    }

    private function newBuild(?array $sizing): array
    {
        return [
            'generation' => bin2hex(random_bytes(16)),
            'fingerprint' => FastLookupConfig::fingerprint($this->attribute),
            'rate' => FastLookupConfig::scope($this->attribute)['false_positive_rate'],
            'capacity' => $sizing['capacity'] ?? null,
            'range_entries' => $sizing['range_entries'] ?? null,
            'reserved' => false,
            'cursor' => '0',
            'high_water' => '0',
            'processed' => 0,
            'total' => $sizing['total'] ?? 0,
            'scan_complete' => false,
            'started_at' => time(),
            'error' => null,
        ];
    }

    private function sizing(array $scope): array
    {
        $types = $scope['attribute_types'];
        $placeholders = implode(', ', array_fill(0, count($types), '?'));
        $table = $this->db->fullTableName($this->attribute);
        $counts = array_fill_keys($types, 0);
        // Deleted rows are counted too, which keeps the count on the type index.
        foreach ($this->query("SELECT type, COUNT(*) AS attributes FROM $table WHERE type IN ($placeholders) GROUP BY type", $types)->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $counts[$row['type']] = (int)$row['attributes'];
        }
        $ranges = 0;
        foreach ($counts as $type => $count) {
            if (in_array($type, self::DOMAIN_TYPES, true)) {
                $ranges += $count;
            }
            if (in_array($type, self::IP_TYPES, true)) {
                $ranges += (int)ceil(self::IP_RANGE_SHARE * $count);
            }
        }
        $total = array_sum($counts);
        return [
            'capacity' => max(FastLookupFilter::MIN_CAPACITY, (int)ceil(self::CAPACITY_HEADROOM * self::TOKENS_PER_ATTRIBUTE * $total)),
            'range_entries' => $ranges,
            'total' => $total,
        ];
    }

    /** An automatically scheduled build is sized before the lock is taken. */
    private function sizeStagedBuild(): void
    {
        $state = $this->readState();
        if (empty($state['build']) || $state['build']['capacity'] !== null) {
            return;
        }
        $sizing = $this->sizing(FastLookupConfig::scope($this->attribute));
        $this->connection->beginTransaction();
        try {
            $state = $this->readState(true);
            if (!empty($state['build']) && $state['build']['capacity'] === null) {
                $state['build'] = array_merge($state['build'], $sizing);
                $this->writeState($state);
            }
            $this->connection->commit();
        } catch (Throwable $e) {
            $this->rollbackOwnedTransaction();
            throw $e;
        }
    }

    /** Reserves the building generation, or verifies Redis still holds its progress. */
    private function prepareBuild(array &$state, ?array $metadata): void
    {
        $build = $state['build'];
        if (empty($build['reserved'])) {
            // Under the state lock: later attributes reach the build through
            // dirty events, earlier ones through the scan.
            $table = $this->db->fullTableName($this->attribute);
            $highWater = $this->query("SELECT MAX(id) AS high_water FROM $table")->fetchColumn();
            $this->filter()->reserve($build['generation'], $build['fingerprint'], (int)$build['capacity'],
                (float)$build['rate'], (int)$build['range_entries']);
            $state['build'] = array_merge($build, ['reserved' => true, 'cursor' => '0',
                'high_water' => $highWater ? (string)$highWater : '0', 'processed' => 0, 'scan_complete' => false,
                'started_at' => time()]);
            if (empty($state['generation'])) {
                // Nothing is served yet, so align Redis with the SQL checkpoint:
                // an earlier failed attempt may have left another revision.
                $this->filter()->checkpoint($state['pending_revision'] ?: $state['revision'], false);
            }
            return;
        }
        $info = $metadata['generations'][$build['generation']] ?? null;
        if (!$info || self::compareIds($info['cursor'], $build['cursor']) < 0) {
            throw new RuntimeException('The IOC index build lost its Redis state.');
        }
    }

    private function scanAttributes(array &$build, int $maximum, array $scope): void
    {
        $valueTool = new FastLookupValueTool($this->attribute);
        $table = $this->db->fullTableName($this->attribute);
        $events = $this->db->fullTableName($this->attribute->Event);
        $types = $scope['attribute_types'];
        $placeholders = implode(', ', array_fill(0, count($types), '?'));
        $published = $scope['published_only'] ? ' AND e.published = TRUE' : '';
        $columns = $valueTool->scanColumns('a');
        $scanned = 0;
        while ($scanned < $maximum) {
            $take = min(self::ATTRIBUTE_BATCH_SIZE, $maximum - $scanned);
            $rows = $this->query("SELECT $columns FROM $table a INNER JOIN $events e ON e.id = a.event_id WHERE a.id > ? AND a.id <= ? AND a.deleted = FALSE AND a.type IN ($placeholders)$published ORDER BY a.id LIMIT $take",
                array_merge([$build['cursor'], $build['high_water']], $types))->fetchAll(PDO::FETCH_ASSOC);
            if ($rows) {
                $this->filter()->add($build['generation'], $valueTool->prepareScannedAttributes($rows));
                $build['cursor'] = (string)$rows[count($rows) - 1]['id'];
                $build['processed'] += count($rows);
                $scanned += count($rows);
            }
            if (count($rows) < $take) {
                $build['scan_complete'] = true;
                $build['total'] = $build['processed'];
                break;
            }
        }
        $this->filter()->setCursor($build['generation'], $build['cursor']);
    }

    private function refreshEvent(array $targets, string $eventId, array $scope): void
    {
        $events = $this->db->fullTableName($this->attribute->Event);
        $filter = $scope['published_only'] ? ' AND published = TRUE' : '';
        $event = $this->query("SELECT published FROM $events WHERE id = ?$filter", [$eventId])->fetch(PDO::FETCH_ASSOC);
        // Without manifests the replaced tokens are unknown: count every
        // re-added attribute, plus one for removals, as possibly stale.
        $stale = 1;
        if ($event) {
            $valueTool = new FastLookupValueTool($this->attribute);
            $table = $this->db->fullTableName($this->attribute);
            $types = $scope['attribute_types'];
            $placeholders = implode(', ', array_fill(0, count($types), '?'));
            $columns = $valueTool->scanColumns('a');
            $lastId = '0';
            do {
                $rows = $this->query("SELECT $columns FROM $table a WHERE a.event_id = ? AND a.id > ? AND a.deleted = FALSE AND a.type IN ($placeholders) ORDER BY a.id LIMIT " . self::ATTRIBUTE_BATCH_SIZE,
                    array_merge([$eventId, $lastId], $types))->fetchAll(PDO::FETCH_ASSOC);
                if ($rows) {
                    $prepared = $valueTool->prepareScannedAttributes($rows);
                    foreach ($targets as $generation) {
                        $this->filter()->add($generation, $prepared);
                    }
                    $lastId = (string)$rows[count($rows) - 1]['id'];
                    $stale += count($rows);
                }
            } while (count($rows) === self::ATTRIBUTE_BATCH_SIZE);
        }
        foreach ($targets as $generation) {
            $this->filter()->markStale($generation, $stale);
        }
    }

    private function scheduleRebuildIfNeeded(array &$state): void
    {
        if ($state['fingerprint'] !== FastLookupConfig::fingerprint($this->attribute)) {
            return;
        }
        $info = $this->filter()->metadata()['generations'][$state['generation']] ?? null;
        if (!$info) {
            return;
        }
        if ($info['inserted'] >= self::REBUILD_AT_CAPACITY * $info['capacity']
            || ($info['inserted'] >= self::REBUILD_MIN_INSERTED && $info['stale'] >= self::REBUILD_AT_STALE * $info['inserted'])) {
            $state['build'] = $this->newBuild(null);
            $this->attribute->log('Scheduled a fast lookup index rebuild: the filter is near capacity or holds many stale entries.', LOG_INFO);
        }
    }

    private static function compareIds(string $left, string $right): int
    {
        return strlen($left) <=> strlen($right) ?: strcmp($left, $right);
    }

    /** Keep Cake delete callbacks and their durable marker in one transaction. */
    public static function withMutationTransaction($model, callable $operation)
    {
        $db = $model->getDataSource();
        $owned = !$db->getConnection()->inTransaction();
        if ($owned && !$db->begin()) {
            throw new RuntimeException('Could not start the IOC mutation transaction.');
        }
        try {
            $result = $operation();
            if ($owned) {
                if ($result === false) {
                    $db->rollback();
                } elseif (!$db->commit()) {
                    throw new RuntimeException('Could not commit the IOC mutation transaction.');
                }
            }
            return $result;
        } catch (Throwable $e) {
            if ($owned) {
                // Use Cake bookkeeping, including when SQL has already aborted
                // the transaction (for example after a deadlock).
                try { $db->rollback(); } catch (Throwable $ignored) { }
            }
            throw $e;
        }
    }

    /** Called inside the model's transaction; errors must abort that mutation. */
    public static function recordChange($model, $eventId): void
    {
        if ((!is_int($eventId) && !is_string($eventId)) || !ctype_digit((string)$eventId) || (int)$eventId < 1) {
            return;
        }
        $db = $model->getDataSource();
        $connection = $db->getConnection();
        $table = $db->fullTableName('admin_settings');
        $owned = !$connection->inTransaction();
        if ($owned) {
            $connection->beginTransaction();
        }
        try {
            $statement = $connection->prepare("SELECT id FROM $table WHERE setting = ?");
            $statement->execute([self::STATE_SETTING]);
            $stateId = $statement->fetchColumn();
            $statement->closeCursor();
            $postgres = $connection->getAttribute(PDO::ATTR_DRIVER_NAME) === 'pgsql';
            if ($stateId === false) {
                // Materialise the lock row even before the first build. Locking
                // an absent row is not portable across SQL isolation levels.
                self::insertStateIfAbsent($connection, $table);
                $statement = $connection->prepare("SELECT id FROM $table WHERE setting = ? FOR UPDATE");
                $statement->execute([self::STATE_SETTING]);
                $stateId = $statement->fetchColumn();
                $statement->closeCursor();
            }
            // Mutations on different events share this lock. Only the worker
            // takes FOR UPDATE, fencing the scan/checkpoint against all writers.
            $lock = $postgres ? ' FOR SHARE' : ' LOCK IN SHARE MODE';
            // Lock by primary key: MariaDB secondary-index shared locks can
            // include the preceding gap, which would block unrelated outbox INSERTs.
            $statement = $connection->prepare("SELECT value FROM $table WHERE id = ?$lock");
            $statement->execute([$stateId]);
            $exists = $statement->fetchColumn();
            $statement->closeCursor();
            $state = $exists === false ? [] : json_decode($exists, true, 32, JSON_THROW_ON_ERROR);
            if (!empty($state['generation']) || !empty($state['build'])) {
                $key = self::DIRTY_PREFIX . (string)$eventId;
                $revision = bin2hex(random_bytes(16));
                $sql = "INSERT INTO $table (setting, value) VALUES (?, ?)";
                $sql .= $postgres
                    ? ' ON CONFLICT (setting) DO UPDATE SET value = EXCLUDED.value'
                    : ' ON DUPLICATE KEY UPDATE value = VALUES(value)';
                $statement = $connection->prepare($sql);
                if (!$statement->execute([$key, $revision])) {
                    throw new RuntimeException('Could not record an IOC index mutation.');
                }
                self::$dispatchModels[spl_object_hash($db)] = $model;
                if (!self::$shutdownRegistered) {
                    register_shutdown_function([self::class, 'dispatchPending']);
                    self::$shutdownRegistered = true;
                }
            }
            if ($owned) {
                $connection->commit();
            }
        } catch (Throwable $e) {
            if ($owned && $connection->inTransaction()) {
                $connection->rollBack();
            }
            throw $e;
        }
    }

    /** Dispatch only after request imports, child writes and commits have ended. */
    public static function dispatchPending(): void
    {
        $models = self::$dispatchModels;
        self::$dispatchModels = [];
        foreach ($models as $model) {
            try {
                if ($model->getDataSource()->getConnection()->inTransaction()) {
                    continue; // Never take ownership of an unfinished caller transaction.
                }
                if (Configure::read('MISP.background_jobs')) {
                    $job = ClassRegistry::init('Job');
                    $jobId = $job->createJob('SYSTEM', Job::WORKER_DEFAULT, 'fast_lookup_pending', '', 'Updating the IOC index.');
                    $job->getBackgroundJobsTool()->enqueue(BackgroundJobsTool::DEFAULT_QUEUE, BackgroundJobsTool::CMD_ADMIN, ['processFastLookup', $jobId, self::PENDING_BATCH_SIZE], true, $jobId);
                } else {
                    $attribute = $model->alias === 'Attribute' ? $model : $model->Attribute;
                    (new self($attribute))->processPending();
                }
            } catch (Throwable $e) {
                // SQL dirty rows survive failed Redis enqueue and worker outages.
                $model->log('Could not dispatch the persistent IOC index update (' . get_class($e) . '). Pending SQL mutations were retained.', LOG_ERR);
            }
        }
    }

    private static function insertStateIfAbsent($connection, string $table): void
    {
        $sql = "INSERT INTO $table (setting, value) VALUES (?, ?)";
        $sql .= $connection->getAttribute(PDO::ATTR_DRIVER_NAME) === 'pgsql'
            ? ' ON CONFLICT (setting) DO NOTHING'
            : ' ON DUPLICATE KEY UPDATE setting = setting';
        $statement = $connection->prepare($sql);
        if (!$statement || !$statement->execute([self::STATE_SETTING, '{}'])) {
            throw new RuntimeException('Could not initialise the IOC index state.');
        }
    }

    private function readState(bool $lock = false): ?array
    {
        $value = $this->query("SELECT value FROM {$this->settingsTable} WHERE setting = ?" . ($lock ? ' FOR UPDATE' : ''), [self::STATE_SETTING])->fetchColumn();
        if ($value === false) {
            return null;
        }
        $state = json_decode($value, true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($state)) {
            throw new RuntimeException('The IOC index SQL checkpoint is corrupt.');
        }
        return $state;
    }

    private function writeState(array $state): void
    {
        $this->query("UPDATE {$this->settingsTable} SET value = ? WHERE setting = ?", [json_encode($state, JSON_THROW_ON_ERROR), self::STATE_SETTING]);
    }

    private function dirtyCount(): int
    {
        return (int)$this->query("SELECT COUNT(*) FROM {$this->settingsTable} WHERE setting LIKE ?", [self::DIRTY_PREFIX . '%'])->fetchColumn();
    }

    private function query(string $sql, array $parameters = [])
    {
        $statement = $this->connection->prepare($sql);
        if (!$statement || !$statement->execute($parameters)) {
            throw new RuntimeException('Could not access the IOC index SQL state.');
        }
        return $statement;
    }

    /** Both revisions are committed before Redis is touched, so a crash can resume. */
    private function stageRevisions(array &$state): void
    {
        $state['pending_revision'] = bin2hex(random_bytes(16));
        $state['next_revision'] = bin2hex(random_bytes(16));
    }

    private function checkpointMatches(array $state, array $metadata, bool $allowPending = false): bool
    {
        // Before the first activation nothing is served: a live generation
        // Redis still holds from a discarded index is irrelevant, and the
        // activation replaces it.
        if (!empty($state['generation']) && (($metadata['live'] ?? null) !== $state['generation']
            || ($metadata['fingerprint'] ?? null) !== ($state['fingerprint'] ?? null))) {
            return false;
        }
        $build = $state['build'] ?? null;
        if ($build && !empty($build['reserved']) && ($metadata['building'] ?? null) !== $build['generation']) {
            return false;
        }
        $revision = $metadata['revision'] ?? null;
        if ($revision === $state['revision']) {
            return true;
        }
        // A crash after the final Redis checkpoint but before the SQL commit
        // leaves Redis on next_revision; the staged batch can still resume.
        return $allowPending && !empty($state['pending_revision'])
            && in_array($revision, array_filter([$state['pending_revision'], $state['next_revision'] ?? null]), true);
    }

    private function progress(array $source): array
    {
        $processed = (int)($source['processed'] ?? 0);
        $total = max($processed, (int)($source['total'] ?? 0));
        $percent = !empty($source['scan_complete']) ? 100 : ($total ? min(99, (int)floor(100 * $processed / $total)) : 0);
        $elapsed = max(0, time() - ($source['started_at'] ?? time()));
        return [
            'processed_attributes' => $processed,
            'total_attributes' => $total,
            'percent' => $percent,
            'eta_seconds' => $processed > 0 && empty($source['scan_complete']) ? (int)ceil(max(0, $total - $processed) * $elapsed / $processed) : null,
        ];
    }

    private function saveFailure(Throwable $e, string $phase): void
    {
        $this->logFailure($e);
        try {
            $this->connection->beginTransaction();
            $state = $this->readState(true);
            if ($state) {
                if ($phase === 'build' && !empty($state['build'])) {
                    // The live generation keeps serving; the build restarts
                    // from scratch in a fresh generation after a resume.
                    $state['build'] = array_merge($state['build'], ['error' => self::BUILD_FAILED, 'reserved' => false,
                        'cursor' => '0', 'processed' => 0, 'scan_complete' => false]);
                } else {
                    $state['error'] = 'The IOC index update failed. Resume the job, or rebuild if its checkpoint is stale.';
                }
                $this->writeState($state);
            }
            $this->connection->commit();
        } catch (Throwable $ignored) {
            $this->rollbackOwnedTransaction();
        }
    }

    private function moduleMissing(): bool
    {
        try {
            return !$this->filter()->moduleAvailable();
        } catch (Throwable $e) {
            return false;
        }
    }

    private function includeStatistics(array $status, bool $include, ?string $generation): array
    {
        if ($include && $generation !== null) {
            try {
                $status['statistics'] = $this->filter()->statistics($generation);
            } catch (Throwable $e) {
                $status['statistics_error'] = 'Redis allocation measurements are currently unavailable.';
            }
        }
        return $status;
    }

    private function logFailure(Throwable $e): void
    {
        $this->attribute->log('Persistent IOC index operation failed (' . get_class($e) . ').', LOG_ERR);
    }

    private function requireIdleConnection(): void
    {
        if ($this->connection->inTransaction()) {
            throw new LogicException('IOC index workers cannot run inside a caller-owned transaction.');
        }
    }

    private function rollbackOwnedTransaction(): void
    {
        if ($this->connection->inTransaction()) {
            $this->connection->rollBack();
        }
    }

    public static function boundedLimit(int $limit): int
    {
        if ($limit < 1 || $limit > 1000) {
            throw new InvalidArgumentException('The IOC index batch size must be between 1 and 1000.');
        }
        return $limit;
    }
}
