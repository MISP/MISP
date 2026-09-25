<?php
App::uses('FastLookupConfig', 'Tools');
App::uses('FastLookupIndex', 'Tools');
App::uses('FastLookupValueTool', 'Tools');

/**
 * SQL owns the index checkpoint and mutation queue. Redis is a derived index.
 *
 * Model callbacks write the queue on their existing connection/transaction.
 * A worker owns its transactions and locks the singleton SQL state row while
 * touching Redis. A durable pending revision distinguishes an interrupted batch
 * from an old Redis backup: only the committed or pending checkpoint can resume.
 * Redis carries the pending revision while a batch writes and a distinct,
 * pre-committed next revision once it completes, so a Redis snapshot taken
 * between two events of a batch never matches the committed SQL checkpoint.
 */
class FastLookupIndexManager
{
    const STATE_SETTING = 'fastLookupIndex:state:v2';
    const DIRTY_PREFIX = 'fastLookupIndex:dirty:v2:';
    const ATTRIBUTE_BATCH_SIZE = 500;

    private $attribute;
    private $db;
    private $connection;
    private $settingsTable;
    private $index;
    private static $dispatchModels = [];
    private static $shutdownRegistered = false;

    public function __construct($attribute = null, $index = null)
    {
        $this->attribute = $attribute ?: ClassRegistry::init('MispAttribute');
        $this->db = $this->attribute->getDataSource();
        $this->connection = $this->db->getConnection();
        $this->settingsTable = $this->db->fullTableName('admin_settings');
        $this->index = $index;
    }

    public function index()
    {
        if ($this->index === null) {
            $this->index = new FastLookupIndex(
                FastLookupConfig::namespaceFor($this->attribute),
                FastLookupConfig::scope($this->attribute)
            );
        }
        return $this->index;
    }

    public function status(bool $metrics = false): array
    {
        $result = [
            'status' => 'unavailable',
            'scope' => FastLookupConfig::scope($this->attribute),
            'progress' => ['processed_events' => 0, 'total_events' => 0, 'percent' => 0, 'eta_seconds' => null],
            'generation' => null,
            'revision' => null,
        ];
        try {
            $state = $this->readState();
            if (!$state || empty($state['generation'])) {
                $result['message'] = 'The IOC index requires an administrator to start a backfill.';
                return $result;
            }
            $result['generation'] = $state['generation'];
            $result['revision'] = $state['revision'];
            $result['progress'] = $this->progress($state);
            if ($state['fingerprint'] !== FastLookupConfig::fingerprint($this->attribute)) {
                $result['message'] = 'The configured IOC scope has changed. A new backfill is required.';
                return $this->includeStatistics($result, $metrics);
            }
            if (!empty($state['error'])) {
                $result['status'] = 'error';
                $result['message'] = $state['error'];
                return $this->includeStatistics($result, $metrics);
            }
            if (!empty($state['pending_revision'])) {
                $result['status'] = empty($state['scan_complete']) ? 'warming' : 'updating';
                $result['message'] = 'An IOC index batch is in progress or awaiting resume.';
                return $this->includeStatistics($result, $metrics);
            }
            $metadata = $this->index()->metadata();
            if (!$this->checkpointMatches($state, $metadata)) {
                $result['message'] = 'The Redis index does not match its SQL checkpoint. Rebuild the index.';
                return $this->includeStatistics($result, $metrics);
            }
            if (empty($state['scan_complete'])) {
                $result['status'] = 'warming';
            } elseif ($this->dirtyCount() > 0) {
                $result['status'] = 'updating';
            } elseif (!empty($metadata['ready'])) {
                $result['status'] = 'ready';
            }
        } catch (Throwable $e) {
            $result['status'] = 'unavailable';
            $result['message'] = 'The IOC index is unavailable. Its SQL queue has been retained.';
            $this->logFailure($e);
        }
        return $this->includeStatistics($result, $metrics);
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
        $scope = FastLookupConfig::scope($this->attribute);
        $fingerprint = FastLookupConfig::fingerprint($this->attribute);
        $this->connection->beginTransaction();
        try {
            $this->insertStateIfAbsent();
            $this->readState(true);
            $events = $this->db->fullTableName($this->attribute->Event);
            $filter = $scope['published_only'] ? ' WHERE published = TRUE' : '';
            $totals = $this->query("SELECT COUNT(*) AS total, MAX(id) AS high_water FROM $events$filter")->fetch(PDO::FETCH_ASSOC);
            $state = [
                'generation' => bin2hex(random_bytes(16)),
                'fingerprint' => $fingerprint,
                'revision' => '0',
                'pending_revision' => bin2hex(random_bytes(16)),
                'next_revision' => bin2hex(random_bytes(16)),
                'needs_initialise' => true,
                'cursor' => '0',
                'high_water' => (string)($totals['high_water'] ?? '0'),
                'processed_events' => 0,
                'total_events' => (int)$totals['total'],
                'scan_complete' => false,
                'started_at' => time(),
                'error' => null,
            ];
            $this->writeState($state);
            $this->connection->commit();
        } catch (Throwable $e) {
            $this->rollbackOwnedTransaction();
            throw $e;
        }
        // Initialisation is resumable too. The durable generation is committed
        // before Redis is touched, so an old Redis backup can never appear ready.
        return $this->runBatchInternal(0, false);
    }

    public function runBatch(int $eventLimit = 100): array
    {
        return $this->runBatchInternal($this->boundedLimit($eventLimit), false);
    }

    public function processPending(int $eventLimit = 25): array
    {
        return $this->runBatchInternal($this->boundedLimit($eventLimit), true);
    }

    private function runBatchInternal(int $eventLimit, bool $pendingOnly): array
    {
        $this->requireIdleConnection();
        try {
            // Commit intent separately. A crash during the next transaction must
            // not erase the revision that identifies its partial Redis writes.
            $this->connection->beginTransaction();
            $state = $this->readState(true);
            if (!$this->canWork($state, $pendingOnly)) {
                $this->connection->commit();
                return $this->status();
            }
            if (!empty($state['needs_initialise'])) {
                // An interrupted initialisation may have installed only some
                // fixed shards. Retry in a fresh generation; Redis can then
                // safely discard its incomplete predecessor.
                $state['generation'] = bin2hex(random_bytes(16));
                $this->stageRevisions($state);
                $this->writeState($state);
            } elseif (empty($state['pending_revision'])) {
                if (!$this->checkpointMatches($state, $this->index()->metadata())) {
                    throw new RuntimeException('The index checkpoint is stale; start a new backfill.');
                }
                $this->stageRevisions($state);
                $this->writeState($state);
            }
            $this->connection->commit();

            $this->connection->beginTransaction();
            $state = $this->readState(true);
            if (!$this->canWork($state, $pendingOnly) || empty($state['pending_revision'])) {
                // A concurrent worker already finished the staged operation.
                $this->connection->commit();
                return $this->status();
            }
            $scope = FastLookupConfig::scope($this->attribute);
            if (!empty($state['needs_initialise'])) {
                $this->index()->initialise($state['generation'], $state['fingerprint'], $this->progress($state));
                $state['needs_initialise'] = false;
            } else {
                $metadata = $this->index()->metadata();
                if (!$this->checkpointMatches($state, $metadata, true)) {
                    throw new RuntimeException('The index checkpoint is stale; start a new backfill.');
                }
            }
            $revision = $state['pending_revision'];
            $this->index()->checkpoint($state['generation'], $revision, $this->progress($state), false);
            $remaining = $eventLimit;
            if (empty($state['scan_complete']) && $eventLimit > 0) {
                $events = $this->db->fullTableName($this->attribute->Event);
                $filter = $scope['published_only'] ? ' AND published = TRUE' : '';
                $rows = $this->query("SELECT id FROM $events WHERE id > ? AND id <= ?$filter ORDER BY id LIMIT $eventLimit", [$state['cursor'], $state['high_water']])->fetchAll(PDO::FETCH_ASSOC);
                foreach ($rows as $row) {
                    $this->refreshEvent($state['generation'], (string)$row['id'], $scope);
                    $state['cursor'] = (string)$row['id'];
                    $state['processed_events']++;
                    $remaining--;
                }
                if (count($rows) < $eventLimit) {
                    $state['scan_complete'] = true;
                    // Events may be deleted or unpublished while the scan runs.
                    $state['total_events'] = $state['processed_events'];
                }
            }
            if (!empty($state['scan_complete']) && $remaining > 0) {
                $dirty = $this->query("SELECT setting, value FROM {$this->settingsTable} WHERE setting LIKE ? ORDER BY id LIMIT $remaining", [self::DIRTY_PREFIX . '%'])->fetchAll(PDO::FETCH_ASSOC);
                foreach ($dirty as $row) {
                    $eventId = substr($row['setting'], strlen(self::DIRTY_PREFIX));
                    $this->refreshEvent($state['generation'], $eventId, $scope);
                    // Never erase a newer mutation, including a change emitted by
                    // a callback invoked while processing the current batch.
                    $this->query("DELETE FROM {$this->settingsTable} WHERE setting = ? AND value = ?", [$row['setting'], $row['value']]);
                }
            }
            $ready = !empty($state['scan_complete']) && $this->dirtyCount() === 0;
            // Never publish the in-progress revision as committed: a Redis
            // snapshot from mid-batch still carries it and must stay stale.
            $committed = $state['next_revision'] ?? $revision;
            $state['revision'] = $committed;
            $state['pending_revision'] = null;
            $state['next_revision'] = null;
            $state['error'] = null;
            $this->index()->checkpoint($state['generation'], $committed, $this->progress($state), $ready);
            $this->writeState($state);
            $this->connection->commit();
        } catch (Throwable $e) {
            $this->rollbackOwnedTransaction();
            $this->saveFailure($e);
        }
        return $this->status();
    }

    private function canWork($state, bool $pendingOnly): bool
    {
        return $state && !empty($state['generation'])
            && $state['fingerprint'] === FastLookupConfig::fingerprint($this->attribute)
            && (!$pendingOnly || !empty($state['scan_complete']));
    }

    private function refreshEvent(string $generation, string $eventId, array $scope): void
    {
        $events = $this->db->fullTableName($this->attribute->Event);
        $filter = $scope['published_only'] ? ' AND published = TRUE' : '';
        $event = $this->query("SELECT published FROM $events WHERE id = ?$filter", [$eventId])->fetch(PDO::FETCH_ASSOC);
        if (!$event) {
            $this->index()->removeEvent($generation, $eventId);
            return;
        }
        $this->index()->beginEvent($generation, $eventId);
        $table = $this->db->fullTableName($this->attribute);
        $types = $scope['attribute_types'];
        if ($types) {
            $typePlaceholders = implode(',', array_fill(0, count($types), '?'));
            $valueTool = new FastLookupValueTool($this->attribute);
            $lastId = '0';
            do {
                $rows = $this->query("SELECT id, type, value1, value2 FROM $table WHERE event_id = ? AND id > ? AND deleted = FALSE AND type IN ($typePlaceholders) ORDER BY id LIMIT " . self::ATTRIBUTE_BATCH_SIZE, array_merge([$eventId, $lastId], $types))->fetchAll(PDO::FETCH_ASSOC);
                if ($rows) {
                    $this->index()->addAttributes($generation, $eventId, $valueTool->prepareAttributes($rows));
                    $lastId = (string)$rows[count($rows) - 1]['id'];
                }
            } while (count($rows) === self::ATTRIBUTE_BATCH_SIZE);
        }
        $this->index()->endEvent($generation, $eventId);
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
                $insert = "INSERT INTO $table (setting, value) VALUES (?, ?)";
                $insert .= $postgres ? ' ON CONFLICT (setting) DO NOTHING' : ' ON DUPLICATE KEY UPDATE setting = setting';
                $statement = $connection->prepare($insert);
                if (!$statement->execute([self::STATE_SETTING, '{}'])) {
                    throw new RuntimeException('Could not initialise the IOC index mutation lock.');
                }
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
            if (!empty($state['generation'])) {
                $key = self::DIRTY_PREFIX . (string)$eventId;
                $revision = bin2hex(random_bytes(16));
                $sql = "INSERT INTO $table (setting, value) VALUES (?, ?)";
                $sql .= $connection->getAttribute(PDO::ATTR_DRIVER_NAME) === 'pgsql'
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
                    $job->getBackgroundJobsTool()->enqueue(BackgroundJobsTool::DEFAULT_QUEUE, BackgroundJobsTool::CMD_ADMIN, ['processFastLookup', $jobId, 25], true, $jobId);
                } else {
                    $attribute = $model->alias === 'Attribute' ? $model : $model->Attribute;
                    (new self($attribute))->processPending(25);
                }
            } catch (Throwable $e) {
                // SQL dirty rows survive failed Redis enqueue and worker outages.
                $model->log('Could not dispatch the persistent IOC index update (' . get_class($e) . '). Pending SQL mutations were retained.', LOG_ERR);
            }
        }
    }

    private function insertStateIfAbsent(): void
    {
        $sql = "INSERT INTO {$this->settingsTable} (setting, value) VALUES (?, ?)";
        $sql .= $this->connection->getAttribute(PDO::ATTR_DRIVER_NAME) === 'pgsql'
            ? ' ON CONFLICT (setting) DO NOTHING'
            : ' ON DUPLICATE KEY UPDATE setting = setting';
        $this->query($sql, [self::STATE_SETTING, '{}']);
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
        $revision = $metadata['revision'] ?? null;
        if (($metadata['generation'] ?? null) !== $state['generation']
            || ($metadata['fingerprint'] ?? null) !== $state['fingerprint']) {
            return false;
        }
        if ($revision === $state['revision']) {
            return true;
        }
        // A crash after the final Redis checkpoint but before the SQL commit
        // leaves Redis on next_revision; the staged batch can still resume.
        return $allowPending && !empty($state['pending_revision'])
            && in_array($revision, array_filter([$state['pending_revision'], $state['next_revision'] ?? null]), true);
    }

    private function progress(array $state): array
    {
        $processed = (int)($state['processed_events'] ?? 0);
        $total = (int)($state['total_events'] ?? 0);
        $percent = !empty($state['scan_complete']) ? 100 : ($total ? min(99, (int)floor(100 * $processed / $total)) : 0);
        $elapsed = max(0, time() - ($state['started_at'] ?? time()));
        return [
            'processed_events' => $processed,
            'total_events' => $total,
            'percent' => $percent,
            'eta_seconds' => $processed > 0 ? (int)ceil(max(0, $total - $processed) * $elapsed / $processed) : null,
        ];
    }

    private function saveFailure(Throwable $e): void
    {
        $this->logFailure($e);
        try {
            $this->connection->beginTransaction();
            $state = $this->readState(true);
            if ($state) {
                $state['error'] = 'The IOC index update failed. Resume the job, or rebuild if its checkpoint is stale.';
                $this->writeState($state);
            }
            $this->connection->commit();
        } catch (Throwable $ignored) {
            $this->rollbackOwnedTransaction();
        }
    }

    private function logFailure(Throwable $e): void
    {
        $this->attribute->log('Persistent IOC index operation failed (' . get_class($e) . ').', LOG_ERR);
    }

    private function includeStatistics(array $status, bool $include): array
    {
        if ($include && !empty($status['generation'])) {
            try {
                $status['statistics'] = $this->index()->statistics($status['generation']);
            } catch (Throwable $e) {
                $status['statistics_error'] = 'Redis allocation measurements are currently unavailable.';
            }
        }
        return $status;
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

    private function boundedLimit(int $limit): int
    {
        if ($limit < 1 || $limit > 1000) {
            throw new InvalidArgumentException('The IOC index batch size must be between 1 and 1000 events.');
        }
        return $limit;
    }
}
