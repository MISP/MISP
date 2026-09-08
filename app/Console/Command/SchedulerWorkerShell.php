<?php

declare(strict_types=1);

App::uses('Shell', 'Console');
App::uses('AppShell', 'Console/Command');
App::uses('Worker', 'Tools/BackgroundJobs');

class SchedulerWorkerShell extends AppShell
{
    public $uses = ['Task', 'Feed', 'Server', 'TaxiiServer', 'Job', 'User'];

    /** @var Worker */
    private $worker;

    /** @var int */
    private $maxExecutionTime;

    /** @var int Consecutive database failures, drives the back-off and log throttling. */
    private $dbFailures = 0;

    const DEFAULT_MAX_EXECUTION_TIME = 0; // unlimited

    const LOOP_INTERVAL = 10;

    /** Upper bound of the back-off applied while the database is unreachable. */
    const MAX_DB_BACKOFF = 60;

    /** Only log every Nth consecutive database failure, so an outage cannot flood the log. */
    const DB_FAILURE_LOG_INTERVAL = 10;

    public const ADMIN_ACTIONS = [
        'updateGalaxies',
        'updateTaxonomies',
        'updateWarningLists',
        'updateNoticeLists',
        'updateObjectTemplates',
        // Reconcile MISP accounts with the external identity provider. The
        // reporting variant changes nothing; the blocking one disables users
        // it no longer backs, so it is a separate, explicit choice.
        'checkUserValidity',
        'blockInvalidUsers'
    ];

    public function getOptionParser(): ConsoleOptionParser
    {
        $parser = parent::getOptionParser();
        $parser->addOption(
            'maxExecutionTime',
            [
                'help' => 'Worker maximum execution time (seconds) before it self-destruct. Zero means unlimited.',
                'default' => self::DEFAULT_MAX_EXECUTION_TIME,
                'required' => false
            ]
        );

        return $parser;
    }

    public function main()
    {
        $pid = getmypid();
        if ($pid === false) {
            throw new RuntimeException("Could not get current process ID");
        }

        $this->worker = new Worker(
            [
                'pid' => $pid,
                'queue' => 'scheduler',
                'user' => ProcessTool::whoami(),
            ]
        );

        $this->maxExecutionTime = (int)($this->params['maxExecutionTime'] ?? self::DEFAULT_MAX_EXECUTION_TIME);

        CakeLog::info("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - starting task scheduler...");

        while (true) {
            $this->checkMaxExecutionTime();

            if (!$this->ensureDatabaseConnection()) {
                sleep($this->databaseBackoff());
                continue;
            }

            $now = time();

            try {
                $tasks = $this->Task->find('all', [
                    'conditions' => [
                        'next_execution_time <=' => $now,
                        'enabled' => true
                    ],
                    'contain' => ['Job'],
                ]);
            } catch (Throwable $e) {
                // A lost connection is picked up by the probe on the next pass,
                // which owns the reconnect, the back-off and the log throttling.
                CakeLog::error("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - failed to fetch tasks: " . $e->getMessage());
                sleep(self::LOOP_INTERVAL);
                continue;
            }

            foreach ($tasks as $task) {
                $task = $task['Task'];
                try {
                    $this->processTask($task);
                } catch (Throwable $e) {
                    $this->logMessage('error', $task['id'], "failed to process task: " . $e->getMessage());
                }
            }

            sleep(self::LOOP_INTERVAL);
        }
    }

    /**
     * Make sure the shared datasource holds a usable connection before querying.
     *
     * When the server drops the connection, CakePHP never re-establishes it on
     * its own, and a failed reconnect leaves the datasource with a null PDO
     * handle - the next query then raises an Error, not an Exception, killing
     * the worker. Probing first keeps the loop alive across outages of any
     * length, and doubles as a keepalive on long-haul database links.
     *
     * @return boolean True when the connection is usable.
     */
    private function ensureDatabaseConnection(): bool
    {
        try {
            $db = ConnectionManager::getDataSource($this->Task->useDbConfig);

            if (!$db->isConnected()) {
                $db->disconnect();
                $db->connect();
            }
        } catch (Throwable $e) {
            $this->dbFailures++;
            if ($this->dbFailures === 1 || $this->dbFailures % self::DB_FAILURE_LOG_INTERVAL === 0) {
                CakeLog::error("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - database unavailable (attempt {$this->dbFailures}): " . $e->getMessage());
            }
            return false;
        }

        if ($this->dbFailures > 0) {
            CakeLog::info("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - database connection re-established after {$this->dbFailures} failed attempt(s).");
            $this->dbFailures = 0;
        }

        return true;
    }

    /**
     * Seconds to wait before retrying, growing with the number of consecutive failures.
     *
     * @return integer
     */
    private function databaseBackoff(): int
    {
        return (int)min(self::LOOP_INTERVAL * max(1, $this->dbFailures), self::MAX_DB_BACKOFF);
    }

    /**
     * Checks if worker maximum execution time is reached, and exits if so.
     *
     * @return void
     */
    private function checkMaxExecutionTime()
    {
        if ($this->maxExecutionTime === 0) {
            return;
        }
        if ((time() - $this->worker->createdAt()) > $this->maxExecutionTime) {
            CakeLog::info("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - worker max execution time reached, exiting gracefully worker...");
            exit;
        }
    }

    private function processTask(array $task)
    {
        $this->logMessage('info', $task['id'], "processing task: {$task['type']}");

        if (isset($task['Job']) && $task['Job']['status'] === Job::STATUS_RUNNING) {
            $this->logMessage('info', $task['id'], "job is already running for this task: {$task['last_job_id']}");
            return;
        }

        $this->setNextExecutionTime($task);

        // Reset last job ID to null before processing
        if ($task['last_job_id']) {
            $this->Task->id = $task['id'];
            $this->Task->saveField('last_job_id', null);
        }

        if ($task['type'] == 'Server') {
            $this->runServerTask($task);
        } elseif ($task['type'] == 'Feed') {
            if ($task['action'] === 'fetch') {
                $this->runFeedFetchTask($task);
            } elseif ($task['action'] === 'cache') {
                $this->runFeedCacheTask($task);
            } else {
                $this->logMessage('error', $task['id'], "unknown action for Feed: {$task['action']}");
                return;
            }
        } elseif ($task['type'] == 'TAXII') {
            if ($task['action'] !== 'push') {
                $this->logMessage('error', $task['id'], "unknown action for TAXII: {$task['action']}");
                return;
            }

            $this->runTaxiiPushTask($task);
        } elseif ($task['type'] == 'Workflow') {
            $this->runWorkflowAdHoc($task);
        } elseif ($task['type'] == 'Periodic Summary') {
            if ($task['action'] !== 'send') {
                $this->logMessage('error', $task['id'], "unknown action for Periodic Summary: {$task['action']}");
                return;
            }

            $this->runSendPeriodicSummary($task);
        } elseif ($task['type'] == 'Admin') {
            $this->runAdminTask($task);
        } else {
            $this->logMessage('error', $task['id'], "unknown type: {$task['type']}");
            return;
        }
    }

    private function logMessage(string $type, $taskId, string $message)
    {
        $this->Task->id = $taskId;
        if ($type === 'error') {
            CakeLog::error("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - Task ID: {$taskId} - {$message}");
            try {
                // Persisting the message is a database write inside the handler
                // for a failure that may itself be the database being down.
                $this->Task->saveField('message', $message);
            } catch (Throwable $e) {
                CakeLog::error("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - Task ID: {$taskId} - could not persist task message: " . $e->getMessage());
            }
        } else {
            CakeLog::info("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - Task ID: {$taskId} - {$message}");
        }
    }

    private function setNextExecutionTime(array $task)
    {
        $previous = (int)$task['next_execution_time'];
        $interval = (int)$task['timer'];
        $now = time();

        $missed = max(1, ceil(($now - $previous) / $interval));
        $next = $previous + $missed * $interval;

        $task['next_execution_time'] = $next;

        try {
            $this->Task->id = $task['id'];
            $this->Task->saveField('next_execution_time', $task['next_execution_time']);
        } catch (Throwable $e) {
            $this->logMessage('error', $task['id'], "failed to save next_execution_time. Error: " . $e->getMessage());
            return;
        }
    }

    private function runServerTask($task)
    {
        if (!in_array($task['action'], ['pull', 'push', 'cache'], true)) {
            $this->logMessage('error', $task['id'], "unknown action: {$task['action']}");
            return;
        }

        $user = $this->User->getAuthUser($task['user_id']);
        if (empty($user)) {
            $this->logMessage('error', $task['id'], "user ID do not match an existing user.");
            return;
        }

        [$serverId, $technique] = explode(',', $task['params']);

        if (!is_numeric($serverId) && $serverId != 'all') {
            $this->logMessage('error', $task['id'], "invalid parameters: expected numeric serverId or 'all'.");
            return;
        }

        $jobId = $this->Job->createJob($user, Job::WORKER_DEFAULT, $task['action'], "Server: $serverId, $technique",  ucfirst($task['action'] . 'ing.'));

        if ($serverId === 'all' && $task['action'] === 'pull') {
            $this->enqueueServerPullAll($task, $user, $jobId);
        } elseif (is_numeric($serverId) && $task['action'] === 'pull') {
            $this->enqueueServerPullById($task, $user, $jobId);
        } elseif ($serverId === 'all' && $task['action'] === 'push') {
            $this->enqueueServerPushAll($task, $user, $jobId);
        } elseif (is_numeric($serverId) && $task['action'] === 'push') {
            $this->enqueueServerPushById($task, $user, $jobId);
        } elseif ($serverId === 'all' && $task['action'] === 'cache') {
            $this->enqueueServerCacheAll($task, $user, $jobId);
        } elseif (is_numeric($serverId) && $task['action'] === 'cache') {
            $this->enqueueServerCacheById($task, $user, $jobId);
        } elseif ($task['action'] === 'pull' || $task['action'] === 'push') {
            $this->logMessage('error', $task['id'], "invalid action for server task: {$task['action']}");
            return;
        }

        $this->Task->save([
            'id' => $task['id'],
            'last_job_id' => $jobId,
            'message' => 'Enqueued',
            'last_run_at' => time()
        ]);
    }

    public function enqueueServerPullById($task, $user, $jobId)
    {
        [$serverId, $technique] = explode(',', $task['params']);

        if (!in_array($technique, ['full', 'update'], true)) {
            $this->logMessage('error', $task['id'], "invalid parameters: expected technique to be 'full' or 'update'.");
            return;
        }

        $this->getBackgroundJobsTool()->enqueue(
            BackgroundJobsTool::DEFAULT_QUEUE,
            BackgroundJobsTool::CMD_SERVER,
            [
                'pull',
                $user['id'],
                $serverId,
                $technique,
                $jobId
            ],
            true,
            $jobId
        );

        $this->logMessage('info', $task['id'], "enqueued Server Pull for Server ID: {$serverId}.");
    }

    public function enqueueServerPullAll($task, $user, $jobId)
    {
        [$serverId, $technique] = explode(',', $task['params']);

        if (!in_array($technique, ['full', 'update'], true)) {
            $this->logMessage('error', $task['id'], "invalid parameters: expected technique to be 'full' or 'update'.");
            return;
        }

        $this->getBackgroundJobsTool()->enqueue(
            BackgroundJobsTool::DEFAULT_QUEUE,
            BackgroundJobsTool::CMD_SERVER,
            [
                'pullAll',
                $user['id'],
                $technique,
                $jobId
            ],
            true,
            $jobId
        );

        $this->logMessage('info', $task['id'], "enqueued Server Pull for all servers.");
    }

    public function enqueueServerPushAll($task, $user, $jobId)
    {
        [$serverId, $technique] = explode(',', $task['params']);

        if (!in_array($technique, ['full', 'update'], true)) {
            $this->logMessage('error', $task['id'], "invalid parameters: expected technique to be 'full' or 'update'.");
            return;
        }

        $this->getBackgroundJobsTool()->enqueue(
            BackgroundJobsTool::DEFAULT_QUEUE,
            BackgroundJobsTool::CMD_SERVER,
            [
                'pushAll',
                $user['id'],
                $technique,
                $jobId
            ],
            true,
            $jobId
        );

        $this->logMessage('info', $task['id'], "enqueued Server Push for all servers.");
    }

    public function enqueueServerPushById($task, $user, $jobId)
    {
        [$serverId, $technique] = explode(',', $task['params']);

        $this->getBackgroundJobsTool()->enqueue(
            BackgroundJobsTool::DEFAULT_QUEUE,
            BackgroundJobsTool::CMD_SERVER,
            [
                'push',
                $user['id'],
                $serverId,
                $technique,
                $jobId
            ],
            true,
            $jobId
        );


        $this->logMessage('info', $task['id'], "enqueued Server Push for Server ID: {$serverId}.");
    }

    public function enqueueServerCacheAll($task, $user, $jobId)
    {
        $this->getBackgroundJobsTool()->enqueue(
            BackgroundJobsTool::DEFAULT_QUEUE,
            BackgroundJobsTool::CMD_SERVER,
            [
                'cacheServerAll',
                $user['id'],
                $jobId
            ],
            true,
            $jobId
        );

        $this->logMessage('info', $task['id'], "enqueued Server Push for all servers.");
    }

    public function enqueueServerCacheById($task, $user, $jobId)
    {
        [$serverId] = explode(',', $task['params']);

        $this->getBackgroundJobsTool()->enqueue(
            BackgroundJobsTool::DEFAULT_QUEUE,
            BackgroundJobsTool::CMD_SERVER,
            [
                'cacheServer',
                $user['id'],
                $serverId,
                $jobId
            ],
            true,
            $jobId
        );

        $this->logMessage('info', $task['id'], "enqueued Server Push for Server ID: {$serverId}.");
    }

    private function runFeedFetchTask($task)
    {
        $feedId = $task['params'];

        if (!is_numeric($feedId) && $feedId != 'all') {
            $this->logMessage('error', $task['id'], "invalid parameters: expected numeric feedId or `all`.");
            return;
        }

        $user = $this->User->getAuthUser($task['user_id']);
        if (empty($user)) {
            $this->logMessage('error', $task['id'], "user ID do not match an existing user.");
            return;
        }

        $jobId = $this->Job->createJob(
            $user,
            Job::WORKER_DEFAULT,
            'fetch_feeds',
            'Feed: ' . $feedId,
            __('Starting fetch from Feed.')
        );

        $this->Feed->getBackgroundJobsTool()->enqueue(
            BackgroundJobsTool::DEFAULT_QUEUE,
            BackgroundJobsTool::CMD_SERVER,
            [
                'fetchFeed',
                $user['id'],
                $feedId,
                $jobId
            ],
            true,
            $jobId
        );

        $this->Task->save([
            'id' => $task['id'],
            'last_job_id' => $jobId,
            'message' => 'Enqueued',
            'last_run_at' => time()
        ]);

        $this->logMessage('info', $task['id'], "enqueued fetch for Feed ID: {$feedId}.");
    }

    private function runFeedCacheTask($task)
    {
        $params = explode(',', $task['params']);

        $feedId = $params[0] ?? 'all';
        $scope = $params[1] ?? null;

        if (!is_numeric($feedId) && $feedId != 'all') {
            $this->logMessage('error', $task['id'], "invalid parameters: expected feedId to be numeric or 'all'.");
            return;
        }

        if (isset($scope) && !in_array($scope, ['all', 'freetext', 'csv', 'misp', 'all'], true)) {
            $this->logMessage('error', $task['id'], "invalid parameters: expected scope to be 'freetext', 'csv', 'misp' or 'all'.");
            return;
        }

        $user = $this->User->getAuthUser($task['user_id']);
        if (empty($user)) {
            $this->logMessage('error', $task['id'], "user ID do not match an existing user.");
            return;
        }

        $jobId = $this->Job->createJob(
            $user,
            Job::WORKER_DEFAULT,
            'cache_feeds',
            is_numeric($feedId) ? $feedId : $scope,
            __('Starting feed caching.')
        );

        $this->Feed->getBackgroundJobsTool()->enqueue(
            BackgroundJobsTool::DEFAULT_QUEUE,
            BackgroundJobsTool::CMD_SERVER,
            [
                'cacheFeed',
                $user['id'],
                is_numeric($feedId) ? $feedId : $scope,
                $jobId
            ],
            true,
            $jobId
        );

        $this->Task->save([
            'id' => $task['id'],
            'last_job_id' => $jobId,
            'message' => 'Enqueued',
            'last_run_at' => time()
        ]);

        $this->logMessage('info', $task['id'], "enqueued cache for Feed with scope: {$scope}.");
    }

    private function runTaxiiPushTask($task)
    {
        $taxiiServerId = $task['params'];

        if (!is_numeric($taxiiServerId) && $taxiiServerId !== 'all') {
            $this->logMessage('error', $task['id'], "invalid parameters: expected numeric TAXII server ID or 'all'.");
            return;
        }

        $user = $this->User->getAuthUser($task['user_id']);
        if (empty($user)) {
            $this->logMessage('error', $task['id'], "user ID do not match an existing user.");
            return;
        }

        if (is_numeric($taxiiServerId) && !$this->TaxiiServer->hasAny([
            'TaxiiServer.id' => $taxiiServerId,
            'TaxiiServer.enabled' => 1,
        ])) {
            $this->logMessage('error', $task['id'], "TAXII server is not found or not enabled: {$taxiiServerId}.");
            return;
        }

        $jobId = $this->Job->createJob(
            $user,
            Job::WORKER_DEFAULT,
            'push_taxii',
            'TAXII Server: ' . $taxiiServerId,
            __('Starting TAXII push.')
        );

        $this->getBackgroundJobsTool()->enqueue(
            BackgroundJobsTool::DEFAULT_QUEUE,
            BackgroundJobsTool::CMD_SERVER,
            [
                'push_taxii',
                $user['id'],
                $taxiiServerId,
                $jobId
            ],
            true,
            $jobId
        );

        $this->Task->save([
            'id' => $task['id'],
            'last_job_id' => $jobId,
            'message' => 'Enqueued',
            'last_run_at' => time()
        ]);

        $this->logMessage('info', $task['id'], "enqueued TAXII Push for TAXII Server ID: {$taxiiServerId}.");
    }

    public function runWorkflowAdHoc($task)
    {
        $workflowId = $task['params'];
        if (empty($workflowId)) {
            $this->logMessage('error', $task['id'], "invalid parameters: expected workflow ID.");
            return;
        }

        $user = $this->User->getAuthUser($task['user_id']);
        if (empty($user)) {
            $this->logMessage('error', $task['id'], "user ID do not match an existing user.");
            return;
        }

        $jobId = $this->Job->createJob(
            $user,
            Job::WORKER_DEFAULT,
            'adhoc_workflow',
            $workflowId,
            __('Starting Ad-Hoc Workflow execution.')
        );

        $this->getBackgroundJobsTool()->enqueue(
            BackgroundJobsTool::DEFAULT_QUEUE,
            BackgroundJobsTool::CMD_WORKFLOW,
            [
                'executeAdHocWorkflow',
                $workflowId,
                null, // TODO: support for ad-hoc workflow payload
                null, // TODO: check what is parameter 3 for executeAdHocWorkflow
                $jobId
            ],
            true,
            $jobId
        );

        $this->Task->save([
            'id' => $task['id'],
            'last_job_id' => $jobId,
            'message' => 'Enqueued',
            'last_run_at' => time()
        ]);

        $this->logMessage('info', $task['id'], "enqueued execution for Ad-Hoc Workflow ID: {$workflowId}.");
    }

    public function runSendPeriodicSummary($task)
    {
        $user = $this->User->getAuthUser($task['user_id']);
        if (empty($user)) {
            $this->logMessage('error', $task['id'], "user ID do not match an existing user.");
            return;
        }

        $jobId = $this->Job->createJob(
            $user,
            Job::WORKER_DEFAULT,
            'send_periodic_summary',
            $user['id'],
            __('Starting Periodic Summary sending.')
        );

        $this->getBackgroundJobsTool()->enqueue(
            BackgroundJobsTool::DEFAULT_QUEUE,
            BackgroundJobsTool::CMD_SERVER,
            [
                'sendPeriodicSummaryToUsers',
                $jobId
            ],
            true,
            $jobId
        );

        $this->Task->save([
            'id' => $task['id'],
            'last_job_id' => $jobId,
            'message' => 'Enqueued',
            'last_run_at' => time()
        ]);

        $this->logMessage('info', $task['id'], "enqueued Periodic Summary sending.");
    }

    public function runAdminTask($task)
    {
        if (!in_array($task['action'], self::ADMIN_ACTIONS)) {
            $this->logMessage('error', $task['id'], "unknown admin action: {$task['action']}");
            return;
        }

        $user = $this->User->getAuthUser($task['user_id']);
        if (empty($user)) {
            $this->logMessage('error', $task['id'], "user ID do not match an existing user.");
            return;
        }

        $jobId = $this->Job->createJob(
            $user,
            Job::WORKER_DEFAULT,
            'admin_action',
            $task['action'],
            __('Starting Admin Action execution.')
        );

        $jobParams = [
            $task['action'],
            $jobId
        ];

        if ($task['action'] === 'updateGalaxies') {
            $jobParams = [
                $task['action'],
                false,
                $jobId
            ];
        }

        if ($task['action'] === 'updateObjectTemplates') {
            $jobParams = [
                $task['action'],
                $user['id'],
                $jobId
            ];
        }

        // Enqueue the admin action
        $this->getBackgroundJobsTool()->enqueue(
            BackgroundJobsTool::DEFAULT_QUEUE,
            BackgroundJobsTool::CMD_ADMIN,
            $jobParams,
            true,
            $jobId
        );

        $this->Task->save([
            'id' => $task['id'],
            'last_job_id' => $jobId,
            'message' => 'Enqueued',
            'last_run_at' => time()
        ]);

        $this->logMessage('info', $task['id'], "enqueued Admin Action: {$task['action']}.");
    }
}
