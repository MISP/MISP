<?php

declare(strict_types=1);

App::uses('Worker', 'Tools/BackgroundJobs');
App::uses('BackgroundJob', 'Tools/BackgroundJobs');

/**
 * BackgroundJobs Tool
 */
class BackgroundJobsTool
{
    /** @var Redis */
    private $RedisConnection;

    public const
        DEFAULT_QUEUE = 'default',
        EMAIL_QUEUE = 'email',
        CACHE_QUEUE = 'cache',
        PRIO_QUEUE = 'prio',
        UPDATE_QUEUE = 'update';

    public const VALID_QUEUES = [
        self::DEFAULT_QUEUE,
        self::EMAIL_QUEUE,
        self::CACHE_QUEUE,
        self::PRIO_QUEUE,
        self::UPDATE_QUEUE,
    ];

    public const CMD_EVENT_SHELL = 'event';

    public const ALLOWED_COMMANDS = [
        self::CMD_EVENT_SHELL
    ];

    public const JOB_STATUS_PREFIX = 'job_status';
    public const WORKER_STATUS_PREFIX = 'worker_status';

    public const CAKE_RESQUE_DEPRECATION_MESSAGE = '[DEPRECATION] CakeResque background jobs engine will be deprecated in future MISP versions, please migrate to the light-weight background jobs processor following this guide: [link].';

    /** @var array */
    private $settings;

    public function initTool(array $settings)
    {
        $this->settings = $settings;

        if (!$this->RedisConnection) {
            $this->RedisConnection = $this->createRedisConnection();
        }
    }

    /**
     * Enqueue a Job.
     *
     * @param string $queue Queue name, e.g. 'default'.
     * @param string $command command of the job.
     * @param array $args Arguments passed to the job.
     * 
     * @return string Background Job Id.
     * @throws InvalidArgumentExceptiony
     */
    public function enqueue($queue, $command, $args = [], $metadata = []): string
    {
        $this->validateQueue($queue);
        $this->validateCommand($command);

        $job = new BackgroundJob(
            [
                'id' => CakeText::uuid(),
                'command' => $command,
                'args' => $args,
                'metadata' => $metadata
            ]
        );

        $this->RedisConnection->rpush(
            $queue,
            json_encode($job->jsonSerialize())
        );

        $this->update($job);

        return $job->id();
    }

    /**
     *  Dequeue a BackgroundJob.
     *  If the queue is empty the read is blocked until a job is pushed to this queue or the timeout is reached.
     *
     * @param string $queue Queue name, e.g. 'default'.
     * @param int    $timeout Time to block the read if the queue is empty.
     *                  Must be less than your configured `read_write_timeout` 
     *                  for the redis connection.
     * 
     * @return BackgroundJob|null.
     * @throws Exception
     */
    public function dequeue($queue, int $timeout = 30): ?BackgroundJob
    {
        $this->validateQueue($queue);

        $rawJob = $this->RedisConnection->blpop($queue, $timeout);

        if (!empty($rawJob) && $rawJob[0] === $queue) {
            try {
                return new BackgroundJob(json_decode($rawJob[1], true));
            } catch (Exception $exception) {
                CakeLog::error("Failed to parse job, invalid format: {$rawJob[1]}. exception: {$exception->getMessage()}");
            }
        }

        return null;
    }

    /**
     * Get the job status.
     *
     * @param string $jobId Backgroun Job Id.
     * 
     * @return BackgroundJob|null job status.
     * 
     */
    public function getJob(string $jobId): ?BackgroundJob
    {
        $rawJob = $this->RedisConnection->get(
            self::JOB_STATUS_PREFIX . ':' . $jobId
        );

        if ($rawJob) {
            return new BackgroundJob(json_decode($rawJob, true));
        }

        return null;
    }

    /**
     * Get the queues's names.
     *
     * @return array Array containing the queues' names.
     */
    public function getQueues(): array
    {
        return self::VALID_QUEUES;
    }

    /**
     * Clear all the queue's jobs.
     *
     * @param string $queue Queue name, e.g. 'default'.
     * 
     * @return boolean True on success, false on failure.
     */
    public function clearQueue($queue): bool
    {
        $this->validateQueue($queue);

        return (bool) $this->RedisConnection->del($queue);
    }

    /**
     * Get worker by PID.
     *
     * @return Worker|null Worker instance.
     */
    public function getWorker(int $workerPid): ?Worker
    {
        $rawWorker = $this->RedisConnection->get(self::WORKER_STATUS_PREFIX . ':' . $workerPid);

        if ($rawWorker) {
            return new Worker(json_decode($rawWorker, true));
        }

        return null;
    }

    /**
     * Get all workers' instances.
     *
     * @return Worker[] List of worker's instances.
     */
    public function getWorkers(): array
    {
        $pattern = self::WORKER_STATUS_PREFIX . ':*';

        // get existing worker status keys
        $iterator = null;
        $workersKeys = [];
        while ($keys = $this->RedisConnection->scan($iterator, $pattern)) {
            foreach ($keys as $key) {
                $workersKeys[] = $key;
            }
        }

        if (!$workersKeys) {
            return [];
        }

        // get workers status
        $workersStatus = $this->RedisConnection->mget($workersKeys);

        $workers = [];
        foreach ($workersStatus as $worker) {
            $workers[] = new Worker(json_decode($worker, true));
        }

        return $workers;
    }

    /**
     * Get the number of jobs inside a queue.
     *
     * @param  string $queue Queue name, e.g. 'default'.
     * 
     * @return integer Number of jobs.
     */
    public function getQueueSize($queue): int
    {
        $this->validateQueue($queue);

        return $this->RedisConnection->llen($queue);
    }

    /**
     * Update job
     *
     * @param BackgroundJob $job
     * 
     * @return void
     */
    public function update(BackgroundJob $job): void
    {
        $job->setUpdatedAt(time());

        $this->RedisConnection->setex(
            self::JOB_STATUS_PREFIX . ':' . $job->id(),
            $this->settings['max_job_history_ttl'],
            json_encode($job->jsonSerialize()),
        );
    }

    /**
     * Run job
     *
     * @param BackgroundJob $job
     * 
     * @return integer Process return code.
     */
    public function run(BackgroundJob $job): int
    {
        $job->setStatus(BackgroundJob::STATUS_RUNNING);
        CakeLog::info("[JOB ID: {$job->id()}] - started.");

        $this->update($job);

        $job = $job->run();

        $this->update($job);

        return $job->returnCode();
    }

    /**
     * Register worker
     *
     * @param integer $workerPid
     * @param string  $queue
     * @param integer $createdAt
     * 
     * @return void
     */
    public function registerWorker(Worker $worker): void
    {
        $this->RedisConnection->set(
            self::WORKER_STATUS_PREFIX . ':' . $worker->pid(),
            json_encode($worker->jsonSerialize())
        );
    }

    /**
     * Update worker
     *
     * @param integer $workerPid
     * @param integer $status
     * 
     * @return void
     */
    public function updateWorkerStatus(int $workerPid, int $status): void
    {
        $worker = $this->getWorker($workerPid);

        if (!$worker) {
            CakeLog::warning("updateWorkerStatus: worker with PID: {$workerPid} not found.");
            return;
        }

        $worker->setUpdatedAt(time());
        $worker->setStatus($status);

        $this->RedisConnection->set(
            self::WORKER_STATUS_PREFIX . ':' . $workerPid,
            json_encode($worker->jsonSerialize())
        );
    }

    /**
     * Unregister worker
     *
     * @param integer $workerPid
     * 
     * @return void
     */
    public function unregisterWorker(int $workerPid): void
    {
        $this->RedisConnection->del(self::WORKER_STATUS_PREFIX . ':' . $workerPid);
    }

    /**
     * Validate queue
     *
     * @return boolean
     * @throws InvalidArgumentException
     */
    private function validateQueue(string $queue): bool
    {
        if (!in_array($queue, self::VALID_QUEUES)) {
            throw new InvalidArgumentException(
                sprintf(
                    'Invalid background job queue, must be one of: [%s]',
                    implode(', ', self::VALID_QUEUES)
                )
            );
        }

        return true;
    }

    /**
     * Validate command
     *
     * @return boolean
     * @throws InvalidArgumentException
     */
    private function validateCommand(string $command): bool
    {
        if (!in_array($command, self::ALLOWED_COMMANDS)) {
            throw new InvalidArgumentException(
                sprintf(
                    'Invalid command, must be one of: [%s]',
                    implode(', ', self::ALLOWED_COMMANDS)
                )
            );
        }

        return true;
    }

    /**
     * @return Redis
     */
    private function createRedisConnection(): Redis
    {
        $redis = new Redis();
        $redis->connect($this->settings['redis_host'], $this->settings['redis_port']);
        $redisPassword = $this->settings['redis_password'];
        if (!empty($redisPassword)) {
            $redis->auth($redisPassword);
        }
        $redis->select($this->settings['redis_database']);

        return $redis;
    }

    private function getSettings(): array
    {
        return [
            'redis_host' => 'localhost',
            'redis_port' => 6379,
            'redis_password' => '',
            'redis_database' => 1,
            'redis_namespace' => 'background_jobs',
            'max_job_history_ttl' => 86400
        ];
    }
}
