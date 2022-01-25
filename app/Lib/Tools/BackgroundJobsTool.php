<?php

declare(strict_types=1);

App::uses('Worker', 'Tools/BackgroundJobs');
App::uses('BackgroundJob', 'Tools/BackgroundJobs');

/**
 * BackgroundJobs Tool
 * 
 * Utility class to queue jobs, run them and monitor workers.
 * 
 * To run a worker manually (debug only):
 *      $ ./Console/cake start_worker [queue]
 * 
 * It is recommended to run these commands with [Supervisor](http://supervisord.org).
 * `Supervisor` has an extensive feature set to manage scripts as services, 
 * such as autorestart, parallel execution, logging, monitoring and much more. 
 * All can be managed via the terminal or a XML-RPC API.
 * 
 * Use the following configuration as a template for the services:
 *      /etc/supervisor/conf.d/misp-workers.conf:
 *      [group:misp-workers]
 *      programs=default,email,cache,prio,update
 *
 *      ; one section per each queue type is required
 *      [program:default]
 *      command=/var/www/MISP/app/Console/cake start_worker default
 *      process_name=%(program_name)s_%(process_num)02d
 *      numprocs=5 ; adjust the amount of parallel workers to your MISP usage 
 *      autostart=true
 *      autorestart=true
 *      redirect_stderr=false
 *      stderr_logfile=/var/www/MISP/app/tmp/logs/misp-workers-errors.log
 *      stdout_logfile=/var/www/MISP/app/tmp/logs/misp-workers.log
 *      user=www-data
 * 
 */
class BackgroundJobsTool
{
    /** @var Redis */
    private $RedisConnection;

    /** @var \Supervisor\Supervisor */
    private $Supervisor;

    const MISP_WORKERS_PROCESS_GROUP = 'misp-workers';

    const
        STATUS_RUNNING = 0,
        STATUS_NOT_ENABLED = 1,
        STATUS_REDIS_NOT_OK = 2,
        STATUS_SUPERVISOR_NOT_OK = 3,
        STATUS_REDIS_AND_SUPERVISOR_NOT_OK = 4;

    const
        DEFAULT_QUEUE = 'default',
        EMAIL_QUEUE = 'email',
        CACHE_QUEUE = 'cache',
        PRIO_QUEUE = 'prio',
        UPDATE_QUEUE = 'update',
        SCHEDULER_QUEUE = 'scheduler';

    const VALID_QUEUES = [
        self::DEFAULT_QUEUE,
        self::EMAIL_QUEUE,
        self::CACHE_QUEUE,
        self::PRIO_QUEUE,
        self::UPDATE_QUEUE,
        self::SCHEDULER_QUEUE,
    ];

    const
        CMD_EVENT = 'event',
        CMD_SERVER = 'server',
        CMD_ADMIN = 'admin';

    const ALLOWED_COMMANDS = [
        self::CMD_EVENT,
        self::CMD_SERVER,
        self::CMD_ADMIN
    ];

    const CMD_TO_SHELL_DICT = [
        self::CMD_EVENT => 'EventShell',
        self::CMD_SERVER => 'ServerShell',
        self::CMD_ADMIN => 'AdminShell'
    ];

    const JOB_STATUS_PREFIX = 'job_status';

    /** @var array */
    private $settings;

    /**
     * Initialize
     * 
     * Settings should have the following format:
     *      [
     *           'enabled' => true,
     *           'redis_host' => 'localhost',
     *           'redis_port' => 6379,
     *           'redis_password' => '',
     *           'redis_database' => 1,
     *           'redis_namespace' => 'background_jobs',
     *           'max_job_history_ttl' => 86400
     *           'supervisor_host' => 'localhost',
     *           'supervisor_port' => '9001',
     *           'supervisor_user' => '',
     *           'supervisor_password' => '',
     *      ]
     *
     * @param array $settings
     */
    public function __construct(array $settings)
    {
        $this->settings = $settings;

        if ($this->settings['enabled'] === true) {
            $this->RedisConnection = $this->createRedisConnection();
        }
    }

    /**
     * Enqueue a Job.
     *
     * @param string $queue Queue name, e.g. 'default'.
     * @param string $command Command of the job.
     * @param array $args Arguments passed to the job.
     * @param boolean|null $trackStatus Whether to track the status of the job.
     * @param int|null $jobId Id of the relational database record representing the job.
     * @param array $metadata Related to the job.
     * @return string Background Job ID.
     * @throws InvalidArgumentException
     */
    public function enqueue(
        string $queue,
        string $command,
        array $args = [],
        $trackStatus = null,
        int $jobId = null,
        array $metadata = []
    ): string {

        if (!$this->settings['enabled']) {
            return $this->resqueEnqueue($queue, self::CMD_TO_SHELL_DICT[$command], $args, $trackStatus, $jobId);
        }

        $this->validateQueue($queue);
        $this->validateCommand($command);

        $backgroundJob = new BackgroundJob(
            [
                'id' => CakeText::uuid(),
                'command' => $command,
                'args' => $args,
                'metadata' => $metadata
            ]
        );

        $this->RedisConnection->rpush(
            $queue,
            $backgroundJob
        );

        $this->update($backgroundJob);

        if ($jobId) {
            $this->updateJobProcessId($jobId, $backgroundJob->id());
        }

        return $backgroundJob->id();
    }

    /**
     * Enqueue a Job using the CakeResque.
     * @deprecated
     * 
     * @param string $queue Name of the queue to enqueue the job to.
     * @param string $class Class of the job.
     * @param array $args Arguments passed to the job.
     * @param boolean $trackStatus Whether to track the status of the job.
     * @param int|null $jobId Id of the relational database record representing the job.
     * @return string Job Id.
     */
    private function resqueEnqueue(
        string $queue,
        string $class,
        $args = [],
        $trackStatus = null,
        int $jobId = null
    ): string {

        $process_id = CakeResque::enqueue(
            $queue,
            $class,
            $args,
            $trackStatus
        );

        if ($jobId) {
            $this->updateJobProcessId($jobId, $process_id);
        }

        return $process_id;
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
     * @throws Exception
     */
    public function dequeue($queue, int $timeout = 30)
    {
        $this->validateQueue($queue);

        $rawJob = $this->RedisConnection->blpop($queue, $timeout);

        if (!empty($rawJob)) {
            return new BackgroundJob($rawJob[1]);
        }

        return null;
    }

    /**
     * Get the job status.
     *
     * @param string $jobId Background Job Id.
     * 
     * 
     */
    public function getJob(string $jobId)
    {
        $rawJob = $this->RedisConnection->get(
            self::JOB_STATUS_PREFIX . ':' . $jobId
        );

        if ($rawJob) {
            return new BackgroundJob($rawJob);
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
     * Get all workers' instances.
     *
     * @return Worker[] List of worker's instances.
     */
    public function getWorkers(): array
    {
        try {
            $procs = $this->getSupervisor()->getAllProcesses();
        } catch (\Exception $exception) {
            CakeLog::error("An error occured when getting the workers statuses via Supervisor API: {$exception->getMessage()}");
            return [];
        }

        $workers = [];
        foreach ($procs as $proc) {
            if ($proc->offsetGet('group') === self::MISP_WORKERS_PROCESS_GROUP) {
                if ($proc->offsetGet('pid') > 0) {
                    $workers[] = new Worker([
                        'pid' => $proc->offsetGet('pid'),
                        'queue' => explode("_", $proc->offsetGet('name'))[0],
                        'user' => $this->processUser((int) $proc->offsetGet('pid')),
                        'createdAt' => $proc->offsetGet('start'),
                        'updatedAt' => $proc->offsetGet('now'),
                        'status' => $this->convertProcessStatus($proc->offsetGet('state'))
                    ]);
                }
            }
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
    public function getQueueSize(string $queue): int
    {
        $this->validateQueue($queue);

        if (!$this->settings['enabled']) {
            return CakeResque::getQueueSize($queue);
        }

        return $this->RedisConnection->llen($queue);
    }

    /**
     * Update job
     *
     * @param BackgroundJob $job
     * 
     * @return void
     */
    public function update(BackgroundJob $job)
    {
        $job->setUpdatedAt(time());

        $this->RedisConnection->setex(
            self::JOB_STATUS_PREFIX . ':' . $job->id(),
            $this->settings['max_job_history_ttl'],
            $job
        );
    }

    /**
     * Start worker by name
     *
     * @param string $name
     * @param boolean $waitForRestart
     * @return boolean
     */
    public function startWorker(string $name, bool $waitForRestart = false): bool
    {
        $this->validateWorkerName($name);

        return $this->getSupervisor()->startProcess(
            sprintf(
                '%s:%s',
                self::MISP_WORKERS_PROCESS_GROUP,
                $name
            ),
            $waitForRestart
        );
    }

    /**
     * Start worker by queue
     *
     * @param string $name
     * @param boolean $waitForRestart
     * @return boolean
     */
    public function startWorkerByQueue(string $queue, bool $waitForRestart = false): bool
    {
        $this->validateQueue($queue);

        $procs = $this->getSupervisor()->getAllProcesses();

        foreach ($procs as $proc) {
            if ($proc->offsetGet('group') === self::MISP_WORKERS_PROCESS_GROUP) {
                $name = explode("_", $proc->offsetGet('name'))[0];
                if ($name === $queue && $proc->offsetGet('state') != \Supervisor\Process::RUNNING) {
                    return $this->getSupervisor()->startProcess(
                        sprintf(
                            '%s:%s',
                            self::MISP_WORKERS_PROCESS_GROUP,
                            $proc->offsetGet('name')
                        ),
                        $waitForRestart
                    );
                }
            }
        }

        return false;
    }

    /**
     * Stop worker by name or pid
     *
     * @param string|int $id
     * @param boolean $waitForRestart
     * @return boolean
     */
    public function stopWorker($id, bool $waitForRestart = false): bool
    {
        if (is_numeric($id)) {
            $process = $this->getProcessByPid((int)$id);
            $name = $process->offsetGet('name');
        } else {
            $name = $id;
        }

        $this->validateWorkerName($name);

        return $this->getSupervisor()->stopProcess(
            sprintf(
                '%s:%s',
                self::MISP_WORKERS_PROCESS_GROUP,
                $name
            ),
            $waitForRestart
        );
    }

    /**
     * Restarts workers
     *
     * @param boolean $waitForRestart
     * @return void
     */
    public function restartWorkers(bool $waitForRestart = false)
    {
        $this->getSupervisor()->stopProcessGroup(self::MISP_WORKERS_PROCESS_GROUP, $waitForRestart);
        $this->getSupervisor()->startProcessGroup(self::MISP_WORKERS_PROCESS_GROUP, $waitForRestart);
    }

    /**
     * Restarts workers with status != RUNNING
     *
     * @param boolean $waitForRestart
     * @return void
     */
    public function restartDeadWorkers(bool $waitForRestart = false)
    {
        $this->getSupervisor()->startProcessGroup(self::MISP_WORKERS_PROCESS_GROUP, $waitForRestart);
    }

    /**
     * Purge queue
     *
     * @param string $queue
     * @return void
     */
    public function purgeQueue(string $queue)
    {
        $this->validateQueue($queue);

        $this->RedisConnection->del($queue);
    }

    /**
     * Return Background Jobs status
     *
     * @return integer
     */
    public function getStatus(): int
    {
        if (!$this->settings['enabled']) {
            return self::STATUS_NOT_ENABLED;
        }

        try {
            $redisStatus = $this->RedisConnection->ping();
        } catch (Exception $exception) {
            CakeLog::error("SimpleBackgroundJobs Redis error: {$exception->getMessage()}");
            $redisStatus = false;
        }

        try {
            $supervisorStatus = $this->getSupervisorStatus();
        } catch (Exception $exception) {
            CakeLog::error("SimpleBackgroundJobs Supervisor error: {$exception->getMessage()}");
            $supervisorStatus = false;
        }

        if ($redisStatus && $supervisorStatus) {
            return self::STATUS_RUNNING;
        } elseif (!$redisStatus && !$supervisorStatus) {
            return self::STATUS_REDIS_AND_SUPERVISOR_NOT_OK;
        } elseif ($redisStatus && !$supervisorStatus) {
            return self::STATUS_SUPERVISOR_NOT_OK;
        } else {
            return self::STATUS_REDIS_NOT_OK;
        }
    }

    /**
     * Return true if Supervisor process is running.
     *
     * @return boolean
     */
    public function getSupervisorStatus(): bool
    {
        return $this->getSupervisor()->getState()['statecode'] === \Supervisor\Supervisor::RUNNING;
    }

    /**
     * Validate queue
     *
     * @return boolean
     * @throws InvalidArgumentException
     */
    private function validateQueue(string $queue): bool
    {
        if (!in_array($queue, self::VALID_QUEUES, true)) {
            throw new InvalidArgumentException(
                sprintf(
                    'Invalid background job queue %s, must be one of: [%s]',
                    $queue,
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
        if (!in_array($command, self::ALLOWED_COMMANDS, true)) {
            throw new InvalidArgumentException(
                sprintf(
                    'Invalid command %s, must be one of: [%s]',
                    $command,
                    implode(', ', self::ALLOWED_COMMANDS)
                )
            );
        }

        return true;
    }

    /**
     * Validate worker name
     *
     * @param string $name
     * @return boolean
     * @throws InvalidArgumentException
     */
    private function validateWorkerName(string $name): bool
    {
        list($queue, $id) = explode('_', $name);

        $this->validateQueue($queue);

        if (!$this->validateQueue($queue) || !is_numeric($id)) {
            throw new InvalidArgumentException("Invalid worker name $name, must be one of format {queue_name}_{process_id}, example: default_00");
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
        $redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_JSON);
        $redis->setOption(Redis::OPT_PREFIX, $this->settings['redis_namespace'] . ':');
        $redisPassword = $this->settings['redis_password'];

        if (!empty($redisPassword)) {
            $redis->auth($redisPassword);
        }
        $redis->select($this->settings['redis_database']);

        return $redis;
    }

    /**
     * @return \Supervisor\Supervisor
     */
    private function getSupervisor()
    {
        if (!$this->Supervisor) {
            $this->Supervisor = $this->createSupervisorConnection();
        }
        return $this->Supervisor;
    }

    /**
     * @return \Supervisor\Supervisor
     * @throws Exception
     */
    private function createSupervisorConnection(): \Supervisor\Supervisor
    {
        $httpOptions = [];
        if (!empty($this->settings['supervisor_user']) && !empty($this->settings['supervisor_password'])) {
            $httpOptions = [
                'auth' => [
                    $this->settings['supervisor_user'],
                    $this->settings['supervisor_password'],
                ],
            ];
        }

        $host = null;
        if (substr($this->settings['supervisor_host'], 0, 5) === 'unix:') {
            if (!defined('CURLOPT_UNIX_SOCKET_PATH')) {
                throw new Exception("For unix socket connection, cURL is required.");
            }
            $httpOptions['curl'][CURLOPT_UNIX_SOCKET_PATH] = substr($this->settings['supervisor_host'], 5);
            $host = 'localhost';
        }

        $client = new \fXmlRpc\Client(
            sprintf(
                'http://%s:%s/RPC2',
                $host ?: $this->settings['supervisor_host'],
                $this->settings['supervisor_port']
            ),
            new \fXmlRpc\Transport\HttpAdapterTransport(
                new \Http\Message\MessageFactory\GuzzleMessageFactory(),
                new \GuzzleHttp\Client($httpOptions)
            )
        );

        if (class_exists('Supervisor\Connector\XmlRpc')) {
            // for compatibility with older versions of supervisor
            $connector = new \Supervisor\Connector\XmlRpc($client);
            return new \Supervisor\Supervisor($connector);
        }

        return new \Supervisor\Supervisor($client);
    }

    private function updateJobProcessId(int $jobId, string $processId)
    {
        $job = ClassRegistry::init('Job');
        $job->id = $jobId;
        $job->save(['process_id' => $processId]);
    }

    /**
     * Get Supervisor process by PID
     *
     * @param integer $pid
     * @return \Supervisor\Process
     *
     * @throws NotFoundException
     */
    private function getProcessByPid(int $pid): \Supervisor\Process
    {
        $procs = $this->getSupervisor()->getAllProcesses();

        foreach ($procs as $proc) {
            if (
                $proc->offsetGet('group') === self::MISP_WORKERS_PROCESS_GROUP &&
                $proc->offsetGet('pid') === $pid
            ) {
                return $proc;
            }
        }

        throw new NotFoundException("Worker with pid=$pid not found.");
    }

    /**
     * Convert process status to worker status
     *
     * @param integer $stateId
     * @return integer
     */
    private function convertProcessStatus(int $stateId): int
    {
        switch ($stateId) {
            case \Supervisor\Process::RUNNING:
                return Worker::STATUS_RUNNING;
            case \Supervisor\Process::UNKNOWN:
                return Worker::STATUS_UNKNOWN;
            default:
                return Worker::STATUS_FAILED;
        }
    }

    /**
     * Get effective user name
     * @param int $pid
     * @return string
     */
    private function processUser(int $pid)
    {
        if (function_exists('posix_getpwuid') && file_exists("/proc/$pid/status")) {
            $content = file_get_contents("/proc/$pid/status");
            preg_match("/Uid:\t([0-9]+)\t([0-9]+)/", $content, $matches);
            return posix_getpwuid((int)$matches[2])['name'];
        } else {
            return trim(shell_exec(sprintf("ps -o uname='' -p %s", $pid)) ?? '');
        }
    }
}
