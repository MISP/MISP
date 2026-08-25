<?php

declare(strict_types=1);

App::uses('Worker', 'Tools/BackgroundJobs');

/**
 * @property Job $Job
 */
class WorkerShell extends AppShell
{
    public $uses = ['Job'];

    public function getOptionParser(): ConsoleOptionParser
    {
        $parser = parent::getOptionParser();
        $parser->addSubcommand('showQueues', [
            'help' => __('Show jobs in worker queues'),
        ]);
        $parser->addSubcommand('flushQueue', [
            'help' => __('Flush jobs in given queue'),
            'parser' => [
                'arguments' => [
                    'queue' => ['help' => __('Queue name'), 'required' => true],
                ],
            ],
        ]);
        $parser->addSubcommand('showJobStatus', [
            'help' => __('Show job status'),
            'parser' => [
                'arguments' => [
                    'job_id' => ['help' => __('Job ID (ID or UUID)'), 'required' => true],
                ],
            ],
        ]);
        $parser->addSubcommand('status', [
            'help' => __('Show the state of Redis, Supervisor and every background worker'),
        ]);
        $parser->addSubcommand('restart', [
            'help' => __('Restart all workers, or a single one'),
            'parser' => [
                'arguments' => [
                    'worker' => [
                        'help' => __('Worker name (e.g. scheduler_00) or PID. All workers are restarted when omitted.'),
                        'required' => false,
                    ],
                ],
            ],
        ]);
        $parser->addSubcommand('restartDead', [
            'help' => __('Start every worker of the group that is not running'),
        ]);
        return $parser;
    }

    /**
     * Report Redis / Supervisor reachability and list the workers Supervisor knows about.
     */
    public function status()
    {
        $tool = $this->getBackgroundJobsTool();

        $this->out(__('Background jobs: %s', $this->backgroundJobsStatusToString($tool->getStatus())));

        $workers = $tool->getWorkers();
        if (empty($workers)) {
            $this->out(__('No worker registered in the "%s" Supervisor group.', BackgroundJobsTool::MISP_WORKERS_PROCESS_GROUP));
            return;
        }

        $this->out('');
        $this->out(sprintf('%-10s %-8s %-12s %-8s %s', 'QUEUE', 'PID', 'USER', 'STATUS', 'STARTED'));
        foreach ($workers as $worker) {
            $this->out(sprintf(
                '%-10s %-8d %-12s %-8s %s',
                $worker->queue(),
                $worker->pid(),
                $worker->user(),
                $this->workerStatusToString($worker->status()),
                date('c', $worker->createdAt())
            ));
        }
    }

    public function restart()
    {
        $tool = $this->getBackgroundJobsTool();
        $worker = $this->args[0] ?? null;

        try {
            if ($worker === null) {
                $tool->restartWorkers(true);
                $this->out(__('All workers restarted.'));
                return;
            }

            $tool->stopWorker($worker, true);
            if (is_numeric($worker)) {
                // A PID no longer identifies a Supervisor program once stopped.
                $tool->restartDeadWorkers(true);
            } else {
                $tool->startWorker($worker, true);
            }
            $this->out(__('Worker %s restarted.', $worker));
        } catch (Throwable $e) {
            $this->error(__('Could not restart the worker'), $e->getMessage());
        }
    }

    /**
     * Starts anything in the group that is not running, FATAL programs included.
     */
    public function restartDead()
    {
        try {
            $this->getBackgroundJobsTool()->restartDeadWorkers(true);
            $this->out(__('Dead workers restarted.'));
        } catch (Throwable $e) {
            $this->error(__('Could not restart the dead workers'), $e->getMessage());
        }
    }

    /**
     * @throws RedisException
     * @throws JsonException
     */
    public function showQueues()
    {
        $tool = $this->getBackgroundJobsTool();
        $runningJobs = $tool->runningJobs();

        foreach (BackgroundJobsTool::VALID_QUEUES as $queue) {
            $this->out("{$queue}:\t{$tool->getQueueSize($queue)}");
            $queueJobs = $runningJobs[$queue] ?? [];
            foreach ($queueJobs as $jobId => $data) {
                $this->out(" - $jobId (" . JsonTool::encode($data) .")");
            }
       }
    }

    public function flushQueue()
    {
        $queue = $this->args[0];
        try {
            $this->getBackgroundJobsTool()->clearQueue($queue);
        } catch (InvalidArgumentException $e) {
            $this->error($e->getMessage());
        }
    }

    public function showJobStatus()
    {
        $processId = $this->args[0];
        if (is_numeric($processId)) {
            $job = $this->Job->find('first', [
                'conditions' => ['Job.id' => $processId],
                'recursive' => -1,
            ]);
            if (!$job) {
                $this->error('Job not found', "Job with ID {$processId} not found");
            }

            $this->out($this->json($job['Job']));
            $processId = $job['Job']['process_id'];
        }

        if (!Validation::uuid($processId)) {
            $this->error('Job not found', "Job ID must be number or UUID, '$processId' given");
        }

        $jobStatus = $this->getBackgroundJobsTool()->getJob($processId);
        if (!$jobStatus) {
            $this->error('Job not found', "Job with UUID {$processId} not found");
        }

        $jobStatus = $jobStatus->jsonSerialize();

        foreach (['createdAt', 'updatedAt'] as $timeField) {
            if (isset($jobStatus[$timeField])) {
                $jobStatus[$timeField] = date('c', $jobStatus[$timeField]);
            }
        }

        if (isset($jobStatus['status'])) {
            $jobStatus['status'] = $this->jobStatusToString($jobStatus['status']);
        }

        $this->out($this->json($jobStatus));
    }

    private function backgroundJobsStatusToString(int $status)
    {
        switch ($status) {
            case BackgroundJobsTool::STATUS_RUNNING:
                return __('OK');
            case BackgroundJobsTool::STATUS_NOT_ENABLED:
                return __('SimpleBackgroundJobs not enabled');
            case BackgroundJobsTool::STATUS_REDIS_NOT_OK:
                return __('Redis not reachable');
            case BackgroundJobsTool::STATUS_SUPERVISOR_NOT_OK:
                return __('Supervisor not reachable');
            case BackgroundJobsTool::STATUS_REDIS_AND_SUPERVISOR_NOT_OK:
                return __('Redis and Supervisor not reachable');
        }
        return __('unknown (%s)', $status);
    }

    private function workerStatusToString(int $status)
    {
        switch ($status) {
            case Worker::STATUS_RUNNING:
                return 'running';
            case Worker::STATUS_FAILED:
                return 'failed';
            case Worker::STATUS_UNKNOWN:
                return 'unknown';
        }
        return "unknown ($status)";
    }

    private function jobStatusToString(int $jobStatus)
    {
        switch ($jobStatus) {
            case Job::STATUS_WAITING:
                return 'waiting';
            case Job::STATUS_RUNNING:
                return 'running';
            case Job::STATUS_FAILED:
                return 'failed';
            case Job::STATUS_COMPLETED:
                return 'completed';
        }
        throw new InvalidArgumentException("Invalid job status $jobStatus");
    }
}