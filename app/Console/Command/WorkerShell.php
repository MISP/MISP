<?php

declare(strict_types=1);

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
        return $parser;
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