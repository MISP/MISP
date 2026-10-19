<?php

declare(strict_types=1);

App::uses('ProcessTool', 'Tools');

class StartWorkerShell extends AppShell
{
    /** @var Worker */
    private $worker;

    /** @var Job|null */
    private $Job;

    /** @var int */
    private $maxExecutionTime;

    const DEFAULT_MAX_EXECUTION_TIME = 86400; // 1 day

    public function getOptionParser(): ConsoleOptionParser
    {
        $parser = parent::getOptionParser();
        $parser
            ->addArgument('queue', [
                'help' => 'Name of the queue to process.',
                'choices' => $this->getBackgroundJobsTool()->getQueues(),
                'required' => true
            ])
            ->addOption(
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
                'queue' => $this->args[0],
                'user' => ProcessTool::whoami(),
            ]
        );

        $this->maxExecutionTime = (int)$this->params['maxExecutionTime'];
        $queue = $this->worker->queue();
        $backgroundJobTool = $this->getBackgroundJobsTool();

        CakeLog::info("[WORKER PID: {$this->worker->pid()}][{$queue}] - starting to process background jobs...");

        while (true) {
            $this->checkMaxExecutionTime();

            $job = $backgroundJobTool->dequeue($queue);
            if ($job) {
                $this->runJob($job);
                $backgroundJobTool->removeFromRunning($this->worker, $job);
            }
        }
    }

    /**
     * @param BackgroundJob $job
     */
    private function runJob(BackgroundJob $job)
    {
        CakeLog::info("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - launching job with ID: {$job->id()}");

        try {
            $job->setStatus(BackgroundJob::STATUS_RUNNING);

            $command = implode(' ', array_merge([$job->command()], $job->args()));
            CakeLog::info("[JOB ID: {$job->id()}] - started command `$command`.");
            $this->getBackgroundJobsTool()->update($job);

            $start = microtime(true);
            $job->run(function (array $status) use ($job) {
                $this->getBackgroundJobsTool()->markAsRunning($this->worker, $job, $status['pid']);
            });
            $duration = number_format(microtime(true) - $start, 3, '.', '');

            if ($job->status() === BackgroundJob::STATUS_COMPLETED) {
                CakeLog::info("[JOB ID: {$job->id()}] - successfully completed in $duration seconds.");
                $this->saveJobExit($job);
            } else {
                CakeLog::error("[JOB ID: {$job->id()}] - failed with error code {$job->returnCode()} after $duration seconds. STDERR: {$job->error()}. STDOUT: {$job->output()}.");
                $errorLine = $job->errorLine();
                $this->saveJobExit($job, "Job failed (exit code {$job->returnCode()})" . ($errorLine === null ? '.' : ': ' . mb_substr($errorLine, 0, 500)));
            }
        } catch (Exception $exception) {
            CakeLog::error("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - job ID: {$job->id()} failed with exception: {$exception->getMessage()}");
            $job->setStatus(BackgroundJob::STATUS_FAILED);
            $this->saveJobExit($job, 'Job failed: ' . $exception->getMessage());
        }
        $this->getBackgroundJobsTool()->update($job);
    }

    /**
     * Records how the job ended in its `jobs` row, which otherwise only the
     * job's own code updates: a crashed job would read as queued for ever.
     *
     * @param BackgroundJob $job
     * @param string|null $failure The message of a failed job.
     * @return void
     */
    private function saveJobExit(BackgroundJob $job, ?string $failure = null)
    {
        $jobId = $job->metadata()['job_id'] ?? null;
        if (!$jobId) {
            return;
        }
        try {
            if ($this->Job === null) {
                $this->Job = ClassRegistry::init('Job');
            }
            // An idle worker can outlive the database server's wait_timeout.
            $db = $this->Job->getDataSource();
            if (!$db->isConnected()) {
                $db->disconnect();
                $db->connect();
            }
            $this->Job->saveExitStatus((int)$jobId, $failure === null, $failure);
        } catch (Throwable $e) {
            CakeLog::error("[JOB ID: {$job->id()}] - could not save the exit status of job $jobId: {$e->getMessage()}");
        }
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
}
