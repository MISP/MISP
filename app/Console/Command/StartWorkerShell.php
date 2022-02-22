<?php

declare(strict_types=1);

App::uses('BackgroundJobsTool', 'Tools');
App::uses('ProcessTool', 'Tools');

class StartWorkerShell extends AppShell
{
    /** @var BackgroundJobsTool */
    private $BackgroundJobsTool;

    /** @var Worker */
    private $worker;

    /** @var int */
    private $maxExecutionTime;

    const DEFAULT_MAX_EXECUTION_TIME = 86400; // 1 day

    public function initialize()
    {
        parent::initialize();
        $this->BackgroundJobsTool = new BackgroundJobsTool(Configure::read('SimpleBackgroundJobs'));
    }

    public function getOptionParser(): ConsoleOptionParser
    {
        $parser = parent::getOptionParser();
        $parser
            ->addArgument('queue', [
                'help' => 'Name of the queue to process.',
                'choices' => $this->BackgroundJobsTool->getQueues(),
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
        $this->worker = new Worker(
            [
                'pid' => getmypid(),
                'queue' => $this->args[0],
                'user' => ProcessTool::whoami(),
            ]
        );

        $this->maxExecutionTime = (int)$this->params['maxExecutionTime'];

        CakeLog::info("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - starting to process background jobs...");

        while (true) {
            $this->checkMaxExecutionTime();

            $job = $this->BackgroundJobsTool->dequeue($this->worker->queue());
            if ($job) {
                $this->runJob($job);
            }
        }
    }

    /**
     * @param BackgroundJob $job
     */
    private function runJob(BackgroundJob $job)
    {
        CakeLog::info("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - launching job with ID: {$job->id()}...");

        try {
            $job->setStatus(BackgroundJob::STATUS_RUNNING);

            $command = implode(' ', array_merge([$job->command()], $job->args()));
            CakeLog::info("[JOB ID: {$job->id()}] - started command `$command`.");
            $this->BackgroundJobsTool->update($job);

            $job->run();

            if ($job->status() === BackgroundJob::STATUS_COMPLETED) {
                CakeLog::info("[JOB ID: {$job->id()}] - completed.");
            } else {
                CakeLog::error("[JOB ID: {$job->id()}] - failed with error code {$job->returnCode()}. STDERR: {$job->error()}. STDOUT: {$job->output()}.");
            }
        } catch (Exception $exception) {
            CakeLog::error("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - job ID: {$job->id()} failed with exception: {$exception->getMessage()}");
            $job->setStatus(BackgroundJob::STATUS_FAILED);
        }
        $this->BackgroundJobsTool->update($job);
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
