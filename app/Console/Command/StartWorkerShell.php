<?php

declare(strict_types=1);

App::uses('BackgroundJobsTool', 'Tools');

class StartWorkerShell extends AppShell
{
    /** @var BackgroundJobsTool */
    private $BackgroundJobsTool;

    /** @var Worker */
    private $worker;

    /** @var int */
    private $sleepInterval;

    /** @var int */
    private $maxExecutionTime;

    private const DEFAULT_SLEEP_INTERVAL = 0; // seconds
    private const DEFAULT_MAX_EXECUTION_TIME = 86400; // 1 day


    public function initialize(): void
    {
        $this->BackgroundJobsTool = new BackgroundJobsTool();
        $this->BackgroundJobsTool->initTool(Configure::read('BackgroundJobs'));
    }

    public function getOptionParser(): ConsoleOptionParser
    {
        $parser = parent::getOptionParser();
        $parser
            ->addArgument('queue', [
                'help' => sprintf(
                    'Name of the queue to process. Must be one of [%]',
                    implode(', ', $this->BackgroundJobsTool->getQueues())
                ),
                'choices' => $this->BackgroundJobsTool->getQueues(),
                'required' => true
            ])
            ->addOption(
                'sleep',
                [
                    'help' => 'Sleep interval between jobs (seconds).',
                    'default' => self::DEFAULT_SLEEP_INTERVAL,
                    'required' => false
                ]
            )->addOption(
                'maxExecutionTime',
                [
                    'help' => 'Worker maximum execution time (seconds) before it self-destruct.',
                    'default' => self::DEFAULT_MAX_EXECUTION_TIME,
                    'required' => false
                ]
            );

        return $parser;
    }

    public function main(): void
    {
        $this->worker = new Worker(
            [
                'pid' => getmypid(),
                'queue' => $this->args[0]
            ]
        );

        $this->sleepInterval = (int)$this->params['sleep'];
        $this->maxExecutionTime = (int)$this->params['maxExecutionTime'];

        CakeLog::info("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - starting to process background jobs...");
        $this->BackgroundJobsTool->registerWorker($this->worker);

        while (true) {
            $this->checkMaxExecutionTime();

            $job = $this->BackgroundJobsTool->dequeue($this->worker->queue());

            if ($job) {
                CakeLog::info("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - launching job with id: {$job->id()} ...");

                try {
                    $this->BackgroundJobsTool->run($job);
                } catch (Exception $exception) {
                    CakeLog::error("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - job id: {$job->id()} failed with exception: {$exception->getMessage()}");
                    $job->status  = BackgroundJob::STATUS_FAILED;
                    $this->BackgroundJobsTool->update($job);
                }
            }

            sleep($this->sleepInterval);
        }
    }

    /**
     * Checks if worker maximum execution time is reached, and exits if so.
     *
     * @return void
     */
    private function checkMaxExecutionTime(): void
    {
        if ((time() - $this->worker->createdAt()) > $this->maxExecutionTime) {
            CakeLog::info("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - worker max execution time reached, exiting gracefully worker...");
            $this->BackgroundJobsTool->unregisterWorker($this->worker->pid());
            exit;
        }
    }
}
