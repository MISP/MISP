<?php

declare(strict_types=1);

App::uses('BackgroundJobsTool', 'Tools');

class MonitorWorkersShell extends AppShell
{
    /** @var BackgroundJobsTool */
    private $BackgroundJobsTool;

    /** @var int */
    private $sleepInterval;

    private const DEFAULT_SLEEP_INTERVAL = 5; // seconds

    public function initialize(): void
    {
        $this->BackgroundJobsTool = new BackgroundJobsTool();
        $this->BackgroundJobsTool->initTool(Configure::read('BackgroundJobs'));
    }

    public function getOptionParser(): ConsoleOptionParser
    {
        $parser = parent::getOptionParser();
        $parser->addOption(
            'sleep',
            [
                'help' => 'Sleep interval between jobs (seconds).',
                'default' => self::DEFAULT_SLEEP_INTERVAL,
                'required' => false
            ]
        );

        return $parser;
    }


    public function main(): void
    {
        $this->sleepInterval = (int)$this->params['sleep'];
        CakeLog::info("[WORKERS MONITOR] - starting to monitor workers...");

        while (true) {
            $this->checkWorkersProcessStatus($this->BackgroundJobsTool->getWorkers());

            sleep($this->sleepInterval);
        }
    }

    /**
     * Check workers process status
     *
     * @param Worker[] $workers
     * @return void
     */
    private function checkWorkersProcessStatus(array $workers): void
    {
        foreach ($workers as $worker) {
            if (!file_exists("/proc/{$worker->pid()}")) {
                CakeLog::info("[WORKERS MONITOR] - worker with pid {$worker->pid()} is gone.");
                $this->BackgroundJobsTool->unregisterWorker($worker->pid());
            }

            $this->BackgroundJobsTool->updateWorkerStatus(
                $worker->pid(),
                Worker::STATUS_RUNNING
            );
        }
    }
}
