<?php

namespace App\Command;

use App\Lib\Tools\BackgroundJobsTool;
use App\Lib\Tools\ProcessTool;
use App\Model\Entity\BackgroundJob;
use App\Model\Entity\Worker;
use Cake\Command\Command;
use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
use Cake\Console\ConsoleOptionParser;
use Cake\Log\LogTrait;
use Exception;

class StartWorkerCommand extends Command
{
    use LogTrait;

    /** @var Worker */
    private $worker;

    /** @var int */
    private $maxExecutionTime;

    /** @var BackgroundJobsTool */
    private $BackgroundJobsTool;

    const DEFAULT_MAX_EXECUTION_TIME = 86400; // 1 day

    protected function buildOptionParser(ConsoleOptionParser $parser): ConsoleOptionParser
    {
        $parser->setDescription("Start a worker queue.");
        $parser
            ->addArgument(
                'queue',
                [
                    'help' => 'Name of the queue to process.',
                    'choices' => BackgroundJobsTool::getInstance()->getQueues(),
                    'required' => true
                ]
            )
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

    public function execute(Arguments $args, ConsoleIo $io)
    {
        $this->worker = new Worker(
            [
                'pid' => getmypid(),
                'queue' => $args->getArgument('queue'),
                'user' => ProcessTool::whoami(),
            ]
        );

        $this->maxExecutionTime = (int)$args->getOption('maxExecutionTime');

        $this->log("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - starting to process background jobs...", 'info');

        while (true) {
            $this->checkMaxExecutionTime();

            $job = BackgroundJobsTool::getInstance()->dequeue($this->worker->queue());
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
        $this->log("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - launching job with ID: {$job->id()}...", 'info');

        try {
            $job->setStatus(BackgroundJob::STATUS_RUNNING);

            $command = implode(' ', array_merge([$job->command()], $job->args()));
            $this->log("[JOB ID: {$job->id()}] - started command `$command`.", 'info');
            BackgroundJobsTool::getInstance()->update($job);

            $job->run();

            if ($job->status() === BackgroundJob::STATUS_COMPLETED) {
                $this->log("[JOB ID: {$job->id()}] - completed.", 'info');
            } else {
                $this->log("[JOB ID: {$job->id()}] - failed with error code {$job->returnCode()}. STDERR: {$job->error()}. STDOUT: {$job->output()}.", 'error');
            }
        } catch (Exception $exception) {
            $this->log("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - job ID: {$job->id()} failed with exception: {$exception->getMessage()}", 'error');
            $job->setStatus(BackgroundJob::STATUS_FAILED);
        }
        BackgroundJobsTool::getInstance()->update($job);
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
            $this->log("[WORKER PID: {$this->worker->pid()}][{$this->worker->queue()}] - worker max execution time reached, exiting gracefully worker...", 'info');
            exit;
        }
    }
}
