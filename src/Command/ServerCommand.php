<?php

namespace App\Command;

use App\Model\Entity\Server;
use Cake\Command\Command;
use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\Core\Configure;
use App\Model\Entity\Job;

class ServerCommand extends Command
{
    use LocatorAwareTrait;

    /** @var ConsoleIo */
    private $io;

    public function execute(Arguments $args, ConsoleIo $io)
    {
        $this->io = $io;

        $arguments = $args->getArguments();
        $action = array_shift($arguments);

        switch ($action) {
            case 'fetchFeed':
                $this->fetchFeed(...$arguments);
                break;
            default:
                $this->io->err('Invalid action.');
        }
        $this->io->out("Bye.");
    }

    public function fetchFeed($userId, $feedId, $jobId = null)
    {
        if (empty($userId) || empty($feedId)) {
            $this->io->err('Usage: ' . (new Server())->command_line_functions['console_automation_tasks']['data']['Fetch feeds as local data'] . PHP_EOL);
            die();
        }

        $UsersTable = $this->fetchTable('Users');
        $user = $UsersTable->getAuthUser($userId, true);

        Configure::write('CurrentUserId', $userId);

        $FeedsTable = $this->fetchTable('Feeds');
        $JobsTable = $this->fetchTable('Jobs');

        if (!empty($jobId)) {
            $jobId = $this->args[2];
        } else {
            $jobId = $JobsTable->createJob($user->toArray(), Job::WORKER_DEFAULT, 'fetch_feeds', 'Feed: ' . $feedId, 'Starting fetch from Feed.');
        }
        if ($feedId === 'all') {
            $feedIds = $FeedsTable->find('column', array(
                'fields' => array('id'),
                'conditions' => array('enabled' => 1)
            ))->toArray();
            $successes = 0;
            $fails = 0;
            foreach ($feedIds as $k => $feedId) {
                $JobsTable->saveProgress($jobId, 'Fetching feed: ' . $feedId, 100 * $k / count($feedIds));
                $result = $FeedsTable->downloadFromFeedInitiator($feedId, $user);
                if ($result) {
                    $successes++;
                } else {
                    $fails++;
                }
            }
            $message = 'Job done. ' . $successes . ' feeds pulled successfully, ' . $fails . ' feeds could not be pulled.';
            $JobsTable->saveStatus($jobId, true, $message);
            $this->io->out($message);
        } else {
            $feedEnabled = $FeedsTable->exists([
                'enabled' => 1,
                'id' => $feedId,
            ]);
            if ($feedEnabled) {
                $result = $FeedsTable->downloadFromFeedInitiator($feedId, $user, $jobId);
                if (!$result) {
                    $JobsTable->saveStatus($jobId, false, 'Job failed. See error log for more details.');
                    $this->io->err('Job failed.');
                } else {
                    $JobsTable->saveStatus($jobId, true);
                    $this->io->out('Job done.');
                }
            } else {
                $message = "Feed with ID $feedId not found or not enabled.";
                $JobsTable->saveStatus($jobId, false, $message);
                $this->io->err($message);
            }
        }
    }
}
