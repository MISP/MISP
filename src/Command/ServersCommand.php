<?php

namespace App\Command;

use Cake\Core\Configure;
use App\Model\Entity\Job;
use App\Lib\Tools\ServerSyncTool;
use App\Lib\Tools\BackgroundJobsTool;
use Exception;

class ServersCommand extends MISPCommand
{
    protected $defaultTable = 'Servers';

    protected $validActions = [
        'fetchFeed',
        'list',
        'listServers',
        'test',
        'fetchIndex',
        'pullAll',
        'pull',
    ];

    /** @var array */
    protected $usage = [
        'test' => 'bin/cake servers test `server_id`',
        'fetchIndex' => 'bin/cake servers fetchIndex `server_id`',
        'fetchFeed' => 'bin/cake servers `fetchFeed` `user_id` feed_id|all|csv|text|misp [job_id]',
        'pullAll' => 'bin/cake servers pullAll `user_id` [full|update]',
        'pull' => 'bin/cake servers pull `user_id` `server_id` [full|update]',
    ];

    public function list()
    {
        $servers = $this->Servers->find('all', [
            'fields' => ['id', 'name', 'url'],
            'recursive' => 0
        ]);
        foreach ($servers as $server) {
            echo sprintf(
                '%sServer #%s :: %s :: %s',
                PHP_EOL,
                $server['id'],
                $server['name'],
                $server['url']
            );
        }
        echo PHP_EOL;
    }

    public function listServers()
    {
        $servers = $this->Servers->find('all', [
            'fields' => ['id', 'name', 'url'],
            'recursive' => 0
        ])->toArray();
        $res = ['servers' => $servers];
        $this->outputJson($res);
    }

    public function test($serverId = null)
    {
        if (empty($serverId)) {
            $this->showActionUsageAndExit();
        }

        $serverId = intval($serverId);
        $server = $this->getServer($serverId);

        $res = $this->Servers->runConnectionTest($server, false);

        $this->outputJson($res);
    }

    public function fetchIndex($serverId = null)
    {
        if (empty($serverId)) {
            $this->showActionUsageAndExit();
        }

        $server = $this->getServer($serverId);

        $serverSync = new ServerSyncTool($server, $this->Servers->setupSyncRequest($server));
        $index = $this->Servers->getEventIndexFromServer($serverSync);

        $this->outputJson($index);
    }

    public function pullAll($userId = null, $technique = 'full')
    {
        if (empty($userId)) {
            $this->showActionUsageAndExit();
        }

        $user = $this->getUser($userId);

        $servers = $this->Servers->find('list', array(
            'conditions' => array('pull' => 1),
            'recursive' => -1,
            'order' => 'priority',
            'fields' => array('id', 'name'),
        ))->toArray();

        foreach ($servers as $serverId => $serverName) {
            $JobsTable = $this->fetchTable('Jobs');
            $jobId = $JobsTable->createJob($user, Job::WORKER_DEFAULT, 'pull', "Server: $serverId", 'Pulling.');
            $backgroundJobId = $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_SERVER,
                [
                    'pull',
                    $user['id'],
                    $serverId,
                    $technique,
                    $jobId,
                ],
                true,
                $jobId
            );

            $this->io->out("Enqueued pulling from $serverName server as job $backgroundJobId");
        }
    }

    public function pull($userId = null, $serverId = null, $technique = 'full', $jobId = null, $force = false)
    {
        if (empty($userId) || empty($serverId)) {
            $this->showActionUsageAndExit();
        }

        $user = $this->getUser($userId);
        $server = $this->getServer($serverId);
        $JobsTable = $this->fetchTable('Jobs');

        if (empty($jobId)) {
            $jobId = $JobsTable->createJob($user, Job::WORKER_DEFAULT, 'pull', 'Server: ' . $serverId, 'Pulling.');
        }

        try {
            $result = $this->Servers->pull($user, $technique, $server, $jobId, $force);
            if (is_array($result)) {
                $message = __('Pull completed. {0} events pulled, {1} events could not be pulled, {2} proposals pulled, {3} sightings pulled, {4} clusters pulled.', count($result[0]), count($result[1]), $result[2], $result[3], $result[4]);
                $JobsTable->saveStatus($jobId, true, $message);
            } else {
                $message = __('ERROR: {0}', $result);
                $JobsTable->saveStatus($jobId, false, $message);
            }
        } catch (Exception $e) {
            $JobsTable->saveStatus($jobId, false, __('ERROR: {0}', $e->getMessage()));
            throw $e;
        }

        $this->io->out($message);
    }

    public function fetchFeed($userId, $feedId, $jobId = null)
    {
        if (empty($userId) || empty($feedId)) {
            $this->showActionUsageAndExit();
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
                    $this->io->error('Job failed.');
                } else {
                    $JobsTable->saveStatus($jobId, true);
                    $this->io->out('Job done.');
                }
            } else {
                $message = "Feed with ID $feedId not found or not enabled.";
                $JobsTable->saveStatus($jobId, false, $message);
                $this->io->error($message);
            }
        }
    }

    /**
     * @param int $userId
     * @return array
     */
    private function getUser($userId): array
    {
        $UsersTable = $this->fetchTable('Users');
        $user = $UsersTable->getAuthUser($userId, true);

        if (empty($user)) {
            $this->io->error('User ID do not match an existing user.');
            die();
        }

        return $user->toArray();
    }

    /**
     * @param int $serverId
     * @return array
     */
    private function getServer($serverId): array
    {
        $server = $this->Servers->get($serverId);

        if (!$server) {
            $this->io->error("Server with ID $serverId doesn't exists.");
            die();
        }

        return $server->toArray();
    }
}
