<?php

namespace App\Command;

use App\Lib\Tools\BackgroundJobsTool;
use App\Lib\Tools\HttpTool;
use App\Lib\Tools\LogExtendedTrait;
use App\Lib\Tools\ServerSyncTool;
use App\Model\Entity\Job;
use Cake\Chronos\Chronos;
use Exception;

class ServersCommand extends MISPCommand
{
    use LogExtendedTrait;

    protected $defaultTable = 'Servers';

    /** @var \App\Model\Table\ServersTable */
    protected $Servers;

    protected $validActions = [
        'fetchFeed',
        'list',
        'listServers',
        'test',
        'fetchIndex',
        'pullAll',
        'pull',
        'push',
        'pushAll',
        'listFeeds',
        'viewFeed',
        'toggleFeed',
        'toggleFeedCaching',
        'loadDefaultFeeds',
        'cacheServer',
        'cacheServerAll',
        'cacheFeed',
        'sendPeriodicSummaryToUsers',
    ];

    /** @var array */
    protected $usage = [
        'test' => 'bin/cake servers test `server_id`',
        'fetchIndex' => 'bin/cake servers fetchIndex `server_id`',
        'fetchFeed' => 'bin/cake servers `fetchFeed` `user_id` feed_id|all|csv|text|misp [job_id]',
        'pullAll' => 'bin/cake servers pullAll `user_id` [full|update]',
        'pull' => 'bin/cake servers pull `user_id` `server_id` [full|update]',
        'push' => 'bin/cake servers push `user_id` `server_id` [full|update] [job_id]',
        'pushAll' => 'bin/cake servers pushAll `user_id` [full|update]',
        'listFeeds' => 'bin/cake servers listFeeds [json|table]',
        'viewFeed' => 'bin/cake servers viewFeed `feed_id` [json|table]',
        'toggleFeed' => 'bin/cake servers toggleFeed `feed_id`',
        'toggleFeedCaching' => 'bin/cake servers toggleFeedCaching `feed_id`',
        'cacheServer' => 'bin/cake servers cacheServer `user_id` `server_id|all` [job_id]',
        'cacheServerAll' => 'bin/cake servers cacheServerAll `user_id` [job_id]',
        'cacheFeed' => 'bin/cake servers cacheFeed `user_id` [feed_id|all|csv|text|misp] [job_id]',
    ];

    public function list()
    {
        $servers = $this->Servers->find(
            'all',
            [
                'fields' => ['id', 'name', 'url'],
                'recursive' => 0
            ]
        );
        foreach ($servers as $server) {
            $this->io->out(
                sprintf(
                    '%sServer #%s :: %s :: %s',
                    PHP_EOL,
                    $server['id'],
                    $server['name'],
                    $server['url']
                )
            );
        }
    }

    public function listServers()
    {
        $servers = $this->Servers->find(
            'all',
            [
                'fields' => ['id', 'name', 'url'],
                'recursive' => 0
            ]
        )->toArray();
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

        $servers = $this->Servers->find(
            'list',
            [
                'conditions' => ['pull' => 1],
                'recursive' => -1,
                'order' => 'priority',
                'fields' => ['id', 'name'],
            ]
        )->toArray();

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

    public function push($userId = null, $serverId = null, $technique = 'full', $jobId = null)
    {
        if (empty($userId) || empty($serverId)) {
            $this->showActionUsageAndExit();
        }

        $JobsTable = $this->fetchTable('Jobs');
        $user = $this->getUser($userId);
        $server = $this->getServer($serverId);
        if (empty($jobId)) {
            $jobId = $JobsTable->createJob($user, Job::WORKER_DEFAULT, 'push', 'Server: ' . $serverId, 'Pushing.');
        }

        $HttpSocket = new HttpTool();
        $HttpSocket->configFromServer($server);
        $result = $this->Servers->push($serverId, $technique, $jobId, $HttpSocket, $user);

        if ($result !== true && !is_array($result)) {
            $message = 'Job failed. Reason: ' . $result;
            $JobsTable->saveStatus($jobId, false, $message);
        } else {
            $message = 'Job done.';
            $JobsTable->saveStatus($jobId, true, $message);
        }
    }

    public function pushAll($userId = null, $technique = 'full')
    {
        $user = $this->getUser($userId);

        $servers = $this->Servers->find(
            'list',
            [
                'conditions' => ['push' => 1],
                'recursive' => -1,
                'order' => 'priority',
                'fields' => ['id', 'name'],
            ]
        );

        foreach ($servers as $serverId => $serverName) {
            $jobId = $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_SERVER,
                [
                    'push',
                    $user['id'],
                    $serverId,
                    $technique
                ]
            );

            $this->io->out("Enqueued pushing from $serverName server as job $jobId");
        }
    }



    public function cacheServer($userId = null, $scope = null, $jobId = null)
    {
        if (empty($userId) || empty($scope)) {
            $this->showActionUsageAndExit();
        }

        $JobsTable = $this->fetchTable('Jobs');

        $user = $this->getUser($userId);
        if (empty($jobId)) {
            $data = [
                'worker' => 'default',
                'job_type' => 'cache_servers',
                'job_input' => 'Server: ' . $scope,
                'status' => 0,
                'retries' => 0,
                'org' => $user['Organisation']['name'],
                'message' => 'Starting server caching.',
            ];
            $job = $JobsTable->newEntity($data);
            $JobsTable->save($job);
            $jobId = $job->id;
        }
        $result = $this->Servers->cacheServerInitiator($user, $scope, $jobId);
        if ($result !== true) {
            $message = 'Job Failed. Reason: ' . $result;
            $JobsTable->saveStatus($jobId, false, $message);
        } else {
            $message = 'Job done.';
            $JobsTable->saveStatus($jobId, true, $message);
        }
        $this->io->out($message);
    }

    public function cacheServerAll($userId = null)
    {
        if (empty($userId)) {
            $this->showActionUsageAndExit();
        }

        $user = $this->getUser($userId);

        $servers = $this->Servers->find(
            'list',
            [
                'conditions' => ['pull' => 1],
                'recursive' => -1,
                'order' => 'priority',
                'fields' => ['id', 'name'],
            ]
        );

        foreach ($servers as $serverId => $serverName) {
            $jobId = $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_SERVER,
                [
                    'cacheServer',
                    $user['id'],
                    $serverId
                ]
            );

            $this->io->out("Enqueued cacheServer from $serverName server as job $jobId");
        }
    }



    public function sendPeriodicSummaryToUsers()
    {
        $periods = $this->__getPeriodsForToday();
        $start_time = time();
        $this->io->out(__('Started periodic summary generation for the {0} period', 'Started periodic summary generation for periods: {1}', count($periods), implode(', ', $periods)));

        $UsersTable = $this->fetchTable('Users');
        foreach ($periods as $period) {
            $users = $UsersTable->getSubscribedUsersForPeriod($period);
            $this->io->out(__('{0} user has subscribed for the `{1}` period', '{2} users has subscribed for the `{3}` period', count($users), count($users), $period));
            foreach ($users as $user) {
                $this->io->out(__('Sending `{0}` report to `{1}`', $period, $user['email']));
                $emailTemplate = $UsersTable->generatePeriodicSummary($user['id'], $period, false);
                if ($emailTemplate === null) {
                    continue; // no new event for this user
                }
                $UsersTable->sendEmail($user, $emailTemplate, false, null);
            }
        }
        $this->io->out(__('All reports sent. Task took {0} seconds', time() -  $start_time));
    }

    private function __getPeriodsForToday(): array
    {
        $today = new Chronos();
        $periods = ['daily'];
        if ($today->format('j') == 1) {
            $periods[] = 'monthly';
        }
        if ($today->format('N') == 1) {
            $periods[] = 'weekly';
        }
        return $periods;
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
