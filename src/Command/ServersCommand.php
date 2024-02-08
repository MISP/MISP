<?php

namespace App\Command;

use App\Lib\Tools\BackgroundJobsTool;
use App\Lib\Tools\HttpTool;
use App\Lib\Tools\LogExtendedTrait;
use App\Lib\Tools\ServerSyncTool;
use App\Model\Entity\Job;
use Cake\Chronos\Chronos;
use Cake\Console\ConsoleIo;
use Cake\Core\Configure;
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

    public function listFeeds($outputStyle = 'json')
    {
        $fields = [
            'id' => 3,
            'source_format' => 10,
            'provider' => 15,
            'url' => 50,
            'enabled' => 8,
            'caching_enabled' => 7
        ];

        $FeedsTable = $this->fetchTable('Feeds');

        $feeds = $FeedsTable->find(
            'all',
            [
                'recursive' => -1,
                'fields' => array_keys($fields)
            ]
        );
        if ($outputStyle === 'table') {
            $this->io->out(str_repeat('=', 114));
            $this->io->out(
                sprintf(
                    '| %s | %s | %s | %s | %s | %s |',
                    str_pad('ID', $fields['id'], ' ', STR_PAD_RIGHT),
                    str_pad('Format', $fields['source_format'], ' ', STR_PAD_RIGHT),
                    str_pad('Provider', $fields['provider'], ' ', STR_PAD_RIGHT),
                    str_pad('Url', $fields['url'], ' ', STR_PAD_RIGHT),
                    str_pad('Fetching', $fields['enabled'], ' ', STR_PAD_RIGHT),
                    str_pad('Caching', $fields['caching_enabled'], ' ', STR_PAD_RIGHT)
                ),
                1,
                ConsoleIo::NORMAL
            );
            $this->io->out(str_repeat('=', 114));
            foreach ($feeds as $feed) {
                $this->io->out(
                    sprintf(
                        '| %s | %s | %s | %s | %s | %s |',
                        str_pad($feed['id'], $fields['id'], ' ', STR_PAD_RIGHT),
                        str_pad($feed['source_format'], $fields['source_format'], ' ', STR_PAD_RIGHT),
                        str_pad(mb_substr($feed['provider'], 0, 13), $fields['provider'], ' ', STR_PAD_RIGHT),
                        str_pad(
                            mb_substr($feed['url'], 0, 48),
                            $fields['url'],
                            ' ',
                            STR_PAD_RIGHT
                        ),
                        $feed['enabled'] ?
                            '<info>' . str_pad(__('Yes'), $fields['enabled'], ' ', STR_PAD_RIGHT) . '</info>' :
                            str_pad(__('No'), $fields['enabled'], ' ', STR_PAD_RIGHT),
                        $feed['caching_enabled'] ?
                            '<info>' . str_pad(__('Yes'), $fields['caching_enabled'], ' ', STR_PAD_RIGHT) . '</info>' :
                            str_pad(__('No'), $fields['caching_enabled'], ' ', STR_PAD_RIGHT)
                    ),
                    1,
                    ConsoleIo::NORMAL
                );
            }
            $this->io->out(str_repeat('=', 114));
        } else {
            $this->outputJson($feeds);
        }
    }

    public function viewFeed($feedId = null, $outputStyle = 'json')
    {
        if (empty($feedId)) {
            $this->showActionUsageAndExit();
        }

        $FeedsTable = $this->fetchTable('Feeds');

        $feed = $FeedsTable->get($feedId)->toArray();

        if (empty($feed)) {
            throw new Exception(__('Invalid feed.'));
        }
        if ($outputStyle === 'table') {
            $this->io->out(str_repeat('=', 114));
            foreach ($feed as $field => $value) {
                if (is_array($value)) {
                    $value = json_encode($value, JSON_PRETTY_PRINT);
                }
                $this->io->out(
                    sprintf(
                        '| %s | %s |',
                        str_pad($field, 20, ' ', STR_PAD_RIGHT),
                        str_pad($value ?? '', 87)
                    ),
                    1,
                    ConsoleIo::NORMAL
                );
            }
            $this->io->out(str_repeat('=', 114));
        } else {
            $this->outputJson($feed);
        }
    }

    public function toggleFeed($feedId = null)
    {
        if (empty($feedId)) {
            $this->showActionUsageAndExit();
        }

        $FeedsTable = $this->fetchTable('Feeds');
        $feed = $FeedsTable->get($feedId);

        $feed['enabled'] = ($feed['enabled']) ? 0 : 1;
        if ($FeedsTable->save($feed)) {
            $this->io->out(__('Feed fetching {0} for feed {1}', ($feed['enabled'] ? __('enabled') : __('disabled')), $feed['id']));
        } else {
            $this->io->out(__('Could not toggle fetching for feed {0}', $feed['id']));
        }
    }


    public function toggleFeedCaching($feedId = null)
    {
        if (empty($feedId)) {
            $this->showActionUsageAndExit();
        }

        $FeedsTable = $this->fetchTable('Feeds');
        $feed = $FeedsTable->get($feedId);

        $feed['caching_enabled'] = ($feed['caching_enabled']) ? 0 : 1;
        if ($FeedsTable->save($feed)) {
            $this->io->out(__('Feed caching {0} for feed {1}', ($feed['caching_enabled'] ? __('enabled') : __('disabled')), $feed['id']));
        } else {
            $this->io->out(__('Could not toggle caching for feed {0}', $feed['id']));
        }
    }

    public function loadDefaultFeeds()
    {
        $FeedsTable = $this->fetchTable('Feeds');
        $FeedsTable->load_default_feeds();
        $this->io->out(__('Default feed metadata loaded.'));
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

        if (empty($jobId)) {
            $jobId = $JobsTable->createJob($user->toArray(), Job::WORKER_DEFAULT, 'fetch_feeds', 'Feed: ' . $feedId, 'Starting fetch from Feed.');
        }
        if ($feedId === 'all') {
            $feedIds = $FeedsTable->find(
                'column',
                [
                    'fields' => ['id'],
                    'conditions' => ['enabled' => 1]
                ]
            )->toArray();
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
            $feedEnabled = $FeedsTable->exists(
                [
                    'enabled' => 1,
                    'id' => $feedId,
                ]
            );
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

    public function cacheFeed($userId = null, $scope = null, $jobId = null)
    {
        if (empty($userId) || empty($scope)) {
            $this->showActionUsageAndExit();
        }

        $user = $this->getUser($userId);

        $FeedsTable = $this->fetchTable('Feeds');
        $JobsTable = $this->fetchTable('Jobs');

        if (!empty($jobId)) {
            $jobId = $JobsTable->createJob($user, Job::WORKER_DEFAULT, 'cache_feeds', 'Feed: ' . $scope, 'Starting feed caching.');
        }
        try {
            $result = $FeedsTable->cacheFeedInitiator($user, $jobId, $scope);
        } catch (Exception $e) {
            $this->logException("Failed caching Feed: $scope", $e);
            $result = false;
        }

        if ($result === false) {
            $message = __('Job failed. See error logs for more details.');
            $JobsTable->saveStatus($jobId, false, $message);
        } else {
            $total = $result['successes'] + $result['fails'];
            $message = __(
                '{0} feed from {1} cached. Failed: {2}',
                $result['successes'],
                $total,
                $result['fails']
            );
            if ($result['fails'] > 0) {
                $message .= ' ' . __('See error logs for more details.');
            }
            $JobsTable->saveStatus($jobId, true, $message);
        }
        $this->io->out($message);
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
