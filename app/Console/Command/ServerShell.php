<?php
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');
require_once 'AppShell.php';

/**
 * @property Job $Job
 * @property Server $Server
 * @property Feed $Feed
 * @property User $User
 */
class ServerShell extends AppShell
{
    public $uses = array('Server', 'Task', 'Job', 'User', 'Feed', 'TaxiiServer');

    public function getOptionParser()
    {
        $parser = parent::getOptionParser();
        $parser->addSubcommand('fetchIndex', [
            'help' => __('Fetch remote instance event index.'),
            'parser' => array(
                'arguments' => array(
                    'server_id' => ['help' => __('Remote server ID.'), 'required' => true],
                ),
            )
        ]);
        return $parser;
    }

    public function list()
    {
        $servers = $this->Server->find('all', [
            'fields' => ['Server.id', 'Server.name', 'Server.url'],
            'recursive' => 0
        ]);
        foreach ($servers as $server) {
            echo sprintf(
                '%sServer #%s :: %s :: %s',
                PHP_EOL,
                $server['Server']['id'],
                $server['Server']['name'],
                $server['Server']['url']
            );
        }
        echo PHP_EOL;
    }

    public function listServers()
    {
        $servers = $this->Server->find('all', [
            'fields' => ['Server.id', 'Server.name', 'Server.url'],
            'recursive' => 0
        ]);
        $res = ['servers' => array_column($servers, 'Server')];
        echo $this->json($res) . PHP_EOL;
    }

    public function test()
    {
        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['console_automation_tasks']['data']['Test'] . PHP_EOL);
        }

        $serverId = intval($this->args[0]);
        $server = $this->getServer($serverId);

        $res = $this->Server->runConnectionTest($server, false);
        echo $this->json($res) . PHP_EOL;
    }

    public function fetchIndex()
    {
        $serverId = intval($this->args[0]);
        $server = $this->getServer($serverId);
        $serverSync = new ServerSyncTool($server, $this->Server->setupSyncRequest($server));
        $index = $this->Server->getEventIndexFromServer($serverSync);
        echo $this->json($index) . PHP_EOL;
    }

    public function pullAll()
    {
        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['console_automation_tasks']['data']['PullAll'] . PHP_EOL);
        }

        $userId = $this->args[0];
        $user = $this->getUser($userId);
        Configure::write('CurrentUserId', $userId);

        if (!empty($this->args[1])) {
            $technique = $this->args[1];
        } else {
            $technique = 'full';
        }

        $servers = $this->Server->find('list', array(
            'conditions' => array('Server.pull' => 1),
            'recursive' => -1,
            'order' => 'Server.priority',
            'fields' => array('Server.id', 'Server.name'),
        ));

        foreach ($servers as $serverId => $serverName) {
            $jobId = $this->Job->createJob($user, Job::WORKER_DEFAULT, 'pull', "Server: $serverId", 'Pulling.');
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

            $this->out("Enqueued pulling from $serverName server as job $backgroundJobId");
        }
    }

    public function pull()
    {
        if (empty($this->args[0]) || empty($this->args[1])) {
            die('Usage: ' . $this->Server->command_line_functions['console_automation_tasks']['data']['Pull'] . PHP_EOL);
        }
        $userId = $this->args[0];
        $user = $this->getUser($userId);
        $serverId = $this->args[1];
        $server = $this->getServer($serverId);
        Configure::write('CurrentUserId', $userId);
        if (!empty($this->args[2])) {
            $technique = $this->args[2];
        } else {
            $technique = 'full';
        }
        if (!empty($this->args[3])) {
            $jobId = $this->args[3];
        } else {
            $jobId = $this->Job->createJob($user, Job::WORKER_DEFAULT, 'pull', 'Server: ' . $serverId, 'Pulling.');
        }
        $force = false;
        if (!empty($this->args[4]) && $this->args[4] === 'force') {
            $force = true;
        }

        // Try to enable garbage collector as pulling events can use a lot of memory
        gc_enable();

        try {
            $result = $this->Server->pull($user, $technique, $server, $jobId, $force);
            if (is_array($result)) {
                $message = __('Pull completed. %s events pulled, %s events could not be pulled, %s proposals pulled, %s sightings pulled, %s clusters pulled, %s analyst data pulled.', count($result[0]), count($result[1]), $result[2], $result[3], $result[4], $result[5]);
                $this->Job->saveStatus($jobId, true, $message);
            } else {
                $message = __('ERROR: %s', $result);
                $this->Job->saveStatus($jobId, false, $message);
            }
        } catch (Exception $e) {
            $this->Job->saveStatus($jobId, false, __('ERROR: %s', $e->getMessage()));
            throw $e;
        }
        echo $message . PHP_EOL;
    }

    public function push()
    {
        if (empty($this->args[0]) || empty($this->args[1])) {
            die('Usage: ' . $this->Server->command_line_functions['console_automation_tasks']['data']['Push'] . PHP_EOL);
        }
        
        $userId = $this->args[0];
        $user = $this->getUser($userId);
        $serverId = $this->args[1];
        $server = $this->getServer($serverId);
        Configure::write('CurrentUserId', $userId);
        $technique = empty($this->args[2]) ? 'full' : $this->args[2];
        if (!empty($this->args[3])) {
            $jobId = $this->args[3];
        } else {
            $jobId = $this->Job->createJob($user, Job::WORKER_DEFAULT, 'push', 'Server: ' . $serverId, 'Pushing.');
        }
        $this->Job->read(null, $jobId);

        App::uses('SyncTool', 'Tools');
        $syncTool = new SyncTool();
        $HttpSocket = $syncTool->setupHttpSocket($server);
        $result = $this->Server->push($serverId, $technique, $jobId, $HttpSocket, $user);

        if ($result !== true && !is_array($result)) {
            $message = 'Job failed. Reason: ' . $result;
            $this->Job->saveStatus($jobId, false, $message);
        } else {
            $message = 'Job done.';
            $this->Job->saveStatus($jobId, true, $message);
        }

        if (isset($this->args[4])) {
            $this->Task->id = $this->args[5];
            $message = 'Job(s) started at ' . date('d/m/Y - H:i:s') . '.';
            $this->Task->saveField('message', $message);
            echo $message . PHP_EOL;
        }
    }

    public function pushAll()
    {
        $userId = $this->args[0];
        $user = $this->getUser($userId);

        Configure::write('CurrentUserId', $userId);
        $technique = isset($this->args[1]) ? $this->args[1] : 'full';

        $servers = $this->Server->find('list', array(
            'conditions' => array('Server.push' => 1),
            'recursive' => -1,
            'order' => 'Server.priority',
            'fields' => array('Server.id', 'Server.name'),
        ));

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

            $this->out("Enqueued pushing from $serverName server as job $jobId");
        }
    }

    public function listFeeds()
    {
        $fields = [
            'id' => 3,
            'source_format' => 10,
            'provider' => 15,
            'url' => 50,
            'enabled' => 8,
            'caching_enabled' => 7
        ];
        $feeds = $this->Feed->find('all', [
            'recursive' => -1,
            'fields' => array_keys($fields)
        ]);
        $outputStyle = (empty($this->args[0]) || $this->args[0] === 'json') ? 'json' : 'table';
        if ($outputStyle === 'table') {
            $this->out(str_repeat('=', 114));
            $this->out(sprintf(
                '| %s | %s | %s | %s | %s | %s |',
                str_pad('ID', $fields['id'], ' ', STR_PAD_RIGHT),
                str_pad('Format', $fields['source_format'], ' ', STR_PAD_RIGHT),
                str_pad('Provider', $fields['provider'], ' ', STR_PAD_RIGHT),
                str_pad('Url', $fields['url'], ' ', STR_PAD_RIGHT),
                str_pad('Fetching', $fields['enabled'], ' ', STR_PAD_RIGHT),
                str_pad('Caching', $fields['caching_enabled'], ' ', STR_PAD_RIGHT)
            ), 1, Shell::NORMAL);
            $this->out(str_repeat('=', 114));
            foreach ($feeds as $feed) {
                $this->out(sprintf(
                    '| %s | %s | %s | %s | %s | %s |',
                    str_pad($feed['Feed']['id'], $fields['id'], ' ', STR_PAD_RIGHT),
                    str_pad($feed['Feed']['source_format'], $fields['source_format'], ' ', STR_PAD_RIGHT),
                    str_pad(mb_substr($feed['Feed']['provider'], 0, 13), $fields['provider'], ' ', STR_PAD_RIGHT),
                    str_pad(
                        mb_substr($feed['Feed']['url'], 0, 48),
                        $fields['url'],
                        ' ',
                        STR_PAD_RIGHT
                    ),
                    $feed['Feed']['enabled'] ?
                        '<info>' . str_pad(__('Yes'), $fields['enabled'], ' ', STR_PAD_RIGHT) . '</info>':
                        str_pad(__('No'), $fields['enabled'], ' ', STR_PAD_RIGHT),
                    $feed['Feed']['caching_enabled'] ?
                        '<info>' . str_pad(__('Yes'), $fields['caching_enabled'], ' ', STR_PAD_RIGHT) . '</info>':
                        str_pad(__('No'), $fields['caching_enabled'], ' ', STR_PAD_RIGHT)
                ), 1, Shell::NORMAL);
            }
            $this->out(str_repeat('=', 114));
        } else {
            $this->out(json_encode($feeds, JSON_PRETTY_PRINT));
        }
    }

    public function viewFeed()
    {
        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['console_automation_tasks']['data']['View Feed'] . PHP_EOL);
        }
        $feed = $this->Feed->find('first', [
            'conditions' => [
                'id' => $this->args[0]
            ],
            'recursive' => -1
        ]);
        if (empty($feed)) {
            throw new NotFoundException(__('Invalid feed.'));
        }
        $outputStyle = (empty($this->args[1]) || $this->args[1] === 'json') ? 'json' : 'table';
        if ($outputStyle === 'table') {
            $this->out(str_repeat('=', 114));
            foreach ($feed['Feed'] as $field => $value) {
                $this->out(sprintf(
                    '| %s | %s |',
                    str_pad($field, 20, ' ', STR_PAD_RIGHT),
                    str_pad($value, 87)
                ), 1, Shell::NORMAL);
            }
            $this->out(str_repeat('=', 114));
        } else {
            $this->out(json_encode($feed));
        }
    }

    public function toggleFeed()
    {
        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['console_automation_tasks']['data']['Toggle feed fetching'] . PHP_EOL);
        }
        $feed = $this->Feed->find('first', [
            'conditions' => [
                'id' => $this->args[0]
            ],
            'recursive' => -1
        ]);
        if (empty($feed)) {
            throw new NotFoundException(__('Invalid feed.'));
        }
        $feed['Feed']['enabled'] = ($feed['Feed']['enabled']) ? 0 : 1;
        if ($this->Feed->save($feed)) {
            $this->out(__('Feed fetching %s for feed %s', ($feed['Feed']['enabled'] ? __('enabled') : __('disabled')), $feed['Feed']['id']));
        } else {
            $this->out(__('Could not toggle fetching for feed %s', $feed['Feed']['id']));
        }
    }

    public function toggleFeedCaching()
    {
        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['console_automation_tasks']['data']['Toggle feed caching'] . PHP_EOL);
        }
        $feed = $this->Feed->find('first', [
            'conditions' => [
                'id' => $this->args[0]
            ],
            'recursive' => -1
        ]);
        if (empty($feed)) {
            throw new NotFoundException(__('Invalid feed.'));
        }
        $feed['Feed']['caching_enabled'] = ($feed['Feed']['caching_enabled']) ? 0 : 1;
        if ($this->Feed->save($feed)) {
            $this->out(__('Feed caching %s for feed %s', ($feed['Feed']['enabled'] ? __('enabled') : __('disabled')), $feed['Feed']['id']));
        } else {
            $this->out(__('Could not toggle caching for feed %s', $feed['Feed']['id']));
        }
    }

    public function loadDefaultFeeds()
    {
        $this->Feed->load_default_feeds();
        $this->out(__('Default feed metadata loaded.'));
    }

    public function fetchFeed()
    {
        if (empty($this->args[0]) || empty($this->args[1])) {
            die('Usage: ' . $this->Server->command_line_functions['console_automation_tasks']['data']['Fetch feeds as local data'] . PHP_EOL);
        }
        
        $userId = $this->args[0];
        $user = $this->getUser($userId);
        $feedId = $this->args[1];
        Configure::write('CurrentUserId', $userId);
        if (!empty($this->args[2])) {
            $jobId = $this->args[2];
        } else {
            $jobId = $this->Job->createJob($user, Job::WORKER_DEFAULT, 'fetch_feeds', 'Feed: ' . $feedId, 'Starting fetch from Feed.');
        }
        if ($feedId === 'all') {
            $feedIds = $this->Feed->find('column', array(
                'fields' => array('Feed.id'),
                'conditions' => array('Feed.enabled' => 1)
            ));
            $successes = 0;
            $fails = 0;
            foreach ($feedIds as $k => $feedId) {
                $this->Job->saveProgress($jobId, 'Fetching feed: ' . $feedId, 100 * $k / count($feedIds));
                $result = $this->Feed->downloadFromFeedInitiator($feedId, $user);
                if ($result) {
                    $successes++;
                } else {
                    $fails++;
                }
            }
            $message = 'Job done. ' . $successes . ' feeds pulled successfully, ' . $fails . ' feeds could not be pulled.';
            $this->Job->saveStatus($jobId, true, $message);
            echo $message . PHP_EOL;
        } else {
            $feedEnabled = $this->Feed->hasAny([
                'Feed.enabled' => 1,
                'Feed.id' => $feedId,
            ]);
            if ($feedEnabled) {
                $result = $this->Feed->downloadFromFeedInitiator($feedId, $user, $jobId);
                if (!$result) {
                    $this->Job->saveStatus($jobId, false, 'Job failed. See error log for more details.');
                    echo 'Job failed.' . PHP_EOL;
                } else {
                    $this->Job->saveStatus($jobId, true);
                    echo 'Job done.' . PHP_EOL;
                }
            } else {
                $message = "Feed with ID $feedId not found or not enabled.";
                $this->Job->saveStatus($jobId, false, $message);
                echo $message . PHP_EOL;
            }
        }
    }

    public function cacheServer()
    {
        if (empty($this->args[0]) || empty($this->args[1])) {
            die('Usage: ' . $this->Server->command_line_functions['console_automation_tasks']['data']['Cache server'] . PHP_EOL);
        }
        
        $userId = $this->args[0];
        $user = $this->getUser($userId);
        $scope = $this->args[1];
        if (!empty($this->args[2])) {
            $jobId = $this->args[2];
        } else {
            $this->Job->create();
            $data = array(
                    'worker' => 'default',
                    'job_type' => 'cache_servers',
                    'job_input' => 'Server: ' . $scope,
                    'status' => 0,
                    'retries' => 0,
                    'org' => $user['Organisation']['name'],
                    'message' => 'Starting server caching.',
            );
            $this->Job->save($data);
            $jobId = $this->Job->id;
        }
        $result = $this->Server->cacheServerInitiator($user, $scope, $jobId);
        if ($result !== true) {
            $message = 'Job Failed. Reason: ' . $result;
            $this->Job->saveStatus($jobId, false, $message);
        } else {
            $message = 'Job done.';
            $this->Job->saveStatus($jobId, true, $message);
        }
        echo $message . PHP_EOL;
    }

    public function cacheServerAll()
    {
        $userId = $this->args[0];
        $user = $this->getUser($userId);

        $servers = $this->Server->find('list', array(
            'conditions' => array('Server.pull' => 1),
            'recursive' => -1,
            'order' => 'Server.priority',
            'fields' => array('Server.id', 'Server.name'),
        ));

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

            $this->out("Enqueued cacheServer from $serverName server as job $jobId");
        }
    }

    public function cacheFeed()
    {
        if (empty($this->args[0]) || empty($this->args[1])) {
            die('Usage: ' . $this->Server->command_line_functions['console_automation_tasks']['data']['Cache feeds for quick lookups'] . PHP_EOL);
        }
        
        $userId = $this->args[0];
        $user = $this->getUser($userId);
        $scope = $this->args[1];
        if (!empty($this->args[2])) {
            $jobId = $this->args[2];
        } else {
            $jobId = $this->Job->createJob($user, Job::WORKER_DEFAULT, 'cache_feeds', 'Feed: ' . $scope, 'Starting feed caching.');
        }
        try {
            $result = $this->Feed->cacheFeedInitiator($user, $jobId, $scope);
        } catch (Exception $e) {
            CakeLog::error($e->getMessage());
            $result = false;
        }

        if ($result === false) {
            $message = __('Job failed. See error logs for more details.');
            $this->Job->saveStatus($jobId, false, $message);

        } else {
            $total = $result['successes'] + $result['fails'];
            $message = __n(
                '%s feed from %s cached. Failed: %s',
                '%s feeds from %s cached. Failed: %s',
                $result['successes'], $result['successes'], $total, $result['fails']
            );
            if ($result['fails'] > 0) {
                $message .= ' ' . __('See error logs for more details.');
            }
            $this->Job->saveStatus($jobId, true, $message);
        }
        echo $message . PHP_EOL;
    }

    public function enqueuePull()
    {
        if (empty($this->args[0]) || empty($this->args[1]) || empty($this->args[2])) {
            die('Usage: ' . $this->Server->command_line_functions['console_automation_tasks']['data']['Enqueue pull'] . PHP_EOL);
        }

        $timestamp = $this->args[0];
        $userId = $this->args[1];
        $taskId = $this->args[2];
        $task = $this->Task->read(null, $taskId);
        if ($timestamp != $task['Task']['next_execution_time']) {
            return;
        }
        if ($task['Task']['timer'] > 0)    $this->Task->reQueue($task, 'default', 'ServerShell', 'enqueuePull', $userId, $taskId);
        $user = $this->User->getAuthUser($userId);
        $servers = $this->Server->find('all', array('recursive' => -1, 'conditions' => array('pull' => 1)));
        $count = count($servers);
        $failCount = 0;
        foreach ($servers as $k => $server) {
            $this->Job->create();
            $data = array(
                    'worker' => 'default',
                    'job_type' => 'pull',
                    'job_input' => 'Server: ' . $server['Server']['id'],
                    'retries' => 0,
                    'org' => $user['Organisation']['name'],
                    'org_id' => $user['org_id'],
                    'process_id' => 'Part of scheduled pull',
                    'message' => 'Pulling.',
            );
            $this->Job->save($data);
            $jobId = $this->Job->id;
            $result = $this->Server->pull($user, 'full', $server, $jobId);
            $this->Job->save(array(
                    'id' => $jobId,
                    'message' => 'Job done.',
                    'progress' => 100,
                    'status' => 4
            ));
            if (is_numeric($result[0])) {
                switch ($result[0]) {
                    case '1' :
                        $this->Job->saveField('message', 'Not authorised. This is either due to an invalid auth key, or due to the sync user not having authentication permissions enabled on the remote server.');
                        break;
                    case '2' :
                        $this->Job->saveField('message', $result[1]);
                        break;
                    case '3' :
                        $this->Job->saveField('message', 'Sorry, incremental pushes are not yet implemented.');
                        break;
                    case '4' :
                        $this->Job->saveField('message', 'Invalid technique chosen.');
                        break;

                }
                $failCount++;
            }
        }
        $this->Task->id = $task['Task']['id'];
        $this->Task->saveField('message', count($servers) . ' job(s) completed at ' . date('d/m/Y - H:i:s') . '. Failed jobs: ' . $failCount . '/' . $count);
    }

    public function enqueueFeedFetch()
    {
        if (empty($this->args[0]) || empty($this->args[1]) || empty($this->args[2])) {
            die('Usage: ' . $this->Server->command_line_functions['console_automation_tasks']['data']['Enqueue feed fetch'] . PHP_EOL);
        }

        $timestamp = $this->args[0];
        $userId = $this->args[1];
        $taskId = $this->args[2];
        $task = $this->Task->read(null, $taskId);
        if ($timestamp != $task['Task']['next_execution_time']) {
            return;
        }
        if ($task['Task']['timer'] > 0)    $this->Task->reQueue($task, 'default', 'ServerShell', 'enqueueFeedFetch', $userId, $taskId);
        $user = $this->User->getAuthUser($userId);
        $failCount = 0;
        $feeds = $this->Feed->find('all', array(
            'recursive' => -1,
            'conditions' => array('enabled' => true)
        ));
        foreach ($feeds as $k => $feed) {
            $this->Job->create();
            $data = array(
                    'worker' => 'default',
                    'job_type' => 'feed_fetch',
                    'job_input' => 'Feed: ' . $feed['Feed']['id'],
                    'retries' => 0,
                    'org' => $user['Organisation']['name'],
                    'org_id' => $user['org_id'],
                    'process_id' => 'Part of scheduled feed fetch',
                    'message' => 'Pulling.',
            );
            $this->Job->save($data);
            $jobId = $this->Job->id;
            $result = $this->Feed->downloadFromFeedInitiator($feed['Feed']['id'], $user, $jobId);
            $this->Job->save(array(
                    'message' => 'Job done.',
                    'progress' => 100,
                    'status' => 4
            ));
            if ($result !== true) {
                $this->Job->saveField('message', 'Could not fetch feed.');
                $failCount++;
            }
        }
        $this->Task->id = $task['Task']['id'];
        $this->Task->saveField('message', count($feeds) . ' job(s) completed at ' . date('d/m/Y - H:i:s') . '. Failed jobs: ' . $failCount . '/' . count($feeds));
    }

    public function enqueueFeedCache()
    {
        if (empty($this->args[0]) || empty($this->args[1]) || empty($this->args[2])) {
            die('Usage: ' . $this->Server->command_line_functions['console_automation_tasks']['data']['Enqueue feed cache'] . PHP_EOL);
        }

        $timestamp = $this->args[0];
        $userId = $this->args[1];
        $taskId = $this->args[2];
        $task = $this->Task->read(null, $taskId);
        if ($timestamp != $task['Task']['next_execution_time']) {
            return;
        }
        if ($task['Task']['timer'] > 0)    $this->Task->reQueue($task, 'default', 'ServerShell', 'enqueueFeedCache', $userId, $taskId);
        $user = $this->User->getAuthUser($userId);
        $this->Job->create();
        $data = array(
            'worker' => 'default',
            'job_type' => 'feed_cache',
            'job_input' => '',
            'retries' => 0,
            'org' => $user['Organisation']['name'],
            'org_id' => $user['org_id'],
            'process_id' => 'Part of scheduled feed caching',
            'message' => 'Caching.',
        );
        $this->Job->save($data);
        $jobId = $this->Job->id;
        try {
            $result = $this->Feed->cacheFeedInitiator($user, $jobId, 'all');
        } catch (Exception $e) {
            CakeLog::error($e->getMessage());
            $result = false;
        }

        if ($result === false) {
            $message = __('Job failed. See error logs for more details.');
            $this->Job->saveStatus($jobId, false, $message);

        } else {
            $total = $result['successes'] + $result['fails'];
            $message = __n(
                '%s feed from %s cached. Failed: %s',
                '%s feeds from %s cached. Failed: %s',
                $result['successes'], $total, $result['fails']
            );
            if ($result['fails'] > 0) {
                $message .= ' ' . __('See error logs for more details.');
            }
            $this->Job->saveStatus($jobId, true, $message);
        }

        $this->Task->id = $task['Task']['id'];
        $this->Task->saveField('message', 'Job completed at ' . date('d/m/Y - H:i:s'));
    }

    public function enqueuePush()
    {
        if (empty($this->args[0]) || empty($this->args[1]) || empty($this->args[2])) {
            die('Usage: ' . $this->Server->command_line_functions['console_automation_tasks']['data']['Enqueue push'] . PHP_EOL);
        }

        $timestamp = $this->args[0];
        $taskId = $this->args[1];
        $userId = $this->args[2];
        $this->Task->id = $taskId;
        $task = $this->Task->read(null, $taskId);
        if ($timestamp != $task['Task']['next_execution_time']) {
            return;
        }
        if ($task['Task']['timer'] > 0)    $this->Task->reQueue($task, 'default', 'ServerShell', 'enqueuePush', $userId, $taskId);

        $this->User->recursive = -1;
        $user = $this->User->getAuthUser($userId);
        $servers = $this->Server->find('all', array('recursive' => -1, 'conditions' => array('push' => 1)));
        foreach ($servers as $k => $server) {
            $this->Job->create();
            $data = array(
                    'worker' => 'default',
                    'job_type' => 'push',
                    'job_input' => 'Server: ' . $server['Server']['id'],
                    'retries' => 0,
                    'org' => $user['Organisation']['name'],
                    'org_id' => $user['org_id'],
                    'process_id' => 'Part of scheduled push',
                    'message' => 'Pushing.',
            );
            $this->Job->save($data);
            $jobId = $this->Job->id;
            App::uses('SyncTool', 'Tools');
            $syncTool = new SyncTool();
            $HttpSocket = $syncTool->setupHttpSocket($server);
            $this->Server->push($server['Server']['id'], 'full', $jobId, $HttpSocket, $user);
        }
        $this->Task->id = $task['Task']['id'];
        $this->Task->saveField('message', count($servers) . ' job(s) completed at ' . date('d/m/Y - H:i:s') . '.');
    }

    public function sendPeriodicSummaryToUsers()
    {
        
        $periods = $this->__getPeriodsForToday();
        $start_time = time();
        echo __n('Started periodic summary generation for the %s period', 'Started periodic summary generation for periods: %s', count($periods), implode(', ', $periods)) . PHP_EOL;
        foreach ($periods as $period) {
            $users = $this->User->getSubscribedUsersForPeriod($period);
            echo __n('%s user has subscribed for the `%s` period', '%s users has subscribed for the `%s` period', count($users), count($users), $period) . PHP_EOL;
            foreach ($users as $user) {
                echo __('Sending `%s` report to `%s`', $period, $user['User']['email']) . PHP_EOL;
                $emailTemplate = $this->User->generatePeriodicSummary($user['User']['id'], $period, false);
                if ($emailTemplate === null) {
                    continue; // no new event for this user
                }
                $this->User->sendEmail($user, $emailTemplate, false, null);
            }
        }
        echo __('All reports sent. Task took %s seconds', time() -  $start_time) . PHP_EOL;
    }

    private function __getPeriodsForToday(): array
    {
        $today = new DateTime();
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
    private function getUser($userId)
    {
        $user = $this->User->getAuthUser($userId);
        if (empty($user)) {
            $this->error('User ID do not match an existing user.');
        }
        return $user;
    }

    /**
     * @param int $serverId
     * @return array
     */
    private function getServer($serverId)
    {
        $server = $this->Server->find('first', [
            'conditions' => ['Server.id' => $serverId],
            'recursive' => -1,
        ]);
        if (!$server) {
            $this->error("Server with ID $serverId doesn't exists.");
        }
        return $server;
    }

    public function push_taxii()
    {
        if (empty($this->args[0]) || empty($this->args[1])) {
            die('Usage: ' . $this->Server->command_line_functions['console_automation_tasks']['data']['Push Taxii'] . PHP_EOL);
        }
        
        $userId = $this->args[0];
        $user = $this->getUser($userId);
        $serverId = $this->args[1];
        if (!empty($this->args[2])) {
            $jobId = $this->args[2];
        } else {
            $jobId = $this->Job->createJob($user, Job::WORKER_DEFAULT, 'push_taxii', 'Server: ' . $serverId, 'Pushing.');
        }
        $this->Job->read(null, $jobId);

        $result = $this->TaxiiServer->push($serverId, $user, $jobId);
        if ($result !== true && !is_array($result)) {
            $message = 'Job failed. Reason: ' . $result;
            $this->Job->saveStatus($jobId, false, $message);
        } else {
            $message = 'Job done.';
            $this->Job->saveStatus($jobId, true, $message);
        }
    }
}
