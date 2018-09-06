<?php
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');
require_once 'AppShell.php';
class ServerShell extends AppShell
{
	public $uses = array('Server', 'Task', 'Job', 'User', 'Feed');

	public function pull() {
		if (empty($this->args[0]) || empty($this->args[1])) {
			die('Usage: ' . $this->Server->command_line_functions['pull'] . PHP_EOL);
		}
		$userId = $this->args[0];
		$user = $this->User->getAuthUser($userId);
		if (empty($this->args[1])) die();
		$serverId = $this->args[1];
		if (!empty($this->args[2])) {
			$technique = $this->args[2];
		} else {
			$technique = 'full';
		}
		if (!empty($this->args[3])) {
			$jobId = $this->args[3];
		} else {
			$this->Job->create();
			$data = array(
					'worker' => 'default',
					'job_type' => 'pull',
					'job_input' => 'Server: ' . $serverId,
					'status' => 0,
					'retries' => 0,
					'org' => $user['Organisation']['name'],
					'message' => 'Pulling.',
			);
			$this->Job->save($data);
			$jobId = $this->Job->id;
		}
		$this->Server->id = $serverId;
		$server = $this->Server->read(null, $serverId);
		$result = $this->Server->pull($user, $serverId, $technique, $server, $jobId);
		$this->Job->id = $jobId;
		$this->Job->save(array(
				'id' => $jobId,
				'message' => 'Job done.',
				'progress' => 100,
				'status' => 4
		));
		if (is_array($result)) {
			$message = sprintf(__('Pull completed. %s events pulled, %s events could not be pulled, %s proposals pulled.', count($result[0]), count($result[1]), count($result[2])));
		} else {
			$message = sprintf(__('ERROR: %s'), $result);
		}
		$this->Job->saveField('message', $message);
		echo $message . PHP_EOL;
	}

	public function push() {
		if (empty($this->args[0]) || empty($this->args[1])) {
			die('Usage: ' . $this->Server->command_line_functions['push'] . PHP_EOL);
		}
		$userId = $this->args[0];
		$user = $this->User->getAuthUser($userId);
		if (empty($user)) die('Invalid user.' . PHP_EOL);
		$serverId = $this->args[1];
		if (!empty($this->args[2])) {
			$jobId = $this->args[2];
		} else {
			$this->Job->create();
			$data = array(
					'worker' => 'default',
					'job_type' => 'push',
					'job_input' => 'Server: ' . $serverId,
					'status' => 0,
					'retries' => 0,
					'org' => $user['Organisation']['name'],
					'message' => 'Pushing.',
			);
			$this->Job->save($data);
			$jobId = $this->Job->id;
		}
		$this->Job->read(null, $jobId);
		$server = $this->Server->read(null, $serverId);
		App::uses('SyncTool', 'Tools');
		$syncTool = new SyncTool();
		$HttpSocket = $syncTool->setupHttpSocket($server);
		$result = $this->Server->push($serverId, 'full', $jobId, $HttpSocket, $user);
		$message = 'Job done.';
		if ($result !== true && !is_array($result)) $message = 'Job failed. Reason: ' . $result;
		$this->Job->save(array(
				'id' => $jobId,
				'message' => $message,
				'progress' => 100,
				'status' => 4
		));
		if (isset($this->args[4])) {
			$this->Task->id = $this->args[5];
			$message = 'Job(s) started at ' . date('d/m/Y - H:i:s') . '.';
			$this->Task->saveField('message', $message);
			echo $message . PHP_EOL;
		}
	}


	public function fetchFeed() {
		if (empty($this->args[0]) || empty($this->args[1])) {
			die('Usage: ' . $this->Server->command_line_functions['fetchFeed'] . PHP_EOL);
		}
		$userId = $this->args[0];
		$user = $this->User->getAuthUser($userId);
		if (empty($user)) {
			echo 'Invalid user.';
			die();
		}
		$feedId = $this->args[1];
		if (!empty($this->args[2])) {
			$jobId = $this->args[2];
		} else {
			$this->Job->create();
			$data = array(
					'worker' => 'default',
					'job_type' => 'fetch_feeds',
					'job_input' => 'Feed: ' . $feedId,
					'status' => 0,
					'retries' => 0,
					'org' => $user['Organisation']['name'],
					'message' => 'Starting fetch from Feed.',
			);
			$this->Job->save($data);
			$jobId = $this->Job->id;
		}
		$this->Job->read(null, $jobId);
		$result = $this->Feed->downloadFromFeedInitiator($feedId, $user, $jobId);
		$this->Job->id = $jobId;
		if (!$result) {
			$message = 'Job Failed.';
			$this->Job->save(array(
					'id' => $jobId,
					'message' => $message,
					'progress' => 0,
					'status' => 3
			));
		} else {
			$message = 'Job done.';
			$this->Job->save(array(
					'id' => $jobId,
					'message' => $message,
					'progress' => 100,
					'status' => 4
			));
		}
		echo $message . PHP_EOL;
	}

	public function cacheFeed() {
		if (empty($this->args[0]) || empty($this->args[1])) {
			die('Usage: ' . $this->Server->command_line_functions['cacheFeed'] . PHP_EOL);
		}
		$userId = $this->args[0];
		$user = $this->User->getAuthUser($userId);
		if (empty($user)) die('Invalid user.' . PHP_EOL);
		$scope = $this->args[1];
		if (!empty($this->args[2])) {
			$jobId = $this->args[2];
		} else {
			$this->Job->create();
			$data = array(
					'worker' => 'default',
					'job_type' => 'cache_feeds',
					'job_input' => 'Feed: ' . $scope,
					'status' => 0,
					'retries' => 0,
					'org' => $user['Organisation']['name'],
					'message' => 'Starting feed caching.',
			);
			$this->Job->save($data);
			$jobId = $this->Job->id;
		}
		$this->Job->read(null, $jobId);
		$result = $this->Feed->cacheFeedInitiator($user, $jobId, $scope);
		$this->Job->id = $jobId;
		if ($result !== true) {
			$message = 'Job Failed. Reason: ';
			$this->Job->save(array(
					'id' => $jobId,
					'message' => $message . $result,
					'progress' => 0,
					'status' => 3
			));
		} else {
			$message = 'Job done.';
			$this->Job->save(array(
					'id' => $jobId,
					'message' => $message,
					'progress' => 100,
					'status' => 4
			));
		}
		echo $message . PHP_EOL;
	}

	public function enqueuePull() {
		$timestamp = $this->args[0];
		$userId = $this->args[1];
		$taskId = $this->args[2];
		$task = $this->Task->read(null, $taskId);
		if ($timestamp != $task['Task']['next_execution_time']) {
			return;
		}
		if ($task['Task']['timer'] > 0)	$this->Task->reQueue($task, 'default', 'ServerShell', 'enqueuePull', $userId, $taskId);
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
			App::uses('SyncTool', 'Tools');
			$syncTool = new SyncTool();
			$result = $this->Server->pull($user, $server['Server']['id'], 'full', $server, $jobId);
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

	public function enqueueFeedFetch() {
		$timestamp = $this->args[0];
		$userId = $this->args[1];
		$taskId = $this->args[2];
		$task = $this->Task->read(null, $taskId);
		if ($timestamp != $task['Task']['next_execution_time']) {
			return;
		}
		if ($task['Task']['timer'] > 0)	$this->Task->reQueue($task, 'default', 'ServerShell', 'enqueueFeedFetch', $userId, $taskId);
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

	public function enqueueFeedCache() {
        $timestamp = $this->args[0];
        $userId = $this->args[1];
        $taskId = $this->args[2];
        $task = $this->Task->read(null, $taskId);
        if ($timestamp != $task['Task']['next_execution_time']) {
            return;
        }
        if ($task['Task']['timer'] > 0)	$this->Task->reQueue($task, 'default', 'ServerShell', 'enqueueFeedCache', $userId, $taskId);
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
        $result = $this->Feed->cacheFeedInitiator($user, $jobId, 'all');
        $this->Job->save(array(
            'message' => 'Job done.',
            'progress' => 100,
            'status' => 4
        ));
        $this->Task->id = $task['Task']['id'];
        $this->Task->saveField('message', 'Job completed at ' . date('d/m/Y - H:i:s'));
    }

	public function enqueuePush() {
		$timestamp = $this->args[0];
		$taskId = $this->args[1];
		$userId = $this->args[2];
		$this->Task->id = $taskId;
		$task = $this->Task->read(null, $taskId);
		if ($timestamp != $task['Task']['next_execution_time']) {
			return;
		}
		if ($task['Task']['timer'] > 0)	$this->Task->reQueue($task, 'default', 'ServerShell', 'enqueuePush', $userId, $taskId);

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
			$result = $this->Server->push($server['Server']['id'], 'full', $jobId, $HttpSocket, $user);
		}
		$this->Task->id = $task['Task']['id'];
		$this->Task->saveField('message', count($servers) . ' job(s) completed at ' . date('d/m/Y - H:i:s') . '.');
	}
}
