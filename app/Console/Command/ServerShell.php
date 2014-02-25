<?php 
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');
//App::uses('AppShell', 'Console/Command');
require_once 'AppShell.php';
class ServerShell extends AppShell
{
	public $uses = array('Server', 'Task', 'Job', 'User');
	
	public function pull() {
		//$user, $id = null, $technique=false, $server
		$userId = $this->args[0];
		$serverId = $this->args[1];
		$technique = $this->args[2];
		$jobId = $this->args[3];
		$this->Job->read(null, $jobId);
		$this->Server->id = $serverId;
		$this->User->recursive = -1;
		$user = $this->User->read(null, $userId);
		$server = $this->Server->read(null, $serverId);
		$result = $this->Server->pull($user['User'], null, $technique, $server, $jobId);
		$this->Job->id = $jobId;
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
					return;
					break;
				case '2' :
					$this->Job->saveField('message', $result[1]);
					return;
					break;
				case '3' :
					$this->Job->saveField('message', 'Sorry, incremental pushes are not yet implemented.');
					return;
					break;
				case '4' :
					$this->Job->saveField('message', 'Invalid technique chosen.');
					return;
					break;
						
			}
		}
	}
	
	public function push() {
		$serverId = $this->args[0];
		$technique = $this->args[1];
		$jobId = $this->args[2];
		$this->Job->read(null, $jobId);
		$server = $this->Server->read(null, $serverId);
		App::uses('SyncTool', 'Tools');
		$syncTool = new SyncTool();
		$HttpSocket = $syncTool->setupHttpSocket($server);
		$result = $this->Server->push($serverId, 'full', $jobId, $HttpSocket);
		$this->Job->save(array(
				'id' => $jobId,
				'message' => 'Job done.',
				'progress' => 100,
				'status' => 4
		));
		if (isset($this->args[3])) {
			$this->Task->id = $this->args[4];
			$this->Task->saveField('message', 'Job(s) started at ' . date('d/m/Y - H:i:s') . '.');
		}
	}
	
	public function enqueuePull() {
		$timestamp = $this->args[0];
		$userId = $this->args[1];
		$taskId = $this->args[2];
		$task = $this->Task->read(null, $taskId);
		if ($timestamp != $task['Task']['next_execution_time']) {
			return;
		}
		$this->User->recursive = -1;
		$user = $this->User->read(array('id', 'org', 'email'), $userId);
		$servers = $this->Server->find('all', array('recursive' => -1, 'conditions' => array('push' => 1)));
		$count = count($servers);
		foreach ($servers as $k => $server) {
			$this->Job->create();
			$data = array(
					'worker' => 'default',
					'job_type' => 'push',
					'job_input' => 'Server: ' . $server['Server']['id'],
					'retries' => 0,
					'org' => $user['User']['org'],
					'process_id' => $this->Task->data['Task']['job_id'],
					'message' => 'Pushing.',
			);
			$this->Job->save($data);
			$jobId = $this->Job->id;
			App::uses('SyncTool', 'Tools');
			$syncTool = new SyncTool();
			$result = $this->Server->pull($user['User'], null, 'full', $server, $jobId);
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
			}
		}
		$task['Task']['message'] = count($servers) . ' job(s) completed at ' . date('d/m/Y - H:i:s') . '.';
		if ($task['Task']['timer'] > 0) {
			$time = time();
			// Keep adding the timer's time interval until we get a date that is in the future! We don't want to keep queuing tasks in the past since they will execute until it catches up.
			while ($task['Task']['next_execution_time'] < $time) {
				$task['Task']['next_execution_time'] = strtotime('+' . $task['Task']['timer'] . ' hours', $task['Task']['next_execution_time']);
			}
			$task['Task']['scheduled_time'] = $this->Task->breakTime($task['Task']['scheduled_time'], $task['Task']['timer']);
			$task['Task']['scheduled_time'] = date('H:i', $task['Task']['next_execution_time']);
		
			// Now that we have figured out when the next execution should happen, it's time to enqueue it.
			$process_id = CakeResque::enqueueAt(
					$task['Task']['next_execution_time'],
					'default',
					'ServerShell',
					array('enqueuePull', $task['Task']['next_execution_time'],$userId, $taskId),
					true
			);
			$task['Task']['job_id'] = $process_id;
			$this->Task->save($task);
		}
	}
	
	public function enqueuePush() {
		$timestamp = $this->args[0];
		$taskId = $this->args[1];
		$org = $this->args[2];
		$this->Task->id = $taskId;
		$task = $this->Task->read(null, $taskId);
		if ($timestamp != $task['Task']['next_execution_time']) {
			return;
		}
		
		$servers = $this->Server->find('all', array('recursive' => -1, 'conditions' => array('push' => 1)));
		$count = count($servers);
		foreach ($servers as $k => $server) {
			$this->Job->create();
			$data = array(
					'worker' => 'default',
					'job_type' => 'push',
					'job_input' => 'Server: ' . $server['Server']['id'],
					'retries' => 0,
					'org' => $org,
					'process_id' => $this->Task->data['Task']['job_id'],
					'message' => 'Pushing.',
			);
			$this->Job->save($data);
			$jobId = $this->Job->id;
			App::uses('SyncTool', 'Tools');
			$syncTool = new SyncTool();
			$HttpSocket = $syncTool->setupHttpSocket($server);
			$result = $this->Server->push($server['Server']['id'], 'full', $jobId, $HttpSocket);
		}
		$task['Task']['message'] = count($servers) . ' job(s) completed at ' . date('d/m/Y - H:i:s') . '.';
		if ($task['Task']['timer'] > 0) {
			$time = time();
			// Keep adding the timer's time interval until we get a date that is in the future! We don't want to keep queuing tasks in the past since they will execute until it catches up.
			while ($task['Task']['next_execution_time'] < $time) {
				$task['Task']['next_execution_time'] = strtotime('+' . $task['Task']['timer'] . ' hours', $task['Task']['next_execution_time']);
			}
			$task['Task']['scheduled_time'] = $this->Task->breakTime($task['Task']['scheduled_time'], $task['Task']['timer']);
			$task['Task']['scheduled_time'] = date('H:i', $task['Task']['next_execution_time']);
		
		// Now that we have figured out when the next execution should happen, it's time to enqueue it.
			$process_id = CakeResque::enqueueAt(
					$task['Task']['next_execution_time'],
					'default',
					'ServerShell',
					array('enqueuePush', $task['Task']['next_execution_time'], $taskId, $org),
					true
			);
			$task['Task']['job_id'] = $process_id;
			$this->Task->save($task);
		}
	}
}
