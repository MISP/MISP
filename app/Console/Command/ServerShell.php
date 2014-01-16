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
		$user = $this->User->read(array('id', 'org', 'email'), $userId);
		$server = $this->Server->read(null, $serverId);
		$result = $this->Server->pull($user['User'], null, $technique, $server, $jobId);
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
		$server = $this->Server->find(null, $serverId);
		App::uses('SyncTool', 'Tools');
		$syncTool = new SyncTool();
		$HttpSocket = $syncTool->setupHttpSocket($server);
		$result = $this->Server->push($id, 'full', $jobId, $HttpSocket);
		$this->Job->save(array(
				'id' => $jobId,
				'message' => 'Job done.',
				'progress' => 100,
				'status' => 4
		));
	}

}
