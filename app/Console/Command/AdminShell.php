<?php
App::uses('AppShell', 'Console/Command');
class AdminShell extends AppShell
{
	public $uses = array('Event', 'Post', 'Attribute', 'Job', 'User', 'Task', 'Whitelist', 'Server', 'Organisation');

	public function jobGenerateCorrelation() {
		$jobId = $this->args[0];
		$this->loadModel('Job');
		$this->Job->id = $jobId;
		$this->loadModel('Attribute');
		$this->Attribute->generateCorrelation($jobId, 0);
		$this->Job->saveField('progress', 100);
		$this->Job->saveField('message', 'Job done.');
		$this->Job->saveField('status', 4);
	}

	public function jobPurgeCorrelation() {
		$jobId = $this->args[0];
		$this->loadModel('Job');
		$this->Job->id = $jobId;
		$this->loadModel('Attribute');
		$this->Attribute->purgeCorrelations();
		$this->Job->saveField('progress', 100);
		$this->Job->saveField('message', 'Job done.');
		$this->Job->saveField('status', 4);
	}

	public function jobGenerateShadowAttributeCorrelation() {
		$jobId = $this->args[0];
		$this->loadModel('Job');
		$this->Job->id = $jobId;
		$this->loadModel('ShadowAttribute');
		$this->ShadowAttribute->generateCorrelation($jobId);
	}

	public function jobUpgrade24() {
		$jobId = $this->args[0];
		$user_id = $this->args[1];
		$this->loadModel('Job');
		$this->Job->id = $jobId;
		$this->loadModel('Server');
		$this->Server->upgrade2324($user_id, $jobId);
		$this->Job->saveField('progress', 100);
		$this->Job->saveField('message', 'Job done.');
		$this->Job->saveField('status', 4);
	}

	public function prune_update_logs() {
		$jobId = $this->args[0];
		$user_id = $this->args[1];
		$user = $this->User->getAuthUser($user_id);
		$this->loadModel('Job');
		$this->Job->id = $jobId;
		$this->loadModel('Log');
		$this->Log->pruneUpdateLogs($jobId, $user);
		$this->Job->saveField('progress', 100);
		$this->Job->saveField('message', 'Job done.');
		$this->Job->saveField('status', 4);
	}
}
