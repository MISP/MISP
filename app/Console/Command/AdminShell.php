<?php
App::uses('AppShell', 'Console/Command');
class AdminShell extends AppShell
{
	public $uses = array('Event');

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
}
