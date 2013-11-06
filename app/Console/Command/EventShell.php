<?php 
//App::uses('AppShell', 'Console/Command');
require_once 'AppShell.php';
class EventShell extends AppShell
{
	public $uses = array('Event', 'Job');
	
	public function doPublish() {
		$id = $this->args[0];
		$this->Event->id = $id;
		if (!$this->Event->exists()) {
			throw new NotFoundException(__('Invalid event'));
		}
		$this->Job->create();
		$data = array(
				'worker' => 'default',
				'job_type' => 'doPublish',
				'job_input' => $id,
				'status' => 0,
				'retries' => 0,
				'message' => 'Job created.',
		);
		$this->Job->save($data);
		$jobID = $this->Job->id;
		//$this->Job->add('default', 'Publish', 'Event published: ' . $id);
		// update the event and set the from field to the current instance's organisation from the bootstrap. We also need to save id and info for the logs.
		$this->Event->recursive = -1;
		$event = $this->Event->read(null, $id);
		$event['Event']['published'] = 1;
		$fieldList = array('published', 'id', 'info');
		$this->Event->save($event, array('fieldList' => $fieldList));
		// only allow form submit CSRF protection.
		$this->Job->saveField('status', 1);
		$this->Job->saveField('message', 'Job done.');
	}
}

