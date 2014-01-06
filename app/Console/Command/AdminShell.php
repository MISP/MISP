<?php 
App::uses('AppShell', 'Console/Command');
class AdminShell extends AppShell
{
	public $uses = array('Event');
	
	public function jobGenerateCorrelation() {
		$this->loadModel('Job');
		$this->Job->create();
		$data = array(
				'worker' => 'default',
				'job_type' => 'generate correlation',
				'job_input' => 'All attributes',
				'status' => 0,
				'retries' => 0,
				'message' => 'Job created.',
		);
		$this->Job->save($data);
		$jobID = $this->Job->id;
		$this->loadModel('Correlation');
		$this->Correlation->deleteAll(array('id !=' => ''), false);
		$this->loadModel('Attribute');
		$fields = array('Attribute.id', 'Attribute.event_id', 'Attribute.distribution', 'Attribute.cluster', 'Event.date', 'Event.org');
		// get all attributes..
		$attributes = $this->Attribute->find('all', array('recursive' => -1));
		// for all attributes..
		$total = count($attributes);
		foreach ($attributes as $k => $attribute) {
			$this->Job->saveField('progress', $k/$total*100);
			$this->Attribute->__afterSaveCorrelation($attribute['Attribute']);
		}
		$this->Job->saveField('progress', 100);
		$this->Job->saveField('message', 'Job done.');
		$this->Job->saveField('status', 1);
	}
}

