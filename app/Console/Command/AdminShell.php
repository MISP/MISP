<?php 
App::uses('AppShell', 'Console/Command');
class AdminShell extends AppShell
{
	public $uses = array('Event');
	
	public function jobGenerateCorrelation() {
		$jobId = $this->args[0];
		$this->loadModel('Job');
		$this->Job->id = $jobId;
		$this->loadModel('Correlation');
		$this->Correlation->deleteAll(array('id !=' => ''), false);
		$this->loadModel('Attribute');
		$fields = array('Attribute.id', 'Attribute.event_id', 'Attribute.distribution', 'Attribute.cluster', 'Event.date', 'Event.org');
		// get all attributes..
		$attributes = $this->Attribute->find('all', array('recursive' => -1));
		// for all attributes..
		$total = count($attributes);
		foreach ($attributes as $k => $attribute) {
			if ($k > 0 && $k % 1000 == 0) {
				$this->Job->saveField('progress', $k/$total*100);
			}
			$this->Attribute->__afterSaveCorrelation($attribute['Attribute']);
		}
		$this->Job->saveField('progress', 100);
		$this->Job->saveField('message', 'Job done.');
		$this->Job->saveField('status', 1);
	}
}

