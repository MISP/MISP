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
		$attributeIDs = array_keys($this->Attribute->find('list'));
		$total = count($attributeIDs);
		$start = 0;
		$continue = true;
		while ($continue) {
			
			$attributes = $this->Attribute->find('all', array('recursive' => -1, 'conditions' => array('AND' => array('Event.id' > $start, 'Event.id' <= ($start + 1000)))));
			foreach ($attributes as $k => $attribute) {
				$this->Attribute->__afterSaveCorrelation($attribute['Attribute']);
			}
			$this->Job->saveField('progress', $k/$total*100);
			$start += 1000;
			if ($start > $total) $continue = false;
		}
		$this->Job->saveField('progress', 100);
		$this->Job->saveField('message', 'Job done.');
		$this->Job->saveField('status', 1);
	}
}

