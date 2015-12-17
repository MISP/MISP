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
		$attribute_ids = array_keys($this->Attribute->find('list'));
		$attributeCount = count($attribute_ids);
		
		for ($i = 0; $i < ceil($attributeCount / 1000); $i++) {
			$currentIds = array_slice($attribute_ids, ($i * 1000), (($i+1) * 1000));
			$fields = array('Attribute.id', 'Attribute.event_id', 'Attribute.distribution', 'Attribute.sharing_group_id', 'Attribute.type', 'Attribute.value1', 'Attribute.value2','Event.date', 'Event.org_id', 'Event.distribution', 'Event.sharing_group_id');
			// get all attributes..
			$attributes = $this->Attribute->find('all', array('recursive' => -1, 'conditions' => array('Attribute.id' => $currentIds), 'contain' => array('Event'), 'fields' => $fields));
			foreach ($attributes as $k => $attribute) {
				$this->Attribute->__afterSaveCorrelation($attribute['Attribute']);
			}
			$this->Job->saveField('progress', $i/$attributeCount*100);
		}
		$this->Job->saveField('progress', 100);
		$this->Job->saveField('message', 'Job done.');
		$this->Job->saveField('status', 1);
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
		$this->Job->saveField('status', 1);
	}
}

