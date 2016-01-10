<?php
App::uses('AppModel', 'Model');

class EventDelegation extends AppModel {

	public $actsAs = array('Containable');
	
	public $validate = array(
		'event_id' => array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
			),
		),
		'org_id' => array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
			),
		)
	);
	
	public $belongsTo = array(
		'Event' => array(
			'className' => 'Event',
		),
		'Org' => array(
			'className' => 'Organisation',
		),
	);

	public function attachTagToEvent($event_id, $tag_id) {
		$existingAssociation = $this->find('first', array(
			'recursive' => -1,
			'conditions' => array(
				'tag_id' => $tag_id,
				'event_id' => $event_id
			)
		));
		if (empty($existingAssociation)) {
			$this->create();
			if (!$this->save(array('event_id' => $event_id, 'tag_id' => $tag_id))) return false;
		}
		return true;
	}
}