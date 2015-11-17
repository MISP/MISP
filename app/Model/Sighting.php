<?php
App::uses('AppModel', 'Model');
class Sighting extends AppModel{
	public $useTable = 'sightings';
	public $recursive = -1;
	public $actsAs = array(
			'Containable',
	);

	public $validate = array(
			'event_uuid' => array(
					'unique' => array(
							'rule' => 'isUnique',
							'message' => 'Event already blacklisted.'
					),
					'uuid' => array(
							'rule' => array('uuid'),
							'message' => 'Please provide a valid UUID'
					),
			)
	);

	public function beforeValidate($options = array()) {
		parent::beforeValidate();
		$date = date('Y-m-d H:i:s');
		if (empty($this->data['Sighting']['id'])) {
			$this->data['Sighting']['date_created'] = $date;
		}
		$this->data['Sighting']['date_modified'] = $date;
		return true;
	}
}