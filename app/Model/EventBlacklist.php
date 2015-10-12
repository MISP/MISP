<?php
App::uses('AppModel', 'Model');
class EventBlacklist extends AppModel{
	public $useTable = 'event_blacklists';
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
		$schema = $this->schema();
		if (!isset($schema['event_info'])) $this->updateDatabase('addEventBlacklistsContext');
		$date = date('Y-m-d H:i:s');
		if (empty($this->data['EventBlacklist']['id'])) {
			$this->data['EventBlacklist']['date_created'] = $date;
		}
		return true;
	}
}