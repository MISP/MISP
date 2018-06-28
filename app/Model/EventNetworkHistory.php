<?php
App::uses('AppModel', 'Model');
class EventNetworkHistory extends AppModel{

	public $useTable = 'event_network_history';

	public $recursive = -1;

	public $actsAs = array(
			'Containable',
	);

	public $belongsTo = array(
		'Organisation' => array(
			'className' => 'Organisation',
			'foreignKey' => 'org_id',
			'conditions' => '',
			'fields' => '',
			'order' => ''
		),
		'User' => array(
			'className' => 'User',
			'foreignKey' => 'user_id',
			'conditions' => '',
			'fields' => '',
			'order' => ''
		)
	);


	public $validate = array(
		'is_json' => array(
				'rule' => array('isValidJson'),
				'message' => 'The provided network is not a valid json format',
				'required' => true,
		),
	);

	public function beforeValidate($options = array()) {
		parent::beforeValidate();
		return true;
	}

	public function isValidJson($text) {
		$check = json_decode($text);
		if ($check === null) {
			return false;
		}
		return true;
	}

}
