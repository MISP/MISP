<?php
App::uses('AppModel', 'Model');
class EventGraph extends AppModel{

	public $useTable = 'event_graph';

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
				'message' => 'The provided eventGraph is not a valid json format',
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
