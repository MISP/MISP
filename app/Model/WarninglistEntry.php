<?php
App::uses('AppModel', 'Model');
class WarninglistEntry extends AppModel{

	public $useTable = 'warninglist_entries';

	public $recursive = -1;

	public $actsAs = array(
			'Containable',
	);

	public $validate = array(
		'value' => array(
			'rule' => array('valueNotEmpty'),
		)
	);

	public $belongsTo = array(
			'Warninglist' => array(
				'className' => 'Warninglist',
				'foreignKey' => 'warninglist_id',
				'counterCache' => true
			)
	);

	public function beforeValidate($options = array()) {
		parent::beforeValidate();
		return true;
	}
}
