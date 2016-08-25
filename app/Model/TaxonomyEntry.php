<?php
App::uses('AppModel', 'Model');

class TaxonomyEntry extends AppModel{

	public $useTable = 'taxonomy_entries';

	public $recursive = -1;

	public $actsAs = array(
			'Containable',
	);

	public $validate = array(
		'value' => array(
			'rule' => array('stringNotEmpty'),
		),
		'expanded' => array(
			'rule' => array('stringNotEmpty'),
		),
	);

	public $belongsTo = array(
		'TaxonomyPredicate'
	);

	public function beforeValidate($options = array()) {
		parent::beforeValidate();
		return true;
	}
}
