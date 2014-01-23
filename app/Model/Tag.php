<?php

App::uses('AppModel', 'Model');

/**
 * Tag Model
 *
 */
class Tag extends AppModel {

/**
 * Use table
 *
 * @var mixed False or table name
 */
	public $useTable = 'tags';

/**
 * Display field
 *
 * @var string
 */
	public $displayField = 'name';

	public $actsAs = array(
			'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
					'roleModel' => 'Tag',
					'roleKey' => 'tag_id',
					'change' => 'full'
			),
	);
	
	public $validate = array(
			'name' => array(
					'notempty' => array(
							'rule' => array('notempty'),
							'message' => 'Please fill in this field',
					),
					'unique' => array(
							'rule' => 'isUnique',
							'message' => 'A similar name already exists.',
					),
			),
			'colour' => array(
					'notempty' => array(
							'rule' => 'notempty',
							'message' => 'Please fill in this field',
					),
					'userdefined' => array(
							'rule' => 'validateColour',
							'message' => 'Colour has to be in the RGB format (#FFFFFF)',
					),
			),
	);
	
	public $hasMany = array(
		'EventTag' => array(
			'className' => 'EventTag',
		)
	);
	public function validateColour($fields) {
		if (!preg_match('/^#[0-9a-f]{6}$/i', $fields['colour'])) return false;
		return true;
	}

}