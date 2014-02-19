<?php
App::uses('AppModel', 'Model');

class SharingGroup extends AppModel {

	public $actsAs = array('Containable');

	public $validate = array(
		'name' => array(
			'unique' => array(
				'rule' => 'isUnique',
				'message' => 'A sharing group with this name already exists.'
			),
			'notempty' => array(
				'rule' => array('notempty'),
				//'message' => 'Your custom message here',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		)
	);

	public $hasAndBelongsToMany = array(
		'Organisation' => array(
			'className' => 'Organisation',
			'joinTable' => 'organisations_sharing_groups',
			'foreignKey' => 'sharing_group_id',
			'associationForeignKey' => 'organisation_id',
		)
	);
}