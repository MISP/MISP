<?php
App::uses('AppModel', 'Model');

class Organisation extends AppModel{

	public $actsAs = array('Containable');

	public $validate = array(
		'name' => array(
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

    public $hasMany = array(
        'User' => array(
            'className' => 'User',
            'foreignKey' => 'organisation_id'
        ),

    );


	public $hasAndBelongsToMany = array(
		'SharingGroup' => array(
			'className' => 'SharingGroup',
			'joinTable' => 'organisations_sharing_groups',
			'foreignKey' => 'organisation_id',
			'associationForeignKey' => 'sharing_group_id',
		)
	);
}
