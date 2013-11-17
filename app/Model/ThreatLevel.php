<?php
App::uses('AppModel', 'Model');

class ThreatLevel extends AppModel {

	public $validate = array(
		'name' => array(
			'notEmpty' => array(
				'rule' => array('notEmpty'),
				'required' => true
			),
		),
		'description' => array(
			'notEmpty' => array(
				'rule' => array('notEmpty'),
			),
		),
		'form_description' => array(
			'notEmpty' => array(
				'rule' => array('notEmpty'),
				'required' => true
			),
		),
	);

/**
 * hasMany associations
 *
 * @var array
 */
	/*public $hasMany = array(
		'Event' => array(
			'className' => 'Event',
			'foreignKey' => 'threat_level_id',
			'dependent' => false,
		)
	);*/

}
