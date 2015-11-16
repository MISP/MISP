<?php
App::uses('AppModel', 'Model');

class ThreatLevel extends AppModel {

	public $validate = array(
		'name' => array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
				'required' => true
			),
		),
		'description' => array(
			'valueNotEmpty' => array(
				'rule' => array('notEmpty'),
			),
		),
		'form_description' => array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
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
