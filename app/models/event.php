<?php
class Event extends AppModel {
	var $name = 'Event';
	var $validate = array(
		'org' => array(
			'notempty' => array(
				'rule' => array('notempty'),
				//'message' => 'Your custom message here',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'date' => array(
			'date' => array(
				'rule' => array('date'),
				//'message' => 'Your custom message here',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'user_id' => array(
			'numeric' => array(
				'rule' => array('numeric'),
				//'message' => 'Your custom message here',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
        'risk' => array(
			'allowedChoice' => array(
                'rule' => array('inList', array('Undefined', 'Low','Medium','High')),
                'message' => 'Options : Undefined, Low, Medium, High'
            ),
		),
		'alerted' => array(
		     'boolean' => array(
                'rule' =>array('boolean'),
            ),
		),
	);
	//The Associations below have been created with all possible keys, those that are not needed can be removed

	var $belongsTo = array(
		'User' => array(
			'className' => 'User',
			'foreignKey' => 'user_id',
			'conditions' => '',
			'fields' => '',
			'order' => ''
		)
	);

	var $hasMany = array(
		'Signature' => array(
			'className' => 'Signature',
			'foreignKey' => 'event_id',
			'dependent' => true,     // cascade deletes
			'conditions' => '',
			'fields' => '',
			'order' => 'Signature.type ASC',
			'limit' => '',
			'offset' => '',
			'exclusive' => '',
			'finderQuery' => '',
			'counterQuery' => ''
		)
	);


	
	
}
