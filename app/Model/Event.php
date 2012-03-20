<?php
App::uses('AppModel', 'Model');
/**
 * Event Model
 *
 * @property User $User
 * @property Signature $Signature
 */
class Event extends AppModel {
/**
 * Display field
 *
 * @var string
 */
	public $displayField = 'id';
/**
 * Validation rules
 *
 * @var array
 */
	public $validate = array(
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
				'required' => true,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'risk' => array(
				'rule' => array('inList', array('Undefined', 'Low','Medium','High')),
				'message' => 'Options : Undefined, Low, Medium, High',
				//'allowEmpty' => false,
				'required' => true,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
		),
		'info' => array(
			'notempty' => array(
				'rule' => array('notempty'),
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
		'alerted' => array(
			'boolean' => array(
				'rule' => array('boolean'),
				//'message' => 'Your custom message here',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'uuid' => array(
			'uuid' => array(
				'rule' => array('uuid'),
				//'message' => 'Your custom message here',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'private' => array(
		        'boolean' => array(
		                'rule' => array('boolean'),
		                //'message' => 'Your custom message here',
		                //'allowEmpty' => false,
		                'required' => false,
		                //'last' => false, // Stop validation after this rule
		                //'on' => 'create', // Limit validation to 'create' or 'update' operations
		        ),
		),
	);

	//The Associations below have been created with all possible keys, those that are not needed can be removed

/**
 * belongsTo associations
 *
 * @var array
 */
	public $belongsTo = array(
		'User' => array(
			'className' => 'User',
			'foreignKey' => 'user_id',
			'conditions' => '',
			'fields' => '',
			'order' => ''
		)
	);

/**
 * hasMany associations
 *
 * @var array
 */
	public $hasMany = array(
		'Signature' => array(
			'className' => 'Signature',
			'foreignKey' => 'event_id',
			'dependent' => true,         // cascade deletes
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

	function getRelatedEvents() {
	    // first get a list of related event_ids
	    // then do a single query to search for all the events with that id
	    $relatedEventIds = Array();
	    foreach ($this->data['Signature'] as $signature ) {
	        if ($signature['type'] == 'other')
	        continue;  // sigs of type 'other' should not be matched against the others
	        $conditions = array('Signature.value =' => $signature['value'], 'Signature.type =' => $signature['type']);
	        $similar_signatures = $this->Signature->find('all',array('conditions' => $conditions));
	        foreach ($similar_signatures as $similar_signature) {
	            if ($this->id == $similar_signature['Signature']['event_id'])
	            continue; // same as this event, not needed in the list
	            $relatedEventIds[] = $similar_signature['Signature']['event_id'];
	        }
	    }
	    $conditions = array("Event.id" => $relatedEventIds);
	    $relatedEvents= $this->find('all',
	    array('conditions' => $conditions,
	                                          'recursive' => 0,
	                                          'order' => 'Event.date DESC',
	                                          'fields' => 'Event.*'
	    )
	    );
	    return $relatedEvents;
	}
}
