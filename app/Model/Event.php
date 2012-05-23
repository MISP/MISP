<?php
App::uses('AppModel', 'Model');
/**
 * Event Model
 *
 * @property User $User
 * @property Attribute $Attribute
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
		'published' => array(
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
		'Attribute' => array(
			'className' => 'Attribute',
			'foreignKey' => 'event_id',
			'dependent' => true,         // cascade deletes
			'conditions' => '',
			'fields' => '',
			'order' => array('Attribute.category ASC', 'Attribute.type ASC'),
			'limit' => '',
			'offset' => '',
			'exclusive' => '',
			'finderQuery' => '',
			'counterQuery' => ''
		)
	);


	function beforeValidate() {
	    // generate UUID if it doesn't exist
	    if (empty($this->data['Event']['uuid']))
	        $this->data['Event']['uuid']= String::uuid();
	}

	public function isOwnedByOrg($eventid, $org) {
	    return $this->field('id', array('id' => $eventid, 'org' => $org)) === $eventid;
	}

	function getRelatedEvents() {
	    // FIXME rewrite this to use the getRelatedAttributes function from the Attributes Model.
	    // only this way the code will be consistent

	    // first get a list of related event_ids
	    // then do a single query to search for all the events with that id
	    $relatedEventIds = Array();
	    foreach ($this->data['Attribute'] as $attribute ) {
	        if ($attribute['type'] == 'other')
	        continue;  // sigs of type 'other' should not be matched against the others
	        $conditions = array('Attribute.value =' => $attribute['value'], 'Attribute.type =' => $attribute['type']);
	        $similar_attributes = $this->Attribute->find('all',array('conditions' => $conditions));
	        foreach ($similar_attributes as $similar_attribute) {
	            if ($this->id == $similar_attribute['Attribute']['event_id'])
	            continue; // same as this event, not needed in the list
	            $relatedEventIds[] = $similar_attribute['Attribute']['event_id'];
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


	/**
	 * Clean up an Event Array that was received by an XML request.
	 * The structure needs to be changed a little bit to be compatible with what CakePHP expects
	 *
	 * This function receives the reference of the variable, so no return is required as it directly
	 * modifies the original data.
	 *
	 * @param &$data The reference to the variable
	 */
	function cleanupEventArrayFromXML(&$data) {
	    // Workaround for different structure in XML/array than what CakePHP expects
	    if (is_array($data['Event']['Attribute'])) {
	        if (is_numeric(implode(array_keys($data['Event']['Attribute']), ''))) {
	            // normal array of multiple Attributes
	            $data['Attribute'] = $data['Event']['Attribute'];
	        } else {
	            // single attribute
	            $data['Attribute'][0] = $data['Event']['Attribute'];
	        }
	    }
	    unset($data['Event']['Attribute']);


	    return $data;
	}
}
