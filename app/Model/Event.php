<?php
App::uses('AppModel', 'Model');
/**
 * Event Model
 *
 * @property User $User
 * @property Attribute $Attribute
 */
class Event extends AppModel {
	
	var $name = 'Event';					// TODO general
    var $actsAs = array('Logable' => array(	// TODO Audit, logable
        'userModel' => 'User', 
        'userKey' => 'user_id', 
        'change' => 'full'
    ));
	
/**
 * Display field
 *
 * @var string
 */
	public $displayField = 'id';
/**
 * Description field
 *
 * @var array
 */

	public $field_descriptions = array(
			'risk' => array('desc' => 'Risk levels: *low* means mass-malware, *medium* means APT malware, *high* means sophisticated APT malware or 0-day attack', 'formdesc' => 'Risk levels:<br/>low: mass-malware<br/>medium: APT malware<br/>high: sophisticated APT malware or 0-day attack'),
			'private' => array('desc' => 'This field tells if the event should be shared with other CyDefSIG servers'),
	        'classification' => array('desc' => 'Set the Traffic Light Protocol classification. <ol><li><em>TLP:AMBER</em>- Share only within the organization on a need-to-know basis</li><li><em>TLP:GREEN:NeedToKnow</em>- Share within your constituency on the need-to-know basis.</li><li><em>TLP:GREEN</em>- Share within your constituency.</li></ol>')
			);

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
// 		'classification' => array(
// 		        'rule' => array('inList', array('TLP:AMBER', 'TLP:GREEN:NeedToKnow', 'TLP:GREEN')),
// 				//'message' => 'Your custom message here',
// 				//'allowEmpty' => false,
// 				'required' => true,
// 				//'last' => false, // Stop validation after this rule
// 				//'on' => 'create', // Limit validation to 'create' or 'update' operations
// 		),
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


	/**
	 * Uploads the event and the associated Attributes to another Server
	 * TODO move this to a component
	 *
	 * @return bool true if success, error message if failed
	 */
	function uploadEventToServer($event, $server, $HttpSocket=null) {
	    if (true ==$event['Event']['private'])  // never upload private events
	        return "Event is private and non exportable";

	    $url = $server['Server']['url'];
	    $authkey = $server['Server']['authkey'];
	    if (null == $HttpSocket) {
	        App::uses('HttpSocket', 'Network/Http');
	        $HttpSocket = new HttpSocket();
	    }
	    $request = array(
	            'header' => array(
	                    'Authorization' => $authkey,
	                    'Accept' => 'application/xml',
	                    'Content-Type' => 'application/xml',
	                    //'Connection' => 'keep-alive' // LATER followup cakephp ticket 2854 about this problem http://cakephp.lighthouseapp.com/projects/42648-cakephp/tickets/2854
	            )
	    );
	    $uri = $url.'/events';

	    // LATER try to do this using a separate EventsController and renderAs() function
	    $xmlArray = array();
	    // rearrange things to be compatible with the Xml::fromArray()
	    $event['Event']['Attribute'] = $event['Attribute'];
	    unset($event['Attribute']);

	    // cleanup the array from things we do not want to expose
	    unset($event['Event']['user_id']);
	    unset($event['Event']['org']);
	    // remove value1 and value2 from the output
	    foreach($event['Event']['Attribute'] as $key => $attribute) {
	        // do not keep attributes that are private
	        if ($event['Event']['Attribute'][$key]['private']) {
	            unset($event['Event']['Attribute'][$key]);
	            continue; // stop processing this
	        }
	        // remove value1 and value2 from the output
	        unset($event['Event']['Attribute'][$key]['value1']);
	        unset($event['Event']['Attribute'][$key]['value2']);
	        // also add the encoded attachment
	        if ($this->Attribute->typeIsAttachment($event['Event']['Attribute'][$key]['type'])) {
	            $encoded_file = $this->Attribute->base64EncodeAttachment($event['Event']['Attribute'][$key]);
	            $event['Event']['Attribute'][$key]['data'] = $encoded_file;
	        }
	    }

	    // display the XML to the user
	    $xmlArray['Event'][] = $event['Event'];
	    $xmlObject = Xml::fromArray($xmlArray, array('format' => 'tags'));
	    $eventsXml = $xmlObject->asXML();
	    // do a REST POST request with the server
	    $data = $eventsXml;
	    // LATER validate HTTPS SSL certificate
	    $response = $HttpSocket->post($uri, $data, $request);
	    if ($response->isOk()) {
	        return true;
	    }
	    else {
	        // parse the XML response and keep the reason why it failed
	        $xml_array = Xml::toArray(Xml::build($response->body));
	        if ("Event already exists" == $xml_array['response']['name']) {
	            return true;
	        } else {
	            return $xml_array['response']['name'];
	        }
	    }
	}

	/**
	 * Download a specific event from a Server
	 * TODO move this to a component
	 * @return array|NULL
	 */
	function downloadEventFromServer($event_id, $server, $HttpSocket=null) {
	    $url = $server['Server']['url'];
	    $authkey = $server['Server']['authkey'];
	    if (null == $HttpSocket) {
	        App::uses('HttpSocket', 'Network/Http');
	        $HttpSocket = new HttpSocket();
	    }
	    $request = array(
	            'header' => array(
	                    'Authorization' => $authkey,
	                    'Accept' => 'application/xml',
	                    'Content-Type' => 'application/xml',
	                    //'Connection' => 'keep-alive' // LATER followup cakephp ticket 2854 about this problem http://cakephp.lighthouseapp.com/projects/42648-cakephp/tickets/2854
	            )
	    );
	    $uri = $url.'/events/'.$event_id;
	    // LATER validate HTTPS SSL certificate
	    $response = $HttpSocket->get($uri, $data='', $request);
	    if ($response->isOk()) {
	        $xml_array = Xml::toArray(Xml::build($response->body));
	        return $xml_array['response'];
	    }
	    else {
	        // TODO parse the XML response and keep the reason why it failed
	        return null;
	    }
	}

	/**
	 * Get an array of event_ids that are present on the remote server
	 * TODO move this to a component
	 * @return array of event_ids
	 */
	function getEventIdsFromServer($server, $HttpSocket=null) {
	    $url = $server['Server']['url'];
	    $authkey = $server['Server']['authkey'];

	    if (null == $HttpSocket) {
	        App::uses('HttpSocket', 'Network/Http');
	        $HttpSocket = new HttpSocket();
	    }
	    $request = array(
	            'header' => array(
	                    'Authorization' => $authkey,
	                    'Accept' => 'application/xml',
	                    'Content-Type' => 'application/xml',
	                    //'Connection' => 'keep-alive' // LATER followup cakephp ticket 2854 about this problem http://cakephp.lighthouseapp.com/projects/42648-cakephp/tickets/2854
	            )
	    );
	    $uri = $url.'/events/index/sort:id/direction:desc/limit:999'; // LATER verify if events are missing because we only selected the last 999
	    $response = $HttpSocket->get($uri, $data='', $request);

	    if ($response->isOk()) {
	        $xml = Xml::build($response->body);
	        $eventArray = Xml::toArray($xml);
	        $event_ids=array();
	        foreach ($eventArray['response']['Event'] as $event) {
	            if (1 != $event['published']) continue;  // do not keep non-published events
	            $event_ids[] = $event['id'];
	        }
	        return $event_ids;
	    }
	    // error, so return null
	    return null;
	}




}
