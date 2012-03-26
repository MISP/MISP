<?php
App::uses('AppModel', 'Model');
App::uses('File', 'Utility');

/**
 * Signature Model
 *
 * @property Event $Event
 */
class Signature extends AppModel {
/**
 * Display field
 *
 * @var string
 */
	public $displayField = 'value';

	var $order = array("Signature.event_id" => "DESC", "Signature.type" => "ASC");
/**
 * Validation rules
 *
 * @var array
 */
	public $validate = array(
		'event_id' => array(
			'numeric' => array(
				'rule' => array('numeric'),
				//'message' => 'Your custom message here',
				//'allowEmpty' => false,
				//'required' => false,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'type' => array(
			'rule' => array('inList', array('md5','sha1',
                                            'filename',
                                            'filename|md5',
                                            'ip-src',
                                            'ip-dst',
                                            'domain',
                                            'email-src',
                                            'email-dst',
                                            'email-subject',
                                            'email-attachment',
                                            'url',
                                            'user-agent',
                                            'regkey',
                                            'regkey|value',
                                            'AS',
                                            'snort',
                                            'pattern-in-file',
                                            'pattern-in-memory',
                                            'vulnerability',
                                            'attachment',
                                            'malware-sample',
                                            'other')),
			'message' => 'Options : md5, sha1, filename, ip, domain, email, url, regkey, AS, other, ...',
			//'allowEmpty' => false,
			'required' => true,
			//'last' => false, // Stop validation after this rule
			//'on' => 'create', // Limit validation to 'create' or 'update' operations

		),
		'category' => array(
			'rule' => array('inList', array('Payload delivery',
		                    'Antivirus detection',
		                    'Payload installation',
		                    'Artifacts dropped',
		                    'Persistence mechanism',
		                    'Registry keys modified',
		                    'Network activity',
		                    'Payload type',
		                    'Attribution',
		                    'Other',
		                    '' // FIXME remove this once all signatures have a category. Otherwise sigs without category are not shown in the list
		                )),
			'message' => 'Options : Payload delivery, Antivirus detection, Payload installation, Files dropped ...'
		),
		'value' => array(
			'notempty' => array(
			'rule' => array('notempty'),
			'message' => 'Please fill in this field',
			//'allowEmpty' => false,
			//'required' => false,
			//'last' => false, // Stop validation after this rule
			//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
			'userdefined' => array(
				'rule' => array('validateSignatureValue'),
				'message' => 'Value not in the right type/format. Please double check the value or select "other" for a type.',
				//'allowEmpty' => false,
				//'required' => true,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'to_ids' => array(
			'boolean' => array(
				'rule' => array('boolean'),
				//'message' => 'Your custom message here',
				//'allowEmpty' => false,
				'required' => false,
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
		'revision' => array(
			'numeric' => array(
				'rule' => array('numeric'),
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
		'Event' => array(
			'className' => 'Event',
			'foreignKey' => 'event_id',
			'conditions' => '',
			'fields' => '',
			'order' => ''
		)
	);


	function beforeSave() {
	    // increment the revision number
	    if (empty($this->data['Signature']['revision'])) $this->data['Signature']['revision'] = 0;
	    $this->data['Signature']['revision'] = 1 + $this->data['Signature']['revision'] ;

	    // always return true after a beforeSave()
	    return true;
	}

	function beforeDelete() {
	    // delete attachments from the disk
	    $this->read();  // first read the signature from the db
	    if('attachment' == $this->data['Signature']['type'] ||
	       'malware-sample'== $this->data['Signature']['type'] ) {
	        // FIXME secure this filesystem access/delete by not allowing to change directories or go outside of the directory container.
	        // only delete the file if it exists
	        $filepath = APP."files/".$this->data['Signature']['event_id']."/".$this->data['Signature']['id'];
	        $file = new File ($filepath);
	        if($file->exists()) {
    	        if (!$file->delete()) {
    	            $this->Session->setFlash(__('Delete failed. Please report to administrator', true), 'default', array(), 'error'); // TODO change this message. Throw an internal error
    	        }
	        }
	    }
	}

	function beforeValidate() {
	    // remove leading and trailing blanks
	    $this->data['Signature']['value'] = trim($this->data['Signature']['value']);

	    switch($this->data['Signature']['type']) {
	        // lowercase these things
	        case 'md5':
	        case 'sha1':
	            $this->data['Signature']['value'] = strtolower($this->data['Signature']['value']);
	            break;
	    }

	    // always return true, otherwise the object cannot be saved
	    return true;
	}

	function validateSignatureValue ($fields) {
	    $value = $fields['value'];
	    $event_id = $this->data['Signature']['event_id'];
	    $type = $this->data['Signature']['type'];
	    $to_ids = $this->data['Signature']['to_ids'];
	    $category = $this->data['Signature']['category'];

	    // check if the signature already exists in the same event
	    $conditions = array('Signature.event_id' => $event_id,
                            'Signature.type' => $type,
                            'Signature.category' => $category,
                            'Signature.value' => $value
	    );
	    if (isset($this->data['Signature']['id']))
	        $conditions['Signature.id !='] = $this->data['Signature']['id'];

	    $params = array('recursive' => 0,
                        'conditions' => $conditions,
	    );
	    if (0 != $this->find('count', $params) )
	    return 'Attribute already exists for this event.';

	    // check data validation
	    switch($this->data['Signature']['type']) {
	        case 'md5':
	            if (preg_match("#^[0-9a-f]{32}$#", $value))
	            	return true;
	            return 'Checksum has invalid length or format. Please double check the value or select "other" for a type.';
	            break;
	        case 'sha1':
	            if (preg_match("#^[0-9a-f]{40}$#", $value))
	            	return true;
	            return 'Checksum has invalid length or format. Please double check the value or select "other" for a type.';
	            break;
	        case 'filename':
	            // no newline
	            if (!preg_match("#\n#", $value))
	            	return true;
	            break;
	        case 'filename|md5':
	            // no newline
	            if (!preg_match("#^.*|[0-9a-f]{32}$#", $value))
	                return true;
	            return 'Checksum has invalid length or format. Please double check the value or select "other" for a type.';
	            break;
	        case 'ip-src':
	            $parts = explode("/", $value);
	            // [0] = the ip
	            // [1] = the network address
	            if (count($parts) <= 2 ) {
	                // ipv4 and ipv6 matching
	                if (filter_var($parts[0],FILTER_VALIDATE_IP)) {
	                    // ip is validated, now check if we have a valid network mask
	                    if (empty($parts[1]))
	                    	return true;
	                    else if(is_numeric($parts[1]) && $parts[1] < 129)
	                    	return true;
	                }
	            }
	            return 'IP address has invalid format. Please double check the value or select "other" for a type.';
	            break;
	        case 'ip-dst':
	            $parts = explode("/", $value);
	            // [0] = the ip
	            // [1] = the network address
	            if (count($parts) <= 2 ) {
	                // ipv4 and ipv6 matching
	                if (filter_var($parts[0],FILTER_VALIDATE_IP)) {
	                    // ip is validated, now check if we have a valid network mask
	                    if (empty($parts[1]))
	                    	return true;
	                    else if(is_numeric($parts[1]) && $parts[1] < 129)
	                    	return true;
	                }
	            }
	            return 'IP address has invalid format. Please double check the value or select "other" for a type.';
	            break;
	        case 'domain':
	            if(preg_match("#^[A-Z0-9.-]+\.[A-Z]{2,4}$#i", $value))
	            	return true;
	            return 'Domain name has invalid format. Please double check the value or select "other" for a type.';
	            break;
	        case 'email-src':
	            // we don't use the native function to prevent issues with partial email addresses
	            if(preg_match("#^[A-Z0-9._%+-]*@[A-Z0-9.-]+\.[A-Z]{2,4}$#i", $value))
	            	return true;
	            return 'Email address has invalid format. Please double check the value or select "other" for a type.';
	            break;
	        case 'email-dst':
	            // we don't use the native function to prevent issues with partial email addresses
	            if(preg_match("#^[A-Z0-9._%+-]*@[A-Z0-9.-]+\.[A-Z]{2,4}$#i", $value))
	            	return true;
	            return 'Email address has invalid format. Please double check the value or select "other" for a type.';
	            break;
	        case 'email-subject':
	            // no newline
	            if (!preg_match("#\n#", $value))
	            	return true;
	            break;
	        case 'email-attachment':
	            // no newline
	            if (!preg_match("#\n#", $value))
	            	return true;
	            break;
	        case 'url':
	            // no newline
	            if (!preg_match("#\n#", $value))
	            	return true;
	            break;
	        case 'user-agent':
	            // no newline
	            if (!preg_match("#\n#", $value))
	            	return true;
	            break;
	        case 'regkey':
	            // no newline
	            if (!preg_match("#\n#", $value))
	            	return true;
	            break;
	        case 'regkey|value':
	            // no newline
	            if (!preg_match("#.*|.*#", $value))
	                return true;
	            break;
	        case 'snort':
	            // no validation yet. TODO implement data validation on snort signature type
	        case 'other':
	            return true;
	            break;
	    }

	    // default action is to return false
	    return true;

	}


	public function isOwnedByOrg($signatureid, $org) {
	    $this->id = $signatureid;
	    $this->read();
	    return $this->data['Event']['org'] === $org;
	}

	function getRelatedSignatures($signature) {
	    // LATER there should be a list of types/categories included here as some are not eligible (AV detection category
	    // or "other" type could be excluded)
	    // LATER getRelatedSignatures($signature) this might become a performance bottleneck
	    $conditions = array('Signature.value =' => $signature['value'],
	        					'Signature.id !=' => $signature['id'],
	        					'Signature.type =' => $signature['type'], );
	    //         $fields = array('Event.*');
	    $fields = array('Signature.*');

	    $similar_events = $this->find('all',array('conditions' => $conditions,
	                                              'fields' => $fields,
	                                              'order' => 'Signature.event_id DESC', )
	    );
	    return $similar_events;
	}

}
