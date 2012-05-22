<?php
App::uses('AppModel', 'Model');
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');

/**
 * Attribute Model
 *
 * @property Event $Event
 */
class Attribute extends AppModel {
/**
 * Display field
 *
 * @var string
 */
	public $displayField = 'value';

	public $virtualFields = array(
	        'value' => 'IF (Attribute.value2="", Attribute.value1, CONCAT(Attribute.value1, "|", Attribute.value2))'
	);


	var $order = array("Attribute.event_id" => "DESC", "Attribute.type" => "ASC");
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
			                                'filename|sha1',
                                            'ip-src',
                                            'ip-dst',
			                                'hostname',
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
                                            'pattern-in-traffic',
                                            'pattern-in-memory',
                                            'vulnerability',
                                            'attachment',
                                            'malware-sample',
                                            'link',
                                            'description',
                                            'other')),
			'message' => 'Options : md5, sha1, filename, ip, domain, email, url, regkey, AS, other, ...',
			//'allowEmpty' => false,
			'required' => true,
			//'last' => false, // Stop validation after this rule
			//'on' => 'create', // Limit validation to 'create' or 'update' operations

		),
		'category' => array(
			'rule' => array('inList', array(
							'Internal reference',
			                'Payload delivery',
			                'Antivirus detection',
			                'Payload installation',
			                'Artifacts dropped',
			                'Persistence mechanism',
			                'Registry keys modified',
			                'Network activity',
			                'Payload type',
			                'Attribution',
			                'External analysis',
			                'Other',
			                '' // FIXME remove this once all attributes have a category. Otherwise sigs without category are not shown in the list
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
				'rule' => array('validateAttributeValue'),
				'message' => 'Value not in the right type/format. Please double check the value or select "other" for a type.',
				//'allowEmpty' => false,
				//'required' => true,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
			'unique' => array(
			        'rule' => array('valueIsUnique'),
			        'message' => 'A similar attribute already exists for this event.',
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
		                'allowEmpty' => true,
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
	    if (empty($this->data['Attribute']['revision'])) $this->data['Attribute']['revision'] = 0;
	    $this->data['Attribute']['revision'] = 1 + $this->data['Attribute']['revision'] ;

	    // explode value of composite type in value1 and value2
	    // or copy value to value1 if not composite type
	    if (!empty($this->data['Attribute']['type'])) {
    	    $composite_types = $this->getCompositeTypes();
    	    if (in_array($this->data['Attribute']['type'], $composite_types)) {
    	        // explode composite types in value1 and value2
        	    $pieces = explode('|', $this->data['Attribute']['value']);
        	    if (2 != sizeof($pieces)) throw new InternalErrorException('Composite type, but value not explodable');
    	        $this->data['Attribute']['value1'] = $pieces[0];
    	        $this->data['Attribute']['value2'] = $pieces[1];
    	    } else {
    	        $this->data['Attribute']['value1'] = $this->data['Attribute']['value'];
    	    }
	    }

	    // always return true after a beforeSave()
	    return true;
	}

	function afterSave() {
	    $result = true;
        // if the 'data' field is set on the $this->data then save the data to the correct file
        if ($this->typeIsAttachment($this->data['Attribute']['type']) && !empty($this->data['Attribute']['data'])) {
            $result = $result && $this->saveBase64EncodedAttachment($this->data['Attribute']);
        }
        return $result;
	}

	function beforeDelete() {
	    // delete attachments from the disk
	    $this->read();  // first read the attribute from the db
	    if($this->typeIsAttachment($this->data['Attribute']['type'])) {
	        // FIXME secure this filesystem access/delete by not allowing to change directories or go outside of the directory container.
	        // only delete the file if it exists
	        $filepath = APP."files/".$this->data['Attribute']['event_id']."/".$this->data['Attribute']['id'];
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
	    $this->data['Attribute']['value'] = trim($this->data['Attribute']['value']);

	    switch($this->data['Attribute']['type']) {
	        // lowercase these things
	        case 'md5':
	        case 'sha1':
	        case 'domain':
	        case 'hostname':
	            $this->data['Attribute']['value'] = strtolower($this->data['Attribute']['value']);
	            break;
	    }

	    // generate UUID if it doesn't exist
	    if (empty($this->data['Attribute']['uuid']))
	        $this->data['Attribute']['uuid']= String::uuid();

	    // always return true, otherwise the object cannot be saved
	    return true;
	}

	function valueIsUnique ($fields) {
	    $value = $fields['value'];
	    $event_id = $this->data['Attribute']['event_id'];
	    $type = $this->data['Attribute']['type'];
	    $to_ids = $this->data['Attribute']['to_ids'];
	    $category = $this->data['Attribute']['category'];

	    // check if the attribute already exists in the same event
	    $conditions = array('Attribute.event_id' => $event_id,
	            'Attribute.type' => $type,
	            'Attribute.category' => $category,
	            'Attribute.value' => $value
	    );
	    if (isset($this->data['Attribute']['id']))
	        $conditions['Attribute.id !='] = $this->data['Attribute']['id'];

	    $params = array('recursive' => 0,
	            'conditions' => $conditions,
	    );
	    if (0 != $this->find('count', $params) )
	        return false;

	    // Say everything is fine
	    return true;
	}

	function validateAttributeValue ($fields) {
	    $value = $fields['value'];

	    // check data validation
	    switch($this->data['Attribute']['type']) {
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
	            if (preg_match("#\n#", $value))
	            	return true;
	            break;
	        case 'filename|md5':
	            // no newline
	            if (preg_match("#^.+\|[0-9a-f]{32}$#", $value))
	                return true;
	            return 'Checksum has invalid length or format. Please double check the value or select "other" for a type.';
	            break;
            case 'filename|sha1':
                // no newline
                if (preg_match("#^.+\|[0-9a-f]{40}$#", $value))
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
	        case 'hostname':
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
	            if (!preg_match("#.+\|.+#", $value))
	                return true;
	            break;
	        case 'snort':
	            // no validation yet. TODO implement data validation on snort attribute type
	        case 'other':
	            return true;
	            break;
	    }

	    // default action is to return false
	    return true;

	}

    function getCompositeTypes() {
        // build the list of composite Attribute.type dynamically by checking if type contains a |
        // default composite types
        $composite_types = array('malware-sample');
        // dynamically generated list
        foreach ($this->validate['type']['rule'][1] as $type) {
            $pieces = explode('|', $type);
            if (2 == sizeof($pieces)) $composite_types[] = $type;
        }
        return $composite_types;
    }

	public function isOwnedByOrg($attributeid, $org) {
	    $this->id = $attributeid;
	    $this->read();
	    return $this->data['Event']['org'] === $org;
	}

	function getRelatedAttributes($attribute, $fields=array()) {
	    // LATER getRelatedAttributes($attribute) this might become a performance bottleneck

	    // exclude these specific categories to be linked
	    switch ($attribute['category']) {
	        case 'Antivirus detection':
	            return null;
	    }
        // exclude these specific types to be linked
        switch ($attribute['type']) {
            case 'description':
            case 'other':
                return null;
        }

        // prepare the conditions
        $conditions = array(
                'Attribute.event_id !=' => $attribute['event_id'],
//                 'Attribute.type' => $attribute['type'],  // LATER also filter on type
                );
        if (empty($attribute['value1']))   // prevent issues with empty fields
            return null;

        if (empty($attribute['value2'])) {
            // no value2, only search for value 1
            $conditions['OR'] = array(
                    'Attribute.value1' => $attribute['value1'],
                    'Attribute.value2' => $attribute['value1'],
            );
        } else {
            // value2 also set, so search for both
            $conditions['OR'] = array(
                    'Attribute.value1' => array($attribute['value1'],$attribute['value2']),
                    'Attribute.value2' => array($attribute['value1'],$attribute['value2']),
            );
        }

        // do the search
	    if (empty($fields)) {
	        $fields = array('Attribute.*');
	    }
	    $similar_events = $this->find('all',array('conditions' => $conditions,
	                                              'fields' => $fields,
	                                              'recursive' => 0,
	                                              'group' => array('Attribute.event_id'),
	                                              'order' => 'Attribute.event_id DESC', )
	    );
	    return $similar_events;
	}

	function typeIsAttachment($type) {
        switch ($type) {
            case 'attachment':
            case 'malware-sample':
                return true;
            default:
                return false;
        }
	}

	function base64EncodeAttachment($attribute) {
	    $filepath = APP."files/".$attribute['event_id']."/".$attribute['id'];
	    $file = new File($filepath);
	    if (!$file->exists()) return '';
        $content = $file->read();
	    return base64_encode($content);
	}

	function saveBase64EncodedAttachment($attribute) {
	    $root_dir = APP.DS."files".DS.$attribute['event_id'];
	    $dir = new Folder($root_dir, true);                         // create directory structure
	    $destpath = $root_dir.DS.$attribute['id'];
	    $file = new File ($destpath, true);	                        // create the file
	    $decoded_data = base64_decode($attribute['data']);          // decode
        if ($file->write($decoded_data)){                           // save the data
            return true;
        } else {
            // error
            return false;
        }
	}



}
