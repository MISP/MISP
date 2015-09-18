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

	public $combinedKeys = array('event_id', 'category', 'type');

	public $name = 'Attribute';				// TODO general

	public $actsAs = array(
		'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
			'userModel' => 'User',
			'userKey' => 'user_id',
			'change' => 'full'),
		'Trim',
		'Containable',
		'Regexp' => array('fields' => array('value')),
	);

/**
 * hasMany relation to shadow attributes
 *
 * Display field
 *
 * @var string
 */
	public $displayField = 'value';

/**
 * Virtual field
 *
 * @var array
 */
	public $virtualFields = array(
			'value' => 'IF (Attribute.value2="", Attribute.value1, CONCAT(Attribute.value1, "|", Attribute.value2))',
			'category_order' => 'IF (Attribute.category="Internal reference", "a",
			IF (Attribute.category="Targeting data", "b",
 			IF (Attribute.category="Antivirus detection", "c",
 			IF (Attribute.category="Payload delivery", "d",
 			IF (Attribute.category="Payload installation", "e",
 			IF (Attribute.category="Artifacts dropped", "f",
 			IF (Attribute.category="Persistence mechanism", "g",
 			IF (Attribute.category="Network activity", "h",
 			IF (Attribute.category="Payload type", "i",
 			IF (Attribute.category="Attribution", "j",
 			IF (Attribute.category="External analysis", "k", "l")))))))))))'
	); // TODO hardcoded

/**
 * Field Descriptions
 * explanations of certain fields to be used in various views
 *
 * @var array
 */
	public $fieldDescriptions = array(
			'signature' => array('desc' => 'Is this attribute eligible to automatically create an IDS signature (network IDS or host IDS) out of it ?'),
			'distribution' => array('desc' => 'Describes who will have access to the event.')
	);

	public $distributionDescriptions = array(
			0 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "This setting will only allow members of your organisation on this server to see it."),
			1 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "Users that are part of your MISP community will be able to see the event. This includes your own organisation, organisations on this MISP server and organisations running MISP servers that synchronise with this server. Any other organisations connected to such linked servers will be restricted from seeing the event. Use this option if you are on the central hub of this community."), // former Community
			2 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "Users that are part of your MISP community will be able to see the event. This includes all organisations on this MISP server, all organisations on MISP servers synchronising with this server and the hosting organisations of servers that connect to those afore mentioned servers (so basically any server that is 2 hops away from this one). Any other organisations connected to linked servers that are 2 hops away from this will be restricted from seeing the event. Use this option if this server isn't the central MISP hub of the community but is connected to it."),
			3 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "This will share the event with all MISP communities, allowing the event to be freely propagated from one server to the next."),
	);

	public $distributionLevels = array(
			0 => 'Your organisation only', 1 => 'This community only', 2 => 'Connected communities', 3 => 'All communities'
	);

	// these are definition of possible types + their descriptions and maybe later other behaviors
	// e.g. if the attribute should be correlated with others or not

	// if these then a category my have upload to be zipped

	public $zippedDefinitions = array(
			'malware-sample'
	);

	// if these then a category my have upload

	public $uploadDefinitions = array(
			'attachment'
	);
	
	// skip Correlation for the following types
	public $nonCorrelatingTypes = array(
			'vulnerability',
			'comment',
			'http-method'
	);

	public $typeDefinitions = array(
			'md5' => array('desc' => 'A checksum in md5 format', 'formdesc' => "You are encouraged to use filename|md5 instead. A checksum in md5 format, only use this if you don't know the correct filename"),
			'sha1' => array('desc' => 'A checksum in sha1 format', 'formdesc' => "You are encouraged to use filename|sha1 instead. A checksum in sha1 format, only use this if you don't know the correct filename"),
			'sha256' => array('desc' => 'A checksum in sha256 format', 'formdesc' => "You are encouraged to use filename|sha256 instead. A checksum in sha256 format, only use this if you don't know the correct filename"),
			'filename' => array('desc' => 'Filename'),
			'filename|md5' => array('desc' => 'A filename and an md5 hash separated by a |', 'formdesc' => "A filename and an md5 hash separated by a | (no spaces)"),
			'filename|sha1' => array('desc' => 'A filename and an sha1 hash separated by a |', 'formdesc' => "A filename and an sha1 hash separated by a | (no spaces)"),
			'filename|sha256' => array('desc' => 'A filename and an sha256 hash separated by a |', 'formdesc' => "A filename and an sha256 hash separated by a | (no spaces)"),
			'ip-src' => array('desc' => "A source IP address of the attacker"),
			'ip-dst' => array('desc' => 'A destination IP address of the attacker or C&C server', 'formdesc' => "A destination IP address of the attacker or C&C server. Also set the IDS flag on when this IP is hardcoded in malware"),
			'hostname' => array('desc' => 'A full host/dnsname of an attacker', 'formdesc' => "A full host/dnsname of an attacker. Also set the IDS flag on when this hostname is hardcoded in malware"),
			'domain' => array('desc' => 'A domain name used in the malware', 'formdesc' => "A domain name used in the malware. Use this instead of hostname when the upper domain is important or can be used to create links between events."),
			'email-src' => array('desc' => "The email address (or domainname) used to send the malware."),
			'email-dst' => array('desc' => "A recipient email address", 'formdesc' => "A recipient email address that is not related to your constituency."),
			'email-subject' => array('desc' => "The subject of the email"),
			'email-attachment' => array('desc' => "File name of the email attachment."),
			'url' => array('desc' => 'url'),
			'http-method' => array('desc' => "HTTP method used by the malware (e.g. POST, GET, ...)."),
			'user-agent' => array('desc' => "The user-agent used by the malware in the HTTP request."),
			'regkey' => array('desc' => "Registry key or value"),
			'regkey|value' => array('desc' => "Registry value + data separated by |"),
			'AS' => array('desc' => 'Autonomous system'),
			'snort' => array('desc' => 'An IDS rule in Snort rule-format', 'formdesc' => "An IDS rule in Snort rule-format. This rule will be automatically rewritten in the NIDS exports."),
			'pattern-in-file' => array('desc' => 'Pattern in file that identifies the malware'),
			'pattern-in-traffic' => array('desc' => 'Pattern in network traffic that identifies the malware'),
			'pattern-in-memory' => array('desc' => 'Pattern in memory dump that identifies the malware'),
			'yara' => array('desc' => 'Yara signature'),
			'vulnerability' => array('desc' => 'A reference to the vulnerability used in the exploit'),
			'attachment' => array('desc' => 'Attachment with external information', 'formdesc' => "Please upload files using the <em>Upload Attachment</em> button."),
			'malware-sample' => array('desc' => 'Attachment containing encrypted malware sample', 'formdesc' => "Please upload files using the <em>Upload Attachment</em> button."),
			'link' => array('desc' => 'Link to an external information'),
			'comment' => array('desc' => 'Comment or description in a human language', 'formdesc' => 'Comment or description in a human language.  This will not be correlated with other attributes (NOT IMPLEMENTED YET)'),
			'text' => array('desc' => 'Name, ID or a reference'),
			'other' => array('desc' => 'Other attribute'),
			'named pipe' => array('desc' => 'Named pipe, use the format \\.\pipe\<PipeName>'),
			'mutex' => array('desc' => 'Mutex, use the format \BaseNamedObjects\<Mutex>'),
 			'target-user' => array('desc' => 'Attack Targets Username(s)'),
 			'target-email' => array('desc' => 'Attack Targets Email(s)'),
 			'target-machine' => array('desc' => 'Attack Targets Machine Name(s)'),
 			'target-org' => array('desc' => 'Attack Targets Department or Orginization(s)'),
 			'target-location' => array('desc' => 'Attack Targets Physical Location(s)'),
 			'target-external' => array('desc' => 'External Target Orginizations Affected by this Attack'),
	);

	// definitions of categories
	public $categoryDefinitions = array(
			'Internal reference' => array(
					'desc' => 'Reference used by the publishing party (e.g. ticket number)',
					'types' => array('link', 'comment', 'text', 'other')
					),
 			'Targeting data' => array(
 					'desc' => 'Internal Attack Targeting and Compromise Information',
 					'formdesc' => 'Targeting information to include recipient email, infected machines, department, and or locations.<br/>',
 					'types' => array('target-user', 'target-email', 'target-machine', 'target-org', 'target-location', 'target-external', 'comment')
 					),
			'Antivirus detection' => array(
					'desc' => 'All the info about how the malware is detected by the antivirus products',
					'formdesc' => 'List of anti-virus vendors detecting the malware or information on detection performance (e.g. 13/43 or 67%). Attachment with list of detection or link to VirusTotal could be placed here as well.',
					'types' => array('link', 'comment', 'text', 'attachment', 'other')
					),
			'Payload delivery' => array(
					'desc' => 'Information about how the malware is delivered',
					'formdesc' => 'Information about the way the malware payload is initially delivered, for example information about the email or web-site, vulnerability used, originating IP etc. Malware sample itself should be attached here.',
					'types' => array('md5', 'sha1', 'sha256','filename', 'filename|md5', 'filename|sha1', 'filename|sha256', 'ip-src', 'ip-dst', 'hostname', 'domain', 'email-src', 'email-dst', 'email-subject', 'email-attachment', 'url', 'user-agent', 'AS', 'pattern-in-file', 'pattern-in-traffic', 'yara', 'attachment', 'malware-sample', 'link', 'comment', 'text', 'vulnerability', 'other')
					),
			'Artifacts dropped' => array(
					'desc' => 'Any artifact (files, registry keys etc.) dropped by the malware or other modifications to the system',
					'types' => array('md5', 'sha1', 'sha256', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha256', 'regkey', 'regkey|value', 'pattern-in-file', 'pattern-in-memory', 'yara', 'attachment', 'malware-sample', 'comment', 'text', 'other', 'named pipe', 'mutex')
					),
			'Payload installation' => array(
					'desc' => 'Info on where the malware gets installed in the system',
					'formdesc' => 'Location where the payload was placed in the system and the way it was installed. For example, a filename|md5 type attribute can be added here like this: c:\\windows\\system32\\malicious.exe|41d8cd98f00b204e9800998ecf8427e.',
					'types' => array('md5', 'sha1', 'sha256', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha256', 'pattern-in-file', 'pattern-in-traffic', 'pattern-in-memory', 'yara', 'vulnerability', 'attachment', 'malware-sample', 'comment', 'text', 'other')
					),
			'Persistence mechanism' => array(
					'desc' => 'Mechanisms used by the malware to start at boot',
					'formdesc' => 'Mechanisms used by the malware to start at boot. This could be a registry key, legitimate driver modification, LNK file in startup',
					'types' => array('filename', 'regkey', 'regkey|value', 'comment', 'text', 'other')
					),
			'Network activity' => array(
					'desc' => 'Information about network traffic generated by the malware',
					'types' => array('ip-src', 'ip-dst', 'hostname', 'domain', 'email-dst', 'url', 'user-agent', 'http-method', 'AS', 'snort', 'pattern-in-file', 'pattern-in-traffic', 'attachment', 'comment', 'text', 'other')
					),
			'Payload type' => array(
					'desc' => 'Information about the final payload(s)',
					'formdesc' => 'Information about the final payload(s). Can contain a function of the payload, e.g. keylogger, RAT, or a name if identified, such as Poison Ivy.',
					'types' => array('comment', 'text', 'other')
					),
			'Attribution' => array(
					'desc' => 'Identification of the group, organisation, or country behind the attack',
					'types' => array('comment', 'text', 'other')
					),
			'External analysis' => array(
					'desc' => 'Any other result from additional analysis of the malware like tools output',
					'formdesc' => 'Any other result from additional analysis of the malware like tools output Examples: pdf-parser output, automated sandbox analysis, reverse engineering report.',
					'types' => array('md5', 'sha1', 'sha256','filename', 'filename|md5', 'filename|sha1', 'filename|sha256', 'ip-src', 'ip-dst', 'hostname', 'domain', 'url', 'user-agent', 'regkey', 'regkey|value', 'AS', 'snort', 'pattern-in-file', 'pattern-in-traffic', 'pattern-in-memory', 'vulnerability', 'attachment', 'malware-sample', 'link', 'comment', 'text', 'other')
					),
			'Other' => array(
					'desc' => 'Attributes that are not part of any other category',
					'types' => array('comment', 'text', 'other')
					)
	);

	public $order = array("Attribute.event_id" => "DESC");

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
			// currently when adding a new attribute type we need to change it in both places
			'rule' => array('validateTypeValue'),
			'message' => 'Options depend on the selected category.',
			//'allowEmpty' => false,
			'required' => true,
			//'last' => false, // Stop validation after this rule
			//'on' => 'create', // Limit validation to 'create' or 'update' operations

		),
		// this could be initialized from categoryDefinitions but dunno how at the moment
		'category' => array(
			'rule' => array('inList', array(
							'Internal reference',
							'Targeting data',
							'Antivirus detection',
							'Payload delivery',
							'Payload installation',
							'Artifacts dropped',
							'Persistence mechanism',
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
			'uniqueValue' => array(
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
			'unique' => array(
				'rule' => 'isUnique',
				'message' => 'The UUID provided is not unique',
				'required' => 'create'
			)
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
		'distribution' => array(
				'rule' => array('inList', array('0', '1', '2', '3')),
				'message' => 'Options : Your organisation only, This community only, Connected communities, All communities',
				//'allowEmpty' => false,
				'required' => true,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
		),
	);
	
	// automatic resolution of complex types
	// If the complex type "file" is chosen for example, then the system will try to categorise the values entered into a complex template field based 
	// on the regular expression rules
	public $validTypeGroups = array(
			'File' => array(
				'description' => '',
				'types' => array('filename', 'filename|md5', 'filename|sha1', 'filename|sha256', 'md5', 'sha1', 'sha256'),
			),
			'CnC' => array(
				'description' => '',
				'types' => array('url', 'domain', 'hostname', 'ip-dst'),
			),
	);
	
	public $typeGroupCategoryMapping = array(
			'Payload delviery' => array('File', 'CnC'),
			'Payload installation' => array('File'),
			'Artifacts dropped' => array('File'),
			'Network activity' => array('CnC'),
	);

	public function __construct($id = false, $table = null, $ds = null) {
		parent::__construct($id, $table, $ds);

}

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
			'order' => '',
			'counterCache' => true
		)
	);
	
	public $hashTypes = array(
		'md5' => array(
			'length' => 32,
			'pattern' => '#^[0-9a-f]{32}$#',
			'lowerCase' => true,
		),
		'sha1' => array(
			'length' => 40,
			'pattern' => '#^[0-9a-f]{40}$#',
			'lowerCase' => true,
		),
		'sha256' => array(
			'length' => 64,
			'pattern' => '#^[0-9a-f]{64}$#',
			'lowerCase' => true,
		)
	);

/**
 * beforeSave
 *
 * @throws InternalErrorException
 * @return bool always true
 */
	public function beforeSave($options = array()) {
		// explode value of composite type in value1 and value2
		// or copy value to value1 if not composite type
		if (!empty($this->data['Attribute']['type'])) {
			$compositeTypes = $this->getCompositeTypes();
			// explode composite types in value1 and value2
			//if (!isset($this->data['Attribute']['value1'])) {
			$pieces = explode('|', $this->data['Attribute']['value']);
			if (in_array($this->data['Attribute']['type'], $compositeTypes)) {
				if (2 != count($pieces)) {
					throw new InternalErrorException('Composite type, but value not explodable');
				}
				$this->data['Attribute']['value1'] = $pieces[0];
				$this->data['Attribute']['value2'] = $pieces[1];
			} else {
				$total = implode('|', $pieces);
				$this->data['Attribute']['value1'] = $total;
				$this->data['Attribute']['value2'] = '';
			}
		}
		// update correlation... (only needed here if there's an update)
		if ($this->id || !empty($this->data['Attribute']['id'])) {
 			$this->__beforeSaveCorrelation($this->data['Attribute']);
		}
		// always return true after a beforeSave()
		return true;
	}

	public function afterSave($created, $options = array()) {
		// update correlation...
		$this->__afterSaveCorrelation($this->data['Attribute']);

		$result = true;

		// if the 'data' field is set on the $this->data then save the data to the correct file
		if (isset($this->data['Attribute']['type']) && $this->typeIsAttachment($this->data['Attribute']['type']) && !empty($this->data['Attribute']['data'])) {
			$result = $result && $this->saveBase64EncodedAttachment($this->data['Attribute']); // TODO : is this correct?
		}
		return $result;
	}

	public function beforeDelete($cascade = true) {
		// delete attachments from the disk
		$this->read(); // first read the attribute from the db
		if ($this->typeIsAttachment($this->data['Attribute']['type'])) {
			// FIXME secure this filesystem access/delete by not allowing to change directories or go outside of the directory container.
			// only delete the file if it exists
			$filepath = APP . "files" . DS . $this->data['Attribute']['event_id'] . DS . $this->data['Attribute']['id'];
			$file = new File ($filepath);
			if ($file->exists()) {
				if (!$file->delete()) {
					throw new InternalErrorException('Delete of file attachment failed. Please report to administrator.');
				}
			}
		}

		// update correlation..
		$this->__beforeDeleteCorrelation($this->data['Attribute']['id']);

	}

	public function beforeValidate($options = array()) {
		parent::beforeValidate();

		// remove leading and trailing blanks
		$this->data['Attribute']['value'] = trim($this->data['Attribute']['value']);

		if (!isset($this->data['Attribute']['type'])) {
			return false;
		}

		switch($this->data['Attribute']['type']) {
			// lowercase these things
			case 'md5':
			case 'sha1':
			case 'sha256':
			case 'domain':
			case 'hostname':
				$this->data['Attribute']['value'] = strtolower($this->data['Attribute']['value']);
				break;
			case 'filename|md5':
			case 'filename|sha1':
			case 'filename|sha256':
				$pieces = explode('|', $this->data['Attribute']['value']);
				$this->data['Attribute']['value'] = $pieces[0] . '|' . strtolower($pieces[1]);
				break;
		}

		// uppercase the following types
		switch($this->data['Attribute']['type']) {
			case 'http-method':
				$this->data['Attribute']['value'] = strtoupper($this->data['Attribute']['value']);
		        break;
        }

		// set to_ids if it doesn't exist
		if (empty($this->data['Attribute']['to_ids'])) {
		    $this->data['Attribute']['to_ids'] = 0;
		}

		// generate UUID if it doesn't exist
		if (empty($this->data['Attribute']['uuid'])) {
			$this->data['Attribute']['uuid'] = String::uuid();
		}

		// generate timestamp if it doesn't exist
		if (empty($this->data['Attribute']['timestamp'])) {
			$date = new DateTime();
			$this->data['Attribute']['timestamp'] = $date->getTimestamp();
		}
		$result = $this->runRegexp($this->data['Attribute']['type'], $this->data['Attribute']['value']);
		if (!$result) {
			$this->invalidate('value', 'This value is blocked by a regular expression in the import filters.');
		} else {
			$this->data['Attribute']['value'] = $result;
		}
		// always return true, otherwise the object cannot be saved
		return true;
	}

	public function valueIsUnique ($fields) {
		$value = $fields['value'];
		$eventId = $this->data['Attribute']['event_id'];
		$type = $this->data['Attribute']['type'];
		$toIds = $this->data['Attribute']['to_ids'];
		$category = $this->data['Attribute']['category'];

		// check if the attribute already exists in the same event
		$conditions = array('Attribute.event_id' => $eventId,
				'Attribute.type' => $type,
				'Attribute.category' => $category,
				'Attribute.value' => $value
		);
		if (isset($this->data['Attribute']['id'])) {
			$conditions['Attribute.id !='] = $this->data['Attribute']['id'];
		}

		$params = array('recursive' => -1,
				'conditions' => $conditions,
		);
		if (0 != $this->find('count', $params)) {
			return false;
		}
		// Say everything is fine
		return true;
	}

	public function validateTypeValue($fields) {
		$category = $this->data['Attribute']['category'];
		if (isset($this->categoryDefinitions[$category]['types'])) {
			return in_array($fields['type'], $this->categoryDefinitions[$category]['types']);
		}
		return false;
	}

	public function validateAttributeValue($fields) {
		$value = $fields['value'];
		return $this->runValidation($value, $this->data['Attribute']['type']);
	}
	
	public function runValidation($value, $type) {
		$returnValue = false;
		// check data validation
		switch($type) {
			case 'md5':
				if (preg_match("#^[0-9a-f]{32}$#", $value)) {
					if ($value === 'd41d8cd98f00b204e9800998ecf8427e') $returnValue = 'The supplied hash indicates an empty file.';
					else $returnValue = true;
				} else {
					$returnValue = 'Checksum has invalid length or format. Please double check the value or select "other" for a type.';
				}
				break;
			case 'sha1':
				if (preg_match("#^[0-9a-f]{40}$#", $value)) {
					if ($value === 'da39a3ee5e6b4b0d3255bfef95601890afd80709') $returnValue = 'The supplied hash indicates an empty file.';
					else $returnValue = true;
				} else {
					$returnValue = 'Checksum has invalid length or format. Please double check the value or select "other" for a type.';
				}
				break;
			case 'sha256':
				if (preg_match("#^[0-9a-f]{64}$#", $value)) {
					if ($value === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') $returnValue = 'The supplied hash indicates an empty file.';
					else $returnValue = true;
				} else {
					$returnValue = 'Checksum has invalid length or format. Please double check the value or select "other" for a type.';
				}
				break;
			case 'http-method':
				if (preg_match("#(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|VERSION-CONTROL|REPORT|CHECKOUT|CHECKIN|UNCHECKOUT|MKWORKSPACE|UPDATE|LABEL|MERGE|BASELINE-CONTROL|MKACTIVITY|ORDERPATCH|ACL|PATCH|SEARCH)#", $value)) {
				    $returnValue = true;
				} else {
					$returnValue = 'Unknown HTTP method.';
				}
				break;
			case 'filename':
				// no newline
				if (!preg_match("#\n#", $value)) {
					$returnValue = true;
				}
				break;
			case 'filename|md5':
				// no newline
				if (preg_match("#^.+\|[0-9a-f]{32}$#", $value)) {
					$parts = explode('|', $value);
					if ($parts[1] === 'd41d8cd98f00b204e9800998ecf8427e') $returnValue = 'The supplied hash indicates an empty file.';
					else $returnValue = true;
				} else {
					$returnValue = 'Checksum has invalid length or format. Please double check the value or select "other" for a type.';
				}
				break;
			case 'filename|sha1':
				// no newline
				if (preg_match("#^.+\|[0-9a-f]{40}$#", $value)) {
					$parts = explode('|', $value);
					if ($parts[1] === 'da39a3ee5e6b4b0d3255bfef95601890afd80709') $returnValue = 'The supplied hash indicates an empty file.';
					else $returnValue = true;
				} else {
					$returnValue = 'Checksum has invalid length or format. Please double check the value or select "other" for a type.';
				}
				break;
			case 'filename|sha256':
				// no newline
				if (preg_match("#^.+\|[0-9a-f]{64}$#", $value)) {
					$parts = explode('|', $value);
					if ($parts[1] === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') $returnValue = 'The supplied hash indicates an empty file.';
					else $returnValue = true;
				} else {
					$returnValue = 'Checksum has invalid length or format. Please double check the value or select "other" for a type.';
				}
				break;
			case 'ip-src':
				$parts = explode("/", $value);
				// [0] = the ip
				// [1] = the network address
				if (count($parts) <= 2 ) {
					// ipv4 and ipv6 matching
					if (filter_var($parts[0],FILTER_VALIDATE_IP)) {
						// ip is validated, now check if we have a valid network mask
						if (empty($parts[1])) {
							$returnValue = true;
						} else {
							if (is_numeric($parts[1]) && $parts[1] < 129) {
								$returnValue = true;
							}
						}
					}
				}
				if (!$returnValue) {
					$returnValue = 'IP address has invalid format. Please double check the value or select "other" for a type.';
				}
				break;
			case 'ip-dst':
				$parts = explode("/", $value);
				// [0] = the ip
				// [1] = the network address
				if (count($parts) <= 2 ) {
					// ipv4 and ipv6 matching
					if (filter_var($parts[0],FILTER_VALIDATE_IP)) {
						// ip is validated, now check if we have a valid network mask
						if (empty($parts[1])) {
							$returnValue = true;
						} else {
							if (is_numeric($parts[1]) && $parts[1] < 129) {
								$returnValue = true;
							}
						}
					}
				}
				if (!$returnValue) {
					$returnValue = 'IP address has invalid format. Please double check the value or select "other" for a type.';
				}
				break;
			case 'hostname':
			case 'domain':
				if (preg_match("#^[A-Z0-9.\-_]+\.[A-Z]{2,}$#i", $value)) {
					$returnValue = true;
				} else {
					$returnValue = 'Domain name has invalid format. Please double check the value or select "other" for a type.';
				}
				break;
			case 'email-src':
				// we don't use the native function to prevent issues with partial email addresses
				if (preg_match("#^[A-Z0-9._%+-]*@[A-Z0-9.\-_]+\.[A-Z]{2,}$#i", $value)) {
					$returnValue = true;
				} else {
					$returnValue = 'Email address has invalid format. Please double check the value or select "other" for a type.';
				}
				break;
			case 'email-dst':
				// we don't use the native function to prevent issues with partial email addresses
				if (preg_match("#^[A-Z0-9._%+-]*@[A-Z0-9.\-_]+\.[A-Z]{2,}$#i", $value)) {
					$returnValue = true;
				} else {
					$returnValue = 'Email address has invalid format. Please double check the value or select "other" for a type.';
				}
				break;
			case 'email-subject':
				// no newline
				if (!preg_match("#\n#", $value)) {
					$returnValue = true;
				}
				break;
			case 'email-attachment':
				// no newline
				if (!preg_match("#\n#", $value)) {
					$returnValue = true;
				}
				break;
			case 'url':
				// no newline
				if (!preg_match("#\n#", $value)) {
					$returnValue = true;
				}
				break;
			case 'user-agent':
				// no newline
				if (!preg_match("#\n#", $value)) {
					$returnValue = true;
				}
				break;
			case 'regkey':
				// no newline
				if (!preg_match("#\n#", $value)) {
					$returnValue = true;
				}
				break;
			case 'regkey|value':
				// no newline
				if (preg_match("#(.)+\|(.)+#", $value) && !preg_match("#\n#", $value)) {
					$returnValue = true;
				}
				break;
			case 'vulnerability':
				if (preg_match("#^(CVE-)[0-9]{4}(-)[0-9]{4,6}$#", $value)) {
					$returnValue = true;
				} else {
					$returnValue = 'Invalid format. Expected: CVE-xxxx-xxxx.';
				}
				break;
			case 'named pipe':
				if (!preg_match("#\n#", $value)) {
					$returnValue = true;
				}
				break;
			case 'mutex':
			case 'AS':
			case 'snort':
			case 'pattern-in-file':
			case 'pattern-in-traffic':
			case 'pattern-in-memory':
			case 'yara':
			case 'attachment':
			case 'malware-sample':
				$returnValue = true;
				break;
			case 'link':
				if (preg_match('#^(http|ftp)(s)?\:\/\/((([a-z|0-9|\-]{1,25})(\.)?){2,7})($|/.*$)#i', $value) && !preg_match("#\n#", $value)) {
					$returnValue = true;
				}
				break;
			case 'comment':
			case 'text':
			case 'other':
				$returnValue = true;
				break;
 			case 'target-user':
 				// no newline
 				if (!preg_match("#\n#", $value)) {
 					$returnValue = true;
 				}
 				break;
 			case 'target-email':
 				if (preg_match("#^[A-Z0-9._%+-]*@[A-Z0-9.-]+\.[A-Z]{2,4}$#i", $value)) {
 					$returnValue = true;
 				} else {
 					$returnValue = 'Email address has invalid format. Please double check the value or select "other" for a type.';
 				}
 				break;
 			case 'target-machine':
 				// no newline
 				if (!preg_match("#\n#", $value)) {
 					$returnValue = true;
 				}
 				break;
 			case 'target-org':
 				// no newline
 				if (!preg_match("#\n#", $value)) {
 					$returnValue = true;
 				}
 				break;
 			case 'target-location':
 				// no newline
 				if (!preg_match("#\n#", $value)) {
 					$returnValue = true;
 				}
 				break;
 			case 'target-external':
 				// no newline
 				if (!preg_match("#\n#", $value)) {
 					$returnValue = true;
 				}
		}
		return $returnValue;
	}

	public function getCompositeTypes() {
		// build the list of composite Attribute.type dynamically by checking if type contains a |
		// default composite types
		$compositeTypes = array('malware-sample');	// TODO hardcoded composite
		// dynamically generated list
		foreach (array_keys($this->typeDefinitions) as $type) {
			$pieces = explode('|', $type);
			if (2 == count($pieces)) {
				$compositeTypes[] = $type;
			}
		}
		return $compositeTypes;
	}

	public function isOwnedByOrg($attributeid, $org) {
		$this->id = $attributeid;
		$this->read();
		return $this->data['Event']['org'] === $org;
	}

	public function getRelatedAttributes($attribute, $fields=array()) {
		// LATER getRelatedAttributes($attribute) this might become a performance bottleneck

		// exclude these specific categories to be linked
		switch ($attribute['category']) {
			case 'Antivirus detection':
				return null;
		}
		// exclude these specific types to be linked
		switch ($attribute['type']) {
			case 'other':
			case 'comment':
				return null;
		}

		// prepare the conditions
		$conditions = array(
				'Attribute.event_id !=' => $attribute['event_id'],
				//'Attribute.type' => $attribute['type'],  // do not filter on type
				);
		if (empty($attribute['value1'])) {	// prevent issues with empty fields
			return null;
		}

		if (empty($attribute['value2'])) {
			// no value2, only search for value 1
			$conditions['OR'] = array(
					'Attribute.value1' => $attribute['value1'],
					'Attribute.value2' => $attribute['value1'],
			);
		} else {
			// value2 also set, so search for both
			$conditions['AND'] = array( // TODO was OR
					'Attribute.value1' => array($attribute['value1'],$attribute['value2']),
					'Attribute.value2' => array($attribute['value1'],$attribute['value2']),
			);
		}

		// do the search
		if (empty($fields)) {
			$fields = array('Attribute.*');
		}
		$similarEvents = $this->find('all',array('conditions' => $conditions,
												'fields' => $fields,
												'recursive' => 0,
												'group' => array('Attribute.event_id'),
												'order' => 'Attribute.event_id DESC', )
		);
		return $similarEvents;
	}

	public function typeIsMalware($type) {
		if (in_array($type, $this->zippedDefinitions)) {
			return true;
		} else {
			return false;
		}
	}

	public function typeIsAttachment($type) {
		if ((in_array($type, $this->zippedDefinitions)) || (in_array($type, $this->uploadDefinitions))) {
			return true;
		} else {
			return false;
		}
	}

	public function base64EncodeAttachment($attribute) {
		$filepath = APP . "files" . DS . $attribute['event_id'] . DS . $attribute['id'];
		$file = new File($filepath);
		if (!$file->exists()) {
			return '';
		}
		$content = $file->read();
		return base64_encode($content);
	}

	public function saveBase64EncodedAttachment($attribute) {
		$rootDir = APP . DS . "files" . DS . $attribute['event_id'];
		$dir = new Folder($rootDir, true);						// create directory structure
		$destpath = $rootDir . DS . $attribute['id'];
		$file = new File ($destpath, true);						// create the file
		$decodedData = base64_decode($attribute['data']);		// decode
		if ($file->write($decodedData)) {						// save the data
			return true;
		} else {
			// error
			return false;
		}
	}

/**
 * add_attachment method
 *
 * @return void
 */
	public function uploadAttachment($fileP, $realFileName, $malware, $eventId = null, $category = null, $extraPath = '', $fullFileName = '', $dist, $fromGFI = false) {
		// Check if there were problems with the file upload
		// only keep the last part of the filename, this should prevent directory attacks
		$filename = basename($fileP);
		$tmpfile = new File($fileP);

		// save the file-info in the database
		$this->create();
		$this->data['Attribute']['event_id'] = $eventId;
		$this->data['Attribute']['distribution'] = $dist;
		if ($malware) {
			$md5 = !$tmpfile->size() ? md5_file($fileP) : $tmpfile->md5();
			$this->data['Attribute']['category'] = $category ? $category : "Payload delivery";
			$this->data['Attribute']['type'] = "malware-sample";
			$this->data['Attribute']['value'] = $fullFileName ? $fullFileName . '|' . $md5 : $filename . '|' . $md5; // TODO gives problems with bigger files
			$this->data['Attribute']['to_ids'] = 1; // LATER let user choose to send this to IDS
			if ($fromGFI)$this->data['Attribute']['comment'] = 'GFI import';
		} else {
			$this->data['Attribute']['category'] = $category ? $category : "Artifacts dropped";
			$this->data['Attribute']['type'] = "attachment";
			$this->data['Attribute']['value'] = $fullFileName ? $fullFileName : $realFileName;
			$this->data['Attribute']['to_ids'] = 0;
			if ($fromGFI)$this->data['Attribute']['comment'] = 'GFI import';
		}

		//???
		if ($this->save($this->data)) {
			// attribute saved correctly in the db
		} else {
			// do some?
		}

		// no errors in file upload, entry already in db, now move the file where needed and zip it if required.
		// no sanitization is required on the filename, path or type as we save
		// create directory structure
		// ???
		$rootDir = APP . "files" . DS . $eventId;
		
		$dir = new Folder($rootDir, true);
		// move the file to the correct location
		$destpath = $rootDir . DS . $this->getId(); // id of the new attribute in the database
		$file = new File ($destpath);
		$zipfile = new File ($destpath . '.zip');
		$fileInZip = new File($rootDir . DS . $extraPath . $filename); // FIXME do sanitization of the filename

		// zip and password protect the malware files
		if ($malware) {
			// TODO check if CakePHP has no easy/safe wrapper to execute commands
			$execRetval = '';
			$execOutput = array();
			exec("zip -j -P infected " . $zipfile->path . ' \'' . addslashes($fileInZip->path) . '\'', $execOutput, $execRetval);
			if ($execRetval != 0) { // not EXIT_SUCCESS
				// do some?
			};
			$fileInZip->delete(); // delete the original not-zipped-file
			rename($zipfile->path, $file->path); // rename the .zip to .nothing
		} else {
			$fileAttach = new File($fileP);
			rename($fileAttach->path, $file->path);
		}
	}

	public function __beforeSaveCorrelation($a) {

		// (update-only) clean up the relation of the old value: remove the existing relations related to that attribute, we DO have a reference, the id
		// ==> DELETE FROM correlations WHERE 1_attribute_id = $a_id OR attribute_id = $a_id; */
		// first check if it's an update
		if (isset($a['id'])) {
			$this->Correlation = ClassRegistry::init('Correlation');
			// FIXME : check that $a['id'] is checked correctly so that the user can't remove attributes he shouldn't
			$dummy = $this->Correlation->deleteAll(array('OR' => array(
					'Correlation.1_attribute_id' => $a['id'],
					'Correlation.attribute_id' => $a['id']))
			);
		}
	}

	public function __afterSaveCorrelation($a) {
		// Don't do any correlation if the type is a non correlating type
		if (!in_array($a['type'], $this->nonCorrelatingTypes)) {
			$event = $this->Event->find('first', array(
					'recursive' => -1,
					'fields' => array('Event.distribution', 'Event.id', 'Event.info', 'Event.org', 'Event.date'),
					'conditions' => array('id' => $a['event_id'])
			));
			$this->Correlation = ClassRegistry::init('Correlation');
			$correlations = array();
			$fields = array('value1', 'value2');
			$correlatingValues = array($a['value1']);
			if (!empty($a['value2'])) $correlatingValues[] = $a['value2'];
			foreach ($correlatingValues as $k => $cV) {
				$correlatingAttributes[$k] = $this->find('all', array(
						'conditions' => array(
							'OR' => array(
								'Attribute.value1' => $cV,
								'Attribute.value2' => $cV
							),
							'AND' => array(
								'Attribute.type !=' => $this->nonCorrelatingTypes,
								'Attribute.id !=' => $a['id'],
								'Attribute.event_id !=' => $a['event_id']
							),
						),
						'recursive => -1',
						'fields' => array('Attribute.event_id', 'Attribute.id', 'Attribute.distribution'),
						'contain' => array('Event' => array('fields' => array('Event.id', 'Event.date', 'Event.info', 'Event.org', 'Event.distribution'))),
				));
			}
			$correlations = array();
			foreach ($correlatingAttributes as $k => $cA) {
				foreach ($cA as $corr) {
					$correlations[] = array(
							'value' => $correlatingValues[$k],
							'1_event_id' => $event['Event']['id'],
							'1_attribute_id' => $a['id'],
							'event_id' => $corr['Attribute']['event_id'],
							'attribute_id' => $corr['Attribute']['id'],
							'org' => $corr['Event']['org'],
							'private' => ($corr['Attribute']['distribution'] == 0 || $corr['Event']['distribution'] == 0) ? true : false,
							'date' => $corr['Event']['date'],
							'info' => $corr['Event']['info'],
					);
					$correlations[] = array(
							'value' => $correlatingValues[$k],
							'1_event_id' => $corr['Event']['id'],
							'1_attribute_id' => $corr['Attribute']['id'],
							'event_id' => $a['event_id'],
							'attribute_id' => $a['id'],
							'org' => $event['Event']['org'],
							'private' => ($a['distribution'] == 0 || $event['Event']['distribution'] == 0) ? true : false,
							'date' => $event['Event']['date'],
							'info' => $event['Event']['info'],
					);
				}
			}
			$this->Correlation->saveMany($correlations);
		}
	}

	private function __beforeDeleteCorrelation($attribute_id) {
		$this->Correlation = ClassRegistry::init('Correlation');
		// When we remove an attribute we need to
		// - remove the existing relations related to that attribute, we DO have an id reference
		// ==> DELETE FROM correlations WHERE 1_attribute_id = $a_id OR attribute_id = $a_id;
		$dummy = $this->Correlation->deleteAll(array('OR' => array(
						'Correlation.1_attribute_id' => $attribute_id,
						'Correlation.attribute_id' => $attribute_id))
		);
	}

	public function uploadAttributeToServer($attribute, $server, $HttpSocket=null) {
		$newLocation = $this->restfullAttributeToServer($attribute, $server, null, $HttpSocket);
		if (is_string($newLocation)) { // HTTP/1.1 302 Found and Location: http://<newLocation>
			$newTextBody = $this->restfullAttributeToServer($attribute, $server, $newLocation, $HttpSocket);
		}
		return true;
	}

/**
 * Uploads the attribute to another Server
 * TODO move this to a component
 *
 * @return bool true if success, error message if failed
 */
	public function restfullAttributeToServer($attribute, $server, $urlPath, $HttpSocket=null) {
		// do not keep attributes that are private
		if (0 == $attribute['distribution']) { // never upload private events
			return "Attribute is private and non exportable";
		}

		$url = $server['Server']['url'];
		$authkey = $server['Server']['authkey'];
		if (null == $HttpSocket) {
			App::uses('SyncTool', 'Tools');
			$syncTool = new SyncTool();
			$HttpSocket = $syncTool->setupHttpSocket($server);
		}
		$request = array(
				'header' => array(
						'Authorization' => $authkey,
						'Accept' => 'application/xml',
						'Content-Type' => 'application/xml',
						//'Connection' => 'keep-alive' // LATER followup cakephp ticket 2854 about this problem http://cakephp.lighthouseapp.com/projects/42648-cakephp/tickets/2854
				)
		);
		$uri = isset($urlPath) ? $urlPath : $url . '/attributes';

		// LATER try to do this using a separate EventsController and renderAs() function
		$xmlArray = array();

		// cleanup the array from things we do not want to expose
		//unset($event['Event']['org']);
		// remove value1 and value2 from the output
		unset($attribute['value1']);
		unset($attribute['value2']);
		// also add the encoded attachment
		if ($this->typeIsAttachment($attribute['type'])) {
			$encodedFile = $this->base64EncodeAttachment($attribute);
			$attribute['data'] = $encodedFile;
		}

		// display the XML to the user
		$xmlArray['Attribute'] = $attribute;
		$xmlObject = Xml::fromArray($xmlArray, array('format' => 'tags'));
		$attributesXml = $xmlObject->asXML();
		// do a REST POST request with the server
		$data = $attributesXml;
		// LATER validate HTTPS SSL certificate
		$this->Dns = ClassRegistry::init('Dns');
		if ($this->Dns->testipaddress(parse_url($uri, PHP_URL_HOST))) {
			// TODO NETWORK for now do not know how to catch the following..
			// TODO NETWORK No route to host
			$response = $HttpSocket->post($uri, $data, $request);
			switch ($response->code) {
				case '200':	// 200 (OK) + entity-action-result
					if ($response->isOk()) {
						return isset($urlPath) ? $response->body() : true;
					} else {
						try {
							// parse the XML response and keep the reason why it failed
							$xmlArray = Xml::toArray(Xml::build($response->body));
						} catch (XmlException $e) {
							return true;
						}
						if (strpos($xmlArray['response']['name'], "Attribute already exists")) {	// strpos, so i can piggyback some value if needed.
							return true;
						} else {
							return $xmlArray['response']['name'];
						}
					}
					break;
				case '302': // Found
				case '404': // Not Found
					return isset($urlPath) ? $response->body() : $response->headers['Location'];
					break;
			}
		}
	}

/**
 * Deletes the attribute from another Server
 * TODO move this to a component
 *
 * @return bool true if success, error message if failed
 */
	public function deleteAttributeFromServer($uuid, $server, $HttpSocket = null) {
		$url = $server['Server']['url'];
		$authkey = $server['Server']['authkey'];
		if (null == $HttpSocket) {
			App::uses('SyncTool', 'Tools');
			$syncTool = new SyncTool();
			$HttpSocket = $syncTool->setupHttpSocket($server);
		}
		$request = array(
				'header' => array(
						'Authorization' => $authkey,
						'Accept' => 'application/xml',
						'Content-Type' => 'application/xml',
						//'Connection' => 'keep-alive' // LATER followup cakephp ticket 2854 about this problem http://cakephp.lighthouseapp.com/projects/42648-cakephp/tickets/2854
				)
		);
		$uri = $url . '/attributes/0?uuid=' . $uuid;

		// LATER validate HTTPS SSL certificate
		$this->Dns = ClassRegistry::init('Dns');
		if ($this->Dns->testipaddress(parse_url($uri, PHP_URL_HOST))) {
			// TODO NETWORK for now do not know how to catch the following..
			// TODO NETWORK No route to host
			$response = $HttpSocket->delete($uri, array(), $request);
			// TODO REST, DELETE, no responce needed
		}
	}

	public function checkComposites() {
		$compositeTypes = $this->getCompositeTypes();
		$fails = array();
		$attributes = $this->find('all', array('recursive' => 0));

		foreach ($attributes as $attribute) {
			if ((in_array($attribute['Attribute']['type'], $compositeTypes)) && (!strlen($attribute['Attribute']['value1']) || !strlen($attribute['Attribute']['value2']))) {
				$fails[] = $attribute['Attribute']['event_id'] . ':' . $attribute['Attribute']['id'];
			}
		}
		return $fails;
	}
	
	public function hids($isSiteAdmin, $org ,$type, $tags = '', $from = false, $to = false, $last = false) {
		if (empty($org)) throw new MethodNotAllowedException('No org supplied.');
		// check if it's a valid type
		if ($type != 'md5' && $type != 'sha1' && $type != 'sha256') {
			throw new UnauthorizedException('Invalid hash type.');
		}
		$typeArray = array($type, 'filename|' . $type);
		if ($type == 'md5') $typeArray[] = 'malware-sample';
		$rules = array();
		$eventIds = $this->Event->fetchEventIds($org, $isSiteAdmin, $from, $to, $last);
		if ($tags !== '') {
			$tag = ClassRegistry::init('Tag');
			$args = $this->dissectArgs($tags);
			$tagArray = $tag->fetchEventTagIds($args[0], $args[1]);
			if (!empty($tagArray[0])) {
				foreach ($eventIds as $k => $v) {
					if (!in_array($v['Event']['id'], $tagArray[0])) unset($eventIds[$k]);
				}
			}
			if (!empty($tagArray[1])) {
				foreach ($eventIds as $k => $v) {
					if (in_array($v['Event']['id'], $tagArray[1])) unset($eventIds[$k]);
				}
			}
		}
		$continue = false;
		foreach ($eventIds as $event) {
			//restricting to non-private or same org if the user is not a site-admin.
			$conditions['AND'] = array('Attribute.to_ids' => 1, 'Event.published' => 1, 'Attribute.type' => $typeArray, 'Attribute.event_id' => $event['Event']['id']);
			if (!$isSiteAdmin && ($org !== $event['Event']['org'])) $conditions['AND']['Attribute.distribution >'] = 0; 
			$params = array(
					'conditions' => $conditions, //array of conditions
					'recursive' => 0, //int
					'fields' => array('Attribute.type', 'Attribute.value1', 'Attribute.value2'),
					'group' => array('Attribute.type', 'Attribute.value1'), //fields to GROUP BY
			);
			$items = $this->find('all', $params);
			App::uses('HidsExport', 'Export');
			$export = new HidsExport();
			$rules = array_merge($rules, $export->export($items, strtoupper($type), $continue));
			$continue = true;
		}
		return $rules;
	}
	
	public function nids($isSiteAdmin, $org, $format, $sid, $id = false, $continue = false, $tags = false, $from = false, $to = false, $last = false) {
		if (empty($org)) throw new MethodNotAllowedException('No org supplied.');
		//restricting to non-private or same org if the user is not a site-admin.

		$eventIds = $this->Event->fetchEventIds($org, $isSiteAdmin, $from, $to, $last);
		if ($tags !== '') {
			$tag = ClassRegistry::init('Tag');
			$args = $this->dissectArgs($tags);
			$tagArray = $tag->fetchEventTagIds($args[0], $args[1]);
			if ($id) {
				foreach ($eventIds as $k => $v) {
					if ($v['Event']['id'] !== $id) unset($eventIds[$k]);
				}
			}
			if (!empty($tagArray[0])) {
				foreach ($eventIds as $k => $v) {
					if (!in_array($v['Event']['id'], $tagArray[0])) unset($eventIds[$k]);
				}
			}
			if (!empty($tagArray[1])) {
				foreach ($eventIds as $k => $v) {
					if (in_array($v['Event']['id'], $tagArray[1])) unset($eventIds[$k]);
				}
			}
		}

		if ($format == 'suricata') App::uses('NidsSuricataExport', 'Export');
		else App::uses('NidsSnortExport', 'Export');
		
		$rules = array();
		foreach ($eventIds as $event) {
			$conditions['AND'] = array('Attribute.to_ids' => 1, "Event.published" => 1, 'Attribute.event_id' => $event['Event']['id']);
			$valid_types = array('ip-dst', 'ip-src', 'email-src', 'email-dst', 'email-subject', 'email-attachment', 'domain', 'hostname', 'url', 'user-agent', 'snort');
			$conditions['AND']['Attribute.type'] = $valid_types;
			if (!$isSiteAdmin && ($org !== $event['Event']['org'])) $conditions['AND']['Attribute.distribution >'] = 0; 
			$params = array(
					'conditions' => $conditions, //array of conditions
					'recursive' => 0, //int
					'group' => array('Attribute.type', 'Attribute.value1'), //fields to GROUP BY
			);
			unset($this->virtualFields['category_order']);  // not needed for IDS export and speeds things up
			$items = $this->find('all', $params);
			
			// export depending of the requested type
			switch ($format) {
				case 'suricata':
					$export = new NidsSuricataExport();
					break;
				case 'snort':
					$export = new NidsSnortExport();
					break;
			}
			$rules = array_merge($rules, $export->export($items, $sid, $format, $continue));
			// Only pre-pend the comments once
			$continue = true;
		}
		return $rules;
	}

	 public function text($org, $isSiteAdmin, $type, $tags = false, $eventId = false, $allowNonIDS = false, $from = false, $to = false, $last = false) {
	 	//restricting to non-private or same org if the user is not a site-admin.
	 	$conditions['AND'] = array();
	 	if ($allowNonIDS === false) $conditions['AND'] = array('Attribute.to_ids =' => 1, 'Event.published =' => 1);
	 	if ($type !== 'all') $conditions['AND']['Attribute.type'] = $type; 
	 	if ($from) $conditions['AND']['Event.date >='] = $from;
	 	if ($to) $conditions['AND']['Event.date <='] = $to;
	 	if ($last) $conditions['AND']['Event.publish_timestamp >='] = $last;
	 	if (!$isSiteAdmin) {
	 		$temp = array();
	 		$distribution = array();
	 		array_push($temp, array('Attribute.distribution >' => 0));
	 		array_push($temp, array('(SELECT events.org FROM events WHERE events.id = Attribute.event_id) LIKE' => $org));
	 		$conditions['OR'] = $temp;
	 	}
	 	if ($eventId !== false) {
	 		$conditions['AND'][] = array('Event.id' => $eventId);
	 	} elseif ($tags !== false) {
	 		// If we sent any tags along, load the associated tag names for each attribute
	 		$tag = ClassRegistry::init('Tag');
	 		$args = $this->dissectArgs($tags);
	 		$tagArray = $tag->fetchEventTagIds($args[0], $args[1]);
	 		$temp = array();
	 		foreach ($tagArray[0] as $accepted) {
	 			$temp['OR'][] = array('Event.id' => $accepted);
	 		}
	 		$conditions['AND'][] = $temp;
	 		$temp = array();
	 		foreach ($tagArray[1] as $rejected) {
	 			$temp['AND'][] = array('Event.id !=' => $rejected);
	 		}
	 		$conditions['AND'][] = $temp;
	 	}
	 	
	 	$params = array(
	 			'conditions' => $conditions, //array of conditions
	 			//'recursive' => 2, //int
	 			//'fields' => array('Attribute.value'), //array of field names
	 			'order' => array('Attribute.value'), //string or array defining order
	 			'group' => array('Attribute.value'), //fields to GROUP BY
	 			'contain' => array('Event' => array(
	 					'fields' => array('Event.id', 'Event.published', 'Event.date', 'Event.publish_timestamp'),
	 	
	 			)));
	 	$attributes = $this->find('all', $params);
	 	return $attributes;
	 }
	 
	 public function rpz($org, $isSiteAdmin, $tags = false, $eventId = false, $from = false, $to = false) {
	 	// we can group hostname and domain as well as ip-src and ip-dst in this case
	 	$conditions['AND'] = array('Attribute.to_ids' => 1, 'Event.published' => 1);
	 	$typesToFetch = array('ip' => array('ip-src', 'ip-dst'), 'domain' => array('domain'), 'hostname' => array('hostname'));
	 	if ($from) $conditions['AND']['Event.date >='] = $from;
	 	if ($to) $conditions['AND']['Event.date <='] = $to;
	 	if (!$isSiteAdmin) {
	 		$temp = array();
	 		$distribution = array();
	 		array_push($temp, array('Attribute.distribution >' => 0));
	 		array_push($temp, array('(SELECT events.org FROM events WHERE events.id = Attribute.event_id) LIKE' => $org));
	 		$conditions['OR'] = $temp;
	 	}
	 	if ($eventId !== false) {
	 		$conditions['AND'][] = array('Event.id' => $eventId);
	 	} elseif ($tags !== false) {
	 		// If we sent any tags along, load the associated tag names for each attribute
	 		$tag = ClassRegistry::init('Tag');
	 		$args = $this->dissectArgs($tags);
	 		$tagArray = $tag->fetchEventTagIds($args[0], $args[1]);
	 		$temp = array();
	 		foreach ($tagArray[0] as $accepted) {
	 			$temp['OR'][] = array('Event.id' => $accepted);
	 		}
	 		$conditions['AND'][] = $temp;
	 		$temp = array();
	 		foreach ($tagArray[1] as $rejected) {
	 			$temp['AND'][] = array('Event.id !=' => $rejected);
	 		}
	 		$conditions['AND'][] = $temp;
	 	}
	 	$values = array();
	 	foreach ($typesToFetch as $k => $v) {
	 		$params = array(
 				'conditions' => array('AND' => 
 					$conditions,
 					array('type' => $v),
 				),
 				'fields' => array('Attribute.value'), //array of field names
 				'order' => array('Attribute.value'), //string or array defining order
 				'group' => array('Attribute.value'), //fields to GROUP BY
 				);
	 		$temp = $this->find('all', $params);
	 		if ($k == 'hostname') {
	 			foreach ($temp as $value) {
	 				$found = false;
	 				foreach ($values['domain'] as $domain) {
	 					if (strpos($value['Attribute']['value'], $domain) != 0) { 
	 						$found = true;
	 					}
	 				}
	 				if (!$found) $values[$k][] = $value['Attribute']['value'];
	 			}
	 		} else foreach ($temp as $value) $values[$k][] = $value['Attribute']['value'];
	 		unset($temp);
	 	}
	 	return $values;
	 }
	 
	 public function generateCorrelation() {
	 	$this->Correlation = ClassRegistry::init('Correlation');
	 	$this->Correlation->deleteAll(array('id !=' => ''), false);
	 	$fields = array('Attribute.id', 'Attribute.event_id', 'Attribute.distribution', 'Attribute.type', 'Attribute.category', 'Attribute.value1', 'Attribute.value2');
	 	// get all attributes..
	 	$attributes = $this->find('all', array('recursive' => -1, 'fields' => $fields));
	 	// for all attributes..
	 	foreach ($attributes as $k => $attribute) {
	 		$this->__afterSaveCorrelation($attribute['Attribute']);
	 	}
	 	return $k;
	 }
	 
	 public function reportValidationIssuesAttributes($eventId) {
	 	$conditions = array();
	 	if ($eventId && is_numeric($eventId)) $conditions = array('event_id' => $eventId);
	 
	 	// get all attributes..
	 	$attributes = $this->find('all', array('recursive' => -1, 'fields' => array('id'), 'conditions' => $conditions));
	 	// for all attributes..
	 	$result = array();
	 	$i = 0;
	 	foreach ($attributes as $a) {
	 		$attribute = $this->find('first', array('recursive' => -1, 'conditions' => array('id' => $a['Attribute']['id'])));
	 		$this->set($attribute);
	 		if ($this->validates()) {
	 			// validates
	 		} else {
	 			$errors = $this->validationErrors;
	 			$result[$i]['id'] = $attribute['Attribute']['id'];
	 			// print_r
	 			$result[$i]['error'] = array();
	 			foreach ($errors as $field => $error) {
	 				$result[$i]['error'][$field] = array('value' => $attribute['Attribute'][$field], 'error' => $error[0]); 
	 			}
	 			$result[$i]['details'] = 'Event ID: [' . $attribute['Attribute']['event_id'] . "] - Category: [" . $attribute['Attribute']['category'] . "] - Type: [" . $attribute['Attribute']['type'] . "] - Value: [" . $attribute['Attribute']['value'] . ']';
	 			$i++;
	 		}
	 	}
	 	return $result;
	 }
	 
	 // This method takes a string from an argument with several elements (separated by '&&' and negated by '!') and returns 2 arrays
	 // array 1 will have all of the non negated terms and array 2 all the negated terms
	 public function dissectArgs($args) {
	 	if (!$args) return array(null, null);
	 	if (is_array($args)) {
	 		$argArray = $args;
	 	} else {
	 		$argArray = explode('&&', $args);
	 	}
	 	$accept = $reject = $result = array();
	 	$reject = array();
	 	foreach ($argArray as $arg) {
	 		if (substr($arg, 0, 1) == '!') {
	 			$reject[] = substr($arg, 1);
	 		} else {
	 			$accept[] = $arg;
	 		}
	 	}
	 	$result[0] = $accept;
	 	$result[1] = $reject;
	 	return $result;
	 }
	 
	 public function checkForValidationIssues($attribute) {
	 	$this->set($attribute);
	 	if ($this->validates()) {
	 		return false;
	 	} else {
	 		return $this->validationErrors;
	 	}
	 }
	 
	 
	 public function checkTemplateAttributes($template, &$data, $event_id, $distribution) {
		 $result = array();
		 $errors = array();
		 $attributes = array();
		 $files = array();
		 $savedFiles = array();
		 if (isset($data['Template']['fileArray'])) $fileArray = json_decode($data['Template']['fileArray'], true);
		 foreach ($template['TemplateElement'] as $element) {
		 	if ($element['element_definition'] == 'attribute') {
		 		$result = $this->__resolveElementAttribute($element['TemplateElementAttribute'][0], $data['Template']['value_' . $element['id']]);
		 	} else if ($element['element_definition'] == 'file') {
		 		$temp = array();
		 		if (isset($fileArray)) {
			 		foreach ($fileArray as $fileArrayElement) {
			 			if ($fileArrayElement['element_id'] == $element['id']) {
			 				$temp[] = $fileArrayElement;
			 			}
			 		}
		 		}
		 		$result = $this->__resolveElementFile($element['TemplateElementFile'][0], $temp);
		 		if ($element['TemplateElementFile'][0]['mandatory'] && empty($temp) && empty($errors[$element['id']])) $errors[$element['id']] = 'This field is mandatory.';
		 	}
		 	if ($element['element_definition'] == 'file' || $element['element_definition'] == 'attribute') {
		 		if ($result['errors']) {
		 			$errors[$element['id']] = $result['errors'];
		 		} else {
		 			foreach ($result['attributes'] as &$a) {
		 				$a['event_id'] = $event_id;
		 				$a['distribution'] = $distribution;
		 				$test = $this->checkForValidationIssues(array('Attribute' => $a));
		 				if ($test) {
		 					foreach ($test['value'] as $e) {
		 						$errors[$element['id']] = $e;
		 					}
		 				} else {
		 					$attributes[] = $a;
		 				}
		 			}
		 		}
			}
		 }
		 return array('attributes' => $attributes, 'errors' => $errors);
	 }
	 

	private function __resolveElementAttribute($element, $value) {
		$attributes = array();
		$results = array();
		$errors=null;
		if (!empty($value)) {
				if ($element['batch']) {
				$values = explode("\n", $value);
				foreach ($values as $v) {
					$v = trim($v);
					$attributes[] = $this->__createAttribute($element, $v);
				}
			} else {
				$attributes[] = $this->__createAttribute($element, trim($value));
			}
			foreach ($attributes as $att) {
				if (isset($att['multi'])) {
					foreach ($att['multi'] as $a) {
						$results[] = $a;
					}
				} else {
					$results[] = $att;
				}
			}
		} else {
			if ($element['mandatory']) $errors = 'This field is mandatory.';
		}
		return array('attributes' => $results, 'errors' => $errors);
	}
	 
	private function __resolveElementFile($element, $files) {
		$attributes = array();
		$errors = null;
		$results = array();
		$count = count($files);
		$element['complex'] = false;
		if ($element['malware']) {
			$element['type'] = 'malware-sample';
			$element['to_ids'] = true;
		} else {
			$element['type'] = 'attachment';
			$element['to_ids'] = false;
		}
		foreach ($files as $file) {	
			if (!preg_match('@^[\w\-. ]+$@', $file['filename'])) {
				$errors = 'Filename not allowed.';
				continue;
			}
			if ($element['malware']) {
				$malwareName = $file['filename'] . '|' . hash_file('md5', APP . 'tmp/files/' . $file['tmp_name']);
				$tmp_file = new File(APP . 'tmp/files/' . $file['tmp_name']);
				if (!$tmp_file->exists()) {
					$errors = 'File cannot be read.';
				} else {
					$element['type'] = 'malware-sample';
					$attributes[] = $this->__createAttribute($element, $malwareName);
					$content = $tmp_file->read();
					$attributes[count($attributes) - 1]['data'] = $file['tmp_name'];
					$element['type'] = 'filename|sha256';
					$sha256 = $file['filename'] . '|' . (hash_file('sha256', APP . 'tmp/files/' . $file['tmp_name']));
					$attributes[] = $this->__createAttribute($element, $sha256);
					$element['type'] = 'filename|sha1';
					$sha1 = $file['filename'] . '|' . (hash_file('sha1', APP . 'tmp/files/' . $file['tmp_name']));
					$attributes[] = $this->__createAttribute($element, $sha1);
				}
			} else {
				$attributes[] = $this->__createAttribute($element, $file['filename']);
				$tmp_file = new File(APP . 'tmp/files/' . $file['tmp_name']);
				if (!$tmp_file->exists()) {
				$errors = 'File cannot be read.';
				} else {
					$content = $tmp_file->read();
					$attributes[count($attributes) - 1]['data'] = $file['tmp_name'];
				}
			}
		}
		return array('attributes' => $attributes, 'errors' => $errors, 'files' => $files);
	}

	private function __createAttribute($element, $value) {
		$attribute = array(
				'comment' => $element['name'],
				'to_ids' => $element['to_ids'],
				'category' => $element['category'],
				'value' => $value,
		);
		if ($element['complex']) {
			App::uses('ComplexTypeTool', 'Tools');
			$complexTypeTool = new ComplexTypeTool();
			$result = $complexTypeTool->checkComplexRouter($value, ucfirst($element['type']));
			if (isset($result['multi'])) {
				$temp = $attribute;
				$attribute = array();
				foreach($result['multi'] as $k => $r) {
					$attribute['multi'][] = $temp;
					$attribute['multi'][$k]['type'] = $r['type'];
					$attribute['multi'][$k]['value'] = $r['value'];
				}
			} else if ($result != false) {
				$attribute['type'] = $result['type'];
				$attribute['value'] = $result['value'];
			} else {
				return false;
			}
		} else {
			$attribute['type'] = $element['type'];
		}
		return $attribute;
	}
	
	// get and converts the contents of a file passed along as a base64 encoded string with the original filename into a zip archive
	// The zip archive is then passed back as a base64 encoded string along with the md5 hash and a flag whether the transaction was successful
	// The archive is password protected using the "infected" password
	// The contents of the archive will be the actual sample, named <md5> and the original filename in a text file named <md5>.filename.txt
	public function handleMaliciousBase64($event_id, $original_filename, $base64, $hash_types) {
		if (!is_numeric($event_id)) throw new Exception('Something went wrong. Received a non numeric event ID while trying to create a zip archive of an uploaded malware sample.');
		$dir = new Folder(APP . "files" . DS . $event_id, true);
		$tmpFile = new File($dir->path . DS . $this->generateRandomFileName(), true, 0600);
		$tmpFile->write(base64_decode($base64));
		$hashes = array();
		foreach ($hash_types as $hash) {
			$hashes[$hash] = $this->__hashRouter($hash, $tmpFile->path);
		}
		$contentsFile = new File($dir->path . DS . $hashes['md5']);
		rename($tmpFile->path, $contentsFile->path);
		$fileNameFile = new File($dir->path . DS . $hashes['md5'] . '.filename.txt');
		$fileNameFile->write($original_filename);
		$fileNameFile->close();
		$zipFile = new File($dir->path . DS . $hashes['md5'] . '.zip');
		exec('zip -j -P infected "' . addslashes($zipFile->path) . '" "' . addslashes($contentsFile->path) . '" "' . addslashes($fileNameFile->path) . '"', $execOutput, $execRetval);
		if ($execRetval != 0) $result = array('success' => false);
		else $result = array_merge(array('data' => base64_encode($zipFile->read()), 'success' => true), $hashes);
		$fileNameFile->delete();
		$zipFile->delete();
		$contentsFile->delete();
		return $result;
	}
	
	private function __hashRouter($hashType, $file) {
		$validHashes = array('md5', 'sha1', 'sha256');
		if (!in_array($hashType, $validHashes)) return false;
		switch ($hashType) {
			case 'md5':
			case 'sha1':
			case 'sha256':
				return hash_file($hashType, $file);
				break;
		}
	}
	
	public function generateRandomFileName() {
		$length = 12;
		$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
		$charLen = strlen($characters) - 1;
		$fn = '';
		for ($p = 0; $p < $length; $p++) {
			$fn .= $characters[rand(0, $charLen)];
		}
		return $fn;
	}
	
	public function resolveHashType($hash) {
		$hashTypes = $this->hashTypes;
		$validTypes = array();
		$length = strlen($hash);
		foreach ($hashTypes as $k => $hashType) {
			$temp = $hashType['lowerCase'] ? strtolower($hash) : $hash;
			if ($hashType['length'] == $length && preg_match($hashType['pattern'], $temp)) $validTypes[] = $k;
		}
		return $validTypes;
	}
}
