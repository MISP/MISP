<?php

App::uses('AppModel', 'Model');
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');

/**
 * Attribute Model
 *
 * @property Event $Event
 */
class ShadowAttribute extends AppModel {

	public $combinedKeys = array('event_id', 'category', 'type');

	public $name = 'ShadowAttribute';				// TODO general

	public $actsAs = array(
		'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
			'userModel' => 'User',
			'userKey' => 'user_id',
			'change' => 'full'),
		'Trim',
		'Containable',
		'Regexp' => array('fields' => array('value', 'value2')),
	);

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

/**
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
			'value' => 'IF (ShadowAttribute.value2="", ShadowAttribute.value1, CONCAT(ShadowAttribute.value1, "|", ShadowAttribute.value2))',
			'category_order' => 'IF (ShadowAttribute.category="Internal reference", "a",
			IF (ShadowAttribute.category="Antivirus detection", "b",
			IF (ShadowAttribute.category="Payload delivery", "c",
			IF (ShadowAttribute.category="Payload installation", "d",
			IF (ShadowAttribute.category="Artifacts dropped", "e",
			IF (ShadowAttribute.category="Persistence mechanism", "f",
			IF (ShadowAttribute.category="Network activity", "g",
			IF (ShadowAttribute.category="Payload type", "h",
			IF (ShadowAttribute.category="Attribution", "i",
			IF (ShadowAttribute.category="Attribution", "j",
			IF (ShadowAttribute.category="External analysis", "k", "l")))))))))))'
	); // TODO hardcoded

/**
 * Field Descriptions
 * explanations of certain fields to be used in various views
 *
 * @var array
 */
	public $fieldDescriptions = array(
			'signature' => array('desc' => 'Is this attribute eligible to automatically create an IDS signature (network IDS or host IDS) out of it ?'),
			//'private' => array('desc' => 'Prevents upload of this single Attribute to other CyDefSIG servers', 'formdesc' => 'Prevents upload of <em>this single Attribute</em> to other CyDefSIG servers.<br/>Used only when the Event is NOT set as Private')
	);

	// if these then a category my have upload to be zipped

	public $zippedDefinitions = array(
			'malware-sample'
	);

	// if these then a category my have upload

	public $uploadDefinitions = array(
			'attachment'
	);

	public $typeDefinitions = array(
			'md5' => array('desc' => 'A checksum in md5 format', 'formdesc' => "You are encouraged to use filename|md5 instead. <br/>A checksum in md5 format, only use this if you don't know the correct filename"),
			'sha1' => array('desc' => 'A checksum in sha1 format', 'formdesc' => "You are encouraged to use filename|sha1 instead. <br/>A checksum in sha1 format, only use this if you don't know the correct filename"),
            'sha256' => array('desc' => 'A checksum in sha256 format', 'formdesc' => "You are encouraged to use filename|sha256 instead. A checksum in sha256 format, o nly use this if you don't know the correct filename"),
			'filename' => array('desc' => 'Filename'),
			'filename|md5' => array('desc' => 'A filename and an md5 hash separated by a |', 'formdesc' => "A filename and an md5 hash separated by a | (no spaces)"),
			'filename|sha1' => array('desc' => 'A filename and an sha1 hash separated by a |', 'formdesc' => "A filename and an sha1 hash separated by a | (no spaces)"),
			'ip-src' => array('desc' => "A source IP address of the attacker"),
			'ip-dst' => array('desc' => 'A destination IP address of the attacker or C&C server', 'formdesc' => "A destination IP address of the attacker or C&C server. <br/>Also set the IDS flag on when this IP is hardcoded in malware"),
			'hostname' => array('desc' => 'A full host/dnsname of an attacker', 'formdesc' => "A full host/dnsname of an attacker. <br/>Also set the IDS flag on when this hostname is hardcoded in malware"),
			'domain' => array('desc' => 'A domain name used in the malware', 'formdesc' => "A domain name used in the malware. <br/>Use this instead of hostname when the upper domain is <br/>important or can be used to create links between events."),
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
			'snort' => array('desc' => 'An IDS rule in Snort rule-format', 'formdesc' => "An IDS rule in Snort rule-format. <br/>This rule will be automatically rewritten in the NIDS exports."),
			'pattern-in-file' => array('desc' => 'Pattern in file that identifies the malware'),
			'pattern-in-traffic' => array('desc' => 'Pattern in network traffic that identifies the malware'),
			'pattern-in-memory' => array('desc' => 'Pattern in memory dump that identifies the malware'),
			'yara' => array('desc' => 'Yara signature'),
			'vulnerability' => array('desc' => 'A reference to the vulnerability used in the exploit'),
			'attachment' => array('desc' => 'Attachment with external information', 'formdesc' => "Please upload files using the <em>Upload Attachment</em> button."),
			'malware-sample' => array('desc' => 'Attachment containing encrypted malware sample', 'formdesc' => "Please upload files using the <em>Upload Attachment</em> button."),
			'link' => array('desc' => 'Link to an external information'),
			'comment' => array('desc' => 'Comment or description in a human language', 'formdesc' => 'Comment or description in a human language. <br/> This will not be correlated with other attributes (NOT IMPLEMENTED YET)'),
			'text' => array('desc' => 'Name, ID or a reference'),
            'named pipe' => array('desc' => 'Named pipe, use the format \\.\pipe\<PipeName>'),
            'mutex' => array('desc' => 'Mutex, use the format \BaseNamedObjects\<Mutex>'),
			'other' => array('desc' => 'Other attribute'),
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
					'formdesc' => 'List of anti-virus vendors detecting the malware or information on detection performance (e.g. 13/43 or 67%).<br/>Attachment with list of detection or link to VirusTotal could be placed here as well.',
					'types' => array('link', 'comment', 'text', 'attachment', 'other')
					),
			'Payload delivery' => array(
					'desc' => 'Information about how the malware is delivered',
					'formdesc' => 'Information about the way the malware payload is initially delivered, <br/>for example information about the email or web-site, vulnerability used, originating IP etc. <br/>Malware sample itself should be attached here.',
					'types' => array('md5', 'sha1', 'sha256', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha256', 'ip-src', 'ip-dst', 'hostname', 'domain', 'email-src', 'email-dst', 'email-subject', 'email-attachment', 'url', 'ip-dst', 'user-agent', 'http-method',  'AS', 'pattern-in-file', 'pattern-in-traffic', 'yara', 'attachment', 'malware-sample', 'link', 'comment', 'text', 'vulnerability', 'other')
					),
			'Artifacts dropped' => array(
					'desc' => 'Any artifact (files, registry keys etc.) dropped by the malware or other modifications to the system',
					'types' => array('md5', 'sha1', 'sha256', 'filename', 'filename|md5', 'filename|sha256', 'filename|sha1', 'regkey', 'regkey|value', 'pattern-in-file', 'pattern-in-memory', 'yara', 'attachment', 'malware-sample', 'comment', 'text', 'other', 'named pipe', 'mutex')
					),
			'Payload installation' => array(
					'desc' => 'Info on where the malware gets installed in the system',
					'formdesc' => 'Location where the payload was placed in the system and the way it was installed.<br/>For example, a filename|md5 type attribute can be added here like this:<br/>c:\\windows\\system32\\malicious.exe|41d8cd98f00b204e9800998ecf8427e.',
					'types' => array('md5', 'sha1', 'sha256', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha256', 'pattern-in-file', 'pattern-in-traffic', 'pattern-in-memory', 'yara', 'vulnerability', 'attachment', 'malware-sample', 'comment', 'text', 'other')
					),
			'Persistence mechanism' => array(
					'desc' => 'Mechanisms used by the malware to start at boot',
					'formdesc' => 'Mechanisms used by the malware to start at boot.<br/>This could be a registry key, legitimate driver modification, LNK file in startup',
					'types' => array('filename', 'regkey', 'regkey|value', 'comment', 'text', 'other')
					),
			'Network activity' => array(
					'desc' => 'Information about network traffic generated by the malware',
					'types' => array('ip-src', 'ip-dst', 'hostname', 'domain', 'email-dst', 'url', 'user-agent', 'http-method','AS', 'snort', 'pattern-in-file', 'pattern-in-traffic', 'attachment', 'comment', 'text', 'other')
					),
			'Payload type' => array(
					'desc' => 'Information about the final payload(s)',
					'formdesc' => 'Information about the final payload(s).<br/>Can contain a function of the payload, e.g. keylogger, RAT, or a name if identified, such as Poison Ivy.',
					'types' => array('comment', 'text', 'other')
					),
			'Attribution' => array(
					'desc' => 'Identification of the group, organisation, or country behind the attack',
					'types' => array('comment', 'text', 'other')
					),
			'External analysis' => array(
					'desc' => 'Any other result from additional analysis of the malware like tools output',
					'formdesc' => 'Any other result from additional analysis of the malware like tools output<br/>Examples: pdf-parser output, automated sandbox analysis, reverse engineering report.',
					'types' => array('md5', 'sha1', 'sha256', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha256', 'ip-src', 'ip-dst', 'hostname', 'domain', 'url', 'user-agent', 'http-method', 'regkey', 'regkey|value', 'AS', 'snort', 'pattern-in-file', 'pattern-in-traffic', 'pattern-in-memory', 'vulnerability', 'attachment', 'malware-sample', 'link', 'comment', 'text', 'other')
					),
			'Other' => array(
					'desc' => 'Attributes that are not part of any other category',
					'types' => array('comment', 'text', 'other')
					)
	);

	public $order = array("ShadowAttribute.event_id" => "DESC", "ShadowAttribute.type" => "ASC");

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
	);

	public function __construct($id = false, $table = null, $ds = null) {
		parent::__construct($id, $table, $ds);
		$this->virtualFields = Set::merge($this->virtualFields,array(
			//'distribution' => 'IF (Attribute.private=true, "Your organization only", IF (Attribute.cluster=true, "This Community-only", "All communities"))',
			//'distribution' => 'IF (ShadowAttribute.private=true AND ShadowAttribute.cluster=false, "Your organization only", IF (ShadowAttribute.private=true AND ShadowAttribute.cluster=true, "This server-only", IF (ShadowAttribute.private=false AND ShadowAttribute.cluster=true, "This Community-only", IF (ShadowAttribute.communitie=true, "Connected communities" , "All communities"))))',
		));
		$this->fieldDescriptions = Set::merge($this->fieldDescriptions,array(
			//'distribution' => array('desc' => 'This fields indicates the intended distribution of the attribute (same as when adding an event, see Add Event)'),
		));
	}

	//The Associations below have been created with all possible keys, those that are not needed can be removed


/**
 * beforeSave
 *
 * @throws InternalErrorException
 * @return bool always true
 */
	public function beforeSave($options = array()) {

		// explode value of composite type in value1 and value2
		// or copy value to value1 if not composite type
		if (!empty($this->data['ShadowAttribute']['type'])) {
			$compositeTypes = $this->getCompositeTypes();
			// explode composite types in value1 and value2
			//if (!isset($this->data['ShadowAttribute']['value1'])) {
			$pieces = explode('|', $this->data['ShadowAttribute']['value']);
			if (in_array($this->data['ShadowAttribute']['type'], $compositeTypes)) {
				if (2 != count($pieces)) {
					throw new InternalErrorException('Composite type, but value not explodable');
				}
				$this->data['ShadowAttribute']['value1'] = $pieces[0];
				$this->data['ShadowAttribute']['value2'] = $pieces[1];
			} else {
				$total = implode('|', $pieces);
				$this->data['ShadowAttribute']['value1'] = $total;
				$this->data['ShadowAttribute']['value2'] = '';
			}
		}
		// always return true after a beforeSave()
		return true;
	}

	public function afterSave($created, $options = array()) {

		$result = true;
		// if the 'data' field is set on the $this->data then save the data to the correct file
		if (isset($this->data['ShadowAttribute']['type']) && $this->typeIsAttachment($this->data['ShadowAttribute']['type']) && !empty($this->data['ShadowAttribute']['data'])) {
			$result = $result && $this->saveBase64EncodedAttachment($this->data['ShadowAttribute']);
		}
		return $result;
	}

	public function beforeDelete($cascade = true) {
		// delete attachments from the disk
		$this->read(); // first read the attribute from the db
		if ($this->typeIsAttachment($this->data['ShadowAttribute']['type'])) {
			// FIXME secure this filesystem access/delete by not allowing to change directories or go outside of the directory container.
			// only delete the file if it exists
			$filepath = APP . "files" . DS . $this->data['ShadowAttribute']['event_id'] . DS . 'shadow' . DS . $this->data['ShadowAttribute']['id'];
			$file = new File ($filepath);
			if ($file->exists()) {
				if (!$file->delete()) {
					throw new InternalErrorException('Delete of file attachment failed. Please report to administrator.');
				}
			}
		}
	}

	public function beforeValidate($options = array()) {
		parent::beforeValidate();
		// remove leading and trailing blanks
		//$this->trimStringFields(); // TODO
		if (isset($this->data['ShadowAttribute']['value'])) $this->data['ShadowAttribute']['value'] = trim($this->data['ShadowAttribute']['value']);

		if (!isset($this->data['ShadowAttribute']['type'])) {
			return false;
		}

		switch($this->data['ShadowAttribute']['type']) {
			// lowercase these things
			case 'md5':
			case 'sha1':
			case 'domain':
			case 'hostname':
				$this->data['ShadowAttribute']['value'] = strtolower($this->data['ShadowAttribute']['value']);
				break;
			case 'filename|md5':
			case 'filename|sha1':
				$pieces = explode('|', $this->data['ShadowAttribute']['value']);
				$this->data['ShadowAttribute']['value'] = $pieces[0] . '|' . strtolower($pieces[1]);
				break;
		}

		// generate UUID if it doesn't exist
		if (empty($this->data['ShadowAttribute']['uuid'])) {
			$this->data['ShadowAttribute']['uuid'] = String::uuid();
		}

		// always return true, otherwise the object cannot be saved
		return true;
	}

	public function validateTypeValue($fields) {
		$category = $this->data['ShadowAttribute']['category'];
		if (isset($this->categoryDefinitions[$category]['types'])) {
			return in_array($fields['type'], $this->categoryDefinitions[$category]['types']);
		}
		return false;
	}

	public function validateAttributeValue($fields) {
		$value = $fields['value'];
		$returnValue = false;

		// check data validation
		switch($this->data['ShadowAttribute']['type']) {
			case 'md5':
				if (preg_match("#^[0-9a-f]{32}$#", $value)) {
					$returnValue = true;
				} else {
					$returnValue = 'Checksum has invalid length or format. Please double check the value or select "other" for a type.';
				}
				break;
			case 'sha1':
				if (preg_match("#^[0-9a-f]{40}$#", $value)) {
					$returnValue = true;
				} else {
					$returnValue = 'Checksum has invalid length or format. Please double check the value or select "other" for a type.';
				}
				break;
			case 'sha256':
				if (preg_match("#^[0-9a-f]{64}$#", $value)) {
					$returnValue = true;
				} else {
					$returnValue = 'Checksum has invalid length or format. Please double check the value or select "other" for a type.';
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
					$returnValue = true;
				} else {
					$returnValue = 'Checksum has invalid length or format. Please double check the value or select "other" for a type.';
				}
				break;
			case 'filename|sha1':
				// no newline
				if (preg_match("#^.+\|[0-9a-f]{40}$#", $value)) {
					$returnValue = true;
				} else {
					$returnValue = 'Checksum has invalid length or format. Please double check the value or select "other" for a type.';
				}
				break;
			case 'filename|sha256':
				// no newline
				if (preg_match("#^.+\|[0-9a-f]{64}$#", $value)) {
					$returnValue = true;
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
			case 'named pipe':
				if (!preg_match("#\n#", $value)) {
					$returnValue = true;
				}
				break;
			case 'hostname':
			case 'domain':
				if (preg_match("#^[A-Z0-9.-]+\.[A-Z]{2,4}$#i", $value)) {
					$returnValue = true;
				} else {
					$returnValue = 'Domain name has invalid format. Please double check the value or select "other" for a type.';
				}
				break;
			case 'email-src':
				// we don't use the native function to prevent issues with partial email addresses
				if (preg_match("#^[A-Z0-9._%+-]*@[A-Z0-9.-]+\.[A-Z]{2,4}$#i", $value)) {
					$returnValue = true;
				} else {
					$returnValue = 'Email address has invalid format. Please double check the value or select "other" for a type.';
				}
				break;
			case 'email-dst':
				// we don't use the native function to prevent issues with partial email addresses
				if (preg_match("#^[A-Z0-9._%+-]*@[A-Z0-9.-]+\.[A-Z]{2,4}$#i", $value)) {
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
	public function uploadAttachment($fileP, $realFileName, $malware, $eventId = null, $category = null, $extraPath = '', $fullFileName = '') {
		// Check if there were problems with the file upload
		// only keep the last part of the filename, this should prevent directory attacks
		$filename = basename($fileP);
		$tmpfile = new File($fileP);

		// save the file-info in the database
		$this->create();
		$this->data['ShadowAttribute']['event_id'] = $eventId;
		if ($malware) {
			$md5 = !$tmpfile->size() ? md5_file($fileP) : $tmpfile->md5();
			$this->data['ShadowAttribute']['category'] = $category ? $category : "Payload delivery";
			$this->data['ShadowAttribute']['type'] = "malware-sample";
			$this->data['ShadowAttribute']['value'] = $fullFileName ? $fullFileName . '|' . $md5 : $filename . '|' . $md5; // TODO gives problems with bigger files
			$this->data['ShadowAttribute']['to_ids'] = 1; // LATER let user choose to send this to IDS
		} else {
			$this->data['ShadowAttribute']['category'] = $category ? $category : "Artifacts dropped";
			$this->data['ShadowAttribute']['type'] = "attachment";
			$this->data['ShadowAttribute']['value'] = $fullFileName ? $fullFileName : $realFileName;
			$this->data['ShadowAttribute']['to_ids'] = 0;
		}

		if ($this->save($this->data)) {
			// attribute saved correctly in the db
		} else {
			// do some?
		}

		// no errors in file upload, entry already in db, now move the file where needed and zip it if required.
		// no sanitization is required on the filename, path or type as we save
		// create directory structure
		if (PHP_OS == 'WINNT') {
			$rootDir = APP . "files" . DS . $eventId;
		} else {
			$rootDir = APP . "files" . DS . $eventId;
		}
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
			exec("zip -j -P infected " . $zipfile->path . ' "' . addslashes($fileInZip->path) . '"', $execOutput, $execRetval);
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

	public function checkComposites() {
		$compositeTypes = $this->getCompositeTypes();
		$fails = array();
		$attributes = $this->find('all', array('recursive' => 0));

		foreach ($attributes as $attribute) {
			if ((in_array($attribute['ShadowAttribute']['type'], $compositeTypes)) && (!strlen($attribute['ShadowAttribute']['value1']) || !strlen($attribute['ShadowAttribute']['value2']))) {
				$fails[] = $attribute['ShadowAttribute']['event_id'] . ':' . $attribute['ShadowAttribute']['id'];
			}
		}
		return $fails;
	}
}

