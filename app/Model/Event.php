<?php
App::uses('AppModel', 'Model');
App::uses('CakeEmail', 'Network/Email');
App::import('Controller', 'Attributes');
Configure::load('config'); // This is needed to load GnuPG.bodyonlyencrypted
/**
 * Event Model
 *
 * @property User $User
 * @property Attribute $Attribute
 */
class Event extends AppModel {

	public $actsAs = array(
		'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
			'userModel' => 'User',
			'userKey' => 'user_id',
			'change' => 'full'),
		'Trim',
		'Containable',
	);

/**
 * Display field
 *
 * @var string
 */
	public $displayField = 'id';

	public $virtualFields = array();

	public $mispVersion = '2.4.0';

/**
 * Description field
 *
 * @var array
 */
	public $fieldDescriptions = array(
		'threat_level_id' => array('desc' => 'Risk levels: *low* means mass-malware, *medium* means APT malware, *high* means sophisticated APT malware or 0-day attack', 'formdesc' => 'Risk levels: low: mass-malware medium: APT malware high: sophisticated APT malware or 0-day attack'),
		'classification' => array('desc' => 'Set the Traffic Light Protocol classification. <ol><li><em>TLP:AMBER</em>- Share only within the organization on a need-to-know basis</li><li><em>TLP:GREEN:NeedToKnow</em>- Share within your constituency on the need-to-know basis.</li><li><em>TLP:GREEN</em>- Share within your constituency.</li></ol>'),
		'submittedgfi' => array('desc' => 'GFI sandbox: export upload', 'formdesc' => 'GFI sandbox: export upload'),
		'submittedioc' => array('desc' => '', 'formdesc' => ''),
		'analysis' => array('desc' => 'Analysis Levels: *Initial* means the event has just been created, *Ongoing* means that the event is being populated, *Complete* means that the event\'s creation is complete', 'formdesc' => 'Analysis levels: Initial: event has been started Ongoing: event population is in progress Complete: event creation has finished'),
		'distribution' => array('desc' => 'Describes who will have access to the event.')
	);

	public $analysisDescriptions = array(
		0 => array('desc' => '*Initial* means the event has just been created', 'formdesc' => 'Creation started'),
		1 => array('desc' => '*Ongoing* means that the event is being populated', 'formdesc' => 'Creation ongoing'),
		2 => array('desc' => '*Complete* means that the event\'s creation is complete', 'formdesc' => 'Creation complete')
	);

	public $distributionDescriptions = array(
		0 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "This setting will only allow members of your organisation on this server to see it."),
		1 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "Users that are part of your MISP community will be able to see the event. This includes your own organisation, organisations on this MISP server and organisations running MISP servers that synchronise with this server. Any other organisations connected to such linked servers will be restricted from seeing the event. Use this option if you are on the central hub of this community."), // former Community
		2 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "Users that are part of your MISP community will be able to see the event. This includes all organisations on this MISP server, all organisations on MISP servers synchronising with this server and the hosting organisations of servers that connect to those afore mentioned servers (so basically any server that is 2 hops away from this one). Any other organisations connected to linked servers that are 2 hops away from this will be restricted from seeing the event. Use this option if this server isn't the central MISP hub of the community but is connected to it."),
		3 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "This will share the event with all MISP communities, allowing the event to be freely propagated from one server to the next."),
		4 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "This distribution of this event will be handled by the selected sharing group."),

	);

	public $analysisLevels = array(
		0 => 'Initial', 1 => 'Ongoing', 2 => 'Completed'
	);

	public $distributionLevels = array(
		0 => 'Your organisation only', 1 => 'This community only', 2 => 'Connected communities', 3 => 'All communities', 4 => 'Sharing group'
	);

	public $shortDist = array(0 => 'Organisation', 1 => 'Community', 2 => 'Connected', 3 => 'All', 4 => ' sharing Group');

	public $export_types = array(
			'xml' => array(
					'extension' => '.xml',
					'type' => 'XML',
					'description' => 'Click this to download all events and attributes that you have access to <small>(except file attachments)</small> in a custom XML format.',
			),
			'csv_sig' => array(
					'extension' => '.csv',
					'type' => 'CSV_Sig',
					'description' => 'Click this to download all attributes that are indicators and that you have access to <small>(except file attachments)</small> in CSV format.',
			),
			'csv_all' => array(
					'extension' => '.csv',
					'type' => 'CSV_All',
					'description' => 'Click this to download all attributes that you have access to <small>(except file attachments)</small> in CSV format.',
			),
			'suricata' => array(
					'extension' => '.rules',
					'type' => 'Suricata',
					'description' => 'Click this to download all network related attributes that you have access to under the Suricata rule format. Only published events and attributes marked as IDS Signature are exported. Administration is able to maintain a whitelist containing host, domain name and IP numbers to exclude from the NIDS export.',
			),
			'snort' => array(
					'extension' => '.rules',
					'type' => 'Snort',
					'description' => 'Click this to download all network related attributes that you have access to under the Snort rule format. Only published events and attributes marked as IDS Signature are exported. Administration is able to maintain a whitelist containing host, domain name and IP numbers to exclude from the NIDS export.',
			),
			'rpz' => array(
					'extension' => '.txt',
					'type' => 'RPZ',
					'description' => 'Click this to download an RPZ Zone file generated from all ip-src/ip-dst, hostname, domain attributes. This can be useful for DNS level firewalling. Only published events and attributes marked as IDS Signature are exported.'
			),
			'md5' => array(
					'extension' => '.txt',
					'type' => 'MD5',
					'description' => 'Click on one of these two buttons to download all MD5 checksums contained in file-related attributes. This list can be used to feed forensic software when searching for susipicious files. Only published events and attributes marked as IDS Signature are exported.',
			),
			'sha1' => array(
					'extension' => '.txt',
					'type' => 'SHA1',
					'description' => 'Click on one of these two buttons to download all SHA1 checksums contained in file-related attributes. This list can be used to feed forensic software when searching for susipicious files. Only published events and attributes marked as IDS Signature are exported.',
			),
			'text' => array(
					'extension' => '.txt',
					'type' => 'TEXT',
					'description' => 'Click on one of the buttons below to download all the attributes with the matching type. This list can be used to feed forensic software when searching for susipicious files. Only published events and attributes marked as IDS Signature are exported.'
			),
	);

	public $csv_event_context_fields_to_fetch = array(
		'event_info' => array('object' => false, 'var' => 'info'),
		'event_member_org' => array('object' => 'Org', 'var' => 'name'),
		'event_source_org' => array('object' => 'Orgc', 'var' => 'name'),
		'event_distribution' => array('object' => false, 'var' => 'distribution'),
		'event_threat_level_id' => array('object' => 'ThreatLevel', 'var' => 'name'),
		'event_analysis' => array('object' => false, 'var' => 'analysis'),
		'event_date' => array('object' => false, 'var' => 'date'),
		'event_tag' => array('object' => 'Tag', 'var' => 'name')
	);

/**
 * Validation rules
 *
 * @var array
 */
	public $validate = array(
		'org_id' => array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
			),
			'numeric' => array(
				'rule' => array('numeric'),
			),
		),
		'orgc_id' => array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
			),
			'numeric' => array(
					'rule' => array('numeric'),
			),
		),
		'date' => array(
			'date' => array(
				'rule' => array('date'),
				'message' => 'Expected date format: YYYY-MM-DD',
				//'allowEmpty' => false,
				'required' => true,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
			),
		),
		'threat_level_id' => array(
			'rule' => array('inList', array('1', '2', '3', '4')),
			'message' => 'Options : 1, 2, 3, 4 (for High, Medium, Low, Undefined)',
			'required' => true
		),

		'distribution' => array(
			'not_empty_if_sg' => array(
				'rule' => array('inList', array('0', '1', '2', '3', '4')),
				'message' => 'Options : Your organisation only, This community only, Connected communities, All communities',
				//'allowEmpty' => false,
				'required' => true,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
				)
		),

		'sharing_group_id' => array(
			'rule' => array('sharingGroupRequired'),
				'message' => 'If the distribution is set to "Sharing Group", a sharing group has to be selected.',
				//'required' => true,
				//'allowEmpty' => true
		),

		'analysis' => array(
			'rule' => array('inList', array('0', '1', '2')),
				'message' => 'Options : 0, 1, 2 (for Initial, Ongoing, Completed)',
				//'allowEmpty' => false,
				'required' => true,
				//'last' => false, // Stop validation after this rule
				//'on' => 'create', // Limit validation to 'create' or 'update' operations
		),
		'info' => array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
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
	);

	public function __construct($id = false, $table = null, $ds = null) {
		parent::__construct($id, $table, $ds);
	}

	// The Associations below have been created with all possible keys, those that are not needed can be removed

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
		),
		'ThreatLevel' => array(
			'className' => 'ThreatLevel',
			'foreignKey' => 'threat_level_id'
		),
		'Org' => array(
				'className' => 'Organisation',
				'foreignKey' => 'org_id'
		),
		'Orgc' => array(
				'className' => 'Organisation',
				'foreignKey' => 'orgc_id'
		),
		'SharingGroup' => array(
				'className' => 'SharingGroup',
				'foreignKey' => 'sharing_group_id'
		)
	);

/**
 * hasMany associations
 *
 * @var array
 *
 * @throws InternalErrorException // TODO Exception
 */
	public $hasMany = array(
		'Attribute' => array(
			'className' => 'Attribute',
			'foreignKey' => 'event_id',
			'dependent' => true,	// cascade deletes
			'conditions' => '',
			'fields' => '',
			'order' => array('Attribute.category ASC', 'Attribute.type ASC'),
			'limit' => '',
			'offset' => '',
			'exclusive' => '',
			'finderQuery' => '',
			'counterQuery' => ''
		),
		'ShadowAttribute' => array(
			'className' => 'ShadowAttribute',
			'foreignKey' => 'event_id',
			'dependent' => true,	// cascade deletes
			'conditions' => '',
			'fields' => '',
			'order' => array('ShadowAttribute.old_id DESC', 'ShadowAttribute.old_id DESC'),
			'limit' => '',
			'offset' => '',
			'exclusive' => '',
			'finderQuery' => '',
			'counterQuery' => ''
		),
		'EventTag' => array(
			'className' => 'EventTag',
			'dependent' => true,
		)
	);

	public function beforeDelete($cascade = true) {
		// blacklist the event UUID if the feature is enabled
		if (Configure::read('MISP.enableEventBlacklisting')) {
			$this->EventBlacklist = ClassRegistry::init('EventBlacklist');
			$this->EventBlacklist->create();
			$orgc = $this->Orgc->find('first', array('conditions' => array('Orgc.id' => $this->data['Event']['orgc_id']), 'recursive' => -1, 'fields' => array('Orgc.name')));
			$this->EventBlacklist->save(array('event_uuid' => $this->data['Event']['uuid'], 'event_info' => $this->data['Event']['info'], 'event_orgc' => $orgc['Orgc']['name']));
		}

		// delete all of the event->tag combinations that involve the deleted event
		$this->EventTag->deleteAll(array('event_id' => $this->id));

		// only delete the file if it exists
		$filepath = APP . "files" . DS . $this->id;
		App::uses('Folder', 'Utility');
		if (is_dir($filepath)) {
			if (!$this->destroyDir($filepath)) {
				throw new InternalErrorException('Delete of event file directory failed. Please report to administrator.');
			}
		}
	}

	public function destroyDir($dir) {
	if (!is_dir($dir) || is_link($dir)) return unlink($dir);
		foreach (scandir($dir) as $file) {
			if ($file == '.' || $file == '..') continue;
			if (!$this->destroyDir($dir . DS . $file)) {
				chmod($dir . DS . $file, 0777);
				if (!$this->destroyDir($dir . DS . $file)) return false;
			}
		}
		return rmdir($dir);
	}

	public function beforeValidate($options = array()) {
		parent::beforeValidate();
		// analysis - setting correct vars
		// TODO refactor analysis into an Enum (in the database)
		if (isset($this->data['Event']['analysis'])) {
			switch ($this->data['Event']['analysis']) {
			    case 'Initial':
			        $this->data['Event']['analysis'] = 0;
			        break;
			    case 'Ongoing':
			        $this->data['Event']['analysis'] = 1;
			        break;
			    case 'Completed':
			        $this->data['Event']['analysis'] = 2;
			        break;
			}
		}
		if (!isset($this->data['Event']['threat_level_id'])) $this->data['Event']['threat_level_id'] = Configure::read('MISP.default_event_threat_level') ? Configure::read('MISP.default_event_threat_level') : '1';

		// generate UUID if it doesn't exist
		if (empty($this->data['Event']['uuid'])) {
			$this->data['Event']['uuid'] = $this->generateUuid();
		}
		// generate timestamp if it doesn't exist
		if (empty($this->data['Event']['timestamp'])) {
			$date = new DateTime();
			$this->data['Event']['timestamp'] = $date->getTimestamp();
		}

		if (empty($this->data['Event']['date'])) {
			$this->data['Event']['date'] = date('Y-m-d');
		}

		if (!isset($this->data['Event']['distribution']) || $this->data['Event']['distribution'] != 4) $this->data['Event']['sharing_group_id'] = 0;
	}

	public function afterSave($created, $options = array()) {
		if (!$created) {
			$this->Correlation = ClassRegistry::init('Correlation');
			$db = $this->getDataSource();
			$values = array('id' => $db->value($this->data['Event']['id']));
			$fields = array('info', 'date');
			foreach ($fields as $field) {
				if (isset($this->data['Event'][$field])) {
					$values[$field] = $db->value($this->data['Event'][$field]);
					$this->Correlation->updateAll(array('Correlation.' . $field => $values[$field]), array('Correlation.event_id' => $values['id']));
				}
			}
		}
	}

	public function isOwnedByOrg($eventid, $org) {
		return $this->field('id', array('id' => $eventid, 'org_id' => $org)) === $eventid;
	}

	// gets the logged in user + an array of events, attaches the correlation count to each
	public function attachCorrelationCountToEvents($user, &$events) {
		$sgids = $this->SharingGroup->fetchAllAuthorised($user);
		if (!isset($sgids) || empty($sgids)) $sgids = array(-1);
		$this->Correlation = ClassRegistry::init('Correlation');
		$eventIds = Set::extract('/Event/id', $events);
		$conditionsCorrelation = $this->__buildEventConditionsCorrelation($user, $eventIds, $sgids);
		$correlations = $this->Correlation->find('all',array(
				'fields' => array('Correlation.1_event_id', 'count(distinct(Correlation.event_id)) as count'),
				'conditions' => $conditionsCorrelation,
				'recursive' => -1,
				'group' => array('Correlation.1_event_id'),
		));
		$correlations = Hash::combine($correlations, '{n}.Correlation.1_event_id', '{n}.0.count');
		foreach ($events as &$event) $event['Event']['correlation_count'] = (isset($correlations[$event['Event']['id']])) ? $correlations[$event['Event']['id']] : 0;
	}

	private function __buildEventConditionsCorrelation($user, $eventIds, $sgids) {
		if (!is_array($eventIds)) $eventIds = array($eventIds);
		if (!$user['Role']['perm_site_admin']) {
			$conditionsCorrelation = array(
					'AND' => array(
							'Correlation.1_event_id' => $eventIds,
							array(
									'OR' => array(
											'Correlation.org_id' => $user['org_id'],
											'AND' => array(
													array(
															'OR' => array(
																	array(
																			'AND' => array(
																					'Correlation.distribution >' => 0,
																					'Correlation.distribution <' => 4,
																			),
																	),
																	array(
																			'AND' => array(
																					'Correlation.distribution' => 4,
																					'Correlation.sharing_group_id' => $sgids
																			),
																	),
															),
													),
													array(
															'OR' => array(
																	'Correlation.a_distribution' => 5,
																	array(
																			'AND' => array(
																					'Correlation.a_distribution >' => 0,
																					'Correlation.a_distribution <' => 4,
																			),
																	),
																	array(
																			'AND' => array(
																					'Correlation.a_distribution' => 4,
																					'Correlation.a_sharing_group_id' => $sgids
																			),
																	),
															),
													),
											),
									),
							),
					),
			);
		} else {
			$conditionsCorrelation = array('Correlation.1_event_id' => $eventIds);
		}
		return $conditionsCorrelation;
	}

	public function getRelatedEvents($user, $eventId = null, $sgids) {
		if ($eventId == null) $eventId = $this->data['Event']['id'];
		if (!isset($sgids) || empty($sgids)) $sgids = array(-1);
		$this->Correlation = ClassRegistry::init('Correlation');
		// search the correlation table for the event ids of the related events
		// Rules:
		// 1. Event is owned by the user (org_id matches)
		// 2. User is allowed to see both the event and the org:
		//    a.  Event:
		//        i. Event has a distribution between 1-3 (community only, connected communities, all orgs)
		//        ii. Event has a sharing group that the user is accessible to view
		//    b.  Attribute:
		//        i. Attribute has a distribution of 5 (inheritance of the event, for this the event check has to pass anyway)
		//        ii. Atttibute has a distribution between 1-3 (community only, connected communities, all orgs)
		//        iii. Attribute has a sharing group that the user is accessible to view
		$conditionsCorrelation = $this->__buildEventConditionsCorrelation($user, $eventId, $sgids);
		$correlations = $this->Correlation->find('all',array(
		        'fields' => 'Correlation.event_id',
		        'conditions' => $conditionsCorrelation,
		        'recursive' => 0,
		        'order' => array('Correlation.event_id DESC')));

		$relatedEventIds = array();
		foreach ($correlations as $correlation) {
			$relatedEventIds[] = $correlation['Correlation']['event_id'];
		}
		$relatedEventIds = array_unique($relatedEventIds);
		// now look up the event data for these attributes
		$conditions = array("Event.id" => $relatedEventIds);
		$fields = array('id', 'date', 'threat_level_id', 'info', 'published', 'uuid', 'analysis', 'timestamp', 'distribution', 'org_id', 'orgc_id');
		$orgfields = array('id', 'name', 'uuid');
		$relatedEvents = $this->find('all',
			array('conditions' => $conditions,
				'recursive' => 0,
				'order' => 'Event.date DESC',
				'fields' => $fields,
				'contain' => array(
					'Org' => array(
						'fields' => $orgfields
					),
					'Orgc' => array(
						'fields' => $orgfields
					)
				)
			)
		);
		return $relatedEvents;
	}

	public function getRelatedAttributes($user, $id = null, $sgids, $shadowAttribute = false) {
		$context = $shadowAttribute ? 'ShadowAttribute' : 'Attribute';
		$settings = array(
			'Attribute' => array('model' => 'Attribute', 'correlationModel' => 'Correlation', 'parentIdField' => '1_attribute_id'),
			'ShadowAttribute' => array('model' => 'ShadowAttribute', 'correlationModel' => 'ShadowAttributeCorrelation', 'parentIdField' => '1_shadow_attribute_id')
		);
		if ($id == null) $id = $this->data['Event']['id'];
		if (!isset($sgids) || empty($sgids)) $sgids = array(-1);
		$this->{$settings[$context]['correlationModel']} = ClassRegistry::init($settings[$context]['correlationModel']);
		if (!$user['Role']['perm_site_admin']) {
			$conditionsCorrelation = array(
					'AND' => array(
							$settings[$context]['correlationModel'] . '.1_event_id' => $id,
							array(
									'OR' => array(
											$settings[$context]['correlationModel'] . '.org_id' => $user['org_id'],
											'AND' => array(
													array(
															'OR' => array(
																	array(
																			'AND' => array(
																					$settings[$context]['correlationModel'] . '.distribution >' => 0,
																					$settings[$context]['correlationModel'] . '.distribution <' => 4,
																			),
																	),
																	array(
																			'AND' => array(
																					$settings[$context]['correlationModel'] . '.distribution' => 4,
																					$settings[$context]['correlationModel'] . '.sharing_group_id' => $sgids
																			),
																	),
															),
													),
													array(
															'OR' => array(
																	$settings[$context]['correlationModel'] . '.a_distribution' => 5,
																	array(
																			'AND' => array(
																					$settings[$context]['correlationModel'] . '.a_distribution >' => 0,
																					$settings[$context]['correlationModel'] . '.a_distribution <' => 4,
																			),
																	),
																	array(
																			'AND' => array(
																					$settings[$context]['correlationModel'] . '.a_distribution' => 4,
																					$settings[$context]['correlationModel'] . '.a_sharing_group_id' => $sgids
																			),
																	),
															),
													),
											),
									)
							)

					)
			);
		} else {
			$conditionsCorrelation = array($settings[$context]['correlationModel'] . '.1_event_id' => $id);
		}
		$correlations = $this->{$settings[$context]['correlationModel']}->find('all',array(
				'fields' => $settings[$context]['correlationModel'] . '.*',
				'conditions' => $conditionsCorrelation,
				'recursive' => 0,
				'order' => array($settings[$context]['correlationModel'] . '.event_id DESC')));
		$relatedAttributes = array();
		foreach ($correlations as $correlation) {
			$current = array(
					'id' => $correlation[$settings[$context]['correlationModel']]['event_id'],
					'org_id' => $correlation[$settings[$context]['correlationModel']]['org_id'],
					'info' => $correlation[$settings[$context]['correlationModel']]['info'],
					'value' => $correlation[$settings[$context]['correlationModel']]['value'],
			);
			if (empty($relatedAttributes[$correlation[$settings[$context]['correlationModel']][$settings[$context]['parentIdField']]]) || !in_array($current, $relatedAttributes[$correlation[$settings[$context]['correlationModel']][$settings[$context]['parentIdField']]])) {
				$relatedAttributes[$correlation[$settings[$context]['correlationModel']][$settings[$context]['parentIdField']]][] = $current;
			}
		}
		return $relatedAttributes;
	}

/**
 * Clean up an Event Array that was received by an XML request.
 * The structure needs to be changed a little bit to be compatible with what CakePHP expects
 *
 * This function receives the reference of the variable, so no return is required as it directly
 * modifies the original data.
 *
 * @param &$data a reference to the variable
 *
 * @throws InternalErrorException
 */
	public function cleanupEventArrayFromXML(&$data) {
		$objects = array('Attribute', 'ShadowAttribute');
		foreach ($objects as $object) {
			// Workaround for different structure in XML/array than what CakePHP expects
			if (isset($data['Event'][$object]) && is_array($data['Event'][$object]) && count($data['Event'][$object])) {
				if (!is_numeric(implode(array_keys($data['Event'][$object]), ''))) {
					// single attribute
					$data['Event'][$object] = array(0 => $data['Event'][$object]);
				}
			}
		}
		$objects = array('Org', 'Orgc', 'SharingGroup');
		foreach ($objects as $object) {
			if (isset($data['Event'][$object][0])) $data['Event'][$object] = $data['Event'][$object][0];
		}
		return $data;
	}

	private function __resolveErrorCode($code, &$event, &$server) {
		$error = false;
		switch ($code) {
			case 403:
				return 'The distribution level of this event blocks it from being pushed.';
				break;
			case 405:
				$error = 'The sync user on the remote instance does not have the required privileges to handle this event.';
				break;
		}
		if ($error) {
			$this->Log = ClassRegistry::init('Log');
			$this->Log->create();
			$this->Log->save(array(
					'org' => 'SYSTEM',
					'model' => 'Server',
					'model_id' => $server['Server']['id'],
					'email' => 'SYSTEM',
					'action' => 'warning',
					'user_id' => 0,
					'title' => 'Uploading Event (' . $event['Event']['id'] . ') to Server (' . $server['Server']['id'] . ')',
					'change' => 'Remote instance returned an error, with error code: ' . $code,
			));
		}
		return $error;
	}

	public function uploadEventToServer($event, $server, $HttpSocket = null) {
		$this->Server = ClassRegistry::init('Server');
		$push = $this->Server->checkVersionCompatibility($server['Server']['id']);
		$deletedAttributes = false;
		if (($push['version'][0] > 2) ||
			($push['version'][0] == 2 && $push['version'][1] > 4) ||
			($push['version'][0] == 2 && $push['version'][1] == 4 && $push['version'][2] > 42)) {
			$deletedAttributes = true;
		}
		if (isset($event['Attribute']) && !$deletedAttributes) {
			foreach ($event['Attribute'] as $k => $v) {
				if ($v['deleted']) unset($event['Attribute'][$k]);
			}
			$event['Attribute'] = array_values($event['Attribute']);
		}
		if (!isset($push['canPush']) || !$push['canPush']) {
			if ($push === 'mangle' && $event['Event']['distribution'] != 4) {
				$event['Event']['orgc'] = $event['Orgc']['name'];
				$event['mangle'] = true;
			} else return 'Trying to push to an outdated instance.';
		}
		$updated = null;
		$newLocation = $newTextBody = '';
		$result = $this->restfulEventToServer($event, $server, null, $newLocation, $newTextBody, $HttpSocket);
		if (is_numeric($result)) {
			$error = $this->__resolveErrorCode($result, $event, $server);
			if ($error) return $error . ' Error code: ' . $result;
		}
		if (strlen($newLocation) || $result) { // HTTP/1.1 200 OK or 302 Found and Location: http://<newLocation>
			if (strlen($newLocation)) { // HTTP/1.1 302 Found and Location: http://<newLocation>
				$result = $this->restfulEventToServer($event, $server, $newLocation, $newLocation, $newTextBody, $HttpSocket);
				if (is_numeric($result)) {
					$error = $this->__resolveErrorCode($result, $event, $server);
					if ($error) return $error . ' Error code: ' . $result;
				}
			}
			$uploadFailed = false;
			try { // TODO Xml::build() does not throw the XmlException
				$json = json_decode($newTextBody, true);
			} catch (Exception $e) {
				$uploadFailed = true;
			}
			if (!is_array($json) || $uploadFailed) {
				$this->Log = ClassRegistry::init('Log');
				$this->Log->create();
				$this->Log->save(array(
						'org' => 'SYSTEM',
						'model' => 'Server',
						'model_id' => $server['Server']['id'],
						'email' => 'SYSTEM',
						'action' => 'warning',
						'user_id' => 0,
						'title' => 'Uploading Event (' . $event['Event']['id'] . ') to Server (' . $server['Server']['id'] . ')',
						'change' => 'Returned message: ', $newTextBody,
				));
				return false;
			}
			// get the remote event_id
			foreach ($json as $jsonEvent) {
				if (is_array($jsonEvent)) {
					foreach ($jsonEvent as $key => $value) {
						if ($key == 'id') {
							break;
						}
					}
				} else {
					$this->Log = ClassRegistry::init('Log');
					$this->Log->create();
					$this->Log->save(array(
							'org' => 'SYSTEM',
							'model' => 'Server',
							'model_id' => $server['Server']['id'],
							'email' => 'SYSTEM',
							'action' => 'warning',
							'user_id' => 0,
							'title' => 'Uploading Event (' . $event['Event']['id'] . ') to Server (' . $server['Server']['id'] . ')',
							'change' => 'Returned message: ', $newTextBody,
					));
					return false;
				}
			}
		}
		return 'Success';
	}

/**
 * Uploads the event and the associated Attributes to another Server
 * TODO move this to a component
 *
 * @return bool true if success, false or error message if failed
 */
	public function restfulEventToServer($event, $server, $urlPath, &$newLocation, &$newTextBody, $HttpSocket = null) {
		if ($event['Event']['distribution'] == 4) {
			if (!empty($event['SharingGroup']['SharingGroupServer'])) {
				$found = false;
				foreach ($event['SharingGroup']['SharingGroupServer'] as $sgs) {
					if ($sgs['server_id'] == $server['Server']['id']) $found = true;
				}
				if (!$found) return 403;
			}
		}
		$serverModel = ClassRegistry::init('Server');
		$server = $serverModel->eventFilterPushableServers($event, array($server));
		if (empty($server)) return 403;
		$server = $server[0];
		if ($this->checkDistributionForPush($event, $server, $context = 'Event')) {
			$event = $this->__updateEventForSync($event, $server);
		} else return 403;
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
						'Accept' => 'application/json',
						'Content-Type' => 'application/json',
						//'Connection' => 'keep-alive' // // LATER followup cakephp issue about this problem: https://github.com/cakephp/cakephp/issues/1961
				)
		);
		$uri = $url . '/events';
		if (isset($urlPath)) {
			$pieces = explode('/', $urlPath);
			$uri .= '/' . end($pieces);
		}
		$data = json_encode($event);
		// LATER validate HTTPS SSL certificate
		$this->Dns = ClassRegistry::init('Dns');
		if ($this->Dns->testipaddress(parse_url($uri, PHP_URL_HOST))) {
			// TODO NETWORK for now do not know how to catch the following..
			// TODO NETWORK No route to host
			$response = $HttpSocket->post($uri, $data, $request);
			switch ($response->code) {
				case '200':	// 200 (OK) + entity-action-result
					if ($response->isOk()) {
						$newTextBody = $response->body();
						$newLocation = null;
						return true;
					} else {
						try {
							$jsonArray = json_decode($response->body, true);
						} catch (Exception $e) {
							return true; // TODO should be false
						}
						if (strpos($jsonArray['name'],"Event already exists")) {	// strpos, so i can piggyback some value if needed.
							return true;
						} else {
							return $jsonArray['name'];
						}
					}
					break;
				case '302': // Found
					$newLocation = $response->headers['Location'];
					$newTextBody = $response->body();
					return true;
					break;
				case '404': // Not Found
					$newLocation = $response->headers['Location'];
					$newTextBody = $response->body();
					return 404;
					break;
				case '405':
					return 405;
					break;
				case '403': // Not authorised
					return 403;
					break;
			}
		}
	}

	private function __updateEventForSync($event, $server) {
		$mangle = isset($event['mangle']);
		if (!$mangle) {
			// rearrange things to be compatible with the Xml::fromArray()
			$objectsToRearrange = array('Attribute', 'Orgc', 'SharingGroup', 'EventTag', 'Org', 'ShadowAttribute');
			foreach ($objectsToRearrange as $o) {
				if (isset($event[$o])) {
					$event['Event'][$o] = $event[$o];
					unset($event[$o]);
				}
			}

			// cleanup the array from things we do not want to expose
			foreach (array('Org', 'org_id', 'orgc_id', 'proposal_email_lock', 'org', 'orgc') as $field) unset($event['Event'][$field]);
			foreach ($event['Event']['EventTag'] as $kt => $tag) {
				if (!$tag['Tag']['exportable']) unset($event['Event']['EventTag'][$kt]);
			}

			// Add the local server to the list of instances in the SG
			if (isset($event['Event']['SharingGroup']) && isset($event['Event']['SharingGroup']['SharingGroupServer'])) {
				foreach ($event['Event']['SharingGroup']['SharingGroupServer'] as &$s) {
					if ($s['server_id'] == 0) {
						$s['Server'] = array('id' => 0, 'url' => Configure::read('MISP.baseurl'));
					}
				}
			}
		} else {
			foreach (array('org_id', 'orgc_id', 'proposal_email_lock', 'org') as $field) unset($event['Event'][$field]);
			foreach (array('Org', 'Orgc', 'SharingGroup', 'EventTag') as $field) unset($event[$field]);
		}
		// remove value1 and value2 from the output
		if (isset($event['Event']['Attribute'])) {
			foreach ($event['Event']['Attribute'] as $key => &$attribute) {
			// do not keep attributes that are private, nor cluster
				if ($attribute['distribution'] < 2) {
					unset($event['Event']['Attribute'][$key]);
					continue; // stop processing this
				}
				// Downgrade the attribute from connected communities to community only
				if ($attribute['distribution'] == 2) {
					$attribute['distribution'] = 1;
				}

				// If the attribute has a sharing group attached, make sure it can be transfered
				if ($attribute['distribution'] == 4) {
					if ($this->checkDistributionForPush(array('Attribute' => $attribute), $server, 'Attribute') === false) {
						unset($event['Event']['Attribute'][$key]);
						continue;
					}
					// Add the local server to the list of instances in the SG
					if (isset($attribute['SharingGroup']['SharingGroupServer'])) {
						foreach ($attribute['SharingGroup']['SharingGroupServer'] as &$s) {
							if ($s['server_id'] == 0) {
								$s['Server'] = array('id' => 0, 'url' => Configure::read('MISP.baseurl'));
							}
						}
					}
				}

				// remove value1 and value2 from the output
				unset($attribute['value1']);
				unset($attribute['value2']);
				// also add the encoded attachment
				if ($this->Attribute->typeIsAttachment($attribute['type'])) {
					$encodedFile = $this->Attribute->base64EncodeAttachment($attribute);
					$attribute['data'] = $encodedFile;
				}
				// Passing the attribute ID together with the attribute could cause the deletion of attributes after a publish/push
				// Basically, if the attribute count differed between two instances, and the instance with the lower attribute
				// count pushed, the old attributes with the same ID got overwritten. Unsetting the ID before pushing it
				// solves the issue and a new attribute is always created.
				unset($attribute['id']);
			}
		}

		if ($mangle) {
			$event['Event']['timestamp'] = $event['Event']['timestamp'] -1;
			if (isset($event['Attribute'])) {
				foreach ($event['Attribute'] as $key => &$attribute) {
					$event['Attribute'][$key]['timestamp'] = $event['Attribute'][$key]['timestamp'] -1;
					if ($attribute['distribution'] == 5) $attribute['distribution'] = $event['Event']['distribution'];
					if ($attribute['distribution'] < 2) {
						unset($event['Event']['Attribute'][$key]);
						continue;
					}
					if ($attribute['distribution'] == 2) {
						$attribute['distribution'] = 1;
					}
					unset($event['Attribute'][$key]['SharingGroup'], $event['Attribute'][$key]['sharing_group_id']);
					if ($attribute['distribution'] == 4) {
						unset($event['Event']['Attribute'][$key]);
						continue;
					}
					// remove value1 and value2 from the output
					unset($attribute['value1']);
					unset($attribute['value2']);
					// also add the encoded attachment
					if ($this->Attribute->typeIsAttachment($attribute['type'])) {
						$encodedFile = $this->Attribute->base64EncodeAttachment($attribute);
						$attribute['data'] = $encodedFile;
					}
					unset($attribute['id']);
				}
			}
		}

		// Downgrade the event from connected communities to community only
		if ($event['Event']['distribution'] == 2) {
			$event['Event']['distribution'] = 1;
		}
		return $event;
	}


/**
 * Deletes the event and the associated Attributes from another Server
 * TODO move this to a component
 *
 * @return bool true if success, error message if failed
 */
	public function deleteEventFromServer($uuid, $server, $HttpSocket=null) {
		// TODO private and delete(?)

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
						//'Connection' => 'keep-alive' // // LATER followup cakephp issue about this problem: https://github.com/cakephp/cakephp/issues/1961
				)
		);
		$uri = $url . '/events/0?uuid=' . $uuid;

		// LATER validate HTTPS SSL certificate
		$this->Dns = ClassRegistry::init('Dns');
		if ($this->Dns->testipaddress(parse_url($uri, PHP_URL_HOST))) {
			// TODO NETWORK for now do not know how to catch the following..
			// TODO NETWORK No route to host
			$response = $HttpSocket->delete($uri, array(), $request);
			// TODO REST, DELETE, some responce needed
		}
	}

/**
 * Download a specific event from a Server
 * TODO move this to a component
 * @return array|NULL
 */
	public function downloadEventFromServer($eventId, $server, $HttpSocket=null, $proposalDownload = false) {
		$url = $server['Server']['url'];
		$authkey = $server['Server']['authkey'];
		if (null == $HttpSocket) {
			//$HttpSocket = new HttpSocket(array(
			//		'ssl_verify_peer' => false
			//		));
			App::uses('SyncTool', 'Tools');
			$syncTool = new SyncTool();
			$HttpSocket = $syncTool->setupHttpSocket($server);
		}
		$request = array(
				'header' => array(
						'Authorization' => $authkey,
						'Accept' => 'application/json',
						'Content-Type' => 'application/json',
						//'Connection' => 'keep-alive' // // LATER followup cakephp issue about this problem: https://github.com/cakephp/cakephp/issues/1961
				)
		);
		if (!$proposalDownload) {
			$uri = $url . '/events/view/' . $eventId . '/deleted:true';
		} else {
			$uri = $url . '/shadow_attributes/getProposalsByUuid/' . $eventId;
		}
		$response = $HttpSocket->get($uri, $data = '', $request);
		if ($response->isOk()) {
			return json_decode($response->body, true);
		} else {
			// TODO parse the XML response and keep the reason why it failed
			return null;
		}
	}

	public function downloadProposalsFromServer($uuidList, $server, $HttpSocket = null) {
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
						'Accept' => 'application/json',
						'Content-Type' => 'application/json',
						//'Connection' => 'keep-alive' // LATER followup cakephp issue about this problem: https://github.com/cakephp/cakephp/issues/1961
				)
		);
		$uri = $url . '/shadow_attributes/getProposalsByUuidList';
		$response = $HttpSocket->post($uri, json_encode($uuidList), $request);
		if ($response->isOk()) {
			return(json_decode($response->body, true));
		} else if ($response->code == '405') {
			// HACKY: without correct permission, the returning null causes Fallback for < 2.4.7 instances
			// which queries every event, for proposal, which it doesn't have permission for
			return array();
		} else {
			// TODO parse the XML response and keep the reason why it failed
			return null;
		}
	}

	public function fetchEventIds($user, $from = false, $to = false, $last = false, $list = false, $timestamp = false, $publish_timestamp = false) {
		$conditions = array();
		// restricting to non-private or same org if the user is not a site-admin.
		if (!$user['Role']['perm_site_admin']) {
			$sgids = $this->SharingGroup->fetchAllAuthorised($user);
			$conditions['AND']['OR'] = array(
				'Event.org_id' => $user['org_id'],
				array(
					'AND' => array(
						'Event.distribution >' => 0,
						'Event.distribution <' => 4,
						Configure::read('MISP.unpublishedprivate') ? array('Event.published =' => 1) : array(),
					),
				),
				array(
					'AND' => array(
						'Event.sharing_group_id' => $sgids,
						'Event.distribution' => 4,
						Configure::read('MISP.unpublishedprivate') ? array('Event.published =' => 1) : array(),
					)
				)
			);
		}
		$fields = array('Event.id', 'Event.org_id', 'Event.distribution', 'Event.sharing_group_id');

		if ($from) $conditions['AND'][] = array('Event.date >=' => $from);
		if ($to) $conditions['AND'][] = array('Event.date <=' => $to);
		if ($last) $conditions['AND'][] = array('Event.publish_timestamp >=' => $last);
		if ($timestamp) $conditions['AND'][] = array('Event.timestamp >=' => $timestamp);
		if ($publish_timestamp) $conditions['AND'][] = array('Event.publish_timestamp >=' => $publish_timestamp);

		if ($list) {
			$params = array(
				'conditions' => $conditions,
				'recursive' => -1,
			);
			$results = array_values($this->find('list', $params));
		} else {
			$params = array(
				'conditions' => $conditions,
				'recursive' => -1,
				'fields' => $fields,
			);
			$results = $this->find('all', $params);
		}
		return $results;
	}

	//Once the data about the user is gathered from the appropriate sources, fetchEvent is called from the controller or background process.
	// Possible options:
	// eventid: single event ID
	// idList: array with event IDs
	// tags: string with the usual tag syntax
	// from: date string (YYYY-MM-DD)
	// to: date string (YYYY-MM-DD)
	// includeAllTags: true will include the tags
	// includeAttachments: true will attach the attachments to the attributes in the data field
	public function fetchEvent($user, $options = array()) {
		if (isset($options['Event.id'])) $options['eventid'] = $options['Event.id'];
		$possibleOptions = array('eventid', 'idList', 'tags', 'from', 'to', 'last', 'to_ids', 'includeAllTags', 'includeAttachments', 'event_uuid', 'distribution', 'sharing_group_id', 'disableSiteAdmin');
		foreach ($possibleOptions as &$opt) if (!isset($options[$opt])) $options[$opt] = false;
		if ($options['eventid']) {
			$conditions['AND'][] = array("Event.id" => $options['eventid']);
		} else {
			$conditions = array();
		}
		if (!isset($user['org_id'])) {
			throw new Exception('There was an error with the user account.');
		}
		$isSiteAdmin = $user['Role']['perm_site_admin'];
		if (isset($options['disableSiteAdmin']) && $options['disableSiteAdmin']) $isSiteAdmin = false;
		$conditionsAttributes = array();

		// restricting to non-private or same org if the user is not a site-admin.
		if (!$isSiteAdmin) {
			$sgids = $this->SharingGroup->fetchAllAuthorised($user);
			if (empty($sgids)) $sgids = array(-1);
			$conditions['AND']['OR'] = array(
				'Event.org_id' => $user['org_id'],
				array(
					'AND' => array(
						'Event.distribution >' => 0,
						'Event.distribution <' => 4,
						Configure::read('MISP.unpublishedprivate') ? array('Event.published =' => 1) : array(),
						$options['distribution'] !== false ? array('Event.distribution =' => $options['distribution']) : array(),
					),
				),
				array(
					'AND' => array(
						'Event.sharing_group_id' => $sgids,
						'Event.distribution' => 4,
						Configure::read('MISP.unpublishedprivate') ? array('Event.published =' => 1) : array(),
						$options['sharing_group_id'] !== false ? array('Event.sharing_group_id =' => $options['sharing_group_id']) : array(),
					)
				)
			);
			// if delegations are enabled, check if there is an event that the current user might see because of the request itself
			if (Configure::read('MISP.delegation')) {
				$this->EventDelegation = ClassRegistry::init('EventDelegation');
				$delegatedEventIDs = $this->EventDelegation->find('list', array(
					'conditions' => array('EventDelegation.org_id' => $user['org_id']),
					'fields' => array('event_id')
				));
				$conditions['AND']['OR']['Event.id'] = $delegatedEventIDs;
			}

			$conditionsAttributes['AND'][0]['OR'] = array(
				array('AND' => array(
					'Attribute.distribution >' => 0,
					'Attribute.distribution !=' => 4,
					$options['distribution'] !== false ? array('Attribute.distribution =' => $options['distribution']) : array(),
				)),
				array('AND' => array(
					'Attribute.distribution' => 4,
					'Attribute.sharing_group_id' => $sgids,
					$options['sharing_group_id'] !== false ? array('Attribute.sharing_group_id =' => $options['sharing_group_id']) : array(),
				)),
				'(SELECT events.org_id FROM events WHERE events.id = Attribute.event_id)' => $user['org_id']
			);
		}
		if ($options['from']) $conditions['AND'][] = array('Event.date >=' => $options['from']);
		if ($options['to']) $conditions['AND'][] = array('Event.date <=' => $options['to']);
		if ($options['last']) $conditions['AND'][] = array('Event.publish_timestamp >=' => $options['last']);
		if ($options['event_uuid']) $conditions['AND'][] = array('Event.uuid' => $options['event_uuid']);

		if (isset($options['deleted']) && $options['deleted']) {
			if (!$user['Role']['perm_sync']) {
				$conditionsAttributes['AND'][] = array(
					'OR' => array(
						'(SELECT events.org_id FROM events WHERE events.id = Attribute.event_id)' => $user['org_id'],
						'Attribute.deleted' => false
					)
				);
			}
		} else $conditionsAttributes['AND']['Attribute.deleted'] = false;

		if ($options['idList'] && !$options['tags']) {
			$conditions['AND'][] = array('Event.id' => $options['idList']);
		}
		// If we sent any tags along, load the associated tag names for each attribute
		if ($options['tags']) {
			$tag = ClassRegistry::init('Tag');
			$args = $this->Attribute->dissectArgs($options['tags']);
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

		if ($options['to_ids']) {
			$conditionsAttributes['AND'][] = array('Attribute.to_ids' => 1);
		}

		// removing this for now, we export the to_ids == 0 attributes too, since there is a to_ids field indicating it in the .xml
		// $conditionsAttributes['AND'] = array('Attribute.to_ids =' => 1);
		// Same idea for the published. Just adjust the tools to check for this
		// TODO: It is important to make sure that this is documented
		// $conditions['AND'][] = array('Event.published =' => 1);

		// do not expose all the data ...
		$fields = array('Event.id', 'Event.orgc_id', 'Event.org_id', 'Event.date', 'Event.threat_level_id', 'Event.info', 'Event.published', 'Event.uuid', 'Event.attribute_count', 'Event.analysis', 'Event.timestamp', 'Event.distribution', 'Event.proposal_email_lock', 'Event.user_id', 'Event.locked', 'Event.publish_timestamp', 'Event.sharing_group_id');
		$fieldsAtt = array('Attribute.id', 'Attribute.type', 'Attribute.category', 'Attribute.value', 'Attribute.to_ids', 'Attribute.uuid', 'Attribute.event_id', 'Attribute.distribution', 'Attribute.timestamp', 'Attribute.comment', 'Attribute.sharing_group_id', 'Attribute.deleted');
		$fieldsShadowAtt = array('ShadowAttribute.id', 'ShadowAttribute.type', 'ShadowAttribute.category', 'ShadowAttribute.value', 'ShadowAttribute.to_ids', 'ShadowAttribute.uuid', 'ShadowAttribute.event_uuid', 'ShadowAttribute.event_id', 'ShadowAttribute.old_id', 'ShadowAttribute.comment', 'ShadowAttribute.org_id', 'ShadowAttribute.proposal_to_delete');
		$fieldsOrg = array('id', 'name', 'uuid');
		$fieldsServer = array('id', 'url', 'name');
		$fieldsSharingGroup = array(
			array('fields' => array('SharingGroup.id','SharingGroup.name', 'SharingGroup.releasability', 'SharingGroup.description')),
			array(
				'fields' => array('SharingGroup.*'),
					'Organisation' => array('fields' => $fieldsOrg),
					'SharingGroupOrg' => array(
						'Organisation' => array('fields' => $fieldsOrg),
					),
					'SharingGroupServer' => array(
						'Server' => array('fields' => $fieldsServer),
				),
			),
		);
		if (!$options['includeAllTags']) $tagConditions = array('exportable' => 1);
		else $tagConditions = array();

		$params = array('conditions' => $conditions,
			'recursive' => 0,
			'fields' => $fields,
			'contain' => array(
				'ThreatLevel' => array(
						'fields' => array('ThreatLevel.name')
				),
				'Org' => array('fields' => $fieldsOrg),
				'Orgc' => array('fields' => $fieldsOrg),
				'Attribute' => array(
					'fields' => $fieldsAtt,
					'conditions' => $conditionsAttributes,
					'SharingGroup' => $fieldsSharingGroup[(($user['Role']['perm_site_admin'] || $user['Role']['perm_sync']) ? 1 : 0)],
				),
				'ShadowAttribute' => array(
					'fields' => $fieldsShadowAtt,
					'conditions' => array('deleted' => 0),
					'Org' => array('fields' => $fieldsOrg)
				),
				'SharingGroup' => $fieldsSharingGroup[(($user['Role']['perm_site_admin'] || $user['Role']['perm_sync']) ? 1 : 0)],
				'EventTag' => array(
					'Tag' => array(
						'conditions' => $tagConditions
					),
				),
			)
		);
		if ($user['Role']['perm_site_admin']) {
			$params['contain']['User'] = array('fields' => 'email');
		}
		$results = $this->find('all', $params);
		if (empty($results)) return array();
		// Do some refactoring with the event
		$sgsids = $this->SharingGroup->fetchAllAuthorised($user);
		if (Configure::read('Plugin.Sightings_enable')) $this->Sighting = ClassRegistry::init('Sighting');
		foreach ($results as $eventKey => &$event) {
			// unset the empty sharing groups that are created due to the way belongsTo is handled
			if (isset($event['SharingGroup']['SharingGroupServer'])) {
				foreach ($event['SharingGroup']['SharingGroupServer'] as &$sgs) {
					if ($sgs['server_id'] == 0) {
						$sgs['Server'] = array('id' => '0', 'url' => Configure::read('MISP.baseurl'), 'name' => Configure::read('MISP.baseurl'));
					}
				}
			}
			if ($event['SharingGroup']['id'] == null) unset($event['SharingGroup']);
			// unset empty event tags that got added because the tag wasn't exportable
			if (!empty($event['EventTag'])) {
				foreach ($event['EventTag'] as $k => &$eventTag) {
					if (empty($eventTag['Tag'])) unset($event['EventTag'][$k]);
				}
				$event['EventTag'] = array_values($event['EventTag']);
			}
			// Let's find all the related events and attach it to the event itself
			$results[$eventKey]['RelatedEvent'] = $this->getRelatedEvents($user, $event['Event']['id'], $sgsids);
			// Let's also find all the relations for the attributes - this won't be in the xml export though
			$results[$eventKey]['RelatedAttribute'] = $this->getRelatedAttributes($user, $event['Event']['id'], $sgsids);
			$results[$eventKey]['RelatedShadowAttribute'] = $this->getRelatedAttributes($user, $event['Event']['id'], $sgsids, true);
			if (isset($event['ShadowAttribute']) && !empty($event['ShadowAttribute']) && isset($options['includeAttachments']) && $options['includeAttachments']) {
				foreach ($event['ShadowAttribute'] as &$sa) {
					if ($this->ShadowAttribute->typeIsAttachment($sa['type'])) {
						$encodedFile = $this->ShadowAttribute->base64EncodeAttachment($sa);
						$sa['data'] = $encodedFile;
					}
				}
			}
			foreach ($event['Attribute'] as $key => &$attribute) {
				if (isset($options['includeAttachments']) && $options['includeAttachments']) {
					if ($this->Attribute->typeIsAttachment($attribute['type'])) {
						$encodedFile = $this->Attribute->base64EncodeAttachment($attribute);
						$attribute['data'] = $encodedFile;
					}
				}
				if (isset($attribute['SharingGroup']['SharingGroupServer'])) {
					foreach ($attribute['SharingGroup']['SharingGroupServer'] as &$sgs) {
						if ($sgs['server_id'] == 0) {
							$sgs['Server'] = array('id' => '0', 'url' => Configure::read('MISP.baseurl'), 'name' => Configure::read('MISP.baseurl'));
						}
					}
				}
				$attribute['ShadowAttribute'] = array();
				// If a shadowattribute can be linked to an attribute, link it to it then remove it from the event
				// This is to differentiate between proposals that were made to an attribute for modification and between proposals for new attributes
				foreach ($event['ShadowAttribute'] as $k => &$sa) {
					if (!empty($sa['old_id'])) {
						if ($sa['old_id'] == $attribute['id']) {
							$results[$eventKey]['Attribute'][$key]['ShadowAttribute'][] = $sa;
							unset($results[$eventKey]['ShadowAttribute'][$k]);
						}
					}
				}
			}
			if (Configure::read('Plugin.Sightings_enable')) {
				$event['Sighting'] = $this->Sighting->attachToEvent($event, $user);
			}
			// remove proposals to attributes that we cannot see
			// if the shadow attribute wasn't moved within an attribute before, this is the case
			foreach ($event['ShadowAttribute'] as $k => &$sa) {
				if (!empty($sa['old_id'])) unset($event['ShadowAttribute'][$k]);
			}
		}
		return $results;
	}

	public function csv($user, $eventid=false, $ignore=false, $attributeIDList = array(), $tags = false, $category = false, $type = false, $includeContext = false, $from = false, $to = false, $last = false) {
		$this->recursive = -1;
		$conditions = array();
		// If we are not in the search result csv download function then we need to check what can be downloaded. CSV downloads are already filtered by the search function.
		if ($eventid !== 'search') {
			if ($from) $conditions['AND'][] = array('Event.date >=' => $from);
			if ($to) $conditions['AND'][] = array('Event.date <=' => $to);
			if ($last) $conditions['AND'][] = array('Event.publish_timestamp >=' => $last);
			// This is for both single event downloads and for full downloads. Org has to be the same as the user's or distribution not org only - if the user is no siteadmin
			if ($ignore == false) $conditions['AND'][] = array('Event.published' => 1);

			// If we sent any tags along, load the associated tag names for each attribute
			if ($tags) {
				$tag = ClassRegistry::init('Tag');
				$args = $this->Attribute->dissectArgs($tags);
				$tagArray = $tag->fetchEventTagIds($args[0], $args[1]);
				$temp = array();
				foreach ($tagArray[0] as $accepted) {
					$temp['OR'][] = array('Event.id' => $accepted);
				}
				if (!empty($temp)) $conditions['AND'][] = $temp;
				$temp = array();
				foreach ($tagArray[1] as $rejected) {
					$temp['AND'][] = array('Event.id !=' => $rejected);
				}
				if (!empty($temp)) $conditions['AND'][] = $temp;
			}
			// if we're downloading a single event, set it as a condition
			if ($eventid) $conditions['AND'][] = array('Event.id' => $eventid);

			//restricting to non-private or same org if the user is not a site-admin.
			if (!$ignore) $conditions['AND'][] = array('Attribute.to_ids' => 1);
			if ($type) $conditions['AND'][] = array('Attribute.type' => $type);
			if ($category) $conditions['AND'][] = array('Attribute.category' => $category);
		}

		if ($eventid === 'search') {
			foreach ($attributeIDList as $aID) $conditions['AND']['OR'][] = array('Attribute.id' => $aID);
		}
		$params = array(
				'conditions' => $conditions, //array of conditions
				'fields' => array('Attribute.event_id', 'Attribute.distribution', 'Attribute.category', 'Attribute.type', 'Attribute.value', 'Attribute.comment', 'Attribute.uuid', 'Attribute.to_ids', 'Attribute.timestamp', 'Attribute.id'),
				'order' => array('Attribute.uuid ASC')
		);

		if ($includeContext) {
			$params['contain'] = array(
				'Event' => array(
						'fields' => array('id', 'info', 'org_id', 'orgc_id', 'date', 'distribution', 'analysis'),
						'SharingGroup' => array('fields' => array('id', 'name')),
						'Org' => array('id', 'name'),
						'Orgc' => array('id', 'name'),
						'ThreatLevel' => array(
								'fields' => array('id', 'name'),
						),
						'EventTag' => array(
								'Tag' => array(
										'fields' => array('id', 'name')
								)
						)
				),
			);
		}
		$attributes = $this->Attribute->fetchAttributes($user, $params);
		if (empty($attributes)) return array();
		foreach ($attributes as &$attribute) {
			$attribute['Attribute']['value'] = str_replace(array('"'), '""', $attribute['Attribute']['value']);
			$attribute['Attribute']['value'] = '"' . $attribute['Attribute']['value'] . '"';
			$attribute['Attribute']['comment'] = str_replace(array('"'), '""', $attribute['Attribute']['comment']);
			$attribute['Attribute']['comment'] = '"' . $attribute['Attribute']['comment'] . '"';
			$attribute['Attribute']['timestamp'] = date('Ymd', $attribute['Attribute']['timestamp']);
			if ($includeContext) {
				$attribute['Event']['info'] = str_replace(array('"'), '""', $attribute['Event']['info']);
				$attribute['Event']['info'] = '"' . $attribute['Event']['info'] . '"';
				$attribute['Event']['Tag']['name'] = '';
				if (!empty($attribute['Event']['EventTag'])) {
					foreach ($attribute['Event']['EventTag'] as $eventTag) {
						if (!empty($attribute['Event']['Tag']['name'])) $attribute['Event']['Tag']['name'] .= ',';
						$attribute['Event']['Tag']['name'] .= str_replace(array('"'), '""', $eventTag['Tag']['name']);
					}
				}
				if (!empty($attribute['Event']['Tag']['name'])) $attribute['Event']['Tag']['name'] = '"' . $attribute['Event']['Tag']['name'] . '"';
			}
		}
		return $attributes;
	}

	public function sendAlertEmailRouter($id, $user) {
		if (Configure::read('MISP.block_old_event_alert') && Configure::read('MISP.block_old_event_alert_age') && is_numeric(Configure::read('MISP.block_old_event_alert_age'))) {
			$oldest = time() - (Configure::read('MISP.block_old_event_alert_age') * 86400);
			$event = $this->find('first', array(
					'conditions' => array('Event.id' => $id),
					'recursive' => -1,
					'fields' => array('Event.date')
			));
			if (empty($event)) return false;
			if (strtotime($event['Event']['date']) < $oldest) return true;
		}
		if (Configure::read('MISP.background_jobs')) {
			$job = ClassRegistry::init('Job');
			$job->create();
			$data = array(
					'worker' => 'email',
					'job_type' => 'publish_alert_email',
					'job_input' => 'Event: ' . $id,
					'status' => 0,
					'retries' => 0,
					'org_id' => $user['org_id'],
					'org' => $user['Organisation']['name'],
					'message' => 'Sending...',
			);
			$job->save($data);
			$jobId = $job->id;
			$process_id = CakeResque::enqueue(
					'email',
					'EventShell',
					array('alertemail', $user['id'], $jobId, $id)
			);
			$job->saveField('process_id', $process_id);
			return true;
		} else {
			return ($this->sendAlertEmail($id, $user));
		}
	}

	public function sendAlertEmail($id, $senderUser, $processId = null) {
		$event = $this->fetchEvent($senderUser, array('eventid' => $id, 'includeAllTags' => true));
		if (empty($event)) throw new MethodNotFoundException('Invalid Event.');
		$userConditions = array('autoalert' => 1);
		$this->User = ClassRegistry::init('User');
		$users = $this->User->getUsersWithAccess(
			$owners = array(
				$event[0]['Event']['orgc_id'],
				$event[0]['Event']['org_id']
			),
			$event[0]['Event']['distribution'],
			$event[0]['Event']['sharing_group_id'],
			$userConditions
		);
		if (Configure::read('MISP.extended_alert_subject')) {
			$subject = preg_replace( "/\r|\n/", "", $event[0]['Event']['info']);
			if (strlen($subject) > 58) {
				$subject = substr($subject, 0, 55) . '... - ';
			} else {
				$subject .= " - ";
			}
		} else {
			$subject = '';
		}
        $tplColorString = !empty(Configure::read('MISP.email_subject_TLP_string')) ? Configure::read('MISP.email_subject_TLP_string') : "TLP Amber";
		$subject = "[" . Configure::read('MISP.org') . " MISP] Event " . $id . " - " . $subject . $event[0]['ThreatLevel']['name'] . " - ".$tplColorString;

		// Initialise the Job class if we have a background process ID
		// This will keep updating the process's progress bar
		if ($processId) {
			$this->Job = ClassRegistry::init('Job');
		}
		$sgModel = ClassRegistry::init('SharingGroup');

		$userCount = count($users);
		foreach ($users as $k => $user) {
			$body = $this->__buildAlertEmailBody($event[0], $user, $sgModel);
			$bodyNoEnc = "A new or modified event was just published on " . Configure::read('MISP.baseurl') . "/events/view/" . $event[0]['Event']['id'];
			$this->User->sendEmail(array('User' => $user), $body, $bodyNoEnc, $subject);
				if ($processId) {
					$this->Job->id = $processId;
					$this->Job->saveField('progress', $k / $userCount * 100);
				}
		}

		if ($processId) {
			$this->Job->saveField('message', 'Mails sent.');
		}
		return true;
	}

	private function __buildAlertEmailBody($event, $user, $sgModel) {
		$owner = false;
		if ($user['org_id'] == $event['Event']['orgc_id'] || $user['org_id'] == $event['Event']['org_id'] || $user['Role']['perm_site_admin']) $owner = true;
		// The mail body, h() is NOT needed as we are sending plain-text mails.
		$body = "";
		$body .= '==============================================' . "\n";
		$appendlen = 20;
		$body .= 'URL         : ' . Configure::read('MISP.baseurl') . '/events/view/' . $event['Event']['id'] . "\n";
		$body .= 'Event ID    : ' . $event['Event']['id'] . "\n";
		$body .= 'Date        : ' . $event['Event']['date'] . "\n";
		if (Configure::read('MISP.showorg')) {
			$body .= 'Reported by : ' . $event['Orgc']['name'] . "\n";
			$body .= 'Local owner of the event : ' . $event['Org']['name'] . "\n";
		}
		$body .= 'Distribution: ' . $this->distributionLevels[$event['Event']['distribution']] . "\n";
		if ($event['Event']['distribution'] == 4) {
			$body .= 'Sharing Group:' . $event['SharingGroup']['name'] . "\n";
		}
		$tags = "";
		foreach ($event['EventTag'] as $k => $tag) {
			$tags .= $tag['Tag']['name'];
			if (($k+1) != count($event['EventTag'])) $tags .= ", ";
		}
		$body .= 'Tags: ' . $tags . "\n";
		$body .= 'Threat Level: ' . $event['ThreatLevel']['name'] . "\n";
		$body .= 'Analysis    : ' . $this->analysisLevels[$event['Event']['analysis']] . "\n";
		$body .= 'Description : ' . $event['Event']['info'] . "\n\n";
		$relatedEvents = $this->getRelatedEvents($user, $event['Event']['id'], array());
		if (!empty($relatedEvents)) {
			$body .= '==============================================' . "\n";
			$body .= 'Related to : '. "\n";
			foreach ($relatedEvents as &$relatedEvent) {
				$body .= Configure::read('MISP.baseurl') . '/events/view/' . $relatedEvent['Event']['id'] . ' (' . $relatedEvent['Event']['date'] . ') ' ."\n";
			}
			$body .= '==============================================' . "\n";
		}
		$body .= 'Attributes (* indicates a new or modified attribute)  :' . "\n";
		$bodyTempOther = "";
		if (isset($event['Attribute'])) {
			foreach ($event['Attribute'] as &$attribute) {
				if (!$owner && $attribute['distribution'] == 0) continue;
				if ($attribute['distribution'] == 4 && !$sgModel->checkIfAuthorised($user, $attribute['sharing_group_id'])) continue;
				$ids = '';
				if ($attribute['to_ids']) $ids = ' (IDS)';
				if (isset($event['Event']['publish_timestamp']) && isset($attribute['timestamp']) && $attribute['timestamp'] > $event['Event']['publish_timestamp']) {
					$line = '*' . $attribute['type'] . str_repeat(' ', $appendlen - 2 - strlen($attribute['type'])) . ': ' . $attribute['value'] . $ids . "\n";
				} else {
					$line = $attribute['type'] . str_repeat(' ', $appendlen - 2 - strlen($attribute['type'])) . ': ' . $attribute['value'] . $ids .  "\n";
				}
				// Defanging URLs (Not "links") emails domains/ips in notification emails
				if ('url' == $attribute['type']) {
					$line = str_ireplace("http","hxxp", $line);
				}
				else if ('email-src' == $attribute['type'] or 'email-dst' == $attribute['type']) {
					$line = str_replace("@","[at]", $line);
				}
				else if ('hostname' == $attribute['type'] or 'domain' == $attribute['type'] or 'ip-src' == $attribute['type'] or 'ip-dst' == $attribute['type']) {
					$line = str_replace(".","[.]", $line);
				}

				if ('other' == $attribute['type']) // append the 'other' attribute types to the bottom.
					$bodyTempOther .= $line;
				else $body .= $line;
			}
		}
		if (!empty($bodyTempOther)) {
			$body .= "\n";
		}
		$body .= $bodyTempOther;	// append the 'other' attribute types to the bottom.
		$body .= '==============================================' . "\n";
		return $body;
	}

	public function sendContactEmail($id, $message, $creator_only, $user, $isSiteAdmin) {
		// fetch the event
		$event = $this->read(null, $id);
		$this->User = ClassRegistry::init('User');
		if (!$creator_only) {
			// Insert extra field here: alertOrg or something, then foreach all the org members
			// limit this array to users with contactalerts turned on!
			$orgMembers = array();
			$this->User->recursive = 0;
			$temp = $this->User->find('all', array(
					'fields' => array('email', 'gpgkey', 'certif_public', 'contactalert', 'id', 'org_id'),
					'conditions' => array('disabled' => 0, 'User.org_id' => $event['Event']['orgc_id']),
					'recursive' => -1
			));
			if (empty($temp)) {
				$temp = $this->User->find('all', array(
						'fields' => array('email', 'gpgkey', 'certif_public', 'contactalert', 'id', 'org_id'),
						'conditions' => array('disabled' => 0, 'User.org_id' => $event['Event']['org_id']),
						'recursive' => -1
				));
			}
			foreach ($temp as $tempElement) {
				if ($tempElement['User']['contactalert'] || $tempElement['User']['id'] == $event['Event']['user_id']) {
					array_push($orgMembers, $tempElement);
				}
			}
		} else {
			$temp = $this->User->find('first', array(
					'conditions' => array('User.id' => $event['Event']['user_id'], 'User.disabled' => 0),
					'fields' => array('User.email', 'User.gpgkey', 'User.certif_public'),
			));
			if (!empty($temp)) $orgMembers = array(0 => $temp);
		}
		if (empty($orgMembers)) return false;
		// The mail body, h() is NOT needed as we are sending plain-text mails.
		$body = "";
		$body .= "Hello, \n";
		$body .= "\n";
		$body .= "Someone wants to get in touch with you concerning a MISP event. \n";
		$body .= "\n";
		$body .= "You can reach him at " . $user['User']['email'] . "\n";
		if (!$user['User']['gpgkey'])
			$body .= "His GPG/PGP key is added as attachment to this email. \n";
		if (!$user['User']['certif_public'])
			$body .= "His Public certificate is added as attachment to this email. \n";
		$body .= "\n";
		$body .= "He wrote the following message: \n";
		$body .= $message . "\n";
		$body .= "\n";
		$body .= "\n";
		$body .= "The event is the following: \n";

		// print the event in mail-format
		// LATER place event-to-email-layout in a function
		$appendlen = 20;
		$body .= 'URL         : ' . Configure::read('MISP.baseurl') . '/events/view/' . $event['Event']['id'] . "\n";
		$bodyevent = $body;
		$bodyevent .= 'Event ID    : ' . $event['Event']['id'] . "\n";
		$bodyevent .= 'Date        : ' . $event['Event']['date'] . "\n";
		if (Configure::read('MISP.showorg')) {
			$body .= 'Reported by : ' . $event['Orgc']['name'] . "\n";
		}
		$bodyevent .= 'Risk        : ' . $event['ThreatLevel']['name'] . "\n";
		$bodyevent .= 'Analysis    : ' . $event['Event']['analysis'] . "\n";

		$userModel = ClassRegistry::init('User');
		$targetUser = $userModel->getAuthUser($orgMembers[0]['User']['id']);
		$sgModel = ClassRegistry::init('SharingGroup');
		$sgs = $sgModel->fetchAllAuthorised($targetUser, false);

		$relatedEvents = $this->getRelatedEvents($targetUser, $id, $sgs);
		if (!empty($relatedEvents)) {
			foreach ($relatedEvents as &$relatedEvent) {
				$bodyevent .= 'Related to  : ' . Configure::read('MISP.baseurl') . '/events/view/' . $relatedEvent['Event']['id'] . ' (' . $relatedEvent['Event']['date'] . ')' . "\n";

			}
		}
		$bodyevent .= 'Info  : ' . "\n";
		$bodyevent .= $event['Event']['info'] . "\n";
		$bodyevent .= "\n";
		$bodyevent .= 'Attributes  :' . "\n";
		$bodyTempOther = "";
		if (!empty($event['Attribute'])) {
			foreach ($event['Attribute'] as &$attribute) {
				$line = '- ' . $attribute['type'] . str_repeat(' ', $appendlen - 2 - strlen( $attribute['type'])) . ': ' . $attribute['value'] . "\n";
				if ('other' == $attribute['type']) // append the 'other' attribute types to the bottom.
					$bodyTempOther .= $line;
				else $bodyevent .= $line;
			}
		}
		$bodyevent .= "\n";
		$bodyevent .= $bodyTempOther;	// append the 'other' attribute types to the bottom.
		$result = true;
        $tplColorString = !empty(Configure::read('MISP.email_subject_TLP_string')) ? Configure::read('MISP.email_subject_TLP_string') : "TLP Amber";
		foreach ($orgMembers as &$reporter) {
			$subject = "[" . Configure::read('MISP.org') . " MISP] Need info about event " . $id . " - ".$tplColorString;
			$result = $this->User->sendEmail($reporter, $bodyevent, $body, $subject, $user) && $result;
		}
		return $result;
	}

	// When we receive an event via REST, we might end up with organisations, sharing groups, tags that we do not know
	// or which we need to update. All of that is controller in this method.
	private function __captureObjects($data, $user) {
		// First we need to check whether the event or any attributes are tied to a sharing group and whether the user is even allowed to create the sharing group / is part of it
		// For this we first collect all the sharing groups
		$sgs = array();
		if ($data['Event']['distribution'] == 4) $sgs[$data['Event']['SharingGroup']['uuid']] = $data['Event']['SharingGroup'];
		if (isset($data['Event']['Attribute'])) {
			if (!isset($data['Event']['Attribute'][0])) $data['Event']['Attribute'] = array(0 => $data['Event']['Attribute']);
			foreach ($data['Event']['Attribute'] as &$attribute) {
				if (isset($attribute['SharingGroup']) && !empty($attribute['SharingGroup']) && isset($attribute['SharingGroup'][0])) $attribute['SharingGroup'] = $attribute['SharingGroup'][0];
				if (isset($attribute['distribution']) && $attribute['distribution'] == 4 && !isset($sgs[$attribute['SharingGroup']['uuid']])) $sgs[$attribute['SharingGroup']['uuid']] = $attribute['SharingGroup'];
			}
		}

		if ($data['Event']['distribution'] == 4) {
			$sg = $this->SharingGroup->captureSG($data['Event']['SharingGroup'], $user);
			if ($sg===false) {
				$sg = 0;
				$data['Event']['distribution'] = 0;
			}
			$data['Event']['sharing_group_id'] = $sg;
			unset($data['Event']['SharingGroup']);
		}
		if (isset($data['Event']['Attribute'])) {
			foreach ($data['Event']['Attribute'] as $k => &$a) {
				unset($data['Event']['Attribute']['id']);
				if (isset($a['distribution']) && $a['distribution'] == 4) {
					$data['Event']['Attribute'][$k]['sharing_group_id'] = $this->SharingGroup->captureSG($data['Event']['Attribute'][$k]['SharingGroup'], $user);
					unset($data['Event']['Attribute'][$k]['SharingGroup']);
				}
			}
		}
		// first we want to see how the creator organisation is encoded
		// The options here are either by passing an organisation object along or simply passing a string along
		if (isset($data['Event']['Orgc'])) {
			$data['Event']['orgc_id'] = $this->Orgc->captureOrg($data['Event']['Orgc'], $user);
			unset($data['Event']['Orgc']);
		} else if (isset($data['Event']['orgc'])) {
			$data['Event']['orgc_id'] = $this->Orgc->captureOrg($data['Event']['orgc'], $user);
			unset($data['Event']['orgc']);
		} else {
			$data['Event']['orgc_id'] = $user['org_id'];
		}
		if (isset($data['Event']['EventTag'])) {
			if (isset($data['Event']['EventTag']['id'])) {
				$temp = $data['Event']['EventTag'];
				unset($data['Event']['EventTag']);
				$data['Event']['EventTag'][0] = $temp;
			}
			$eventTags = array();
			foreach ($data['Event']['EventTag'] as $k => $tag) {
				$eventTags[] = array('tag_id' => $this->EventTag->Tag->captureTag($data['Event']['EventTag'][$k]['Tag'], $user));
				unset($data['Event']['EventTag'][$k]);
			}
			$data['Event']['EventTag'] = $eventTags;
		}
		if (!isset($data['Event']['EventTag'])) $data['Event']['EventTag'] = array();
		if (isset($data['Event']['Tag'])) {
			if (isset($data['Event']['Tag']['name'])) $data['Event']['Tag'] = array($data['Event']['Tag']);
			foreach ($data['Event']['Tag'] as $tag) {
				$tag_id = $this->EventTag->Tag->captureTag($tag, $user);
				if ($tag_id) $data['Event']['EventTag'][] = array('tag_id' => $tag_id);
			}
			unset($data['Event']['Tag']);
		}
		return $data;
	}

	/**
	 * Low level function to add an Event based on an Event $data array
	 *
	 * @return bool true if success
	 */
	public function _add(&$data, $fromXml, $user, $org_id='', $passAlong = null, $fromPull = false, $jobId = null, &$created_id = 0, &$validationErrors = array()) {
		if ($jobId) {
			App::import('Component','Auth');
		}
		if (Configure::read('MISP.enableEventBlacklisting') && isset($data['Event']['uuid'])) {
			$event = $this->find('first', array(
					'recursive' => -1,
					'fields' => array('uuid'),
					'conditions' => array('id' => $this->id),
			));
			$this->EventBlacklist = ClassRegistry::init('EventBlacklist');
			$r = $this->EventBlacklist->find('first', array('conditions' => array('event_uuid' => $data['Event']['uuid'])));
			if (!empty($r))	return 'blocked';
		}
		$this->create();
		// force check userid and orgname to be from yourself
		$data['Event']['user_id'] = $user['id'];

		if ($fromPull) {
			$data['Event']['org_id'] = $org_id;
		} else {
			$data['Event']['org_id'] = $user['Organisation']['id'];
		}
		// set these fields if the event is freshly created and not pushed from another instance.
		// Moved out of if (!$fromXML), since we might get a restful event without the orgc/timestamp set
		if (!isset($data['Event']['orgc_id']) && !isset($data['Event']['orgc'])) {
			$data['Event']['orgc_id'] = $data['Event']['org_id'];
		} else {
			if (!isset($data['Event']['Orgc'])) {
				if ($data['Event']['orgc_id'] != $user['org_id'] && !$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin']) throw new MethodNotAllowedException('Event cannot be created as you are not a member of the creator organisation.');
			} else {
				if ($data['Event']['Orgc']['uuid'] != $user['Organisation']['uuid'] && !$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin']) throw new MethodNotAllowedException('Event cannot be created as you are not a member of the creator organisation.');
			}
			if ($data['Event']['orgc_id'] != $user['org_id'] && !$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin']) throw new MethodNotAllowedException('Event cannot be created as you are not a member of the creator organisation.');
		}
		if (Configure::read('MISP.enableOrgBlacklisting')) {
			$this->OrgBlacklist = ClassRegistry::init('OrgBlacklist');
			$orgc = $this->Orgc->find('first', array('conditions' => array('Orgc.id' => $data['Event']['orgc_id']), 'fields' => array('Orgc.uuid'), 'recursive' => -1));
			if ($this->OrgBlacklist->hasAny(array('OrgBlacklist.org_uuid' => $orgc['Orgc']['uuid']))) return 'blocked';
		}
		if ($fromXml) {
			// Workaround for different structure in XML/array than what CakePHP expects
			$data = $this->cleanupEventArrayFromXML($data);
			// the event_id field is not set (normal) so make sure no validation errors are thrown
			// LATER do this with	$this->validator()->remove('event_id');
			unset($this->Attribute->validate['event_id']); // otherwise gives bugs because event_id is not set
			unset($this->Attribute->validate['value']['uniqueValue']); // unset this - we are saving a new event, there are no values to compare against and event_id is not set in the attributes
		}
		unset($data['Event']['id']);
		if (isset($data['Event']['published']) && $data['Event']['published'] && $user['Role']['perm_publish'] == false) $data['Event']['published'] = false;
		if (isset($data['Event']['uuid'])) {
			// check if the uuid already exists
			$existingEventCount = $this->find('count', array('conditions' => array('Event.uuid' => $data['Event']['uuid'])));
			if ($existingEventCount > 0) {
				// RESTful, set response location header so client can find right URL to edit
				if ($fromPull) return false;
				$existingEvent = $this->find('first', array('conditions' => array('Event.uuid' => $data['Event']['uuid'])));
				if ($fromXml) $created_id = $existingEvent['Event']['id'];
				return $existingEvent['Event']['id'];
			} else {
				if ($fromXml) $data = $this->__captureObjects($data, $user);
			}
		} else {
			if ($fromXml) $data = $this->__captureObjects($data, $user);
		}
		// FIXME chri: validatebut  the necessity for all these fields...impact on security !
		$fieldList = array(
				'Event' => array('org_id', 'orgc_id', 'date', 'threat_level_id', 'analysis', 'info', 'user_id', 'published', 'uuid', 'timestamp', 'distribution', 'sharing_group_id', 'locked'),
				'Attribute' => array('event_id', 'category', 'type', 'value', 'value1', 'value2', 'to_ids', 'uuid', 'timestamp', 'distribution', 'comment', 'sharing_group_id', 'deleted'),
		);
		$saveResult = $this->save(array('Event' => $data['Event']), array('fieldList' => $fieldList['Event']));
		$this->Log = ClassRegistry::init('Log');
		if ($saveResult) {
			if (isset($data['Event']['EventTag'])) {
				foreach ($data['Event']['EventTag'] as $et) {
					$this->EventTag->create();
					$et['event_id'] = $this->id;
					$this->EventTag->save($et);
				}
			}
			if (isset($data['Event']['Attribute'])) {
				foreach ($data['Event']['Attribute'] as $k => &$attribute) {
					$attribute['event_id'] = $this->id;
					unset($attribute['id']);
					$this->Attribute->create();
					if (!$this->Attribute->save($attribute, array('fieldList' => $fieldList['Attribute']))) {
						$validationErrors['Attribute'][$k] = $this->Attribute->validationErrors;
						$attribute_short = (isset($attribute['category']) ? $attribute['category'] : 'N/A') . '/' . (isset($attribute['type']) ? $attribute['type'] : 'N/A') . ' ' . (isset($attribute['value']) ? $attribute['value'] : 'N/A');
						$this->Log->create();
						$this->Log->save(array(
								'org' => $user['Organisation']['name'],
								'model' => 'Attribute',
								'model_id' => 0,
								'email' => $user['email'],
								'action' => 'add',
								'user_id' => $user['id'],
								'title' => 'Attribute dropped due to validation for Event ' . $this->id . ' failed: ' . $attribute_short,
								'change' => json_encode($this->Attribute->validationErrors),
						));
					}
				}
			}

			if ($fromXml) $created_id = $this->id;
			if (!empty($data['Event']['published']) && 1 == $data['Event']['published']) {
				// do the necessary actions to publish the event (email, upload,...)
				if ('true' != Configure::read('MISP.disablerestalert')) {
					$this->sendAlertEmailRouter($this->getID(), $user);
				}
				$this->publish($this->getID(), $passAlong);
			}
			return true;
		} else {
			$validationErrors['Event'] = $this->validationErrors;
			return json_encode($this->validationErrors);
		}
	}

	public function _edit(&$data, $user, $id, $jobId = null) {
		$data = $this->cleanupEventArrayFromXML($data);
		unset($this->Attribute->validate['event_id']);
		unset($this->Attribute->validate['value']['unique']); // otherwise gives bugs because event_id is not set

		// reposition to get the event.id with given uuid
		if (isset($data['Event']['uuid'])) $existingEvent = $this->findByUuid($data['Event']['uuid']);
		else $existingEvent = $this->findById($id);
		// If the event exists...
		$dateObj = new DateTime();
		$date = $dateObj->getTimestamp();
		if (count($existingEvent)) {
			$data['Event']['id'] = $existingEvent['Event']['id'];
			$id = $existingEvent['Event']['id'];
			// Conditions affecting all:
			// user.org == event.org
			// edit timestamp newer than existing event timestamp
			if (!isset($data['Event']['timestamp']) || $data['Event']['timestamp'] > $existingEvent['Event']['timestamp']) {
				if (!isset($data['Event']['timestamp'])) $data['Event']['timestamp'] = $date;
				if ($data['Event']['distribution'] == 4) {
					if (!isset($data['Event']['SharingGroup'])) {
						if (!isset($data['Event']['sharing_group_id'])) return(array('error' => 'Event could not be saved: Sharing group chosen as the distribution level, but no sharing group specified. Make sure that the event includes a valid sharing_group_id or change to a different distribution level.'));
						if (!$this->SharingGroup->checkIfAuthorised($user, $data['Event']['sharing_group_id'])) return(array('error' => 'Event could not be saved: Invalid sharing group or you don\'t have access to that sharing group.'));
					} else {
						$data['Event']['sharing_group_id'] = $this->SharingGroup->captureSG($data['Event']['SharingGroup'], $user);
						unset($data['Event']['SharingGroup']);
						if ($data['Event']['sharing_group_id'] === false) return (array('error' => 'Event could not be saved: User not authorised to create the associated sharing group.'));
					}
				}
				// If the above is true, we have two more options:
				// For users that are of the creating org of the event, always allow the edit
				// For users that are sync users, only allow the edit if the event is locked
				if ($existingEvent['Event']['orgc_id'] === $user['org_id']
				|| ($user['Role']['perm_sync'] && $existingEvent['Event']['locked']) || $user['Role']['perm_site_admin']) {
					if ($user['Role']['perm_sync']) {
						if ($data['Event']['distribution'] == 4 && !$this->SharingGroup->checkIfAuthorised($user, $data['Event']['sharing_group_id'])) {
							return (array('error' => 'Event could not be saved: The sync user has to have access to the sharing group in order to be able to edit it.'));
						}
					}
				} else {
					return (array('error' => 'Event could not be saved: The user used to edit the event is not authorised to do so. This can be caused by the user not being of the same organisation as the original creator of the event whilst also not being a site administrator.'));
				}
			} else {
				return (array('error' => 'Event could not be saved: Event in the request not newer than the local copy.'));
			}
			// If a field is not set in the request, just reuse the old value
			$recoverFields = array('analysis', 'threat_level_id', 'info', 'distribution', 'date');
			foreach ($recoverFields as $rF) {
				if (!isset($data['Event'][$rF])) $data['Event'][$rF] = $existingEvent['Event'][$rF];
			}
		} else {
			return (array('error' => 'Event could not be saved: Could not find the local event.'));
		}
		if (isset($data['Event']['published']) && $data['Event']['published'] && !$user['Role']['perm_publish']) $data['Event']['published'] = false;
		if (!isset($data['Event']['published'])) $data['Event']['published'] = false;
		$fieldList = array(
				'Event' => array('date', 'threat_level_id', 'analysis', 'info', 'published', 'uuid', 'distribution', 'timestamp', 'sharing_group_id'),
				'Attribute' => array('event_id', 'category', 'type', 'value', 'value1', 'value2', 'to_ids', 'uuid', 'revision', 'distribution', 'timestamp', 'comment', 'sharing_group_id', 'deleted')
		);
		$saveResult = $this->save(array('Event' => $data['Event']), array('fieldList' => $fieldList['Event']));
		$this->Log = ClassRegistry::init('Log');
		if ($saveResult) {
			$validationErrors = array();
			if (isset($data['Event']['Attribute'])) {
				foreach ($data['Event']['Attribute'] as $k => $attribute) {
					if (isset($attribute['uuid'])) {
						$existingAttribute = $this->Attribute->findByUuid($attribute['uuid']);
						if (count($existingAttribute)) {
							if ($existingAttribute['Attribute']['event_id'] != $id) {
								$result = $this->Log->save(array(
										'org' => $user['Organisation']['name'],
										'model' => 'Event',
										'model_id' => $id,
										'email' => $user['email'],
										'action' => 'edit',
										'user_id' => $user['id'],
										'title' => 'Duplicate UUID found in attribute',
										'change' => 'An attribute was blocked from being saved due to a duplicate UUID. The uuid in question is: ' . $attribute['uuid'],
								));
								unset($data['Event']['Attribute'][$k]);
							} else {
								// If a field is not set in the request, just reuse the old value
								$recoverFields = array('value', 'to_ids', 'distribution', 'category', 'type', 'comment', 'sharing_group_id');
								foreach ($recoverFields as $rF) if (!isset($attribute[$rF])) $data['Event']['Attribute'][$k][$rF] = $existingAttribute['Attribute'][$rF];
								$data['Event']['Attribute'][$k]['id'] = $existingAttribute['Attribute']['id'];
								// Check if the attribute's timestamp is bigger than the one that already exists.
								// If yes, it means that it's newer, so insert it. If no, it means that it's the same attribute or older - don't insert it, insert the old attribute.
								// Alternatively, we could unset this attribute from the request, but that could lead with issues if we decide that we want to start deleting attributes that don't exist in a pushed event.
								if (isset($data['Event']['Attribute'][$k]['timestamp'])) {
									if ($data['Event']['Attribute'][$k]['timestamp'] <= $existingAttribute['Attribute']['timestamp']) {
										unset($data['Event']['Attribute'][$k]);
										continue;
									}
								} else {
									$data['Event']['Attribute'][$k]['timestamp'] = $date;
								}
							}
						} else {
							$this->Attribute->create();
						}
					} else {
						$this->Attribute->create();
					}
					$data['Event']['Attribute'][$k]['event_id'] = $this->id;
					if ($data['Event']['Attribute'][$k]['distribution'] == 4) {
						$data['Event']['Attribute'][$k]['sharing_group_id'] = $this->SharingGroup->captureSG($data['Event']['Attribute'][$k]['SharingGroup'], $user);
					}
					if (!$this->Attribute->save($data['Event']['Attribute'][$k], array('fieldList' => $fieldList['Attribute']))) {
						$validationErrors['Attribute'][$k] = $this->Attribute->validationErrors;
						$attribute_short = (isset($data['Event']['Attribute'][$k]['category']) ? $data['Event']['Attribute'][$k]['category'] : 'N/A') . '/' . (isset($data['Event']['Attribute'][$k]['type']) ? $data['Event']['Attribute'][$k]['type'] : 'N/A') . ' ' . (isset($data['Event']['Attribute'][$k]['value']) ? $data['Event']['Attribute'][$k]['value'] : 'N/A');
						$this->Log->create();
						$this->Log->save(array(
							'org' => $user['Organisation']['name'],
							'model' => 'Attribute',
							'model_id' => 0,
							'email' => $user['email'],
							'action' => 'edit',
							'user_id' => $user['id'],
							'title' => 'Attribute dropped due to validation for Event ' . $this->id . ' failed: ' . $attribute_short,
							'change' => json_encode($this->Attribute->validationErrors),
						));
					}
				}
			}
			if (isset($data['Event']['Tag']) && $user['Role']['perm_tagger']) {
				foreach ($data['Event']['Tag'] as $tag) {
					$tag_id = $this->EventTag->Tag->captureTag($tag, $user);
					if ($tag_id) {
						$this->EventTag->attachTagToEvent($this->id, $tag_id);
					} else {
						// If we couldn't attach the tag it is most likely because we couldn't create it - which could have many reasons
						// However, if a tag couldn't be added, it could also be that the user is a tagger but not a tag editor
						// In which case if no matching tag is found, no tag ID is returned. Logging these is pointless as it is the correct behaviour.
						if ($user['Role']['perm_tag_editor']) {
							$this->Log->create();
							$this->Log->save(array(
								'org' => $user['Organisation']['name'],
								'model' => 'Event',
								'model_id' => $this->id,
								'email' => $user['email'],
								'action' => 'edit',
								'user_id' => $user['id'],
								'title' => 'Failed create or attach Tag ' . $tag['name'] . ' to the event.',
								'change' => ''
							));
						}
					}
				}
			}
			// if published -> do the actual publishing
			if ((!empty($data['Event']['published']) && 1 == $data['Event']['published'])) {
				// do the necessary actions to publish the event (email, upload,...)
				if (true != Configure::read('MISP.disablerestalert')) {
					$this->sendAlertEmailRouter($id, $user);
				}
				$this->publish($existingEvent['Event']['id']);
			}
			return true;
		}
		return $this->validationErrors;
	}

	// format has to be:
	// array('Event' => array(), 'Attribute' => array('ShadowAttribute' => array()), 'EventTag' => array(), 'ShadowAttribute' => array());
	public function savePreparedEvent($event) {
		unset($event['Event']['id']);
		$this->create();
		$this->save($event['Event']);
		$event['Event']['id'] = $this->id;
		$objects = array('Attribute', 'ShadowAttribute', 'EventTag');
		foreach ($objects as $object_type) {
			if (!empty($event[$object_type])) {
				$saveMethod = '__savePrepared' . $object_type;
				foreach ($event[$object_type] as $object) $this->$saveMethod($object, $event);
			}
		}
		return $event['Event']['id'];
	}

	// pass an event or an attribute together with the server id.
	// If the distribution of the object outright allows for it to be shared, return true
	// If the distribution is org only / comm only, return false
	// If the distribution is sharing group only, check if the sync user is in the sharing group or not, return true if yes, false if no
	public function checkDistributionForPush($object, $server, $context = 'Event') {
		if ($object[$context]['distribution'] < 2) return false;
		if ($object[$context]['distribution'] == 4) {
			if ($context === 'Event') {
				return $this->SharingGroup->checkIfServerInSG($object['SharingGroup'], $server);
			}
			else {
				return $this->SharingGroup->checkIfServerInSG($object[$context]['SharingGroup'], $server);
			}
		}
		return true;
	}

	/**
	 * Uploads this specific event to all remote servers
	 * TODO move this to a component
	 *
	 * @return bool true if success, false if, partly, failed
	 */
	public function uploadEventToServersRouter($id, $passAlong = null) {
		// make sure we have all the data of the Event
		$event = $this->find('first', array(
				'conditions' => array('Event.id' => $id),
				'recursive' => -1,
				'contain' => array(
						'Attribute' => array(
								'SharingGroup' => array(
										'SharingGroupOrg' => array(
											'fields' => array('id', 'org_id', 'extend'),
											'Organisation' => array(
												'fields' => array('id', 'uuid', 'name')
											)
										),
										'SharingGroupServer' => array(
											'fields' => array('id', 'server_id', 'all_orgs'),
											'Server' => array(
												'fields' => array('id', 'url', 'name')
											)
										),
								)
						),
						'EventTag' => array('Tag'),
						'Org' => array('fields' => array('id', 'uuid', 'name', 'local')),
						'Orgc' => array('fields' => array('id', 'uuid', 'name', 'local')),
						'SharingGroup' => array(
							'Organisation' => array(
								'fields' => array('id', 'uuid', 'name', 'local'),
							),
							'SharingGroupOrg' => array(
								'fields' => array('id', 'org_id', 'extend'),
								'Organisation' => array(
									'fields' => array('id', 'uuid', 'name')
								)
							),
							'SharingGroupServer' => array(
								'fields' => array('id', 'server_id', 'all_orgs'),
								'Server' => array(
									'fields' => array('id', 'url', 'name')
								)
							),
						),
				),
		));
		if (empty($event)) return true;

		if ($event['Event']['distribution'] < 2) return true;
		$event['Event']['locked'] = 1;
		// get a list of the servers
		$this->Server = ClassRegistry::init('Server');
		$conditions = array('push' => 1);
		if ($passAlong) $conditions[] = array('Server.id !=' => $passAlong);
		$servers = $this->Server->find('all', array('conditions' => $conditions));
		// iterate over the servers and upload the event
		if (empty($servers))
			return true;

		$uploaded = true;
		$failedServers = array();
		App::uses('SyncTool', 'Tools');
		foreach ($servers as &$server) {
			$syncTool = new SyncTool();
			$HttpSocket = $syncTool->setupHttpSocket($server);
			// Skip servers where the event has come from.
			if (($passAlong != $server)) {
				$thisUploaded = $this->uploadEventToServer($event, $server, $HttpSocket);
				if (!$thisUploaded) {
					$uploaded = !$uploaded ? $uploaded : $thisUploaded;
					$failedServers[] = $server['Server']['url'];
				}
				if (isset($this->data['ShadowAttribute'])) {
					$this->Server->syncProposals($HttpSocket, $server, null, $id, $this);
				}
			}
		}
		if (!$uploaded) {
			return $failedServers;
		} else {
			return true;
		}
	}

	public function publishRouter($id, $passAlong = null, $user) {
		if (Configure::read('MISP.background_jobs')) {
			$job = ClassRegistry::init('Job');
			$job->create();
			$data = array(
					'worker' => 'default',
					'job_type' => 'publish_event',
					'job_input' => 'Event ID: ' . $id,
					'status' => 0,
					'retries' => 0,
					'org_id' => $user['org_id'],
					'org' => $user['Organisation']['name'],
					'message' => 'Publishing.',
			);
			$job->save($data);
			$jobId = $job->id;
			$process_id = CakeResque::enqueue(
					'default',
					'EventShell',
					array('publish', $id, $passAlong, $jobId, $user['id'])
			);
			$job->saveField('process_id', $process_id);
			return $process_id;
		} else {
			$result = $this->publish($id, $passAlong);
			return $result;
		}
	}

	/**
	 * Performs all the actions required to publish an event
	 *
	 * @param unknown_type $id
	 */
	public function publish($id, $passAlong = null, $jobId = null) {
		$this->id = $id;
		$this->recursive = 0;
		$event = $this->read(null, $id);
		if ($jobId) {
			$this->Behaviors->unload('SysLogLogable.SysLogLogable');
		} else {
			// update the DB to set the published flag
			// for background jobs, this should be done already
			$fieldList = array('published', 'id', 'info', 'publish_timestamp');
			$event['Event']['published'] = 1;
			$event['Event']['publish_timestamp'] = time();
			$this->save($event, array('fieldList' => $fieldList));
		}
		if (Configure::read('Plugin.ZeroMQ_enable')) {
			App::uses('PubSubTool', 'Tools');
			$pubSubTool = new PubSubTool();
			$hostOrg = $this->Org->find('first', array('conditions' => array('name' => Configure::read('MISP.org')), 'fields' => array('id')));
			if (!empty($hostOrg)) {
				$user = array('org_id' => $hostOrg['Org']['id'], 'Role' => array('perm_sync' => false, 'perm_site_admin' => false), 'Organisation' => $hostOrg['Org']);
				$fullEvent = $this->fetchEvent($user, array('eventid' => $id));
				if (!empty($fullEvent)) $pubSubTool->publishEvent($fullEvent[0]);
			}
		}
		if ($event['Event']['distribution'] > 1) {
			$uploaded = $this->uploadEventToServersRouter($id, $passAlong);
		} else {
			return true;
		}
		return $uploaded;
	}


	/**
	 *
	 * Sends out an email to all people within the same org
	 * with the request to be contacted about a specific event.
	 * @todo move __sendContactEmail($id, $message) to a better place. (components?)
	 *
	 * @param unknown_type $id The id of the event for wich you want to contact the org.
	 * @param unknown_type $message The custom message that will be appended to the email.
	 * @param unknown_type $all, true: send to org, false: send to person.
	 *
	 * @codingStandardsIgnoreStart
	 * @throws \UnauthorizedException as well. // TODO Exception NotFoundException
	 * @codingStandardsIgnoreEnd
	 *
	 * @return True if success, False if error
	 */
	public function sendContactEmailRouter($id, $message, $creator_only, $user, $isSiteAdmin, $JobId = false) {
		if (Configure::read('MISP.background_jobs')) {
			$job = ClassRegistry::init('Job');
			$job->create();
			$data = array(
					'worker' => 'email',
					'job_type' => 'contact_alert',
					'job_input' => 'Owner ' . ($creator_only ? 'user' : 'org') . ' of event #' . $id,
					'status' => 0,
					'retries' => 0,
					'org_id' => $user['org_id'],
					'message' => 'Contacting.',
			);
			$job->save($data);
			$jobId = $job->id;
			$process_id = CakeResque::enqueue(
					'email',
					'EventShell',
					array('contactemail', $id, $message, $creator_only, $user['id'], $isSiteAdmin, $jobId)
			);
			$job->saveField('process_id', $process_id);
			return true;
		} else {
			$result = $this->sendContactEmail($id, $message, $creator_only, array('User' => $user), $isSiteAdmin);
			return $result;
		}
	}

	public function generateLocked() {
		$this->User = ClassRegistry::init('User');
		$this->User->recursive = -1;
		$localOrgs = array();
		$conditions = array();
		$orgs = $this->User->find('all', array('fields' => array('DISTINCT org_id')));
		foreach ($orgs as $k => $org) {
			$orgs[$k]['User']['count'] = $this->User->getOrgMemberCount($orgs[$k]['User']['org_id']);
			if ($orgs[$k]['User']['count'] > 1) {
				$localOrgs[] = $orgs[$k]['User']['org_id'];
				$conditions['AND'][] = array('orgc !=' => $orgs[$k]['User']['org_id']);
			} else if ($orgs[$k]['User']['count'] == 1) {
				// If we only have a single user for an org, check if that user is a sync user. If not, then it is a valid local org and the events created by him/her should be unlocked.
				$this->User->recursive = 1;
				$user = ($this->User->find('first', array(
						'fields' => array('id', 'role_id'),
						'conditions' => array('org_id' => $org['User']['org_id']),
						'contain' => array('Role' => array(
								'fields' => array('id', 'perm_sync'),
						))
				)));
				if (!$user['Role']['perm_sync']) {
					$conditions['AND'][] = array('orgc !=' => $orgs[$k]['User']['org_id']);
				}
			}
		}
		// Don't lock stuff that's already locked
		$conditions['AND'][] = array('locked !=' => true);
		$this->recursive = -1;
		$toBeUpdated = $this->find('count', array(
				'conditions' => $conditions
		));
		$this->updateAll(
				array('Event.locked' => 1),
				$conditions
		);
		return $toBeUpdated;
	}

	public function reportValidationIssuesEvents() {
		$this->Behaviors->detach('Regexp');
		// get all events..
		$events = $this->find('all', array('recursive' => -1));
		// for all events..
		$result = array();
		$k = 0;
		$i = 0;
		foreach ($events as $k => $event) {
			$this->set($event);
			if ($this->validates()) {
				// validates
			} else {
				$errors = $this->validationErrors;
				$result[$i]['id'] = $event['Event']['id'];
				$result[$i]['error'] = $errors;
				$result[$i]['details'] = $event;
				$i++;
			}
		}
		return array($result, $k);
	}

	public function generateThreatLevelFromRisk() {
		$risk = array('Undefined' => 4, 'Low' => 3, 'Medium' => 2, 'High' => 1);
		$events = $this->find('all', array('recursive' => -1));
		$k = 0;
		foreach ($events as $k => $event) {
			if ($event['Event']['threat_level_id'] == 0 && isset($event['Event']['risk'])) {
				$event['Event']['threat_level_id'] = $risk[$event['Event']['risk']];
				$this->save($event);
			}
		}
		return $k;
	}

	// check two version strings. If version 1 is older than 2, return -1, if they are the same return 0, if version 2 is older return 1
	public function compareVersions($version1, $version2) {
		$version1Array = explode('.', $version1);
		$version2Array = explode('.', $version2);

		if ($version1Array[0] != $version2Array[0]) {
			if ($version1Array[0] > $version2Array[0]) return 1;
			else return -1;
		}
		if ($version1Array[1] != $version2Array[1]) {
			if ($version1Array[1] > $version2Array[1]) return 1;
			else return -1;
		}
		if ($version1Array[2] != $version2Array[2]) {
			if ($version1Array[2] > $version2Array[2]) return 1;
			else return -1;
		}
	}

	// main dispatch method for updating an incoming xmlArray - pass xmlArray to all of the appropriate transformation methods to make all the changes necessary to save the imported event
	public function updateXMLArray($xmlArray, $response = true) {
		if (isset($xmlArray['xml_version']) && $response) {
			$xmlArray['response']['xml_version'] = $xmlArray['xml_version'];
			unset($xmlArray['xml_version']);
		}

		if (!$response) {
			$xmlArray = array('response' => $xmlArray);
		}
		// if a version is set, it must be at least 2.2.0 - check the version and save the result of the comparison
		if (isset($xmlArray['response']['xml_version'])) $version = $this->compareVersions($xmlArray['response']['xml_version'], $this->mispVersion);
		// if no version is set, set the version to older (-1) manually
		else $version = -1;
		// same version, proceed normally
		if ($version != 0) {
			// The xml is from an instance that is newer than the local instance, let the user know that the admin needs to upgrade before it could be imported
			if ($version == 1) throw new Exception('This XML file is from a MISP instance that is newer than the current instance. Please contact your administrator about upgrading this instance.');

			// if the xml contains an event or events from an older MISP instance, let's try to upgrade it!
			// Let's manually set the version to something below 2.2.0 if there is no version set in the xml
			if (!isset($xmlArray['response']['xml_version'])) $xmlArray['response']['xml_version'] = '2.1.0';

			// Upgrade from versions below 2.2.0 will need to replace the risk field with threat level id
			if ($this->compareVersions($xmlArray['response']['xml_version'], '2.2.0') < 0) {
				if ($response) $xmlArray['response'] = $this->__updateXMLArray220($xmlArray['response']);
				else $xmlArray = $this->__updateXMLArray220($xmlArray);
			}
		}
		unset($xmlArray['response']['xml_version']);
		if ($response) return $xmlArray;
		else return $xmlArray['response'];
	}

	// replaces the old risk value with the new threat level id
	private function __updateXMLArray220($xmlArray) {
		$risk = array('Undefined' => 4, 'Low' => 3, 'Medium' => 2, 'High' => 1);
		if (isset($xmlArray['Event'][0])) {
			foreach ($xmlArray['Event'] as &$event) {
				if (!isset($event['threat_level_id'])) {
					$event['threat_level_id'] = $risk[$event['risk']];
				}
			}
		} else {
			if (!isset($xmlArray['Event']['threat_level_id']) && isset($xmlArray['Event']['risk'])) {
				$xmlArray['Event']['threat_level_id'] = $risk[$xmlArray['Event']['risk']];
			}
		}
		return $xmlArray;
	}

	public function checkIfNewer($incomingEvent) {
		$localEvent = $this->find('first', array('conditions' => array('uuid' => $incomingEvent['uuid']), 'recursive' => -1, 'fields' => array('Event.uuid', 'Event.timestamp')));
		if (empty($localEvent) || $incomingEvent['timestamp'] > $localEvent['Event']['timestamp']) return true;
		return false;
	}

	public function removeOlder(&$eventArray) {
		$uuidsToCheck = array();
		foreach ($eventArray as $k => &$event) {
			$uuidsToCheck[$event['uuid']] = $k;
		}
		$localEvents = $this->find('list', array('recursive' => -1, 'fields' => array('Event.uuid', 'Event.timestamp')));
		foreach ($uuidsToCheck as $uuid => $eventArrayId) {
			if (isset($localEvents[$uuid]) && $localEvents[$uuid] >= $eventArray[$eventArrayId]['timestamp']) unset($eventArray[$eventArrayId]);
		}
	}

	public function stix($id, $tags, $attachments, $user, $returnType, $from = false, $to = false, $last = false) {
		$eventIDs = $this->Attribute->dissectArgs($id);
		$tagIDs = $this->Attribute->dissectArgs($tags);
		$idList = $this->getAccessibleEventIds($eventIDs[0], $eventIDs[1], $tagIDs[0], $tagIDs[1]);
		if (empty($idList)) throw new Exception('No matching events found to export.');
		$events = $this->fetchEvent($user, array('idList' => $idList, 'last' => $last, 'from' => $from, 'to' => $to));
		if (empty($events)) throw new Exception('No matching events found to export.');

		// If a second argument is passed (and it is either "yes", "true", or 1) base64 encode all of the attachments
		if ($attachments == "yes" || $attachments == "true" || $attachments == 1) {
			foreach ($events as &$event) {
				foreach ($event['Attribute'] as &$attribute) {
					if ($this->Attribute->typeIsAttachment($attribute['type'])) {
						$encodedFile = $this->Attribute->base64EncodeAttachment($attribute);
						$attribute['data'] = $encodedFile;
					}
				}
			}
		}
		if (Configure::read('MISP.tagging')) {
			foreach ($events as &$event) {
				$event['Tag'] = $this->EventTag->Tag->findEventTags($event['Event']['id']);
			}
		}
		// generate a randomised filename for the temporary file that will be passed to the python script
		$randomFileName = $this->generateRandomFileName();
		$tempFile = new File(APP . "files" . DS . "scripts" . DS . "tmp" . DS . $randomFileName, true, 0644);

		// save the json_encoded event(s) to the temporary file
		$result = $tempFile->write(json_encode($events));
		$scriptFile = APP . "files" . DS . "scripts" . DS . "misp2stix.py";

		// Execute the python script and point it to the temporary filename
		$result = shell_exec('python ' . $scriptFile . ' ' . $randomFileName . ' ' . $returnType . ' ' . Configure::read('MISP.baseurl') . ' "' . Configure::read('MISP.org') . '"');

		// The result of the script will be a returned JSON object with 2 variables: success (boolean) and message
		// If success = 1 then the temporary output file was successfully written, otherwise an error message is passed along
		$decoded = json_decode($result);
		$result = array();
		$result['success'] = $decoded->success;
		$result['message'] = $decoded->message;

		if ($result['success'] == 1) {
			$file = new File(APP . "files" . DS . "scripts" . DS . "tmp" . DS . $randomFileName . ".out");
			$result['data'] = $file->read();
		}
		$tempFile->delete();
		$file = new File(APP . "files" . DS . "scripts" . DS . "tmp" . DS . $randomFileName . ".out");
		$file->delete();
		return $result;
	}

	public function getAccessibleEventIds($include, $exclude, $includedTags, $excludedTags) {
		$conditions = array();

		// get all of the event IDs based on include / exclude
		if (!empty($include)) $conditions['OR'] = array('id' => $include);
		if (!empty($exclude)) $conditions['NOT'] = array('id' => $exclude);
		$events = $this->find('all', array(
			'recursive' => -1,
			'fields' => array('id', 'org_id', 'orgc_id', 'distribution'),
			'conditions' => $conditions
		));
		$ids = array();
		foreach ($events as $event) {
			$ids[] = $event['Event']['id'];
		}
		// get all of the event IDs based on includedTags / excludedTags
		if (!empty($includedTags) || !empty($excludedTags)) {
			$eventIDsFromTags = $this->EventTag->getEventIDsFromTags($includedTags, $excludedTags);
			// get the intersect of the two
			$ids = array_intersect($ids, $eventIDsFromTags);
		}
		return $ids;
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


	public function sharingGroupRequired($field) {
		if ($this->data[$this->alias]['distribution'] == 4) {
			return (!empty($field));
		}
		return true;
	}

	// convenience method to check whther a user can see an event
	public function checkIfAuthorised($user, $id) {
		if (!isset($user['id'])) throw new MethodNotAllowedException('Invalid user.');
		$this->id = $id;
		if (!$this->exists()) return false;
		if ($user['Role']['perm_site_admin']) return true;
		$event = $this->find('first', array(
			'conditions' => array('id' => $id),
			'recursive' => -1,
			'fields' => array('id', 'sharing_group_id', 'distribution', 'org_id')
		));
		if ($event['Event']['org_id'] == $user['org_id'] || ($event['Event']['distribution'] > 0 && $event['Event']['distribution'] < 4)) return true;
		if ($event['Event']['distribution'] == 4 && $this->SharingGroup->checkIfAuthorised($user, $event['Event']['sharing_group_id'])) return true;
		return false;
	}

	// expects a date string in the YYYY-MM-DD format
	// returns the passed string or false if the format is invalid
	// based on the fix provided by stevengoosensB
	public function dateFieldCheck($date) {
		// regex check for from / to field by stevengoossensB
		return (preg_match('/^[0-9]{4}-(0[1-9]|1[012])-(0[1-9]|1[0-9]|2[0-9]|3[01])$/', $date)) ? $date : false;
	}

	public function resolveTimeDelta($delta) {
		$multiplierArray = array('d' => 86400, 'h' => 3600, 'm' => 60);
		$multiplier = $multiplierArray['d'];
		$lastChar = strtolower(substr($delta, -1));
		if (!is_numeric($lastChar) && array_key_exists($lastChar, $multiplierArray)) {
			$multiplier = $multiplierArray[$lastChar];
			$delta = substr($delta, 0, -1);
		}
		if (!is_numeric($delta)) return false;
		return time() - ($delta * $multiplier);
	}

	public function rearrangeEventForView(&$event, $passedArgs = array(), $all = false) {
		$fTool = new FinancialTool();
		foreach ($event['Event'] as $k => $v) {
			if (is_array($v)) {
				$event[$k] = $v;
				unset($event['Event'][$k]);
			}
		}
		$filterType = false;
		if (isset($passedArgs['attributeFilter'])) {
			if (in_array($passedArgs['attributeFilter'], array_keys($this->Attribute->typeGroupings)) || in_array($passedArgs['attributeFilter'], array('proposal', 'correlation', 'warning'))) {
				$filterType = $passedArgs['attributeFilter'];
			} else {
				unset($passedArgs['attributeFilter']);
			}
		}
		$eventArray = array();
		$correlatedAttributes = isset($event['RelatedAttribute']) ? array_keys($event['RelatedAttribute']) : array();
		$correlatedShadowAttributes = isset($event['RelatedShadowAttribute']) ? array_keys($event['RelatedShadowAttribute']) : array();
		foreach ($event['Attribute'] as $attribute) {
			if ($filterType && !in_array($filterType, array('proposal', 'correlation', 'warning'))) if (!in_array($attribute['type'], $this->Attribute->typeGroupings[$filterType])) continue;
			if (isset($attribute['distribution']) && $attribute['distribution'] != 4) unset($attribute['SharingGroup']);
			$attribute['objectType'] = 0;
			if (!empty($attribute['ShadowAttribute'])) $attribute['hasChildren'] = 1;
			else $attribute['hasChildren'] = 0;
			if ($filterType === 'proposal' && $attribute['hasChildren'] == 0) continue;
			if ($filterType === 'correlation' && !in_array($attribute['id'], $correlatedAttributes)) continue;
			$eventArray[] = $attribute;
		}
		unset($event['Attribute']);
		if (isset($event['ShadowAttribute'])) {
			foreach ($event['ShadowAttribute'] as $shadowAttribute) {
				if ($filterType === 'correlation' && !in_array($shadowAttribute['id'], $correlatedShadowAttributes)) continue;
				if ($filterType && !in_array($filterType, array('proposal', 'correlation', 'warning'))) if (!in_array($attribute['type'], $this->Attribute->typeGroupings[$filterType])) continue;
				$shadowAttribute['objectType'] = 2;
				$eventArray[] = $shadowAttribute;
			}
		}
		unset($event['ShadowAttribute']);
		App::uses('CustomPaginationTool', 'Tools');
		$customPagination = new CustomPaginationTool();
		if ($all) $passedArgs['page'] = 0;
		$eventArrayWithProposals = array();

		foreach ($eventArray as $k => &$object) {
			if ($object['category'] === 'Financial fraud') {
				if (!$fTool->validateRouter($object['type'], $object['value'])) {
					$object['validationIssue'] = true;
				}
			}
			if ($object['objectType'] == 0) {
				if (isset($object['ShadowAttribute'])) {
					$shadowAttributeTemp = $object['ShadowAttribute'];
					unset($object['ShadowAttribute']);
					$eventArrayWithProposals[] = $object;
					foreach ($shadowAttributeTemp as $kk => $shadowAttribute) {
						$shadowAttribute['objectType'] = 1;
						if ($kk == 0) $shadowAttribute['firstChild'] = true;
						if (($kk + 1) == count($shadowAttributeTemp)) $shadowAttribute['lastChild'] = true;
						$eventArrayWithProposals[] = $shadowAttribute;
					}
				} else {
					$eventArrayWithProposals[] = $object;
				}
			} else {
				$eventArrayWithProposals[] = $object;
			}
			unset($eventArray[$k]);
		}
		$event['objects'] = $eventArrayWithProposals;
		$this->Warninglist = ClassRegistry::init('Warninglist');
		$warningLists = $this->Warninglist->fetchForEventView();
		if (!empty($warningLists)) $event = $this->Warninglist->setWarnings($event, $warningLists);
		if ($filterType && $filterType == 'warning') {
			foreach ($event['objects'] as $k => &$object) if (empty($object['warnings'])) unset($event['objects'][$k]);
			$event['objects'] = array_values($event['objects']);
		}
		$params = $customPagination->applyRulesOnArray($event['objects'], $passedArgs, 'events', 'category');
		return $params;
	}

	// pass along a json from the server filter rules
	// returns a conditions set to be merged into pagination / event fetch / etc
	public function filterRulesToConditions($rules) {
		$rules = json_decode($rules, true);
		$operators = array('OR', 'NOT');
		foreach ($operators as $op) {
			if (!empty($rules['tags'][$op])) {
				$event_ids = $this->EventTag->find('list', array(
					'recursive' => -1,
					'conditions' => array('EventTag.tag_id' => $rules['tags'][$op]),
					'fields' => array('EventTag.event_id')
				));
				$rules['events'][$op] = $event_ids;
			}
		}
		$conditions = array();
		$fields = array('events' => 'Event.id', 'orgs' => 'Event.orgc_id');
		foreach ($fields as $k => $field) {
			$temp = array();
			if (!empty($rules[$k]['OR'])) $temp['OR'][$field] = $rules[$k]['OR'];
			if (!empty($rules[$k]['NOT'])) $temp['AND'][$field . ' !='] = $rules[$k]['NOT'];
			$conditions['AND'][] = $temp;
		}
		return $conditions;
	}
}
