<?php
App::uses('AppModel', 'Model');
App::uses('CakeEmail', 'Network/Email');
App::uses('RandomTool', 'Tools');
Configure::load('config'); // This is needed to load GnuPG.bodyonlyencrypted

class Event extends AppModel {

	public $actsAs = array(
		'SysLogLogable.SysLogLogable' => array(
			'userModel' => 'User',
			'userKey' => 'user_id',
			'change' => 'full'),
		'Trim',
		'Containable',
	);

	public $displayField = 'id';

	public $virtualFields = array();

	public $mispVersion = '2.4.0';

	public $fieldDescriptions = array(
		'threat_level_id' => array('desc' => 'Risk levels: *low* means mass-malware, *medium* means APT malware, *high* means sophisticated APT malware or 0-day attack', 'formdesc' => 'Risk levels: low: mass-malware medium: APT malware high: sophisticated APT malware or 0-day attack'),
		'classification' => array('desc' => 'Set the Traffic Light Protocol classification. <ol><li><em>TLP:AMBER</em>- Share only within the organization on a need-to-know basis</li><li><em>TLP:GREEN:NeedToKnow</em>- Share within your constituency on the need-to-know basis.</li><li><em>TLP:GREEN</em>- Share within your constituency.</li></ol>'),
		'submittedgfi' => array('desc' => 'GFI sandbox: export upload', 'formdesc' => 'GFI sandbox: export upload'),
		'submittedioc' => array('desc' => '', 'formdesc' => ''),
		'analysis' => array('desc' => 'Analysis Levels: *Initial* means the event has just been created, *Ongoing* means that the event is being populated, *Complete* means that the event\'s creation is complete', 'formdesc' => 'Analysis levels: Initial: event has been started Ongoing: event population is in progress Complete: event creation has finished'),
		'distribution' => array('desc' => 'Describes who will have access to the event.')
	);

	public $analysisDescriptions = array(
		0 => array('desc' => '*Initial* means the event has just been created', 'formdesc' => 'Event has just been created and is in an initial state'),
		1 => array('desc' => '*Ongoing* means that the event is being populated', 'formdesc' => 'The analysis is still ongoing'),
		2 => array('desc' => '*Complete* means that the event\'s creation is complete', 'formdesc' => 'The event creator considers the analysis complete')
	);

	public $distributionDescriptions = array(
		0 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "This setting will only allow members of your organisation on this server to see it."),
		1 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "Organisations that are part of this MISP community will be able to see the event."),
		2 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "Organisations that are either part of this MISP community or part of a directly connected MISP community will be able to see the event."),
		3 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "This will share the event with all MISP communities, allowing the event to be freely propagated from one server to the next."),
		4 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "This distribution of this event will be handled by the selected sharing group."),

	);

	public $analysisLevels = array(
		0 => 'Initial', 1 => 'Ongoing', 2 => 'Completed'
	);

	public $distributionLevels = array(
		0 => 'Your organisation only', 1 => 'This community only', 2 => 'Connected communities', 3 => 'All communities', 4 => 'Sharing group'
	);

	private $__fTool = false;

	public $shortDist = array(0 => 'Organisation', 1 => 'Community', 2 => 'Connected', 3 => 'All', 4 => ' sharing Group');

	private $__assetCache = array();

	public $export_types = array(
			'json' => array(
					'extension' => '.json',
					'type' => 'JSON',
					'requiresPublished' => 0,
					'canHaveAttachments' => true,
					'description' => 'Click this to download all events and attributes that you have access to in MISP JSON format.',
			),
			'xml' => array(
					'extension' => '.xml',
					'type' => 'XML',
					'requiresPublished' => 0,
					'canHaveAttachments' => true,
					'description' => 'Click this to download all events and attributes that you have access to in MISP XML format.',
			),
			'csv_sig' => array(
					'extension' => '.csv',
					'type' => 'CSV_Sig',
					'requiresPublished' => 1,
					'canHaveAttachments' => false,
					'description' => 'Click this to download all attributes that are indicators and that you have access to <small>(except file attachments)</small> in CSV format.',
			),
			'csv_all' => array(
					'extension' => '.csv',
					'type' => 'CSV_All',
					'requiresPublished' => 0,
					'canHaveAttachments' => false,
					'description' => 'Click this to download all attributes that you have access to <small>(except file attachments)</small> in CSV format.',
			),
			'suricata' => array(
					'extension' => '.rules',
					'type' => 'Suricata',
					'requiresPublished' => 1,
					'canHaveAttachments' => false,
					'description' => 'Click this to download all network related attributes that you have access to under the Suricata rule format. Only published events and attributes marked as IDS Signature are exported. Administration is able to maintain a whitelist containing host, domain name and IP numbers to exclude from the NIDS export.',
			),
			'snort' => array(
					'extension' => '.rules',
					'type' => 'Snort',
					'requiresPublished' => 1,
					'canHaveAttachments' => false,
					'description' => 'Click this to download all network related attributes that you have access to under the Snort rule format. Only published events and attributes marked as IDS Signature are exported. Administration is able to maintain a whitelist containing host, domain name and IP numbers to exclude from the NIDS export.',
			),
			'bro' => array(
					'extension' => '.intel',
					'type' => 'Bro',
					'requiresPublished' => 1,
					'canHaveAttachments' => false,
					'description' => 'Click this to download all network related attributes that you have access to under the Bro rule format. Only published events and attributes marked as IDS Signature are exported. Administration is able to maintain a whitelist containing host, domain name and IP numbers to exclude from the NIDS export.',
			),
			'stix' => array(
					'extension' => '.xml',
					'type' => 'STIX',
					'requiresPublished' => 1,
					'canHaveAttachments' => true,
					'description' => 'Click this to download an a STIX document containing the STIX version of all events and attributes that you have access to.'
			),
			'rpz' => array(
					'extension' => '.txt',
					'type' => 'RPZ',
					'requiresPublished' => 1,
					'canHaveAttachments' => false,
					'description' => 'Click this to download an RPZ Zone file generated from all ip-src/ip-dst, hostname, domain attributes. This can be useful for DNS level firewalling. Only published events and attributes marked as IDS Signature are exported.'
			),
			'md5' => array(
					'extension' => '.txt',
					'type' => 'MD5',
					'requiresPublished' => 1,
					'canHaveAttachments' => false,
					'description' => 'Click on one of these two buttons to download all MD5 checksums contained in file-related attributes. This list can be used to feed forensic software when searching for susipicious files. Only published events and attributes marked as IDS Signature are exported.',
			),
			'sha1' => array(
					'extension' => '.txt',
					'type' => 'SHA1',
					'requiresPublished' => 1,
					'canHaveAttachments' => false,
					'description' => 'Click on one of these two buttons to download all SHA1 checksums contained in file-related attributes. This list can be used to feed forensic software when searching for susipicious files. Only published events and attributes marked as IDS Signature are exported.',
			),
			'sha256' => array(
					'extension' => '.txt',
					'type' => 'SHA256',
					'requiresPublished' => 1,
					'canHaveAttachments' => false,
					'description' => 'Click on one of these two buttons to download all SHA256 checksums contained in file-related attributes. This list can be used to feed forensic software when searching for susipicious files. Only published events and attributes marked as IDS Signature are exported.',
			),
			'text' => array(
					'extension' => '.txt',
					'type' => 'TEXT',
					'requiresPublished' => 1,
					'canHaveAttachments' => false,
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
				'rule' => array('custom', '/^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/'),
				'message' => 'Please provide a valid UUID'
			),
		),
	);

	public function __construct($id = false, $table = null, $ds = null) {
		parent::__construct($id, $table, $ds);
	}

	// The Associations below have been created with all possible keys, those that are not needed can be removed

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
		'Object' => array(
			'className' => 'MispObject',
			'foreignKey' => 'event_id',
			'dependent' => true,
			'conditions' => '',
			'fields' => '',
			'order' => false,
			'limit' => '',
			'offset' => '',
			'exclusive' => '',
			'finderQuery' => '',
			'counterQuery' => ''
		),
		'EventTag' => array(
			'className' => 'EventTag',
			'dependent' => true,
		),
		'Sighting' => array(
			'className' => 'Sighting',
			'dependent' => true,
		)
	);

	public function beforeDelete($cascade = true) {
		// blacklist the event UUID if the feature is enabled
		if (Configure::read('MISP.enableEventBlacklisting') !== false) {
			$this->EventBlacklist = ClassRegistry::init('EventBlacklist');
			$this->EventBlacklist->create();
			$orgc = $this->Orgc->find('first', array('conditions' => array('Orgc.id' => $this->data['Event']['orgc_id']), 'recursive' => -1, 'fields' => array('Orgc.name')));
			$this->EventBlacklist->save(array('event_uuid' => $this->data['Event']['uuid'], 'event_info' => $this->data['Event']['info'], 'event_orgc' => $orgc['Orgc']['name']));
			if (!empty($this->data['Event']['id'])) {
				if (Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_attribute_notifications_enable')) {
					$pubSubTool = $this->getPubSubTool();
					$pubSubTool->event_save(array('Event' => $this->data['Event']), 'delete');
				}
			}
		}

		// delete all of the event->tag combinations that involve the deleted event
		$this->EventTag->deleteAll(array('event_id' => $this->id));

		// only delete the file if it exists
		$attachments_dir = Configure::read('MISP.attachments_dir');
		if (empty($attachments_dir)) {
			$my_server = ClassRegistry::init('Server');
			$attachments_dir = $my_server->getDefaultAttachments_dir();
		}
		$filepath = $attachments_dir . DS . $this->id;
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
		} else {
			$this->data['Event']['analysis'] = 0;
		}
		if (!isset($this->data['Event']['threat_level_id'])) $this->data['Event']['threat_level_id'] = Configure::read('MISP.default_event_threat_level') ? Configure::read('MISP.default_event_threat_level') : 4;

		// generate UUID if it doesn't exist
		if (empty($this->data['Event']['uuid'])) {
			$this->data['Event']['uuid'] = CakeText::uuid();
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
			if (isset($this->data['Event']['date'])) {
				$this->Correlation->updateAll(array('Correlation.date' => $db->value($this->data['Event']['date'])), array('Correlation.event_id' => intval($this->data['Event']['id'])));
			}
			if (isset($this->data['Event']['info'])) {
				$this->Correlation->updateAll(array('Correlation.info' => $db->value($this->data['Event']['info'])), array('Correlation.event_id' => intval($this->data['Event']['id'])));
			}
		}
		if (empty($this->data['Event']['unpublishAction']) && empty($this->data['Event']['skip_zmq']) && Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_event_notifications_enable')) {
			$pubSubTool = $this->getPubSubTool();
			$event = $this->quickFetchEvent($this->data['Event']['id']);
			if (!empty($event)) $pubSubTool->event_save($event, $created ? 'add' : 'edit');
		}
	}

	public function buildEventConditions($user) {
		$conditions = array();
		if ($user['Role']['perm_site_admin']) {
			return $conditions;
		}
		$sgids = $this->SharingGroup->fetchAllAuthorised($user);
		$conditions['OR'] = array(
			'Event.orgc_id' => $user['org_id'],
			'Event.distribution' => array(1, 2, 3),
			'AND' => array(
				'Event.distribution' => 4,
				'Event.sharing_group_id' => $sgids
			)
		);
		return $conditions;
	}

	public function isOwnedByOrg($eventid, $org) {
		return $this->field('id', array('id' => $eventid, 'org_id' => $org)) === $eventid;
	}

	public function attachtagsToEvents($events) {
		$tagsToFetch = array();
		foreach ($events as $k => $event) {
			if (!empty($event['EventTag'])) {
				foreach ($event['EventTag'] as $et) {
					$tagsToFetch[$et['tag_id']] = $et['tag_id'];
				}
			}
		}
		$tags = $this->EventTag->Tag->find('all', array(
			'conditions' => array('Tag.id' => $tagsToFetch),
			'recursive' => -1,
			'order' => false
		));
		$tags = Set::combine($tags, '{n}.Tag.id', '{n}');
		foreach ($events as $k => $event) {
			if (!empty($event['EventTag'])) {
				foreach ($event['EventTag'] as $k2 => $et) {
					$events[$k]['EventTag'][$k2]['Tag'] = $tags[$et['tag_id']]['Tag'];
				}
			}
		}
		return $events;
	}

	// gets the logged in user + an array of events, attaches the correlation count to each
	public function attachCorrelationCountToEvents($user, $events) {
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
		return $events;
	}

	public function attachSightingsCountToEvents($user, $events) {
		$eventIds = Set::extract('/Event/id', $events);
		$this->Sighting = ClassRegistry::init('Sighting');
		$sightings = $this->Sighting->find('all', array(
			'fields' => array('Sighting.event_id', 'count(distinct(Sighting.id)) as count'),
			'conditions' => array('event_id' => $eventIds),
			'recursive' => -1,
			'group' => array('event_id')
		));
		$sightings = Hash::combine($sightings, '{n}.Sighting.event_id', '{n}.0.count');
		foreach ($events as $key => $event) {
			$events[$key]['Event']['sightings_count'] = (isset($sightings[$event['Event']['id']])) ? $sightings[$event['Event']['id']] : 0;
		}
		return $events;
	}

	public function attachProposalsCountToEvents($user, $events) {
		$eventIds = Set::extract('/Event/id', $events);
		$proposals = $this->ShadowAttribute->find('all', array(
				'fields' => array('ShadowAttribute.event_id', 'count(distinct(ShadowAttribute.id)) as count'),
				'conditions' => array('event_id' => $eventIds, 'deleted' => 0),
				'recursive' => -1,
				'group' => array('event_id')
		));
		$proposals = Hash::combine($proposals, '{n}.ShadowAttribute.event_id', '{n}.0.count');
		foreach ($events as $key => $event) {
			$events[$key]['Event']['proposals_count'] = (isset($proposals[$event['Event']['id']])) ? $proposals[$event['Event']['id']] : 0;
		}
		return $events;
	}

	public function attachDiscussionsCountToEvents($user, $events) {
		$eventIds = Set::extract('/Event/id', $events);
		$this->Thread = ClassRegistry::init('Thread');
		$threads = $this->Thread->find('list', array(
			'conditions' => array('Thread.event_id' => $eventIds),
			'fields' => array('Thread.event_id', 'Thread.id')
		));
		$posts = $this->Thread->Post->find('all', array(
			'conditions' => array('Post.thread_id' => $threads),
			'recursive' => -1,
			'fields' => array('Count(id) AS post_count', 'thread_id', 'max(date_modified) as last_post'),
			'group' => array('Post.thread_id')
		));
		$event_threads = array();
		foreach ($posts as $k => $v) {
			foreach ($threads as $k2 => $v2) {
				if ($v2 == $v['Post']['thread_id']) {
					$event_threads[$k2] = array(
						'post_count' => $v[0]['post_count'],
						'last_post' => strtotime($v[0]['last_post'])
					);
				}
			}
		}
		foreach ($events as $k => $v) {
			$events[$k]['Event']['post_count'] = !empty($event_threads[$events[$k]['Event']['id']]) ? $event_threads[$events[$k]['Event']['id']]['post_count'] : 0;
			$events[$k]['Event']['last_post'] = !empty($event_threads[$events[$k]['Event']['id']]) ? $event_threads[$events[$k]['Event']['id']]['last_post'] : 0;

		}
		return $events;
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
		$correlations = $this->Correlation->find('list', array(
				'fields' => array('Correlation.event_id', 'Correlation.event_id'),
				'conditions' => $conditionsCorrelation,
				'recursive' => 0,
				'group' => 'Correlation.event_id',
				'order' => array('Correlation.event_id DESC')));

		$relatedEventIds = array_values($correlations);
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
		$fieldsToRearrange = array('Org', 'Orgc');
		foreach ($relatedEvents as $k => $relatedEvent) {
			foreach ($fieldsToRearrange as $field) {
				if (isset($relatedEvent[$field])) {
					$relatedEvents[$k]['Event'][$field] = $relatedEvent[$field];
					unset($relatedEvents[$k][$field]);
				}
			}
		}
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
		$max_correlations = Configure::read('MISP.max_correlations_per_event');
		if (empty($max_correlations)) $max_correlations = 5000;
		$correlations = $this->{$settings[$context]['correlationModel']}->find('all',array(
				'fields' => $settings[$context]['correlationModel'] . '.*',
				'conditions' => $conditionsCorrelation,
				'recursive' => -1,
				'order' => false,
				'limit' => $max_correlations
		));
		$relatedAttributes = array();
		foreach ($correlations as $k => $correlation) {
			$current = array(
					'id' => $correlation[$settings[$context]['correlationModel']]['event_id'],
					'org_id' => $correlation[$settings[$context]['correlationModel']]['org_id'],
					'info' => $correlation[$settings[$context]['correlationModel']]['info'],
					'value' => $correlation[$settings[$context]['correlationModel']]['value'],
			);
			if (empty($relatedAttributes[$correlation[$settings[$context]['correlationModel']][$settings[$context]['parentIdField']]]) || !in_array($current, $relatedAttributes[$correlation[$settings[$context]['correlationModel']][$settings[$context]['parentIdField']]])) {
				$relatedAttributes[$correlation[$settings[$context]['correlationModel']][$settings[$context]['parentIdField']]][] = $current;
			}
			unset($correlations[$k]);
		}
		return $relatedAttributes;
	}

	/**
	 * Clean up an Event Array that was received by an XML request.
	 * The structure needs to be changed a little bit to be compatible with what CakePHP expects
	 *
	 * This function receives the reference of the variable, so no return is required as it directly
	 * modifies the original data.
	 */
	public function cleanupEventArrayFromXML(&$data) {
		$objects = array('Attribute', 'ShadowAttribute', 'Object');
		foreach ($objects as $object) {
			// Workaround for different structure in XML/array than what CakePHP expects
			if (isset($data['Event'][$object]) && is_array($data['Event'][$object]) && count($data['Event'][$object])) {
				if (!is_numeric(implode(array_keys($data['Event'][$object]), ''))) {
					// single attribute
					$data['Event'][$object] = array(0 => $data['Event'][$object]);
				}
				$data['Event'][$object] = array_values($data['Event'][$object]);
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
		$push = $this->Server->checkVersionCompatibility($server['Server']['id'], false, $HttpSocket);
		if (!isset($push['canPush'])) {
			$test = $this->Server->checkLegacyServerSyncPrivilege($server['Server']['id'], $HttpSocket);
		} else {
			if (!$push['canPush']) {
				return 'The remote user is not a sync user - the upload of the event has been blocked.';
			}
		}
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
			return 'Trying to push to an outdated instance.';
		}
		if (isset($server['Server']['unpublish_event'])) {
			$unpublish_event = $server['Server']['unpublish_event'];
			if ($unpublish_event) {
				$event['Event']['published'] = 0;
			}
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
			try {
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

	public function addHeaders($request) {
		$version = $this->checkMISPVersion();
		$version = implode('.', $version);
		try {
			$commit = trim(shell_exec('git log --pretty="%H" -n1 HEAD'));
		} catch (Exception $e) {
			$commit = false;
		}
		$request['header']['MISP-version'] = $version;
		if ($commit) {
			$request['header']['commit'] = $commit;
		}
		return $request;
	}

	// Uploads the event and the associated Attributes to another Server
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
		$request = $this->addHeaders($request);
		$uri = $url . '/events';
		if (isset($urlPath)) {
			$pieces = explode('/', $urlPath);
			$uri .= '/' . end($pieces);
		}
		$data = json_encode($event);
		// LATER validate HTTPS SSL certificate
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

	private function __updateEventForSync($event, $server) {
		// rearrange things to be compatible with the Xml::fromArray()
		$objectsToRearrange = array('Attribute', 'Object', 'Orgc', 'SharingGroup', 'EventTag', 'Org', 'ShadowAttribute');
		foreach ($objectsToRearrange as $o) {
			if (isset($event[$o])) {
				$event['Event'][$o] = $event[$o];
				unset($event[$o]);
			}
		}

		// cleanup the array from things we do not want to expose
		foreach (array('Org', 'org_id', 'orgc_id', 'proposal_email_lock', 'org', 'orgc') as $field) unset($event['Event'][$field]);
		foreach ($event['Event']['EventTag'] as $kt => $tag) {
			if (!$tag['Tag']['exportable']) {
				unset($event['Event']['EventTag'][$kt]);
			} else {
				unset($tag['org_id']);
				$event['Event']['Tag'][] = $tag['Tag'];
			}
		}
		unset($event['Event']['EventTag']);

		// Add the local server to the list of instances in the SG
		if (isset($event['Event']['SharingGroup']) && isset($event['Event']['SharingGroup']['SharingGroupServer'])) {
			foreach ($event['Event']['SharingGroup']['SharingGroupServer'] as &$s) {
				if ($s['server_id'] == 0) {
					$s['Server'] = array('id' => 0, 'url' => Configure::read('MISP.baseurl'));
				}
			}
		}

		// prepare attribute for sync
		if (!empty($event['Event']['Attribute'])) {
			foreach ($event['Event']['Attribute'] as $key => $attribute) {
				$event['Event']['Attribute'][$key] = $this->__updateAttributeForSync($attribute, $server);
				if (empty($event['Event']['Attribute'][$key])) unset($event['Event']['Attribute'][$key]);
			}
		}

		// prepare Object for sync
		if (!empty($event['Event']['Object'])) {
			foreach ($event['Event']['Object'] as $key => $object) {
				$event['Event']['Object'][$key] = $this->__updateObjectForSync($object, $server);
				if (empty($event['Event']['Object'][$key])) unset($event['Event']['Object'][$key]);
			}
		}

		// Downgrade the event from connected communities to community only
		if (!$server['Server']['internal'] && $event['Event']['distribution'] == 2) {
			$event['Event']['distribution'] = 1;
		}
		if (!empty($event['Event']['Attribute'])) $event['Event']['Attribute'] = array_values($event['Event']['Attribute']);
		if (!empty($event['Event']['Object'])) $event['Event']['Object'] = array_values($event['Event']['Object']);
		return $event;
	}

	private function __updateObjectForSync($object, $server) {
		if (!$server['Server']['internal'] && $object['distribution'] < 2) {
			return false;
		}
		// Downgrade the object from connected communities to community only
		if (!$server['Server']['internal'] && $object['distribution'] == 2) {
			$object['distribution'] = 1;
		}
		// If the object has a sharing group attached, make sure it can be transfered
		if ($object['distribution'] == 4) {
			if (!$server['Server']['internal'] && $this->checkDistributionForPush(array('Object' => $object), $server, 'Object') === false) {
				return false;
			}
			// Add the local server to the list of instances in the SG
			if (isset($object['SharingGroup']['SharingGroupServer'])) {
				foreach ($object['SharingGroup']['SharingGroupServer'] as &$s) {
					if ($s['server_id'] == 0) {
						$s['Server'] = array('id' => 0, 'url' => Configure::read('MISP.baseurl'));
					}
				}
			}
		}
		if (!empty($object['Attribute'])) {
			foreach ($object['Attribute'] as $key => $attribute) {
				$object['Attribute'][$key] = $this->__updateAttributeForSync($attribute, $server);
				if (empty($object['Attribute'][$key])) unset($object['Attribute'][$key]);
			}
		}
		return $object;
	}

	private function __updateAttributeForSync($attribute, $server) {
		// do not keep attributes that are private, nor cluster
			if (!$server['Server']['internal'] && $attribute['distribution'] < 2) {
				return false;
			}
			// Downgrade the attribute from connected communities to community only
			if (!$server['Server']['internal'] && $attribute['distribution'] == 2) {
				$attribute['distribution'] = 1;
			}

			// If the attribute has a sharing group attached, make sure it can be transfered
			if ($attribute['distribution'] == 4) {
				if (!$server['Server']['internal'] && $this->checkDistributionForPush(array('Attribute' => $attribute), $server, 'Attribute') === false) {
					return false;
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
			foreach ($attribute['AttributeTag'] as $kt => $tag) {
				if (!$tag['Tag']['exportable']) {
					unset($attribute['AttributeTag'][$kt]);
				} else {
					unset($tag['Tag']['org_id']);
					$attribute['Tag'][] = $tag['Tag'];
				}
			}
			unset($attribute['AttributeTag']);

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
			return $attribute;
	}

	public function downloadEventFromServer($eventId, $server, $HttpSocket=null) {
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
		$request = $this->addHeaders($request);
		$uri = $url . '/events/view/' . $eventId . '/deleted:true';
		$response = $HttpSocket->get($uri, $data = '', $request);
		if ($response->isOk()) {
			return json_decode($response->body, true);
		}
		return null;
	}

	public function quickDelete($event) {
		$id = $event['Event']['id'];
		$this->Thread = ClassRegistry::init('Thread');
		$thread = $this->Thread->find('first', array(
			'conditions' => array('Thread.event_id' => $id),
			'fields' => array('Thread.id'),
			'recursive' => -1
		));
		$thread_id = !empty($thread) ? $thread['Thread']['id'] : false;
		$relations = array(
			array(
				'table' => 'attributes',
				'foreign_key' => 'event_id',
				'value' => $id
			),
			array(
				'table' => 'shadow_attributes',
				'foreign_key' => 'event_id',
				'value' => $id
			),
			array(
				'table' => 'event_tags',
				'foreign_key' => 'event_id',
				'value' => $id
			),
			array(
				'table' => 'attribute_tags',
				'foreign_key' => 'event_id',
				'value' => $id
			),
			array(
				'table' => 'threads',
				'foreign_key' => 'event_id',
				'value' => $id
			),
			array(
				'table' => 'correlations',
				'foreign_key' => 'event_id',
				'value' => $id
			),
			array(
				'table' => 'correlations',
				'foreign_key' => '1_event_id',
				'value' => $id
			),
			array(
				'table' => 'sightings',
				'foreign_key' => 'event_id',
				'value' => $id
			),
			array(
				'table' => 'event_delegations',
				'foreign_key' => 'event_id',
				'value' => $id
			),
			array(
				'table' => 'objects',
				'foreign_key' => 'event_id',
				'value' => $id
			),
			array(
				'table' => 'object_references',
				'foreign_key' => 'event_id',
				'value' => $id
			)
		);
		if ($thread_id) {
			$relations[] = 	array(
				'table' => 'posts',
				'foreign_key' => 'thread_id',
				'value' => $thread_id
			);
		}
		App::uses('QueryTool', 'Tools');
		$queryTool = new QueryTool();
		foreach ($relations as $relation) {
				$queryTool->quickDelete($relation['table'], $relation['foreign_key'], $relation['value'], $this);
		}
		return $this->delete($id, false);
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
		$request = $this->addHeaders($request);
		$uri = $url . '/shadow_attributes/getProposalsByUuidList';
		$response = $HttpSocket->post($uri, json_encode($uuidList), $request);
		if ($response->isOk()) {
			return(json_decode($response->body, true));
		} else {
			return false;
		}
	}

	private function __createEventConditions($user) {
		$conditions = array();
		if (!$user['Role']['perm_site_admin']) {
			$sgids = $this->cacheSgids($user, true);
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
		return $conditions;
	}

	public function fetchSimpleEventIds($user, $params = array()) {
		$conditions = $this->__createEventConditions($user);
		$conditions['AND'][] = $params['conditions'];
		$results = array_values($this->find('list', array(
			'conditions' => $conditions,
			'recursive' => -1,
			'fields' => array('Event.id')
		)));
		return $results;
	}

	public function fetchSimpleEvents($user, $params, $includeOrgc = false) {
		$conditions = $this->__createEventConditions($user);
		$conditions['AND'][] = $params['conditions'];
		$params = array(
			'conditions' => $conditions,
			'recursive' => -1
		);
		if ($includeOrgc) {
			$params['contain'] = array('Orgc.name');
		}
		$results = array_values($this->find('all', $params));
		return $results;
	}

	public function fetchEventIds($user, $from = false, $to = false, $last = false, $list = false, $timestamp = false, $publish_timestamp = false, $eventIdList = false) {
		$conditions = array();
		// restricting to non-private or same org if the user is not a site-admin.
		if (!$user['Role']['perm_site_admin']) {
			$sgids = $this->SharingGroup->fetchAllAuthorised($user);
			if (empty($sgids)) $sgids = -1;
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
		if ($eventIdList) $conditions['AND'][] = array('Event.id' => $eventIdList);
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

	/*
	 * Unlike the other fetchers, this one foregoes any ACL checks.
	 * the objective is simple: Fetch the given event with all related objects needed for the ZMQ output,
	 * standardising on this function for fetching the event to be passed to the pubsub handler
	 */
	public function quickFetchEvent($id) {
		$event = $this->find('first', array(
			'recursive' => -1,
			'conditions' => array('Event.id' => $id),
			'contain' => array(
				'Orgc' => array(
					'fields' => array('Orgc.id', 'Orgc.uuid', 'Orgc.name')
				),
				'EventTag' => array(
					'Tag' => array('fields' => array('Tag.id', 'Tag.name', 'Tag.colour', 'Tag.exportable'))
				)
			)
		));
		return $event;
	}

	//Once the data about the user is gathered from the appropriate sources, fetchEvent is called from the controller or background process.
	// Possible options:
	// eventid: single event ID
	// idList: array with event IDs
	// tags: string with the usual tag syntax
	// from: date string (YYYY-MM-DD)
	// to: date string (YYYY-MM-DD)
	// includeAllTags: true will include the tags that are marked as non-exportable
	// includeAttachments: true will attach the attachments to the attributes in the data field
	public function fetchEvent($user, $options = array(), $useCache = false) {
		if (isset($options['Event.id'])) $options['eventid'] = $options['Event.id'];
		$possibleOptions = array('eventid', 'idList', 'tags', 'from', 'to', 'last', 'to_ids', 'includeAllTags', 'includeAttachments', 'event_uuid', 'distribution', 'sharing_group_id', 'disableSiteAdmin', 'metadata', 'includeGalaxy', 'enforceWarninglist', 'sgReferenceOnly', 'flatten', 'blockedAttributeTags');
		if (!isset($options['excludeGalaxy']) || !$options['excludeGalaxy']) {
			$this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
		}
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
		$conditionsObjects = array();
		$conditionsObjectReferences = array();

		if (isset($options['flatten']) && $options['flatten']) {
			$flatten = true;
		} else {
			$flatten = false;
		}
		$sgids = $this->cacheSgids($user, $useCache);
		// restricting to non-private or same org if the user is not a site-admin.
		if (!$isSiteAdmin) {
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
						Configure::read('MISP.unpublishedprivate') ? array('Event.published =' => 1) : array()
					)
				)
			);
			// if delegations are enabled, check if there is an event that the current user might see because of the request itself
			if (Configure::read('MISP.delegation')) {
				$delegatedEventIDs = $this->__cachedelegatedEventIDs($user, $useCache);
				$conditions['AND']['OR']['Event.id'] = $delegatedEventIDs;
			}
			$conditionsAttributes['AND'][0]['OR'] = array(
				array('AND' => array(
					'Attribute.distribution >' => 0,
					'Attribute.distribution !=' => 4,
				)),
				array('AND' => array(
					'Attribute.distribution' => 4,
					'Attribute.sharing_group_id' => $sgids,
				)),
				'(SELECT events.org_id FROM events WHERE events.id = Attribute.event_id)' => $user['org_id']
			);

			$conditionsObjects['AND'][0]['OR'] = array(
				array('AND' => array(
					'Object.distribution >' => 0,
					'Object.distribution !=' => 4,
				)),
				array('AND' => array(
					'Object.distribution' => 4,
					'Object.sharing_group_id' => $sgids,
				)),
				'(SELECT events.org_id FROM events WHERE events.id = Object.event_id)' => $user['org_id']
			);
		}
		if ($options['distribution']) {
			$conditions['AND'][] = array('Event.distribution' => $options['distribution']);
			$conditionsAttributes['AND'][] = array('Attribute.distribution' => $options['distribution']);
			$conditionsObjects['AND'][] = array('Object.distribution' => $options['distribution']);
		}
		if ($options['sharing_group_id']) {
			$conditions['AND'][] = array('Event.sharing_group_id' => $options['sharing_group_id']);
			$conditionsAttributes['AND'][] = array('Attribute.sharing_group_id' => $options['sharing_group_id']);
			$conditionsObjects['AND'][] = array('Object.sharing_group_id' => $options['sharing_group_id']);
		}
		if ($options['from']) $conditions['AND'][] = array('Event.date >=' => $options['from']);
		if ($options['to']) $conditions['AND'][] = array('Event.date <=' => $options['to']);
		if ($options['last']) $conditions['AND'][] = array('Event.publish_timestamp >=' => $options['last']);
		if ($options['event_uuid']) $conditions['AND'][] = array('Event.uuid' => $options['event_uuid']);

		$softDeletables = array('Attribute', 'Object', 'ObjectReference');
		if (isset($options['deleted']) && $options['deleted']) {
			if (!$user['Role']['perm_sync']) {
				foreach ($softDeletables as $softDeletable) {
					${'conditions' . $softDeletable . 's'}['AND'][] = array(
						'OR' => array(
							'(SELECT events.org_id FROM events WHERE events.id = ' . $softDeletable . '.event_id)' => $user['org_id'],
							$softDeletable . '.deleted' => 0
						)
					);
				}
			}
		} else {
			foreach ($softDeletables as $softDeletable) {
				${'conditions' . $softDeletable . 's'}['AND'][$softDeletable . '.deleted'] = 0;
			}
		}
		if ($options['idList'] && !$options['tags']) {
			$conditions['AND'][] = array('Event.id' => $options['idList']);
		}
		// If we sent any tags along, load the associated tag names for each attribute
		if ($options['tags']) {
			$temp = $this->__generateCachedTagFilters($options['tags']);
			foreach ($temp as $rules) {
				$conditions['AND'][] = $rules;
			}
		}

		if ($options['to_ids']) {
			$conditionsAttributes['AND'][] = array('Attribute.to_ids' => 1);
		}

		// removing this for now, we export the to_ids == 0 attributes too, since there is a to_ids field indicating it in the .xml
		// $conditionsAttributes['AND'] = array('Attribute.to_ids =' => 1);
		// Same idea for the published. Just adjust the tools to check for this
		// $conditions['AND'][] = array('Event.published =' => 1);

		// do not expose all the data ...
		$fields = array('Event.id', 'Event.orgc_id', 'Event.org_id', 'Event.date', 'Event.threat_level_id', 'Event.info', 'Event.published', 'Event.uuid', 'Event.attribute_count', 'Event.analysis', 'Event.timestamp', 'Event.distribution', 'Event.proposal_email_lock', 'Event.user_id', 'Event.locked', 'Event.publish_timestamp', 'Event.sharing_group_id', 'Event.disable_correlation');
		$fieldsAtt = array('Attribute.id', 'Attribute.type', 'Attribute.category', 'Attribute.value', 'Attribute.to_ids', 'Attribute.uuid', 'Attribute.event_id', 'Attribute.distribution', 'Attribute.timestamp', 'Attribute.comment', 'Attribute.sharing_group_id', 'Attribute.deleted', 'Attribute.disable_correlation', 'Attribute.object_id', 'Attribute.object_relation');
		$fieldsObj = array('*');
		$fieldsShadowAtt = array('ShadowAttribute.id', 'ShadowAttribute.type', 'ShadowAttribute.category', 'ShadowAttribute.value', 'ShadowAttribute.to_ids', 'ShadowAttribute.uuid', 'ShadowAttribute.event_uuid', 'ShadowAttribute.event_id', 'ShadowAttribute.old_id', 'ShadowAttribute.comment', 'ShadowAttribute.org_id', 'ShadowAttribute.proposal_to_delete', 'ShadowAttribute.timestamp');
		$fieldsOrg = array('id', 'name', 'uuid');
		$fieldsServer = array('id', 'url', 'name');
		if (!$options['includeAllTags']) $tagConditions = array('exportable' => 1);
		else $tagConditions = array();
		$sharingGroupData = $this->__cacheSharingGroupData($user, $useCache);
		$params = array(
			'conditions' => $conditions,
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
					'order' => false,
					'AttributeTag' => array(
						'Tag' => array('conditions' => $tagConditions, 'order' => false),
						'order' => false
					),
				),
				'Object' => array(
					'fields' => $fieldsObj,
					'conditions' => $conditionsObjects,
					'order' => false,
					'ObjectReference' => array(
						'conditions' => $conditionsObjectReferences,
						'order' => false
					)
				),
				'ShadowAttribute' => array(
					'fields' => $fieldsShadowAtt,
					'conditions' => array('deleted' => 0),
					'Org' => array('fields' => $fieldsOrg),
					'order' => false
				),
				'EventTag' => array(
					'Tag' => array('conditions' => $tagConditions, 'order' => false),
					'order' => false
				)
			)
		);
		if ($flatten) {
			unset($params['contain']['Object']);
		}
		if ($options['metadata']) {
			unset($params['contain']['Attribute']);
			unset($params['contain']['ShadowAttribute']);
		}
		if ($user['Role']['perm_site_admin']) {
			$params['contain']['User'] = array('fields' => 'email');
		}
		$results = $this->find('all', $params);
		if (empty($results)) return array();

		// Do some refactoring with the event
		if (Configure::read('Plugin.Sightings_enable') !== false) {
			$this->Sighting = ClassRegistry::init('Sighting');
		}
		$userEmails = array();
		$fields = array(
			'common' => array('distribution', 'sharing_group_id', 'uuid'),
			'Attribute' => array('value', 'type', 'category', 'to_ids'),
			'Object' => array('name', 'meta-category')
		);
		foreach ($results as $eventKey => &$event) {
			if (!empty($event['Object'])) {
				foreach ($event['Object'] as $k => $object) {
					if (!empty($object['ObjectReference'])) {
						foreach ($object['ObjectReference'] as $k2 => $reference) {
							$type = array('Attribute', 'Object')[$reference['referenced_type']];
							$temp = $this->{$type}->find('first', array(
								'recursive' => -1,
								'fields' => array_merge($fields['common'], $fields[array('Attribute', 'Object')[$reference['referenced_type']]]),
								'conditions' => array('id' => $reference['referenced_id'])
							));
							if (!empty($temp)) {
								if (!$isSiteAdmin && $user['org_id'] != $event['Event']['orgc_id']) {
									if ($temp[$type]['distribution'] == 0 || ($temp[$type]['distribution'] == 4 && !in_array($temp[$type]['sharing_group_id'], $sgsids))) {
										unset($object['ObjectReference'][$k2]);
										continue;
									}
								}
								$event['Object'][$k]['ObjectReference'][$k2][$type] = $temp[$type];
							}
						}
					}
				}
			}
			if (!$options['sgReferenceOnly'] && $event['Event']['sharing_group_id']) {
				$event['SharingGroup'] = $sharingGroupData[$event['Event']['sharing_group_id']]['SharingGroup'];
			}
			// Add information for auditor user
			if ($event['Event']['orgc_id'] === $user['org_id'] && $user['Role']['perm_audit']) {
				if (!isset($userEmails[$event['Event']['user_id']])) {
					$userEmails[$event['Event']['user_id']] = $this->User->getAuthUser($event['Event']['user_id'])['email'];
				}
				$event['Event']['event_creator_email'] = $userEmails[$event['Event']['user_id']];
			}
			$event['Galaxy'] = array();
			// unset empty event tags that got added because the tag wasn't exportable
			if (!empty($event['EventTag'])) {
				foreach ($event['EventTag'] as $k => &$eventTag) {
					if (empty($eventTag['Tag'])) {
						unset($event['EventTag'][$k]);
						continue;
					}
					if (!isset($options['excludeGalaxy']) || !$options['excludeGalaxy']) {
						if (substr($eventTag['Tag']['name'], 0, strlen('misp-galaxy:')) === 'misp-galaxy:') {
							$cluster = $this->GalaxyCluster->getCluster($eventTag['Tag']['name']);
							if ($cluster) {
								$found = false;
								foreach ($event['Galaxy'] as $k => $galaxy) {
									if ($galaxy['id'] == $cluster['GalaxyCluster']['Galaxy']['id']) {
										$found = true;
										$temp = $cluster;
										unset($temp['GalaxyCluster']['Galaxy']);
										$event['Galaxy'][$k]['GalaxyCluster'][] = $temp['GalaxyCluster'];
										continue;
									}
								}
								if (!$found) {
									$event['Galaxy'][] = $cluster['GalaxyCluster']['Galaxy'];
									$temp = $cluster;
									unset($temp['GalaxyCluster']['Galaxy']);
									$event['Galaxy'][count($event['Galaxy']) - 1]['GalaxyCluster'][] = $temp['GalaxyCluster'];
								}
							}
						}
					}
				}
				$event['EventTag'] = array_values($event['EventTag']);
			}
			// Let's find all the related events and attach it to the event itself
			$results[$eventKey]['RelatedEvent'] = $this->getRelatedEvents($user, $event['Event']['id'], $sgids);
			// Let's also find all the relations for the attributes - this won't be in the xml export though
			$results[$eventKey]['RelatedAttribute'] = $this->getRelatedAttributes($user, $event['Event']['id'], $sgids);
			$results[$eventKey]['RelatedShadowAttribute'] = $this->getRelatedAttributes($user, $event['Event']['id'], $sgids, true);
			if (isset($event['ShadowAttribute']) && !empty($event['ShadowAttribute']) && isset($options['includeAttachments']) && $options['includeAttachments']) {
				foreach ($event['ShadowAttribute'] as $k => $sa) {
					if ($this->ShadowAttribute->typeIsAttachment($sa['type'])) {
						$encodedFile = $this->ShadowAttribute->base64EncodeAttachment($sa);
						$event['ShadowAttribute'][$k]['data'] = $encodedFile;
					}
				}
			}
			if (isset($event['Attribute'])) {
				if ($options['enforceWarninglist']) {
					$this->Warninglist = ClassRegistry::init('Warninglist');
					$warninglists = $this->Warninglist->fetchForEventView();
				}
				if (isset($options['includeFeedCorrelations']) && $options['includeFeedCorrelations']) {
					$this->Feed = ClassRegistry::init('Feed');
					if (!empty($options['overrideLimit'])) $overrideLimit = true;
					else $overrideLimit = false;
					$event['Attribute'] = $this->Feed->attachFeedCorrelations($event['Attribute'], $user, $event['Event'], $overrideLimit);
				}
				$event = $this->__filterBlockedAttributesByTags($event, $options, $user);
				$event['Attribute'] = $this->__attachSharingGroups(!$options['sgReferenceOnly'], $event['Attribute'], $sharingGroupData);
				foreach ($event['Attribute'] as $key => $attribute) {
					if ($options['enforceWarninglist'] && !$this->Warninglist->filterWarninglistAttributes($warninglists, $attribute, $this->Warninglist)) {
						unset($event['Attribute'][$key]);
						continue;
					}
					if (isset($options['includeAttachments']) && $options['includeAttachments']) {
						if ($this->Attribute->typeIsAttachment($attribute['type'])) {
							$encodedFile = $this->Attribute->base64EncodeAttachment($attribute);
							$event['Attribute'][$key]['data'] = $encodedFile;
						}
					}
					// unset empty attribute tags that got added because the tag wasn't exportable
					if (!empty($attribute['AttributeTag'])) {
						foreach ($attribute['AttributeTag'] as $atk => $attributeTag) {
							if (empty($attributeTag['Tag'])) unset($event['Attribute'][$key]['AttributeTag'][$atk]);
						}
						$event['Attribute'][$key]['AttributeTag'] = array_values($event['Attribute'][$key]['AttributeTag']);
					}
					$event['Attribute'][$key]['ShadowAttribute'] = array();
					// If a shadowattribute can be linked to an attribute, link it to it then remove it from the event
					// This is to differentiate between proposals that were made to an attribute for modification and between proposals for new attributes

					if (isset($event['ShadowAttribute'])) {
						foreach ($event['ShadowAttribute'] as $k => $sa) {
							if (!empty($sa['old_id'])) {
								if ($event['ShadowAttribute'][$k]['old_id'] == $attribute['id']) {
									$results[$eventKey]['Attribute'][$key]['ShadowAttribute'][] = $sa;
									unset($results[$eventKey]['ShadowAttribute'][$k]);
								}
							}
						}
					}
					if (Configure::read('MISP.proposals_block_attributes') && isset($options['to_ids']) && $options['to_ids']) {
						foreach ($results[$eventKey]['Attribute'][$key]['ShadowAttribute'] as $sa) {
							if ($sa['proposal_to_delete'] || $sa['to_ids'] == 0) {
								unset($results[$eventKey]['Attribute'][$key]);
								continue;
							}
						}
					}
					if (!$flatten && $event['Attribute'][$key]['object_id'] != 0) {
						if (!empty($event['Object'])) {
							$event['Object'] = $this->__attachSharingGroups(!$options['sgReferenceOnly'], $event['Object'], $sharingGroupData);
							foreach ($event['Object'] as $objectKey => $objectValue) {
								if (!empty($event['Object'][$objectKey]['Attribute'])) {
									$event['Object'][$objectKey]['Attribute'] = $this->__attachSharingGroups(!$options['sgReferenceOnly'], $event['Object'][$objectKey]['Attribute'], $sharingGroupData);
								}
								if ($event['Attribute'][$key]['object_id'] == $objectValue['id']) {
									$event['Object'][$objectKey]['Attribute'][] = $event['Attribute'][$key];
								}
							}
						}
						unset($event['Attribute'][$key]);
					}
				}
				$event['Attribute'] = array_values($event['Attribute']);
			}
			if (!empty($event['ShadowAttribute'])) {
				if ($isSiteAdmin && isset($options['includeFeedCorrelations']) && $options['includeFeedCorrelations']) {
					$this->Feed = ClassRegistry::init('Feed');
					if (!empty($options['overrideLimit'])) $overrideLimit = true;
					else $overrideLimit = false;
					$event['ShadowAttribute'] = $this->Feed->attachFeedCorrelations($event['ShadowAttribute'], $user, $event['Event'], $overrideLimit);
				}
			}
			if (Configure::read('Plugin.Sightings_enable') !== false) {
				$event['Sighting'] = $this->Sighting->attachToEvent($event, $user);
			}
			// remove proposals to attributes that we cannot see
			// if the shadow attribute wasn't moved within an attribute before, this is the case
			if (isset($event['ShadowAttribute'])) {
				foreach ($event['ShadowAttribute'] as $k => $sa) {
					if (!empty($sa['old_id'])) unset($event['ShadowAttribute'][$k]);
				}
				$event['ShadowAttribute'] = array_values($event['ShadowAttribute']);
			}
			if ($event['Event']['orgc_id'] === $user['org_id'] && $user['Role']['perm_audit']) {
				$UserEmail = $this->User->getAuthUser($event['Event']['user_id'])['email'];
				$event['Event']['event_creator_email'] = $UserEmail;
			}
		}
		return $results;
	}

	private function __attachSharingGroups($doAttach, $data, $sharingGroupData) {
		foreach ($data as $k => $v) {
			if ($v['distribution'] == 4) {
				$data[$k]['SharingGroup'] = $sharingGroupData[$v['sharing_group_id']]['SharingGroup'];
			}
		}
		return $data;
	}

	// Filter the attributes within an event based on the tag filter block rules
	private function __filterBlockedAttributesByTags($event, $options, $user) {
		if (!empty($options['blockedAttributeTags'])) {
			foreach ($options['blockedAttributeTags'] as $key => $blockedTag) {
				if (!is_numeric($blockedTag)) {
					$options['blockedAttributeTags'][$key] = $this->EventTag->Tag->lookupTagIdFromName($blockedTag);
				} else {
					$options['blockedAttributeTags'][$key] = $blockedTag;
				}
			}
		}
		if (!empty($user['Server']['push_rules'])) {
			$push_rules = json_decode($user['Server']['push_rules'], true);
			if (!empty($push_rules['tags']['NOT'])) {
				if (empty($options['blockedAttributeTags'])) {
					$options['blockedAttributeTags'] = array();
				}
				$options['blockedAttributeTags'] = array_merge($options['blockedAttributeTags'], $push_rules['tags']['NOT']);
			}
		}
		if (!empty($options['blockedAttributeTags'])) {
			if (!empty($event['Attribute'])) {
				$event['Attribute'] = $this->__filterBlockedAttributesFromContainer($event['Attribute'], $options['blockedAttributeTags']);
			}
		}
		return $event;
	}

	// accepts an attribute array and a list of blocked tags. Returns the attribute array with the blocked attributes cleaned out.
	private function __filterBlockedAttributesFromContainer($container, $blockedTags) {
		foreach ($container as $key => $attribute) {
			if (!empty($attribute['AttributeTag'])) {
				foreach ($attribute['AttributeTag'] as $at) {
					if (in_array($at['tag_id'], $blockedTags)) {
						unset($container[$key]);
					}
				}
			}
		}
		$container = array_values($container);
		return $container;
	}

	private function __escapeCSVField(&$field) {
		$field = str_replace(array('"'), '""', $field);
		$field = '"' . $field . '"';
	}

	public function csv($user, $eventid=false, $ignore=false, $attributeIDList = array(), $tags = false, $category = false, $type = false, $includeContext = false, $from = false, $to = false, $last = false, $enforceWarninglist = false, $value = false) {
		$this->recursive = -1;
		$conditions = array();
		// If we are not in the search result csv download function then we need to check what can be downloaded. CSV downloads are already filtered by the search function.
		if ($eventid !== 'search') {
			if ($from) $conditions['AND']['Event.date >='] = $from;
			if ($to) $conditions['AND']['Event.date <='] = $to;
			if ($last) $conditions['AND']['Event.publish_timestamp >='] = $last;
			// This is for both single event downloads and for full downloads. Org has to be the same as the user's or distribution not org only - if the user is no siteadmin
			if ($ignore == false) $conditions['AND']['Event.published'] = 1;

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
			if (!$ignore) $conditions['AND']['Attribute.to_ids'] = 1;
			if ($type) $conditions['AND']['Attribute.type'] = $type;
			if ($category) $conditions['AND']['Attribute.category'] = $category;
			if ($value) {
				$temp = array(
					'OR' => array(
						'Attribute.value1' => $value,
						'Attribute.value2' => $value
					)
				);

				$conditions['AND'][] = $temp;
			}
		}

		if ($eventid === 'search') {
			foreach ($attributeIDList as $aID) $conditions['AND']['OR'][] = array('Attribute.id' => $aID);
		}
		$params = array(
				'conditions' => $conditions, //array of conditions
				'fields' => array('Attribute.event_id', 'Attribute.distribution', 'Attribute.category', 'Attribute.type', 'Attribute.value', 'Attribute.comment', 'Attribute.uuid', 'Attribute.to_ids', 'Attribute.timestamp', 'Attribute.id'),
				'order' => array('Attribute.uuid ASC'),
				'enforceWarninglist' => $enforceWarninglist,
				'flatten' => true
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
		$params['contain']['Object'] = array('fields' => array('id', 'uuid', 'name', 'meta-category'));
		$attributes = $this->Attribute->fetchAttributes($user, $params);
		if (empty($attributes)) return array();
		foreach ($attributes as &$attribute) {
			$this->__escapeCSVField($attribute['Attribute']['value']);
			$this->__escapeCSVField($attribute['Attribute']['comment']);
			$attribute['Attribute']['timestamp'] = date('Ymd', $attribute['Attribute']['timestamp']);
			if (empty($attribute['Object'])) {
					$attribute['Object']['uuid'] = '""';
					$attribute['Object']['name'] = '';
					$attribute['Object']['meta-category'] = '';
			}
			$this->__escapeCSVField($attribute['Object']['name']);
			$this->__escapeCSVField($attribute['Object']['meta-category']);
			if ($includeContext) {
				$this->__escapeCSVField($attribute['Event']['info']);
				$this->__escapeCSVField($attribute['Org']['name']);
				$this->__escapeCSVField($attribute['Orgc']['name']);
				$attribute['Event']['Tag']['name'] = '';
				$attribute['attribute_tag'] = '';
				if (!empty($attribute['AttributeTag'])) {
					$tags = array();
					foreach ($attribute['AttributeTag'] as $attributeTag) {
						if (!empty($attributeTag['Tag']['name'])) {
							$tags[] = $attributeTag['Tag']['name'];
						}
					}
					$attribute['attribute_tag'] = implode(',', $tags);
				}
				$this->__escapeCSVField($attribute['attribute_tag']);
				if (!empty($attribute['Event']['EventTag'])) {
					$tags = array();
					foreach ($attribute['Event']['EventTag'] as $eventTag) {
						if (!empty($eventTag['Tag']['name'])) {
							$tags[] = $eventTag['Tag']['name'];
						}
					}
					$attribute['Event']['Tag']['name'] = implode(',', $tags);
				}
				$this->__escapeCSVField($attribute['Event']['Tag']['name']);
			}
		}
		return $attributes;
	}

	public function sendAlertEmailRouter($id, $user, $oldpublish = null) {
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
		if (Configure::read('MISP.block_event_alert') && Configure::read('MISP.block_event_alert_tag') && !empty(Configure::read('MISP.block_event_alert_tag'))) {
			$noAlertTag = Configure::read('MISP.block_event_alert_tag');
			$tagLen = strlen($noAlertTag);
			$event = $this->fetchEvent($user, array('eventid' => $id, 'includeAllTags' => true));
			if (empty($event)) return false;
			foreach ($event[0]['EventTag'] as $k => $tag) {
				if(strcasecmp($noAlertTag, $tag['Tag']['name']) == 0) {
					return true;
				}
			}
		}
		if (Configure::read('MISP.disable_emailing')) {
			$this->Log = ClassRegistry::init('Log');
			$this->Log->create();
			$this->Log->save(array(
					'org' => 'SYSTEM',
					'model' => 'Event',
					'model_id' => $id,
					'email' => $user['email'],
					'action' => 'publish',
					'title' => 'E-mail alerts not sent out during publishing. Reason: Emailing is currently disabled on this instance.',
					'change' => null,
			));
			return true;
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
					array('alertemail', $user['id'], $jobId, $id, $oldpublish),
					true
			);
			$job->saveField('process_id', $process_id);
			return true;
		} else {
			return ($this->sendAlertEmail($id, $user, $oldpublish));
		}
	}

	public function sendAlertEmail($id, $senderUser, $oldpublish = null, $processId = null) {
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
		$subjMarkingString = !empty(Configure::read('MISP.email_subject_TLP_string')) ? Configure::read('MISP.email_subject_TLP_string') : "tlp:amber";
		$subjTag = !empty(Configure::read('MISP.email_subject_tag')) ? Configure::read('MISP.email_subject_tag') : "tlp";
		$tagLen = strlen($subjTag);
		foreach ($event[0]['EventTag'] as $k => $tag) {
			$tagName=$tag['Tag']['name'];
			if(strncasecmp($subjTag, $tagName, $tagLen) == 0 && strlen($tagName) > $tagLen && ($tagName[$tagLen] == ':' || $tagName[$tagLen] == '=')) {
				if(Configure::read('MISP.email_subject_include_tag_name') === false) {
					$subjMarkingString = trim(substr($tagName, $tagLen+1), '"');
				} else {
					$subjMarkingString = $tagName;
				}
				break;
			}
		}
		$threatLevel = $event[0]['ThreatLevel']['name'] . " - ";
		if(Configure::read('MISP.threatlevel_in_email_subject') === false) {
			$threatLevel = '';
		}
		$subject = "[" . Configure::read('MISP.org') . " MISP] Event " . $id . " - " . $subject . $threatLevel . $subjMarkingString;

		// Initialise the Job class if we have a background process ID
		// This will keep updating the process's progress bar
		if ($processId) {
			$this->Job = ClassRegistry::init('Job');
		}
		$sgModel = ClassRegistry::init('SharingGroup');

		$userCount = count($users);
		foreach ($users as $k => $user) {
			$body = $this->__buildAlertEmailBody($event[0], $user, $oldpublish, $sgModel);
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

	private function __buildAlertEmailObject($user, &$body, &$bodyTempOther, $objects, $owner, $oldpublish) {
		foreach ($objects as $object) {
			if (!$owner && $object['distribution'] == 0) continue;
			if ($object['distribution'] == 4 && !$this->SharingGroup->checkIfAuthorised($user, $object['sharing_group_id'])) continue;
			if (isset($oldpublish) && isset($object['timestamp']) && $object['timestamp'] > $oldpublish) {
				$body .= '* ';
			} else {
				$body .= '  ';
			}
			$body .= $object['name'] . '/' . $object['meta-category'] . "\n";
			if (!empty($object['Attribute'])) {
				$body .= $this->__buildAlertEmailAttribute($user, $body, $bodyTempOther, $object['Attribute'], $owner, $oldpublish, '    ');
			}
		}
	}

	private function __buildAlertEmailAttribute($user, &$body, &$bodyTempOther, $attributes, $owner, $oldpublish, $indent = '  ') {
		$appendlen = 20;
		foreach ($attributes as $attribute) {
			if (!$owner && $attribute['distribution'] == 0) continue;
			if ($attribute['distribution'] == 4 && !$this->SharingGroup->checkIfAuthorised($user, $attribute['sharing_group_id'])) continue;
			$ids = '';
			if ($attribute['to_ids']) $ids = ' (IDS)';
			$strRepeatCount = $appendlen - 2 - strlen($attribute['type']);
			$strRepeat = ($strRepeatCount > 0) ? str_repeat(' ', $strRepeatCount) : '';
			if (isset($oldpublish) && isset($attribute['timestamp']) && $attribute['timestamp'] > $oldpublish) {
				$line = '* ' . $indent . $attribute['category'] . '/' . $attribute['type'] . $strRepeat . ': ' . $attribute['value'] . $ids . " *\n";
			} else {
				$line = $indent . $attribute['category'] . '/' . $attribute['type'] . $strRepeat . ': ' . $attribute['value'] . $ids .  "\n";
			}
			// Defanging URLs (Not "links") emails domains/ips in notification emails
			if ('url' == $attribute['type'] || 'uri' == $attribute['type']) {
				$line = str_ireplace("http","hxxp", $line);
				$line = str_ireplace(".","[.]", $line);
			}
			else if (in_array($attribute['type'], array('email-src', 'email-dst', 'whois-registrant-email', 'dns-soa-email', 'email-reply-to'))) {
				$line = str_replace("@","[at]", $line);
			}
			else if (in_array($attribute['type'], array('hostname', 'domain', 'ip-src', 'ip-dst', 'domain|ip'))) {
				$line = str_replace(".","[.]", $line);
			}
			if (!empty($attribute['AttributeTag'])) {
				$line .= '  - Tags: ';
				foreach ($attribute['AttributeTag'] as $k => $aT) {
					if ($k > 0) {
						$line .= ', ';
					}
					$line .= $aT['Tag']['name'];
				}
				$line .= "\n";
			}
			if ('other' == $attribute['type']) // append the 'other' attribute types to the bottom.
				$bodyTempOther .= $line;
			else $body .= $line;
		}
	}

	private function __buildAlertEmailBody($event, $user, $oldpublish, $sgModel) {
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
		$body .= 'Description : ' . $event['Event']['info'] . "\n";
		$relatedEvents = $this->getRelatedEvents($user, $event['Event']['id'], array());
		if (!empty($relatedEvents)) {
			$body .= '==============================================' . "\n";
			$body .= 'Related to: '. "\n";
			foreach ($relatedEvents as &$relatedEvent) {
				$body .= Configure::read('MISP.baseurl') . '/events/view/' . $relatedEvent['Event']['id'] . ' (' . $relatedEvent['Event']['date'] . ') ' ."\n";
			}
			$body .= '==============================================' . "\n";
		}
		$bodyTempOther = "";
		if (!empty($event['Attribute'])) {
			$body .= 'Attributes (* indicates a new or modified attribute):' . "\n";
			$this->__buildAlertEmailAttribute($user, $body, $bodyTempOther, $event['Attribute'], $owner, $oldpublish);
		}
		if (!empty($event['Object'])) {
			$body .= 'Objects (* indicates a new or modified object):' . "\n";
			$this->__buildAlertEmailObject($user, $body, $bodyTempOther, $event['Object'], $owner, $oldpublish);
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

	private function __captureSGForElement($element, $user) {
		if (isset($element['SharingGroup'])) {
			$sg = $this->SharingGroup->captureSG($element['SharingGroup'], $user);
			unset($element['SharingGroup']);
		} else {
			$sg = $this->SharingGroup->checkIfAuthorised($user, $element['sharing_group_id']) ? $element['sharing_group_id'] : false;
		}
		if ($sg===false) {
			$sg = 0;
			$data['Event']['distribution'] = 0;
		}
		$element['sharing_group_id'] = $sg;
		return $element;
	}

	// When we receive an event via REST, we might end up with organisations, sharing groups, tags that we do not know
	// or which we need to update. All of that is controlled in this method.
	private function __captureObjects($data, $user) {
		// First we need to check whether the event or any attributes are tied to a sharing group and whether the user is even allowed to create the sharing group / is part of it
		if (isset($data['Event']['distribution']) && $data['Event']['distribution'] == 4) {
			$data['Event'] = $this->__captureSGForElement($data['Event'], $user);
		}
		if (!empty($data['Event']['Attribute'])) {
			foreach ($data['Event']['Attribute'] as $k => $a) {
				unset($data['Event']['Attribute']['id']);
				if (isset($a['distribution']) && $a['distribution'] == 4) {
					$data['Event']['Attribute'][$k] = $this->__captureSGForElement($data['Event']['Attribute'][$k], $user);
				}
			}
		}
		if (!empty($data['Event']['Object'])) {
			foreach($data['Event']['Object'] as $k => $o) {
				if (isset($o['distribution']) && $o['distribution'] == 4) {
					$data['Event']['Object'][$k] = $this->__captureSGForElement($data['Event']['Object'][$k], $user);
				}
				foreach ($o['Attribute'] as $k2 => $a) {
					if (isset($a['distribution']) && $a['distribution'] == 4) {
						$data['Event']['Object'][$k2]['Attribute'][$k] = $this->__captureSGForElement($data['Event']['Object'][$k2]['Attribute'][$k], $user);
					}
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
			if (isset($data['Event']['EventTag']['id'])) $data['Event']['EventTag'] = array($data['Event']['EventTag']);
			$eventTags = array();
			foreach ($data['Event']['EventTag'] as $k => $tag) {
				$eventTags[] = array('tag_id' => $this->EventTag->Tag->captureTag($data['Event']['EventTag'][$k]['Tag'], $user));
				unset($data['Event']['EventTag'][$k]);
			}
			$data['Event']['EventTag'] = $eventTags;
		} else {
			$data['Event']['EventTag'] = array();
		}
		if (isset($data['Event']['Tag'])) {
			if (isset($data['Event']['Tag']['name'])) $data['Event']['Tag'] = array($data['Event']['Tag']);
			foreach ($data['Event']['Tag'] as $tag) {
				$tag_id = $this->EventTag->Tag->captureTag($tag, $user);
				if ($tag_id) $data['Event']['EventTag'][] = array('tag_id' => $tag_id);
			}
			unset($data['Event']['Tag']);
		}

		if (!empty($data['Event']['Attribute'])) {
			$data['Event']['Attribute'] = $this->__captureAttributeTags($data['Event']['Attribute'], $user);
		}
		if (!empty($data['Event']['Object'])) {
			foreach ($data['Event']['Object'] as $k => $object) {
				if (!empty($data['Event']['Object'][$k]['Attribute'])) {
					$data['Event']['Object'][$k]['Attribute'] = $this->__captureAttributeTags($data['Event']['Object'][$k]['Attribute'], $user);
				}
			}
		}
		return $data;
	}

	private function __captureAttributeTags($attributes, $user) {
		foreach ($attributes as $k => $a) {
			if (isset($attributes[$k]['AttributeTag'])) {
				if (isset($attributes[$k]['AttributeTag']['id'])) $attributes[$k]['AttributeTag'] = array($attributes[$k]['AttributeTag']);
				$attributeTags = array();
				foreach ($attributes[$k]['AttributeTag'] as $tk => $tag) {
					$attributeTags[] = array('tag_id' => $this->Attribute->AttributeTag->Tag->captureTag($attributes[$k]['AttributeTag'][$tk]['Tag'], $user));
					unset($attributes[$k]['AttributeTag'][$tk]);
				}
				$attributes[$k]['AttributeTag'] = $attributeTags;
			} else {
				$attributes[$k]['AttributeTag'] = array();
			}
			if (isset($attributes[$k]['Tag'])) {
				if (isset($attributes[$k]['Tag']['name'])) $attributes[$k]['Tag'] = array($attributes[$k]['Tag']);
				foreach ($attributes[$k]['Tag'] as $tag) {
					$tag_id = $this->Attribute->AttributeTag->Tag->captureTag($tag, $user);
					if ($tag_id) $attributes[$k]['AttributeTag'][] = array('tag_id' => $tag_id);
				}
				unset($attributes[$k]['Tag']);
			}
		}
		return $attributes;
	}

	// Low level function to add an Event based on an Event $data array
	public function _add(&$data, $fromXml, $user, $org_id = 0, $passAlong = null, $fromPull = false, $jobId = null, &$created_id = 0, &$validationErrors = array()) {
		if ($jobId) {
			App::uses('AuthComponent', 'Controller/Component');
		}
		if (Configure::read('MISP.enableEventBlacklisting') !== false && isset($data['Event']['uuid'])) {
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
				if (isset($data['Event']['orgc_id']) && $data['Event']['orgc_id'] != $user['org_id'] && !$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin']) throw new MethodNotAllowedException('Event cannot be created as you are not a member of the creator organisation.');
			} else {
				if ($data['Event']['Orgc']['uuid'] != $user['Organisation']['uuid'] && !$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin']) throw new MethodNotAllowedException('Event cannot be created as you are not a member of the creator organisation.');
				if (isset($data['Event']['orgc']) && $data['Event']['orgc'] != $user['Organisation']['name'] && !$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin']) throw new MethodNotAllowedException('Event cannot be created as you are not a member of the creator organisation.');
			}
			if (isset($data['Event']['orgc_id']) && $data['Event']['orgc_id'] != $user['org_id'] && !$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin']) throw new MethodNotAllowedException('Event cannot be created as you are not a member of the creator organisation.');
		}
		if (!Configure::check('MISP.enableOrgBlacklisting') || Configure::read('MISP.enableOrgBlacklisting') !== false) {
			$this->OrgBlacklist = ClassRegistry::init('OrgBlacklist');
			if (!isset($data['Event']['Orgc']['uuid'])) {
				$orgc = $this->Orgc->find('first', array('conditions' => array('Orgc.id' => $data['Event']['orgc_id']), 'fields' => array('Orgc.uuid'), 'recursive' => -1));
			} else {
				$orgc = array('Orgc' => array('uuid' => $data['Event']['Orgc']['uuid']));
			}
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
		if (isset($data['Event']['published']) && $data['Event']['published'] && $user['Role']['perm_publish'] == 0) $data['Event']['published'] = 0;
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
		$fieldList = array(
				'Event' => array(
					'org_id',
					'orgc_id',
					'date',
					'threat_level_id',
					'analysis',
					'info',
					'user_id',
					'published',
					'uuid',
					'timestamp',
					'distribution',
					'sharing_group_id',
					'locked',
					'disable_correlation'
				),
				'Attribute' => array(
					'event_id',
					'category',
					'type',
					'value',
					'to_ids',
					'uuid',
					'timestamp',
					'distribution',
					'comment',
					'sharing_group_id',
					'deleted',
					'disable_correlation',
					'object_id',
					'object_relation'
				),
				'Object' => array(
					'name',
					'meta-category',
					'description',
					'template_uuid',
					'template_version',
					'event_id',
					'uuid',
					'timestamp',
					'distribution',
					'sharing_group_id',
					'comment',
					'deleted'
				),
				'ObjectRelation' => array()
		);
		$saveResult = $this->save(array('Event' => $data['Event']), array('fieldList' => $fieldList['Event']));
		$this->Log = ClassRegistry::init('Log');
		if ($saveResult) {
			if ($passAlong) {
				$this->Server = ClassRegistry::init('Server');
				$server = $this->Server->find('first', array(
					'conditions' => array(
						'Server.id' => $passAlong
					),
					'recursive' => -1,
					'fields' => array(
						'Server.name',
						'Server.id',
						'Server.unpublish_event'
					)
				));
				$this->Log->create();
				$this->Log->save(array(
						'org' => $user['Organisation']['name'],
						'model' => 'Event',
						'model_id' => $saveResult['Event']['id'],
						'email' => $user['email'],
						'action' => 'add',
						'user_id' => $user['id'],
						'title' => 'Event pulled from Server(' . $server['Server']['id'] . ') - "' . $server['Server']['name'] . '"',
						'change' => ''
				));
			}
			if (isset($data['Event']['EventTag'])) {
				foreach ($data['Event']['EventTag'] as $et) {
					$this->EventTag->create();
					$et['event_id'] = $this->id;
					$this->EventTag->save($et);
				}
			}
			if (isset($data['Event']['Attribute']) && !empty($data['Event']['Attribute'])) {
				foreach ($data['Event']['Attribute'] as $k => $attribute) {
					$block = false;
					for ($i = 0; $i < $k; $i++) {
						if (
							$data['Event']['Attribute'][$i]['value'] == $attribute['value'] &&
							$data['Event']['Attribute'][$i]['type'] == $attribute['type'] &&
							$data['Event']['Attribute'][$i]['category'] == $attribute['category']
						) {
							$block = true;
							unset($data['Event']['Attribute'][$i]);
							break;
						}
					}
					if (!$block) {
						$data['Event']['Attribute'][$k] = $this->Attribute->captureAttribute($attribute, $this->id, $user, 0, $this->Log);
					}
				}
				$data['Event']['Attribute'] = array_values($data['Event']['Attribute']);
			}
			if (!empty($data['Event']['Object'])) {
				foreach ($data['Event']['Object'] as $object) {
					$result = $this->Object->captureObject($object, $this->id, $user, $this->Log);
				}
				foreach ($data['Event']['Object'] as $object) {
					if (isset($object['ObjectReference'])) {
						foreach ($object['ObjectReference'] as $objectRef) {
							$result = $this->Object->ObjectReference->captureReference($objectRef, $this->id, $user, $this->Log);
						}
					}
				}
			}
			if ($fromXml) $created_id = $this->id;
			if (!empty($data['Event']['published']) && 1 == $data['Event']['published']) {
				// do the necessary actions to publish the event (email, upload,...)
				if (('true' != Configure::read('MISP.disablerestalert'))) {
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
				if (isset($data['Event']['distribution']) && $data['Event']['distribution'] == 4) {
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
						if (isset($data['Event']['distribution']) && $data['Event']['distribution'] == 4 && !$this->SharingGroup->checkIfAuthorised($user, $data['Event']['sharing_group_id'])) {
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
		if (!empty($data['Event']['published']) && !$user['Role']['perm_publish']) $data['Event']['published'] = 0;
		if (!isset($data['Event']['published'])) $data['Event']['published'] = 0;
		$fieldList = array(
			'date',
			'threat_level_id',
			'analysis',
			'info',
			'published',
			'uuid',
			'distribution',
			'timestamp',
			'sharing_group_id',
			'disable_correlation'
		);
		$saveResult = $this->save(array('Event' => $data['Event']), array('fieldList' => $fieldList));
		$this->Log = ClassRegistry::init('Log');
		if ($saveResult) {
			$validationErrors = array();
			if (isset($data['Event']['Attribute'])) {
				$data['Event']['Attribute'] = array_values($data['Event']['Attribute']);
				foreach ($data['Event']['Attribute'] as $k => $attribute) {
					$result = $this->Attribute->editAttribute($attribute, $this->id, $user, 0, $this->Log);
					if ($result !== true) {
						$validationErrors['Attribute'][] = $result;
					}
				}
			}
			if (isset($data['Event']['Object'])) {
				$data['Event']['Object'] = array_values($data['Event']['Object']);
				foreach ($data['Event']['Object'] as $k => $object) {
					$result = $this->Object->editObject($object, $this->id, $user, $this->Log);
					if ($result !== true) {
						$validationErrors['Object'][] = $result;
					}
				}
				foreach ($data['Event']['Object'] as $object) {
					if (isset($object['ObjectReference'])) {
						foreach ($object['ObjectReference'] as $objectRef) {
							$result = $this->Object->ObjectReference->captureReference($objectRef, $this->id, $user, $this->Log);
						}
					}
				}
			}
			if (isset($event['Event']['EventTag'])) {
				$event['Event']['Tag'] = $event['Event']['EventTag']['Tag'];
				unset($event['Event']['EventTag']);
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
					$this->sendAlertEmailRouter($id, $user, $existingEvent['Event']['publish_timestamp']);
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

	private function __savePreparedAttribute(&$attribute, $event) {
		unset($attribute['id']);
		$attribute['event_id'] = $event['Event']['id'];
		$this->Attribute->create();
		$this->Attribute->save($attribute);
		foreach ($attribute['ShadowAttribute'] as $k => $sa) {
			$this->__savePreparedShadowAttribute($sa, $event, $this->Attribute->id);
		}
	}

	private function __savePreparedShadowAttribute($shadow_attribute, $event, $old_id = 0) {
		unset($shadow_attribute['id']);
		$shadow_attribute['event_id'] = $event['Event']['id'];
		$shadow_attribute['old_id'] = $old_id;
		$this->ShadowAttribute->create();
		$this->ShadowAttribute->save($shadow_attribute);
	}

	private function __savePreparedEventTag($event_tag, $event) {
		unset($event_tag['id']);
		$event_tag['event_id'] = $event['Event']['id'];
		$this->EventTag->create();
		$this->EventTag->save($event_tag);
	}

	// pass an event or an attribute together with the server id.
	// If the distribution of the object outright allows for it to be shared, return true
	// If the distribution is org only / comm only, return false
	// If the distribution is sharing group only, check if the sync user is in the sharing group or not, return true if yes, false if no
	public function checkDistributionForPush($object, $server, $context = 'Event') {
		if (empty(Configure::read('MISP.host_org_id')) || !$server['Server']['internal'] || Configure::read('MISP.host_org_id') != $server['Server']['remote_org_id']) {
			if ($object[$context]['distribution'] < 2) return false;
		}
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

	// Uploads this specific event to all remote servers
	public function uploadEventToServersRouter($id, $passAlong = null) {
		$eventOrgcId = $this->find('first', array(
			'conditions' => array('Event.id' => $id),
			'recursive' => -1,
			'fields' => array('Event.orgc_id')
		));
		// we create a fake site admin user object to fetch the event with everything included
		// This replaces the old method of manually just fetching everything, staying consistent
		// with the fetchEvent() output
		$elevatedUser = array(
			'Role' => array(
				'perm_site_admin' => 1,
				'perm_sync' => 1
			),
			'org_id' => $eventOrgcId['Event']['orgc_id']
		);
		$elevatedUser['Role']['perm_site_admin'] = 1;
		$elevatedUser['Role']['perm_sync'] = 1;
		$elevatedUser['Role']['perm_audit'] = 0;
		$event = $this->fetchEvent($elevatedUser, array('eventid' => $id, 'metadata' => 1));
		if (empty($event)) return true;
		$event = $event[0];
		$event['Event']['locked'] = 1;
		// get a list of the servers
		$this->Server = ClassRegistry::init('Server');
		$conditions = array('push' => 1);
		if ($passAlong) $conditions[] = array('Server.id !=' => $passAlong);
		$servers = $this->Server->find('all', array('conditions' => $conditions));
		// iterate over the servers and upload the event
		if (empty($servers)) {
			return true;
		}
		$uploaded = true;
		$failedServers = array();
		App::uses('SyncTool', 'Tools');
		foreach ($servers as &$server) {
			if ((!isset($server['Server']['internal']) || !$server['Server']['internal']) && $event['Event']['distribution'] < 2) {
				continue;
			}
			$syncTool = new SyncTool();
			$HttpSocket = $syncTool->setupHttpSocket($server);
			// Skip servers where the event has come from.
			if (($passAlong != $server)) {
				$params = array();
				if (!empty($server['Server']['push_rules'])) {
					$push_rules = json_decode($server['Server']['push_rules'], true);
					if (!empty($push_rules['tags']['NOT'])) {
						$params['blockedAttributeTags'] = $push_rules['tags']['NOT'];
					}
				}
				$params = array_merge($params, array('eventid' => $id, 'includeAttachments' => true, 'includeAllTags' => true, 'deleted' => true));
				$event = $this->fetchEvent($elevatedUser, $params);
				$event = $event[0];
				$event['Event']['locked'] = 1;
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
			if (empty($failedServers)) {
				return true;
			}
			return $failedServers;
		} else {
			return true;
		}
	}

	public function publishRouter($id, $passAlong = null, $user) {
		if (Configure::read('MISP.background_jobs')) {
			$job = ClassRegistry::init('Job');
			$job->create();
			$this->ResqueStatus = new ResqueStatus\ResqueStatus(Resque::redis());
			$workers = $this->ResqueStatus->getWorkers();
			$workerType = 'default';
			foreach ($workers as $worker) {
				if ($worker['queue'] === 'prio') {
					$workerType = 'prio';
				}
			}
			$data = array(
					'worker' => $workerType,
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
					'prio',
					'EventShell',
					array('publish', $id, $passAlong, $jobId, $user['id']),
					true
			);
			$job->saveField('process_id', $process_id);
			return $process_id;
		} else {
			$result = $this->publish($id, $passAlong);
			return $result;
		}
	}

	// Performs all the actions required to publish an event
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
			$event['Event']['skip_zmq'] = 1;
			$this->save($event, array('fieldList' => $fieldList));
		}
		if (Configure::read('Plugin.ZeroMQ_enable')) {
			$pubSubTool = $this->getPubSubTool();
			$hostOrg = $this->Org->find('first', array('conditions' => array('name' => Configure::read('MISP.org')), 'fields' => array('id')));
			if (!empty($hostOrg)) {
				$user = array('org_id' => $hostOrg['Org']['id'], 'Role' => array('perm_sync' => 0, 'perm_audit' => 0, 'perm_site_admin' => 0), 'Organisation' => $hostOrg['Org']);
				$fullEvent = $this->fetchEvent($user, array('eventid' => $id));
				if (!empty($fullEvent)) $pubSubTool->publishEvent($fullEvent[0], 'publish');
			}
		}
		$uploaded = $this->uploadEventToServersRouter($id, $passAlong);
		return $uploaded;
	}


	// Sends out an email to all people within the same org with the request to be contacted about a specific event.
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
					array('contactemail', $id, $message, $creator_only, $user['id'], $isSiteAdmin, $jobId),
					true
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

	public function stix2($id, $user) {
		$event = $this->fetchEvent($user, array('eventid' => $id));
		App::uses('JSONConverterTool', 'Tools');
		$converter = new JSONConverterTool();
		$event = $converter->convert($event[0]);
		$randomFileName = $this->generateRandomFileName();
		$tmpDir = APP . "files" . DS . "scripts" . DS . "tmp";
		$tempFile = new File($tmpDir . DS . $randomFileName, true, 0644);
		$tempFile->write($event);
		$scriptFile = APP . "files" . DS . "scripts" . DS . "stix2" . DS . "misp2stix2.py";
		$result = shell_exec('python3 ' . $scriptFile . ' ' . $tempFile->path . ' json ' . ' ' . escapeshellarg(Configure::read('MISP.baseurl')) . ' ' . escapeshellarg(Configure::read('MISP.org')) . ' 2>' . APP . 'tmp/logs/exec-errors.log');
		$tempFile->delete();
		if (trim($result) == 1) {
			$resultFile = new File($tmpDir . DS . $randomFileName . '.out', true, 0644);
			$result = $resultFile->read();
			$resultFile->delete();
			return $result;
		} else {
			return false;
		}
	}

	public function stix($id, $tags, $attachments, $user, $returnType = 'xml', $from = false, $to = false, $last = false, $jobId = false, $returnFile = false) {
		$eventIDs = $this->Attribute->dissectArgs($id);
		$tagIDs = $this->Attribute->dissectArgs($tags);
		$idList = $this->getAccessibleEventIds($eventIDs[0], $eventIDs[1], $tagIDs[0], $tagIDs[1]);
		if (!empty($idList)) {
			$event_ids = $this->fetchEventIds($user, $from, $to, $last, true);
			$event_ids = array_intersect($event_ids, $idList);
		}
		$randomFileName = $this->generateRandomFileName();
		$tmpDir = APP . "files" . DS . "scripts" . DS . "tmp";
		$stixFile = new File($tmpDir . DS . $randomFileName . ".stix");
		$stix_framing = shell_exec('python ' . APP . "files" . DS . "scripts" . DS . 'misp2stix_framing.py ' . escapeshellarg(Configure::read('MISP.baseurl')) . ' ' . escapeshellarg(Configure::read('MISP.org')) . ' ' . escapeshellarg($returnType) . ' 2>' . APP . 'tmp/logs/exec-errors.log');
		if (empty($stix_framing)) {
			$stixFile->delete();
			return array('success' => 0, 'message' => 'There was an issue generating the STIX export.');
		}
		$stixFile->write(substr($stix_framing, 0, -1));
		if ($returnType === 'xml') {
			$stixFile->append("    <stix:Related_Packages>\n");
		}
		$result = array();
		if ($jobId) {
			$this->Job = ClassRegistry::init('Job');
			$this->Job->id = $jobId;
			if (!$this->Job->exists()) $jobId = false;
		}
		$i = 0;
		$eventCount = count($event_ids);
		foreach ($event_ids as $event_id) {
			$tempFile = new File($tmpDir . DS . $randomFileName, true, 0644);
			$event = $this->fetchEvent($user, array('eventid' => $event_id));
			if (empty($event)) continue;
			if ($attachments == "yes" || $attachments == "true" || $attachments == 1) {
				foreach ($event[0]['Attribute'] as &$attribute) {
					if ($this->Attribute->typeIsAttachment($attribute['type'])) {
						$encodedFile = $this->Attribute->base64EncodeAttachment($attribute);
						$attribute['data'] = $encodedFile;
					}
				}
			}
			$event[0]['Tag'] = array();
			foreach ($event[0]['EventTag'] as $tag) {
				$event[0]['Tag'][] = $tag['Tag'];
			}
			App::uses('JSONConverterTool', 'Tools');
			$converter = new JSONConverterTool();
			$event = $converter->convert($event[0]);
			$tempFile->write($event);
			unset($event);
			$scriptFile = APP . "files" . DS . "scripts" . DS . "misp2stix.py";
			$result = shell_exec('python ' . $scriptFile . ' ' . $randomFileName . ' ' . escapeshellarg($returnType) . ' ' . escapeshellarg(Configure::read('MISP.baseurl')) . ' ' . escapeshellarg(Configure::read('MISP.org')) . ' 2>' . APP . 'tmp/logs/exec-errors.log');
			// The result of the script will be a returned JSON object with 2 variables: success (boolean) and message
			// If success = 1 then the temporary output file was successfully written, otherwise an error message is passed along
			$decoded = json_decode($result, true);
			if (!isset($decoded['success']) || !$decoded['success']) {
				$tempFile->delete();
				$stixFile->delete();
				return array('success' => 0, 'message' => $decoded['message']);
			}
			$file = new File(APP . "files" . DS . "scripts" . DS . "tmp" . DS . $randomFileName . ".out");
			if ($returnType == 'xml') {
				$stix_event = '            ' . substr($file->read(), 0, -1);
				$stix_event = explode("\n", $stix_event);
				$stix_event[0] = str_replace("STIX_Package", "Package", $stix_event[0]);
				$stix_event[count($stix_event)-1] = str_replace("STIX_Package", "Package", $stix_event[count($stix_event)-1]);
				$stix_event = implode("\n", $stix_event);
				$stix_event = str_replace("\n", "\n            ", $stix_event) . "\n";
				$stix_event = "        <stix:Related_Package>\n" . $stix_event . "        </stix:Related_Package>\n";
			} else {
				$stix_event = $file->read() . (($i + 1) != $eventCount ? ',' : '');
			}
			$stixFile->append($stix_event);
			$file->close();
			$file->delete();
			$i++;
			if ($jobId) {
				$this->Job->saveField('message', 'Event ' . $i . '/' . $eventCount);
				if ($i % 10 == 0) {
					$this->Job->saveField('progress', $i * 80 / $eventCount);
				}
			}
			$tempFile->close();
		}
		if ($returnType == 'xml') {
			$stixFile->append("    </stix:Related_Packages>\n</stix:STIX_Package>\n\n");
		} else {
			$stixFile->append("]}\n");
		}
		if($tempFile) {
			$tempFile->delete();
		}
		if (!$returnFile) {
			$data = $stixFile->read();
			$stixFile->delete();
		}
		return array('success' => 1, 'data' => $returnFile ? $stixFile->path : $data);
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
		return (new RandomTool())->random_str(FALSE, 12);
	}


	public function sharingGroupRequired($field) {
		if ($this->data[$this->alias]['distribution'] == 4) {
			return (!empty($field));
		}
		return true;
	}

	// convenience method to check whether a user can see an event
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

	private function __prepareAttributeForView(
		$attribute,
		$correlatedAttributes,
		$correlatedShadowAttributes,
		$filterType = false,
		&$eventWarnings,
		$warningLists
	) {
		$attribute['objectType'] = 'attribute';
		$include = true;
		if ($filterType && !in_array($filterType, array('proposal', 'correlation', 'warning'))) {
			if (!in_array($attribute['type'], $this->Attribute->typeGroupings[$filterType])) {
				$include = false;
			}
		}
		if ($filterType === 'proposal' && empty($attribute['ShadowAttribute'])) {
			$include = false;
		}
		if ($filterType === 'correlation' && !in_array($attribute['id'], $correlatedAttributes)) {
			$include = false;
		}
		if (!empty($attribute['ShadowAttribute'])) {
			$temp = array();
			foreach ($attribute['ShadowAttribute'] as $k => $proposal) {
				$result = $this->__prepareProposalForView(
					$proposal,
					$correlatedShadowAttributes,
					$filterType,
					$eventWarnings,
					$warningLists
				);
				if ($result['include']) $temp[] = $result['data'];
			}
			$attribute['ShadowAttribute'] = $temp;
		}
		$attribute = $this->__prepareGenericForView($attribute, $eventWarnings, $warningLists);
		if ($filterType === 'warning') {
			if (empty($attribute['warnings'])) $include = false;
		}
		return array('include' => $include, 'data' => $attribute);
	}

	private function __prepareProposalForView(
		$proposal,
		$correlatedShadowAttributes,
		$filterType = false,
		&$eventWarnings,
		$warningLists
	) {
		if ($proposal['proposal_to_delete']) {
			$proposal['objectType'] = 'proposal_delete';
		} else {
			$proposal['objectType'] = 'proposal';
		}

		$include = true;
		if ($filterType === 'correlation' && !in_array($proposal['id'], $correlatedShadowAttributes)) {
			$include = false;
		}
		if ($filterType && !in_array($filterType, array('proposal', 'correlation', 'warning'))) {
			if (!in_array($proposal['type'], $this->Attribute->typeGroupings[$filterType])) {
				$include = false;
			}
		}
		$proposal = $this->__prepareGenericForView($proposal, $eventWarnings, $warningLists);
		if ($filterType === 'warning') {
			if (empty($proposal['warnings'])) $include = false;
		}
		return array('include' => $include, 'data' => $proposal);
	}

	private function __prepareObjectForView(
		$object,
		$correlatedAttributes,
		$correlatedShadowAttributes,
		$filterType = false,
		&$eventWarnings,
		$warningLists
	) {
		$object['category'] = $object['meta-category'];
		$proposal['objectType'] = 'object';
		// filters depend on child objects
		$include = empty($filterType) || $filterType == 'object' || $object['meta-category'] === $filterType;
		if ($filterType === 'correlation' || $filterType === 'proposal') {
			$include = $this->__checkObjectByFilter($object, $filterType, $correlatedAttributes, $correlatedShadowAttributes);
		}
		if (!empty($object['Attribute'])) {
			$temp = array();
			foreach ($object['Attribute'] as $k => $proposal) {
				$result = $this->__prepareAttributeForView(
					$proposal,
					$correlatedAttributes,
					$correlatedShadowAttributes,
					false,
					$eventWarnings,
					$warningLists
				);
				if ($result['include']) $temp[] = $result['data'];
			}
			$object['Attribute'] = $temp;
		}
		if ($filterType === 'warning') {
			$include = $this->__checkObjectByFilter($object, $filterType, $correlatedAttributes, $correlatedShadowAttributes);
		}
		return array('include' => $include, 'data' => $object);
	}

	private function __checkObjectByFilter($object, $filterType, $correlatedAttributes, $correlatedShadowAttributes) {
		$include = false;
		switch($filterType) {
			case 'warning':
				if (!empty($object['Attribute'])) {
					foreach ($object['Attribute'] as $k => $attribute) {
						if (!empty($attribute['warnings'])) {
							$include = true;
						}
						if (!empty($attribute['ShadowAttribute'])) {
							foreach ($attribute['ShadowAttribute'] as $shadowAttribute) {
								if (!empty($shadowAttribute['warnings'])) {
									$include = true;
								}
							}
						}
					}
				}
				break;
			case 'correlation':
				if (!empty($object['Attribute'])) {
					foreach ($object['Attribute'] as $k => $attribute) {
						if (in_array($attribute['id'], $correlatedAttributes)) {
							$include = true;
						} else {
							if (!empty($attribute['ShadowAttribute'])) {
								foreach ($attribute['ShadowAttribute'] as $k => $shadowAttribute) {
									if (in_array($shadowAttribute['id'], $correlatedShadowAttributes)) {
										$include = true;
									}
								}
							}
						}
					}
				}
				break;
			case 'proposal':
				if (!empty($object['Attribute'])) {
					foreach ($object['Attribute'] as $k => $attribute) {
						if (!empty($attribute['ShadowAttribute'])) {
							$include = true;
						}
					}
				}
				break;
		}
		return $include;
	}

	private function __prepareGenericForView(
		$object,
		&$eventWarnings,
		$warningLists
	) {
		if (!$this->__fTool) {
				$this->__fTool = new FinancialTool();
		}
		if ($object['type'] == 'attachment' && preg_match('/.*\.(jpg|png|jpeg|gif)$/i', $object['value'])) {
			$object['image'] = $this->Attribute->base64EncodeAttachment($object);
		}
		if (isset($object['distribution']) && $object['distribution'] != 4) unset($object['SharingGroup']);
		if ($object['objectType'] !== 'object') {
			if ($object['category'] === 'Financial fraud') {
				if (!$this->__fTool->validateRouter($object['type'], $object['value'])) {
					$object['validationIssue'] = true;
				}
			}
		}
		$object = $this->Warninglist->checkForWarning($object, $eventWarnings, $warningLists);
		return $object;
	}

	public function rearrangeEventForView(&$event, $passedArgs = array(), $all = false) {
		$this->Warninglist = ClassRegistry::init('Warninglist');
		$warningLists = $this->Warninglist->fetchForEventView();
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
		$eventWarnings = array();
		$correlatedAttributes = isset($event['RelatedAttribute']) ? array_keys($event['RelatedAttribute']) : array();
		$correlatedShadowAttributes = isset($event['RelatedShadowAttribute']) ? array_keys($event['RelatedShadowAttribute']) : array();
		$event['objects'] = array();
		foreach ($event['Attribute'] as $attribute) {
			$result = $this->__prepareAttributeForView(
				$attribute,
				$correlatedAttributes,
				$correlatedShadowAttributes,
				$filterType,
				$eventWarnings,
				$warningLists
			);
			if ($result['include']) $event['objects'][] = $result['data'];
		}
		unset($event['Attribute']);
		if (!empty($event['ShadowAttribute'])) {
			foreach ($event['ShadowAttribute'] as $proposal) {
				$result = $this->__prepareProposalForView(
					$proposal,
					$correlatedShadowAttributes,
					$filterType,
					$eventWarnings,
					$warningLists
				);
				$event['objects'][] = $result['data'];
			}
		}
		if (!empty($event['Object'])) {
			foreach ($event['Object'] as $object) {
				$object['objectType'] = 'object';
				$result = $this->__prepareObjectForView(
					$object,
					$correlatedAttributes,
					$correlatedShadowAttributes,
					$filterType,
					$eventWarnings,
					$warningLists
				);
				if ($result['include']) $event['objects'][] = $result['data'];
			}
		}
		unset($event['Object']);
		unset($event['ShadowAttribute']);
		$referencedObjectFields = array('meta-category', 'name', 'uuid', 'id');
		foreach ($event['objects'] as $object) {
			if (!in_array($object['objectType'], array('attribute', 'object'))) continue;
			if (!empty($object['ObjectReference'])) {
				foreach ($object['ObjectReference'] as $reference) {
					if (isset($reference['referenced_uuid'])) {
						foreach ($event['objects'] as $k => $v) {
							if ($v['uuid'] == $reference['referenced_uuid']) {
								$temp = array();
								foreach ($referencedObjectFields as $field) {
									if (isset($object[$field])) $temp[$field] = $object[$field];
								}
								$temp['relationship_type'] = $reference['relationship_type'];
								$event['objects'][$k]['referenced_by'][$object['objectType']][] = $temp;
							}
						}
					}
				}
			}
		}
		App::uses('CustomPaginationTool', 'Tools');
		$customPagination = new CustomPaginationTool();
		if ($all) $passedArgs['page'] = 0;
		$params = $customPagination->applyRulesOnArray($event['objects'], $passedArgs, 'events', 'category');
		$params['total_elements'] = count($event['objects']);
		$event['Event']['warnings'] = $eventWarnings;
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

	public function handleModuleResult($result, $event_id) {
		$resultArray = array();
		$freetextResults = array();
		App::uses('ComplexTypeTool', 'Tools');
		$complexTypeTool = new ComplexTypeTool();
		if (isset($result['results']) && !empty($result['results'])) {
			foreach ($result['results'] as $k => &$r) {
				if (!is_array($r['values'])) {
					$r['values'] = array($r['values']);
				}
				if (!isset($r['types']) && isset($r['type'])) {
					$r['types'] = array($r['type']);
				}
				if (!is_array($r['types'])) {
					$r['types'] = array($r['types']);
				}
				if (isset($r['categories']) && !is_array($r['categories'])) {
					$r['categories'] = array($r['categories']);
				}
				if (isset($r['tags']) && !is_array($r['tags'])) {
					$r['tags'] = array($r['tags']);
				}
				foreach ($r['values'] as &$value) {
					if (!is_array($r['values']) || !isset($r['values'][0])) {
						$r['values'] = array($r['values']);
					}
				}
				foreach ($r['values'] as $valueKey => &$value) {
					if (empty($value)) {
						unset($r['values'][$valueKey]);
						continue;
					}
					if (in_array('freetext', $r['types'])) {
						if (is_array($value)) $value = json_encode($value);
						$this->Warninglist = ClassRegistry::init('Warninglist');
						$complexTypeTool->setTLDs($this->Warninglist->fetchTLDLists());
						$freetextResults = array_merge($freetextResults, $complexTypeTool->checkComplexRouter($value, 'FreeText'));
						if (!empty($freetextResults)) {
							foreach ($freetextResults as &$ft) {
								$temp = array();
								foreach ($ft['types'] as $type) {
									$temp[$type] = $type;
								}
								$ft['types'] = $temp;
								$ft['comment'] = isset($r['comment']) ? $r['comment'] : false;
							}
						}
						$r['types'] = array_diff($r['types'], array('freetext'));
						// if we just removed the only type in the result then more on to the next result
						if (empty($r['types'])) continue 2;
						$r['types'] = array_values($r['types']);
					}
				}
				foreach ($r['values'] as &$value) {
					$temp = array(
							'event_id' => $event_id,
							'types' => $r['types'],
							'default_type' => $r['types'][0],
							'comment' => isset($r['comment']) ? $r['comment'] : false,
							'to_ids' => isset($r['to_ids']) ? $r['to_ids'] : false,
							'value' => $value,
							'tags' => isset($r['tags']) ? $r['tags'] : false
					);
					if (isset($r['categories'])) {
						$temp['categories'] = $r['categories'];
						$temp['default_category'] = $r['categories'][0];
					}
					if (isset($r['data'])) $temp['data'] = $r['data'];
					if (isset($r['distribution'])) $temp['distribution'] = $r['distribution'];
					// if data_is_handled is set then MISP assumes that the sample is already zipped and encrypted
					// in this case it will not try to do this by itself - however it also won't create additional hashes
					if (isset($r['data_is_handled'])) $temp['data_is_handled'] = $r['data_is_handled'];
					$resultArray[] = $temp;
				}

			}
			$resultArray = array_merge($resultArray, $freetextResults);
		}
		return $resultArray;
	}

	public function export($user = false, $module = false, $options = array()) {
		if (empty($user)) return 'Invalid user.';
		if  (empty($module)) return 'Invalid module.';
		$this->Module = ClassRegistry::init('Module');
		$module = $this->Module->getEnabledModule($module, 'Export');
		$events = $this->fetchEvent($user, $options);
		if (empty($events)) return 'Invalid event.';
		$modulePayload = array('module' => $module['name']);
		if (isset($module['meta']['config'])) {
			foreach ($module['meta']['config'] as $conf) {
				$modulePayload['config'][$conf] = Configure::read('Plugin.Export_' . $module['name'] . '_' . $conf);
			}
		}
		$modulePayload['data'] = $events;
		$result = $this->Module->queryModuleServer('/query', json_encode($modulePayload, true), false, 'Export');
		return array(
				'data' => $result['data'],
				'extension' => $module['mispattributes']['outputFileExtension'],
				'response' => $module['mispattributes']['responseType']
		);
	}

	public function getSightingData($event) {
		$this->Sighting = ClassRegistry::init('Sighting');
		if (!empty($event['Sighting'])) {
			$attributeSightings = array();
			$attributeOwnSightings = array();
			$attributeSightingsPopover = array();
			$sightingsData = array();
			$sparklineData = array();
			$startDates = array();
			$range = (!empty(Configure::read('MISP.Sightings_range')) && is_numeric(Configure::read('MISP.Sightings_range'))) ? Configure::read('MISP.Sightings_range') : 365;
			$range = strtotime("-" . $range . " days", time());
			foreach ($event['Sighting'] as $sighting) {
				$type = $this->Sighting->type[$sighting['type']];
				if (!isset($sightingsData[$sighting['attribute_id']][$type])) {
					$sightingsData[$sighting['attribute_id']][$type] = array('count' => 0);
				}
				$sightingsData[$sighting['attribute_id']][$type]['count']++;
				$orgName = isset($sighting['Organisation']['name']) ? $sighting['Organisation']['name'] : 'Others';
				if ($sighting['type'] == '0' && (!isset($startDates[$sighting['attribute_id']]) || $startDates[$sighting['attribute_id']] > $sighting['date_sighting'])) {
					if ($sighting['date_sighting'] >= $range) {
						$startDates[$sighting['attribute_id']] = $sighting['date_sighting'];
					}
				}
				if ($sighting['type'] == '0' && (!isset($startDates['event']) || $startDates['event'] > $sighting['date_sighting'])) {
					if ($sighting['date_sighting'] >= $range) {
						$startDates['event'] = $sighting['date_sighting'];
					}
				}
				if (!isset($sightingsData[$sighting['attribute_id']][$type]['orgs'][$orgName])) {
					$sightingsData[$sighting['attribute_id']][$type]['orgs'][$orgName] = array('count' => 1, 'date' => $sighting['date_sighting']);
				} else {
					$sightingsData[$sighting['attribute_id']][$type]['orgs'][$orgName]['count']++;
					if ($sightingsData[$sighting['attribute_id']][$type]['orgs'][$orgName]['date'] < $sighting['date_sighting']) {
						$sightingsData[$sighting['attribute_id']][$type]['orgs'][$orgName]['date'] = $sighting['date_sighting'];
					}
				}
				if ($sighting['type'] !== '0') continue;
				$date = date("Y-m-d", $sighting['date_sighting']);
				if (!isset($sparklineData[$sighting['attribute_id']][$date])) {
					$sparklineData[$sighting['attribute_id']][$date] = 1;
				} else {
					$sparklineData[$sighting['attribute_id']][$date]++;
				}
				if (!isset($sparklineData['event'][$date])) {
					$sparklineData['event'][$date] = 1;
				} else {
					$sparklineData['event'][$date]++;
				}
			}
			$csv = array();
			foreach ($startDates as $k => $v) {
				$startDates[$k] = date('Y-m-d', $v);
			}
			$range = (!empty(Configure::read('MISP.Sightings_range')) && is_numeric(Configure::read('MISP.Sightings_range'))) ? Configure::read('MISP.Sightings_range') : 365;
			foreach ($sparklineData as $aid => $data) {
				if (!isset($startDates[$aid])) continue;
				$startDate = $startDates[$aid];
				if (strtotime($startDate) < strtotime('-' . $range . ' days', time())) {
					$startDate = date('Y-m-d');
				}
				$startDate = date('Y-m-d',strtotime("-3 days", strtotime($startDate)));
				$to = date('Y-m-d', time());
				$sighting = $data;
				for ($date = $startDate; strtotime($date) <= strtotime($to); $date = date('Y-m-d',strtotime("+1 day", strtotime($date)))) {
					if (!isset($csv[$aid])) {
						$csv[$aid] = 'Date,Close\n';
					}
					if (isset($sighting[$date])) {
						$csv[$aid] .= $date . ',' . $sighting[$date] . '\n';
					} else {
						$csv[$aid] .= $date . ',0\n';
					}
				}
			}
			return array(
					'data' => $sightingsData,
					'csv' => $csv
			);
		}
		return array('data' => array(), 'csv' => array());
	}

	public function setSimpleConditions($parameterKey, $parameterValue, $conditions, $restrictScopeToEvents = false) {
		if (is_array($parameterValue)) {
			$elements = $parameterValue;
		} else {
			$elements = explode('&&', $parameterValue);
		}
		App::uses('CIDRTool', 'Tools');
		$cidr = new CIDRTool();
		$subcondition = array();
		foreach ($elements as $v) {
			if ($v == '') continue;
			if (substr($v, 0, 1) == '!') {
				// check for an IPv4 address and subnet in CIDR notation (e.g. 127.0.0.1/8)
				if ($parameterKey === 'value' && $cidr->checkCIDR(substr($v, 1), 4)) {
					$cidrresults = $cidr->CIDR(substr($v, 1));
					foreach ($cidrresults as $result) {
						$subcondition['AND'][] = array('Attribute.value NOT LIKE' => $result);
					}
				} else {
					if ($parameterKey === 'org') {
						$found_orgs = $this->Org->find('all', array(
							'recursive' => -1,
							'conditions' => array('LOWER(name) LIKE' => '%' . strtolower(substr($v, 1)) . '%'),
						));
						foreach ($found_orgs as $o) {
							$subcondition['AND'][] = array('Event.orgc_id !=' => $o['Org']['id']);
						}
					} else if ($parameterKey === 'eventid') {
						if ($restrictScopeToEvents) {
							$subcondition['AND'][] = array('Event.id !=' => substr($v, 1));
						} else {
							$subcondition['AND'][] = array('Attribute.event_id !=' => substr($v, 1));
						}
					} else if ($parameterKey === 'uuid') {
						$subcondition['AND'][] = array('Event.uuid !=' => substr($v, 1));
						$subcondition['AND'][] = array('Attribute.uuid !=' => substr($v, 1));
					} else {
						$subcondition['AND'][] = array('Attribute.' . $parameterKey . ' NOT LIKE' => '%'.substr($v, 1).'%');
					}
				}
			} else {
				// check for an IPv4 address and subnet in CIDR notation (e.g. 127.0.0.1/8)
				if ($parameterKey === 'value' && $cidr->checkCIDR($v, 4)) {
					$cidrresults = $cidr->CIDR($v);
					foreach ($cidrresults as $result) {
						if (!empty($result)) $subcondition['OR'][] = array('Attribute.value LIKE' => $result);
					}
				} else {
					if ($parameterKey === 'org') {
						$found_orgs = $this->Org->find('all', array(
								'recursive' => -1,
								'conditions' => array('LOWER(name) LIKE' => '%' . strtolower($v) . '%'),
						));
						foreach ($found_orgs as $o) {
							$subcondition['OR'][] = array('Event.orgc_id' => $o['Org']['id']);
						}
					} else if ($parameterKey === 'eventid') {
						if ($restrictScopeToEvents) {
							$subcondition['OR'][] = array('Event.id' => $v);
						} else {
							$subcondition['OR'][] = array('Attribute.event_id' => $v);
						}
					} else if ($parameterKey === 'uuid') {
						$subcondition['OR'][] = array('Attribute.uuid' => $v);
						$subcondition['OR'][] = array('Event.uuid' => $v);
					}else {
						if (!empty($v)) $subcondition['OR'][] = array('Attribute.' . $parameterKey . ' LIKE' => '%'.$v.'%');
					}
				}
			}
		}
		if (!empty($subcondition)) array_push ($conditions['AND'], $subcondition);
		return $conditions;
	}

	public function prepareEventForView() {
		// workaround to get the event dates in to the attribute relations
		$relatedDates = array();
		if (!empty($event['RelatedEvent'])) {
			foreach ($event['RelatedEvent'] as $relation) {
				$relatedDates[$relation['Event']['id']] = $relation['Event']['date'];
			}
			if (!empty($event['RelatedAttribute'])) {
				foreach ($event['RelatedAttribute'] as $key => $relatedAttribute) {
					foreach ($relatedAttribute as $key2 => $relation) {
						$event['RelatedAttribute'][$key][$key2]['date'] = $relatedDates[$relation['id']];
					}
				}
			}
		}
		$dataForView = array(
			'Attribute' => array('attrDescriptions', 'typeDefinitions', 'categoryDefinitions', 'distributionDescriptions', 'distributionLevels', 'shortDist'),
			'Event' => array('fieldDescriptions')
		);
		foreach ($dataForView as $m => $variables) {
			if ($m === 'Event') {
				$currentModel = $this;
			} else if ($m === 'Attribute') {
				$currentModel = $this->Attribute;
			}
			foreach ($variables as $alias => $variable) {
				$this->set($alias, $currentModel->{$variable});
			}
		}
	}

	public function cacheSgids($user, $useCache = false) {
		if ($useCache && isset($this->__assetCache['sgids'])) {
			return $this->__assetCache['sgids'];
		} else {
			$sgids = $this->SharingGroup->fetchAllAuthorised($user);
			if (empty($sgids)) $sgids = array(-1);
			if ($useCache) $this->__assetCache['sgids'] = $sgids;
			return $sgids;
		}
	}

	private function __cacheSharingGroupData($user, $useCache = false) {
		if ($useCache && isset($this->__assetCache['sharingGroupData'])) {
			return $this->__assetCache['sharingGroupData'];
		} else {
			$sharingGroupDataTemp = $this->SharingGroup->fetchAllAuthorised($user, 'simplified');
			$sharingGroupData = array();
			foreach ($sharingGroupDataTemp as $k => $v) {
				if (isset($v['Organisation'])) $v['SharingGroup']['Organisation'] = $v['Organisation'];
				if (isset($v['SharingGroupOrg'])) $v['SharingGroup']['SharingGroupOrg'] = $v['SharingGroupOrg'];
				if (isset($v['SharingGroupServer'])) {
					$v['SharingGroup']['SharingGroupServer'] = $v['SharingGroupServer'];
					foreach ($v['SharingGroup']['SharingGroupServer'] as &$sgs) {
						if ($sgs['server_id'] == 0) {
							$sgs['Server'] = array('id' => '0', 'url' => Configure::read('MISP.baseurl'), 'name' => Configure::read('MISP.baseurl'));
						}
					}
				}
				$sharingGroupData[$v['SharingGroup']['id']] = array('SharingGroup' => $v['SharingGroup']);
			}
			if ($useCache) $this->__assetCache['sharingGroupData'] = $sharingGroupData;
			return $sharingGroupData;
		}
	}

	private function __cachedelegatedEventIDs($user, $useCache = false) {
		if ($useCache && isset($this->__assetCache['delegatedEventIDs'])) {
			return $this->__assetCache['delegatedEventIDs'];
		} else {
			$this->EventDelegation = ClassRegistry::init('EventDelegation');
			$delegatedEventIDs = $this->EventDelegation->find('list', array(
				'conditions' => array('EventDelegation.org_id' => $user['org_id']),
				'fields' => array('event_id')
			));
			if ($useCache) $this->__assetCache['delegationEventIDs'] = $delegatedEventIDs;
			return $delegatedEventIDs;
		}
	}

	private function __generateCachedTagFilters($tagRules, $useCache = false) {
		if ($useCache && isset($this->__assetCache['tagFilters'])) {
			return $this->__assetCache['tagFilters'];
		} else {
			$filters = array();
			$tag = ClassRegistry::init('Tag');
			$args = $this->Attribute->dissectArgs($tagRules);
			$tagArray = $this->EventTag->Tag->fetchEventTagIds($args[0], $args[1]);
			$temp = array();
			foreach ($tagArray[0] as $accepted) {
				$temp['OR'][] = array('Event.id' => $accepted);
			}
			$filters[] = $temp;
			$temp = array();
			foreach ($tagArray[1] as $rejected) {
				$temp['AND'][] = array('Event.id !=' => $rejected);
			}
			$filters[] = $temp;
			if ($useCache) $this->__assetCache['tagFilters'] = $filters;
			return $filters;
		}
	}

	private function __destroyCaches() {
		$this->__assetCache = array();
	}

	public function unpublishEvent($id, $proposalLock = false) {
		$event = $this->find('first', array(
			'recursive' => -1,
			'conditions' => array('Event.id' => $id)
		));
		if (empty($event)) return false;
		$event['Event']['published'] = 0;
		$date = new DateTime();
		$event['Event']['timestamp'] = $date->getTimestamp();
		if ($proposalLock) $event['Event']['proposal_email_lock'] = 0;
		$event['Event']['unpublishAction'] = true;
		return $this->save($event);
	}
}
