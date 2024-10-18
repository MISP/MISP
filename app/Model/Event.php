<?php
App::uses('AppModel', 'Model');
App::uses('CakeEmail', 'Network/Email');
App::uses('AttachmentTool', 'Tools');
App::uses('TmpFileTool', 'Tools');
App::uses('SendEmailTemplate', 'Tools');
App::uses('ProcessTool', 'Tools');

/**
 * @property User $User
 * @property MispAttribute $Attribute
 * @property MispObject $Object
 * @property EventReport $EventReport
 * @property ShadowAttribute $ShadowAttribute
 * @property EventTag $EventTag
 * @property SharingGroup $SharingGroup
 * @property ThreatLevel $ThreatLevel
 * @property Sighting $Sighting
 * @property Organisation $Org
 * @property Organisation $Orgc
 * @property CryptographicKey $CryptographicKey
 * @property Note $Note
 * @property Opinion $Opinion
 * @property Relationship $Relationship
 */
class Event extends AppModel
{
    // Event distribution constants
    const DISTRIBUTION_ORGANISATION = 0,
        DISTRIBUTION_COMMUNITY = 1,
        DISTRIBUTION_CONNECTED = 2,
        DISTRIBUTION_ALL = 3,
        DISTRIBUTION_SHARING_GROUP = 4;

    const NO_PUSH_DISTRIBUTION = 'distribution',
        NO_PUSH_SERVER_RULES = 'push_rules';

    public $actsAs = array(
        'AuditLog',
        'SysLogLogable.SysLogLogable' => array(
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'full'),
        'Trim',
        'Containable',
        'EventWarning',
        'AnalystDataParent'
    );

    public $displayField = 'id';

    public $mispVersion = '2.4.0';

    private $__beforeSaveData = null;

    public $fieldDescriptions = array(
        'threat_level_id' => array('desc' => 'Risk levels: *low* means mass-malware, *medium* means APT malware, *high* means sophisticated APT malware or 0-day attack', 'formdesc' => 'Risk levels: low: mass-malware medium: APT malware high: sophisticated APT malware or 0-day attack'),
        'classification' => array('desc' => 'Set the Traffic Light Protocol classification. <ol><li><em>TLP:AMBER</em>- Share only within the organization on a need-to-know basis</li><li><em>TLP:GREEN:NeedToKnow</em>- Share within your constituency on the need-to-know basis.</li><li><em>TLP:GREEN</em>- Share within your constituency.</li></ol>'),
        'submittedioc' => array('desc' => '', 'formdesc' => ''),
        'analysis' => array('desc' => 'Analysis Levels: *Initial* means the event has just been created, *Ongoing* means that the event is being populated, *Complete* means that the event\'s creation is complete', 'formdesc' => 'Analysis levels: Initial: event has been started Ongoing: event population is in progress Complete: event creation has finished'),
        'distribution' => array('desc' => 'Describes who will have access to the event.')
    );

    public $analysisDescriptions = array(
        0 => array('desc' => '*Initial* means the event has just been created', 'formdesc' => 'Event has just been created and is in an initial state'),
        1 => array('desc' => '*Ongoing* means that the event is being populated', 'formdesc' => 'The analysis is still ongoing'),
        2 => array('desc' => '*Complete* means that the event\'s creation is complete', 'formdesc' => 'The event creator considers the analysis complete')
    );

    public $distributionDescriptions = [
        self::DISTRIBUTION_ORGANISATION => [
            'desc' => 'This field determines the current distribution of the event',
            'formdesc' => "This setting will only allow members of your organisation on this server to see it.",
        ],
        self::DISTRIBUTION_COMMUNITY => [
            'desc' => 'This field determines the current distribution of the event',
            'formdesc' => "Organisations that are part of this MISP community will be able to see the event.",
        ],
        self::DISTRIBUTION_CONNECTED => [
            'desc' => 'This field determines the current distribution of the event',
            'formdesc' => "Organisations that are either part of this MISP community or part of a directly connected MISP community will be able to see the event.",
        ],
        self::DISTRIBUTION_ALL => [
            'desc' => 'This field determines the current distribution of the event',
            'formdesc' => "This will share the event with all MISP communities, allowing the event to be freely propagated from one server to the next.",
        ],
        self::DISTRIBUTION_SHARING_GROUP => [
            'desc' => 'This field determines the current distribution of the event',
            'formdesc' => "This distribution of this event will be handled by the selected sharing group.",
        ],
    ];

    public $distributionLevels = [
        self::DISTRIBUTION_ORGANISATION => 'Your organisation only',
        self::DISTRIBUTION_COMMUNITY => 'This community only',
        self::DISTRIBUTION_CONNECTED => 'Connected communities',
        self::DISTRIBUTION_ALL => 'All communities',
        self::DISTRIBUTION_SHARING_GROUP => 'Sharing group',
    ];

    public $analysisLevels = array(
        0 => 'Initial', 1 => 'Ongoing', 2 => 'Completed'
    );

    public $shortDist = array(0 => 'Organisation', 1 => 'Community', 2 => 'Connected', 3 => 'All', 4 => ' sharing Group');

    public $validFormats = array(
        'attack' => array('html', 'AttackExport', 'html'),
        'attack-sightings' => array('json', 'AttackSightingsExport', 'json'),
        'cache' => array('txt', 'CacheExport', 'cache'),
        'context' => array('html', 'ContextExport', 'html'),
        'context-markdown' => array('txt', 'ContextMarkdownExport', 'md'),
        'count' => array('txt', 'CountExport', 'txt'),
        'csv' => array('csv', 'CsvExport', 'csv'),
        'hashes' => array('txt', 'HashesExport', 'txt'),
        'hosts' => array('txt', 'HostsExport', 'txt'),
        'json' => array('json', 'JsonExport', 'json'),
        'kunai' => ['json', 'KunaiExport', 'json'],
        'netfilter' => array('txt', 'NetfilterExport', 'sh'),
        'opendata' => array('txt', 'OpendataExport', 'txt'),
        'openioc' => array('xml', 'OpeniocExport', 'ioc'),
        'rpz' => array('txt', 'RPZExport', 'rpz'),
        'snort' => array('txt', 'NidsSnortExport', 'rules'),
        'stix' => array('xml', 'Stix1Export', 'xml'),
        'stix-json' => array('json', 'Stix1Export', 'json'),
        'stix2' => array('json', 'Stix2Export', 'json'),
        'suricata' => array('txt', 'NidsSuricataExport', 'rules'),
        'text' => array('text', 'TextExport', 'txt'),
        'xml' => array('xml', 'XmlExport', 'xml'),
        'yara' => array('txt', 'YaraExport', 'yara'),
        'yara-json' => array('json', 'YaraExport', 'json')
    );

    public $possibleOptions = array(
        'eventid',
        'idList',
        'tags',
        'from',
        'to',
        'last',
        'to_ids',
        'includeAllTags', // include also non exportable tags, default `false`
        'includeAttachments',
        'event_uuid',
        'distribution',
        'sharing_group_id',
        'disableSiteAdmin',
        'metadata',
        'enforceWarninglist', // return just attributes that contains no warnings
        'sgReferenceOnly', // do not fetch additional information about sharing groups
        'flatten',
        'blockedAttributeTags',
        'eventsExtendingUuid',
        'extended',
        'extensionList',
        'excludeGalaxy',
        // 'includeCustomGalaxyCluster', // not used
        'includeRelatedTags',
        'excludeLocalTags',
        'includeDecayScore',
        'includeScoresOnEvent',
        'includeSightingdb',
        'includeFeedCorrelations',
        'includeServerCorrelations',
        'includeWarninglistHits',
        'includeGranularCorrelations',
        'noEventReports', // do not include event report in event data
        'noShadowAttributes', // do not fetch proposals,
        'limit',
        'page',
        'order',
        'protected',
        'published',
        'orgc_id',
    );

    public $validate = array(
        'org_id' => array(
            'rule' => 'numeric',
            'required' => true,
            'allowEmpty' => false,
        ),
        'orgc_id' => array(
            'rule' => 'numeric',
            'required' => true,
            'allowEmpty' => false,
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
                'required' => true
            ),
        ),
        'user_id' => array(
            'numeric' => array(
                'rule' => array('numeric')
            )
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
                'rule' => 'uuid',
                'message' => 'Please provide a valid RFC 4122 UUID'
            ),
            'unique' => array(
                'rule' => 'isUnique',
                'message' => 'The UUID provided is not unique',
                'on' => 'create'
            ),
        ),
        'extends_uuid' => array(
            'uuid' => array(
                'rule' => 'uuid',
                'message' => 'Please provide a valid UUID',
                'allowEmpty' => true
            )
        )
    );

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
            'className' => 'MispAttribute',
            'foreignKey' => 'event_id',
            'dependent' => true,    // cascade deletes
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
            'dependent' => true,    // cascade deletes
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
        ),
        'EventReport' => array(
            'className' => 'EventReport',
            'dependent' => true,
        ),
        'CryptographicKey' => [
            'foreignKey' => 'parent_id',
            'conditions' => [
                'parent_type' => 'Event'
            ],
            'dependent' => true
        ]
    );

    private $assetCache = [];

    /** @var array|null */
    private $eventBlockRule;

    public $fast_update = false;

    public function beforeDelete($cascade = true)
    {
        // blocklist the event UUID if the feature is enabled
        if (Configure::read('MISP.enableEventBlocklisting') !== false && empty($this->skipBlocklist)) {
            $this->EventBlocklist = ClassRegistry::init('EventBlocklist');
            $orgc = $this->Orgc->find('first', array('conditions' => array('Orgc.id' => $this->data['Event']['orgc_id']), 'recursive' => -1, 'fields' => array('Orgc.name')));
            $this->EventBlocklist->create();
            $this->EventBlocklist->save(array(
                'event_uuid' => $this->data['Event']['uuid'],
                'event_info' => $this->data['Event']['info'],
                'event_orgc' => $orgc['Orgc']['name'],
                'comment' => __('Automatically blocked by deleting event'),
            ));
        }

        if (!empty($this->data['Event']['id'])) {
            if ($this->pubToZmq('event')) {
                $pubSubTool = $this->getPubSubTool();
                $pubSubTool->event_save(array('Event' => $this->data['Event']), 'delete');
            }
            if (Configure::read('Plugin.Kafka_enable')) {
                $kafkaEventTopic = Configure::read('Plugin.Kafka_event_notifications_topic');
                if (Configure::read('Plugin.Kafka_event_notifications_enable') && !empty($kafkaEventTopic)) {
                    $kafkaPubTool = $this->getKafkaPubTool();
                    $kafkaPubTool->publishJson($kafkaEventTopic, array('Event' => $this->data['Event']), 'delete');
                }
                $kafkaPubTopic = Configure::read('Plugin.Kafka_event_publish_notifications_topic');
                if (!empty($this->data['Event']['published']) && Configure::read('Plugin.Kafka_event_publish_notifications_enable') && !empty($kafkaPubTopic)) {
                    $hostOrg = $this->Org->find('first', array('conditions' => array('name' => Configure::read('MISP.org')), 'fields' => array('id')));
                    if (!empty($hostOrg)) {
                        $user = array('org_id' => $hostOrg['Org']['id'], 'Role' => array('perm_sync' => 0, 'perm_audit' => 0, 'perm_site_admin' => 0), 'Organisation' => $hostOrg['Org']);
                        $params = array('eventid' => $this->data['Event']['id']);
                        if (Configure::read('Plugin.Kafka_include_attachments')) {
                            $params['includeAttachments'] = 1;
                        }
                        $fullEvent = $this->fetchEvent($user, $params);
                        if (!empty($fullEvent)) {
                            $kafkaPubTool = $this->getKafkaPubTool();
                            $kafkaPubTool->publishJson($kafkaPubTopic, $fullEvent[0], 'delete');
                        }
                    }
                }
            }
        }

        try {
            $this->loadAttachmentTool()->deleteAll($this->id);
        } catch (Exception $e) {
            $this->logException('Delete of event file directory failed.', $e);
            throw new InternalErrorException('Delete of event file directory failed. Please report to administrator.');
        }
        $this->CryptographicKey->deleteAll(['CryptographicKey.parent_type' => 'Event', 'CryptographicKey.parent_id' => $this->id]);
    }

    public function beforeValidate($options = array())
    {
        $event = &$this->data['Event'];
        // analysis - setting correct vars
        if (isset($event['analysis'])) {
            switch ($event['analysis']) {
                case 'Initial':
                    $event['analysis'] = 0;
                    break;
                case 'Ongoing':
                    $event['analysis'] = 1;
                    break;
                case 'Completed':
                    $event['analysis'] = 2;
                    break;
            }
        } else {
            $event['analysis'] = 0;
        }

        if (!isset($event['threat_level_id'])) {
            $event['threat_level_id'] = Configure::read('MISP.default_event_threat_level') ?: 4;
        }

        // generate UUID if it doesn't exist
        if (!empty($event['uuid'])) {
            $event['uuid'] = strtolower($event['uuid']);
        }

        // Convert event ID to uuid if needed
        if (!empty($event['extends_uuid'])) {
            if (is_numeric($event['extends_uuid'])) {
                $extended_event = $this->find('first', array(
                    'recursive' => -1,
                    'conditions' => array('Event.id' => $event['extends_uuid']),
                    'fields' => array('Event.uuid')
                ));
                if (empty($extended_event)) {
                    $event['extends_uuid'] = '';
                    $this->invalidate('extends_uuid', 'Invalid event ID provided.');
                } else {
                    $event['extends_uuid'] = $extended_event['Event']['uuid'];
                }
            } else {
                $event['extends_uuid'] = strtolower($event['extends_uuid']);
            }
        }

        // generate timestamp if it doesn't exist
        if (empty($event['timestamp'])) {
            $event['timestamp'] = time();
        }

        if (isset($event['publish_timestamp']) && empty($event['publish_timestamp'])) {
            $event['publish_timestamp'] = 0;
        }

        if (empty($event['date'])) {
            $event['date'] = date('Y-m-d');
        }

        if (!isset($event['distribution']) || $event['distribution'] != 4) {
            $event['sharing_group_id'] = 0;
        }
    }

    public function beforeSave($options = [])
    {
        // generate UUID if not provided
        if (empty($this->data['Event']['uuid'])) {
            $this->data['Event']['uuid'] = CakeText::uuid();
        }
        $this->__beforeSaveData = $this->data['Event'];

        $trigger_id = 'event-before-save';
        if ($this->isTriggerCallable($trigger_id)) {
            $event = $this->data;
            $workflowErrors = [];
            $logging = [
                'model' => 'Event',
                'action' => 'add',
                'id' => 0,
                'message' => __('The workflow `%s` prevented the saving of event (%s)', $trigger_id, $event['Event']['uuid']),
            ];
            $triggerData = $event;
            $workflowSuccess = $this->executeTrigger($trigger_id, $triggerData, $workflowErrors, $logging);
            if (!$workflowSuccess) {
                return false;
            }
        }

        return true;
    }

    public function afterSave($created, $options = array())
    {
        $event = $this->data['Event'];
        if (!Configure::read('MISP.completely_disable_correlation') && !$created) {
            if (
                empty($this->__beforeSaveData) ||
                (
                    isset($this->__beforeSaveData['distribution']) &&
                    $event['distribution'] != $this->__beforeSaveData['distribution']
                ) ||
                (
                    isset($this->__beforeSaveData['sharing_group_id']) &&
                    $event['sharing_group_id'] != $this->__beforeSaveData['sharing_group_id']
                )
            ) {
                $this->Attribute->Correlation->updateContainedCorrelations($event, 'event');
            }
        }
        $this->__beforeSaveData = null;
        if (empty($event['unpublishAction']) && empty($event['skip_zmq']) && $this->pubToZmq('event')) {
            $pubSubTool = $this->getPubSubTool();
            $eventForZmq = $this->quickFetchEvent($event['id']);
            if (!empty($event)) {
                $pubSubTool->event_save($eventForZmq, $created ? 'add' : 'edit');
            }
        }
        if (empty($event['unpublishAction']) && empty($event['skip_kafka'])) {
            $this->publishKafkaNotification('event', $this->quickFetchEvent($event['id']), $created ? 'add' : 'edit');
        }
        if ($this->isTriggerCallable('event-after-save')) {
            $event = $this->quickFetchEvent($event['id']);
            $workflowErrors = [];
            $logging = [
                'model' => 'Event',
                'action' => $created ? 'add' : 'edit',
                'id' => $event['Event']['id'],
            ];
            $triggerData = $event;
            $this->executeTrigger('event-after-save', $triggerData, $workflowErrors, $logging);
        }
    }

    public function attachTagsToEvents(array $events)
    {
        $tagsToFetch = array();
        foreach ($events as $event) {
            foreach ($event['EventTag'] as $et) {
                $tagsToFetch[$et['tag_id']] = $et['tag_id'];
            }
        }
        if (empty($tagsToFetch)) {
            return $events;
        }
        $tags = $this->EventTag->Tag->find('all', array(
            'conditions' => array('Tag.id' => $tagsToFetch),
            'recursive' => -1,
            'fields' => ['id', 'name', 'colour', 'is_galaxy'], // fetch just necessary columns
            'order' => false
        ));
        $tags = array_column(array_column($tags, 'Tag'), null, 'id');
        foreach ($events as &$event) {
            foreach ($event['EventTag'] as &$et) {
                $et['Tag'] = $tags[$et['tag_id']];
            }
        }
        return $events;
    }

    /**
     * @param int $event_id
     * @return array|bool|mixed|null
     * @throws Exception
     */
    public function touch($event_id)
    {
        return $this->unpublishEvent($event_id);
    }

    public function attachTagsToEventAndTouch($event_id, array $options, array $user)
    {
        $tags = $options['tags'];
        $local = $options['local'];
        $relationship = $options['relationship_type'];
        $touchEvent = false;
        $success = false;
        $capturedTags = [];
        foreach ($tags as $tag_name) {
            $nothingToChange = false;
            $tag_id = $this->captureTagWithCache(
                [
                    'name' => $tag_name,
                ],
                $user,
                $capturedTags
            );
            $tag = [
                'id' => $tag_id,
                'local' => $local,
                'relationship_type' => $relationship,
            ];
            $attachSuccess = $this->EventTag->attachTagToEvent($event_id, $tag, $nothingToChange);
            $success = $success || $attachSuccess;
            $touchEvent = $touchEvent || !$nothingToChange;
        }
        if ($touchEvent) {
           return $this->touch($event_id);
        }
        return $success;
    }

    public function detachTagsFromEventAndTouch($event_id, array $options)
    {
        $tags = $options['tags'];
        $local = $options['local'];
        $touchEvent = false;
        $success = false;
        foreach ($tags as $tag_name) {
            $nothingToChange = false;
            $tag_id = $this->EventTag->Tag->lookupTagIdFromName($tag_name);
            if ($tag_id == -1) {
                $success = $success || true;
                continue;
            }
            $detachSuccess = $this->EventTag->detachTagFromEvent($event_id, $tag_id, $local, $nothingToChange);
            $success = $success || $detachSuccess;
            $touchEvent = $touchEvent || !$nothingToChange;
        }
        if ($touchEvent) {
            return $this->touch($event_id);
        }
        return $success;
    }

    /**
     * Gets the logged in user + an array of events, attaches the correlation count to each
     * @param array $user
     * @param array $events
     * @return array
     */
    public function attachCorrelationCountToEvents(array $user, array $events)
    {
        $sgids = $this->SharingGroup->authorizedIds($user);
        foreach ($events as &$event) {
            $event['Event']['correlation_count'] = $this->getRelatedEventCount($user, $event['Event']['id'], $sgids);
        }
        return $events;
    }

    public function attachSightingsCountToEvents(array $user, array $events)
    {
        $eventIds = array_column(array_column($events, 'Event'), 'id');
        $this->Sighting->virtualFields['count'] = 'count(Sighting.id)';
        $sightings = $this->Sighting->find('list', array(
            'fields' => array('Sighting.event_id', 'Sighting.count'),
            'conditions' => array('event_id' => $eventIds),
            'group' => array('event_id')
        ));
        foreach ($events as $key => $event) {
            $events[$key]['Event']['sightings_count'] = isset($sightings[$event['Event']['id']]) ? $sightings[$event['Event']['id']] : 0;
        }
        return $events;
    }

    public function attachProposalsCountToEvents($user, $events)
    {
        $eventIds = array_column(array_column($events, 'Event'), 'id');
        $proposals = $this->ShadowAttribute->find('all', array(
                'fields' => array('ShadowAttribute.event_id', 'count(distinct(ShadowAttribute.id)) as count'),
                'conditions' => array('event_id' => $eventIds, 'deleted' => 0),
                'recursive' => -1,
                'group' => array('event_id')
        ));
        $proposals = Hash::combine($proposals, '{n}.ShadowAttribute.event_id', '{n}.0.count');
        foreach ($events as $key => $event) {
            $events[$key]['Event']['proposals_count'] = isset($proposals[$event['Event']['id']]) ? $proposals[$event['Event']['id']] : 0;
        }
        return $events;
    }

    public function attachDiscussionsCountToEvents($user, $events)
    {
        $eventIds = array_column(array_column($events, 'Event'), 'id');
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

    public function getRelatedEventCount(array $user, $eventId, $sgids)
    {
        if (!isset($sgids) || empty($sgids)) {
            $sgids = array(-1);
        }
        return count($this->Attribute->Correlation->getRelatedEventIds($user, $eventId, $sgids));
    }

    private function getRelatedEvents($user, $eventId, $sgids)
    {
        if (!isset($sgids) || empty($sgids)) {
            $sgids = array(-1);
        }
        $relatedEventIds = $this->Attribute->Correlation->getRelatedEventIds($user, $eventId, $sgids);
        if (empty($relatedEventIds)) {
            return [];
        }
        // now look up the event data for these attributes
        $relatedEvents =  $this->find(
            'all',
            [
                'conditions' => [
                    'Event.id' => $relatedEventIds
                ],
                'recursive' => -1,
                'order' => 'date DESC',
                'fields' => [
                    'id', 'date', 'threat_level_id', 'info', 'published', 'uuid', 'analysis', 'timestamp', 'distribution', 'org_id', 'orgc_id'
                ],
                'contain' => [
                    'Org' => [
                        'fields' => ['id', 'name', 'uuid']
                    ],
                    'Orgc' => [
                        'fields' => ['id', 'name', 'uuid']
                    ]
                ]
            ]
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

    /**
     * Get related attributes for event
     * @param array $user
     * @param int|array $eventIds Event IDs
     * @return array
     */
    public function getRelatedAttributes(array $user, $eventIds)
    {
        if (!isset($this->Correlation)) {
            $this->Correlation = ClassRegistry::init('Correlation');
        }
        $sgids = $this->SharingGroup->authorizedIds($user);
        $relatedAttributes = $this->Correlation->getAttributesRelatedToEvent($user, $eventIds, $sgids);
        return $relatedAttributes;
    }

    /**
     * Clean up an Event Array that was received by an XML request.
     * The structure needs to be changed a little bit to be compatible with what CakePHP expects
     *
     * This function receives the reference of the variable, so no return is required as it directly
     * modifies the original data.
     */
    private function cleanupEventArrayFromXML(&$data)
    {
        $objects = array('Attribute', 'ShadowAttribute', 'Object');
        foreach ($objects as $object) {
            // Workaround for different structure in XML/array than what CakePHP expects
            if (isset($data['Event'][$object]) && is_array($data['Event'][$object]) && count($data['Event'][$object])) {
                if (!is_numeric(implode('', array_keys($data['Event'][$object])))) {
                    // single attribute
                    $data['Event'][$object] = array(0 => $data['Event'][$object]);
                }
                $data['Event'][$object] = array_values($data['Event'][$object]);
            }
        }
        $objects = array('Org', 'Orgc', 'SharingGroup');
        foreach ($objects as $object) {
            if (isset($data['Event'][$object][0])) {
                $data['Event'][$object] = $data['Event'][$object][0];
            }
        }
        return $data;
    }

    /**
     * Returns list of server that event will be pushed.
     * @param array $event
     * @return array
     */
    public function listServerToPush(array $event)
    {
        $elevatedUser = array(
            'Role' => array(
                'perm_site_admin' => 1,
                'perm_sync' => 1,
                'perm_audit' => 0,
            ),
            'org_id' => $event['Event']['orgc_id']
        );
        // Fetch event with details
        $event = $this->fetchEvent($elevatedUser, ['eventid' => $event['Event']['id'], 'metadata' => true]);
        $event = $event[0];

        $this->Server = ClassRegistry::init('Server');
        $servers = $this->Server->find('all', [
            'conditions' => ['Server.push' => true],
            'recursive' => -1,
            'contain' => ['RemoteOrg', 'Organisation'],
            'order' => ['Server.priority ASC', 'Server.id ASC'],
        ]);

        $output = [];
        foreach ($servers as $server) {
            $isEventPushableToServer = $this->shouldBePushedToServer($event, $server, $reason);
            if ($isEventPushableToServer) {
                $result = true;
            } else {
                if ($reason === self::NO_PUSH_DISTRIBUTION) {
                    $result = 'The distribution level of this event blocks it from being pushed.';
                } elseif ($reason === self::NO_PUSH_SERVER_RULES) {
                    $result = 'The server rules blocks it from being pushed.';
                } else {
                    $result = $reason;
                }
            }
            $output[$server['Server']['name']] = $result;
        }
        return $output;
    }

    /**
     * Check if event can be pushed to remote server.
     *
     * @param array $event
     * @param array $server
     * @param string $reason If method returns false, this variable contains reason why event should not be pushed
     * @return bool
     */
    public function shouldBePushedToServer(array $event, array $server, &$reason)
    {
        if (!isset($server['Server']['internal'])) {
            throw new InvalidArgumentException('Invalid Server array provided.');
        }

        // This check is probably redundant, because it should be checked in also in `checkDistributionForPush`
        // But keep it here just for sure
        if (!$server['Server']['internal'] && $event['Event']['distribution'] < self::DISTRIBUTION_CONNECTED) {
            $reason = self::NO_PUSH_DISTRIBUTION;
            return false;
        }

        if (empty($this->Server->eventFilterPushableServers($event, [$server]))) {
            $reason = self::NO_PUSH_SERVER_RULES;
            return false;
        }

        if (!$this->checkDistributionForPush($event, $server)) {
            $reason = self::NO_PUSH_DISTRIBUTION;
            return false;
        }

        return true;
    }

    /**
     * @param array $event
     * @param array $server
     * @param ServerSyncTool $serverSync
     * @return false|string
     * @throws HttpSocketJsonException
     * @throws JsonException
     * @throws Exception
     */
    public function uploadEventToServer(array $event, array $server, ServerSyncTool $serverSync)
    {
        $this->Server = ClassRegistry::init('Server');

        if (empty($this->Server->eventFilterPushableServers($event, [$server]))) {
            return 'The server rules blocks it from being pushed.';
        }
        if (!$this->checkDistributionForPush($event, $server, 'Event')) {
            return 'The distribution level of this event blocks it from being pushed.';
        }

        $push = $this->Server->checkVersionCompatibility($server, false, $serverSync);
        if (empty($push['canPush'])) {
            return 'The remote user is not a sync user - the upload of the event has been blocked.';
        }
        if (!empty($server['Server']['unpublish_event'])) {
            $event['Event']['published'] = 0;
        }
        try {
            // TODO: Replace by __updateEventForSync method in future
            $event = $this->__prepareForPushToServer($event, $server);
            if (is_numeric($event)) {
                throw new Exception("This should never happen.");
            }

            $response = $serverSync->pushEvent($event)->json();
            $serverSync->debug("Pushed event '{$event['Event']['uuid']}' to remote server as event with remote ID {$response['Event']['id']}");
        } catch (Crypt_GPG_KeyNotFoundException $e) {
            $errorMessage = sprintf(
                'Could not push event %s to remote server #%s. Reason: %s',
                $event['Event']['uuid'],
                $server['Server']['id'],
                $e->getMessage()
            );
            $this->logException($errorMessage, $e);
            $this->__logUploadResult($server, $event, $errorMessage);
            return false;
        } catch (Exception $e) {
            $errorMessage = $e->getMessage();
            if ($e instanceof HttpSocketHttpException && $e->getCode() === 403) {
                // Do not log errors that are expected
                $errorJson = $e->getResponse()->json();
                if (isset($errorJson['errors'])) {
                    $errorMessage = $errorJson['errors'];
                    if ($errorMessage === 'Event could not be saved: Event in the request not newer than the local copy.') {
                        return $errorMessage;
                    }
                }
            }
            $this->logException("Could not push event '{$event['Event']['uuid']}' to remote server #{$server['Server']['id']}", $e);
            $this->__logUploadResult($server, $event, $errorMessage);
            return false;
        }
        return 'Success';
    }

    private function __prepareForPushToServer($event, $server)
    {
        $serverId = $server['Server']['id'];
        if ($event['Event']['distribution'] == 4) {
            if (empty($event['SharingGroup']['roaming']) && empty($server['Server']['internal'])) {
                $serverFound = false;
                if (!empty($event['SharingGroup']['SharingGroupServer'])) {
                    foreach ($event['SharingGroup']['SharingGroupServer'] as $sgs) {
                        if ($sgs['server_id'] == $server['Server']['id']) {
                            $serverFound = true;
                        }
                    }
                }
                if (!$serverFound) {
                    $this->log("Error when pushing event {$event['Event']['uuid']} to remote server {$serverId}: server not found in sharing group.");
                    return 403;
                }
            }
            $orgFound = false;
            if (!empty($event['SharingGroup']['SharingGroupOrg'])) {
                foreach ($event['SharingGroup']['SharingGroupOrg'] as $org) {
                    if (isset($org['Organisation']) && $org['Organisation']['uuid'] === $server['RemoteOrg']['uuid']) {
                        $orgFound = true;
                    }
                }
            }
            if (!$orgFound) {
                $this->log("Error when pushing event {$event['Event']['uuid']} to remote server {$serverId}: org not found in sharing group.");
                return 403;
            }
        }
        $serverModel = ClassRegistry::init('Server');
        $server = $serverModel->eventFilterPushableServers($event, array($server));
        if (empty($server)) {
            $this->log("Error when pushing event {$event['Event']['uuid']} to remote server {$serverId}: event doesn't match sever push rules.");
            return 403;
        }
        $server = $server[0];
        if ($this->checkDistributionForPush($event, $server, 'Event')) {
            $event = $this->__updateEventForSync($event, $server);
        } else {
            $this->log("Error when pushing event {$event['Event']['uuid']} to remote server {$serverId}: event doesn't match distribution.");
            return 403;
        }
        return $event;
    }

    private function __rearrangeEventStructureForSync($event)
    {
        // rearrange things to be compatible with the Xml::fromArray()
        $objectsToRearrange = array(
            'Attribute',
            'Object',
            'Orgc',
            'SharingGroup',
            'EventTag',
            'Org',
            'ShadowAttribute',
            'EventReport',
            'CryptographicKey',
            'ThreatLevel',
            'Galaxy'
        );
        foreach ($objectsToRearrange as $o) {
            if (isset($event[$o])) {
                $event['Event'][$o] = $event[$o];
                unset($event[$o]);
            }
        }
        // cleanup the array from things we do not want to expose
        foreach (array('Org', 'org_id', 'orgc_id', 'proposal_email_lock', 'org', 'orgc') as $field) {
            unset($event['Event'][$field]);
        }
        return ['Event' => $event['Event']];
    }

    // since we fetch the event and filter on tags after / server, we need to cull all of the non exportable tags
    public function __removeNonExportableTags($data, $dataType, $server = [])
    {
        if (isset($data[$dataType . 'Tag'])) {
            if (!empty($data[$dataType . 'Tag'])) {
                foreach ($data[$dataType . 'Tag'] as $k => $tag) {
                    if (!$tag['Tag']['exportable'] || (!empty($tag['local']) && empty($server['Server']['internal']))) {
                        unset($data[$dataType . 'Tag'][$k]);
                    } else {
                        unset($tag['org_id']);
                        $data['Tag'][] = $tag['Tag'];
                    }
                }
            }
            unset($data[$dataType . 'Tag']);
        }
        return $data;
    }

    private function __prepareAttributesForSync($data,$server, $pushRules)
    {
        // prepare attribute for sync
        if (!empty($data['Attribute'])) {
            foreach ($data['Attribute'] as $key => $attribute) {
                if (
                    !empty(Configure::read('MISP.enable_synchronisation_filtering_on_type')) &&
                    !empty($pushRules['type_attributes']['NOT']) &&
                    in_array($attribute['type'], $pushRules['type_attributes']['NOT'])
                ) {
                    unset($data['Attribute'][$key]);
                    continue;
                }
                $data['Attribute'][$key] = $this->__updateAttributeForSync($attribute, $server);
                if (empty($data['Attribute'][$key])) {
                    unset($data['Attribute'][$key]);
                } else {
                    $data['Attribute'][$key] = $this->__removeNonExportableTags($data['Attribute'][$key], 'Attribute', $server);
                }
            }
            $data['Attribute'] = array_values($data['Attribute']);
        }
        return $data;
    }

    private function __prepareObjectsForSync($data,$server, $pushRules)
    {
        // prepare Object for sync
        if (!empty($data['Object'])) {
            foreach ($data['Object'] as $key => $object) {
                if (
                    !empty(Configure::read('MISP.enable_synchronisation_filtering_on_type')) &&
                    !empty($pushRules['type_objects']['NOT']) &&
                    in_array($object['template_uuid'], $pushRules['type_objects']['NOT'])
                ) {
                    unset($data['Object'][$key]);
                    continue;
                }
                $data['Object'][$key] = $this->__updateObjectForSync($object, $server);
                if (empty($data['Object'][$key])) {
                    unset($data['Object'][$key]);
                } else {
                    $data['Object'][$key] = $this->__prepareAttributesForSync($data['Object'][$key], $server, $pushRules);
                }
            }
            $data['Object'] = array_values($data['Object']);
        }
        return $data;
    }

    private function __prepareEventReportForSync($data, $server)
    {
        if (!empty($data['EventReport'])) {
            foreach ($data['EventReport'] as $key => $report) {
                $data['EventReport'][$key] = $this->__updateEventReportForSync($report, $server);
                if (empty($data['EventReport'][$key])) {
                    unset($data['EventReport'][$key]);
                }
            }
            $data['EventReport'] = array_values($data['EventReport']);
        }
        if (isset($data['EventReport']) && empty($data['EventReport'])) {
            unset($data['EventReport']);
        }
        return $data;
    }

    private function __updateEventForSync($event, $server)
    {
        $event = $this->__rearrangeEventStructureForSync($event);
        $event['Event'] = $this->__removeNonExportableTags($event['Event'], 'Event', $server);
        // Add the local server to the list of instances in the SG
        if (isset($event['Event']['SharingGroup']) && isset($event['Event']['SharingGroup']['SharingGroupServer'])) {
            foreach ($event['Event']['SharingGroup']['SharingGroupServer'] as &$s) {
                if ($s['server_id'] == 0) {
                    $s['Server'] = array(
                        'id' => 0,
                        'url' => $this->__getAnnounceBaseurl(),
                        'name' => $this->__getAnnounceBaseurl()
                    );
                }
            }
        }

        $pushRules = $this->jsonDecode($server['Server']['push_rules']);
        $event['Event'] = $this->__prepareAttributesForSync($event['Event'], $server, $pushRules);
        $event['Event'] = $this->__prepareObjectsForSync($event['Event'], $server, $pushRules);
        $event['Event'] = $this->__prepareEventReportForSync($event['Event'], $server, $pushRules);

        // Downgrade the event from connected communities to community only
        if (!$server['Server']['internal'] && $event['Event']['distribution'] == 2) {
            $event['Event']['distribution'] = 1;
        }

        return $event;
    }

    private function __updateObjectForSync($object, $server)
    {
        if (!$server['Server']['internal'] && $object['distribution'] < 2) {
            return false;
        }
        // Downgrade the object from connected communities to community only
        if (!$server['Server']['internal'] && $object['distribution'] == 2) {
            $object['distribution'] = 1;
        }
        // If the object has a sharing group attached, make sure it can be transferred
        if ($object['distribution'] == 4) {
            if (!$server['Server']['internal'] && $this->checkDistributionForPush(array('Object' => $object), $server, 'Object') === false) {
                return false;
            }
            // Add the local server to the list of instances in the SG
            if (isset($object['SharingGroup']['SharingGroupServer'])) {
                foreach ($object['SharingGroup']['SharingGroupServer'] as &$s) {
                    if ($s['server_id'] == 0) {
                        $s['Server'] = array(
                            'id' => 0,
                            'url' => $this->__getAnnounceBaseurl(),
                            'name' => $this->__getAnnounceBaseurl()
                        );
                    }
                }
            }
        }
        return $object;
    }

    public function __getAnnounceBaseurl()
    {
        $baseurl = '';
        if (!empty(Configure::read('MISP.external_baseurl'))) {
            $baseurl = Configure::read('MISP.external_baseurl');
        } else if (!empty(Configure::read('MISP.baseurl'))) {
            $baseurl = Configure::read('MISP.baseurl');
        }
        return $baseurl;
    }

    private function __updateAttributeForSync($attribute, $server)
    {
        // do not keep attributes that are private, nor cluster
        if (!$server['Server']['internal'] && $attribute['distribution'] < 2) {
            return false;
        }
        // Downgrade the attribute from connected communities to community only
        if (!$server['Server']['internal'] && $attribute['distribution'] == 2) {
            $attribute['distribution'] = 1;
        }

        // If the attribute has a sharing group attached, make sure it can be transferred
        if ($attribute['distribution'] == 4) {
            if (!$server['Server']['internal'] && $this->checkDistributionForPush(array('Attribute' => $attribute), $server, 'Attribute') === false) {
                return false;
            }
            // Add the local server to the list of instances in the SG
            if (!empty($attribute['SharingGroup']['SharingGroupServer'])) {
                foreach ($attribute['SharingGroup']['SharingGroupServer'] as &$s) {
                    if ($s['server_id'] == 0) {
                        $s['Server'] = array(
                            'id' => 0,
                            'url' => $this->__getAnnounceBaseurl(),
                            'name' => $this->__getAnnounceBaseurl()
                        );
                    }
                }
            }
        }
        // also add the encoded attachment
        if ($this->Attribute->typeIsAttachment($attribute['type'])) {
            $attribute['data'] = $this->Attribute->base64EncodeAttachment($attribute);
        }
        // Passing the attribute ID together with the attribute could cause the deletion of attributes after a publish/push
        // Basically, if the attribute count differed between two instances, and the instance with the lower attribute
        // count pushed, the old attributes with the same ID got overwritten. Unsetting the ID before pushing it
        // solves the issue and a new attribute is always created.
        unset($attribute['id']);
        // remove value1 and value2 from the output
        unset($attribute['value1']);
        unset($attribute['value2']);
        return $attribute;
    }

    private function __updateEventReportForSync($report, $server)
    {
        if (!$server['Server']['internal'] && $report['distribution'] < 2) {
            return false;
        }
        // check if remote version support event reports
        $eventReportSupportedByRemote = false;
        $uri = $server['Server']['url'] . '/eventReports/add';
        $HttpSocket = $this->setupHttpSocket($server, null);
        $request = $this->setupSyncRequest($server);
        try {
            $response = $HttpSocket->get($uri, false, $request);
            if ($response->isOk()) {
                $apiDescription = json_decode($response->body, true);
                $eventReportSupportedByRemote = !empty($apiDescription['description']);
            }
        } catch (Exception $e) {
            $this->Log = ClassRegistry::init('Log');
            $message = __('Remote version does not support event report.');
            $this->Log->createLogEntry('SYSTEM', $action, 'Server', $id, $message);
        }

        if (!$eventReportSupportedByRemote) {
            return [];
        }

        // Downgrade the object from connected communities to community only
        if (!$server['Server']['internal'] && $report['distribution'] == 2) {
            $report['distribution'] = 1;
        }
        // If the object has a sharing group attached, make sure it can be transferred
        if ($report['distribution'] == 4) {
            if (!$server['Server']['internal'] && $this->checkDistributionForPush(array('EventReport' => $report), $server, 'EventReport') === false) {
                return false;
            }
            // Add the local server to the list of instances in the SG
            if (isset($object['SharingGroup']['SharingGroupServer'])) {
                foreach ($object['SharingGroup']['SharingGroupServer'] as &$s) {
                    if ($s['server_id'] == 0) {
                        $s['Server'] = array(
                            'id' => 0,
                            'url' => $this->__getAnnounceBaseurl(),
                            'name' => $this->__getAnnounceBaseurl()
                        );
                    }
                }
            }
        }
        return $report;
    }

    /**
     * Download event metadata from remote server.
     *
     * @param int $eventId
     * @param array $server
     * @param bool $minimal Return just minimal event response
     * @return array|null Null when event doesn't exists on remote server
     * @throws Exception
     */
    public function downloadEventMetadataFromServer($eventId, $server, $minimal = false)
    {
        $serverSync = new ServerSyncTool($server, $this->setupSyncRequest($server));
        $data = $serverSync->eventIndex(['eventid' => $eventId, 'minimal' => $minimal ? '1' : '0'])->json();
        if (empty($data)) {
            return null;
        }
        // Old format used by old MISP version
        if (isset($data['id'])) {
            return $data;
        }
        return $data[0];
    }

    /**
     * @param array $event
     * @return bool
     */
    public function quickDelete(array $event)
    {
        $id = (int)$event['Event']['id'];
        $this->Thread = ClassRegistry::init('Thread');
        $thread = $this->Thread->find('first', array(
            'conditions' => array('Thread.event_id' => $id),
            'fields' => array('Thread.id'),
            'recursive' => -1
        ));
        $thread_id = !empty($thread) ? (int)$thread['Thread']['id'] : false;
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
            ),
            array(
                'table' => 'event_reports',
                'foreign_key' => 'event_id',
                'value' => $id
            )
        );
        if ($thread_id) {
            $relations[] =  array(
                'table' => 'posts',
                'foreign_key' => 'thread_id',
                'value' => $thread_id
            );
        }
        if (!Configure::read('MISP.completely_disable_correlation')) {
            $correlationTableName = $this->Attribute->Correlation->getTableName();
            array_push(
                $relations,
                array(
                    'table' => $correlationTableName,
                    'foreign_key' => 'event_id',
                    'value' => $id
                ),
                array(
                    'table' => $correlationTableName,
                    'foreign_key' => '1_event_id',
                    'value' => $id
                )
            );
        }

        $db = $this->getDataSource();
        $db->begin();
        $connection = $db->getConnection();
        foreach ($relations as $relation) {
            $query = $connection->prepare('DELETE FROM ' . $db->name($relation['table']) . ' WHERE ' . $db->name($relation['foreign_key']) . ' = :value');
            $query->bindValue(':value', $relation['value'], PDO::PARAM_INT);
            $query->execute();
        }
        if (!$db->commit()) {
            return false;
        }
        $this->set($event);
        return $this->delete(null, false);
    }

    public function createEventConditions($user, $skip_own_event_rule = false)
    {
        $conditions = array();
        if (!$user['Role']['perm_site_admin']) {
            $sgids = $this->SharingGroup->authorizedIds($user);
            $unpublishedPrivate = Configure::read('MISP.unpublishedprivate');
            $conditions['AND']['OR'] = [
                [
                    'AND' => [
                        'Event.distribution >' => 0,
                        'Event.distribution <' => 4,
                        $unpublishedPrivate ? array('Event.published' => 1) : [],
                    ],
                ],
                [
                    'AND' => [
                        'Event.sharing_group_id' => $sgids,
                        'Event.distribution' => 4,
                        $unpublishedPrivate ? array('Event.published' => 1) : [],
                    ]
                ]
            ];
            if (!$skip_own_event_rule) {
                $conditions['AND']['OR'][] = ['Event.org_id' => $user['org_id']];
            }
        }
        return $conditions;
    }

    public function set_filter_wildcard(&$params, $conditions, $options)
    {
        $tempConditions = array();
        $tempConditions[] = array('Event.info LIKE' => $params['wildcard']);
        $attributeParams = array('value1', 'value2', 'comment');
        foreach ($attributeParams as $attributeParam) {
            $subQueryOptions = array(
                'conditions' => array('Attribute.' . $attributeParam . ' LIKE' => $params['wildcard']),
                'fields' => array('event_id')
            );
            $tempConditions[] = $this->subQueryGenerator($this->Attribute, $subQueryOptions, 'Event.id');
        }
        $tagScopes = array('Event', 'Attribute');
        $this->AttributeTag = ClassRegistry::init('AttributeTag');
        $tagIds = $this->AttributeTag->Tag->find('column', array(
            'recursive' => -1,
            'conditions' => array('Tag.name LIKE' => $params['wildcard']),
            'fields' => array('Tag.id')
        ));
        if (!empty($tagIds)) {
            foreach ($tagScopes as $tagScope) {
                $subQueryOptions = array(
                    'conditions' => array(
                        'tag_id' => $tagIds,
                    ),
                    'fields' => array('event_id')
                );
                $tempConditions[] = $this->subQueryGenerator($this->{$tagScope . 'Tag'}, $subQueryOptions, 'Event.id');
            }
        }
        return $tempConditions;
    }

    public function set_filter_wildcard_attributes(&$params, $conditions, $options)
    {
        $tempConditions = array();
        $tempConditions[] = array('Event.info LIKE' => $params['wildcard']);
        $attributeParams = array('value1', 'value2', 'comment');
        foreach ($attributeParams as $attributeParam) {
            $tempConditions[] = array('Attribute.' . $attributeParam . ' LIKE' => $params['wildcard']);
        }
        $tagIds = $this->Attribute->AttributeTag->Tag->find('column', array(
            'recursive' => -1,
            'conditions' => array('Tag.name LIKE' => $params['wildcard']),
            'fields' => array('Tag.id')
        ));
        if (!empty($tagIds)) {
            $subQueryOptions = array(
                'conditions' => array(
                    'tag_id' => $tagIds,
                ),
                'fields' => array('event_id')
            );
            $tempConditions[] = $this->subQueryGenerator($this->EventTag, $subQueryOptions, 'Attribute.event_id');
            $subQueryOptions = array(
                'conditions' => array(
                    'tag_id' => $tagIds,
                ),
                'fields' => array('attribute_id')
            );
            $tempConditions[] = $this->subQueryGenerator($this->Attribute->AttributeTag, $subQueryOptions, 'Attribute.id');
        }
        return $tempConditions;
    }

    /**
     * @param array $user
     * @param array $params
     * @param int $result_count
     * @return array Event IDs, when `include_attribute_count` is enabled, then it is Event ID => Attribute count
     */
    public function filterEventIds($user, &$params = array(), &$result_count = 0)
    {
        $conditions = $this->createEventConditions($user);
        if (isset($params['wildcard'])) {
            $temp = array();
            $options = array(
                'filter' => 'wildcard',
                'scope' => 'Event',
                'pop' => false,
                'context' => 'Event'
            );
            $conditions['AND'][] = array('OR' => $this->set_filter_wildcard($params, $temp, $options));
        } else {
            $simple_params = array(
                'Event' => array(
                    'eventid' => array('function' => 'set_filter_eventid', 'pop' => true),
                    'eventinfo' => array('function' => 'set_filter_eventinfo'),
                    'ignore' => array('function' => 'set_filter_ignore'),
                    'tags' => array('function' => 'set_filter_tags', 'pop' => true),
                    'event_tags' => array('function' => 'set_filter_tags', 'pop' => true),
                    'from' => array('function' => 'set_filter_timestamp', 'pop' => true),
                    'to' => array('function' => 'set_filter_timestamp', 'pop' => true),
                    'date' => array('function' => 'set_filter_date', 'pop' => true),
                    'last' => array('function' => 'set_filter_timestamp', 'pop' => true),
                    'timestamp' => array('function' => 'set_filter_timestamp', 'pop' => true),
                    'event_timestamp' => array('function' => 'set_filter_timestamp', 'pop' => true),
                    'publish_timestamp' => array('function' => 'set_filter_timestamp', 'pop' => true),
                    'org' => array('function' => 'set_filter_org', 'pop' => true),
                    'orgc_id' => array('function' => 'set_filter_orgc_id', 'pop' => true),
                    'uuid' => array('function' => 'set_filter_uuid', 'pop' => true),
                    'published' => array('function' => 'set_filter_published', 'pop' => true),
                    'threat_level_id' => array('function' => 'set_filter_threat_level_id', 'pop' => true),
                    'sharinggroup' => array('function' => 'set_filter_sharing_group')
                ),
                'Object' => array(
                    'object_name' => array('function' => 'set_filter_object_name'),
                    'object_template_uuid' => array('function' => 'set_filter_object_template_uuid'),
                    'object_template_version' => array('function' => 'set_filter_object_template_version')
                ),
                'Attribute' => array(
                    'value' => array('function' => 'set_filter_value'),
                    'category' => array('function' => 'set_filter_simple_attribute'),
                    'type' => array('function' => 'set_filter_type'),
                    'object_relation' => array('function' => 'set_filter_simple_attribute'),
                    'tags' => array('function' => 'set_filter_tags', 'pop' => true),
                    'ignore' => array('function' => 'set_filter_ignore'),
                    'deleted' => array('function' => 'set_filter_deleted'),
                    'to_ids' => array('function' => 'set_filter_to_ids'),
                    'comment' => array('function' => 'set_filter_comment'),
                    'sharinggroup' => array('function' => 'set_filter_sharing_group')
                )
            );
            foreach ($params as $param => $paramData) {
                foreach ($simple_params as $scope => $simple_param_scoped) {
                    if (isset($simple_param_scoped[$param]) && $paramData !== false) {
                        $options = array(
                            'filter' => $param,
                            'scope' => $scope,
                            'pop' => !empty($simple_param_scoped[$param]['pop']),
                            'context' => 'Event'
                        );
                        if ($scope === 'Event') {
                            $conditions = $this->{$simple_param_scoped[$param]['function']}($params, $conditions, $options);
                        } else {
                            $temp = array();
                            $temp = $this->{$simple_param_scoped[$param]['function']}($params, $temp, $options);
                            if (!empty($temp)) {
                                $subQueryOptions = array(
                                    'conditions' => $temp,
                                    'fields' => array(
                                        'event_id'
                                    )
                                );
                                $subQuery = $this->subQueryGenerator($this->{$scope}, $subQueryOptions, 'Event.id');
                                if ($param === 'value') {
                                    $subQuery[0] = explode('WHERE', $subQuery[0]);
                                    $subQuery[0][0] .= ' USE INDEX (value1, value2) ';
                                    $subQuery[0] = implode('WHERE', $subQuery[0]);
                                }
                                $conditions['AND'][] = $subQuery;
                            }
                        }
                    }
                }
            }
        }
        $find_params = array(
            'conditions' => $conditions,
            'recursive' => -1,
        );
        if (isset($params['order'])) {
            $find_params['order'] = $this->findOrder(
                $params['order'],
                'Event',
                ['id', 'info', 'analysis', 'threat_level_id', 'distribution', 'timestamp', 'publish_timestamp']
            );
        }
        if (isset($params['limit'])) {
            // Get the count (but not the actual data) of results for paginators
            $result_count = $this->find('count', $find_params);
            $find_params['limit'] = $params['limit'];
            if (isset($params['page'])) {
                $find_params['page'] = $params['page'];
            }
        }
        if (!empty($params['include_attribute_count'])) {
            $find_params['fields'] = array('Event.id', 'Event.attribute_count');
            $results = $this->find('list', $find_params);
        } else {
            $find_params['fields'] = array('Event.id');
            $results = $this->find('column', $find_params);
        }
        if (!isset($params['limit'])) {
            $result_count = count($results);
        }
        return $results;
    }

    public function fetchSimpleEventIds(array $user, $params = array())
    {
        $conditions = $this->createEventConditions($user);
        $conditions['AND'][] = $params['conditions'];
        $results = $this->find('column', array(
            'conditions' => $conditions,
            'fields' => array('Event.id')
        ));
        return $results;
    }

    /**
     * @param array $user
     * @param string|int $id Event ID or UUID
     * @param array $params
     * @return array|null
     */
    public function fetchSimpleEvent(array $user, $id, array $params = array())
    {
        $conditions = $this->createEventConditions($user);

        if (is_numeric($id)) {
            $conditions['AND'][]['Event.id'] = $id;
        } else if (Validation::uuid($id)) {
            $conditions['AND'][]['Event.uuid'] = $id;
        } else {
            return null;
        }
        if (isset($params['conditions'])) {
            $conditions['AND'][] = $params['conditions'];
        }
        $params['conditions'] = $conditions;
        $params['recursive'] = -1;
        return $this->find('first', $params);
    }

    /**
     * @param array $user
     * @param array $params
     * @param bool $includeOrgc
     * @return array
     */
    public function fetchSimpleEvents(array $user, array $params, $includeOrgc = false)
    {
        $conditions = $this->createEventConditions($user);
        $conditions['AND'][] = $params['conditions'];
        $params = array(
            'conditions' => $conditions,
            'recursive' => -1
        );
        if ($includeOrgc) {
            $params['contain'] = array('Orgc.name');
        }
        return $this->find('all', $params);
    }

    public function fetchEventIds($user, $options)
    {
        // restricting to non-private or same org if the user is not a site-admin.
        $conditions = $this->createEventConditions($user);
        $paramMapping = [
            'from' => 'Event.date >=',
            'to' => 'Event.date <=',
            'last' => 'Event.publish_timestamp >=',
            'timestamp' => 'Event.timestamp >=',
            'publish_timestamp' => 'Event.publish_timestamp >=',
            'eventIdList' => 'Event.id',
        ];
        foreach ($paramMapping as $paramName => $paramLookup) {
            if (isset($options[$paramName])) {
                $conditions['AND'][] = [$paramLookup => $options[$paramName]];
            }
        }
        if (isset($options['list'])) {
            $params = array(
                'conditions' => $conditions,
                'fields' => ['Event.id'],
            );
            $results = $this->find('column', $params);
        } else {
            $params = array(
                'conditions' => $conditions,
                'recursive' => -1,
                'fields' => ['Event.id', 'Event.org_id', 'Event.distribution', 'Event.sharing_group_id'],
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
    public function quickFetchEvent($id)
    {
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
    public function fetchEvent($user, $options = array(), $useCache = false)
    {
        if (!isset($user['org_id'])) {
            throw new InvalidArgumentException('There was an error with the user account (missing `org_id` field).');
        }
        if (isset($options['Event.id'])) {
            $options['eventid'] = $options['Event.id'];
        }
        if (!isset($options['excludeLocalTags']) && !empty($user['Role']['perm_sync']) && empty($user['Role']['perm_site_admin'])) {
            $options['excludeLocalTags'] = 1;
        }
        if (!isset($options['includeEventCorrelations'])) {
            $options['includeEventCorrelations'] = true;
        }
        if (!isset($options['fetchFullClusters'])) {
            $options['fetchFullClusters'] = true;
        }
        if (!isset($options['fetchFullClusterRelationship'])) {
            $options['fetchFullClusterRelationship'] = false;
        }
        if (!isset($options['includeAnalystData'])) {
            $options['includeAnalystData'] = false;
        } else {
            $options['includeAnalystData'] = !empty($options['includeAnalystData']);
        }
        foreach ($this->possibleOptions as $opt) {
            if (!isset($options[$opt])) {
                $options[$opt] = null;
            }
        }
        $conditions = $this->createEventConditions($user);
        if ($options['eventid']) {
            $conditions['AND'][] = array("Event.id" => $options['eventid']);
        }
        if ($options['eventsExtendingUuid']) {
            if (!is_array($options['eventsExtendingUuid'])) {
                $options['eventsExtendingUuid'] = array($options['eventsExtendingUuid']);
            }
            foreach ($options['eventsExtendingUuid'] as $extendedEvent) {
                $extendedUuids = array();
                if (!Validation::uuid($extendedEvent)) {
                    $eventUuid = $this->find('first', array(
                        'recursive' => -1,
                        'conditions' => array('Event.id' => $extendedEvent),
                        'fields' => array('Event.uuid')
                    ));
                    if (!empty($eventUuid)) {
                        $extendedUuids[] = $eventUuid['Event']['uuid'];
                    }
                } else {
                    $extendedUuids[] = $extendedEvent;
                }
            }
            if (!empty($extendedUuids)) {
                $conditions['AND'][] = array('Event.extends_uuid' => $extendedUuids);
            } else {
                // We've set as a search pattern any event that extends an event and didn't find anything
                // valid, make sure we don't get everything thrown in our face that the user can see.
                $conditions['AND'][] = array('Event.id' => -1);
            }
        }
        $isSiteAdmin = $user['Role']['perm_site_admin'];
        if (isset($options['disableSiteAdmin']) && $options['disableSiteAdmin']) {
            $isSiteAdmin = false;
        }
        $conditionsAttributes = array();
        $conditionsObjects = array();
        $conditionsEventReport = array();

        $flatten = (bool)$options['flatten'];
        // restricting to non-private or same org if the user is not a site-admin.
        $sgids = $this->SharingGroup->authorizedIds($user);
        if (!$isSiteAdmin) {
            // if delegations are enabled, check if there is an event that the current user might see because of the request itself
            if (Configure::read('MISP.delegation')) {
                $delegatedEventIDs = $this->__cachedelegatedEventIDs($user, $useCache);
                $conditions['AND']['OR']['Event.id'] = $delegatedEventIDs;
            }
            $attributeCondSelect = '(SELECT events.org_id FROM events WHERE events.id = Attribute.event_id)';
            $objectCondSelect = '(SELECT events.org_id FROM events WHERE events.id = Object.event_id)';
            $eventReportCondSelect = '(SELECT events.org_id FROM events WHERE events.id = EventReport.event_id)';
            if (!$this->isMysql()) {
                $schemaName = $this->getDataSource()->config['schema'];
                $attributeCondSelect = sprintf('(SELECT "%s"."events"."org_id" FROM "%s"."events" WHERE "%s"."events"."id" = "Attribute"."event_id")', $schemaName, $schemaName, $schemaName);
                $objectCondSelect = sprintf('(SELECT "%s"."events"."org_id" FROM "%s"."events" WHERE "%s"."events"."id" = "Object"."event_id")', $schemaName, $schemaName, $schemaName);
                $eventReportCondSelect = sprintf('(SELECT "%s"."events"."org_id" FROM "%s"."events" WHERE "%s"."events"."id" = "EventReport"."event_id")', $schemaName, $schemaName, $schemaName);
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
                $attributeCondSelect => $user['org_id']
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
                $objectCondSelect => $user['org_id']
            );

            $conditionsEventReport['AND'][0]['OR'] = array(
                array('AND' => array(
                    'EventReport.distribution >' => 0,
                    'EventReport.distribution !=' => 4,
                )),
                array('AND' => array(
                    'EventReport.distribution' => 4,
                    'EventReport.sharing_group_id' => $sgids,
                )),
                $eventReportCondSelect => $user['org_id']
            );
        }
        if ($options['distribution']) {
            $conditions['AND'][] = array('Event.distribution' => $options['distribution']);
            $conditionsAttributes['AND'][] = array('Attribute.distribution' => $options['distribution']);
            $conditionsObjects['AND'][] = array('Object.distribution' => $options['distribution']);
            $conditionsEventReport['AND'][] = array('EventReport.distribution' => $options['distribution']);
        }
        if ($options['sharing_group_id']) {
            $conditions['AND'][] = array('Event.sharing_group_id' => $options['sharing_group_id']);
            $conditionsAttributes['AND'][] = array('Attribute.sharing_group_id' => $options['sharing_group_id']);
            $conditionsObjects['AND'][] = array('Object.sharing_group_id' => $options['sharing_group_id']);
            $conditionsEventReport['AND'][] = array('EventReport.sharing_group_id' => $options['sharing_group_id']);
        }
        if ($options['from']) {
            $conditions['AND'][] = array('Event.date >=' => $options['from']);
        }
        if ($options['to']) {
            $conditions['AND'][] = array('Event.date <=' => $options['to']);
        }
        if ($options['last']) {
            $conditions['AND'][] = array('Event.publish_timestamp >=' => $options['last']);
        }
        if ($options['event_uuid']) {
            $conditions['AND'][] = array('Event.uuid' => $options['event_uuid']);
        }
        if (isset($options['protected'])) {
            $conditions['AND'][] = array('Event.protected' => $options['protected']);
        }
        if (isset($options['published'])) {
            $conditions['AND'][] = array('Event.published' => $options['published']);
        }
        if ($options['orgc_id']) {
            $conditions['AND'][] = array('Event.orgc_id' => $options['orgc_id']);
        }
        if (!empty($options['includeRelatedTags'])) {
            $options['includeGranularCorrelations'] = 1;
        }
        if (isset($options['ignore']) && empty($options['ignore'])) {
            $conditions['AND'][] = array('Event.published' => 1);
            $conditionsAttributes['AND'][] = array('Attribute.to_ids' => 1);
        }
        $softDeletables = array('Attribute', 'Object', 'EventReport');
        if (isset($options['deleted'])) {
            if (!is_array($options['deleted'])) {
                $options['deleted'] = array($options['deleted']);
            }
            foreach ($options['deleted'] as $deleted_key => $deleted_value) {
                if ($deleted_value === 'only') {
                    $deleted_value = 1;
                }
                $options['deleted'][$deleted_key] = (int)$deleted_value;
            }
            if (!$user['Role']['perm_sync']) {
                foreach ($softDeletables as $softDeletable) {
                    if (in_array(0, $options['deleted'])) {
                        $deletion_subconditions = array(
                            sprintf('%s.deleted', $softDeletable) => 0
                        );
                    } else {
                        $deletion_subconditions = array(
                            '1=0'
                        );
                    }
                    ${'conditions' . $softDeletable . 's'}['AND'][] = array(
                        'OR' => array(
                            'AND' => array(
                                sprintf('(SELECT events.org_id FROM events WHERE events.id = %s.event_id)', $softDeletable) => $user['org_id'],
                                "$softDeletable.deleted" => $options['deleted'],
                            ),
                            $deletion_subconditions
                        )
                    );
                }
            } else {
                // MySQL couldn't optimise query, so it is better just skip this condition
                $both = in_array(0, $options['deleted']) && in_array(1, $options['deleted']);
                if (!$both) {
                    foreach ($softDeletables as $softDeletable) {
                        ${'conditions' . $softDeletable . 's'}['AND'][] = [
                            "$softDeletable.deleted" => $options['deleted'],
                        ];
                    }
                }
            }
        } else {
            foreach ($softDeletables as $softDeletable) {
                ${'conditions' . $softDeletable . 's'}['AND'][$softDeletable . '.deleted'] = 0;
            }
        }
        $proposal_conditions = array('OR' => array('ShadowAttribute.deleted' => 0));
        if (isset($options['deleted_proposals'])) {
            if ($isSiteAdmin) {
                $proposal_conditions = array('OR' => array('ShadowAttribute.deleted' => 1));
            } else {
                $proposal_conditions['OR'][] = array('(SELECT events.org_id FROM events WHERE events.id = ShadowAttribute.event_id)' => $user['org_id']);
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
        if (!empty($options['to_ids']) || $options['to_ids'] === 0) {
            $conditionsAttributes['AND'][] = array('Attribute.to_ids' => $options['to_ids']);
        }

        // removing this for now, we export the to_ids == 0 attributes too, since there is a to_ids field indicating it in the .xml
        // $conditionsAttributes['AND'] = array('Attribute.to_ids =' => 1);
        // Same idea for the published. Just adjust the tools to check for this
        // $conditions['AND'][] = array('Event.published =' => 1);

        // do not expose all the data ...
        $fields = array('Event.id', 'Event.orgc_id', 'Event.org_id', 'Event.date', 'Event.threat_level_id', 'Event.info', 'Event.published', 'Event.uuid', 'Event.attribute_count', 'Event.analysis', 'Event.timestamp', 'Event.distribution', 'Event.proposal_email_lock', 'Event.user_id', 'Event.locked', 'Event.publish_timestamp', 'Event.sharing_group_id', 'Event.disable_correlation', 'Event.extends_uuid', 'Event.protected');
        $fieldsAtt = array('Attribute.id', 'Attribute.type', 'Attribute.category', 'Attribute.value', 'Attribute.to_ids', 'Attribute.uuid', 'Attribute.event_id', 'Attribute.distribution', 'Attribute.timestamp', 'Attribute.comment', 'Attribute.sharing_group_id', 'Attribute.deleted', 'Attribute.disable_correlation', 'Attribute.object_id', 'Attribute.object_relation', 'Attribute.first_seen', 'Attribute.last_seen');
        $fieldsShadowAtt = array('ShadowAttribute.id', 'ShadowAttribute.type', 'ShadowAttribute.category', 'ShadowAttribute.value', 'ShadowAttribute.to_ids', 'ShadowAttribute.uuid', 'ShadowAttribute.event_uuid', 'ShadowAttribute.event_id', 'ShadowAttribute.old_id', 'ShadowAttribute.comment', 'ShadowAttribute.org_id', 'ShadowAttribute.proposal_to_delete', 'ShadowAttribute.timestamp', 'ShadowAttribute.first_seen', 'ShadowAttribute.last_seen');
        $fieldsOrg = array('id', 'name', 'uuid', 'local');
        $params = array(
            'conditions' => $conditions,
            'recursive' => 0,
            'fields' => $fields,
            'contain' => array(
                'ThreatLevel' => array(
                        'fields' => array('ThreatLevel.name')
                ),
                'Attribute' => array(
                    'fields' => $fieldsAtt,
                    'conditions' => $conditionsAttributes,
                    'order' => false
                ),
                'Object' => array(
                    'conditions' => $conditionsObjects,
                    'order' => false,
                ),
                'ShadowAttribute' => array(
                    'fields' => $fieldsShadowAtt,
                    'conditions' => $proposal_conditions,
                    'Org' => array('fields' => $fieldsOrg),
                    'order' => false
                ),
                'EventTag' => array(
                    'order' => false
                ),
                'EventReport' => array(
                    'conditions' => $conditionsEventReport,
                    'order' => false
                ),
                'CryptographicKey'
            )
        );
        if (!empty($options['excludeLocalTags'])) {
            $params['contain']['EventTag']['conditions'] = array(
                'EventTag.local' => 0
            );
        }
        if ($flatten) {
            unset($params['contain']['Object']);
        }
        if ($options['noEventReports']) {
            unset($params['contain']['EventReport']);
        }
        if ($options['noShadowAttributes']) {
            unset($params['contain']['ShadowAttribute']);
        }
        if ($options['metadata']) {
            unset($params['contain']['Attribute']);
            unset($params['contain']['ShadowAttribute']);
            unset($params['contain']['Object']);
            unset($params['contain']['EventReport']);
        }
        if (!empty($options['limit'])) {
            $params['limit'] = $options['limit'];
        }
        if (!empty($options['page'])) {
            $params['page'] = $options['page'];
        }
        $this->includeAnalystData = $options['includeAnalystData'];
        $this->includeAnalystDataRecursive = $options['includeAnalystData'];
        if (!empty($options['order'])) {
            $params['order'] = $this->findOrder(
                $options['order'],
                'Event',
                ['id', 'info', 'analysis', 'threat_level_id', 'distribution', 'timestamp', 'publish_timestamp']
            );
        }
        $results = $this->find('all', $params);
        if (empty($results)) {
            return array();
        }
        $sharingGroupReferenceOnly = (bool)$options['sgReferenceOnly'];
        $sharingGroupData = $sharingGroupReferenceOnly ? [] : $this->__cacheSharingGroupData($user, $useCache);

        // Initialize classes that will be necessary during event fetching
        if ((!empty($options['includeDecayScore']) || !empty($options['includeScoresOnEvent'])) && !isset($this->DecayingModel)) {
            $this->DecayingModel = ClassRegistry::init('DecayingModel');
        }
        if (
            $options['includeServerCorrelations'] &&
            (!$isSiteAdmin && $user['org_id'] != Configure::read('MISP.host_org_id') && !Configure::read('MISP.show_server_correlations_for_all_users', false))
        ) {
            $options['includeServerCorrelations'] = false; // not permission to see server correlations
        }
        if (($options['includeFeedCorrelations'] || $options['includeServerCorrelations']) && !isset($this->Feed)) {
            $this->Feed = ClassRegistry::init('Feed');
        }
        if (($options['enforceWarninglist'] || $options['includeWarninglistHits']) && !isset($this->Warninglist)) {
            $this->Warninglist = ClassRegistry::init('Warninglist');
        }
        // Precache current user email
        $userEmails = empty($user['id']) ? [] : [$user['id'] => $user['email']];

        if (!$options['includeAllTags']) {
            $justExportableTags = true;
        } else {
            $justExportableTags = false;
        }

        $overrideLimit = !empty($options['overrideLimit']);

        if (!empty($options['allow_proposal_blocking']) && !Configure::read('MISP.proposals_block_attributes')) {
            $options['allow_proposal_blocking'] = false; // proposal blocking is not enabled
        }

        if (!$options['metadata']) {
            $this->__attachAttributeTags($results, $options['excludeLocalTags']);
        }

        if (!$options['metadata'] && !$flatten) {
            $this->__attachReferences($results);
        }

        foreach ($results as &$event) {
            /*
            // REMOVING THIS FOR NOW - users should see data they own, even if they're not in the sharing group.
            if ($event['Event']['distribution'] == 4 && !in_array($event['Event']['sharing_group_id'], $sgids)) {
                $this->Log = ClassRegistry::init('Log');
                $this->Log->create();
                $this->Log->saveOrFailSilently(array(
                    'org' => $user['Organisation']['name'],
                    'model' => 'Event',
                    'model_id' => $event['Event']['id'],
                    'email' => $user['email'],
                    'action' => 'fetchEvent',
                    'user_id' => $user['id'],
                    'title' => 'User was able to fetch the event but not the sharing_group it belongs to',
                    'change' => ''
                ));
                unset($results[$eventKey]); // Current user cannot access sharing_group associated to this event
                continue;
            }
            */
            if ($options['includeWarninglistHits'] || $options['enforceWarninglist']) {
                $eventWarnings = $this->Warninglist->attachWarninglistToAttributes($event['Attribute']);
                $this->Warninglist->attachWarninglistToAttributes($event['ShadowAttribute']);
                $event['warnings'] = $eventWarnings;
            }
            $this->__attachTags($event, $justExportableTags);
            $this->__attachGalaxies($event, $user, $options['excludeGalaxy'], $options['fetchFullClusters'], $options['fetchFullClusterRelationship']);
            $event = $this->Orgc->attachOrgs($event, $fieldsOrg);
            if (!$sharingGroupReferenceOnly && $event['Event']['sharing_group_id']) {
                if (isset($sharingGroupData[$event['Event']['sharing_group_id']])) {
                    $event['SharingGroup'] = $sharingGroupData[$event['Event']['sharing_group_id']];
                }
            }

            // Include information about event creator user email. This information is included for:
            // - users from event creator org
            // - site admins
            // In export, this information will be included in `event_creator_email` field for auditors of event creator org and site admins.
            $sameOrg = $event['Event']['orgc_id'] === $user['org_id'];
            if ($sameOrg || $user['Role']['perm_site_admin']) {
                if (!isset($userEmails[$event['Event']['user_id']])) {
                    $userEmails[$event['Event']['user_id']] = $this->User->field('email', ['id' => $event['Event']['user_id']]);
                }

                $userEmail = $userEmails[$event['Event']['user_id']];
                if ($sameOrg && $user['Role']['perm_audit'] || $user['Role']['perm_site_admin']) {
                    $event['Event']['event_creator_email'] = $userEmail;
                }
                $event['User']['email'] = $userEmail;
            }
            // Let's find all the related events and attach it to the event itself
            if ($options['includeEventCorrelations']) {
                $event['RelatedEvent'] = $this->getRelatedEvents($user, $event['Event']['id'], $sgids);
            }
            // Let's also find all the relations for the attributes - this won't be in the xml export though
            if (!empty($options['includeGranularCorrelations'])) {
                $event['RelatedAttribute'] = $this->getRelatedAttributes($user, $event['Event']['id']);
                if (!empty($options['includeRelatedTags'])) {
                    $event = $this->includeRelatedTags($event, $options);
                }
                //$event['RelatedShadowAttribute'] = $this->getRelatedAttributes($user, $event['Event']['id'], true);
            }
            if (!empty($options['includeScoresOnEvent'])) {
                // $event = $this->DecayingModel->attachBaseScoresToEvent($user, $event);
                $event = $this->DecayingModel->attachScoresToEvent($user, $event);
            }
            $shadowAttributeByOldId = [];
            if (!empty($event['ShadowAttribute'])) {
                if ($isSiteAdmin && $options['includeFeedCorrelations']) {
                    $event['ShadowAttribute'] = $this->Feed->attachFeedCorrelations($event['ShadowAttribute'], $user, $event['Event'], $overrideLimit);
                }
                if ($options['includeServerCorrelations']) {
                    $event['ShadowAttribute'] = $this->Feed->attachFeedCorrelations($event['ShadowAttribute'], $user, $event['Event'], $overrideLimit, 'Server');
                }

                if ($options['includeAttachments']) {
                    foreach ($event['ShadowAttribute'] as &$sa) {
                        if ($this->ShadowAttribute->typeIsAttachment($sa['type'])) {
                            $encodedFile = $this->ShadowAttribute->base64EncodeAttachment($sa);
                            $sa['data'] = $encodedFile;
                        }
                    }
                    unset($sa);
                }

                foreach ($event['ShadowAttribute'] as $sa) {
                    $shadowAttributeByOldId[$sa['old_id']][] = $sa;
                }
                // Assign just shadow attributes that are linked to event (that means they have old_id set to `0`)
                $event['ShadowAttribute'] = $shadowAttributeByOldId[0] ?? [];
            }
            if (!empty($event['Attribute'])) {
                if ($options['includeFeedCorrelations']) {
                    $event['Attribute'] = $this->Feed->attachFeedCorrelations($event['Attribute'], $user, $event['Event'], $overrideLimit);
                }
                if ($options['includeServerCorrelations']) {
                    $event['Attribute'] = $this->Feed->attachFeedCorrelations($event['Attribute'], $user, $event['Event'], $overrideLimit, 'Server');
                }
                $event = $this->__filterBlockedAttributesByTags($event, $options, $user);
                if (!$sharingGroupReferenceOnly) {
                    $event['Attribute'] = $this->__attachSharingGroups($event['Attribute'], $sharingGroupData);
                }

                if (!empty($options['includeGranularCorrelations'])) {
                    $event['Attribute'] = $this->Attribute->Correlation->attachCorrelationExclusion($event['Attribute']);
                }
                if (!empty($options['includeAnalystData'])) {
                    $event['Attribute'] = $this->Attribute->attachAnalystDataBulk($event['Attribute']);
                }

                // move all object attributes to a temporary container
                $tempObjectAttributeContainer = array();
                foreach ($event['Attribute'] as $key => &$attribute) {
                    if ($options['enforceWarninglist'] && !empty($attribute['warnings'])) {
                        unset($event['Attribute'][$key]);
                        continue;
                    }
                    if ($attribute['category'] === 'Financial fraud') {
                        $attribute = $this->Attribute->attachValidationWarnings($attribute);
                    }
                    if ($options['includeAttachments'] && $this->Attribute->typeIsAttachment($attribute['type'])) {
                        $encodedFile = $this->Attribute->base64EncodeAttachment($attribute);
                        $attribute['data'] = $encodedFile;
                    }
                    if (!empty($options['includeDecayScore'])) {
                        if (isset($event['EventTag'])) { // include EventTags for score computation
                            $attribute['EventTag'] = $event['EventTag'];
                        }
                        $attribute = $this->DecayingModel->attachScoresToAttribute($user, $attribute);
                        if (isset($event['EventTag'])) { // remove included EventTags
                            unset($attribute['EventTag']);
                        }
                    }
                    // If a shadowattribute can be linked to an attribute, link it to it
                    // This is to differentiate between proposals that were made to an attribute for modification and between proposals for new attributes
                    $attribute['ShadowAttribute'] = $shadowAttributeByOldId[$attribute['id']] ?? [];
                    if (!empty($options['allow_proposal_blocking'])) {
                        foreach ($attribute['ShadowAttribute'] as $sa) {
                            if ($sa['proposal_to_delete'] || $sa['to_ids'] == 0) {
                                unset($event['Attribute'][$key]);
                                continue 2;
                            }
                        }
                    }
                    if (!$flatten && $attribute['object_id'] != 0) {
                        $tempObjectAttributeContainer[$attribute['object_id']][] = $attribute;
                        unset($event['Attribute'][$key]);
                    }
                }
                $event['Attribute'] = array_values($event['Attribute']);
                unset($attribute);
            }
            if (!empty($event['Object'])) {
                if (!$sharingGroupReferenceOnly) {
                    $event['Object'] = $this->__attachSharingGroups($event['Object'], $sharingGroupData);
                }
                foreach ($event['Object'] as &$objectValue) {
                    if (isset($tempObjectAttributeContainer[$objectValue['id']])) {
                        $objectValue['Attribute'] = $tempObjectAttributeContainer[$objectValue['id']];
                    }
                }
                if (!empty($options['includeAnalystData'])) {
                    $event['Object'] = $this->Object->attachAnalystDataBulk($event['Object']);
                }
                unset($tempObjectAttributeContainer);
            }
            if (!empty($event['EventReport'])) {
                if (!$sharingGroupReferenceOnly) {
                    $event['EventReport'] = $this->__attachSharingGroups($event['EventReport'], $sharingGroupData);
                }
                if (!empty($options['includeAnalystData'])) {
                    $event['EventReport'] = $this->EventReport->attachAnalystDataBulk($event['EventReport']);
                }
            }
            if (empty($options['metadata']) && empty($options['noSightings'])) {
                if (empty(Configure::read('MISP.disable_sighting_loading'))) {
                    $event['Sighting'] = $this->Sighting->attachToEvent($event, $user);
                }
            }
            if ($options['includeSightingdb']) {
                $this->Sightingdb = ClassRegistry::init('Sightingdb');
                $event = $this->Sightingdb->attachToEvent($event, $user);
            }
        }
        if ($options['extended']) {
            foreach ($results as $k => $result) {
                $results[$k] = $this->__mergeExtensions($user, $result, $options);
            }
        }
        if ($options['extensionList']) {
            foreach ($results as $k => $result) {
                $results[$k] = $this->__fetchEventsExtendingEvent($user, $result, $options);
            }
        }
        return $results;
    }

    /**
     * Attach galaxy clusters to event and attributes.
     * @param array $event
     * @param array $user
     * @param bool $excludeGalaxy
     * @param bool $fetchFullCluster
     */
    private function __attachGalaxies(array &$event, array $user, $excludeGalaxy, $fetchFullCluster, $fetchFullRelationship=false)
    {
        $galaxyTags = [];
        $event['Galaxy'] = [];
        if (!$excludeGalaxy && isset($event['EventTag'])) {
            foreach ($event['EventTag'] as $eventTag) {
                if ($eventTag['Tag']['is_galaxy']) {
                    $galaxyTags[$eventTag['Tag']['id']] = $eventTag['Tag']['name'];
                }
            }
        }
        if (isset($event['Attribute'])) {
            foreach ($event['Attribute'] as &$attribute) {
                $attribute['Galaxy'] = [];
                if (!$excludeGalaxy && isset($attribute['AttributeTag'])) {
                    foreach ($attribute['AttributeTag'] as $attributeTag) {
                        if ($attributeTag['Tag']['is_galaxy']) {
                            $galaxyTags[$attributeTag['Tag']['id']] = $attributeTag['Tag']['name'];
                        }
                    }
                }
            }
        }

        if ($excludeGalaxy || empty($galaxyTags)) {
            return;
        }

        $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
        $clusters = $this->GalaxyCluster->getClustersByTags($galaxyTags, $user, true, $fetchFullCluster, $fetchFullRelationship);

        if (empty($clusters)) {
            return;
        }

        $clustersByTagIds = array_column(array_column($clusters, 'GalaxyCluster'), null, 'tag_id');
        unset($clusters);
        if (isset($event['EventTag'])) {
            foreach ($event['EventTag'] as $eventTag) {
                if (!$eventTag['Tag']['is_galaxy']) {
                    continue;
                }
                $tagId = $eventTag['Tag']['id'];
                if (isset($clustersByTagIds[$tagId])) {
                    $cluster = $clustersByTagIds[$tagId];
                    $galaxyId = $cluster['Galaxy']['id'];
                    $cluster['event_tag_id'] = $eventTag['id'];
                    $cluster['local'] = $eventTag['local'] ?? false;
                    $cluster['relationship_type'] = !empty($eventTag['relationship_type']) ? $eventTag['relationship_type'] : false;
                    if (isset($event['Galaxy'][$galaxyId])) {
                        unset($cluster['Galaxy']);
                        $event['Galaxy'][$galaxyId]['GalaxyCluster'][] = $cluster;
                    } else {
                        $event['Galaxy'][$galaxyId] = $cluster['Galaxy'];
                        unset($cluster['Galaxy']);
                        $event['Galaxy'][$galaxyId]['GalaxyCluster'] = [$cluster];
                    }
                }
            }
            $event['Galaxy'] = array_values($event['Galaxy']);
        }
        if (isset($event['Attribute'])) {
            foreach ($event['Attribute'] as &$attribute) {
                if (isset($attribute['AttributeTag'])) {
                    foreach ($attribute['AttributeTag'] as $attributeTag) {
                        if (isset($attributeTag['Tag']['is_galaxy']) && !$attributeTag['Tag']['is_galaxy']) {
                            continue;
                        }
                        $tagId = $attributeTag['Tag']['id'];
                        if (isset($clustersByTagIds[$tagId])) {
                            $cluster = $clustersByTagIds[$tagId];
                            $galaxyId = $cluster['Galaxy']['id'];
                            $cluster['attribute_tag_id'] = $attributeTag['id'];
                            $cluster['local'] = $attributeTag['local'] ?? false;
                            $cluster['relationship_type'] = !empty($attributeTag['relationship_type']) ? $attributeTag['relationship_type'] : false;
                            if (isset($attribute['Galaxy'][$galaxyId])) {
                                unset($cluster['Galaxy']);
                                $attribute['Galaxy'][$galaxyId]['GalaxyCluster'][] = $cluster;
                            } else {
                                $attribute['Galaxy'][$galaxyId] = $cluster['Galaxy'];
                                unset($cluster['Galaxy']);
                                $attribute['Galaxy'][$galaxyId]['GalaxyCluster'] = [$cluster];
                            }
                        }
                    }
                    $attribute['Galaxy'] = array_values($attribute['Galaxy']);
                }
            }
        }
    }

    private function __cacheRelatedEventTags($eventTagCache, array $relatedAttribute, $excludeLocalTags)
    {
        if (!isset($eventTagCache[$relatedAttribute['id']])) {
            $params = array(
                'contain' => array(
                    'Tag' => array(
                        'fields' => array(
                            'Tag.id', 'Tag.name', 'Tag.colour', 'Tag.numerical_value'
                        )
                    )
                ),
                'recursive' => -1,
                'conditions' => array(
                    'EventTag.event_id' => $relatedAttribute['id']
                )
            );
            if ($excludeLocalTags) {
                $params['conditions']['EventTag.local'] = 0;
            }
            $eventTags = $this->EventTag->find('all', $params);
            $eventTagCache[$relatedAttribute['id']] = [];
            foreach ($eventTags as $et) {
                if (!isset($eventTagCache[$relatedAttribute['id']][$et['Tag']['id']])) {
                    $eventTagCache[$relatedAttribute['id']][$et['Tag']['id']] = $et['Tag'];
                }
            }
        }
        return $eventTagCache;
    }

    private function includeRelatedTags(array $event, array $options)
    {
        $eventTagCache = array();
        $excludeLocalTags = !empty($options['excludeLocalTags']);
        foreach ($event['RelatedAttribute'] as $attributeId => $relatedAttributes) {
            $tags = [];
            foreach ($relatedAttributes as $relatedAttribute) {
                $eventTagCache = $this->__cacheRelatedEventTags($eventTagCache, $relatedAttribute, $excludeLocalTags);
                foreach ($eventTagCache[$relatedAttribute['id']] as $tagId => $tag) {
                    $tags[$tagId]= $tag;
                }
                $params = array(
                    'contain' => array(
                        'Tag' => array(
                            'fields' => array(
                                'Tag.id', 'Tag.name', 'Tag.colour', 'Tag.numerical_value'
                            )
                        )
                    ),
                    'recursive' => -1,
                    'conditions' => array(
                        'AttributeTag.attribute_id' => $relatedAttribute['attribute_id']
                    )
                );
                if ($excludeLocalTags) {
                    $params['conditions']['AttributeTag.local'] = 0;
                }
                $attributeTags = $this->Attribute->AttributeTag->find('all', $params);
                foreach ($attributeTags as $at) {
                    $tags[$at['Tag']['id']] = $at['Tag'];
                }
            }
            if (!empty($tags)) {
                $attributePos = false;
                foreach ($event['Attribute'] as $k => $attribute) {
                    if ($attribute['id'] == $attributeId) {
                        $attributePos = $k;
                        break;
                    }
                }
                $event['Attribute'][$attributePos]['RelatedTags'] = array_values($tags);
            }
        }
        return $event;
    }

    /**
     * @param array $user
     * @param array $event
     * @param array $options
     * @return array
     * @throws Exception
     */
    private function __fetchEventsExtendingEvent(array $user, array $event, array $options)
    {
        $extensions = $this->fetchEvent($user, [
            'eventsExtendingUuid' => $event['Event']['uuid'],
            'sgReferenceOnly' => $options['sgReferenceOnly'],
            'metadata' => 1
        ]);
        $extensionList = [];
        foreach ($extensions as $extension) {
            $extensionList[] = [
                'id' => $extension['Event']['id'],
                'uuid' => $extension['Event']['uuid'],
                'info' => $extension['Event']['info'],
                'Orgc' => [
                    'id' => $extension['Orgc']['id'],
                    'uuid' => $extension['Orgc']['uuid'],
                    'name' => $extension['Orgc']['name']
                ]
            ];
        }
        $event['Event']['ExtendedBy'] = $extensionList;
        return $event;
    }

    /**
     * @param array $user
     * @param array $event
     * @param array $options
     * @return array
     * @throws Exception
     */
    private function __mergeExtensions(array $user, array $event, array $options)
    {
        $extensions = $this->fetchEvent($user, [
            'eventsExtendingUuid' => $event['Event']['uuid'],
            'includeEventCorrelations' => $options['includeEventCorrelations'],
            'includeWarninglistHits' => $options['includeWarninglistHits'],
            'noShadowAttributes' => $options['noShadowAttributes'],
            'noEventReports' => $options['noEventReports'],
            'noSightings' => isset($options['noSightings']) ? $options['noSightings'] : null,
            'sgReferenceOnly' => $options['sgReferenceOnly'],
            'includeAnalystData' => $options['includeAnalystData'],
        ]);
        foreach ($extensions as $extensionEvent) {
            $eventMeta = array(
                'id' => $extensionEvent['Event']['id'],
                'info' => $extensionEvent['Event']['info'],
                'orgc_id' => $extensionEvent['Event']['orgc_id'],
                'user_id' => $extensionEvent['Event']['user_id'],
                'Orgc' => array(
                    'id' => $extensionEvent['Orgc']['id'],
                    'name' => $extensionEvent['Orgc']['name'],
                    'uuid' => $extensionEvent['Orgc']['uuid'],
                ),
            );
            $event['Event']['extensionEvents'][$eventMeta['id']] = $eventMeta;
            $thingsToMerge = array('Attribute', 'Object', 'ShadowAttribute', 'Galaxy');
            foreach ($thingsToMerge as $thingToMerge) {
                if (!isset($event[$thingToMerge])) {
                    $event[$thingToMerge] = [];
                }
                if (!isset($extensionEvent[$thingToMerge])) {
                    $extensionEvent[$thingToMerge] = [];
                }
                $event[$thingToMerge] = array_merge($event[$thingToMerge], $extensionEvent[$thingToMerge]);
            }
            // Merge event reports if requested
            if (!$options['noEventReports'] && isset($event['EventReport'])) {
                $event['EventReport'] = array_merge($event['EventReport'], $extensionEvent['EventReport']);
            }
            // Merge just tags that are not already in main event
            foreach ($extensionEvent['EventTag'] as $eventTag) {
                foreach ($event['EventTag'] as $eT) {
                    if ($eT['Tag']['id'] == $eventTag['Tag']['id']) {
                        continue 2; // tag already exists, skip
                    }
                }
                $event['EventTag'][] = $eventTag;
            }
            if ($options['includeEventCorrelations']) {
                // Merge just related events that are not already in main event
                foreach ($extensionEvent['RelatedEvent'] as $relatedEvent) {
                    foreach ($event['RelatedEvent'] as $rE) {
                        if ($rE['Event']['id'] == $relatedEvent['Event']['id']) {
                            continue 2; // event already exists, skip
                        }
                    }
                    $event['RelatedEvent'][] = $relatedEvent;
                }
            }
            if ($options['includeWarninglistHits']) {
                // Merge just event warninglist that are not already in main event
                foreach ($extensionEvent['warnings'] as $warninglistId => $warning) {
                    if (!isset($event['warnings'][$warninglistId])) {
                        $event['warnings'][$warninglistId] = $warning;
                    }
                }
            }
        }
        return $event;
    }

    private function __attachSharingGroups($data, $sharingGroupData)
    {
        foreach ($data as $k => $v) {
            if ($v['distribution'] == 4) {
                if (isset($sharingGroupData[$v['sharing_group_id']])) {
                    $data[$k]['SharingGroup'] = $sharingGroupData[$v['sharing_group_id']];
                } else {
                    unset($data[$k]); // current user could not fetch the sharing_group
                }
            }
        }
        return $data;
    }

    // Filter the attributes within an event based on the tag filter block rules
    private function __filterBlockedAttributesByTags($event, $options, $user)
    {
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
    private function __filterBlockedAttributesFromContainer($container, $blockedTags)
    {
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

    public function set_filter_sharing_group(&$params, $conditions, $options)
    {
        if (!empty($params['sharinggroup'])) {
            $params['sharinggroup'] = $this->convert_filters($params['sharinggroup']);
            if ($options['scope'] === 'Attribute') {
                $conditions = $this->generic_add_filter($conditions, $params['sharinggroup'], ['Event.sharing_group_id', 'Attribute.sharing_group_id']);
            } else {
                $conditions = $this->generic_add_filter($conditions, $params['sharinggroup'], 'Event.sharing_group_id');
            }
        }
        return $conditions;
    }

    public function set_filter_orgc_id(&$params, $conditions, $options)
    {
        if (!empty($params['orgc_id'])) {
            $orgFilter = ['OR' => $params['orgc_id']];
            $conditions = $this->generic_add_filter($conditions, $orgFilter, 'Event.orgc_id');
        }
        return $conditions;
    }

    public function set_filter_org(&$params, $conditions, $options)
    {
        if (!empty($params['org'])) {
            $params['org'] = $this->convert_filters($params['org']);
            if (!empty($params['org']['OR'])) {
                foreach ($params['org']['OR'] as $k => $org) {
                    if (!is_numeric($org)) {
                        $existingOrg = $this->Orgc->find('first', array(
                            'recursive' => -1,
                            'conditions' => array(
                                'OR' => array(
                                    'Orgc.name' => $org,
                                    'Orgc.uuid' => $org
                                )
                            ),
                            'fields' => array('Orgc.id')
                        ));
                        if (empty($existingOrg)) {
                            $params['org']['OR'][$k] = -1;
                        } else {
                            $params['org']['OR'][$k] = $existingOrg['Orgc']['id'];
                        }
                    }
                }
            }
            if (!empty($params['org']['NOT'])) {
                $temp = array();
                foreach ($params['org']['NOT'] as $org) {
                    if (!is_numeric($org)) {
                        $existingOrg = $this->Orgc->find('first', array(
                            'recursive' => -1,
                            'conditions' => array(
                                'OR' => array(
                                    'Orgc.name' => $org,
                                    'Orgc.uuid' => $org
                                )
                            ),
                            'fields' => array('Orgc.id')
                        ));
                        if (!empty($existingOrg)) {
                            $temp[] = $existingOrg['Orgc']['id'];
                        }
                    } else {
                        $temp[] = $org;
                    }
                }
                if (!empty($temp)) {
                    $params['org']['NOT'] = $temp;
                } else {
                    unset($params['org']['NOT']);
                }
            }
            $conditions = $this->generic_add_filter($conditions, $params['org'], 'Event.orgc_id');
        }
        return $conditions;
    }

    public function set_filter_eventid(&$params, $conditions, $options)
    {
        if (!empty($params['eventid']) && $params['eventid'] !== 'all') {
            $params['eventid'] = $this->convert_filters($params['eventid']);
            $keys = array(
                'uuid' => 'Event.uuid',
                'id' => 'Event.id'
            );
            $id_params = array();
            foreach ($params['eventid'] as $operand => $list) {
                foreach ($list as $id) {
                    if ($operand === 'OR') {
                        $id_params['AND']['OR'][$keys[Validation::uuid($id) ? 'uuid' : 'id']][] = $id;
                    } else if ($operand === 'AND') {
                        $id_params['AND']['AND'][$keys[Validation::uuid($id) ? 'uuid' : 'id']][] = $id;
                    } else {
                        $id_params['AND']['NOT'][$keys[Validation::uuid($id) ? 'uuid' : 'id']][] = $id;
                    }
                }
            }
            $conditions['AND'][] = $id_params;
        }
        return $conditions;
    }

    public function set_filter_eventinfo(&$params, $conditions, $options)
    {
        if (!empty($params['eventinfo'])) {
            $params['eventinfo'] = $this->convert_filters($params['eventinfo']);
            $conditions = $this->generic_add_filter($conditions, $params['eventinfo'], 'Event.info');
        }
        return $conditions;
    }

    public function set_filter_uuid(&$params, $conditions, $options)
    {
        if ($options['scope'] === 'Event') {
            if (!empty($params['uuid'])) {
                $params['uuid'] = $this->convert_filters($params['uuid']);
                if (!empty($params['uuid']['OR'])) {
                    $subQueryOptions = array(
                        'conditions' => array('Attribute.uuid' => $params['uuid']['OR']),
                        'fields' => array('event_id')
                    );
                    $attributeSubquery = $this->subQueryGenerator($this->Attribute, $subQueryOptions, 'Event.id');
                    $conditions['AND'][] = array(
                        'OR' => array(
                            'Event.uuid' => $params['uuid']['OR'],
                            $attributeSubquery
                        )
                    );
                }
                if (!empty($params['uuid']['NOT'])) {
                    $subQueryOptions = array(
                        'conditions' => array('Attribute.uuid' => $params['uuid']['NOT']),
                        'fields' => array('event_id')
                    );
                    $attributeSubquery = $this->subQueryGenerator($this->Attribute, $subQueryOptions, 'Event.id');
                    $conditions['AND'][] = array(
                        'NOT' => array(
                            'Event.uuid' => $params['uuid']['NOT'],
                            $attributeSubquery
                        )
                    );
                }
            }
        } else {
            $conditions = $this->{$options['scope']}->set_filter_uuid($params, $conditions, $options);
        }
        return $conditions;
    }

    public function set_filter_mixed_id(&$params, $conditions, $options)
    {
        if (!empty($params['mixed_id'])) {
            $params['mixed_id'] = $this->convert_filters($params['mixed_id']);
            if (!empty($options['scope']) && $options['scope'] === 'Event') {
                $conditions = $this->generic_add_filter($conditions, $params['uuid'], 'Event.uuid');
            }
            if (!empty($options['scope']) && $options['scope'] === 'Attribute') {
                $conditions = $this->generic_add_filter($conditions, $params['uuid'], 'Attribute.uuid');
            }
        }
        return $conditions;
    }

    public function set_filter_deleted(&$params, $conditions, $options)
    {
        $conditional_for_filter = null;
        if (isset($params['deleted'])) {
            if (empty($options['scope'])) {
                $scope = 'Attribute';
            } else {
                if ($options['scope'] === 'Object') {
                    $conditional_for_filter = [
                        'Attribute.object_id' => 0
                    ];
                }
                $scope = $options['scope'];
            }
            $deleted = $this->convert_filters($params['deleted']);
            $conditions = $this->generic_add_filter($conditions, $deleted, $scope . '.deleted', $conditional_for_filter);
        }
        return $conditions;
    }

    public function set_filter_to_ids(&$params, $conditions, $options)
    {
        if (isset($params['to_ids'])) {
            if ($params['to_ids'] === 'exclude') {
                $params['to_ids'] = 0;
            }
            $conditions['AND']['Attribute.to_ids'] = $params['to_ids'];
        }
        return $conditions;
    }

    public function set_filter_ignore(&$params, $conditions, $options)
    {
        if (empty($params['ignore'])) {
            if (empty($options['scope'])) {
                $scope = 'Attribute';
            } else {
                $scope = $options['scope'];
            }
            if ($scope === 'Attribute') {
                $conditions['AND']['Attribute.to_ids'] = 1;
            } else {
                $conditions['AND']['Event.published'] = 1;
            }
        }
        return $conditions;
    }

    public function set_filter_published(&$params, $conditions, $options)
    {
        if (isset($params['published']) && $params['published'] !== [true, false]) {
            $conditions['AND']['Event.published'] = $params['published'];
        }
        return $conditions;
    }

    public function set_filter_threat_level_id(&$params, $conditions, $options)
    {
        if (isset($params['threat_level_id'])) {
            $conditions['AND']['Event.threat_level_id'] = $params['threat_level_id'];
        }
        return $conditions;
    }

    public function set_filter_tags(&$params, $conditions, $options)
    {
        if (!empty($params['tags']) || !empty($params['event_tags'])) {
            $conditions = $this->Attribute->set_filter_tags($params, $conditions, $options);
        }
        return $conditions;
    }

    public function set_filter_type(&$params, $conditions, $options)
    {
        if (!empty($params[$options['filter']])) {
            $params[$options['filter']] = $this->convert_filters($params[$options['filter']]);
            if (!empty(Configure::read('MISP.attribute_filters_block_only'))) {
                if ($options['context'] === 'Event' && !empty($params[$options['filter']]['OR'])) {
                    unset($params[$options['filter']]['OR']);
                }
            }
            if (!empty($params[$options['filter']])) {
                foreach (['OR', 'NOT'] as $operator) {
                    if (
                        !empty($params[$options['filter']][$operator]) &&
                        (
                            in_array('email-src', $params[$options['filter']][$operator]) ||
                            in_array('email-dst', $params[$options['filter']][$operator])
                        ) && (
                            !in_array('email', $params[$options['filter']][$operator])
                        )
                    ) {
                        $params[$options['filter']][$operator][] = 'email';
                    }
                }
            }
            $conditions = $this->generic_add_filter($conditions, $params[$options['filter']], 'Attribute.' . $options['filter']);
        }
        return $conditions;
    }


    public function set_filter_simple_attribute(&$params, $conditions, $options)
    {
        if (!empty($params[$options['filter']])) {
            $params[$options['filter']] = $this->convert_filters($params[$options['filter']]);
            if (!empty(Configure::read('MISP.attribute_filters_block_only'))) {
                if ($options['context'] === 'Event' && !empty($params[$options['filter']]['OR'])) {
                    unset($params[$options['filter']]['OR']);
                }
            }
            $conditions = $this->generic_add_filter($conditions, $params[$options['filter']], 'Attribute.' . $options['filter']);
        }
        return $conditions;
    }

    public function set_filter_attribute_id(&$params, $conditions, $options)
    {
        if (!empty($params[$options['filter']])) {
            $params[$options['filter']] = $this->convert_filters($params[$options['filter']]);
            $conditions = $this->generic_add_filter($conditions, $params[$options['filter']], 'Attribute.' . $options['filter']);
        }
        return $conditions;
    }

    /**
     * @param string $value
     * @return string
     */
    private static function compressIpv6($value)
    {
        if (strpos($value, ':') && $converted = inet_pton($value)) {
            return inet_ntop($converted);
        }
        return $value;
    }

    public function set_filter_value(&$params, $conditions, $options)
    {
        if (!empty($params['value'])) {
            $params[$options['filter']] = $this->convert_filters($params['value']);
            foreach (['OR', 'AND', 'NOT'] as $operand) {
                if (!empty($params[$options['filter']][$operand])) {
                    foreach ($params[$options['filter']][$operand] as $k => $v) {
                        if ($operand === 'NOT') {
                            $v = mb_substr($v, 1);
                        }
                        if (filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                            $v = $this->compressIpv6($v);
                        }
                        $params[$options['filter']][$operand][$k] = $operand === 'NOT' ? '!' . $v : $v;
                    }
                }
            }
            $conditions = $this->generic_add_filter($conditions, $params['value'], ['Attribute.value1', 'Attribute.value2']);
        }

        return $conditions;
    }

    public function set_filter_object_name(&$params, $conditions, $options)
    {
        if (!empty($params['object_name'])) {
            $params['object_name'] = $this->convert_filters($params['object_name']);
            $conditions = $this->generic_add_filter($conditions, $params['object_name'], 'Object.name');

        }
        return $conditions;
    }

    public function set_filter_object_template_uuid(&$params, $conditions, $options)
    {
        if (!empty($params['object_template_uuid'])) {
            $params['object_template_uuid'] = $this->convert_filters($params['object_template_uuid']);
            $conditions = $this->generic_add_filter($conditions, $params['object_template_uuid'], 'Object.template_uuid');

        }
        return $conditions;
    }

    public function set_filter_object_template_version(&$params, $conditions, $options)
    {
        if (!empty($params['object_template_version'])) {
            $params['object_template_version'] = $this->convert_filters($params['object_template_version']);
            $conditions = $this->generic_add_filter($conditions, $params['object_template_version'], 'Object.template_version');

        }
        return $conditions;
    }

    public function set_filter_comment(&$params, $conditions, $options)
    {
        if (!empty($params['comment'])) {
            $params['comment'] = $this->convert_filters($params['comment']);
            $conditions = $this->generic_add_filter($conditions, $params['comment'], 'Attribute.comment');
        }
        return $conditions;
    }

    public function set_filter_seen(&$params, $conditions, $options)
    {
        $f = $options['scope'] . '.' . $options['filter'];
        $conditions = $this->Attribute->setTimestampSeenConditions($params[$options['filter']], $conditions, $f);
        return $conditions;
    }

    /**
     * @param array $params
     * @param array $conditions
     * @param array $options
     * @return array
     */
    public function set_filter_timestamp(&$params, $conditions, $options)
    {
        if ($options['filter'] === 'from') {
            if (is_numeric($params['from'])) {
                $conditions['AND']['Event.date >='] = date('Y-m-d', $params['from']);
            } else {
                $conditions['AND']['Event.date >='] = $params['from'];
            }
        } elseif ($options['filter'] === 'to') {
            if (is_numeric($params['to'])) {
                $conditions['AND']['Event.date <='] = date('Y-m-d', $params['to']);
            } else {
                $conditions['AND']['Event.date <='] = $params['to'];
            }
        } else {
            if (empty($options['scope'])) {
                $scope = 'Attribute';
            } else {
                $scope = $options['scope'];
            }
            $filters = array(
                'timestamp' => array(
                    $scope . '.timestamp'
                ),
                'publish_timestamp' => array(
                    'Event.publish_timestamp'
                ),
                'last' => array(
                    'Event.publish_timestamp'
                ),
                'event_timestamp' => array(
                    'Event.timestamp'
                ),
                'attribute_timestamp' => array(
                    'Attribute.timestamp'
                ),
            );
            foreach ($filters[$options['filter']] as $f) {
                $conditions = $this->Attribute->setTimestampConditions($params[$options['filter']], $conditions, $f);
                if (!empty($options['pop'])) {
                    unset($params[$options['filter']]);
                }
            }
        }
        return $conditions;
    }

    public function set_filter_date(&$params, $conditions, $options)
    {
        $timestamp = $this->Attribute->setTimestampConditions($params[$options['filter']], $conditions, 'Event.date', true);
        if (!is_array($timestamp)) {
            $conditions['AND']['Event.date >='] = date('Y-m-d', $timestamp);
        } else {
            $conditions['AND']['Event.date >='] = date('Y-m-d', $timestamp[0]);
            $conditions['AND']['Event.date <='] = date('Y-m-d', $timestamp[1]);
        }
        return $conditions;
    }

    public function sendAlertEmailRouter($id, $user, $oldpublish = null)
    {
        if (Configure::read('MISP.block_old_event_alert')) {
            $oldest = time() - (Configure::read('MISP.block_old_event_alert_age') * 86400);
            $oldest_date = time() - (Configure::read('MISP.block_old_event_alert_by_date') * 86400);
            $event = $this->find('first', array(
                    'conditions' => array('Event.id' => $id),
                    'recursive' => -1,
                    'fields' => array('Event.timestamp', 'Event.date')
            ));
            if (empty($event)) {
                return false;
            }
            if (!empty(Configure::read('MISP.block_old_event_alert_age')) && is_numeric(Configure::read('MISP.block_old_event_alert_age'))) {
                if (intval($event['Event']['timestamp']) < $oldest) {
                    return true;
                }
            }
            if (!empty(Configure::read('MISP.block_old_event_alert_by_date')) && is_numeric(Configure::read('MISP.block_old_event_alert_by_date'))) {
                if (strtotime($event['Event']['date']) < $oldest_date) {
                    return true;
                }
            }
        }
        if (Configure::read('MISP.block_event_alert') && Configure::read('MISP.block_event_alert_tag') && !empty(Configure::read('MISP.block_event_alert_tag'))) {
            $noAlertTag = Configure::read('MISP.block_event_alert_tag');
            $tagLen = strlen($noAlertTag);
            $event = $this->fetchEvent($user, array('eventid' => $id, 'includeAllTags' => true));
            if (empty($event)) {
                return false;
            }
            foreach ($event[0]['EventTag'] as $k => $tag) {
                if (strcasecmp($noAlertTag, $tag['Tag']['name']) == 0) {
                    return true;
                }
            }
        }
        if (Configure::read('MISP.disable_emailing')) {
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
            $this->Log->saveOrFailSilently(array(
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
        $banStatus = $this->getEventRepublishBanStatus($id);
        $banStatusUser = $this->User->checkNotificationBanStatus($user);
        if ($banStatus['active'] || $banStatusUser['active']) {
            $logMessage = $banStatus['active'] ? $banStatus['message'] : $banStatusUser['message'];
            $banError = $banStatus['error'] || $banStatusUser['error'];
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
            $this->Log->saveOrFailSilently(array(
                    'org' => 'SYSTEM',
                    'model' => 'Event',
                    'model_id' => $id,
                    'email' => $user['email'],
                    'action' => 'publish',
                    'title' => __('E-mail alerts not sent out during publishing'),
                    'change' => $logMessage,
            ));
            return !$banError;
        }
        if (Configure::read('MISP.background_jobs')) {
            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob($user, Job::WORKER_EMAIL, 'publish_alert_email', "Event: $id", 'Sending...');

            $args = [
                'alertemail',
                $user['id'],
                $jobId,
                $id,
            ];
            if ($oldpublish !== null) {
                $args[] = $oldpublish;
            }

            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::EMAIL_QUEUE,
                BackgroundJobsTool::CMD_EVENT,
                $args,
                true,
                $jobId
            );

            return true;
        } else {
            return $this->sendAlertEmail($id, $user, $oldpublish);
        }
    }

    /**
     * @param int $id
     * @param array $senderUser Not used anymore.
     * @param int|null $oldpublish Timestamp of old publishing.
     * @param int|null $jobId
     * @return bool
     * @throws Exception
     */
    public function sendAlertEmail($id, array $senderUser, $oldpublish = null, $jobId = null)
    {
        $event = $this->find('first', [
           'conditions' => ['Event.id' => $id],
           'recursive' => -1,
        ]);
        if (empty($event)) {
            throw new NotFoundException('Invalid Event.');
        }

        // Initialise the Job class if we have a background process ID
        // This will keep updating the process's progress bar
        if ($jobId) {
            $this->Job = ClassRegistry::init('Job');
        }

        $this->NotificationLog = ClassRegistry::init('NotificationLog');
        if (!$this->NotificationLog->check($event['Event']['orgc_id'], 'publish')) {
            if ($jobId) {
                $this->Job->saveStatus($jobId, true, __('Mails blocked by org alert threshold.'));
            }
            return true;
        }
        $userConditions = array('autoalert' => 1);
        $usersWithAccess = $this->User->getUsersWithAccess(
            $owners = array(
                $event['Event']['orgc_id'],
                $event['Event']['org_id']
            ),
            $event['Event']['distribution'],
            $event['Event']['sharing_group_id'],
            $userConditions
        );

        $userCount = count($usersWithAccess);
        $metadataOnly = Configure::read('MISP.event_alert_metadata_only') || Configure::read('MISP.publish_alerts_summary_only');
        foreach ($usersWithAccess as $k => $user) {
            // Fetch event for user that will receive alert e-mail to respect all ACLs
            $eventForUser = $this->fetchEvent($user, [
                'eventid' => $id,
                'includeAllTags' => true,
                'includeEventCorrelations' => true,
                'noEventReports' => true,
                'noSightings' => true,
                'metadata' => $metadataOnly,
            ]);
            if (empty($eventForUser)) {
                $this->Job->saveProgress($jobId, null, $k / $userCount * 100);
                $this->loadLog()->createLogEntry($senderUser, 'alert', 'User', $user['id'], __('Something went wrong with alerting user #%s about event #%s. Sending was blocked due to insufficient access to the given event.'));
                continue;
            }
            $eventForUser = $eventForUser[0];
            if ($this->User->UserSetting->checkPublishFilter($user, $eventForUser)) {
                $body = $this->prepareAlertEmail($eventForUser, $user, $oldpublish);
                $this->User->sendEmail(['User' => $user], $body, false, null);
            }
            if ($jobId) {
                $this->Job->saveProgress($jobId, null, $k / $userCount * 100);
            }
        }

        if ($jobId) {
            $this->Job->saveStatus($jobId, true, __('Mails sent.'));
        }
        return true;
    }

    /**
     * @param array $event
     * @param array $user E-mail receiver
     * @param int|null $oldpublish Timestamp of previous publishing.
     * @return SendEmailTemplate
     * @throws CakeException
     */
    public function prepareAlertEmail(array $event, array $user, $oldpublish = null)
    {
        if (Configure::read('MISP.extended_alert_subject')) {
            $subject = preg_replace("/\r|\n/", "", $event['Event']['info']);
            if (mb_strlen($subject) > 58) {
                $subject = mb_substr($subject, 0, 55) . '... - ';
            } else {
                $subject .= " - ";
            }
        } else {
            $subject = '';
        }

        if (Configure::read('MISP.threatlevel_in_email_subject') === false) {
            $threatLevel = '';
        } else {
            $threatLevel = $event['ThreatLevel']['name'] . " - ";
        }

        $subjMarkingString = $this->getEmailSubjectMarkForEvent($event);
        $subject = "[" . Configure::read('MISP.org') . " MISP] Event {$event['Event']['id']} - $subject$threatLevel" . strtoupper($subjMarkingString);

        $template = new SendEmailTemplate('alert');
        $template->set('event', $event);
        $template->set('user', $user);
        $template->set('oldPublishTimestamp', $oldpublish);
        $template->set('baseurl', $this->__getAnnounceBaseurl());
        $template->set('distributionLevels', $this->distributionLevels);
        $template->set('analysisLevels', $this->analysisLevels);
        $template->set('tlp', $subjMarkingString);
        $template->set('title', Configure::read('MISP.title_text'));
        $template->subject($subject);
        $template->referenceId("event-alert|{$event['Event']['id']}");

        $unsubscribeLink = $this->__getAnnounceBaseurl() . '/users/unsubscribe/' . $this->User->unsubscribeCode($user);
        $template->set('unsubscribe', $unsubscribeLink);
        $template->listUnsubscribe($unsubscribeLink);
        return $template;
    }

    /**
     * @param int $id Event ID
     * @param string $message Message that user want to send to event creator
     * @param bool $creator_only Should be contacted just event creator or all user from org owning given event?
     * @param array $user User that wanna know more
     * @return bool True if all e-mails was send correctly.
     * @throws Exception
     */
    public function sendContactEmail($id, $message, $creator_only, array $user)
    {
        // fetch the event as user that requested more information. So if creators will reply to that email, no data
        // that requestor could not access would be leaked.
        $event = $this->fetchEvent($user, [
            'eventid' => $id,
            'includeAllTags' => true,
            'includeEventCorrelations' => true,
        ]);
        if (empty($event)) {
            throw new NotFoundException('Invalid Event.');
        }
        $event = $event[0];

        if (!$creator_only) {
            // Insert extra field here: alertOrg or something, then foreach all the org members
            // limit this array to users with contactalerts turned on!
            $orgMembers = array();
            $this->User->recursive = 0;
            $temp = $this->User->find('all', array(
                    'fields' => array('email', 'gpgkey', 'certif_public', 'contactalert', 'id', 'org_id', 'disabled'),
                    'conditions' => array('disabled' => 0, 'User.org_id' => $event['Event']['orgc_id']),
                    'recursive' => -1
            ));
            foreach ($temp as $tempElement) {
                if ($tempElement['User']['contactalert'] || $tempElement['User']['id'] == $event['Event']['user_id']) {
                    array_push($orgMembers, $tempElement);
                }
            }
        } else {
            $temp = $this->User->find('first', array(
                    'conditions' => array(
                        'User.id' => $event['Event']['user_id'],
                        'User.disabled' => 0,
                        'User.org_id' => $event['Event']['orgc_id'],
                    ),
                    'fields' => array('User.email', 'User.gpgkey', 'User.certif_public', 'User.id', 'User.disabled'),
                    'recursive' => -1
            ));
            if (!empty($temp)) {
                $orgMembers = array($temp);
            }
        }
        if (empty($orgMembers)) {
            return false;
        }
        $tplColorString = $this->getEmailSubjectMarkForEvent($event);
        $subject = "[" . Configure::read('MISP.org') . " MISP] Need info about event $id - " . strtoupper($tplColorString);
        $result = true;
        foreach ($orgMembers as $eventReporter) {
            $requestor = !empty($user['User']) ? $user : ['User' => $user];
            $reporterForEmailTemplate = !empty($eventReporter['User']) ? $eventReporter['User'] : $eventReporter;
            $body = $this->prepareContactAlertEmail($requestor, $reporterForEmailTemplate, $message, $event);
            $result = $this->User->sendEmail($eventReporter, $body, false, $subject, ['User' => $user]) && $result;
        }
        return $result;
    }

    /**
     * @param array $user
     * @param array $eventReporter
     * @param string $message
     * @param array $event
     * @return SendEmailTemplate
     */
    private function prepareContactAlertEmail(array $user, array $eventReporter, $message, array $event)
    {
        $template = new SendEmailTemplate('alert_contact');
        $template->set('event', $event);
        $template->set('requestor', $user);
        $template->set('message', $message);
        $template->set('user', $eventReporter);
        $template->set('baseurl', $this->__getAnnounceBaseurl());
        $template->set('distributionLevels', $this->distributionLevels);
        $template->set('analysisLevels', $this->analysisLevels);
        $template->set('contactAlert', true);
        $template->set('tlp', $this->getEmailSubjectMarkForEvent($event));
        return $template;
    }

    /**
     * @param array $element
     * @param array $user
     * @param bool|false $server
     * @return array
     */
    public function captureSGForElement($element, $user, $server=false)
    {
        if (isset($element['SharingGroup'])) {
            $sg = $this->SharingGroup->captureSG($element['SharingGroup'], $user, $server);
            unset($element['SharingGroup']);
        } elseif (isset($element['sharing_group_id'])) {
            $sg = $this->SharingGroup->checkIfAuthorised($user, $element['sharing_group_id']) ? $element['sharing_group_id'] : false;
        } else {
            $sg = false;
        }
        if ($sg===false) {
            $sg = 0;
            $element['distribution'] = 0;
        }
        $element['sharing_group_id'] = $sg;
        return $element;
    }

    /**
     * When we receive an event via REST, we might end up with organisations, sharing groups, tags that we do not know
     * or which we need to update. All of that is controlled in this method.
     * @param array $event
     * @param array $user
     * @param array|false $server
     * @return array
     * @throws Exception
     */
    private function __captureObjects(array $event, array $user, $server=false)
    {
        // First we need to check whether the event or any attributes are tied to a sharing group and whether the user is even allowed to create the sharing group / is part of it
        if (isset($event['distribution']) && $event['distribution'] == 4) {
            $event = $this->captureSGForElement($event, $user, $server);
        }

        if (!empty($event['Attribute'])) {
            foreach ($event['Attribute'] as $k => $a) {
                unset($event['Attribute'][$k]['id']);
                if (isset($a['distribution']) && $a['distribution'] == 4) {
                    $event['Attribute'][$k] = $this->captureSGForElement($a, $user, $server);
                }
            }
        }
        if (!empty($event['Object'])) {
            foreach ($event['Object'] as $k => $o) {
                if (isset($o['distribution']) && $o['distribution'] == 4) {
                    $event['Object'][$k] = $this->captureSGForElement($o, $user, $server);
                }
                if (!empty($o['Attribute'])) {
                    foreach ($o['Attribute'] as $k2 => $a) {
                        if (isset($a['distribution']) && $a['distribution'] == 4) {
                            $event['Object'][$k]['Attribute'][$k2] = $this->captureSGForElement($a, $user, $server);
                        }
                    }
                }
            }
        }

        // first we want to see how the creator organisation is encoded
        // The options here are either by passing an organisation object along or simply passing a string along
        if (isset($event['Orgc'])) {
            $event['orgc_id'] = $this->Orgc->captureOrg($event['Orgc'], $user);
            unset($event['Orgc']);
        } elseif (isset($event['orgc'])) {
            $event['orgc_id'] = $this->Orgc->captureOrg($event['orgc'], $user);
            unset($event['orgc']);
        } else {
            $event['orgc_id'] = $user['org_id'];
        }

        $event_tag_ids = array();
        $capturedTags = []; // cache captured tag
        $eventTags = [];
        if (isset($event['EventTag'])) {
            if (isset($event['EventTag']['id'])) {
                $event['EventTag'] = array($event['EventTag']);
            }
            foreach ($event['EventTag'] as $tag) {
                $tagId = $this->captureTagWithCache($tag['Tag'], $user, $capturedTags);
                if ($tagId && !in_array($tagId, $event_tag_ids)) {
                    $eventTags[] = array(
                        'tag_id' => $tagId,
                        'local' => isset($tag['local']) ? $tag['local'] : false,
                        'relationship_type' => isset($tag['relationship_type']) ? $tag['relationship_type'] : '',
                    );
                    $event_tag_ids[] = $tagId;
                }
            }
        }
        if (isset($event['Tag'])) {
            if (isset($event['Tag']['name'])) {
                $event['Tag'] = array($event['Tag']);
            }
            foreach ($event['Tag'] as $tag) {
                $tag_id = $this->captureTagWithCache($tag, $user, $capturedTags);
                if ($tag_id && !in_array($tag_id, $event_tag_ids)) {
                    $eventTags[] = [
                        'tag_id' => $tag_id,
                        'local' => isset($tag['local']) ? $tag['local'] : false,
                        'relationship_type' => isset($tag['relationship_type']) ? $tag['relationship_type'] : '',
                    ];
                    $event_tag_ids[] = $tag_id;
                }
            }
            unset($event['Tag']);
        }
        $event['EventTag'] = $eventTags;

        if (!empty($event['Attribute'])) {
            $event['Attribute'] = $this->__captureAttributeTags($event['Attribute'], $user, $capturedTags);
        }
        if (!empty($event['Object'])) {
            foreach ($event['Object'] as $k => $object) {
                if (!empty($object['Attribute'])) {
                    $event['Object'][$k]['Attribute'] = $this->__captureAttributeTags($object['Attribute'], $user, $capturedTags);
                }
            }
        }
        return $event;
    }

    /**
     * @param array $tag
     * @param array $user
     * @param array $capturedTags
     * @return false|int
     * @throws Exception
     */
    public function captureTagWithCache(array $tag, array $user, array &$capturedTags)
    {
        $tagName = $tag['name'];
        if (isset($capturedTags[$tagName])) {
            $tagId = $capturedTags[$tagName];
        } else {
            $tagId = $this->Attribute->AttributeTag->Tag->captureTag($tag, $user);
            if ($tagId) {
                $tagId = (int)$tagId;
                $capturedTags[$tagName] = $tagId;
            }
        }
        return $tagId;
    }

    /**
     * Capture tags for attributes and replace tags just by IDs
     * @param array $attributes
     * @param array $user
     * @param array $capturedTags
     * @return array
     * @throws Exception
     */
    private function __captureAttributeTags(array $attributes, array $user, array &$capturedTags)
    {
        foreach ($attributes as $k => $a) {
            $attributeTags = [];
            if (isset($a['AttributeTag'])) {
                if (isset($a['AttributeTag']['id'])) {
                    $a['AttributeTag'] = array($a['AttributeTag']);
                }
                foreach ($a['AttributeTag'] as $tag) {
                    $attributeTags[] = array(
                        'tag_id' => $this->captureTagWithCache($tag['Tag'], $user, $capturedTags),
                        'local' => isset($tag['local']) ? $tag['local'] : 0,
                        'relationship_type' => isset($tag['relationship_type']) ? $tag['relationship_type'] : '',
                    );
                }
            }
            if (isset($a['Tag'])) {
                if (isset($a['Tag']['name'])) {
                    $a['Tag'] = array($a['Tag']);
                }
                foreach ($a['Tag'] as $tag) {
                    $tagId = $this->captureTagWithCache($tag, $user, $capturedTags);
                    if ($tagId) {
                        $attributeTags[] = [
                            'tag_id' => $tagId,
                            'local' => isset($tag['local']) ? $tag['local'] : false,
                            'relationship_type' => isset($tag['relationship_type']) ? $tag['relationship_type'] : '',
                        ];
                    }
                }
                unset($attributes[$k]['Tag']);
            }
            $attributes[$k]['AttributeTag'] = $attributeTags;
        }
        return $attributes;
    }

    /**
     * @param array $event
     * @return bool
     */
    private function checkEventBlockRules(array $event)
    {
        if (!isset($this->eventBlockRule)) {
            $this->AdminSetting = ClassRegistry::init('AdminSetting');
            $setting = $this->AdminSetting->getSetting('eventBlockRule');
            $this->eventBlockRule = $setting ? json_decode($setting, true) : false;
        }
        if (empty($this->eventBlockRule)) {
            return true;
        }
        if (!empty($this->eventBlockRule['tags'])) {
            if (!is_array($this->eventBlockRule['tags'])) {
                $this->eventBlockRule['tags'] = [$this->eventBlockRule['tags']];
            }
            $eventTags = Hash::extract($event, 'Event.Tag.{n}.name');
            if (empty($eventTags)) {
                $eventTags = Hash::extract($event, 'Event.EventTag.{n}.Tag.name');
            }
            if (!empty($eventTags)) {
                foreach ($this->eventBlockRule['tags'] as $blockTag) {
                    if (in_array($blockTag, $eventTags)) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    /**
     * @param array $user
     * @param string $data
     * @param bool $isXml
     * @param bool $takeOwnership
     * @param bool $publish
     * @return array[]
     * @throws Exception
     */
    public function addMISPExportFile(array $user, $data, $isXml = false, $takeOwnership = false, $publish = false)
    {
        if (empty($data)) {
            throw new Exception("File is empty");
        }

        if ($isXml) {
            App::uses('Xml', 'Utility');
            $dataArray = Xml::toArray(Xml::build($data));
        } else {
            $dataArray = $this->jsonDecode($data);
            if (isset($dataArray['response'][0])) {
                foreach ($dataArray['response'] as $k => $temp) {
                    $dataArray['Event'][] = $temp['Event'];
                    unset($dataArray['response'][$k]);
                }
            }
        }
        // In case we receive an event that is not encapsulated in a response. This should never happen (unless it's a copy+paste fail),
        // but just in case, let's clean it up anyway.
        if (isset($dataArray['Event'])) {
            $dataArray['response']['Event'] = $dataArray['Event'];
            unset($dataArray['Event']);
        } elseif (!isset($dataArray['response'])){
            // Accept an event not containing the `Event` key
            $dataArray['response']['Event'] = $dataArray;
        }
        if (!isset($dataArray['response']) || !isset($dataArray['response']['Event'])) {
            $exception = $isXml ? __('This is not a valid MISP XML file.') : __('This is not a valid MISP JSON file.');
            throw new Exception($exception);
        }
        $dataArray = $this->updateXMLArray($dataArray);
        $eventsToAdd = isset($dataArray['response']['Event'][0]) ? $dataArray['response']['Event'] : [$dataArray['response']['Event']];
        $results = array();
        $validationIssues = array();
        foreach ($eventsToAdd as $event) {
            if ($takeOwnership) {
                $event['orgc_id'] = $user['org_id'];
                unset($event['Orgc']);
            }
            $event = array('Event' => $event);
            $created_id = 0;
            $event['Event']['locked'] = 1;
            $event['Event']['published'] = $publish;
            $event = $this->updatedLockedFieldForAllAnalystData($event);
            $result = $this->_add($event, true, $user, '', null, false, null, $created_id, $validationIssues);
            $results[] = [
                'info' => $event['Event']['info'],
                'result' => $result,
                'id' => $created_id,
                'validationIssues' => $validationIssues,
            ];
        }
        return $results;
    }

    private function updatedLockedFieldForAllAnalystData(array $event): array
    {
        $event = $this->updatedLockedFieldForAnalystData($event, 'Event');
        if (!empty($event['Event']['Attribute'])) {
            for ($i=0; $i < count($event['Event']['Attribute']); $i++) {
                $event['Event']['Attribute'][$i] = $this->updatedLockedFieldForAnalystData($event['Event']['Attribute'][$i]);
            }
        }
        if (!empty($event['Event']['Object'])) {
            for ($i=0; $i < count($event['Event']['Object']); $i++) {
                 if (isset($event['Event']['Object'][$i])) {
                    $event['Event']['Object'][$i] = $this->updatedLockedFieldForAnalystData($event['Event']['Object'][$i]);
                }
                if (!empty($event['Event']['Object'][$i])) {
                    for ($j=0; $j < count($event['Event']['Object'][$i]['Attribute']); $j++) {
                        $event['Event']['Object'][$i]['Attribute'][$j] = $this->updatedLockedFieldForAnalystData($event['Event']['Object'][$i]['Attribute'][$j]);
                    }
                }
            }
        }
        if (!empty($event['Event']['EventReport'])) {
            for ($i=0; $i < count($event['Event']['EventReport']); $i++) {
                $event['Event']['EventReport'][$i] = $this->updatedLockedFieldForAnalystData($event['Event']['EventReport'][$i]);
            }
        }
        return $event;
    }

    private function updatedLockedFieldForAnalystData(array $data, $model=false): array
    {
        $this->AnalystData = ClassRegistry::init('AnalystData');
        if (!empty($model)) {
            $data = $data[$model];
        }
        foreach ($this->AnalystData::ANALYST_DATA_TYPES as $type) {
            if (!empty($data[$type])) {
                for ($i=0; $i < count($data[$type]); $i++) {
                    $data[$type][$i]['locked'] = true;
                    foreach ($this->AnalystData::ANALYST_DATA_TYPES as $childType) {
                        if (!empty($data[$type][$i][$childType])) {
                            for ($j=0; $j < count($data[$type][$i][$childType]); $j++) {
                                $data[$type][$i][$childType][$j]['locked'] = true;
                                $data[$type][$i][$childType][$j] = $this->updatedLockedFieldForAnalystData($data[$type][$i][$childType][$j]);
                            }
                        }
                    }
                }
            }
        }
        if (!empty($model)) {
            $data = [$model => $data];
        }
        return $data;
    }

    /**
     * Low level function to add an Event based on an Event $data array.
     *
     * @param array $data
     * @param bool $fromXml
     * @param array $user
     * @param int $org_id
     * @param int|null $passAlong Server ID or null
     * @param bool $fromPull
     * @param int|null $jobId
     * @param int $created_id
     * @param array $validationErrors
     * @return bool|int|string True when new event was created, int when event with the same uuid already exists, string when validation errors
     * @throws Exception
     */
    public function _add(array &$data, $fromXml, array $user, $org_id = 0, $passAlong = null, $fromPull = false, $jobId = null, &$created_id = 0, &$validationErrors = array())
    {
        if (Configure::read('MISP.enableEventBlocklisting') !== false && isset($data['Event']['uuid'])) {
            if (!isset($this->EventBlocklist)) {
                $this->EventBlocklist = ClassRegistry::init('EventBlocklist');
            }
            if ($this->EventBlocklist->isBlocked($data['Event']['uuid'])) {
                return 'Blocked by blocklist';
            }
        }
        if (!$this->checkEventBlockRules($data)) {
            return 'Blocked by event block rules';
        }
        $breakOnDuplicate = !empty($data['Event']['breakOnDuplicate']);
        if (empty($data['Event']['Attribute']) && empty($data['Event']['Object']) && !empty($data['Event']['published']) && empty($data['Event']['EventReport'])) {
            $validationErrors['Event'] = 'Received a published event that was empty. Event add process blocked.';
            $this->loadLog()->createLogEntry($user, 'add', 'Event', 0, $validationErrors['Event']);
            return json_encode($validationErrors);
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
            $orgc_id = $data['Event']['orgc_id'] ?? null;
            $orgc_uuid = $data['Event']['Orgc']['uuid'] ?? null;
            if (!$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin']) {
                if ($orgc_uuid != $user['Organisation']['uuid'] && $orgc_id != $user['org_id']) {
                    throw new MethodNotAllowedException('Event cannot be created as you are not a member of the creator organisation.');
                }
            }
        }
        if (!Configure::check('MISP.enableOrgBlocklisting') || Configure::read('MISP.enableOrgBlocklisting') !== false) {
            if (!isset($data['Event']['Orgc']['uuid'])) {
                $orgc = $data['Event']['orgc_id'];
            } else {
                $orgc = $data['Event']['Orgc']['uuid'];
            }
            if (!isset($this->OrgBlocklist)) {
                $this->OrgBlocklist = ClassRegistry::init('OrgBlocklist');
            }
            if ($this->OrgBlocklist->isBlocked($orgc)) {
                $this->OrgBlocklist->saveEventBlocked($orgc);
                return 'blocked';
            }
        }
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
                    'Server.unpublish_event',
                    'Server.publish_without_email',
                    'Server.internal',
                    'Server.url',
                    'Server.remote_org_id',
                )
            ));
        } else {
            $server['Server']['internal'] = false;
        }
        if ($fromXml) {
            // Workaround for different structure in XML/array than what CakePHP expects
            $data = $this->cleanupEventArrayFromXML($data);
            // the event_id field is not set (normal) so make sure no validation errors are thrown
            // LATER do this with   $this->validator()->remove('event_id');
            unset($this->Attribute->validate['event_id']); // otherwise gives bugs because event_id is not set
            unset($this->Attribute->validate['value']['uniqueValue']); // unset this - we are saving a new event, there are no values to compare against and event_id is not set in the attributes
        }
        unset($data['Event']['id']);
        if (
            (Configure::read('MISP.block_publishing_for_same_creator') && !$user['Role']['perm_sync']) ||
            (isset($data['Event']['published']) && $data['Event']['published'] && $user['Role']['perm_publish'] == 0)
        ) {
            if (isset($data['Event']['published']) && $data['Event']['published']) {
                $this->loadLog()->createLogEntry($user, 'add', 'Event', 0, 'Event will not be published');
            }
            $data['Event']['published'] = 0;
        }
        if (isset($data['Event']['uuid'])) {
            // check if the uuid already exists
            $existingEvent = $this->find('first', [
                'conditions' => ['Event.uuid' => $data['Event']['uuid']],
                'fields' => ['Event.id'],
                'recursive' => -1,
            ]);
            if ($existingEvent) {
                // RESTful, set response location header so client can find right URL to edit
                if ($fromPull) {
                    return false;
                }
                if ($fromXml) {
                    $created_id = $existingEvent['Event']['id'];
                }
                return $existingEvent['Event']['id'];
            }
        }
        if ($fromXml) {
            $data['Event'] = $this->__captureObjects($data['Event'], $user, $server);
        }
        $fieldList = array(
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
            'disable_correlation',
            'extends_uuid',
            'protected'
        );
        $saveResult = $this->save(array('Event' => $data['Event']), array('fieldList' => $fieldList));
        if ($saveResult) {
            if ($jobId) {
                /** @var EventLock $eventLock */
                if (!isset($this->EventLock)) {
                    $this->EventLock = ClassRegistry::init('EventLock');
                }
                $this->EventLock->insertLockBackgroundJob($this->id, $jobId);
            }

            if ($passAlong) {
                if ($server['Server']['publish_without_email'] == 0) {
                    $st = "enabled";
                } else {
                    $st = "disabled";
                }
                $logTitle = 'Event pulled from Server (' . $server['Server']['id'] . ') - "' . $server['Server']['name'] . '" - Notification by mail ' . $st;
                $this->loadLog()->createLogEntry($user, 'add', 'Event', $saveResult['Event']['id'], $logTitle);
            }
            if (!empty($data['Event']['EventTag'])) {
                $toSave = [];
                foreach ($data['Event']['EventTag'] as $et) {
                    $et['event_id'] = $this->id;
                    $toSave[] = $et;
                }
                if (!$this->EventTag->saveMany($toSave, ['validate' => true])) {
                    $this->log("Could not save tags when capturing event with ID {$this->id}.", LOG_WARNING);
                } else if (!empty($this->EventTag->validationErrors)) {
                    $this->log("Could not save some tags when capturing event with ID {$this->id}: " . json_encode($this->EventTag->validationErrors), LOG_WARNING);
                }
            }
            $parentEvent = $this->find('first', array(
                'conditions' => array('Event.id' => $this->id),
                'recursive' => -1
            ));
            if (!empty($data['Event']['Attribute'])) {
                $attributeHashes = [];
                foreach ($data['Event']['Attribute'] as $attribute) {
                    if (!empty($attribute['deleted'])) {
                        $this->Attribute->captureAttribute($attribute, $this->id, $user, 0, null, $parentEvent);
                    } else {
                        $attributeHash = sha1($attribute['value'] . '|' . $attribute['type'] . '|' . $attribute['category'], true);
                        if (!isset($attributeHashes[$attributeHash])) { // do not save duplicate values
                            $attributeHashes[$attributeHash] = true;
                            $this->Attribute->captureAttribute($attribute, $this->id, $user, 0, null, $parentEvent);
                        }
                    }
                }
                unset($attributeHashes);
            }

            if (!empty($data['Event']['Object'])) {
                $referencesToCapture = [];
                foreach ($data['Event']['Object'] as $object) {
                    $result = $this->Object->captureObject($object, $this->id, $user, false, $breakOnDuplicate, $parentEvent);
                    if (isset($object['ObjectReference'])) {
                        foreach ($object['ObjectReference'] as $objectRef) {
                            $objectRef['source_uuid'] = $object['uuid'];
                            $referencesToCapture[] = $objectRef;
                        }
                    }
                }
                foreach ($referencesToCapture as $referenceToCapture) {
                    $result = $this->Object->ObjectReference->captureReference(
                        $referenceToCapture,
                        $this->id
                    );
                    if ($result !== true) {
                        $title = "Could not save object reference when capturing event with ID {$this->id}";
                        $this->loadLog()->validationError($user, 'add', 'ObjectReference', $title, $result, $referenceToCapture);
                    }
                }
            }
            if (!empty($data['Event']['EventReport'])) {
                foreach ($data['Event']['EventReport'] as $report) {
                    $result = $this->EventReport->captureReport($user, $report, $this->id);
                }
            }

            // capture new keys, update existing, remove those no longer in the pushed data
            if (!empty($data['Event']['CryptographicKey'])) {
                $this->CryptographicKey->captureCryptographicKeyUpdate(
                    $user,
                    $data['Event']['CryptographicKey'],
                    $this->id,
                    'Event'
                );
            }

            // zeroq: check if sightings are attached and add to event
            if (isset($data['Sighting']) && !empty($data['Sighting'])) {
                $this->Sighting->captureSightings($data['Sighting'], null, $this->id, $user);
            }

            $this->captureAnalystData($user, $data['Event'], 'Event', $saveResult['Event']['uuid']);
            if ($fromXml) {
                $created_id = $this->id;
            }
            $workflowResult = $this->afterAddWorkflow($this->id, $fromPull);
            if (is_array($workflowResult)) {
                return implode(', ', $workflowResult);
            }
            if (!empty($data['Event']['published']) && 1 == $data['Event']['published']) {
                // do the necessary actions to publish the event (email, upload,...)
                if (('true' != Configure::read('MISP.disablerestalert')) && (empty($server) || empty($server['Server']['publish_without_email']))) {
                    $this->sendAlertEmailRouter($this->id, $user);
                }
                $this->publish($this->id, $passAlong);
            }
            if (empty($data['Event']['locked']) && !empty(Configure::read('MISP.default_event_tag_collection'))) {
                $this->TagCollection = ClassRegistry::init('TagCollection');
                $tagCollection = $this->TagCollection->fetchTagCollection($user, array('conditions' => array('TagCollection.id' => Configure::read('MISP.default_event_tag_collection'))));
                if (!empty($tagCollection)) {
                    $tag_id_list = array();
                    foreach ($tagCollection[0]['TagCollectionTag'] as $tagCollectionTag) {
                        $tag_id_list[] = $tagCollectionTag['tag_id'];
                    }
                    foreach ($tag_id_list as $tag_id) {
                        $tag = $this->EventTag->Tag->find('first', array(
                            'conditions' => array('Tag.id' => $tag_id),
                            'recursive' => -1,
                            'fields' => array('Tag.name')
                        ));
                        if (!empty($tag)) {
                            $found = $this->EventTag->find('first', array(
                                'conditions' => array(
                                    'event_id' => $this->id,
                                    'tag_id' => $tag_id
                                ),
                                'recursive' => -1,
                            ));
                            if (empty($found)) {
                                $this->EventTag->create();
                                if ($this->EventTag->save(array('event_id' => $this->id, 'tag_id' => $tag_id))) {
                                    $this->loadLog()->createLogEntry($user, 'tag', 'Event', $this->id, 'Attached tag (' . $tag_id . ') "' . $tag['Tag']['name'] . '" to event (' . $this->id . ')', 'Event (' . $this->id . ') tagged as Tag (' . $tag_id . ')');
                                }
                            }
                        }
                    }
                }
            }
            if ($jobId) {
                $this->EventLock->deleteBackgroundJobLock($this->id, $jobId);
            }

            return true;
        } else {
            $validationErrors['Event'] = $this->validationErrors;
            return json_encode($validationErrors);
        }
    }

    /**
     * @param int $eventId
     * @param bool $fromPull
     * @return true|array
     */
    private function afterAddWorkflow($eventId, $fromPull)
    {
        $triggerId = $fromPull ? 'event-after-save-new-from-pull' : 'event-after-save-new';
        if (!$this->isTriggerCallable($triggerId)) {
            return true;
        }

        $userForWorkflow = $this->User->getAuthUser(Configure::read('CurrentUserId'), true);
        $userForWorkflow['Role']['perm_site_admin'] = 1;

        $fullSavedEvent = $this->fetchEvent($userForWorkflow, [
            'eventid' => $eventId,
            'includeAttachments' => 1
        ])[0];
        $workflowErrors = [];
        $logging = [
            'model' => 'Event',
            'action' => 'add',
            'id' => $eventId,
        ];
        $success = $this->executeTrigger($triggerId, $fullSavedEvent, $workflowErrors, $logging);
        if (!$success) {
            return $workflowErrors;
        }
        return true;
    }

    public function _edit(array &$data, array $user, $id = null, $jobId = null, $passAlong = null, $force = false, $fast_update = false)
    {
        $data = $this->cleanupEventArrayFromXML($data);
        unset($this->Attribute->validate['event_id']);
        unset($this->Attribute->validate['value']['unique']); // otherwise gives bugs because event_id is not set
        // reposition to get the event.id with given uuid
        if (isset($data['Event']['uuid'])) {
            $conditions = ['Event.uuid' => $data['Event']['uuid']];
        } elseif ($id) {
            $conditions = ['Event.id' => $id];
        } else {
            throw new InvalidArgumentException("No event UUID or ID provided.");
        }
        $existingEvent = $this->find('first', ['conditions' => $conditions, 'recursive' => -1]);
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
                    'Server.unpublish_event',
                    'Server.publish_without_email',
                    'Server.internal',
                    'Server.remove_missing_tags'
                )
            ));
        } else {
            $server['Server']['internal'] = false;
        }
        // If the event exists...
        if (!empty($existingEvent)) {
            $data['Event']['id'] = $existingEvent['Event']['id'];
            $id = $existingEvent['Event']['id'];
            // Conditions affecting all:
            // user.org == event.org
            // edit timestamp newer than existing event timestamp
            if ($force || !isset($data['Event']['timestamp']) || $data['Event']['timestamp'] > $existingEvent['Event']['timestamp']) {
                if (!isset($data['Event']['timestamp'])) {
                    $data['Event']['timestamp'] = time();
                }
                if (isset($data['Event']['distribution']) && $data['Event']['distribution'] == 4) {
                    if (!isset($data['Event']['SharingGroup'])) {
                        if (!isset($data['Event']['sharing_group_id'])) {
                            return array('error' => 'Event could not be saved: Sharing group chosen as the distribution level, but no sharing group specified. Make sure that the event includes a valid sharing_group_id or change to a different distribution level.');
                        }
                        if (!$this->SharingGroup->checkIfAuthorised($user, $data['Event']['sharing_group_id'])) {
                            return array('error' => 'Event could not be saved: Invalid sharing group or you don\'t have access to that sharing group.');
                        }
                    } else {
                        $data['Event']['sharing_group_id'] = $this->SharingGroup->captureSG($data['Event']['SharingGroup'], $user, $server);
                        unset($data['Event']['SharingGroup']);
                        if ($data['Event']['sharing_group_id'] === false) {
                            return array('error' => 'Event could not be saved: User not authorised to create the associated sharing group.');
                        }
                    }
                }
                // If the above is true, we have two more options:
                // For users that are of the creating org of the event, always allow the edit
                // For users that are sync users, only allow the edit if the event is locked
                if ($existingEvent['Event']['orgc_id'] === $user['org_id']
                || ($user['Role']['perm_sync'] && $existingEvent['Event']['locked']) || $user['Role']['perm_site_admin']) {
                    if ($user['Role']['perm_sync']) {
                        if (isset($data['Event']['distribution']) && $data['Event']['distribution'] == 4 && !$this->SharingGroup->checkIfAuthorised($user, $data['Event']['sharing_group_id'])) {
                            return array('error' => 'Event could not be saved: The sync user has to have access to the sharing group in order to be able to edit it.');
                        }
                    }
                } else {
                    return array('error' => 'Event could not be saved: The user used to edit the event is not authorised to do so. This can be caused by the user not being of the same organisation as the original creator of the event whilst also not being a site administrator.');
                }
            } else {
                return array('error' => 'Event could not be saved: Event in the request not newer than the local copy.');
            }
            $changed = false;
            // If a field is not set in the request, just reuse the old value
            // Also, compare the event to the existing event and see whether this is a meaningful change
            $recoverFields = array('analysis', 'threat_level_id', 'info', 'distribution', 'date', 'org_id');
            foreach ($recoverFields as $rF) {
                if (!isset($data['Event'][$rF])) {
                    $data['Event'][$rF] = $existingEvent['Event'][$rF];
                } else {
                    if ($data['Event'][$rF] != $existingEvent['Event'][$rF]) {
                        $changed = true;
                    }
                }
            }
        } else {
            return array('error' => 'Event could not be saved: Could not find the local event.');
        }
        if (
            (Configure::read('MISP.block_publishing_for_same_creator', false) && !$user['Role']['perm_sync'] && $user['id'] == $existingEvent['Event']['user_id']) ||
            (!empty($data['Event']['published']) && !$user['Role']['perm_publish'])
        ) {
            $data['Event']['published'] = 0;
        }
        if (!isset($data['Event']['published'])) {
            $data['Event']['published'] = 0;
        }
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
            'disable_correlation',
            'extends_uuid'
        );
        $saveResult = $this->save(array('Event' => $data['Event']), array('fieldList' => $fieldList));
        if ($saveResult) {
            if ($jobId) {
                /** @var EventLock $eventLock */
                $eventLock = ClassRegistry::init('EventLock');
                $eventLock->insertLockBackgroundJob($data['Event']['id'], $jobId);
            }
            $validationErrors = array();

            // capture new keys, update existing, remove those no longer in the pushed data
            if (!empty($data['Event']['CryptographicKey'])) {
                $this->CryptographicKey->captureCryptographicKeyUpdate(
                    $user,
                    $data['Event']['CryptographicKey'],
                    $existingEvent['Event']['id'],
                    'Event'
                );
            }
            if (isset($data['Event']['Attribute'])) {
                $data['Event']['Attribute'] = array_values($data['Event']['Attribute']);
                $attributes = [];
                foreach ($data['Event']['Attribute'] as $k => $attribute) {
                    $nothingToChange = false;
                    $result = $this->Attribute->editAttribute($attribute, $saveResult, $user, 0, false, $force, $nothingToChange, $server);
                    if (is_array($result)) {
                        $attributes[] = $result;
                    }
                    if (!$nothingToChange) {
                        $changed = true;
                    }
                }
                $this->Attribute->editAttributeBulk($attributes, $saveResult, $user);
            }
            if (isset($data['Event']['Object'])) {
                $data['Event']['Object'] = array_values($data['Event']['Object']);
                foreach ($data['Event']['Object'] as $object) {
                    $nothingToChange = false;
                    $result = $this->Object->editObject($object, $saveResult, $user, false, $force, $nothingToChange);
                    if ($result !== true) {
                        $validationErrors['Object'][] = $result;
                    }
                    if (!$nothingToChange) {
                        $changed = true;
                    }
                }
                foreach ($data['Event']['Object'] as $object) {
                    if (isset($object['ObjectReference'])) {
                        foreach ($object['ObjectReference'] as $objectRef) {
                            $nothingToChange = false;
                            $objectRef['source_uuid'] = $object['uuid'];
                            $result = $this->Object->ObjectReference->captureReference($objectRef, $this->id);
                            if ($result !== true) {
                                $title = "Could not save object reference when capturing event with ID {$this->id}";
                                $this->loadLog()->validationError($user, 'edit', 'ObjectReference', $title, $result, $objectRef);
                            }
                            if ($result && !$nothingToChange) {
                                $changed = true;
                            }
                        }
                    }
                }
            }
            if (isset($data['Event']['EventReport'])) {
                foreach ($data['Event']['EventReport'] as $report) {
                    $nothingToChange = false;
                    $result = $this->EventReport->editReport($user, ['EventReport' => $report], $this->id, true, $nothingToChange);
                    if (!empty($result)) {
                        $validationErrors['EventReport'][] = $result;
                    }
                    if (!$nothingToChange) {
                        $changed = true;
                    }
                }
            }
            if (isset($data['Event']['Tag']) && $user['Role']['perm_tagger']) {
                foreach ($data['Event']['Tag'] as $tag) {
                    $tag_id = $this->EventTag->Tag->captureTag($tag, $user);
                    if ($tag_id) {
                        $nothingToChange = false;
                        $tag['id'] = $tag_id;
                        $result = $this->EventTag->handleEventTag($this->id, $tag, $nothingToChange);
                        if ($result && !$nothingToChange) {
                            $changed = true;
                        }
                    } else {
                        // If we couldn't attach the tag it is most likely because we couldn't create it - which could have many reasons
                        // However, if a tag couldn't be added, it could also be that the user is a tagger but not a tag editor
                        // In which case if no matching tag is found, no tag ID is returned. Logging these is pointless as it is the correct behaviour.
                        if ($user['Role']['perm_tag_editor']) {
                            $this->loadLog()->createLogEntry($user, 'edit', 'Event', $this->id, "Failed create or attach Tag {$tag['name']} to the event.");
                        }
                    }
                }
            }
            // zeroq: if sightings then attach to event
            if (isset($data['Sighting']) && !empty($data['Sighting'])) {
                $this->Sighting->captureSightings($data['Sighting'], null, $this->id, $user);
            }

            $this->captureAnalystData($user, $data['Event'], 'Event', $saveResult['Event']['uuid']);
            // if published -> do the actual publishing
            if ($changed && (!empty($data['Event']['published']) && 1 == $data['Event']['published'])) {
                // The edited event is from a remote server ?
                if ($passAlong) {
                    $st = $server['Server']['publish_without_email'] == 0 ? 'enabled' : 'disabled';
                    $logTitle = 'Event edited from Server (' . $server['Server']['id'] . ') - "' . $server['Server']['name'] . '" - Notification by mail ' . $st;
                } else {
                    $logTitle = 'Event edited (locally)';
                }
                $this->loadLog()->createLogEntry($user, 'add', 'Event', $saveResult['Event']['id'], $logTitle);
                // do the necessary actions to publish the event (email, upload,...)
                if ((true != Configure::read('MISP.disablerestalert')) && (empty($server) || empty($server['Server']['publish_without_email']))) {
                    $this->sendAlertEmailRouter($id, $user, $existingEvent['Event']['publish_timestamp']);
                }
                $this->publish($existingEvent['Event']['id'], $passAlong);
            }
            if ($jobId) {
                $eventLock->deleteBackgroundJobLock($data['Event']['id'], $jobId);
            }
            return true;
        }
        return $this->validationErrors;
    }

    // format has to be:
    // array('Event' => array(), 'Attribute' => array('ShadowAttribute' => array()), 'EventTag' => array(), 'ShadowAttribute' => array());
    public function savePreparedEvent($event)
    {
        unset($event['Event']['id']);
        $this->create();
        $this->save($event['Event']);
        $event['Event']['id'] = $this->id;
        $objects = array('Attribute', 'ShadowAttribute', 'EventTag', 'Object');
        foreach ($objects as $object_type) {
            if (!empty($event[$object_type])) {
                $saveMethod = '__savePrepared' . $object_type;
                foreach ($event[$object_type] as $object) {
                    $this->$saveMethod($object, $event);
                }
            }
        }
        if (!empty($event['Object'])) {
            $objectRefTypes = array('Attribute', 'Object');
            foreach ($event['Object'] as $k => $object) {
                foreach ($object['ObjectReference'] as $k2 => $objectRef) {
                    $savedObjectRef = $this->Object->ObjectReference->find('first', array(
                        'recursive' => -1,
                        'conditions' => array('ObjectReference.uuid' => $objectRef['uuid'])
                    ));
                    $objectRefType = intval($savedObjectRef['ObjectReference']['referenced_type']);
                    $element = $this->{$objectRefTypes[$objectRefType]}->find('first', array(
                        'conditions' => array($objectRefTypes[$objectRefType] . '.uuid' => $objectRef['referenced_uuid']),
                        'recursive' => -1,
                        'fields' => array($objectRefTypes[$objectRefType] . '.id')
                    ));
                    $savedObjectRef['ObjectReference']['referenced_id'] = $element[$objectRefTypes[$objectRefType]]['id'];
                    $result = $this->Object->ObjectReference->save($savedObjectRef);
                }
            }
        }
        return $event['Event']['id'];
    }

    private function __savePreparedAttribute(&$attribute, $event, $object_id = 0)
    {
        unset($attribute['id']);
        $attribute['event_id'] = $event['Event']['id'];
        $attribute['object_id'] = $object_id;
        $this->Attribute->create();
        $this->Attribute->save($attribute);
        foreach ($attribute['ShadowAttribute'] as $k => $sa) {
            $this->__savePreparedShadowAttribute($sa, $event, $this->Attribute->id);
        }
        foreach ($attribute['AttributeTag'] as $k => $at) {
            $this->__savePreparedAttributeTag($at, $event, $this->Attribute->id);
        }
        return true;
    }

    private function __savePreparedObject(&$object, $event)
    {
        unset($object['id']);
        $object['event_id'] = $event['Event']['id'];
        $this->Object->create();
        $this->Object->save($object);
        foreach ($object['Attribute'] as $k => $a) {
            $this->__savePreparedAttribute($a, $event, $this->Object->id);
        }
        foreach ($object['ObjectReference'] as $objectRef) {
            $this->__savePreparedObjectReference($objectRef, $event, $this->Object->id, $object['uuid']);
        }
        return true;
    }

    #referenced IDs have to be updated after everything else is done!
    private function __savePreparedObjectReference($objectRef, $event, $object_id, $object_uuid)
    {
        unset($objectRef['id']);
        $objectRef['event_id'] = $event['Event']['id'];
        $objectRef['object_id'] = $object_id;
        $objectRef['object_uuid'] = $object_uuid;
        $this->Object->ObjectReference->create();
        $this->Object->ObjectReference->save($objectRef);
        return true;
    }

    private function __savePreparedShadowAttribute($shadow_attribute, $event, $old_id = 0)
    {
        unset($shadow_attribute['id']);
        $shadow_attribute['event_id'] = $event['Event']['id'];
        $shadow_attribute['old_id'] = $old_id;
        $this->ShadowAttribute->create();
        $this->ShadowAttribute->save($shadow_attribute);
        return true;
    }

    private function __savePreparedEventTag($event_tag, $event)
    {
        unset($event_tag['id']);
        $event_tag['event_id'] = $event['Event']['id'];
        $this->EventTag->create();
        $this->EventTag->save($event_tag);
        return true;
    }

    private function __savePreparedAttributeTag($attribute_tag, $event, $attribute_id)
    {
        unset($attribute_tag['id']);
        $attribute_tag['event_id'] = $event['Event']['id'];
        $attribute_tag['attribute_id'] = $attribute_id;
        $this->Attribute->AttributeTag->create();
        $this->Attribute->AttributeTag->save($attribute_tag);
        return true;
    }

    // pass an event or an attribute together with the server id.
    // If the distribution of the object outright allows for it to be shared, return true
    // If the distribution is org only / comm only, return false
    // If the distribution is sharing group only, check if the sync user is in the sharing group or not, return true if yes, false if no
    public function checkDistributionForPush($object, $server, $context = 'Event')
    {
        $model = $context;
        if ($context === 'Sighting') {
            $model = 'Event';
        }
        if (empty(Configure::read('MISP.host_org_id')) || !$server['Server']['internal'] || Configure::read('MISP.host_org_id') != $server['Server']['remote_org_id']) {
            if ($context != 'Sighting' && $object[$model]['distribution'] < 2) {
                return false;
            }
        }
        if ($object[$model]['distribution'] == 4) {
            if ($context === 'Event' || $context === 'Sighting') {
                return $this->SharingGroup->checkIfServerInSG($object['SharingGroup'], $server);
            } else {
                return $this->SharingGroup->checkIfServerInSG($object[$context]['SharingGroup'], $server);
            }
        }
        return true;
    }

    /**
     * New variant of uploadEventToServersRouter (since 2.4.137) for pushing sightings.
     * @param array $event with event tags and whole sharing group
     * @param null|int $passAlong Server ID that should be skipped from uploading.
     * @param array $sightingsUuidsToPush
     * @return array|bool
     * @throws Exception
     */
    private function uploadEventSightingsToServersRouter(array $event, $passAlong, array $sightingsUuidsToPush)
    {
        $this->Server = ClassRegistry::init('Server');
        $conditions = ['Server.push_sightings' => 1];
        if ($passAlong) {
            $conditions[] = array('Server.id !=' => $passAlong);
        }
        $servers = $this->Server->find('all', [
            'conditions' => $conditions,
            'contain' => ['RemoteOrg'], // remote org required for checkDistributionForPush
            'recursive' => -1,
            'order' => ['Server.priority ASC', 'Server.id ASC'],
        ]);
        // TODO: This are new conditions, that was not used in old code
        // Filter out servers that do not match server conditions for event push
        $servers = $this->Server->eventFilterPushableServers($event, $servers);
        // Filter out servers that do not match event sharing group distribution for event push
        $servers = array_filter($servers, function (array $server) use ($event) {
            return $this->checkDistributionForPush($event, $server, 'Sighting');
        });
        if (empty($servers)) {
            return true;
        }

        $failedServers = [];
        foreach ($servers as $server) {
            $serverSync = new ServerSyncTool($server, $this->setupSyncRequest($server));
            try {
                try {
                    if ($serverSync->eventExists($event) === false) {
                        continue; // skip if event not exists on remote server
                    }
                } catch (Exception $e) {}

                $this->pushSightingsToServer($serverSync, $event, $sightingsUuidsToPush);
            } catch (Exception $e) {
                $this->logException("Uploading sightings to server {$server['Server']['id']} failed.", $e);
                $failedServers[] = $server['Server']['url'];
            }
        }
        if (!empty($failedServers)) {
            return $failedServers;
        }
        return true;
    }

    /**
     * @param ServerSyncTool $serverSync
     * @param array $event
     * @param array $sightingsUuidsToPush
     * @throws HttpSocketJsonException
     * @throws Exception
     */
    private function pushSightingsToServer(ServerSyncTool $serverSync, array $event, array $sightingsUuidsToPush = [])
    {
        $fakeSyncUser = [
            'org_id' => $serverSync->server()['Server']['remote_org_id'],
            'Role' => [
                'perm_site_admin' => 0,
            ],
        ];

        // Process sightings in batch to keep memory requirements low
        foreach ($this->Sighting->fetchUuidsForEventToPush($event, $fakeSyncUser, $sightingsUuidsToPush) as $batch) {
            // Filter out sightings that already exists on remote server
            $existingSightings = $serverSync->filterSightingUuidsForPush($event, $batch);
            $newSightings = array_diff($batch, $existingSightings);
            if (empty($newSightings)) {
                continue;
            }

            $conditions = ['Sighting.uuid' => $newSightings];
            $sightings = $this->Sighting->attachToEvent($event, $fakeSyncUser, null, $conditions, true);
            $serverSync->uploadSightings($sightings, $event['Event']['uuid']);
        }
    }

    /**
     * @param int $id Event ID
     * @param int|null $passAlong ID of server that event will be not pushed
     * @return array|bool
     * @throws Exception
     */
    private function uploadEventToServersRouter($id, $passAlong = null)
    {
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
                'perm_sync' => 1,
                'perm_audit' => 0,
            ),
            'org_id' => $eventOrgcId['Event']['orgc_id']
        );
        $event = $this->fetchEvent($elevatedUser, ['eventid' => $id, 'metadata' => 1]);
        if (empty($event)) {
            return true;
        }
        $event = $event[0];
        $event['Event']['locked'] = 1;
        // get a list of the servers
        $this->Server = ClassRegistry::init('Server');
        $conditions = ['push' => 1];
        if ($passAlong) {
            $conditions[] = ['Server.id !=' => $passAlong];
        }
        $servers = $this->Server->find('all', [
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => ['RemoteOrg', 'Organisation'],
            'order' => ['Server.priority ASC', 'Server.id ASC'],
        ]);
        // iterate over the servers and upload the event
        if (empty($servers)) {
            return true;
        }
        $uploaded = true;
        $failedServers = [];

        foreach ($servers as $server) {
            if (
                (!isset($server['Server']['internal']) || !$server['Server']['internal']) && $event['Event']['distribution'] < 2
            ) {
                continue;
            }
            // Skip servers where the event has come from.
            if ($passAlong != $server['Server']['id']) {
                $serverSync = new ServerSyncTool($server, $this->setupSyncRequest($server));
                $params = [
                    'eventid' => $id,
                    'includeAttachments' => true,
                    'includeAllTags' => true,
                    'deleted' => [0, 1],
                    'excludeGalaxy' => 1,
                    'noSightings' => true, // sightings are pushed separately
                ];
                if (!empty($server['Server']['push_rules'])) {
                    $pushRules = json_decode($server['Server']['push_rules'], true);
                    if (!empty($pushRules['tags']['NOT'])) {
                        $params['blockedAttributeTags'] = $pushRules['tags']['NOT'];
                    }
                }
                if (!empty($server['Server']['internal'])) {
                    $params['excludeLocalTags'] = 0;
                }
                $event = $this->fetchEvent($elevatedUser, $params);
                $event = $event[0];
                $event['Event']['locked'] = 1;

                $fakeSyncUser = array(
                    'org_id' => $server['Server']['remote_org_id'],
                    'Role' => array(
                        'perm_site_admin' => 0
                    )
                );
                // TODO: We are pushing galaxy clusters to remove server even if event is not pushable to that server
                $this->Server->syncGalaxyClusters($serverSync, $server, $fakeSyncUser, $technique=$event['Event']['id'], $event=$event);
                $thisUploaded = $this->uploadEventToServer($event, $server, $serverSync);
                if ($thisUploaded === 'Success') {
                    try {
                        $this->pushSightingsToServer($serverSync, $event); // push sighting by method that check for duplicates
                    } catch (Exception $e) {
                        $this->logException("Uploading sightings to server {$server['Server']['id']} failed.", $e);
                    }
                }
                if (isset($this->data['ShadowAttribute'])) {
                    $this->Server->syncProposals(null, $server, null, $id, $this);
                }
                if (!$thisUploaded) {
                    $uploaded = !$uploaded ? $uploaded : $thisUploaded;
                    $failedServers[] = $server['Server']['url'];
                }
            }
        }
        if (!$uploaded) {
            if (empty($failedServers)) {
                return true;
            }
            return $failedServers;
        }
        return true;
    }

    /**
     * @param int $id Event ID
     * @param array $user
     * @param int|null $passAlong Server ID that should be skipped when pushing sightings.
     * @param array $sightingUuids Push just sightings with these UUIDs
     * @return array|bool
     * @throws Exception
     */
    public function publishSightingsRouter($id, array $user, $passAlong = null, array $sightingUuids = [])
    {
        if (Configure::read('MISP.background_jobs')) {
            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $message = empty($sightingUuids) ? __('Publishing sightings.') : __('Publishing %s sightings.', count($sightingUuids));
            $jobId = $job->createJob($user, Job::WORKER_DEFAULT, 'publish_event', "Event ID: $id", $message);

            $args = ['publish_sightings', $id, $passAlong, $jobId, $user['id']];
            if (!empty($sightingUuids)) {
                $args[] = $this->getBackgroundJobsTool()->enqueueDataFile($sightingUuids);
            }

            return $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_EVENT,
                $args,
                true,
                $jobId
            );
        }

        return $this->publishSightings($id, $passAlong, $sightingUuids);
    }

    public function publishRouter($id, $passAlong = null, $user)
    {
        if (Configure::read('MISP.background_jobs')) {

            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob($user, Job::WORKER_PRIO, 'publish_event', "Event ID: $id", 'Publishing.');

            return $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::PRIO_QUEUE,
                BackgroundJobsTool::CMD_EVENT,
                [
                    'publish',
                    $id,
                    $passAlong,
                    $jobId,
                    $user['id']
                ],
                true,
                $jobId
            );
        }
        return $this->publish($id, $passAlong);
    }

    /**
     * @param int|string $id Event ID or UUID
     * @param $passAlong
     * @param array $sightingsUuidsToPush
     * @return array|bool
     * @throws Exception
     */
    public function publishSightings($id, $passAlong = null, array $sightingsUuidsToPush = [])
    {
        if (is_numeric($id)) {
            $condition = array('Event.id' => $id);
        } else {
            $condition = array('Event.uuid' => $id);
        }
        $event = $this->find('first', array(
            'recursive' => -1,
            'conditions' => $condition,
            'contain' => ['EventTag', 'SharingGroup' => ['SharingGroupServer', 'SharingGroupOrg' => ['Organisation']]],
        ));
        if (empty($event)) {
            return false;
        }

        // update the DB to set the sightings timestamp
        // for background jobs, this should be done already
        $fieldList = array('id', 'info', 'sighting_timestamp');
        $event['Event']['sighting_timestamp'] = time();
        $event['Event']['skip_zmq'] = 1;
        $event['Event']['skip_kafka'] = 1;
        $this->save($event, array('fieldList' => $fieldList));

        return $this->uploadEventSightingsToServersRouter($event, $passAlong, $sightingsUuidsToPush);
    }

    // Performs all the actions required to publish an event
    public function publish($id, $passAlong = null, $jobId = null)
    {
        $event = $this->find('first', array(
            'recursive' => -1,
            'conditions' => array('Event.id' => $id)
        ));

        if (empty($event)) {
            return false;
        }
        $hostOrg = $this->Org->find('first', [
            'recursive' => -1,
            'conditions' => [
                'id' => Configure::read('MISP.host_org_id')
            ],
        ]);
        if (empty($hostOrg)) {
            $hostOrg = $this->Org->find('first', [
                'recursive' => -1,
                'order' => ['id ASC']
            ]);
        }
        $userForPubSub = [
            'id' => 0,
            'org_id' => $hostOrg['Org']['id'],
            'Role' => ['perm_sync' => 0, 'perm_audit' => 0, 'perm_site_admin' => 1],
            'Organisation' => $hostOrg['Org']
        ];
        $allowZMQ = Configure::read('Plugin.ZeroMQ_enable');
        $kafkaTopic = Configure::read('Plugin.Kafka_event_publish_notifications_topic');
        $allowKafka = Configure::read('Plugin.Kafka_enable') &&
            Configure::read('Plugin.Kafka_event_publish_notifications_enable') &&
            !empty($kafkaTopic);
        $triggerCallable = $this->isTriggerCallable('event-publish');

        if ($allowZMQ || $allowKafka || $triggerCallable) {
            $currentUserId = Configure::read('CurrentUserId');
            $userForWorkflow = $this->User->getAuthUser($currentUserId, true);
            $userForWorkflow['Role']['perm_site_admin'] = 1;
            $fullEvent = $this->fetchEvent($userForWorkflow, [
                'eventid' => $id,
                'includeAttachments' => 1
            ]);
        }
        if ($triggerCallable) {
            $workflowErrors = [];
            $logging = [
                'model' => 'Event',
                'action' => 'publish',
                'id' => $id,
                'message' => __('Publishing stopped by a blocking workflow.'),
            ];
            $success = $this->executeTrigger('event-publish', $fullEvent[0], $workflowErrors, $logging);
            if (empty($success)) {
                $errorMessage = implode(', ', $workflowErrors);

                return $errorMessage;
            }
        }
        if ($jobId) {
            $this->Behaviors->unload('SysLogLogable.SysLogLogable');
        } else {
            // update the DB to set the published flag
            // for background jobs, this should be done already
            $fieldList = array('published', 'id', 'info', 'publish_timestamp');
            $event['Event']['published'] = 1;
            $event['Event']['publish_timestamp'] = time();
            $event['Event']['skip_zmq'] = 1;
            $event['Event']['skip_kafka'] = 1;
            $result = $this->save($event, array('fieldList' => $fieldList));
            if (!$result) {
                return json_encode($this->validationErrors);
            }
        }
        if ($allowZMQ) {
            $this->publishEventToZmq($id, $userForPubSub, $fullEvent);
        }
        if ($allowKafka) {
            $this->publishEventToKafka($id, $userForPubSub, $fullEvent, $kafkaTopic);
        }
        return $this->uploadEventToServersRouter($id, $passAlong);
    }

    // Sends out an email to all people within the same org with the request to be contacted about a specific event.
    public function sendContactEmailRouter($id, $message, $creator_only, $user)
    {
        if (Configure::read('MISP.background_jobs')) {
            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob(
                $user,
                Job::WORKER_EMAIL,
                'contact_alert',
                'Owner ' . ($creator_only ? 'user' : 'org') . ' of event #' . $id,
                'Contacting.'
            );

            return $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::EMAIL_QUEUE,
                BackgroundJobsTool::CMD_EVENT,
                [
                    'contactemail',
                    $id,
                    $message,
                    $creator_only,
                    $user['id'],
                    $jobId
                ],
                true,
                $jobId
            );

            return true;
        } else {
            return $this->sendContactEmail($id, $message, $creator_only, $user);
        }
    }

    public function reportValidationIssuesEvents()
    {
        $this->Behaviors->detach('Regexp');
        // get all events..
        $events = $this->find('all', array('recursive' => -1));
        // for all events..
        $result = array();
        $k = 0;
        $i = 0;
        foreach ($events as $k => $event) {
            $this->set($event);
            if (!$this->validates()) {
                $errors = $this->validationErrors;
                $result[$i]['id'] = $event['Event']['id'];
                $result[$i]['error'] = $errors;
                $result[$i]['details'] = $event;
                $i++;
            }
        }
        return array($result, $k);
    }

    // check two version strings. If version 1 is older than 2, return -1, if they are the same return 0, if version 2 is older return 1
    public function compareVersions($version1, $version2)
    {
        $version1Array = explode('.', $version1);
        $version2Array = explode('.', $version2);

        if ($version1Array[0] != $version2Array[0]) {
            if ($version1Array[0] > $version2Array[0]) {
                return 1;
            } else {
                return -1;
            }
        }
        if ($version1Array[1] != $version2Array[1]) {
            if ($version1Array[1] > $version2Array[1]) {
                return 1;
            } else {
                return -1;
            }
        }
        if ($version1Array[2] != $version2Array[2]) {
            if ($version1Array[2] > $version2Array[2]) {
                return 1;
            } else {
                return -1;
            }
        }
    }

    // main dispatch method for updating an incoming xmlArray - pass xmlArray to all of the appropriate transformation methods to make all the changes necessary to save the imported event
    public function updateXMLArray($xmlArray, $response = true)
    {
        if (isset($xmlArray['xml_version']) && $response) {
            $xmlArray['response']['xml_version'] = $xmlArray['xml_version'];
            unset($xmlArray['xml_version']);
        }

        if (!$response) {
            $xmlArray = array('response' => $xmlArray);
        }
        // if a version is set, it must be at least 2.2.0 - check the version and save the result of the comparison
        if (isset($xmlArray['response']['xml_version'])) {
            $version = $this->compareVersions($xmlArray['response']['xml_version'], $this->mispVersion);
        }
        // if no version is set, set the version to older (-1) manually
        else {
            $version = -1;
        }
        // same version, proceed normally
        if ($version != 0) {
            // The xml is from an instance that is newer than the local instance, let the user know that the admin needs to upgrade before it could be imported
            if ($version == 1) {
                throw new Exception('This XML file is from a MISP instance that is newer than the current instance. Please contact your administrator about upgrading this instance.');
            }

            // if the xml contains an event or events from an older MISP instance, let's try to upgrade it!
            // Let's manually set the version to something below 2.2.0 if there is no version set in the xml
            if (!isset($xmlArray['response']['xml_version'])) {
                $xmlArray['response']['xml_version'] = '2.1.0';
            }

            // Upgrade from versions below 2.2.0 will need to replace the risk field with threat level id
            if ($this->compareVersions($xmlArray['response']['xml_version'], '2.2.0') < 0) {
                if ($response) {
                    $xmlArray['response'] = $this->__updateXMLArray220($xmlArray['response']);
                } else {
                    $xmlArray = $this->__updateXMLArray220($xmlArray);
                }
            }
        }
        unset($xmlArray['response']['xml_version']);
        if ($response) {
            return $xmlArray;
        } else {
            return $xmlArray['response'];
        }
    }

    // replaces the old risk value with the new threat level id
    private function __updateXMLArray220($xmlArray)
    {
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

    public function sharingGroupRequired($field)
    {
        if ($this->data[$this->alias]['distribution'] == 4) {
            return (!empty($field));
        }
        return true;
    }

    // expects a date string in the YYYY-MM-DD format
    // returns the passed string or false if the format is invalid
    // based on the fix provided by stevengoosensB
    public function dateFieldCheck($date)
    {
        // regex check for from / to field by stevengoossensB
        return (preg_match('/^[0-9]{4}-(0[1-9]|1[012])-(0[1-9]|1[0-9]|2[0-9]|3[01])$/', $date)) ? $date : false;
    }

    /**
     * @param array $attribute
     * @param array $correlatedAttributes
     * @param array $correlatedShadowAttributes
     * @param array $filterType
     * @param array $sightingsData
     * @return array|null
     */
    private function __prepareAttributeForView(
        $attribute,
        $correlatedAttributes,
        $correlatedShadowAttributes,
        $filterType = false,
        $sightingsData
    ) {
        $attribute['objectType'] = 'attribute';

        if ($filterType) {
            $include = true;
            /* proposal */
            if ($filterType['proposal'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (!empty($attribute['ShadowAttribute'])) { // `include only`
                $include = $include && ($filterType['proposal'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['proposal'] == 2);
            }

            /* correlation */
            if ($filterType['correlation'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (isset($correlatedAttributes[$attribute['id']])) { // `include only`
                $include = $include && ($filterType['correlation'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['correlation'] == 2);
                if (!empty($attribute['over_correlation'])) {
                    $include = false;
                }
            }

            if ($filterType['correlationId'] && $include) {
                $include = false;
                if (isset($correlatedAttributes[$attribute['id']])) {
                    foreach ($correlatedAttributes[$attribute['id']] as $correlation) {
                        if (in_array($correlation['id'], $filterType['correlationId'])) {
                            $include = true;
                            break;
                        }
                    }
                }
            }

            /* feed */
            if ($filterType['feed'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (!empty($attribute['Feed'])) { // `include only`
                $include = $include && ($filterType['feed'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['feed'] == 2);
            }

            /* server */
            if ($filterType['server'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (!empty($attribute['Server'])) { // `include only`
                $include = $include && ($filterType['server'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['server'] == 2);
            }

            /* sightings */
            if ($filterType['sighting'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (isset($sightingsData['data'][$attribute['id']])) { // `include only`
                $include = $include && ($filterType['sighting'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['sighting'] == 2);
            }

            /* TypeGroupings */
            if (
                $filterType['attributeFilter'] !== 'all'
                && isset(MispAttribute::TYPE_GROUPINGS[$filterType['attributeFilter']])
                && !in_array($attribute['type'], MispAttribute::TYPE_GROUPINGS[$filterType['attributeFilter']], true)
            ) {
                return null;
            }

            if ($filterType['warning'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (!empty($attribute['warnings']) || !empty($attribute['validationIssue'])) { // `include only`
                $include = $include && ($filterType['warning'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['warning'] == 2);
            }

            if ($filterType['warninglistId'] && $include) {
                $include = false;
                if (isset($attribute['warnings'])) {
                    foreach ($attribute['warnings'] as $warning) {
                        if (in_array($warning['warninglist_id'], $filterType['warninglistId'])) {
                            $include = true;
                            break;
                        }
                    }
                }
            }

            if (!$include) {
                return null;
            }
        }

        if (!empty($attribute['ShadowAttribute'])) {
            $temp = array();
            foreach ($attribute['ShadowAttribute'] as $proposal) {
                $result = $this->__prepareProposalForView($proposal, $correlatedShadowAttributes, $filterType);
                if ($result) {
                    $temp[] = $result;
                }
            }
            $attribute['ShadowAttribute'] = $temp;
        }
        return $this->__prepareGenericForView($attribute);
    }

    /**
     * @param array $proposal
     * @param array $correlatedShadowAttributes
     * @param array $filterType
     * @return array|null
     */
    private function __prepareProposalForView($proposal, $correlatedShadowAttributes, $filterType = false)
    {
        if ($proposal['proposal_to_delete']) {
            $proposal['objectType'] = 'proposal_delete';
        } else {
            $proposal['objectType'] = 'proposal';
        }

        $include = true;
        if ($filterType) {
            $include = $filterType['proposal'] != 2;

            /* correlation */
            if ($filterType['correlation'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (isset($correlatedShadowAttributes[$proposal['id']])) { // `include only`
                $include = $include && ($filterType['correlation'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['correlation'] == 2);
            }

            if ($filterType['correlationId'] && $include) {
                $include = false;
                if (isset($correlatedShadowAttributes[$proposal['id']])) {
                    foreach ($correlatedShadowAttributes[$proposal['id']] as $correlation) {
                        if (in_array($correlation['id'], $filterType['correlationId'])) {
                            $include = true;
                            break;
                        }
                    }
                }
            }

            /* feed */
            if ($filterType['feed'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (!empty($proposal['Feed'])) { // `include only`
                $include = $include && ($filterType['feed'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['feed'] == 2);
            }

            /* server */
            if ($filterType['server'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (!empty($attribute['Server'])) { // `include only`
                $include = $include && ($filterType['server'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['server'] == 2);
            }

            /* TypeGroupings */
            if (
                $filterType['attributeFilter'] !== 'all'
                && isset(MispAttribute::TYPE_GROUPINGS[$filterType['attributeFilter']])
                && !in_array($proposal['type'], MispAttribute::TYPE_GROUPINGS[$filterType['attributeFilter']], true)
            ) {
                return null;
            }

            /* warning */
            if ($filterType['warning'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (!empty($proposal['warnings']) || !empty($proposal['validationIssue'])) { // `include only`
                $include = $include && ($filterType['warning'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['warning'] == 2);
            }
        }

        if (!$include) {
            return null;
        }

        return $this->__prepareGenericForView($proposal);
    }

    private function __prepareObjectForView(
        $object,
        $correlatedAttributes,
        $correlatedShadowAttributes,
        $filterType,
        $sightingsData
    ) {
        $object['category'] = $object['meta-category'];

        $include = empty($filterType['attributeFilter']) ||
            in_array($filterType['attributeFilter'], array('all', 'object', 'correlation', 'proposal', 'warning')) ||
            $object['meta-category'] === $filterType['attributeFilter'];

        if (!$include) {
            return null;
        }

        if (!empty($object['Attribute'])) {
            $temp = array();
            foreach ($object['Attribute'] as $attribute) {
                $result = $this->__prepareAttributeForView(
                    $attribute,
                    $correlatedAttributes,
                    $correlatedShadowAttributes,
                    false,
                    $sightingsData
                );
                if ($result) {
                    $temp[] = $result;
                }
            }
            $object['Attribute'] = $temp;
        }

        // filters depend on child objects
        if (in_array($filterType['attributeFilter'], array('correlation', 'proposal', 'warning'), true)
            || $filterType['correlation'] != 0
            || $filterType['proposal'] != 0
            || $filterType['warning'] != 0
            || $filterType['sighting'] != 0
            || $filterType['feed'] != 0
            || $filterType['server'] != 0
            || $filterType['warninglistId'] !== null
            || $filterType['correlationId'] !== null
        ) {
            $include = $this->__checkObjectByFilter($object, $filterType, $correlatedAttributes, $correlatedShadowAttributes, $sightingsData);
            if (!$include) {
                return null;
            }
        }

        return $object;
    }

    /**
     * @param array $object
     * @param array $filterType
     * @param array $correlatedAttributes
     * @param array $correlatedShadowAttributes
     * @param array $sightingsData
     * @return bool
     */
    private function __checkObjectByFilter($object, $filterType, $correlatedAttributes, $correlatedShadowAttributes, $sightingsData)
    {
        if (empty($object['Attribute'])) { // reject empty object
            return false;
        }

        /* proposal */
        if ($filterType['proposal'] == 0) { // `both`
            // pass, do not consider as `both` is selected
        } else if ($filterType['proposal'] == 1 || $filterType['proposal'] == 2) {
            $flagKeep = false;
            foreach ($object['Attribute'] as $attribute) { // check if object contains at least 1 proposal
                if (!empty($attribute['ShadowAttribute'])) {
                    $flagKeep = ($filterType['proposal'] == 1); // keep if proposal are included
                    break;
                }
            }
            if (!$flagKeep) {
                return false;
            }
        }

        /* warning */
        if ($filterType['warning'] == 0) { // `both`
            // pass, do not consider as `both` is selected
        } else if ($filterType['warning'] == 1 || $filterType['warning'] == 2) {
            $flagKeep = false;
            foreach ($object['Attribute'] as $attribute) { // check if object contains at least 1 warning
                if (!empty($attribute['warnings'])) {
                    $flagKeep = ($filterType['warning'] == 1); // keep if warnings are included
                } else {
                    $flagKeep = ($filterType['warning'] == 2); // keep if warnings are excluded
                }
                if (!$flagKeep && !empty($attribute['ShadowAttribute'])) {
                    foreach ($attribute['ShadowAttribute'] as $shadowAttribute) {
                        if (!empty($shadowAttribute['warnings'])) {
                            $flagKeep = ($filterType['warning'] == 1); // do not keep if warning are excluded
                            break;
                        }
                    }
                }
                if ($flagKeep) {
                    break;
                }
            }
            if (!$flagKeep) {
                return false;
            }
        }

        if ($filterType['warninglistId']) {
            // check if object contains at least one attribute that is part of given warninglist
            $flagKeep = false;
            foreach ($object['Attribute'] as $attribute) {
                if (isset($attribute['warnings'])) {
                    foreach ($attribute['warnings'] as $warning) {
                        if (in_array($warning['warninglist_id'], $filterType['warninglistId'])) {
                            $flagKeep = true;
                            break 2;
                        }
                    }
                }
            }
            if (!$flagKeep) {
                return false;
            }
        }

        if ($filterType['correlationId']) {
            $flagKeep = false;
            // check if object contains at least one attribute that is correlating with given event ID
            foreach ($object['Attribute'] as $attribute) {
                if (isset($correlatedAttributes[$attribute['id']])) {
                    foreach ($correlatedAttributes[$attribute['id']] as $correlation) {
                        if (in_array($correlation['id'], $filterType['correlationId'])) {
                            $flagKeep = true;
                            break 2;
                        }
                    }
                }
                if (!empty($attribute['ShadowAttribute'])) {
                    foreach ($attribute['ShadowAttribute'] as $shadowAttribute) {
                        if (isset($correlatedShadowAttributes[$shadowAttribute['id']])) {
                            foreach ($correlatedShadowAttributes[$shadowAttribute['id']] as $correlation) {
                                if (in_array($correlation['id'], $filterType['correlationId'])) {
                                    $flagKeep = true;
                                    break 2;
                                }
                            }
                        }
                    }
                }
            }
            if (!$flagKeep) {
                return false;
            }
        }

        /* correlation */
        if ($filterType['correlation'] == 0) { // `both`
            // pass, do not consider as `both` is selected
        } else if ($filterType['correlation'] == 1 || $filterType['correlation'] == 2) {
            $flagKeep = false;
            foreach ($object['Attribute'] as $attribute) { // check if object contains at least 1 warning
                if (isset($correlatedAttributes[$attribute['id']])) {
                    $flagKeep = ($filterType['correlation'] == 1); // keep if correlations are included
                } else {
                    $flagKeep = ($filterType['correlation'] == 2); // keep if correlations are excluded
                }
                if (!$flagKeep && !empty($attribute['ShadowAttribute'])) {
                    foreach ($attribute['ShadowAttribute'] as $shadowAttribute) {
                        if (isset($correlatedShadowAttributes[$shadowAttribute['id']])) {
                            $flagKeep = ($filterType['correlation'] == 1); // keep if correlations are included
                            break;
                        }
                    }
                }
                if ($flagKeep) {
                    break;
                }
            }
            if (!$flagKeep) {
                return false;
            }
        }

        /* sighting */
        if ($filterType['sighting'] == 0) { // `both`
            // pass, do not consider as `both` is selected
        } else if ($filterType['sighting'] == 1 || $filterType['sighting'] == 2) {
            $flagKeep = false;
            foreach ($object['Attribute'] as $attribute) { // check if object contains at least 1 warning
                if (isset($sightingsData['data'][$attribute['id']])) {
                    $flagKeep = ($filterType['sighting'] == 1); // keep if server are included
                } else {
                    $flagKeep = ($filterType['sighting'] == 2); // keep if server are excluded
                }
                if (!$flagKeep && !empty($attribute['ShadowAttribute'])) {
                    foreach ($attribute['ShadowAttribute'] as $shadowAttribute) {
                        if (isset($sightingsData['data'][$attribute['id']])) {
                            $flagKeep = ($filterType['sighting'] == 1); // do not keep if server are excluded
                            break;
                        }
                    }
                }
                if ($flagKeep) {
                    break;
                }
            }
            if (!$flagKeep) {
                return false;
            }
        }

        /* feed */
        if ($filterType['feed'] == 0) { // `both`
            // pass, do not consider as `both` is selected
        } else if ($filterType['feed'] == 1 || $filterType['feed'] == 2) {
            $flagKeep = false;
            foreach ($object['Attribute'] as $attribute) { // check if object contains at least 1 warning
                if (!empty($attribute['Feed'])) {
                    $flagKeep = ($filterType['feed'] == 1); // keep if feed are included
                } else {
                    $flagKeep = ($filterType['feed'] == 2); // keep if feed are excluded
                }
                if (!$flagKeep && !empty($attribute['ShadowAttribute'])) {
                    foreach ($attribute['ShadowAttribute'] as $shadowAttribute) {
                        if (!empty($shadowAttribute['Feed'])) {
                            $flagKeep = ($filterType['feed'] == 1); // do not keep if feed are excluded
                            break;
                        }
                    }
                }
                if ($flagKeep) {
                    break;
                }
            }
            if (!$flagKeep) {
                return false;
            }
        }

        /* server */
        if ($filterType['server'] == 0) { // `both`
            // pass, do not consider as `both` is selected
        } else if ($filterType['server'] == 1 || $filterType['server'] == 2) {
            $flagKeep = false;
            foreach ($object['Attribute'] as $attribute) { // check if object contains at least 1 warning
                if (!empty($attribute['Server'])) {
                    $flagKeep = ($filterType['server'] == 1); // keep if server are included
                } else {
                    $flagKeep = ($filterType['server'] == 2); // keep if server are excluded
                }
                if (!$flagKeep && !empty($attribute['ShadowAttribute'])) {
                    foreach ($attribute['ShadowAttribute'] as $shadowAttribute) {
                        if (!empty($shadowAttribute['Server'])) {
                            $flagKeep = ($filterType['server'] == 1); // do not keep if server are excluded
                            break;
                        }
                    }
                }
                if ($flagKeep) {
                    break;
                }
            }
            if (!$flagKeep) {
                return false;
            }
        }
        return true;
    }

    /**
     * @param array $object
     * @return array
     */
    private function __prepareGenericForView($object)
    {
        if ($this->Attribute->isImage($object)) {
            if (!empty($object['data'])) {
                $object['image'] = $object['data'];
            } else {
                if (extension_loaded('gd')) {
                    // if extension is loaded, the data is not passed to the view because it is asynchronously fetched
                    $object['image'] = true; // tell the view that it is an image despite not having the actual data
                } else {
                    if ($object['objectType'] === 'proposal') {
                        $object['image'] = $this->ShadowAttribute->base64EncodeAttachment($object);
                    } else {
                        $object['image'] = $this->Attribute->base64EncodeAttachment($object);
                    }
                }
            }
        }
        if ($object['type'] === 'attachment' && $this->loadAttachmentScan()->isEnabled()) {
            $type = $object['objectType'] === 'attribute' ? AttachmentScan::TYPE_ATTRIBUTE : AttachmentScan::TYPE_SHADOW_ATTRIBUTE;
            $object['infected'] = $this->loadAttachmentScan()->isInfected($type, $object['id']);;
        }
        return $object;
    }

    /**
     * @param array $event
     * @param array $passedArgs
     * @param false $all
     * @param array $sightingsData
     * @return array
     */
    public function rearrangeEventForView(&$event, $passedArgs = array(), $all = false, $sightingsData=array())
    {
        foreach ($event['Event'] as $k => $v) {
            if (is_array($v)) {
                $event[$k] = $v;
                unset($event['Event'][$k]);
            }
        }
        $filterType = array(
            'attributeFilter' => isset($passedArgs['attributeFilter']) ? $passedArgs['attributeFilter'] : 'all',
            'proposal' => isset($passedArgs['proposal']) ? $passedArgs['proposal'] : 0,
            'correlation' => isset($passedArgs['correlation']) ? $passedArgs['correlation'] : 0,
            'warning' => isset($passedArgs['warning']) ? $passedArgs['warning'] : 0,
            'deleted' => isset($passedArgs['deleted']) ? $passedArgs['deleted'] : 0,
            'toIDS' => isset($passedArgs['toIDS']) ? $passedArgs['toIDS'] : 0,
            'sighting' => isset($passedArgs['sighting']) ? $passedArgs['sighting'] : 0,
            'feed' => isset($passedArgs['feed']) ? $passedArgs['feed'] : 0,
            'server' => isset($passedArgs['server']) ? $passedArgs['server'] : 0,
            'warninglistId' => isset($passedArgs['warninglistId']) ? (is_array($passedArgs['warninglistId']) ? $passedArgs['warninglistId'] : [$passedArgs['warninglistId']]) : null,
            'correlationId' => isset($passedArgs['correlationId']) ? (is_array($passedArgs['correlationId']) ? $passedArgs['correlationId'] : [$passedArgs['correlationId']]) : null,
        );
        // update proposal, correlation and warning accordingly
        if (in_array($filterType['attributeFilter'], array('proposal', 'correlation', 'warning'), true)) {
            $filterType[$filterType['attributeFilter']] = 1;
        }

        $correlatedAttributes = isset($event['RelatedAttribute']) ? $event['RelatedAttribute'] : [];
        $correlatedShadowAttributes = isset($event['RelatedShadowAttribute']) ? $event['RelatedShadowAttribute'] : [];
        $objects = array();

        if (isset($event['Attribute'])) {
            foreach ($event['Attribute'] as $attribute) {
                $result = $this->__prepareAttributeForView(
                    $attribute,
                    $correlatedAttributes,
                    $correlatedShadowAttributes,
                    $filterType,
                    $sightingsData
                );
                if ($result) {
                    $objects[] = $result;
                }
            }
            unset($event['Attribute']);
        }

        if (isset($event['ShadowAttribute'])) {
            foreach ($event['ShadowAttribute'] as $proposal) {
                $result = $this->__prepareProposalForView(
                    $proposal,
                    $correlatedShadowAttributes,
                    $filterType
                );
                if ($result) {
                    $objects[] = $result;
                }
            }
            unset($event['ShadowAttribute']);
        }
        if (isset($event['Object'])) {
            foreach ($event['Object'] as $object) {
                $object['objectType'] = 'object';
                $result = $this->__prepareObjectForView(
                    $object,
                    $correlatedAttributes,
                    $correlatedShadowAttributes,
                    $filterType,
                    $sightingsData
                );
                if ($result) {
                    $objects[] = $result;
                }
            }
            unset($event['Object']);
        }

        $referencedByArray = array();
        foreach ($objects as $object) {
            $objectType = $object['objectType'];
            if (($objectType === 'attribute' || $objectType === 'object') && !empty($object['ObjectReference'])) {
                foreach ($object['ObjectReference'] as $reference) {
                    if (isset($reference['referenced_uuid'])) {
                        $referencedByArray[$reference['referenced_uuid']][$objectType][] = array(
                            'meta-category' => $object['meta-category'],
                            'name' => $object['name'],
                            'uuid' => $object['uuid'],
                            'id' => isset($object['id']) ? $object['id'] : 0,
                            'object_type' => $objectType,
                            'relationship_type' => $reference['relationship_type']
                        );
                    }
                }
            }
        }
        App::uses('CustomPaginationTool', 'Tools');
        $customPagination = new CustomPaginationTool();
        if ($all) {
            $passedArgs['page'] = 0;
        }
        $params = $customPagination->applyRulesOnArray($objects, $passedArgs, 'events', 'category');
        $objects = $this->attachAnalystDataToViewObjects($objects);
        foreach ($objects as $k => $object) {
            if (isset($referencedByArray[$object['uuid']])) {
                foreach ($referencedByArray[$object['uuid']] as $objectType => $references) {
                    $objects[$k]['referenced_by'][$objectType] = $references;
                }
            }
        }
        $event['objects'] = $objects;
        $params['total_elements'] = count($objects);
        return $params;
    }

    // take a list of paginated, rearranged objects from the event view generation's viewUI() function
    // collect all attribute and object uuids from the object list
    // fetch the related analyst data and inject them back into the object list
    public function attachAnalystDataToViewObjects($objects)
    {
        $attribute_notes = [];
        $object_notes = [];
        foreach ($objects as $k => $object) {
            if ($object['objectType'] === 'object') {
                $object_notes[] = $object['uuid'];
                foreach ($object['Attribute'] as $a) {
                    $attribute_notes[] = $a['uuid'];
                }
            } else if ($object['objectType'] === 'attribute') {
                $attribute_notes[] = $object['uuid'];
            }
        }
        $attribute_notes = $this->Attribute->fetchAnalystDataBulk($attribute_notes);
        $object_notes = $this->Object->fetchAnalystDataBulk($object_notes);
        foreach ($objects as $k => $object) {
            if ($object['objectType'] === 'object') {
                if (!empty($object_notes[$object['uuid']])) {
                    $objects[$k] = array_merge($object, $object_notes[$object['uuid']]);
                }
                foreach ($object['Attribute'] as $k2 => $a) {
                    if (!empty($attribute_notes[$a['uuid']])) {
                        $objects[$k]['Attribute'][$k2] = array_merge($a, $attribute_notes[$a['uuid']]);
                    }
                }
            } else if ($object['objectType'] === 'attribute') {
                if (!empty($attribute_notes[$object['uuid']])) {
                    $objects[$k] = array_merge($object, $attribute_notes[$object['uuid']]);
                }
            }
        }
        return $objects;
    }

    // pass along a json from the server filter rules
    // returns a conditions set to be merged into pagination / event fetch / etc
    public function filterRulesToConditions($rules)
    {
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
            if (!empty($rules[$k]['OR'])) {
                $temp['OR'][$field] = $rules[$k]['OR'];
            }
            if (!empty($rules[$k]['NOT'])) {
                $temp['AND'][$field . ' !='] = $rules[$k]['NOT'];
            }
            $conditions['AND'][] = $temp;
        }
        return $conditions;
    }

    public function fetchInitialObject($event_id, $object_id)
    {
        $initial_object = $this->Object->find('first', array(
            'conditions' => array('Object.id' => $object_id,
                                  'Object.event_id' => $event_id,
                                  'Object.deleted' => 0),
            'recursive' => -1,
            'fields' => array('Object.id', 'Object.uuid', 'Object.name', 'Object.distribution', 'Object.sharing_group_id')
        ));
        if (!empty($initial_object)) {
            $initial_attributes = $this->Attribute->find('all', array(
                'conditions' => array('Attribute.object_id' => $object_id,
                                      'Attribute.deleted' => 0),
                'recursive' => -1,
                'fields' => array('Attribute.id', 'Attribute.uuid', 'Attribute.type',
                                  'Attribute.object_relation', 'Attribute.value')
            ));
            if (!empty($initial_attributes)) {
                $initial_object['Attribute'] = array();
                foreach ($initial_attributes as $initial_attribute) {
                    array_push($initial_object['Attribute'], $initial_attribute['Attribute']);
                }
            }
            $initial_references = $this->Object->ObjectReference->find('all', array(
                'conditions' => array('ObjectReference.object_id' => $object_id,
                                      'ObjectReference.event_id' => $event_id,
                                      'ObjectReference.deleted' => 0),
                'recursive' => -1,
                'fields' => array('ObjectReference.referenced_uuid', 'ObjectReference.relationship_type')
            ));
            if (!empty($initial_references)) {
                $initial_object['ObjectReference'] = array();
                foreach ($initial_references as $initial_reference) {
                    array_push($initial_object['ObjectReference'], $initial_reference['ObjectReference']);
                }
            }
        }
        return $initial_object;
    }

    public function handleModuleResult($result, $event_id)
    {
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
                        if (is_array($value)) {
                            $value = json_encode($value);
                        }
                        $this->Warninglist = ClassRegistry::init('Warninglist');
                        $complexTypeTool->setTLDs($this->Warninglist->fetchTLDLists());
                        $complexTypeTool->setSecurityVendorDomains($this->Warninglist->fetchSecurityVendorDomains());
                        $freetextResults = array_merge($freetextResults, $complexTypeTool->checkFreeText($value));
                        if (!empty($freetextResults)) {
                            foreach ($freetextResults as &$ft) {
                                $temp = array();
                                foreach ($ft['types'] as $type) {
                                    $temp[$type] = $type;
                                }
                                $ft['event_id'] = $event_id;
                                $ft['types'] = $temp;
                                $ft['comment'] = isset($r['comment']) ? $r['comment'] : false;
                            }
                        }
                        $r['types'] = array_diff($r['types'], array('freetext'));
                        // if we just removed the only type in the result then more on to the next result
                        if (empty($r['types'])) {
                            continue 2;
                        }
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
                    if (isset($r['data'])) {
                        $temp['data'] = $r['data'];
                    }
                    if (isset($r['distribution'])) {
                        $temp['distribution'] = $r['distribution'];
                    }
                    // if data_is_handled is set then MISP assumes that the sample is already zipped and encrypted
                    // in this case it will not try to do this by itself - however it also won't create additional hashes
                    if (isset($r['data_is_handled'])) {
                        $temp['data_is_handled'] = $r['data_is_handled'];
                    }
                    $resultArray[] = $temp;
                }
            }
            $resultArray = array_merge($resultArray, $freetextResults);
        }
        return $resultArray;
    }

    /**
     * @param array $result
     * @return array
     */
    public function handleMispFormatFromModuleResult(&$result)
    {
        $defaultDistribution = $this->Attribute->defaultDistribution();
        $event = array();
        if (!empty($result['results']['Attribute'])) {
            $attributes = array();
            foreach ($result['results']['Attribute'] as &$tmp_attribute) {
                $tmp_attribute = $this->__fillAttribute($tmp_attribute, $defaultDistribution);
                $attributes[] = $tmp_attribute;
            }
            $event['Attribute'] = $attributes;
        }
        if (!empty($result['results']['Object'])) {
            $objects = array();
            foreach ($result['results']['Object'] as $tmp_object) {
                $tmp_object['distribution'] = (isset($tmp_object['distribution']) ? (int)$tmp_object['distribution'] : $defaultDistribution);
                $tmp_object['sharing_group_id'] = (isset($tmp_object['sharing_group_id']) ? (int)$tmp_object['sharing_group_id'] : 0);
                if (!empty($tmp_object['Attribute'])) {
                    foreach ($tmp_object['Attribute'] as &$tmp_attribute) {
                        $tmp_attribute = $this->__fillAttribute($tmp_attribute, $defaultDistribution);
                    }
                }
                $objects[] = $tmp_object;
            }
            $event['Object'] = $objects;
        }
        if (!empty($result['results']['EventReport'])) {
            $event['EventReport'] = $result['results']['EventReport'];
        }
        foreach (array('Tag', 'Galaxy') as $field) {
            if (!empty($result['results'][$field])) {
                $event[$field] = $result['results'][$field];
            }
        }
        return $event;
    }

    /**
     * @param array $attribute
     * @param int $defaultDistribution
     * @return array
     */
    private function __fillAttribute($attribute, $defaultDistribution)
    {
        if (is_array($attribute['type'])) {
            $attribute_type = $attribute['type'][0];
            if (empty($attribute['category'])) {
                $categories = array();
                foreach ($attribute['type'] as $type) {
                    $category = $this->Attribute->typeDefinitions[$type]['default_category'];
                    if (!in_array($category, $categories)) {
                        $categories[] = $category;
                    }
                }
                $attribute['category'] = count($categories) === 1 ? $categories[0] : $categories;
            }
        } else {
            $attribute_type = $attribute['type'];
            if (empty($attribute['category'])) {
                $attribute['category'] = $this->Attribute->typeDefinitions[$attribute_type]['default_category'];
            }
        }
        if (!isset($attribute['to_ids'])) {
            $attribute['to_ids'] = $this->Attribute->typeDefinitions[$attribute_type]['to_ids'];
        }
        $attribute['value'] = $this->Attribute->runRegexp($attribute['type'], $attribute['value']);
        $attribute['distribution'] = (isset($attribute['distribution']) ? (int)$attribute['distribution'] : $defaultDistribution);
        $attribute['sharing_group_id'] = (isset($attribute['sharing_group_id']) ? (int)$attribute['sharing_group_id'] : 0);
        return $attribute;
    }

    /**
     * @param array $user
     * @param string $module
     * @param array $options
     * @return array
     * @throws Exception
     */
    public function export(array $user, $module, array $options = array())
    {
        if (empty($module)) {
            throw new InvalidArgumentException('Invalid module.');
        }
        $this->Module = ClassRegistry::init('Module');
        $module = $this->Module->getEnabledModule($module, 'Export');
        if (!is_array($module)) {
            throw new NotFoundException('Invalid module.');
        }
        // Export module can specify additional options for event fetch
        if (isset($module['meta']['fetch_options'])) {
            $options = array_merge($options, $module['meta']['fetch_options']);
        }
        $events = $this->fetchEvent($user, $options);
        if (empty($events)) {
            throw new NotFoundException('Invalid event.');
        }
        $modulePayload = array('module' => $module['name']);
        if (isset($module['meta']['config'])) {
            foreach ($module['meta']['config'] as $conf) {
                $modulePayload['config'][$conf] = Configure::read('Plugin.Export_' . $module['name'] . '_' . $conf);
            }
        }
        $standard_format = !empty($module['meta']['require_standard_format']);
        if ($standard_format) {
            App::uses('JSONConverterTool', 'Tools');
            foreach ($events as $k => $event) {
                $events[$k] = JSONConverterTool::convert($event, false, true);
            }
        }
        $modulePayload['data'] = $events;
        $result = $this->Module->queryModuleServer($modulePayload, false, 'Export');
        return [
            'data' => $result['data'],
            'extension' => $module['mispattributes']['outputFileExtension'],
            'response' => $module['mispattributes']['responseType']
        ];
    }

    public function __cacheSharingGroupData($user, $useCache = false)
    {
        if ($useCache && isset($this->assetCache['sharingGroupData'])) {
            return $this->assetCache['sharingGroupData'];
        } else {
            $sharingGroupDataTemp = $this->SharingGroup->fetchAllAuthorised($user, 'simplified');
            $sharingGroupData = array();
            foreach ($sharingGroupDataTemp as $v) {
                if (isset($v['Organisation'])) {
                    $v['SharingGroup']['Organisation'] = $v['Organisation'];
                }
                if (isset($v['SharingGroupOrg'])) {
                    $v['SharingGroup']['SharingGroupOrg'] = $v['SharingGroupOrg'];
                }
                if (isset($v['SharingGroupServer'])) {
                    $v['SharingGroup']['SharingGroupServer'] = $v['SharingGroupServer'];
                    foreach ($v['SharingGroup']['SharingGroupServer'] as &$sgs) {
                        if ($sgs['server_id'] == 0) {
                            $sgs['Server'] = array(
                                'id' => '0',
                                'url' => $this->__getAnnounceBaseurl(),
                                'name' => $this->__getAnnounceBaseurl()
                            );
                        }
                    }
                }
                $sharingGroupData[$v['SharingGroup']['id']] = $v['SharingGroup'];
            }
            if ($useCache) {
                $this->assetCache['sharingGroupData'] = $sharingGroupData;
            }
            return $sharingGroupData;
        }
    }

    private function __cachedelegatedEventIDs($user, $useCache = false)
    {
        if ($useCache && isset($this->assetCache['delegatedEventIDs'])) {
            return $this->assetCache['delegatedEventIDs'];
        } else {
            $this->EventDelegation = ClassRegistry::init('EventDelegation');
            $delegatedEventIDs = $this->EventDelegation->find('list', array(
                'conditions' => array('EventDelegation.org_id' => $user['org_id']),
                'fields' => array('event_id')
            ));
            if ($useCache) {
                $this->assetCache['delegationEventIDs'] = $delegatedEventIDs;
            }
            return $delegatedEventIDs;
        }
    }

    private function __generateCachedTagFilters($tagRules, $useCache = false)
    {
        if ($useCache && isset($this->assetCache['tagFilters'])) {
            return $this->assetCache['tagFilters'];
        } else {
            $filters = array();
            $args = $this->Attribute->dissectArgs($tagRules);
            $tagArray = $this->EventTag->fetchEventTagIds($args[0], $args[1]);
            if (!empty($tagArray[0])) {
                $filters[] = ['OR' => ['Event.id' => $tagArray[0]]];
            } else {
                $filters[] = ['AND' => ['Event.id NOT IN' => $tagArray[1]]];
            }
            if ($useCache) {
                $this->assetCache['tagFilters'] = $filters;
            }
            return $filters;
        }
    }

    /**
     * @param int|array $eventOrEventId Event ID or event array
     * @param bool $proposalLock
     * @param int|null $timestamp If not provided, current time will be used
     * @return array|bool|mixed|null
     * @throws Exception
     */
    public function unpublishEvent($eventOrEventId, $proposalLock = false, $timestamp = null)
    {
        if (is_array($eventOrEventId)) {
            $event = $eventOrEventId;
            if (!isset($event['Event']['id'])) {
                throw new InvalidArgumentException('Invalid event array provided.');
            }
        } else {
            $event = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('Event.id' => $eventOrEventId)
                //'fields' => ['id', 'info'], // info is required because of SysLogLogableBehavior
            ));
            if (empty($event)) {
                return false;
            }
        }

        $fields = ['published', 'timestamp'];
        $event['Event']['published'] = 0;
        $event['Event']['timestamp'] = $timestamp ?: time();
        if ($proposalLock) {
            $event['Event']['proposal_email_lock'] = 0;
            $fields[] = 'proposal_email_lock';
        }
        $event['Event']['unpublishAction'] = true;
        return $this->save($event, true, $fields);
    }

    /**
     * @param array $user
     * @param string $file Path
     * @param string $stixVersion
     * @param string $originalFile
     * @param bool $publish
     * @param int $distribution
     * @param int|null $sharingGroupId
     * @param bool $galaxiesAsTags
     * @param int $clusterDistribution
     * @param int|null $clusterSharingGroupId
     * @param bool $debug
     * @return int|string|array
     * @throws JsonException
     * @throws InvalidArgumentException
     * @throws Exception
     */
    public function upload_stix(array $user, $file, $stixVersion, $originalFile, $publish, $distribution, $sharingGroupId, $galaxiesAsTags, $clusterDistribution, $clusterSharingGroupId, $debug = false)
    {
        $decoded = $this->convertStixToMisp($stixVersion, $file, $distribution, $sharingGroupId, $galaxiesAsTags, $clusterDistribution, $clusterSharingGroupId, $user['Organisation']['uuid'], $debug);

        if (!empty($decoded['success'])) {
            $data = JsonTool::decodeArray($decoded['converted']);
            if (empty($data['Event'])) {
                $data = array('Event' => $data);
            }
            if (!$galaxiesAsTags) {
                if (!isset($this->GalaxyCluster)) {
                    $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
                }
                $this->__handleGalaxiesAndClusters($user, $data['Event']);
                if (!empty($data['Event']['Attribute'])) {
                    foreach ($data['Event']['Attribute'] as &$attribute) {
                        $this->__handleGalaxiesAndClusters($user, $attribute);
                    }
                }
                if (!empty($data['Event']['Object'])) {
                    foreach ($data['Event']['Object'] as &$misp_object) {
                        if (!empty($misp_object['Attribute'])) {
                            foreach ($misp_object['Attribute'] as &$attribute) {
                                $this->__handleGalaxiesAndClusters($user, $attribute);
                            }
                        }
                    }
                }
            }
            $stixVersion = $decoded['stix_version'];
            $created_id = false;
            $validationIssues = false;
            $result = $this->_add($data, true, $user, '', null, false, null, $created_id, $validationIssues);
            if ($result === true) {
                if ($originalFile) {
                    $this->add_original_file($decoded['original'], $originalFile, $created_id, $stixVersion);
                }
                if ($publish && $user['Role']['perm_publish']) {
                    if (!Configure::read('MISP.block_publishing_for_same_creator', false) || $user['Role']['perm_sync']) {
                        $this->publish($created_id);
                    }
                }
                return $created_id;
            } else if (is_numeric($result)) {
                return __('Event with the same UUID already exists.');
            } else if (is_string($result)) {
                return $result;
            }
            return $validationIssues;
        }
        $response = __($decoded['error']);
        if (!$user['Role']['perm_site_admin']) {
            $response .= ' ' . __('Please ask your administrator to');
        } else {
            $response .= ' '  . __('Please');
        }
        $response .= ' ' . __('check whether the dependencies for STIX are met via the diagnostic tool.');
        return $response;
    }

    /**
     * @param string $stixVersion
     * @param string $file Path to STIX file
     * @param int $distribution
     * @param int|null $sharingGroupId
     * @param bool $galaxiesAsTags
     * @param int $clusterDistribution
     * @param int|null $clusterSharingGroupId
     * @param string $orgUuid
     * @param bool $debug
     * @return array
     * @throws Exception
     */
    private function convertStixToMisp($stixVersion, $file, $distribution, $sharingGroupId, $galaxiesAsTags, $clusterDistribution, $clusterSharingGroupId, $orgUuid, $debug)
    {
        $scriptDir = APP . 'files' . DS . 'scripts';
        if ($stixVersion === '2' || $stixVersion === '2.0' || $stixVersion === '2.1') {
            $scriptFile = $scriptDir . DS . 'stix2' . DS . 'stix2misp.py';
            $outputPath = $file . '.out';
            $shellCommand = [
                ProcessTool::pythonBin(),
                $scriptFile,
                '-i', $file,
                '--distribution', $distribution,
                '--org_uuid', $orgUuid
            ];
            if ($distribution == 4) {
                array_push($shellCommand, '--sharing_group_id', $sharingGroupId);
            }
            if ($galaxiesAsTags) {
                $shellCommand[] = '--galaxies_as_tags';
            } else {
                array_push($shellCommand, '--cluster_distribution', $clusterDistribution);
                if ($clusterDistribution == 4) {
                    array_push($shellCommand, '--cluster_sharing_group_id', $clusterSharingGroupId);
                }
            }
            if ($debug) {
                $shellCommand[] = '--debug';
            }
            $stixVersion = "STIX 2.1";
        } else if ($stixVersion === '1' || $stixVersion === '1.1' || $stixVersion === '1.2') {
            $scriptFile = $scriptDir . DS . 'stix2misp.py';
            $outputPath = $file . '.json';
            $shellCommand = [
                ProcessTool::pythonBin(),
                $scriptFile,
                $file,
                Configure::read('MISP.default_event_distribution'),
                Configure::read('MISP.default_attribute_distribution'),
                $this->__getTagNamesFromSynonyms($scriptDir)
            ];
            $stixVersion = "STIX 1.1";
        } else {
            throw new InvalidArgumentException('Invalid STIX version');
        }

        try {
            $stdout = ProcessTool::execute($shellCommand, null, true);
        } catch (ProcessException $e) {
            $this->logException("Could not import $stixVersion file $file", $e);
            $stdout = $e->stdout();
        }

        $stdout = preg_split("/\r\n|\n|\r/", trim($stdout));
        $stdout = trim(end($stdout));
        $decoded = JsonTool::decode($stdout);

        if (empty($decoded['stix_version'])) {
            $decoded['stix_version'] = $stixVersion;
        }

        $decoded['original'] = FileAccessTool::readAndDelete($file);
        if (!empty($decoded['success'])) {
            $decoded['converted'] = FileAccessTool::readAndDelete($outputPath);
        }

        return $decoded;
    }

    private function __handleGalaxiesAndClusters($user, &$data)
    {
        if (!empty($data['Galaxy'])) {
            $tag_names = $this->GalaxyCluster->convertGalaxyClustersToTags($user, $data['Galaxy']);
            if (empty($data['Tag'])) {
                $data['Tag'] = [];
            }
            foreach ($tag_names as $tag_name) {
                $data['Tag'][] = array('name' => $tag_name);
            }
        }
    }

    /**
     * @param string $scriptDir
     * @return string
     * @throws Exception
     */
    private function __getTagNamesFromSynonyms($scriptDir)
    {
        $synonymsToTagNames = $scriptDir . DS . 'tmp' . DS . 'synonymsToTagNames.json';
        if (!file_exists($synonymsToTagNames) || (time() - filemtime($synonymsToTagNames)) > 600) {
            if (!isset($this->GalaxyCluster)) {
                $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
            }
            $clusters = $this->GalaxyCluster->find('all', array(
                'recursive' => -1,
                'fields' => array(
                    'GalaxyCluster.value',
                    'MAX(GalaxyCluster.version)',
                    'GalaxyCluster.tag_name',
                    'GalaxyCluster.id'
                ),
                'group' => array('GalaxyCluster.tag_name')
            ));
            $synonyms = $this->GalaxyCluster->GalaxyElement->find('all', array(
                'recursive' => -1,
                'fields' => array('galaxy_cluster_id', 'value'),
                'conditions' => array('key' => 'synonyms')
            ));
            $idToSynonyms = array();
            foreach ($synonyms as $synonym) {
                $idToSynonyms[$synonym['GalaxyElement']['galaxy_cluster_id']][] = $synonym['GalaxyElement']['value'];
            }
            $mapping = array();
            foreach ($clusters as $cluster) {
                $mapping[$cluster['GalaxyCluster']['value']][] = $cluster['GalaxyCluster']['tag_name'];
                if (!empty($idToSynonyms[$cluster['GalaxyCluster']['id']])) {
                    foreach ($idToSynonyms[$cluster['GalaxyCluster']['id']] as $synonym) {
                        $mapping[$synonym][] = $cluster['GalaxyCluster']['tag_name'];
                    }
                }
            }
            FileAccessTool::writeToFile($synonymsToTagNames, JsonTool::encode($mapping));
        }
        return $synonymsToTagNames;
    }

    public function enrichmentRouter($options)
    {
        $result = $this->enrichment($options);
        return __('#' . $result . ' attributes have been created during the enrichment process.');
        if (Configure::read('MISP.background_jobs')) {

            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob(
                $options['user'],
                Job::WORKER_PRIO,
                'enrichment',
                'Event ID: ' . $options['event_id'] . ' modules: ' . json_encode($options['modules']),
                'Enriching event.'
            );

            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::PRIO_QUEUE,
                BackgroundJobsTool::CMD_EVENT,
                [
                    'enrichment',
                    $options['user']['id'],
                    $options['event_id'],
                    json_encode($options['modules']),
                    $jobId
                ],
                true,
                $jobId
            );

            return true;
        } else {
            $result = $this->enrichment($options);
            return __('#' . $result . ' attributes have been created during the enrichment process.');
        }
    }

    public function enrichment(array $params)
    {
        $option_fields = array('user', 'event_id', 'modules');
        foreach ($option_fields as $option_field) {
            if (empty($params[$option_field])) {
                throw new MethodNotAllowedException(__('%s not set', $option_field));
            }
        }
        if (!empty($params['attribute_uuids'])) {
            $attributes = $this->Attribute->fetchAttributes($params['user'], [
                'conditions' => [
                    'Attribute.uuid' => $params['attribute_uuids'],
                ],
                'withAttachments' => 1,
            ]);
            $event = [
                [
                    'Event' => ['id' => $params['event_id']],
                    'Attribute' => Hash::extract($attributes, '{n}.Attribute')
                ]
            ];
        } else {
            $event = $this->fetchEvent($params['user'], [
                'eventid' => $params['event_id'],
                'includeAttachments' => 1,
                'flatten' => 1,
            ]);
            if (empty($event)) {
                throw new MethodNotAllowedException('Invalid event.');
            }
        }

        $this->Module = ClassRegistry::init('Module');
        $enabledModules = $this->Module->getEnabledModules($params['user']);
        if (empty($enabledModules) || is_string($enabledModules)) {
            return true;
        }
        foreach ($enabledModules['modules'] as $k => $temp) {
            if (isset($temp['meta']['config'])) {
                $settings = array();
                foreach ($temp['meta']['config'] as $conf) {
                    $settings[$conf] = Configure::read('Plugin.Enrichment_' . $temp['name'] . '_' . $conf);
                }
                $enabledModules['modules'][$k]['config'] = $settings;
            }
        }

        $attributes_added = 0;
        $initial_objects = array();
        $event_id = $event[0]['Event']['id'];
        foreach ($event[0]['Attribute'] as $attribute) {
            $object_id = $attribute['object_id'];
            if ($object_id != '0' && empty($initial_objects[$object_id])) {
                $initial_objects[$object_id] = $this->fetchInitialObject($event_id, $object_id);
            }
            foreach ($enabledModules['modules'] as $module) {
                if (in_array($module['name'], $params['modules'])) {
                    if (in_array($attribute['type'], $module['mispattributes']['input'])) {
                        $data = array('module' => $module['name'], 'event_id' => $event_id, 'attribute_uuid' => $attribute['uuid']);
                        if (!empty($module['config'])) {
                            $data['config'] = $module['config'];
                        }
                        if (!empty($module['mispattributes']['format']) && $module['mispattributes']['format'] === 'misp_standard') {
                            $data['attribute'] = $attribute;
                        } else {
                            $data[$attribute['type']] = $attribute['value'];
                        }
                        if ($object_id != '0' && !empty($initial_objects[$object_id])) {
                            $attribute['Object'] = $initial_objects[$object_id]['Object'];
                        }
                        $triggerData = $event[0];
                        $triggerData['Attribute'] = [$attribute];
                        $result = $this->Module->queryModuleServer($data, false, 'Enrichment', false, $triggerData);
                        if ($result === false) {
                            throw new MethodNotAllowedException(h($module['name']) . ' service not reachable.');
                        } else if (!is_array($result)) {
                            continue 2;
                        } else if (!isset($result['results'])) {
                            throw new RuntimeException("Invalid response received from module {$module['name']}, response data do not contains results field.");
                        }
                        //if (isset($result['error'])) $this->Session->setFlash($result['error']);
                        if (!empty($module['mispattributes']['format']) && $module['mispattributes']['format'] === 'misp_standard') {
                            if ($object_id != '0' && !empty($initial_objects[$object_id])) {
                                $result['initialObject'] = $initial_objects[$object_id];
                            }
                            $default_comment = $attribute['value'] . ': enriched via the ' . $module['name'] . ' module.';
                            $attributes_added += $this->processModuleResultsData($params['user'], $result['results'], $event_id, $default_comment, false, false, true);
                        } else {
                            $attributes = $this->handleModuleResult($result, $event_id);
                            foreach ($attributes as $a) {
                                $this->Attribute->create();
                                $a['distribution'] = $attribute['distribution'];
                                $a['sharing_group_id'] = $attribute['sharing_group_id'];
                                $comment = 'Attribute #' . $attribute['id'] . ' enriched by ' . $module['name'] . '.';
                                if (!empty($a['comment'])) {
                                    $a['comment'] .= PHP_EOL . $comment;
                                } else {
                                    $a['comment'] = $comment;
                                }
                                $a['type'] = empty($a['default_type']) ? $a['types'][0] : $a['default_type'];
                                $result = $this->Attribute->save($a);
                                if ($result) {
                                    $attributes_added++;
                                }
                            }
                        }
                    }
                }
            }
        }
        return $attributes_added;
    }

    /**
     * @param array $user
     * @param array $data
     * @param string $dataType
     * @param bool $excludeGalaxy
     * @param bool $cullGalaxyTags
     * @return array
     */
    public function massageTags(array $user, array $data, $dataType = 'Event', $excludeGalaxy = false, $cullGalaxyTags = false)
    {
        $data['Galaxy'] = array();

        // unset empty event tags that got added because the tag wasn't exportable
        if (!empty($data[$dataType . 'Tag'])) {
            if (!isset($this->GalaxyCluster)) {
                $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
            }
            foreach ($data[$dataType . 'Tag'] as $k => &$dataTag) {
                if (empty($dataTag['Tag'])) {
                    unset($data[$dataType . 'Tag'][$k]);
                    continue;
                }
                $dataTag['Tag']['local'] = empty($dataTag['local']) ? false : true;
                if (!isset($excludeGalaxy) || !$excludeGalaxy) {
                    if (str_starts_with($dataTag['Tag']['name'], 'misp-galaxy:')) {
                        $cluster = $this->GalaxyCluster->getCluster($dataTag['Tag']['name'], $user);
                        if ($cluster) {
                            $found = false;
                            $cluster['GalaxyCluster']['local'] = $dataTag['local'] ?? false;
                            $cluster['GalaxyCluster'][strtolower($dataType) . '_tag_id'] = $dataTag['id'];
                            foreach ($data['Galaxy'] as $j => $galaxy) {
                                if ($galaxy['id'] == $cluster['GalaxyCluster']['Galaxy']['id']) {
                                    $found = true;
                                    $temp = $cluster;
                                    unset($temp['GalaxyCluster']['Galaxy']);
                                    $data['Galaxy'][$j]['GalaxyCluster'][] = $temp['GalaxyCluster'];
                                    break;
                                }
                            }
                            if (!$found) {
                                $data['Galaxy'][] = $cluster['GalaxyCluster']['Galaxy'];
                                $temp = $cluster;
                                unset($temp['GalaxyCluster']['Galaxy']);
                                $data['Galaxy'][count($data['Galaxy']) - 1]['GalaxyCluster'][] = $temp['GalaxyCluster'];
                            }
                            if ($cullGalaxyTags) {
                                unset($data[$dataType . 'Tag'][$k]);
                            }
                        }
                    }
                }
            }
            $data[$dataType . 'Tag'] = array_values($data[$dataType . 'Tag']);
        }
        return $data;
    }

    public function insertLock($user, $id)
    {
        $eventLock = ClassRegistry::init('EventLock');
        $eventLock->insertLock($user, $id);
    }

    /**
     * @param array $server
     * @param array $event
     * @param mixed $newTextBody
     * @throws Exception
     */
    private function __logUploadResult(array $server, array $event, $newTextBody)
    {
        if (!is_string($newTextBody)) {
            $newTextBody = JsonTool::encode($newTextBody);
        }

        $title = 'Uploading Event (' . $event['Event']['id'] . ') to Server (' . $server['Server']['id'] . ')';
        $change = 'Returned message: ' . $newTextBody;

        $this->loadLog()->createLogEntry('SYSTEM', 'warning', 'Server', $server['Server']['id'], $title, $change);
    }

    /**
     * @param array $user
     * @param array $attributes
     * @param int $id Event ID
     * @param string $default_comment
     * @param bool $proposals
     * @param bool $adhereToWarninglists
     * @param int|false $jobId
     * @param bool $returnRawResults
     * @return array|false|string
     * @throws Exception
     */
    public function processFreeTextData(array $user, $attributes, $id, $default_comment = '', $proposals = false, $adhereToWarninglists = false, $jobId = false, $returnRawResults = false)
    {
        $event = $this->find('first', array(
            'conditions' => array('id' => $id),
            'recursive' => -1,
            'fields' => ['Event.id', 'Event.uuid', 'Event.distribution', 'Event.org_id', 'Event.orgc_id', 'Event.sharing_group_id', 'Event.disable_correlation'],
        ));
        if (empty($event)) {
            return false;
        }
        $results = array();
        $objectType = $proposals ? 'ShadowAttribute' : 'Attribute';
        /** @var Model $model */
        $model = $this->$objectType;

        if ($adhereToWarninglists) {
            $this->Warninglist = ClassRegistry::init('Warninglist');
        }
        $saved = 0;
        $failed = 0;
        $attributeSources = array('attributes', 'ontheflyattributes');
        $ontheflyattributes = array();
        $i = 0;
        if ($jobId) {
            /** @var EventLock $eventLock */
            $eventLock = ClassRegistry::init('EventLock');
            $eventLock->insertLockBackgroundJob($event['Event']['id'], $jobId);

            $this->Job = ClassRegistry::init('Job');
            $total = count($attributeSources);
        }
        foreach ($attributeSources as $source) {
            foreach (${$source} as $attribute) {
                if ($attribute['type'] === 'ip-src/ip-dst') {
                    $types = array('ip-src', 'ip-dst');
                } elseif ($attribute['type'] === 'ip-src|port/ip-dst|port') {
                    $types = array('ip-src|port', 'ip-dst|port');
                } elseif ($attribute['type'] === 'malware-sample') {
                    if (!isset($attribute['data_is_handled']) || !$attribute['data_is_handled']) {
                        $result = $this->Attribute->handleMaliciousBase64($id, $attribute['value'], $attribute['data'], array('md5', 'sha1', 'sha256'), $objectType === 'ShadowAttribute' ? true : false);
                        if (!$result['success']) {
                            $failed++;
                            continue;
                        }
                        $attribute['data'] = $result['data'];
                        $shortValue = $attribute['value'];
                        $attribute['value'] = $shortValue . '|' . $result['md5'];
                        $additionalHashes = array('sha1', 'sha256');
                        foreach ($additionalHashes as $hash) {
                            $temp = $attribute;
                            $temp['type'] = 'filename|' . $hash;
                            $temp['value'] = $shortValue . '|' . $result[$hash];
                            unset($temp['data']);
                            $ontheflyattributes[] = $temp;
                        }
                    }
                    $types = array($attribute['type']);
                } else {
                    $types = array($attribute['type']);
                }
                foreach ($types as $type) {
                    $model->create();
                    $attribute['type'] = $type;
                    if (empty($attribute['comment'])) {
                        $attribute['comment'] = $default_comment;
                    }
                    $attribute['event_id'] = $id;
                    if ($objectType === 'ShadowAttribute') {
                        $attribute['org_id'] = $user['org_id'];
                        $attribute['event_org_id'] = $event['Event']['orgc_id'];
                        $attribute['email'] = $user['email'];
                        $attribute['event_uuid'] = $event['Event']['uuid'];
                    }
                    // adhere to the warninglist
                    if ($adhereToWarninglists) {
                        if (!$this->Warninglist->filterWarninglistAttribute($attribute)) {
                            if ($adhereToWarninglists === 'soft') {
                                $attribute['to_ids'] = 0;
                            } else {
                                // just ignore the attribute
                                continue;
                            }
                        }
                    }
                    $saved_attribute = $model->save($attribute, ['parentEvent' => $event]);
                    if ($saved_attribute) {
                        $results[] = $saved_attribute;
                        // If Tags, attach each tags to attribute
                        if (!empty($attribute['tags'])) {
                            foreach (explode(",", $attribute['tags']) as $tagName) {
                                $tagId = $this->Attribute->AttributeTag->Tag->captureTag(array('name' => trim($tagName)), $user);
                                if ($tagId === false) {
                                    continue;  // user don't have permission to use that tag
                                }
                                if (!$this->Attribute->AttributeTag->attachTagToAttribute($saved_attribute['Attribute']['id'], $id, $tagId)) {
                                    throw new MethodNotAllowedException(__('Could not add tags.'));
                                }
                            }
                        }
                        $saved++;
                    } else {
                        $lastError = $model->validationErrors;
                        $failed++;
                    }
                }
                if ($jobId) {
                    if ($i % 20 === 0) {
                        $this->Job->saveProgress($jobId, 'Attribute ' . $i . '/' . $total, $i * 80 / $total);
                    }
                }
            }
        }
        $emailResult = '';
        $messageScope = $objectType === 'ShadowAttribute' ? 'proposals' : 'attributes';
        if ($saved > 0) {
            if ($objectType !== 'ShadowAttribute') {
                $this->unpublishEvent($id);
            } else {
                if (!$this->ShadowAttribute->sendProposalAlertEmail($id)) {
                    $emailResult = " but sending out the alert e-mails has failed for at least one recipient";
                }
            }
        }
        $messageScopeSaved = $this->__apply_inflector($saved, $messageScope);
        if ($failed > 0) {
            if ($failed == 1) {
                $messageScopeFailed = Inflector::singularize($messageScope);
                $message = $saved . ' ' . $messageScopeSaved . ' created' . $emailResult . '. ' . $failed . ' ' . $messageScopeFailed . ' could not be saved. Reason for the failure: ' . json_encode($lastError);
            } else {
                $message = $saved . ' ' . $messageScopeSaved . ' created' . $emailResult . '. ' . $failed . ' ' . $messageScope . ' could not be saved. This may be due to attributes with similar values already existing.';
            }
        } else {
            $message = $saved . ' ' . $messageScopeSaved . ' created' . $emailResult . '.';
        }
        if ($jobId) {
            $eventLock->deleteBackgroundJobLock($event['Event']['id'], $jobId);
            $this->Job->saveStatus($jobId, true, __('Processing complete. %s', $message));
        }
        if (!empty($returnRawResults)) {
            return $results;
        }
        return $message;
    }

    /**
     * @param array $user
     * @param array $resolved_data
     * @param int $id
     * @param string $default_comment
     * @param int|false $jobId
     * @param bool $adhereToWarninglists
     * @param bool $event_level
     * @return int|string
     * @throws JsonException
     */
    public function processModuleResultsData(array $user, $resolved_data, $id, $default_comment = '', $jobId = false, $adhereToWarninglists = false, $event_level = false)
    {
        $event = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['id' => $id],
        ]);
        if (empty($event)) {
            throw new Exception("Event with ID `$id` not found.");
        }
        if ($jobId) {
            $this->Job = ClassRegistry::init('Job');
            $this->Job->id = $jobId;

            /** @var EventLock $eventLock */
            $eventLock = ClassRegistry::init('EventLock');
            $eventLock->insertLockBackgroundJob($event['Event']['id'], $jobId);
        }
        $failed_attributes = $failed_objects = $failed_object_attributes = $failed_reports = 0;
        $saved_attributes = $saved_objects = $saved_object_attributes = $saved_reports = 0;
        $items_count = 0;
        $failed = array();
        $recovered_uuids = array();
        foreach (array('Attribute', 'Object', 'EventReport') as $feature) {
            if (isset($resolved_data[$feature])) {
                $items_count += count($resolved_data[$feature]);
            }
        }
        if (!empty($resolved_data['Tag'])) {
            foreach ($resolved_data['Tag'] as $tag) {
                $tag_id = $this->EventTag->Tag->captureTag($tag, $user);
                if ($tag_id) {
                    $tag['id'] = $tag_id;
                    $this->EventTag->attachTagToEvent($id, $tag);
                }
            }
        }

        if (!empty($resolved_data['Attribute'])) {
            $total_attributes = count($resolved_data['Attribute']);
            $processedAttributes = 0;
            foreach ($resolved_data['Attribute'] as $attribute) {
                $this->Attribute->create();
                if (empty($attribute['comment'])) {
                    $attribute['comment'] = $default_comment;
                }
                if (!isset($attribute['distribution'])) {
                    $attribute['distribution'] = $this->Attribute->defaultDistribution();
                }
                if ($attribute['distribution'] != 4) {
                    $attribute['sharing_group_id'] = 0;
                }
                if (!empty($attribute['data']) && !empty($attribute['encrypt'])) {
                    $attribute = $this->Attribute->onDemandEncrypt($attribute);
                }
                $attribute['event_id'] = $id;
                if ($this->Attribute->save($attribute)) {
                    $saved_attributes++;
                    if (!empty($attribute['Tag'])) {
                        foreach ($attribute['Tag'] as $tag) {
                            $tag_id = $this->Attribute->AttributeTag->Tag->captureTag($tag, $user);
                            if ($tag_id) {
                                $relationship_type = empty($tag['relationship_type']) ? false : $tag['relationship_type'];
                                $this->Attribute->AttributeTag->attachTagToAttribute($this->Attribute->id, $id, $tag_id, !empty($tag['local']), $relationship_type);
                            }
                        }
                    }
                } else {
                    $this->Attribute->logDropped($user, $attribute);
                    $failed_attributes++;
                    $lastAttributeError = $this->Attribute->validationErrors;
                    $original_uuid = $this->__findOriginalUUID(
                        $attribute['type'],
                        $attribute['value'],
                        $id
                    );
                    if (!empty($original_uuid)) {
                        $recovered_uuids[$attribute['uuid']] = $original_uuid;
                    } else {
                        $failed[] = $attribute['uuid'];
                    }
                }
                if ($jobId) {
                    $processedAttributes++;
                    $this->Job->saveProgress($jobId, "Attribute $processedAttributes/$total_attributes", $processedAttributes * 100 / $items_count);
                }
            }
        } else {
            $total_attributes = 0;
        }

        if (!empty($resolved_data['Object'])) {
            $initial_object_id = isset($resolved_data['initialObject']) ? $resolved_data['initialObject']['Object']['id'] : "0";
            $total_objects = count($resolved_data['Object']);
            $processedObjects = 0;
            $references = array();
            foreach ($resolved_data['Object'] as $object) {
                if (isset($object['meta_category']) && !isset($object['meta-category'])) {
                    $object['meta-category'] = $object['meta_category'];
                    unset($object['meta_category']);
                }
                if (empty($object['comment'])) {
                    $object['comment'] = $default_comment;
                }
                $object['event_id'] = $id;
                if (isset($object['id']) && $object['id'] == $initial_object_id) {
                    $initial_object = $resolved_data['initialObject'];
                    $recovered_uuids[$object['uuid']] = $initial_object['Object']['uuid'];
                    if ($object['name'] != $initial_object['Object']['name']) {
                        throw new NotFoundException(__('Invalid object.'));
                    }
                    $initial_attributes = array();
                    if (!empty($initial_object['Attribute'])) {
                        foreach ($initial_object['Attribute'] as $initial_attribute) {
                            $initial_attributes[$initial_attribute['object_relation']][] = $initial_attribute['value'];
                        }
                    }
                    $initial_references = array();
                    if (!empty($initial_object['ObjectReference'])) {
                        foreach ($initial_object['ObjectReference'] as $initial_reference) {
                            $initial_references[$initial_reference['relationship_type']][] = $initial_reference['referenced_uuid'];
                        }
                    }
                    if (!empty($object['Attribute'])) {
                        foreach ($object['Attribute'] as $object_attribute) {
                            $object_relation = $object_attribute['object_relation'];
                            if (isset($initial_attributes[$object_relation]) && in_array($object_attribute['value'], $initial_attributes[$object_relation])) {
                                continue;
                            }
                            if ($this->__saveObjectAttribute($object_attribute, null, $event, $initial_object_id, $user)) {
                                $saved_object_attributes++;
                            } else {
                                $failed_object_attributes++;
                                $lastObjectAttributeError = $this->Attribute->validationErrors;
                            }
                        }
                    }
                    if (!empty($object['ObjectReference'])) {
                        foreach ($object['ObjectReference'] as $object_reference) {
                            $references[] = array('objectId' => $initial_object_id, 'reference' => $object_reference);
                        }
                    }
                    $saved_objects++;
                } else {
                    if (!empty($object['Attribute'])) {
                        $current_object_id = $this->__findCurrentObjectId($id, $object['Attribute']);
                        if ($current_object_id) {
                            $original_uuid = $this->Object->find('first', array(
                                'conditions' => array('Object.id' => $current_object_id, 'Object.event_id' => $id,
                                                      'Object.name' => $object['name'], 'Object.deleted' => 0),
                                'recursive' => -1,
                                'fields' => array('Object.uuid')
                            ));
                            if (!empty($original_uuid)) {
                                $recovered_uuids[$object['uuid']] = $original_uuid['Object']['uuid'];
                            }
                            $object_id = $current_object_id;
                        } else {
                            $this->Object->create();
                            if ($this->Object->save($object)) {
                                $object_id = $this->Object->id;
                                foreach ($object['Attribute'] as $object_attribute) {
                                    if ($this->__saveObjectAttribute($object_attribute, null, $event, $object_id, $user)) {
                                        $saved_object_attributes++;
                                    } else {
                                        $failed_object_attributes++;
                                        $lastObjectAttributeError = $this->Attribute->validationErrors;
                                    }
                                }
                                $saved_objects++;
                            } else {
                                $failed_objects++;
                                $lastObjectError = $this->Object->validationErrors;
                                $failed[] = $object['uuid'];
                                continue;
                            }
                        }
                    } else {
                        $this->Object->create();
                        if ($this->Object->save($object)) {
                            $object_id = $this->Object->id;
                            $saved_objects++;
                        } else {
                            $failed_objects++;
                            $lastObjectError = $this->Object->validationErrors;
                            $failed[] = $object['uuid'];
                            continue;
                        }
                    }
                    if (!empty($object['ObjectReference'])) {
                        foreach ($object['ObjectReference'] as $object_reference) {
                            $references[] = array('objectId' => $object_id, 'reference' => $object_reference);
                        }
                    }
                }
                if ($jobId) {
                    $processedObjects++;
                    $this->Job->saveProgress($jobId, "Object $processedObjects/$total_objects", ($processedObjects + $total_attributes) * 100 / $items_count);
                }
            }

            if (!empty($references)) {
                $reference_errors = array();
                foreach ($references as $reference) {
                    $object_id = $reference['objectId'];
                    $reference = $reference['reference'];
                    if (in_array($reference['object_uuid'], $failed)) {
                        continue; // if object that contains reference couldn't be added, skip
                    }
                    if (isset($recovered_uuids[$reference['object_uuid']])) {
                        $reference['object_uuid'] = $recovered_uuids[$reference['object_uuid']];
                    }
                    if (isset($recovered_uuids[$reference['referenced_uuid']])) {
                        $reference['referenced_uuid'] = $recovered_uuids[$reference['referenced_uuid']];
                    }
                    $current_reference = $this->Object->ObjectReference->hasAny([
                        'ObjectReference.object_id' => $object_id,
                        'ObjectReference.referenced_uuid' => $reference['referenced_uuid'],
                        'ObjectReference.relationship_type' => $reference['relationship_type'],
                        'ObjectReference.event_id' => $id,
                        'ObjectReference.deleted' => 0,
                    ]);
                    if ($current_reference) {
                        continue; // Reference already exists, skip.
                    }
                    list($referenced_id, $referenced_uuid, $referenced_type) = $this->Object->ObjectReference->getReferencedInfo(
                        $reference['referenced_uuid'],
                        array('Event' => array('id' => $id)),
                        false,
                        $user
                    );
                    if (!$referenced_id && !$referenced_uuid && !$referenced_type) {
                        continue;
                    }
                    $reference = array(
                        'event_id' => $id,
                        'referenced_id' => $referenced_id,
                        'referenced_uuid' => $referenced_uuid,
                        'referenced_type' => $referenced_type,
                        'object_id' => $object_id,
                        'object_uuid' => $reference['object_uuid'],
                        'relationship_type' => $reference['relationship_type']
                    );
                    $this->Object->ObjectReference->create();
                    if (!$this->Object->ObjectReference->save($reference)) {
                        $reference_errors[] = $this->Object->ObjectReference->validationErrors;
                    }
                }
            }
        }

        if (!empty($resolved_data['EventReport'])) {
            $total_reports = count($resolved_data['EventReport']);
            foreach ($resolved_data['EventReport'] as $i => $report) {
                $this->EventReport->create();
                $report['event_id'] = $id;
                if ($this->EventReport->save($report)) {
                    $saved_reports++;
                } else {
                    $failed_reports++;
                    $lastReportError = $this->EventReport->validationErrors;
                }
                if ($jobId) {
                    $current = ($i + 1);
                    $this->Job->saveProgress($jobId, "EventReport $current/$total_reports", $current * 100 / $items_count);
                }
            }
        }

        if ($saved_attributes > 0 || $saved_objects > 0 || $saved_reports > 0) {
            $this->unpublishEvent($event);
        }
        if ($event_level) {
            return $saved_attributes + $saved_object_attributes + $saved_reports;
        }
        $message = '';
        if ($saved_attributes > 0) {
            $message .= $saved_attributes . ' ' . $this->__apply_inflector($saved_attributes, 'attribute') . ' created. ';
        }
        if ($failed_attributes > 0) {
            if ($failed_attributes == 1) {
                $reason = ' attribute could not be saved. Reason for the failure: ' . json_encode($lastAttributeError) . ' ';
            } else {
                $reason = ' attributes could not be saved. This may be due to attributes with similar values already existing. ';
            }
            $message .= $failed_attributes . $reason;
        }
        if ($saved_objects > 0) {
            $message .= $saved_objects . ' ' . $this->__apply_inflector($saved_objects, 'object') . ' created';
            if ($saved_object_attributes > 0) {
                $message .= ' (including a total of ' . $saved_object_attributes . ' object ' . $this->__apply_inflector($saved_object_attributes, 'attribute') . '). ';
            } else {
                $message .= '. ';
            }
        }
        if ($failed_objects > 0) {
            if ($failed_objects == 1) {
                $reason = ' object could not be saved. Reason for the failure: ';
            } else {
                $reason = ' objects could not be saved. An example of reason for the failure: ';
            }
            $message .= $failed_objects . $reason . json_encode($lastObjectError) . ' ';
        }
        if ($failed_object_attributes > 0) {
            if ($failed_object_attributes == 1) {
                $reason = 'object attribute could not be saved. Reason for the failure: ';
            } else {
                $reason = 'object attributes could not be saved. An example of reason for the failure: ';
            }
            $message .= 'By the way, ' . $failed_object_attributes . $reason . json_encode($lastObjectAttributeError) . '.';
        }
        if (!empty($reference_errors)) {
            $reference_error = sizeof($reference_errors) == 1 ? 'a reference is' : 'some references are';
            $message .= ' Also, be aware that ' . $reference_error . ' missing: ';
            foreach ($reference_errors as $error) {
                $message .= $error;
            }
            $message .= 'you can have a look at the module results view you just left, to compare.';
        }
        if ($saved_reports > 0) {
            $message .= $saved_reports . ' ' . $this->__apply_inflector($saved_reports, 'eventReport') . ' created. ';
        }
        if ($failed_reports > 0) {
            if ($failed_reports == 1) {
                $reason = ' eventReport could not be saved. Reason for the failure: ' . json_encode($lastReportError) . ' ';
            } else {
                $reason = ' eventReport could not be saved. ';
            }
            $message .= $failed_reports . $reason;
        }
        if ($jobId) {
            $this->Job->saveStatus($jobId, true, 'Processing complete. ' . $message);
            $eventLock->deleteBackgroundJobLock($event['Event']['id'], $jobId);
        }
        return $message;
    }

    private function __apply_inflector($count, $scope)
    {
        return ($count == 1 ? Inflector::singularize($scope) : Inflector::pluralize($scope));
    }

    private function __findCurrentObjectId($event_id, $attributes)
    {
        $conditions = array();
        foreach($attributes as $attribute) {
            $conditions[] = array('AND' => array(
                'Attribute.object_relation' => $attribute['object_relation'],
                'Attribute.value' => $attribute['value'],
                'Attribute.type' => $attribute['type']
            ));
        }
        $ids = array();
        foreach ($this->Object->Attribute->find('all', array(
            'conditions' => array(
                'Attribute.event_id' => $event_id,
                'Attribute.object_id !=' => 0,
                'Attribute.deleted' => 0,
                'OR' => $conditions
            ),
            'recursive' => -1,
            'fields' => array('Attribute.object_id'))) as $found_id) {
            $ids[] = $found_id['Attribute']['object_id'];
        }
        $attributes_count = sizeof($attributes);
        foreach (array_count_values($ids) as $id => $count) {
            if ($count >= $attributes_count) {
                return $id;
            }
        }
        return 0;
    }

    private function __findOriginalUUID($attribute_type, $attribute_value, $event_id)
    {
        $original_uuid = $this->Object->Attribute->find(
            'first',
            array(
                'conditions' => array(
                    'Attribute.event_id' => $event_id,
                    'Attribute.deleted' => 0,
                    'Attribute.object_id' => 0,
                    'Attribute.type' => $attribute_type,
                    'Attribute.value' => $attribute_value
                ),
                'recursive' => -1,
                'fields' => array('Attribute.uuid')
            )
        );
        if (!empty($original_uuid)) {
            return $original_uuid['Attribute']['uuid'];
        }
        $original_uuid = $this->Object->find(
            'first',
            array(
                'conditions' => array(
                    'Attribute.event_id' => $event_id,
                    'Attribute.deleted' => 0,
                    'Attribute.type' => $attribute_type,
                    'Attribute.value1' => $attribute_value,
                    'Object.event_id' => $event_id
                ),
                'recursive' => -1,
                'fields' => array('Object.uuid'),
                'joins' => array(
                    array(
                        'table' => 'attributes',
                        'alias' => 'Attribute',
                        'type' => 'inner',
                        'conditions' => array(
                            'Attribute.object_id = Object.id'
                        )
                    )
                )
            )
        );
        return (!empty($original_uuid)) ? $original_uuid['Object']['uuid'] : $original_uuid;
    }

    /**
     * @param array $attribute
     * @param string|null $default_comment
     * @param array $event
     * @param int $object_id
     * @param array $user
     * @return array|bool|mixed
     * @throws Exception
     */
    private function __saveObjectAttribute(array $attribute, $default_comment, array $event, $object_id, array $user)
    {
        $attribute['object_id'] = $object_id;
        $attribute['event_id'] = $event['Event']['id'];
        if (empty($attribute['comment']) && $default_comment) {
            $attribute['comment'] = $default_comment;
        }
        if (!isset($attribute['distribution'])) {
            $attribute['distribution'] = $this->Attribute->defaultDistribution();
        }
        if ($attribute['distribution'] != 4) {
            $attribute['sharing_group_id'] = 0;
        }
        if (!empty($attribute['data']) && !empty($attribute['encrypt'])) {
            $attribute = $this->Attribute->onDemandEncrypt($attribute);
        }
        $this->Attribute->create();
        $attribute_save = $this->Attribute->save($attribute, ['parentEvent' => $event]);
        if ($attribute_save) {
            if (!empty($attribute['Tag'])) {
                foreach ($attribute['Tag'] as $tag) {
                    $tag_id = $this->Attribute->AttributeTag->Tag->captureTag($tag, $user);
                    $relationship_type = empty($tag['relationship_type']) ? false : $tag['relationship_type'];
                    if ($tag_id) {
                        $this->Attribute->AttributeTag->attachTagToAttribute($this->Attribute->id, $event['Event']['id'], $tag_id, !empty($tag['local']), $relationship_type);
                    }
                }
            }
        } else {
            $this->Attribute->logDropped($user, $attribute);
        }
        return $attribute_save;
    }

    public function processFreeTextDataRouter(array $user, array $attributes, $id, $default_comment = '', $proposals = false, $adhereToWarninglists = false, $returnRawResults = false)
    {
        if (Configure::read('MISP.background_jobs') && count($attributes) > 5) { // on background process just big attributes batch
            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob(
                $user,
                Job::WORKER_PRIO,
                "process_freetext_data",
                'Event: ' . $id,
                'Processing...'
            );

            $tempData = array(
                'user' => $user,
                'attributes' => $attributes,
                'id' => $id,
                'default_comment' => $default_comment,
                'proposals' => $proposals,
                'adhereToWarninglists' => $adhereToWarninglists,
                'jobId' => $jobId,
            );

            try {
                $filePath = $this->getBackgroundJobsTool()->enqueueDataFile($tempData);
                $this->getBackgroundJobsTool()->enqueue(
                    BackgroundJobsTool::PRIO_QUEUE,
                    BackgroundJobsTool::CMD_EVENT,
                    [
                        'processfreetext',
                        $filePath
                    ],
                    true,
                    $jobId
                );

                return 'Freetext ingestion queued for background processing. Attributes will be added to the event as they are being processed.';
            } catch (Exception $e) {
                $this->logException("Could not process freetext in background.", $e, LOG_NOTICE);
            }
        }
        return $this->processFreeTextData($user, $attributes, $id, $default_comment, $proposals, $adhereToWarninglists, false, $returnRawResults);
    }

    public function processModuleResultsDataRouter($user, $resolved_data, $id, $default_comment = '')
    {
        if (Configure::read('MISP.background_jobs')) {
            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob($user, Job::WORKER_PRIO, "process_module_results_data", 'Event: ' . $id, 'Processing...');

            $tempData = array(
                'user' => $user,
                'misp_format' => $resolved_data,
                'id' => $id,
                'default_comment' => $default_comment,
                'jobId' => $jobId
            );

            try {
                $filePath = $this->getBackgroundJobsTool()->enqueueDataFile($tempData);

                $this->getBackgroundJobsTool()->enqueue(
                    BackgroundJobsTool::PRIO_QUEUE,
                    BackgroundJobsTool::CMD_EVENT,
                    [
                        'processmoduleresult',
                        $filePath
                    ],
                    true,
                    $jobId
                );

                return 'Module results ingestion queued for background processing. Related data will be added to the event as it is being processed.';
            } catch (Exception $e) {
                $this->logException("Could not process module results in background.", $e, LOG_NOTICE);
            }
        }
        return $this->processModuleResultsData($user, $resolved_data, $id, $default_comment);
    }

    /**
     * Attach references to objects faster than CakePHP.
     * @param array $events
     */
    private function __attachReferences(array &$events)
    {
        $eventIds = [];
        foreach ($events as $event) {
            if (!empty($event['Object'])) {
                $eventIds[] = $event['Event']['id']; // event contains objects
            }
        }
        if (!empty($eventIds)) {
            // Do not fetch fields that we already know to reduce memory usage
            $schema = $this->Object->ObjectReference->schema();
            unset($schema['event_id']);
            unset($schema['source_uuid']);

            $references = $this->Object->ObjectReference->find('all', [
                'conditions' => ['ObjectReference.event_id' => $eventIds],
                'fields' => array_keys($schema),
                'recursive' => -1,
            ]);
        }
        if (empty($references)) {
            // Assign empty object reference object
            foreach ($events as &$event) {
                foreach ($event['Object'] as &$object) {
                    $object['ObjectReference'] = [];
                }
            }
            return;
        }
        $referencesForObject = [];
        foreach ($references as $reference) {
            $referencesForObject[$reference['ObjectReference']['object_id']][] = $reference['ObjectReference'];
        }
        $fieldsToCopy = array(
            'common' => array('distribution', 'sharing_group_id', 'uuid'),
            'Attribute' => array('value', 'type', 'category', 'to_ids'),
            'Object' => array('name', 'meta-category')
        );
        foreach ($events as &$event) {
            $eventIdCache = [];
            foreach ($event['Object'] as &$object) {
                $objectReferences = $referencesForObject[$object['id']] ?? [];
                foreach ($objectReferences as &$reference) {
                    $reference['event_id'] = $event['Event']['id'];
                    $reference['source_uuid'] = $object['uuid'];
                    // find referenced object in current event
                    $type = $reference['referenced_type'] == 0 ? 'Attribute' : 'Object';
                    // construct array with ID in key, so we can search attributes and objects by ID faster
                    if (!isset($eventIdCache[$type])) {
                        $eventIdCache[$type] = array_column($event[$type], null, 'id');
                    }
                    $found = $eventIdCache[$type][$reference['referenced_id']] ?? null;

                    if ($found) {
                        // copy requested fields
                        $copied = [];
                        foreach (array_merge($fieldsToCopy['common'], $fieldsToCopy[$type]) as $field) {
                            $copied[$field] = $found[$field];
                        }
                        $reference[$type] = $copied;
                    } else { // object / attribute might be from an extended event
                        $otherEventText = __('%s from another event', $type);
                        $reference[$type] = [
                            'name' => '',
                            'meta-category' => $otherEventText,
                            'category' => $otherEventText,
                            'type' => '',
                            'value' => '',
                            'uuid' => $reference['referenced_uuid']
                        ];
                    }
                }
                $object['ObjectReference'] = $objectReferences;
            }
        }
    }

    /**
     * Faster way how to attach tags to events that integrated in CakePHP.
     * @param array $events
     * @param bool $excludeLocalTags
     */
    private function __attachAttributeTags(array &$events, $excludeLocalTags = false)
    {
        $eventIds = array_column(array_column($events, 'Event'), 'id');
        $conditions = ['AttributeTag.event_id' => $eventIds];
        if ($excludeLocalTags) {
            $conditions['AttributeTag.local'] = false;
        }
        $ats = $this->Attribute->AttributeTag->find('all', [
            'conditions' => $conditions,
            'fields' => ['AttributeTag.id', 'AttributeTag.attribute_id', 'AttributeTag.tag_id', 'AttributeTag.local', 'AttributeTag.relationship_type'], // we don't need id or event_id
            'recursive' => -1,
        ]);
        if (empty($ats)) {
            foreach ($events as &$event) {
                foreach ($event['Attribute'] as &$attribute) {
                    $attribute['AttributeTag'] = [];
                }
            }
            return;
        }
        $atForAttributes = [];
        foreach ($ats as $at) {
            $atForAttributes[$at['AttributeTag']['attribute_id']][] = $at['AttributeTag'];
        }
        foreach ($events as &$event) {
            foreach ($event['Attribute'] as &$attribute) {
                $attribute['AttributeTag'] = $atForAttributes[$attribute['id']] ?? [];
            }
        }
    }

    /**
     * Get tag from cache by given ID.
     *
     * @param int $tagId
     * @param bool $justExportable If true, return just exportable tags.
     * @return array|null
     */
    private function __getCachedTag($tagId, $justExportable)
    {
        if (!isset($this->assetCache['tags'][$tagId])) {
            return null;
        }
        $tag = $this->assetCache['tags'][$tagId];
        if ($justExportable && !$tag['exportable']) {
            return null;
        }
        return $tag;
    }

    /**
     * Fetches all tags for event and event attributes in one query and save to cache.
     *
     * @param array $event
     * @param bool $justExportable If true, cache just exportable tags.
     */
    private function __precacheTagsForEvent(array $event, $justExportable)
    {
        $tagIds = [];
        if (!empty($event['EventTag'])) {
            foreach ($event['EventTag'] as $eventTag) {
                $tagIds[$eventTag['tag_id']] = true;
            }
        }

        if (!empty($event['Attribute'])) {
            foreach ($event['Attribute'] as $attribute) {
                foreach ($attribute['AttributeTag'] as $attributeTag) {
                    $tagIds[$attributeTag['tag_id']] = true;
                }
            }
        }

        $notCachedTags = array_diff_key($tagIds, $this->assetCache['tags'] ?? []);
        if (empty($notCachedTags)) {
            return;
        }
        $conditions = ['Tag.id' => array_keys($notCachedTags)];
        if ($justExportable) {
            $conditions['Tag.exportable'] = 1;
        }
        $tags = $this->EventTag->Tag->find('all', [
            'recursive' => -1,
            'conditions' => $conditions,
        ]);
        foreach ($tags as $tag) {
            $this->assetCache['tags'][$tag['Tag']['id']] = $tag['Tag'];
        }
    }

    /**
     * Attach tags to attributes and event.
     *
     * @param array $event
     * @param bool $justExportable If true, attach just exportable tags.
     */
    private function __attachTags(array &$event, $justExportable)
    {
        $this->__precacheTagsForEvent($event, $justExportable);

        if (!empty($event['EventTag'])) {
            foreach ($event['EventTag'] as $etk => $eventTag) {
                $tag = $this->__getCachedTag($eventTag['tag_id'], $justExportable);
                if ($tag !== null) {
                    $tag['local'] = empty($eventTag['local']) ? false : true;
                    $tag['relationship_type'] = empty($eventTag['relationship_type']) ? null : $eventTag['relationship_type'];
                    $event['EventTag'][$etk]['Tag'] = $tag;
                } else {
                    unset($event['EventTag'][$etk]);
                }
            }
            $event['EventTag'] = array_values($event['EventTag']);
        }
        if (!empty($event['Attribute'])) {
            foreach ($event['Attribute'] as $ak => $attribute) {
                if (!empty($attribute['AttributeTag'])) {
                    foreach ($attribute['AttributeTag'] as $atk => $attributeTag) {
                        $tag = $this->__getCachedTag($attributeTag['tag_id'], $justExportable);
                        if ($tag !== null) {
                            $tag['local'] = empty($attributeTag['local']) ? false : true;
                            $tag['relationship_type'] = empty($attributeTag['relationship_type']) ? null : $attributeTag['relationship_type'];
                            $event['Attribute'][$ak]['AttributeTag'][$atk]['Tag'] = $tag;
                        } else {
                            unset($event['Attribute'][$ak]['AttributeTag'][$atk]);
                        }
                    }
                    $event['Attribute'][$ak]['AttributeTag'] = array_values($event['Attribute'][$ak]['AttributeTag']);
                }
            }
        }
    }


    public function restSearchFilterMassage($filters, $non_restrictive_export, $user)
    {
        if (!empty($filters['ignore'])) {
            $filters['to_ids'] = array(0, 1);
            $filters['published'] = array(0, 1);
        }
        if (!empty($filters['quickFilter'])) {
            $filters['searchall'] = $filters['quickFilter'];
            if (!empty($filters['value'])) {
                unset($filters['value']);
            }
        }
        if (isset($filters['searchall'])) {
            if (!empty($filters['value'])) {
                $filters['wildcard'] = $filters['value'];
            } else {
                $filters['wildcard'] = $filters['searchall'];
            }
        }

        if (isset($filters['tag']) and !isset($filters['tags'])) {
            $filters['tags'] = $filters['tag'];
        }
        if (!empty($filters['withAttachments'])) {
            $filters['includeAttachments'] = 1;
        }
        if (empty($non_restrictive_export)) {
            if (!isset($filters['to_ids'])) {
                $filters['to_ids'] = 1;
            }
            if (!isset($filters['published'])) {
                $filters['published'] = 1;
            }
            $filters['allow_proposal_blocking'] = 1;
        }
        $subqueryElements = $this->harvestSubqueryElements($filters);
        $filters = $this->addFiltersFromSubqueryElements($filters, $subqueryElements, $user);
        return $filters;
    }

    /**
     * @param array $user
     * @param string $returnFormat
     * @param array $filters
     * @param bool $paramsOnly
     * @param int|false $jobId
     * @param int $elementCounter
     * @param bool $renderView
     * @return TmpFileTool
     * @throws Exception
     */
    public function restSearch(array $user, $returnFormat, $filters, $paramsOnly = false, $jobId = false, &$elementCounter = 0, &$renderView = false)
    {
        if (!isset($this->validFormats[$returnFormat][1])) {
            throw new NotFoundException('Invalid output format.');
        }
        App::uses($this->validFormats[$returnFormat][1], 'Export');
        $exportTool = new $this->validFormats[$returnFormat][1]();

        if ($jobId) {
            $this->Job = ClassRegistry::init('Job');
            $this->Job->id = $jobId;
        }

        if (method_exists($exportTool, 'setDefaultFilters')) {
            $exportTool->setDefaultFilters($filters);
        }

        if (!empty($exportTool->renderView)) {
            $renderView = $exportTool->renderView;
        }
        $non_restrictive_export = !empty($exportTool->non_restrictive_export);
        $filters = $this->restSearchFilterMassage($filters, $non_restrictive_export, $user);

        $filters = $this->addFiltersFromUserSettings($user, $filters);
        if (empty($exportTool->mock_query_only)) {
            $filters['include_attribute_count'] = 1;
            $eventid = $this->filterEventIds($user, $filters, $elementCounter);
            $eventCount = count($eventid);
            $eventids_chunked = $this->clusterEventIds($exportTool, $eventid);
            unset($eventid);
        } else {
            $eventids_chunked = array();
        }
        if (!empty($exportTool->additional_params)) {
            $filters = array_merge($filters, $exportTool->additional_params);
        }

        $exportToolParams = array(
            'user' => $user,
            'params' => array(),
            'returnFormat' => $returnFormat,
            'scope' => 'Event',
            'filters' => $filters
        );
        if (empty($exportTool->non_restrictive_export)) {
            if (!isset($filters['to_ids'])) {
                $filters['to_ids'] = 1;
            }
            if (!isset($filters['published'])) {
                $filters['published'] = 1;
            }
        }
        $tmpfile = new TmpFileTool();
        $tmpfile->write($exportTool->header($exportToolParams));
        $i = 0;
        $this->Allowedlist = ClassRegistry::init('Allowedlist');
        $separator = $exportTool->separator($exportToolParams);
        unset($filters['page']);
        unset($filters['limit']);
        foreach ($eventids_chunked as $chunk) {
            $filters['eventid'] = $chunk;
            if (!empty($filters['tags']['NOT'])) {
                $filters['blockedAttributeTags'] = $filters['tags']['NOT'];
                unset($filters['tags']['NOT']);
            }
            $result = $this->fetchEvent($user, $filters, true);
            $result = $this->Allowedlist->removeAllowedlistedFromArray($result, false);
            foreach ($result as $event) {
                if ($jobId && $i % 10 == 0) {
                    $this->Job->saveField('progress', intval((100 * $i) / $eventCount));
                    $this->Job->saveField('message', 'Converting Event ' . $i . '/' . $eventCount . '.');
                }
                $temp = $exportTool->handler($event, $exportToolParams);
                if ($temp !== '') {
                    $tmpfile->writeWithSeparator($temp, $separator);
                    $i++;
                }
            }
        }
        $footer = $exportTool->footer($exportToolParams);
        if ($footer instanceof TmpFileTool) {
            return $footer; // Some exports returns TmpFileTool with all data when ends, so we can just pass the file as output
        }

        $tmpfile->write($footer);
        return $tmpfile;
    }

    /*
     *  Receive a list of eventids in the id=>count format
     *  Chunk them by the attribute count to fit the memory limits
     *
     */
    public function clusterEventIds($exportTool, $eventIds)
    {
        $memory_in_mb = $this->convert_to_memory_limit_to_mb(ini_get('memory_limit'));
        $default_attribute_memory_coefficient = Configure::check('MISP.default_attribute_memory_coefficient') ? Configure::read('MISP.default_attribute_memory_coefficient') : 80;
        $default_event_memory_divisor = Configure::check('MISP.default_event_memory_multiplier') ? Configure::read('MISP.default_event_memory_divisor') : 3;
        $memory_scaling_factor = isset($exportTool->memory_scaling_factor) ? $exportTool->memory_scaling_factor : $default_attribute_memory_coefficient;
        // increase the cost per attribute to account for the overhead of object metadata
        $memory_scaling_factor = $memory_scaling_factor / $default_event_memory_divisor;
        $limit = $memory_in_mb * $memory_scaling_factor;
        $eventIdList = array();
        $continue = true;
        $i = 0;
        $current_chunk_size = 0;
        $largest_event = 0;
        $largest_event_id = 0;
        foreach ($eventIds as $id => $count) {
            if ($count > $largest_event) {
                $largest_event = $count;
                $largest_event_id = $id;
            }
            if ($current_chunk_size == 0 && $count > $limit) {
                $eventIdList[$i][] = $id;
                $current_chunk_size = $count;
                $i++;
            } else {
                if (($current_chunk_size + $count) > $limit) {
                    $i++;
                    $eventIdList[$i][] = $id;
                    $current_chunk_size = $count;
                } else {
                    $current_chunk_size += $count;
                    $eventIdList[$i][] = $id;
                }
            }
        }
        if ($largest_event/$memory_scaling_factor > $memory_in_mb) {
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
            $this->Log->saveOrFailSilently(array(
                    'org' => 'SYSTEM',
                    'model' => 'Event',
                    'model_id' => 0,
                    'email' => 'SYSTEM',
                    'action' => 'error',
                    'title' => sprintf('Event fetch potential memory exhaustion.' . PHP_EOL . 'During the fetching of events, a large event (#%s) was detected that exceeds the available PHP memory.' . PHP_EOL . 'Consider raising the PHP max_memory setting to at least %sM', $largest_event_id, ceil($largest_event/$memory_scaling_factor)),
                    'change' => null,
            ));
        }
        return $eventIdList;
    }

    /**
     * @param string $file File content
     * @param string $original_filename
     * @param int $event_id
     * @param string $format
     * @return bool
     * @throws Exception
     */
    public function add_original_file($file, $original_filename, $event_id, $format)
    {
        $distribution = $this->Attribute->defaultDistribution();
        $this->Object->create();
        $object = array(
            'name' => 'original-imported-file',
            'meta-category' => 'file',
            'description' => 'Object describing the original file used to import data in MISP.',
            'template_uuid' => '4cd560e9-2cfe-40a1-9964-7b2e797ecac5',
            'template_version' => '2',
            'event_id' => $event_id,
            'distribution' => $distribution
        );
        if (!$this->Object->save($object)) {
            throw new Exception("Could not save object for original file because of validation errors:" . json_encode($this->Object->validationErrors));
        }
        $object_id = $this->Object->id;
        $attributes = array(
            array(
                'type' => 'attachment',
                'category' => 'External analysis',
                'to_ids' => false,
                'event_id' => $event_id,
                'distribution' => $distribution,
                'object_relation' => 'imported-sample',
                'value' => $original_filename,
                'data_raw' => $file,
                'object_id' => $object_id,
                'disable_correlation' => true
            ),
            array(
                'type' => 'text',
                'category' => 'Other',
                'to_ids' => false,
                'event_id' => $event_id,
                'distribution' => $distribution,
                'object_id' => $object_id,
                'object_relation' => 'format',
                'value' => $format,
                'disable_correlation' => true
            )
        );
        if (!$this->Attribute->saveMany($attributes)) {
            throw new Exception("Could not save attributes for original file because of validation errors:" . json_encode($this->Attribute->validationErrors));
        }
        return true;
    }

    private function getRequiredTaxonomies()
    {
        $this->Taxonomy = ClassRegistry::init('Taxonomy');
        return $this->Taxonomy->find('column', array(
            'conditions' => array('Taxonomy.required' => 1, 'Taxonomy.enabled' => 1),
            'fields' => array('Taxonomy.namespace')
        ));
    }

    public function missingTaxonomies(array $event)
    {
        $requiredTaxonomies = $this->getRequiredTaxonomies();
        return $this->checkMissingTaxonomies($requiredTaxonomies, $event['EventTag']);
    }

    public function checkIfPublishable($id)
    {
        $requiredTaxonomies = $this->getRequiredTaxonomies();
        if (!empty($requiredTaxonomies)) {
            $eventTags = $this->EventTag->find('all', array(
                'conditions' => array('EventTag.event_id' => $id),
                'recursive' => -1,
                'contain' => array('Tag' => ['fields' => ['name']])
            ));
            $missing = $this->checkMissingTaxonomies($requiredTaxonomies, $eventTags);
            if (!empty($missing)) {
                return $missing;
            }
        }
        return true;
    }

    /**
     * @param array $requiredTaxonomies
     * @param array $eventTags
     * @return array
     */
    private function checkMissingTaxonomies(array $requiredTaxonomies, array $eventTags)
    {
        $missing = [];
        foreach ($requiredTaxonomies as $requiredTaxonomy) {
            $found = false;
            foreach ($eventTags as $tag) {
                $splits = $this->Taxonomy->splitTagToComponents($tag['Tag']['name']);
                if ($splits !== null && $splits['namespace'] === $requiredTaxonomy) {
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                $missing[] = $requiredTaxonomy;
            }
        }
        return $missing;
    }

    public function harvestSubqueryElements($options)
    {
        $acceptedRules = array(
            'galaxy' => 1,
            'org' => array('sector', 'local', 'nationality')
        );
        $subqueryElement = array(
            'galaxy' => array(),
            'org' => array(),
        );
        foreach($options as $rule => $value) {
            $split = explode(".", $rule, 2);
            if (count($split) > 1) {
                $scope = $split[0];
                $element = $split[1];
                if (isset($acceptedRules[$scope])) {
                    if (is_array($acceptedRules[$scope]) && !in_array($element, $acceptedRules[$scope])) {
                        continue;
                    } else {
                        $subqueryElement[$scope][$element] = $value;
                    }
                }
            }
        }
        return $subqueryElement;
    }

    public function addFiltersFromSubqueryElements($filters, $subqueryElements, $user)
    {
        if (!empty($subqueryElements['galaxy'])) {
            $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
            $tagsFromGalaxyMeta = $this->GalaxyCluster->getClusterTagsFromMeta($subqueryElements['galaxy'], $user);
            if (empty($tagsFromGalaxyMeta)) {
                $filters['eventid'] = -1;
            }
            if (!empty($filters['tags'])) {
                $filters['tags'][] = $tagsFromGalaxyMeta;
            } else {
                $filters['tags'] = $tagsFromGalaxyMeta;
            }
        }
        if (!empty($subqueryElements['org'])) {
            $Organisation = ClassRegistry::init('Organisation');
            $orgcIdsFromMeta = $Organisation->getOrgIdsFromMeta($subqueryElements['org']);
            if (!empty($filters['org'])) {
                $filters['org'][] = $orgcIdsFromMeta;
            } else {
                $filters['org'] = $orgcIdsFromMeta;
            }
        }
        return $filters;
    }

    public function addFiltersFromUserSettings($user, $filters)
    {
        $this->UserSetting = ClassRegistry::init('UserSetting');
        $defaultParameters = $this->UserSetting->getDefaultRestSearchParameters($user);
        $filters = array_replace_recursive($defaultParameters, $filters);
        return $filters;
    }

    /**
     * @param array $event
     */
    public function removeGalaxyClusterTags(array &$event)
    {
        $galaxyTagIds = array();
        foreach ($event['Galaxy'] as $galaxy) {
            foreach ($galaxy['GalaxyCluster'] as $galaxyCluster) {
                $galaxyTagIds[$galaxyCluster['tag_id']] = true;
            }
        }

        if (empty($galaxyTagIds)) {
            return;
        }

        foreach ($event['EventTag'] as $k => $eventTag) {
            if (isset($galaxyTagIds[$eventTag['tag_id']])) {
                unset($event['EventTag'][$k]);
            }
        }
    }

    /**
     * Returns all tag names attached to any elements in an event
     *
     * @param  array $event
     * @return array All tag names in the event with tag name in key and also in value
     */
    public function extractAllTagNames(array $event)
    {
        $tags = array();
        if (!empty($event['EventTag'])) {
            foreach ($event['EventTag'] as $eventTag) {
                $tagName = $eventTag['Tag']['name'];
                $tags[$tagName] = $tagName;
            }
        }
        if (!empty($event['Attribute'])) {
            foreach ($event['Attribute'] as $attribute) {
                foreach ($attribute['AttributeTag'] as $attributeTag) {
                    $tagName = $attributeTag['Tag']['name'];
                    $tags[$tagName] = $tagName;
                }
            }
        }
        if (!empty($event['Object'])) {
            foreach ($event['Object'] as $object) {
                if (!empty($object['Attribute'])) {
                    foreach ($object['Attribute'] as $attribute) {
                        foreach ($attribute['AttributeTag'] as $attributeTag) {
                            $tagName = $attributeTag['Tag']['name'];
                            $tags[$tagName] = $tagName;
                        }
                    }
                }
            }
        }
        return $tags;
    }

    public function recoverEvent($id)
    {
        $this->Log = ClassRegistry::init('Log');
        $result = $this->Log->recoverDeletedEvent($id);
        return $result;
    }

    /**
     * @param array $event Event with assigned `EventTag`
     * @return string
     */
    private function getEmailSubjectMarkForEvent(array $event)
    {
        $subjTag = Configure::read('MISP.email_subject_tag') ?: "tlp";
        $tagLen = strlen($subjTag);
        foreach ($event['EventTag'] as $tag) {
            $tagName = $tag['Tag']['name'];
            if (strncasecmp($subjTag, $tagName, $tagLen) === 0 && strlen($tagName) > $tagLen && ($tagName[$tagLen] === ':' || $tagName[$tagLen] === '=')) {
                if (Configure::read('MISP.email_subject_include_tag_name') === false) {
                    return trim(substr($tagName, $tagLen + 1), '"');
                } else {
                    return $tagName;
                }
            }
        }

        // default value if no match found
        return Configure::read('MISP.email_subject_TLP_string') ?: "tlp:amber";
    }

    public function getExtendingEventIdsFromEvent($user, $eventID)
    {
        $event = $this->fetchSimpleEvent($user, $eventID);
        if (!empty($event)) {
            $extendingEventIds = $this->fetchSimpleEventIds($user, ['conditions' => [
                'extends_uuid' => $event['Event']['uuid']
            ]]);
            return $extendingEventIds;
        }
        return [];
    }

    public function getEventRepublishBanStatus($eventID)
    {
        $banStatus = [
            'error' => false,
            'active' => false,
            'message' => __('Event publish is not banned')
        ];
        if (Configure::read('MISP.event_alert_republish_ban')) {
            $event = $this->find('first', array(
                    'conditions' => array('Event.id' => $eventID),
                    'recursive' => -1,
                    'fields' => array('Event.uuid')
            ));
            if (empty($event)) {
                $banStatus['error'] = true;
                $banStatus['active'] = true;
                $banStatus['message'] = __('Event not found');
                return $banStatus;
            }
            $banThresholdMinutes = intval(Configure::read('MISP.event_alert_republish_ban_threshold'));
            $banThresholdSeconds = 60 * $banThresholdMinutes;
            $redis = $this->setupRedis();
            if ($redis === false) {
                $banStatus['error'] = true;
                $banStatus['active'] = true;
                $banStatus['message'] =  __('Reason: Could not reach redis to check republish emailing ban status.');
                return $banStatus;
            }
            $redisKey = "misp:event_alert_republish_ban:{$event['Event']['uuid']}";
            $banLiftTimestamp = $redis->get($redisKey);
            if (!empty($banLiftTimestamp)) {
                $remainingMinutes = (intval($banLiftTimestamp) - time()) / 60;
                $banStatus['active'] = true;
                if (Configure::read('MISP.event_alert_republish_ban_refresh_on_retry')) {
                    $redis->multi(Redis::PIPELINE)
                        ->set($redisKey, time() + $banThresholdSeconds)
                        ->expire($redisKey, $banThresholdSeconds)
                        ->exec();
                    $banStatus['message'] = __('Reason: Event is banned from sending out emails. Ban has been refreshed and will be lifted in %smin', $banThresholdMinutes);
                } else {
                    $banStatus['message'] = __('Reason: Event is banned from sending out emails. Ban will be lifted in %smin %ssec.', floor($remainingMinutes), $remainingMinutes % 60);
                }
                return $banStatus;
            } else {
                $redis->multi(Redis::PIPELINE)
                    ->set($redisKey, time() + $banThresholdSeconds)
                    ->expire($redisKey, $banThresholdSeconds)
                    ->exec();
                return $banStatus;
            }
        }
        $banStatus['message'] = __('Emailing republishing ban setting is not enabled');
        return $banStatus;
    }

    /**
     * @return array[]
     * @deprecated
     */
    public function exportTypes()
    {
        return array(
            'json' => array(
                'extension' => '.json',
                'type' => 'JSON',
                'scope' => 'Event',
                'requiresPublished' => 0,
                'params' => array('includeAttachments' => 1, 'ignore' => 1, 'returnFormat' => 'json'),
                'description' => __('Click this to download all events and attributes that you have access to in MISP JSON format.'),
            ),
            'xml' => array(
                'extension' => '.xml',
                'type' => 'XML',
                'scope' => 'Event',
                'params' => array('includeAttachments' => 1, 'ignore' => 1, 'returnFormat' => 'xml'),
                'requiresPublished' => 0,
                'description' => __('Click this to download all events and attributes that you have access to in MISP XML format.'),
            ),
            'csv_sig' => array(
                'extension' => '.csv',
                'type' => 'CSV_Sig',
                'scope' => 'Event',
                'requiresPublished' => 1,
                'params' => array('published' => 1, 'to_ids' => 1, 'returnFormat' => 'csv'),
                'description' => __('Click this to download all attributes that are indicators and that you have access to (except file attachments) in CSV format.'),
            ),
            'csv_all' => array(
                'extension' => '.csv',
                'type' => 'CSV_All',
                'scope' => 'Event',
                'requiresPublished' => 0,
                'params' => array('ignore' => 1, 'returnFormat' => 'csv'),
                'description' => __('Click this to download all attributes that you have access to (except file attachments) in CSV format.'),
            ),
            'suricata' => array(
                'extension' => '.rules',
                'type' => 'Suricata',
                'scope' => 'Attribute',
                'requiresPublished' => 1,
                'params' => array('returnFormat' => 'suricata'),
                'description' => __('Click this to download all network related attributes that you have access to under the Suricata rule format. Only published events and attributes marked as IDS Signature are exported. Administration is able to maintain a allowedlist containing host, domain name and IP numbers to exclude from the NIDS export.'),
            ),
            'snort' => array(
                'extension' => '.rules',
                'type' => 'Snort',
                'scope' => 'Attribute',
                'requiresPublished' => 1,
                'params' => array('returnFormat' => 'snort'),
                'description' => __('Click this to download all network related attributes that you have access to under the Snort rule format. Only published events and attributes marked as IDS Signature are exported. Administration is able to maintain a allowedlist containing host, domain name and IP numbers to exclude from the NIDS export.'),
            ),
            'bro' => array(
                'extension' => '.intel',
                'type' => 'Bro',
                'scope' => 'Attribute',
                'requiresPublished' => 1,
                'params' => array('returnFormat' => 'bro'),
                'description' => __('Click this to download all network related attributes that you have access to under the Bro rule format. Only published events and attributes marked as IDS Signature are exported. Administration is able to maintain a allowedlist containing host, domain name and IP numbers to exclude from the NIDS export.'),
            ),
            'stix' => array(
                'extension' => '.xml',
                'type' => 'STIX',
                'scope' => 'Event',
                'requiresPublished' => 1,
                'params' => array('returnFormat' => 'stix', 'includeAttachments' => 1),
                'description' => __('Click this to download a STIX document containing the STIX version of all events and attributes that you have access to.')
            ),
            'stix2' => array(
                'extension' => '.json',
                'type' => 'STIX2',
                'scope' => 'Event',
                'requiresPublished' => 1,
                'params' => array('returnFormat' => 'stix2', 'includeAttachments' => 1),
                'description' => __('Click this to download a STIX2 document containing the STIX2 version of all events and attributes that you have access to.')
            ),
            'rpz' => array(
                'extension' => '.txt',
                'type' => 'RPZ',
                'scope' => 'Attribute',
                'requiresPublished' => 1,
                'params' => array('returnFormat' => 'rpz'),
                'description' => __('Click this to download an RPZ Zone file generated from all ip-src/ip-dst, hostname, domain attributes. This can be useful for DNS level firewalling. Only published events and attributes marked as IDS Signature are exported.')
            ),
            'text' => array(
                'extension' => '.txt',
                'type' => 'TEXT',
                'scope' => 'Attribute',
                'requiresPublished' => 1,
                'params' => array('returnFormat' => 'text', 'includeAttachments' => 1),
                'description' => __('Click on one of the buttons below to download all the attributes with the matching type. This list can be used to feed forensic software when searching for susipicious files. Only published events and attributes marked as IDS Signature are exported.')
            ),
            'yara' => array(
                'extension' => '.yara',
                'type' => 'Yara',
                'scope' => 'Event',
                'requiresPublished' => 1,
                'params' => array('returnFormat' => 'yara'),
                'description' => __('Click this to download Yara rules generated from all relevant attributes.')
            ),
            'yara-json' => array(
                'extension' => '.json',
                'type' => 'Yara',
                'scope' => 'Event',
                'requiresPublished' => 1,
                'params' => array('returnFormat' => 'yara-json'),
                'description' => __('Click this to download Yara rules generated from all relevant attributes. Rules are returned in a JSON format with information about origin (generated or parsed) and validity.')
            ),
        );
    }

    private function __prepareEventForPubSub($id, $user, &$fullEvent)
    {
        if ($fullEvent) {
            if (empty(Configure::read('Plugin.ZeroMQ_include_attachments'))) {
                if (!empty($fullEvent[0]['Attribute'])) {
                    foreach ($fullEvent[0]['Attribute'] as $k => $attribute) {
                        if (isset($attribute['data'])) {
                            unset($fullEvent[0]['Attribute'][$k]['data']);
                        }
                    }
                }
                if (!empty($fullEvent[0]['Object'])) {
                    foreach ($fullEvent[0]['Object'] as $k => $object) {
                        if (!empty($object['Attribute'])) {
                            foreach ($object['Attribute'] as $k2 => $attribute) {
                                if (isset($attribute['data'])) {
                                    unset($fullEvent[0]['Object'][$k]['Attribute'][$k2]['data']);
                                }
                            }
                        }
                    }
                }
            }
        } else {
            $params = [
                'eventid' => $id
            ];
            if (Configure::read('Plugin.ZeroMQ_include_attachments')) {
                $params['includeAttachments'] = 1;
            }
            $fullEvent = $this->fetchEvent($user, $params);
        }
        return $fullEvent;
    }

    public function publishEventToZmq($id, $user, &$fullEvent)
    {
        $fullEvent = $this->__prepareEventForPubSub($id, $user, $fullEvent);
        if (!empty($fullEvent)) {
            $pubSubTool = $this->getPubSubTool();
            $pubSubTool->publishEvent($fullEvent[0], 'publish');
        }
    }

    public function publishEventToKafka($id, $user, &$fullEvent, $kafkaTopic)
    {
        $fullEvent = $this->__prepareEventForPubSub($id, $user, $fullEvent);
        if (!empty($fullEvent)) {
            $kafkaPubTool = $this->getKafkaPubTool();
            $kafkaPubTool->publishJson($kafkaTopic, $fullEvent[0], 'publish');
        }
    }

    public function captureAnalystData($user, $data, $parentObjectType, $parentObjectUUID)
    {
        $this->Note = ClassRegistry::init('Note');
        $this->Opinion = ClassRegistry::init('Opinion');
        $this->Relationship = ClassRegistry::init('Relationship');
        foreach ($this->Note::ANALYST_DATA_TYPES as $type) {
            if (!empty($data[$type])) {
                foreach ($data[$type] as $analystData) {
                    $analystData['note_type_name'] = $type;
                    $analystData['object_type'] = $parentObjectType;
                    $analystData['object_uuid'] = $parentObjectUUID;
                    $this->{$type}->captureAnalystData($user, $analystData);
                }
            }
        }
    }

    public function getTrendsForTags(array $user, array $eventFilters=[], int $baseDayRange, int $rollingWindows=3, $tagFilterPrefixes=null): array
    {
        $fullDayNumber = $baseDayRange + $baseDayRange * $rollingWindows;
        $fullRange = $this->resolveTimeDelta($fullDayNumber . 'd');
        $eventFilters['last'] = $fullRange . 'd';
        $eventFilters['order'] = 'timestamp DESC';
        $events = $this->fetchEvent($user, $eventFilters);
        App::uses('TrendingTool', 'Tools');
        $trendingTool = new TrendingTool($this);
        $trendAnalysis = $trendingTool->getTrendsForTags($events, $baseDayRange, $rollingWindows, $tagFilterPrefixes);
        $clusteredTags = $trendAnalysis['clustered_tags'];
        $trendAnalysis = $trendAnalysis['trend_analysis'];
        return [
            'clustered_tags' => $trendAnalysis,
            'clustered_events' => $clusteredTags['eventNumberPerRollingWindow'],
            'all_tags' => $clusteredTags['allTagsPerPrefix'],
            'all_timestamps' => array_keys($clusteredTags['eventNumberPerRollingWindow']),
        ];
    }

    public function getTrendsForTagsFromEvents(array $events, int $baseDayRange, int $rollingWindows=3, $tagFilterPrefixes=null): array
    {
        $oldestTimestamp = $this->resolveTimeDelta($baseDayRange + $baseDayRange * $rollingWindows . 'd');
        $events = array_filter($events, function($event) use ($oldestTimestamp) { // Filter out events having old modification compared to their publish_timestamp
            return $event['Event']['timestamp'] >= $oldestTimestamp;
        });
        App::uses('TrendingTool', 'Tools');
        $trendingTool = new TrendingTool($this);
        $trendAnalysis = $trendingTool->getTrendsForTags($events, $baseDayRange, $rollingWindows, $tagFilterPrefixes);
        $clusteredTags = $trendAnalysis['clustered_tags'];
        $trendAnalysis = $trendAnalysis['trend_analysis'];
        return [
            'clustered_tags' => $trendAnalysis,
            'clustered_events' => $clusteredTags['eventNumberPerRollingWindow'],
            'all_tags' => $clusteredTags['allTagsPerPrefix'],
            'all_timestamps' => array_keys($clusteredTags['eventNumberPerRollingWindow']),
        ];
    }

    public function extractRelatedCourseOfActions(array $events): array
    {
        $mitre_attack_galaxy_type = 'mitre-attack-pattern';
        $mitre_coa_galaxy_type = 'mitre-course-of-action';
        $allowedRelationTypes = ['mitigates'];
        $coa = [];
        foreach ($events as $event) {
            foreach ($event['Galaxy'] as $galaxy) {
                foreach ($galaxy['GalaxyCluster'] as $cluster) {
                    foreach ($cluster['GalaxyClusterRelation'] as $relation) {
                        if (in_array($relation['referenced_galaxy_cluster_type'], $allowedRelationTypes) && $relation['TargetCluster']['type'] == $mitre_coa_galaxy_type) {
                            if (!isset($coa[$relation['TargetCluster']['tag_name']])) {
                                $coa[$relation['TargetCluster']['tag_name']] = $relation['TargetCluster'];
                                $coa[$relation['TargetCluster']['tag_name']]['occurrence'] = 0;
                                $coa[$relation['TargetCluster']['tag_name']]['techniques'] = [];
                            }
                            $coa[$relation['TargetCluster']['tag_name']]['occurrence'] += 1;
                            if ($cluster['type'] == $mitre_attack_galaxy_type) {
                                $coa[$relation['TargetCluster']['tag_name']]['techniques'][$cluster['tag_name']] = $cluster;
                            }
                        }
                    }
                    if (!empty($cluster['TargetingClusterRelation'])) {
                        foreach ($cluster['TargetingClusterRelation'] as $relation) {
                            if (in_array($relation['referenced_galaxy_cluster_type'], $allowedRelationTypes) && $relation['GalaxyCluster']['type'] == $mitre_coa_galaxy_type) {
                                if (!isset($coa[$relation['GalaxyCluster']['tag_name']])) {
                                    $coa[$relation['GalaxyCluster']['tag_name']] = $relation['GalaxyCluster'];
                                    $coa[$relation['GalaxyCluster']['tag_name']]['techniques'] = [];
                                    $coa[$relation['GalaxyCluster']['tag_name']]['occurrence'] = 0;
                                }
                                $coa[$relation['GalaxyCluster']['tag_name']]['occurrence'] += 1;
                                if ($cluster['type'] == $mitre_attack_galaxy_type
                                ) {
                                    $coa[$relation['GalaxyCluster']['tag_name']]['techniques'][$cluster['tag_name']] = $cluster;
                                }
                            }
                        }
                    }
                }
            }
        }
        uasort($coa, function ($a, $b) {
            return $a['occurrence'] > $b['occurrence'] ? -1 : 1;
        });

        return $coa;
    }
}
