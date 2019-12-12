<?php
App::uses('AppModel', 'Model');
App::uses('CakeEmail', 'Network/Email');
App::uses('RandomTool', 'Tools');

class Event extends AppModel
{
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
                    'scope' => 'Event',
                    'requiresPublished' => 0,
                    'params' => array('includeAttachments' => 1, 'ignore' => 1, 'returnFormat' => 'json'),
                    'description' => 'Click this to download all events and attributes that you have access to in MISP JSON format.',
            ),
            'xml' => array(
                    'extension' => '.xml',
                    'type' => 'XML',
                    'scope' => 'Event',
                    'params' => array('includeAttachments' => 1, 'ignore' => 1, 'returnFormat' => 'xml'),
                    'requiresPublished' => 0,
                    'description' => 'Click this to download all events and attributes that you have access to in MISP XML format.',
            ),
            'csv_sig' => array(
                    'extension' => '.csv',
                    'type' => 'CSV_Sig',
                    'scope' => 'Event',
                    'requiresPublished' => 1,
                    'params' => array('published' => 1, 'to_ids' => 1, 'returnFormat' => 'csv'),
                    'description' => 'Click this to download all attributes that are indicators and that you have access to <small>(except file attachments)</small> in CSV format.',
            ),
            'csv_all' => array(
                    'extension' => '.csv',
                    'type' => 'CSV_All',
                    'scope' => 'Event',
                    'requiresPublished' => 0,
                    'params' => array('ignore' => 1, 'returnFormat' => 'csv'),
                    'description' => 'Click this to download all attributes that you have access to <small>(except file attachments)</small> in CSV format.',
            ),
            'suricata' => array(
                    'extension' => '.rules',
                    'type' => 'Suricata',
                    'scope' => 'Attribute',
                    'requiresPublished' => 1,
                    'params' => array('returnFormat' => 'suricata'),
                    'description' => 'Click this to download all network related attributes that you have access to under the Suricata rule format. Only published events and attributes marked as IDS Signature are exported. Administration is able to maintain a whitelist containing host, domain name and IP numbers to exclude from the NIDS export.',
            ),
            'snort' => array(
                    'extension' => '.rules',
                    'type' => 'Snort',
                    'scope' => 'Attribute',
                    'requiresPublished' => 1,
                    'params' => array('returnFormat' => 'snort'),
                    'description' => 'Click this to download all network related attributes that you have access to under the Snort rule format. Only published events and attributes marked as IDS Signature are exported. Administration is able to maintain a whitelist containing host, domain name and IP numbers to exclude from the NIDS export.',
            ),
            'bro' => array(
                    'extension' => '.intel',
                    'type' => 'Bro',
                    'scope' => 'Attribute',
                    'requiresPublished' => 1,
                    'params' => array('returnFormat' => 'bro'),
                    'description' => 'Click this to download all network related attributes that you have access to under the Bro rule format. Only published events and attributes marked as IDS Signature are exported. Administration is able to maintain a whitelist containing host, domain name and IP numbers to exclude from the NIDS export.',
            ),
            'stix' => array(
                    'extension' => '.xml',
                    'type' => 'STIX',
                    'scope' => 'Event',
                    'requiresPublished' => 1,
                    'params' => array('returnFormat' => 'stix', 'includeAttachments' => 1),
                    'description' => 'Click this to download a STIX document containing the STIX version of all events and attributes that you have access to.'
            ),
            'stix-json' => array(
                    'extension' => '.json',
                    'type' => 'STIX',
                    'scope' => 'Event',
                    'requiresPublished' => 1,
                    'params' => array('returnFormat' => 'stix', 'includeAttachments' => 1),
                    'description' => 'Click this to download a STIX document containing the STIX version of all events and attributes that you have access to.'
            ),
            'stix2' => array(
                    'extension' => '.json',
                    'type' => 'STIX2',
                    'scope' => 'Event',
                    'requiresPublished' => 1,
                    'params' => array('returnFormat' => 'stix2', 'includeAttachments' => 1),
                    'description' => 'Click this to download a STIX2 document containing the STIX2 version of all events and attributes that you have access to.'
            ),
            'rpz' => array(
                    'extension' => '.txt',
                    'type' => 'RPZ',
                    'scope' => 'Attribute',
                    'requiresPublished' => 1,
                    'params' => array('returnFormat' => 'rpz'),
                    'description' => 'Click this to download an RPZ Zone file generated from all ip-src/ip-dst, hostname, domain attributes. This can be useful for DNS level firewalling. Only published events and attributes marked as IDS Signature are exported.'
            ),
            'text' => array(
                    'extension' => '.txt',
                    'type' => 'TEXT',
                    'scope' => 'Attribute',
                    'requiresPublished' => 1,
                    'params' => array('returnFormat' => 'text', 'includeAttachments' => 1),
                    'description' => 'Click on one of the buttons below to download all the attributes with the matching type. This list can be used to feed forensic software when searching for susipicious files. Only published events and attributes marked as IDS Signature are exported.'
            ),
            'yara' => array(
                    'extension' => '.yara',
                    'type' => 'Yara',
                    'scope' => 'Event',
                    'requiresPublished' => 1,
                    'params' => array('returnFormat' => 'yara'),
                    'description' => 'Click this to download Yara rules generated from all relevant attributes.'
            ),
            'yara-json' => array(
                    'extension' => '.json',
                    'type' => 'Yara',
                    'scope' => 'Event',
                    'requiresPublished' => 1,
                    'params' => array('returnFormat' => 'yara-json'),
                    'description' => 'Click this to download Yara rules generated from all relevant attributes. Rules are returned in a JSON format with information about origin (generated or parsed) and validity.'
            ),
    );

    public $validFormats = array(
        'json' => array('json', 'JsonExport', 'json'),
        'openioc' => array('xml', 'OpeniocExport', 'ioc'),
        'xml' => array('xml', 'XmlExport', 'xml'),
        'suricata' => array('txt', 'NidsSuricataExport', 'rules'),
        'snort' => array('txt', 'NidsSnortExport', 'rules'),
        'rpz' => array('txt', 'RPZExport', 'rpz'),
        'text' => array('text', 'TextExport', 'txt'),
        'hashes' => array('txt', 'HashesExport', 'txt'),
        'csv' => array('csv', 'CsvExport', 'csv'),
        'stix' => array('xml', 'Stix1Export', 'xml'),
        'stix-json' => array('json', 'Stix1Export', 'json'),
        'stix2' => array('json', 'Stix2Export', 'json'),
        'yara' => array('txt', 'YaraExport', 'yara'),
        'yara-json' => array('json', 'YaraExport', 'json'),
        'cache' => array('txt', 'CacheExport', 'cache'),
        'attack' => array('html', 'AttackExport', 'html'),
        'attack-sightings' => array('json', 'AttackSightingsExport', 'json'),
        'netfilter' => array('txt', 'NetfilterExport', 'sh')
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
                'rule' => array('custom', '/^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/'),
                'message' => 'Please provide a valid UUID'
            ),
        ),
        'extends_uuid' => array(
            'uuid' => array(
                'rule' => array('custom', '/^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/'),
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
            'className' => 'Attribute',
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
        )
    );

    public function __construct($id = false, $table = null, $ds = null)
    {
        parent::__construct($id, $table, $ds);

        $this->export_types = array(
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
                    'description' => __('Click this to download all network related attributes that you have access to under the Suricata rule format. Only published events and attributes marked as IDS Signature are exported. Administration is able to maintain a whitelist containing host, domain name and IP numbers to exclude from the NIDS export.'),
            ),
            'snort' => array(
                    'extension' => '.rules',
                    'type' => 'Snort',
                    'scope' => 'Attribute',
                    'requiresPublished' => 1,
                    'params' => array('returnFormat' => 'snort'),
                    'description' => __('Click this to download all network related attributes that you have access to under the Snort rule format. Only published events and attributes marked as IDS Signature are exported. Administration is able to maintain a whitelist containing host, domain name and IP numbers to exclude from the NIDS export.'),
            ),
            'bro' => array(
                    'extension' => '.intel',
                    'type' => 'Bro',
                    'scope' => 'Attribute',
                    'requiresPublished' => 1,
                    'params' => array('returnFormat' => 'bro'),
                    'description' => __('Click this to download all network related attributes that you have access to under the Bro rule format. Only published events and attributes marked as IDS Signature are exported. Administration is able to maintain a whitelist containing host, domain name and IP numbers to exclude from the NIDS export.'),
            ),
            'stix' => array(
                    'extension' => '.xml',
                    'type' => 'STIX',
                    'scope' => 'Event',
                    'requiresPublished' => 1,
                    'params' => array('returnFormat' => 'stix', 'includeAttachments' => 1),
                    'description' => __('Click this to download an a STIX document containing the STIX version of all events and attributes that you have access to.')
            ),
            'stix2' => array(
                    'extension' => '.json',
                    'type' => 'STIX2',
                    'scope' => 'Event',
                    'requiresPublished' => 1,
                    'params' => array('returnFormat' => 'stix2', 'includeAttachments' => 1),
                    'description' => __('Click this to download an a STIX2 document containing the STIX2 version of all events and attributes that you have access to.')
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

    public function beforeDelete($cascade = true)
    {
        // blacklist the event UUID if the feature is enabled
        if (Configure::read('MISP.enableEventBlacklisting') !== false && empty($this->skipBlacklist)) {
            $this->EventBlacklist = ClassRegistry::init('EventBlacklist');
            $this->EventBlacklist->create();
            $orgc = $this->Orgc->find('first', array('conditions' => array('Orgc.id' => $this->data['Event']['orgc_id']), 'recursive' => -1, 'fields' => array('Orgc.name')));
            $this->EventBlacklist->save(array('event_uuid' => $this->data['Event']['uuid'], 'event_info' => $this->data['Event']['info'], 'event_orgc' => $orgc['Orgc']['name']));
            if (!empty($this->data['Event']['id'])) {
                if (Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_event_notifications_enable')) {
                    $pubSubTool = $this->getPubSubTool();
                    $pubSubTool->event_save(array('Event' => $this->data['Event']), 'delete');
                }
                if (Configure::read('Plugin.Kafka_enable')) {
                    $kafkaEventTopic = Configure::read('Plugin.Kafka_event_notifications_topic');
                    if(Configure::read('Plugin.Kafka_event_notifications_enable') && !empty($kafkaEventTopic)) {
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
        }

        // delete all of the event->tag combinations that involve the deleted event
        $this->EventTag->deleteAll(array('event_id' => $this->id));

        // only delete the file if it exists
        $attachments_dir = Configure::read('MISP.attachments_dir');
        if (empty($attachments_dir)) {
            $attachments_dir = $this->getDefaultAttachments_dir();
        }

        // Things get a little funky here
        if ($this->attachmentDirIsS3()) {
            // S3 doesn't have folders
            // So we have to basically `ls` them to look for a prefix
            $s3 = $this->getS3Client();
            $s3->deleteDirectory($this->id);
        } else {
            $filepath = $attachments_dir . DS . $this->id;
            App::uses('Folder', 'Utility');
            if (is_dir($filepath)) {
                if (!$this->destroyDir($filepath)) {
                    throw new InternalErrorException('Delete of event file directory failed. Please report to administrator.');
                }
            }
        }
    }

    public function destroyDir($dir)
    {
        if (!is_dir($dir) || is_link($dir)) {
            return unlink($dir);
        }
        foreach (scandir($dir) as $file) {
            if ($file == '.' || $file == '..') {
                continue;
            }
            if (!$this->destroyDir($dir . DS . $file)) {
                chmod($dir . DS . $file, 0777);
                if (!$this->destroyDir($dir . DS . $file)) {
                    return false;
                }
            }
        }
        return rmdir($dir);
    }

    public function beforeValidate($options = array())
    {
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

        if (!isset($this->data['Event']['threat_level_id'])) {
            $this->data['Event']['threat_level_id'] = Configure::read('MISP.default_event_threat_level') ? Configure::read('MISP.default_event_threat_level') : 4;
        }

        // generate UUID if it doesn't exist
        if (empty($this->data['Event']['uuid'])) {
            $this->data['Event']['uuid'] = CakeText::uuid();
        }

        // Convert event ID to uuid if needed
        if (!empty($this->data['Event']['extends_uuid']) && is_numeric($this->data['Event']['extends_uuid'])) {
            $extended_event = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('Event.id' => $this->data['Event']['extends_uuid']),
                'fields' => array('Event.uuid')
            ));
            if (empty($extended_event)) {
                $this->data['Event']['extends_uuid'] = '';
            } else {
                $this->data['Event']['extends_uuid'] = $extended_event['Event']['uuid'];
            }
        }

        // generate timestamp if it doesn't exist
        if (empty($this->data['Event']['timestamp'])) {
            $date = new DateTime();
            $this->data['Event']['timestamp'] = $date->getTimestamp();
        }

        if (empty($this->data['Event']['date'])) {
            $this->data['Event']['date'] = date('Y-m-d');
        }

        if (!isset($this->data['Event']['distribution']) || $this->data['Event']['distribution'] != 4) {
            $this->data['Event']['sharing_group_id'] = 0;
        }
    }

    public function afterSave($created, $options = array())
    {
        if (!Configure::read('MISP.completely_disable_correlation') && !$created) {
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
            if (!empty($event)) {
                $pubSubTool->event_save($event, $created ? 'add' : 'edit');
            }
        }
        if (empty($this->data['Event']['unpublishAction']) && empty($this->data['Event']['skip_kafka'])) {
            $this->publishKafkaNotification('event', $this->quickFetchEvent($this->data['Event']['id']), $created ? 'add' : 'edit');
        }
    }

    public function buildEventConditions($user)
    {
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

    public function isOwnedByOrg($eventid, $org)
    {
        return $this->field('id', array('id' => $eventid, 'org_id' => $org)) === $eventid;
    }

    public function attachtagsToEvents($events)
    {
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
    public function attachCorrelationCountToEvents($user, $events)
    {
        $sgids = $this->SharingGroup->fetchAllAuthorised($user);
        if (!isset($sgids) || empty($sgids)) {
            $sgids = array(-1);
        }
        $this->Correlation = ClassRegistry::init('Correlation');
        $eventIds = Set::extract('/Event/id', $events);
        $conditionsCorrelation = $this->__buildEventConditionsCorrelation($user, $eventIds, $sgids);
        $correlations = $this->Correlation->find('all', array(
            'fields' => array('Correlation.1_event_id', 'count(distinct(Correlation.event_id)) as count'),
            'conditions' => $conditionsCorrelation,
            'recursive' => -1,
            'group' => array('Correlation.1_event_id'),
        ));
        $correlations = Hash::combine($correlations, '{n}.Correlation.1_event_id', '{n}.0.count');
        foreach ($events as &$event) {
            $event['Event']['correlation_count'] = (isset($correlations[$event['Event']['id']])) ? $correlations[$event['Event']['id']] : 0;
        }
        return $events;
    }

    public function attachSightingsCountToEvents($user, $events)
    {
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

    public function attachProposalsCountToEvents($user, $events)
    {
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

    public function attachDiscussionsCountToEvents($user, $events)
    {
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

    private function __buildEventConditionsCorrelation($user, $eventIds, $sgids)
    {
        if (!is_array($eventIds)) {
            $eventIds = array($eventIds);
        }
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

    public function getRelatedEvents($user, $eventId = null, $sgids)
    {
        if ($eventId == null) {
            $eventId = $this->data['Event']['id'];
        }
        if (!isset($sgids) || empty($sgids)) {
            $sgids = array(-1);
        }
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
        $relatedEvents = $this->find(
            'all',
            array('conditions' => $conditions,
                'recursive' => -1,
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

    public function getRelatedAttributes($user, $id = null, $sgids, $shadowAttribute = false, $scope = 'event')
    {
        $context = $shadowAttribute ? 'ShadowAttribute' : 'Attribute';
        $settings = array(
            'Attribute' => array('model' => 'Attribute', 'correlationModel' => 'Correlation', 'parentIdField' => '1_attribute_id'),
            'ShadowAttribute' => array('model' => 'ShadowAttribute', 'correlationModel' => 'ShadowAttributeCorrelation', 'parentIdField' => '1_shadow_attribute_id')
        );
        if ($scope === 'event' && $id == null) {
            $id = $this->data['Event']['id'];
        } elseif ($scope === 'attribute' && $id == null) {
            $id = $this->data['Attribute']['id'];
        }
        if (!isset($sgids) || empty($sgids)) {
            $sgids = array(-1);
        }
        $this->{$settings[$context]['correlationModel']} = ClassRegistry::init($settings[$context]['correlationModel']);
        if (!$user['Role']['perm_site_admin']) {
            $conditionsCorrelation = array(
                    'AND' => array(
                            $settings[$context]['correlationModel'] . '.1_' . $scope . '_id' => $id,
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
            $conditionsCorrelation = array($settings[$context]['correlationModel'] . '.1_' . $scope . '_id' => $id);
        }
        $max_correlations = Configure::read('MISP.max_correlations_per_event');
        if (empty($max_correlations)) {
            $max_correlations = 5000;
        }
        $correlations = $this->{$settings[$context]['correlationModel']}->find('all', array(
                'fields' => $settings[$context]['correlationModel'] . '.*',
                'conditions' => $conditionsCorrelation,
                'recursive' => -1,
                'order' => false,
                'limit' => $max_correlations
        ));
        $relatedAttributes = array();
        $orgc_ids = array();
        foreach ($correlations as $k => $correlation) {
            if (empty($orgc_ids[$correlation[$settings[$context]['correlationModel']]['event_id']])) {
                $temp = $this->find('first', array(
                    'recursive' => -1,
                    'conditions' => array('Event.id' => $correlation[$settings[$context]['correlationModel']]['event_id']),
                    'fields' => array('Event.orgc_id')
                ));
                if (!empty($temp)) {
                    $orgc_ids[$correlation[$settings[$context]['correlationModel']]['event_id']] = $temp['Event']['orgc_id'];
                }
            }
            $current = array(
                    'id' => $correlation[$settings[$context]['correlationModel']]['event_id'],
                    'attribute_id' => $correlation[$settings[$context]['correlationModel']]['attribute_id'],
                    'info' => $correlation[$settings[$context]['correlationModel']]['info'],
                    'value' => $correlation[$settings[$context]['correlationModel']]['value'],
            );
            if (!empty($orgc_ids[$correlation[$settings[$context]['correlationModel']]['event_id']])) {
                $current['org_id'] = $orgc_ids[$correlation[$settings[$context]['correlationModel']]['event_id']];
            } else {
                $current['org_id'] = 'unknown';
            }
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
    public function cleanupEventArrayFromXML(&$data)
    {
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
            if (isset($data['Event'][$object][0])) {
                $data['Event'][$object] = $data['Event'][$object][0];
            }
        }
        return $data;
    }

    private function __resolveErrorCode($code, &$event, &$server)
    {
        $error = false;
        switch ($code) {
            case 403:
                return 'The distribution level of this event blocks it from being pushed.';
            case 405:
                $error = 'The sync user on the remote instance does not have the required privileges to handle this event.';
                break;
        }
        if ($error) {
            $newTextBody = 'Uploading Event (' . $event['Event']['id'] . ') to Server (' . $server['Server']['id'] . ')';
            $this->__logUploadResult($server, $event, $newTextBody);
        }
        return $error;
    }

    private function __executeRestfulEventToServer($event, $server, $resourceId, &$newLocation, &$newTextBody, $HttpSocket, $scope)
    {
        $result = $this->restfulEventToServer($event, $server, $resourceId, $newLocation, $newTextBody, $HttpSocket, $scope);
        if (is_numeric($result)) {
            $error = $this->__resolveErrorCode($result, $event, $server);
            if ($error) {
                return $error . ' Error code: ' . $result;
            }
        }
        return true;
    }

    public function uploadSightingsToServer($sightings, $server, $event_uuid, $HttpSocket = null)
    {
        $HttpSocket = $this->setupHttpSocket($server, $HttpSocket);
        $request = $this->setupSyncRequest($server);
        $uri = $server['Server']['url'] . '/sightings/bulkSaveSightings/' . $event_uuid;
        foreach ($sightings as &$sighting) {
            if (!isset($sighting['org_id'])) {
                $sighting['org_id'] = '0';
            }
        }
        $data = json_encode($sightings);
        if (!empty(Configure::read('Security.sync_audit'))) {
            $pushLogEntry = sprintf(
                "==============================================================\n\n[%s] Pushing Sightings for Event #%s to Server #%d:\n\n%s\n\n",
                date("Y-m-d H:i:s"),
                $event_uuid,
                $server['Server']['id'],
                $data
            );
            file_put_contents(APP . 'files/scripts/tmp/debug_server_' . $server['Server']['id'] . '.log', $pushLogEntry, FILE_APPEND);
        }
        $response = $HttpSocket->post($uri, $data, $request);
        return $this->__handleRestfulEventToServerResponse($response, $newLocation, $newTextBody);
    }

    public function uploadEventToServer($event, $server, $HttpSocket = null, $scope = 'events')
    {
        $this->Server = ClassRegistry::init('Server');
        $push = $this->Server->checkVersionCompatibility($server['Server']['id'], false, $HttpSocket);
        if ($scope === 'events' && empty($push['canPush'])) {
            return 'The remote user is not a sync user - the upload of the event has been blocked.';
        } elseif ($scope === 'sightings' && empty($push['canPush']) && empty($push['canSight'])) {
            return 'The remote user is not a sightings user - the upload of the sightings has been blocked.';
        }
        if (!empty($server['Server']['unpublish_event'])) {
            $event['Event']['published'] = 0;
        }
        $updated = null;
        $newLocation = $newTextBody = '';
        $result = $this->__executeRestfulEventToServer($event, $server, null, $newLocation, $newTextBody, $HttpSocket, $scope);
        if ($result !== true) {
            return $result;
        }
        if (strlen($newLocation)) { // HTTP/1.1 302 Found and Location: http://<newLocation>
            $result = $this->__executeRestfulEventToServer($event, $server, $newLocation, $newLocation, $newTextBody, $HttpSocket, $scope);
            if ($result !== true) {
                return $result;
            }
        }
        $uploadFailed = false;
        try {
            $json = json_decode($newTextBody, true);
        } catch (Exception $e) {
            $uploadFailed = true;
        }
        if (!is_array($json) || $uploadFailed) {
            return $this->__logUploadResult($server, $event, $newTextBody);
        }
        return 'Success';
    }

    private function __prepareForPushToServer($event, $server)
    {
        if ($event['Event']['distribution'] == 4) {
            if (!empty($event['SharingGroup']['SharingGroupServer'])) {
                $found = false;
                foreach ($event['SharingGroup']['SharingGroupServer'] as $sgs) {
                    if ($sgs['server_id'] == $server['Server']['id']) {
                        $found = true;
                    }
                }
                if (!$found) {
                    return 403;
                }
            } else if (empty($event['SharingGroup']['roaming'])) {
                return 403;
            }
        }
        $serverModel = ClassRegistry::init('Server');
        $server = $serverModel->eventFilterPushableServers($event, array($server));
        if (empty($server)) {
            return 403;
        }
        $server = $server[0];
        if ($this->checkDistributionForPush($event, $server, 'Event')) {
            $event = $this->__updateEventForSync($event, $server);
        } else {
            return 403;
        }
        return $event;
    }

    private function __getLastUrlPathComponent($urlPath)
    {
        if (!empty($urlPath)) {
            $pieces = explode('/', $urlPath);
            return '/' . end($pieces);
        }
        return '';
    }

    private function __handleRestfulEventToServerResponse($response, &$newLocation, &$newTextBody)
    {
        switch ($response->code) {
            case '200': // 200 (OK) + entity-action-result
                if ($response->isOk()) {
                    $newTextBody = $response->body();
                    return true;
                } else {
                    try {
                        $jsonArray = json_decode($response->body, true);
                    } catch (Exception $e) {
                        return true;
                    }
                    return $jsonArray['name'];
                }
                // no break
            case '302': // Found
                $newLocation = $response->headers['Location'];
                $newTextBody = $response->body();
                return true;
            case '404': // Not Found
                $newLocation = $response->headers['Location'];
                $newTextBody = $response->body();
                return 404;
            case '405':
                return 405;
            case '403': // Not authorised
                return 403;
        }
    }

    // Uploads the event and the associated Attributes to another Server
    public function restfulEventToServer($event, $server, $urlPath, &$newLocation, &$newTextBody, $HttpSocket = null, $scope)
    {
        $event = $this->__prepareForPushToServer($event, $server);
        if (is_numeric($event)) {
            return $event;
        }
        $url = $server['Server']['url'];
        $HttpSocket = $this->setupHttpSocket($server, $HttpSocket);
        $request = $this->setupSyncRequest($server);
        if ($scope === 'sightings') {
            $scope .= '/bulkSaveSightings';
            $urlPath = $event['Event']['uuid'];
        }
        $uri = $url . '/' . $scope . $this->__getLastUrlPathComponent($urlPath);
        $data = json_encode($event);
        if (!empty(Configure::read('Security.sync_audit'))) {
            $pushLogEntry = sprintf(
                "==============================================================\n\n[%s] Pushing Event #%d to Server #%d:\n\n%s\n\n",
                date("Y-m-d H:i:s"),
                $event['Event']['id'],
                $server['Server']['id'],
                $data
            );
            file_put_contents(APP . 'files/scripts/tmp/debug_server_' . $server['Server']['id'] . '.log', $pushLogEntry, FILE_APPEND);
        }
        $response = $HttpSocket->post($uri, $data, $request);
        return $this->__handleRestfulEventToServerResponse($response, $newLocation, $newTextBody);
    }

    private function __rearrangeEventStructureForSync($event)
    {
        // rearrange things to be compatible with the Xml::fromArray()
        $objectsToRearrange = array('Attribute', 'Object', 'Orgc', 'SharingGroup', 'EventTag', 'Org', 'ShadowAttribute');
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
        return $event;
    }

    // since we fetch the event and filter on tags after / server, we need to cull all of the non exportable tags
    private function __removeNonExportableTags($data, $dataType)
    {
        if (!empty($data[$dataType . 'Tag'])) {
            foreach ($data[$dataType . 'Tag'] as $k => $tag) {
                if (!$tag['Tag']['exportable'] || !empty($tag['local'])) {
                    unset($data[$dataType . 'Tag'][$k]);
                } else {
                    unset($tag['org_id']);
                    $data['Tag'][] = $tag['Tag'];
                }
            }
            unset($data[$dataType . 'Tag']);
        }
        return $data;
    }

    private function __prepareAttributesForSync($data, $server)
    {
        // prepare attribute for sync
        if (!empty($data['Attribute'])) {
            foreach ($data['Attribute'] as $key => $attribute) {
                $data['Attribute'][$key] = $this->__updateAttributeForSync($attribute, $server);
                if (empty($data['Attribute'][$key])) {
                    unset($data['Attribute'][$key]);
                } else {
                    $data['Attribute'][$key] = $this->__removeNonExportableTags($data['Attribute'][$key], 'Attribute');
                }
            }
            $data['Attribute'] = array_values($data['Attribute']);
        }
        return $data;
    }

    private function __prepareObjectsForSync($data, $server)
    {
        // prepare Object for sync
        if (!empty($data['Object'])) {
            foreach ($data['Object'] as $key => $object) {
                $data['Object'][$key] = $this->__updateObjectForSync($object, $server);
                if (empty($data['Object'][$key])) {
                    unset($data['Object'][$key]);
                } else {
                    $data['Object'][$key] = $this->__prepareAttributesForSync($data['Object'][$key], $server);
                }
            }
            $data['Object'] = array_values($data['Object']);
        }
        return $data;
    }

    private function __updateEventForSync($event, $server)
    {
        $event = $this->__rearrangeEventStructureForSync($event);
        $event['Event'] = $this->__removeNonExportableTags($event['Event'], 'Event');
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
        $event['Event'] = $this->__prepareAttributesForSync($event['Event'], $server);
        $event['Event'] = $this->__prepareObjectsForSync($event['Event'], $server);

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

    private function __getAnnounceBaseurl()
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

    public function downloadEventFromServer($eventId, $server, $HttpSocket=null)
    {
        $url = $server['Server']['url'];
        $HttpSocket = $this->setupHttpSocket($server, $HttpSocket);
        $request = $this->setupSyncRequest($server);
        $uri = $url . '/events/view/' . $eventId . '/deleted[]:0/deleted[]:1/excludeGalaxy:1';
        $response = $HttpSocket->get($uri, $data = '', $request);
        if ($response->isOk()) {
            return json_decode($response->body, true);
        }
        return null;
    }

    public function quickDelete($event)
    {
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
            $relations[] =  array(
                'table' => 'posts',
                'foreign_key' => 'thread_id',
                'value' => $thread_id
            );
        }
        if (!Configure::read('MISP.completely_disable_correlation')) {
            array_push(
                $relations,
                array(
                    'table' => 'correlations',
                    'foreign_key' => 'event_id',
                    'value' => $id
                ),
                array(
                    'table' => 'correlations',
                    'foreign_key' => '1_event_id',
                    'value' => $id
                )
            );
        }
        App::uses('QueryTool', 'Tools');
        $queryTool = new QueryTool();
        foreach ($relations as $relation) {
            $queryTool->quickDelete($relation['table'], $relation['foreign_key'], $relation['value'], $this);
        }
        return $this->delete($id, false);
    }

    public function downloadProposalsFromServer($uuidList, $server, $HttpSocket = null)
    {
        $url = $server['Server']['url'];
        $HttpSocket = $this->setupHttpSocket($server, $HttpSocket);
        $request = $this->setupSyncRequest($server);
        $uri = $url . '/shadow_attributes/getProposalsByUuidList';
        $response = $HttpSocket->post($uri, json_encode($uuidList), $request);
        if ($response->isOk()) {
            return(json_decode($response->body, true));
        } else {
            return false;
        }
    }

    public function createEventConditions($user)
    {
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
        $tagIds = $this->AttributeTag->Tag->find('list', array(
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
        $tagScopes = array('Event', 'Attribute');
        $this->AttributeTag = ClassRegistry::init('AttributeTag');
        $tagIds = $this->AttributeTag->Tag->find('list', array(
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
            $tempConditions[] = $this->subQueryGenerator($this->AttributeTag, $subQueryOptions, 'Attribute.id');
        }
        return $tempConditions;
    }

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
                    'tags' => array('function' => 'set_filter_tags'),
                    'from' => array('function' => 'set_filter_timestamp', 'pop' => true),
                    'to' => array('function' => 'set_filter_timestamp', 'pop' => true),
                    'date' => array('function' => 'set_filter_date', 'pop' => true),
                    'last' => array('function' => 'set_filter_timestamp', 'pop' => true),
                    'timestamp' => array('function' => 'set_filter_timestamp', 'pop' => true),
                    'event_timestamp' => array('function' => 'set_filter_timestamp', 'pop' => true),
                    'publish_timestamp' => array('function' => 'set_filter_timestamp', 'pop' => true),
                    'org' => array('function' => 'set_filter_org', 'pop' => true),
                    'uuid' => array('function' => 'set_filter_uuid', 'pop' => true),
                    'published' => array('function' => 'set_filter_published', 'pop' => true)
                ),
                'Object' => array(
                    'object_name' => array('function' => 'set_filter_object_name'),
                    'deleted' => array('function' => 'set_filter_deleted')
                ),
                'Attribute' => array(
                    'value' => array('function' => 'set_filter_value'),
                    'category' => array('function' => 'set_filter_simple_attribute'),
                    'type' => array('function' => 'set_filter_simple_attribute'),
                    'object_relation' => array('function' => 'set_filter_simple_attribute'),
                    'tags' => array('function' => 'set_filter_tags', 'pop' => true),
                    'ignore' => array('function' => 'set_filter_ignore'),
                    'uuid' => array('function' => 'set_filter_uuid'),
                    'deleted' => array('function' => 'set_filter_deleted'),
                    'to_ids' => array('function' => 'set_filter_to_ids'),
                    'comment' => array('function' => 'set_filter_comment')
                )
            );
            foreach ($params as $param => $paramData) {
                foreach ($simple_params as $scope => $simple_param_scoped) {
                    if (isset($simple_param_scoped[$param]) && $params[$param] !== false) {
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

        $fields = array('Event.id');
        if (!empty($params['include_attribute_count'])) {
            $fields[] = 'Event.attribute_count';
        }
        $find_params = array(
            'conditions' => $conditions,
            'recursive' => -1,
            'fields' => $fields
        );
        if (isset($params['limit'])) {
            // Get the count (but not the actual data) of results for paginators
            $result_count = $this->find('count', $find_params);
            $find_params['limit'] = $params['limit'];
            if (isset($params['page'])) {
                $find_params['page'] = $params['page'];
            }
        }
        $results = $this->find('list', $find_params);
        if (!isset($params['limit'])) {
            $result_count = count($results);
        }
        return $results;
    }

    public function fetchSimpleEventIds($user, $params = array())
    {
        $conditions = $this->createEventConditions($user);
        $conditions['AND'][] = $params['conditions'];
        $results = array_values($this->find('list', array(
            'conditions' => $conditions,
            'recursive' => -1,
            'fields' => array('Event.id')
        )));
        return $results;
    }

    public function fetchSimpleEvents($user, $params, $includeOrgc = false)
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
        $results = array_values($this->find('all', $params));
        return $results;
    }

    public function fetchEventIds($user, $from = false, $to = false, $last = false, $list = false, $timestamp = false, $publish_timestamp = false, $eventIdList = false)
    {
        // restricting to non-private or same org if the user is not a site-admin.
        $conditions = $this->createEventConditions($user);
        $fields = array('Event.id', 'Event.org_id', 'Event.distribution', 'Event.sharing_group_id');

        if ($from) {
            $conditions['AND'][] = array('Event.date >=' => $from);
        }
        if ($to) {
            $conditions['AND'][] = array('Event.date <=' => $to);
        }
        if ($last) {
            $conditions['AND'][] = array('Event.publish_timestamp >=' => $last);
        }
        if ($timestamp) {
            $conditions['AND'][] = array('Event.timestamp >=' => $timestamp);
        }
        if ($publish_timestamp) {
            $conditions['AND'][] = array('Event.publish_timestamp >=' => $publish_timestamp);
        }
        if ($eventIdList) {
            $conditions['AND'][] = array('Event.id' => $eventIdList);
        }
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
        if (isset($options['Event.id'])) {
            $options['eventid'] = $options['Event.id'];
        }
        $possibleOptions = array(
            'eventid',
            'idList',
            'tags',
            'from',
            'to',
            'last',
            'to_ids',
            'includeAllTags',
            'includeAttachments',
            'event_uuid',
            'distribution',
            'sharing_group_id',
            'disableSiteAdmin',
            'metadata',
            'enforceWarninglist',
            'sgReferenceOnly',
            'flatten',
            'blockedAttributeTags',
            'eventsExtendingUuid',
            'extended',
            'excludeGalaxy',
            'includeRelatedTags',
            'excludeLocalTags',
            'includeDecayScore',
            'includeSightingdb'
        );
        if (!isset($options['excludeLocalTags']) && !empty($user['Role']['perm_sync']) && empty($user['Role']['perm_site_admin'])) {
            $options['excludeLocalTags'] = 1;
        }
        if (!isset($options['excludeGalaxy']) || !$options['excludeGalaxy']) {
            $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
        }
        if (!empty($options['includeDecayScore'])) {
            $this->DecayingModel = ClassRegistry::init('DecayingModel');
        }
        foreach ($possibleOptions as &$opt) {
            if (!isset($options[$opt])) {
                $options[$opt] = false;
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
        if (!isset($user['org_id'])) {
            throw new Exception('There was an error with the user account.');
        }
        $isSiteAdmin = $user['Role']['perm_site_admin'];
        if (isset($options['disableSiteAdmin']) && $options['disableSiteAdmin']) {
            $isSiteAdmin = false;
        }
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
            // if delegations are enabled, check if there is an event that the current user might see because of the request itself
            if (Configure::read('MISP.delegation')) {
                $delegatedEventIDs = $this->__cachedelegatedEventIDs($user, $useCache);
                $conditions['AND']['OR']['Event.id'] = $delegatedEventIDs;
            }
            $attributeCondSelect = '(SELECT events.org_id FROM events WHERE events.id = Attribute.event_id)';
            $objectCondSelect = '(SELECT events.org_id FROM events WHERE events.id = Object.event_id)';
            if ($this->getDataSource()->config['datasource'] == 'Database/Postgres') {
                $schemaName = $this->getDataSource()->config['schema'];
                $attributeCondSelect = sprintf('(SELECT "%s"."events"."org_id" FROM "%s"."events" WHERE "%s"."events"."id" = "Attribute"."event_id")', $schemaName, $schemaName, $schemaName);
                $objectCondSelect = sprintf('(SELECT "%s"."events"."org_id" FROM "%s"."events" WHERE "%s"."events"."id" = "Object"."event_id")', $schemaName, $schemaName, $schemaName);
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
        if (!empty($options['includeRelatedTags'])) {
            $options['includeGranularCorrelations'] = 1;
        }
        if (isset($options['ignore']) && empty($options['ignore'])) {
            $conditions['AND'][] = array('Event.published' => 1);
            $conditionsAttributes['AND'][] = array('Attribute.to_ids' => 1);
        }
        $softDeletables = array('Attribute', 'Object', 'ObjectReference');
        if (isset($options['deleted'])) {
            if (!is_array($options['deleted'])) {
                $options['deleted'] = array($options['deleted']);
            }
            foreach ($options['deleted'] as $deleted_key => $deleted_value) {
                if ($deleted_value === 'only') {
                    $deleted_value = 1;
                }
                $options['deleted'][$deleted_key] = intval($deleted_value);
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
                                sprintf('%s.deleted', $softDeletable) => $options['deleted']
                            ),
                            $deletion_subconditions
                        )
                    );
                }
            } else {
                foreach ($softDeletables as $softDeletable) {
                    ${'conditions' . $softDeletable . 's'}['AND'][] = array(
                        sprintf('%s.deleted', $softDeletable) => $options['deleted']
                    );
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
        $fields = array('Event.id', 'Event.orgc_id', 'Event.org_id', 'Event.date', 'Event.threat_level_id', 'Event.info', 'Event.published', 'Event.uuid', 'Event.attribute_count', 'Event.analysis', 'Event.timestamp', 'Event.distribution', 'Event.proposal_email_lock', 'Event.user_id', 'Event.locked', 'Event.publish_timestamp', 'Event.sharing_group_id', 'Event.disable_correlation', 'Event.extends_uuid');
        $fieldsAtt = array('Attribute.id', 'Attribute.type', 'Attribute.category', 'Attribute.value', 'Attribute.to_ids', 'Attribute.uuid', 'Attribute.event_id', 'Attribute.distribution', 'Attribute.timestamp', 'Attribute.comment', 'Attribute.sharing_group_id', 'Attribute.deleted', 'Attribute.disable_correlation', 'Attribute.object_id', 'Attribute.object_relation');
        $fieldsObj = array('*');
        $fieldsShadowAtt = array('ShadowAttribute.id', 'ShadowAttribute.type', 'ShadowAttribute.category', 'ShadowAttribute.value', 'ShadowAttribute.to_ids', 'ShadowAttribute.uuid', 'ShadowAttribute.event_uuid', 'ShadowAttribute.event_id', 'ShadowAttribute.old_id', 'ShadowAttribute.comment', 'ShadowAttribute.org_id', 'ShadowAttribute.proposal_to_delete', 'ShadowAttribute.timestamp');
        $fieldsOrg = array('id', 'name', 'uuid', 'local');
        $fieldsServer = array('id', 'url', 'name');
        if (!$options['includeAllTags']) {
            $tagConditions = array('exportable' => 1);
        } else {
            $tagConditions = array();
        }
        $sharingGroupData = $this->__cacheSharingGroupData($user, $useCache);
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
                    'AttributeTag' => array(
                        'Tag' => array('conditions' => $tagConditions, 'order' => false),
                        'order' => false
                    ),
                    'order' => false
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
                    'conditions' => $proposal_conditions,
                    'Org' => array('fields' => $fieldsOrg),
                    'order' => false
                ),
                'EventTag' => array(
                    'Tag' => array('conditions' => $tagConditions, 'order' => false),
                    'order' => false
                 )
            )
        );
        if (!empty($options['excludeLocalTags'])) {
            $params['contain']['EventTag']['conditions'] = array(
                'EventTag.local' => 0
            );
            $params['contain']['Attribute']['AttributeTag']['conditions'] = array(
                'AttributeTag.local' => 0
            );
        }
        if ($flatten) {
            unset($params['contain']['Object']);
        }
        if ($options['metadata']) {
            unset($params['contain']['Attribute']);
            unset($params['contain']['ShadowAttribute']);
            unset($params['contain']['Object']);
        }
        if ($user['Role']['perm_site_admin']) {
            $params['contain']['User'] = array('fields' => 'email');
        }
        $results = $this->find('all', $params);
        if (empty($results)) {
            return array();
        }
        // Do some refactoring with the event
        $userEmails = array();
        $fields = array(
            'common' => array('distribution', 'sharing_group_id', 'uuid'),
            'Attribute' => array('value', 'type', 'category', 'to_ids'),
            'Object' => array('name', 'meta-category')
        );
        foreach ($results as $eventKey => &$event) {
            $this->__attachReferences($user, $event, $sgids, $fields);
            $event = $this->Orgc->attachOrgsToEvent($event, $fieldsOrg);
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
            $event = $this->massageTags($event, 'Event', $options['excludeGalaxy']);
            // Let's find all the related events and attach it to the event itself
            $results[$eventKey]['RelatedEvent'] = $this->getRelatedEvents($user, $event['Event']['id'], $sgids);
            // Let's also find all the relations for the attributes - this won't be in the xml export though
            if (!empty($options['includeGranularCorrelations'])) {
                $results[$eventKey]['RelatedAttribute'] = $this->getRelatedAttributes($user, $event['Event']['id'], $sgids);
                if (!empty($options['includeRelatedTags'])) {
                    $results[$eventKey] = $this->includeRelatedTags($results[$eventKey], $options);
                }
                $results[$eventKey]['RelatedShadowAttribute'] = $this->getRelatedAttributes($user, $event['Event']['id'], $sgids, true);
            }
            if (isset($event['ShadowAttribute']) && !empty($event['ShadowAttribute']) && isset($options['includeAttachments']) && $options['includeAttachments']) {
                foreach ($event['ShadowAttribute'] as $k => $sa) {
                    if ($this->ShadowAttribute->typeIsAttachment($sa['type'])) {
                        $encodedFile = $this->ShadowAttribute->base64EncodeAttachment($sa);
                        $event['ShadowAttribute'][$k]['data'] = $encodedFile;
                    }
                }
            }
            if (isset($event['Attribute'])) {
                if (!empty($options['enforceWarninglist']) || !empty($options['includeWarninglistHits'])) {
                    $this->Warninglist = ClassRegistry::init('Warninglist');
                    $warninglists = $this->Warninglist->fetchForEventView();
                }
                if (isset($options['includeFeedCorrelations']) && $options['includeFeedCorrelations']) {
                    $this->Feed = ClassRegistry::init('Feed');
                    if (!empty($options['overrideLimit'])) {
                        $overrideLimit = true;
                    } else {
                        $overrideLimit = false;
                    }
                    $event['Attribute'] = $this->Feed->attachFeedCorrelations($event['Attribute'], $user, $event['Event'], $overrideLimit);
                }
                if (!empty($options['includeServerCorrelations']) && ($user['Role']['perm_site_admin'] || $user['org_id'] == Configure::read('MISP.host_org_id'))) {
                    $this->Feed = ClassRegistry::init('Feed');
                    if (!empty($options['overrideLimit'])) {
                        $overrideLimit = true;
                    } else {
                        $overrideLimit = false;
                    }
                    $event['Attribute'] = $this->Feed->attachFeedCorrelations($event['Attribute'], $user, $event['Event'], $overrideLimit, 'Server');
                }
                $event = $this->__filterBlockedAttributesByTags($event, $options, $user);
                $event['Attribute'] = $this->__attachSharingGroups(!$options['sgReferenceOnly'], $event['Attribute'], $sharingGroupData);
                // move all object attributes to a temporary container
                $tempObjectAttributeContainer = array();
                foreach ($event['Attribute'] as $key => $attribute) {
                    if ($options['enforceWarninglist']) {
                        if (!$this->Warninglist->filterWarninglistAttributes($warninglists, $attribute, $this->Warninglist)) {
                            unset($event['Attribute'][$key]);
                            continue;
                        }
                    } else if (!empty($options['includeWarninglistHits'])) {
                        $event['Attribute'][$key] = $this->Warninglist->checkForWarning($event['Attribute'][$key], $event['Event']['warnings'], $warninglists, true);
                        //$event['Attribute'][$key] = $this->Warninglist->simpleCheckForWarning($event['Attribute'][$key], $warninglists);
                    }
                    $event['Attribute'][$key] = $this->massageTags($event['Attribute'][$key], 'Attribute', $options['excludeGalaxy']);
                    if ($event['Attribute'][$key]['category'] === 'Financial fraud') {
                        $event['Attribute'][$key] = $this->Attribute->attachValidationWarnings($event['Attribute'][$key]);
                    }
                    if (isset($options['includeAttachments']) && $options['includeAttachments']) {
                        if ($this->Attribute->typeIsAttachment($attribute['type'])) {
                            $encodedFile = $this->Attribute->base64EncodeAttachment($attribute);
                            $event['Attribute'][$key]['data'] = $encodedFile;
                        }
                    }
                    if (!empty($options['includeDecayScore'])) {
                        if (isset($event['EventTag'])) { // include EventTags for score computation
                            $event['Attribute'][$key]['EventTag'] = $event['EventTag'];
                        }
                        $event['Attribute'][$key] = $this->DecayingModel->attachScoresToAttribute($user, $event['Attribute'][$key]);
                        if (isset($event['EventTag'])) { // remove included EventTags
                            unset($event['Attribute'][$key]['EventTag']);
                        }
                    }
                    // unset empty attribute tags that got added because the tag wasn't exportable
                    if (!empty($attribute['AttributeTag'])) {
                        foreach ($attribute['AttributeTag'] as $atk => $attributeTag) {
                            if (empty($attributeTag['Tag'])) {
                                unset($event['Attribute'][$key]['AttributeTag'][$atk]);
                            }
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
                    if (
                        Configure::read('MISP.proposals_block_attributes') &&
                        !empty($options['allow_proposal_blocking'])
                    ) {
                        foreach ($results[$eventKey]['Attribute'][$key]['ShadowAttribute'] as $sa) {
                            if ($sa['proposal_to_delete'] || $sa['to_ids'] == 0) {
                                unset($results[$eventKey]['Attribute'][$key]);
                                continue;
                            }
                        }
                    }
                    if (!$flatten && $event['Attribute'][$key]['object_id'] != 0) {
                        $tempObjectAttributeContainer[$event['Attribute'][$key]['object_id']][] = $event['Attribute'][$key];
                        unset($event['Attribute'][$key]);
                    }
                }
                $event['Attribute'] = array_values($event['Attribute']);
            }
            if (!empty($event['Object'])) {
                $event['Object'] = $this->__attachSharingGroups(!$options['sgReferenceOnly'], $event['Object'], $sharingGroupData);
                foreach ($event['Object'] as $objectKey => $objectValue) {
                    if (!empty($tempObjectAttributeContainer[$objectValue['id']])) {
                        $event['Object'][$objectKey]['Attribute'] = $tempObjectAttributeContainer[$objectValue['id']];
                        unset($tempObjectAttributeContainer[$objectValue['id']]);
                    }
                }
            }
            if (!empty($event['ShadowAttribute'])) {
                if ($isSiteAdmin && isset($options['includeFeedCorrelations']) && $options['includeFeedCorrelations']) {
                    $this->Feed = ClassRegistry::init('Feed');
                    if (!empty($options['overrideLimit'])) {
                        $overrideLimit = true;
                    } else {
                        $overrideLimit = false;
                    }
                    $event['ShadowAttribute'] = $this->Feed->attachFeedCorrelations($event['ShadowAttribute'], $user, $event['Event'], $overrideLimit);
                }
            }
            if (!empty($options['includeServerCorrelations']) && $user['org_id'] == Configure::read('MISP.host_org_id')) {
                $this->Feed = ClassRegistry::init('Feed');
                if (!empty($options['overrideLimit'])) {
                    $overrideLimit = true;
                } else {
                    $overrideLimit = false;
                }
                $event['ShadowAttribute'] = $this->Feed->attachFeedCorrelations($event['ShadowAttribute'], $user, $event['Event'], $overrideLimit, 'Server');
            }
            if (empty($options['metadata'])) {
                $this->Sighting = ClassRegistry::init('Sighting');
                $event['Sighting'] = $this->Sighting->attachToEvent($event, $user);
            }
            if ($options['includeSightingdb']) {
                $this->Sightingdb = ClassRegistry::init('Sightingdb');
                $event = $this->Sightingdb->attachToEvent($event, $user);
            }
            // remove proposals to attributes that we cannot see
            // if the shadow attribute wasn't moved within an attribute before, this is the case
            if (isset($event['ShadowAttribute'])) {
                foreach ($event['ShadowAttribute'] as $k => $sa) {
                    if (!empty($sa['old_id'])) {
                        unset($event['ShadowAttribute'][$k]);
                    }
                }
                $event['ShadowAttribute'] = array_values($event['ShadowAttribute']);
            }
            if ($event['Event']['orgc_id'] === $user['org_id'] && $user['Role']['perm_audit']) {
                $UserEmail = $this->User->getAuthUser($event['Event']['user_id'])['email'];
                $event['Event']['event_creator_email'] = $UserEmail;
            }
        }
        if ($options['extended']) {
            foreach ($results as $k => $result) {
                $results[$k] = $this->__mergeExtensions($user, $result['Event']['uuid'], $result);
            }
        }
        return $results;
    }

    private function __cacheRelatedEventTags($eventTagCache, $relatedAttribute, $local = 0)
    {
        if (empty($eventTagCache[$relatedAttribute['id']])) {
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
            if ($local) {
                $params['conditions']['EventTag.local'] = 1;
            }
            $eventTags = $this->EventTag->find('all', $params);
            if (!empty($eventTags)) {
                foreach ($eventTags as $et) {
                    if (!isset($eventTagCache[$relatedAttribute['id']][$et['Tag']['id']])) {
                        $eventTagCache[$relatedAttribute['id']][$et['Tag']['id']] = $et['Tag'];
                    }
                }
            }
        }
        return $eventTagCache;
    }

    public function includeRelatedTags($event, $options)
    {
        $eventTagCache = array();
        $tags = array();
        $includeAllTags = !empty($options['includeAllTags']);
        foreach ($event['RelatedAttribute'] as $attributeId => $relatedAttributes) {
            $attributePos = false;
            foreach ($event['Attribute'] as $k => $attribute) {
                if ($attribute['id'] == $attributeId) {
                    $attributePos = $k;
                    break;
                }
            }
            foreach ($relatedAttributes as $relatedAttribute) {
                $eventTagCache = $this->__cacheRelatedEventTags($eventTagCache, $relatedAttribute, empty($options['excludeLocalTags']) ? 0 : 1);
                if (!empty($eventTagCache[$relatedAttribute['id']])) {
                    if (!isset($event['Attribute'][$attributePos]['RelatedTags'])) {
                        $event['Attribute'][$attributePos]['RelatedTags'] = array();
                    }
                    $event['Attribute'][$attributePos]['RelatedTags'] = array_merge($event['Attribute'][$attributePos]['RelatedTags'], $eventTagCache[$relatedAttribute['id']]);
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
                if (!empty($options['excludeLocalTags'])) {
                    $params['conditions']['AttributeTag.local'] = 0;
                }
                $attributeTags = $this->Attribute->AttributeTag->find('all', $params);
                if (!empty($attributeTags)) {
                    foreach ($attributeTags as $at) {
                        $event['Attribute'][$attributePos]['RelatedTags'][$at['Tag']['id']] = $at['Tag'];
                    }
                }
            }
        }
        return $event;
    }

    private function __mergeExtensions($user, $uuid, $event)
    {
        $extensions = $this->fetchEvent($user, array('eventsExtendingUuid' => $uuid));
        $thingsToMerge = array('Attribute', 'Object', 'ShadowAttribute', 'EventTag', 'Galaxy', 'RelatedEvent');
        foreach ($extensions as $k2 => $extensionEvent) {
            $eventMeta = array(
                'id' => $extensionEvent['Event']['id'],
                'info' => $extensionEvent['Event']['info'],
                'Orgc' => array(
                    'id' => $extensionEvent['Orgc']['id'],
                    'name' => $extensionEvent['Orgc']['name'],
                    'uuid' => $extensionEvent['Orgc']['uuid']
                )
            );
            $event['Event']['extensionEvents'][$eventMeta['id']] = $eventMeta;
            foreach ($thingsToMerge as $thingToMerge) {
                $event[$thingToMerge] = array_merge($event[$thingToMerge], $extensionEvent[$thingToMerge]);
            }
        }
        return $event;
    }

    private function __attachSharingGroups($doAttach, $data, $sharingGroupData)
    {
        if (!$doAttach) {
            return $data;
        }
        foreach ($data as $k => $v) {
            if ($v['distribution'] == 4) {
                $data[$k]['SharingGroup'] = $sharingGroupData[$v['sharing_group_id']]['SharingGroup'];
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

    private function __escapeCSVField(&$field)
    {
        $field = str_replace(array('"'), '""', $field);
        $field = '"' . $field . '"';
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
                            'conditions' => array('Orgc.name' => $org),
                            'fields' => array('Orgc.name', 'Orgc.id')
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
                            'conditions' => array('Orgc.name' => $org),
                            'fields' => array('Orgc.name', 'Orgc.id')
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
        if (!empty($params['uuid'])) {
            $params['uuid'] = $this->convert_filters($params['uuid']);
            if (!empty($options['scope']) && $options['scope'] === 'Event') {
                $conditions = $this->generic_add_filter($conditions, $params['uuid'], 'Event.uuid');
            }
            if (!empty($options['scope']) && $options['scope'] === 'Attribute') {
                $conditions = $this->generic_add_filter($conditions, $params['uuid'], 'Attribute.uuid');
            }
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
        if (!empty($params['deleted'])) {
            if (empty($options['scope'])) {
                $scope = 'Attribute';
            } else {
                $scope = $options['scope'];
            }
            if ($params['deleted']) {
                $conditions = $this->generic_add_filter($conditions, $params['deleted'], $scope . '.deleted');
            }
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
        if (isset($params['published'])) {
            $conditions['AND']['Event.published'] = $params['published'];
        }
        return $conditions;
    }

    public function set_filter_tags(&$params, $conditions, $options)
    {
        if (!empty($params['tags'])) {
            $conditions = $this->Attribute->set_filter_tags($params, $conditions, $options);
        }
        return $conditions;
    }

    public function set_filter_simple_attribute(&$params, $conditions, $options)
    {
        if (!empty($params[$options['filter']])) {
            $params[$options['filter']] = $this->convert_filters($params[$options['filter']]);
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

    public function set_filter_value(&$params, $conditions, $options, $keys = array('Attribute.value1', 'Attribute.value2'))
    {
        if (!empty($params['value'])) {
            $params[$options['filter']] = $this->convert_filters($params[$options['filter']]);
            $conditions = $this->generic_add_filter($conditions, $params[$options['filter']], $keys);

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

    public function set_filter_timestamp(&$params, $conditions, $options)
    {
        if ($options['filter'] == 'from') {
            $conditions['AND']['Event.date >='] = $params['from'];
        } elseif ($options['filter'] == 'to') {
            $conditions['AND']['Event.date <='] = $params['to'];
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

    public function sendAlertEmail($id, $senderUser, $oldpublish = null, $processId = null)
    {
        $event = $this->fetchEvent($senderUser, array('eventid' => $id, 'includeAllTags' => true));
        if (empty($event)) {
            throw new NotFoundException('Invalid Event.');
        }
        $this->NotificationLog = ClassRegistry::init('NotificationLog');
        if (!$this->NotificationLog->check($event[0]['Event']['orgc_id'], 'publish')) {
            if ($processId) {
                $this->Job->id = $processId;
                $this->Job->saveField('progress', 100);
                $this->Job->saveField('message', 'Mails blocked by org alert threshold.');
            }
            return true;
        }
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
            $subject = preg_replace("/\r|\n/", "", $event[0]['Event']['info']);
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
            if (strncasecmp($subjTag, $tagName, $tagLen) == 0 && strlen($tagName) > $tagLen && ($tagName[$tagLen] == ':' || $tagName[$tagLen] == '=')) {
                if (Configure::read('MISP.email_subject_include_tag_name') === false) {
                    $subjMarkingString = trim(substr($tagName, $tagLen+1), '"');
                } else {
                    $subjMarkingString = $tagName;
                }
                break;
            }
        }
        $threatLevel = $event[0]['ThreatLevel']['name'] . " - ";
        if (Configure::read('MISP.threatlevel_in_email_subject') === false) {
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
        $this->UserSetting = ClassRegistry::init('UserSetting');
        foreach ($users as $k => $user) {
            if ($this->UserSetting->checkPublishFilter($user, $event[0])) {
                $body = $this->__buildAlertEmailBody($event[0], $user, $oldpublish, $sgModel);
                $bodyNoEnc = "A new or modified event was just published on " . $this->__getAnnounceBaseurl() . "/events/view/" . $event[0]['Event']['id'];
                $this->User->sendEmail(array('User' => $user), $body, $bodyNoEnc, $subject);
            }
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

    private function __buildAlertEmailObject($user, &$body, &$bodyTempOther, $objects, $owner, $oldpublish)
    {
        foreach ($objects as $object) {
            if (!$owner && $object['distribution'] == 0) {
                continue;
            }
            if ($object['distribution'] == 4 && !$this->SharingGroup->checkIfAuthorised($user, $object['sharing_group_id'])) {
                continue;
            }
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

    private function __buildAlertEmailAttribute($user, &$body, &$bodyTempOther, $attributes, $owner, $oldpublish, $indent = '  ')
    {
        $appendlen = 20;
        foreach ($attributes as $attribute) {
            if (!$owner && $attribute['distribution'] == 0) {
                continue;
            }
            if ($attribute['distribution'] == 4 && !$this->SharingGroup->checkIfAuthorised($user, $attribute['sharing_group_id'])) {
                continue;
            }
            $ids = '';
            if ($attribute['to_ids']) {
                $ids = ' (IDS)';
            }
            $strRepeatCount = $appendlen - 2 - strlen($attribute['type']);
            $strRepeat = ($strRepeatCount > 0) ? str_repeat(' ', $strRepeatCount) : '';
            if (isset($oldpublish) && isset($attribute['timestamp']) && $attribute['timestamp'] > $oldpublish) {
                $line = '* ' . $indent . $attribute['category'] . '/' . $attribute['type'] . $strRepeat . ': ' . $attribute['value'] . $ids . " *\n";
            } else {
                $line = $indent . $attribute['category'] . '/' . $attribute['type'] . $strRepeat . ': ' . $attribute['value'] . $ids .  "\n";
            }
            // Defanging URLs (Not "links") emails domains/ips in notification emails
            if ('url' == $attribute['type'] || 'uri' == $attribute['type']) {
                $line = str_ireplace("http", "hxxp", $line);
                $line = str_ireplace(".", "[.]", $line);
            } elseif (in_array($attribute['type'], array('email-src', 'email-dst', 'whois-registrant-email', 'dns-soa-email', 'email-reply-to'))) {
                $line = str_replace("@", "[at]", $line);
            } elseif (in_array($attribute['type'], array('hostname', 'domain', 'ip-src', 'ip-dst', 'domain|ip'))) {
                $line = str_replace(".", "[.]", $line);
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
            if ('other' == $attribute['type']) { // append the 'other' attribute types to the bottom.
                $bodyTempOther .= $line;
            } else {
                $body .= $line;
            }
        }
    }

    private function __buildAlertEmailBody($event, $user, $oldpublish, $sgModel)
    {
        $owner = false;
        if ($user['org_id'] == $event['Event']['orgc_id'] || $user['org_id'] == $event['Event']['org_id'] || $user['Role']['perm_site_admin']) {
            $owner = true;
        }
        // The mail body, h() is NOT needed as we are sending plain-text mails.
        $body = "";
        $body .= '==============================================' . "\n";
        $appendlen = 20;
        $body .= 'URL         : ' . $this->__getAnnounceBaseurl() . '/events/view/' . $event['Event']['id'] . "\n";
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
            if (($k+1) != count($event['EventTag'])) {
                $tags .= ", ";
            }
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
                $body .= $this->__getAnnounceBaseurl() . '/events/view/' . $relatedEvent['Event']['id'] . ' (' . $relatedEvent['Event']['date'] . ') ' ."\n";
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
        $body .= $bodyTempOther;    // append the 'other' attribute types to the bottom.
        $body .= '==============================================' . "\n";
        return $body;
    }

    public function sendContactEmail($id, $message, $creator_only, $user, $isSiteAdmin)
    {
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
                        'User.org_id' => $event['Event']
                    ),
                    'fields' => array('User.email', 'User.gpgkey', 'User.certif_public'),
                    'recursive' => -1
            ));
            if (!empty($temp)) {
                $orgMembers = array(0 => $temp);
            }
        }
        if (empty($orgMembers)) {
            return false;
        }
        foreach ($orgMembers as $reporter) {
            $temp = $this->__buildContactEventEmailBody($user, $message, $event, $reporter, $id);
            $bodyevent = $temp[0];
            $body = $temp[1];
            $result = true;
            $tplColorString = !empty(Configure::read('MISP.email_subject_TLP_string')) ? Configure::read('MISP.email_subject_TLP_string') : "tlp:amber";
            $subject = "[" . Configure::read('MISP.org') . " MISP] Need info about event " . $id . " - ".$tplColorString;
            $result = $this->User->sendEmail($reporter, $bodyevent, $body, $subject, $user) && $result;
        }
        return $result;
    }

    private function __buildContactEventEmailBody($user, $message, $event, $targetUser, $id)
    {
        // The mail body, h() is NOT needed as we are sending plain-text mails.
        $body = "";
        $body .= "Hello, \n";
        $body .= "\n";
        $body .= "Someone wants to get in touch with you concerning a MISP event. \n";
        $body .= "\n";
        $body .= "You can reach him at " . $user['User']['email'] . "\n";
        if (!$user['User']['gpgkey']) {
            $body .= "His GnuPG key is added as attachment to this email. \n";
        }
        if (!$user['User']['certif_public']) {
            $body .= "His Public certificate is added as attachment to this email. \n";
        }
        $body .= "\n";
        $body .= "He wrote the following message: \n";
        $body .= $message . "\n";
        $body .= "\n";
        $body .= "\n";
        $body .= "The event is the following: \n";

        // print the event in mail-format
        // LATER place event-to-email-layout in a function
        $appendlen = 20;
        $body .= 'URL         : ' . $this->__getAnnounceBaseurl() . '/events/view/' . $event['Event']['id'] . "\n";
        $bodyevent = $body;
        $bodyevent .= 'Event ID    : ' . $event['Event']['id'] . "\n";
        $bodyevent .= 'Date        : ' . $event['Event']['date'] . "\n";
        if (Configure::read('MISP.showorg')) {
            $body .= 'Reported by : ' . $event['Orgc']['name'] . "\n";
        }
        $bodyevent .= 'Risk        : ' . $event['ThreatLevel']['name'] . "\n";
        $bodyevent .= 'Analysis    : ' . $event['Event']['analysis'] . "\n";

        $userModel = ClassRegistry::init('User');
        $targetUser = $userModel->getAuthUser($targetUser['User']['id']);
        $sgModel = ClassRegistry::init('SharingGroup');
        $sgs = $sgModel->fetchAllAuthorised($targetUser, false);

        $relatedEvents = $this->getRelatedEvents($targetUser, $id, $sgs);
        if (!empty($relatedEvents)) {
            foreach ($relatedEvents as &$relatedEvent) {
                $bodyevent .= 'Related to  : ' . $this->__getAnnounceBaseurl() . '/events/view/' . $relatedEvent['Event']['id'] . ' (' . $relatedEvent['Event']['date'] . ')' . "\n";
            }
        }
        $bodyevent .= 'Info  : ' . "\n";
        $bodyevent .= $event['Event']['info'] . "\n";
        $bodyevent .= "\n";
        $bodyevent .= 'Attributes  :' . "\n";
        $bodyTempOther = "";
        if (!empty($event['Attribute'])) {
            foreach ($event['Attribute'] as &$attribute) {
                $line = '- ' . $attribute['type'] . str_repeat(' ', $appendlen - 2 - strlen($attribute['type'])) . ': ' . $attribute['value'] . "\n";
                if ('other' == $attribute['type']) { // append the 'other' attribute types to the bottom.
                    $bodyTempOther .= $line;
                } else {
                    $bodyevent .= $line;
                }
            }
        }
        $bodyevent .= "\n";
        $bodyevent .= $bodyTempOther;   // append the 'other' attribute types to the bottom.
        return array($bodyevent, $body);
    }

    private function __captureSGForElement($element, $user)
    {
        if (isset($element['SharingGroup'])) {
            $sg = $this->SharingGroup->captureSG($element['SharingGroup'], $user);
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

    // When we receive an event via REST, we might end up with organisations, sharing groups, tags that we do not know
    // or which we need to update. All of that is controlled in this method.
    private function __captureObjects($data, $user)
    {
        // First we need to check whether the event or any attributes are tied to a sharing group and whether the user is even allowed to create the sharing group / is part of it
        if (isset($data['Event']['distribution']) && $data['Event']['distribution'] == 4) {
            $data['Event'] = $this->__captureSGForElement($data['Event'], $user);
        }
        if (!empty($data['Event']['Attribute'])) {
            foreach ($data['Event']['Attribute'] as $k => $a) {
                unset($data['Event']['Attribute']['id']);
                if (isset($a['distribution']) && $a['distribution'] == 4) {
                    $data['Event']['Attribute'][$k] = $this->__captureSGForElement($a, $user);
                    if ($data['Event']['Attribute'][$k] === false) {
                        unset($data['Event']['Attribute']);
                    }
                }
            }
        }
        if (!empty($data['Event']['Object'])) {
            foreach ($data['Event']['Object'] as $k => $o) {
                if (isset($o['distribution']) && $o['distribution'] == 4) {
                    $data['Event']['Object'][$k] = $this->__captureSGForElement($o, $user);
                    if ($data['Event']['Object'][$k] === false) {
                        unset($data['Event']['Object'][$k]);
                        continue;
                    }
                }
                foreach ($o['Attribute'] as $k2 => $a) {
                    if (isset($a['distribution']) && $a['distribution'] == 4) {
                        $data['Event']['Object'][$k]['Attribute'][$k2] = $this->__captureSGForElement($a, $user);
                        if ($data['Event']['Object'][$k]['Attribute'][$k2] === false) {
                            unset($data['Event']['Object'][$k]['Attribute'][$k2]);
                        }
                    }
                }
            }
        }

        // first we want to see how the creator organisation is encoded
        // The options here are either by passing an organisation object along or simply passing a string along
        if (isset($data['Event']['Orgc'])) {
            $data['Event']['orgc_id'] = $this->Orgc->captureOrg($data['Event']['Orgc'], $user);
            unset($data['Event']['Orgc']);
        } elseif (isset($data['Event']['orgc'])) {
            $data['Event']['orgc_id'] = $this->Orgc->captureOrg($data['Event']['orgc'], $user);
            unset($data['Event']['orgc']);
        } else {
            $data['Event']['orgc_id'] = $user['org_id'];
        }

        $event_tag_ids = array();
        if (isset($data['Event']['EventTag'])) {
            if (isset($data['Event']['EventTag']['id'])) {
                $data['Event']['EventTag'] = array($data['Event']['EventTag']);
            }
            $eventTags = array();
            foreach ($data['Event']['EventTag'] as $k => $tag) {
                $temp = $this->EventTag->Tag->captureTag($data['Event']['EventTag'][$k]['Tag'], $user);
                if ($temp && !in_array($temp, $event_tag_ids)) {
                    $eventTags[] = array('tag_id' => $temp);
                    $event_tag_ids[] = $temp;
                }
                unset($data['Event']['EventTag'][$k]);
            }
            $data['Event']['EventTag'] = $eventTags;
        } else {
            $data['Event']['EventTag'] = array();
        }
        if (isset($data['Event']['Tag'])) {
            if (isset($data['Event']['Tag']['name'])) {
                $data['Event']['Tag'] = array($data['Event']['Tag']);
            }
            foreach ($data['Event']['Tag'] as $tag) {
                $tag_id = $this->EventTag->Tag->captureTag($tag, $user);
                if ($tag_id && !in_array($tag_id, $event_tag_ids)) {
                    $data['Event']['EventTag'][] = array('tag_id' => $tag_id);
                    $event_tag_ids[] = $tag_id;
                }
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

    private function __captureAttributeTags($attributes, $user)
    {
        foreach ($attributes as $k => $a) {
            if (isset($attributes[$k]['AttributeTag'])) {
                if (isset($attributes[$k]['AttributeTag']['id'])) {
                    $attributes[$k]['AttributeTag'] = array($attributes[$k]['AttributeTag']);
                }
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
                if (isset($attributes[$k]['Tag']['name'])) {
                    $attributes[$k]['Tag'] = array($attributes[$k]['Tag']);
                }
                foreach ($attributes[$k]['Tag'] as $tag) {
                    $tag_id = $this->Attribute->AttributeTag->Tag->captureTag($tag, $user);
                    if ($tag_id) {
                        $attributes[$k]['AttributeTag'][] = array('tag_id' => $tag_id);
                    }
                }
                unset($attributes[$k]['Tag']);
            }
        }
        return $attributes;
    }

    // Low level function to add an Event based on an Event $data array
    public function _add(&$data, $fromXml, $user, $org_id = 0, $passAlong = null, $fromPull = false, $jobId = null, &$created_id = 0, &$validationErrors = array())
    {
        if ($jobId) {
            App::uses('AuthComponent', 'Controller/Component');
        }
        if (Configure::read('MISP.enableEventBlacklisting') !== false && isset($data['Event']['uuid'])) {
            $this->EventBlacklist = ClassRegistry::init('EventBlacklist');
            $r = $this->EventBlacklist->find('first', array('conditions' => array('event_uuid' => $data['Event']['uuid'])));
            if (!empty($r)) {
                return 'Blocked by blacklist';
            }
        }
        if (empty($data['Event']['Attribute']) && empty($data['Event']['Object']) && !empty($data['Event']['published'])) {
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
            $validationErrors['Event'] = 'Received a published event that was empty. Event add process blocked.';
            $this->Log->save(array(
                    'org' => $user['Organisation']['name'],
                    'model' => 'Event',
                    'model_id' => 0,
                    'email' => $user['email'],
                    'action' => 'add',
                    'user_id' => $user['id'],
                    'title' => $validationErrors['Event'],
                    'change' => ''
            ));
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
            if (!isset($data['Event']['Orgc'])) {
                if (isset($data['Event']['orgc_id']) && $data['Event']['orgc_id'] != $user['org_id'] && !$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin']) {
                    throw new MethodNotAllowedException('Event cannot be created as you are not a member of the creator organisation.');
                }
            } else {
                if ($data['Event']['Orgc']['uuid'] != $user['Organisation']['uuid'] && !$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin']) {
                    throw new MethodNotAllowedException('Event cannot be created as you are not a member of the creator organisation.');
                }
                if (isset($data['Event']['orgc']) && $data['Event']['orgc'] != $user['Organisation']['name'] && !$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin']) {
                    throw new MethodNotAllowedException('Event cannot be created as you are not a member of the creator organisation.');
                }
            }
            if (isset($data['Event']['orgc_id']) && $data['Event']['orgc_id'] != $user['org_id'] && !$user['Role']['perm_sync'] && !$user['Role']['perm_site_admin']) {
                throw new MethodNotAllowedException('Event cannot be created as you are not a member of the creator organisation.');
            }
        }
        if (!Configure::check('MISP.enableOrgBlacklisting') || Configure::read('MISP.enableOrgBlacklisting') !== false) {
            $this->OrgBlacklist = ClassRegistry::init('OrgBlacklist');
            if (!isset($data['Event']['Orgc']['uuid'])) {
                $orgc = $this->Orgc->find('first', array('conditions' => array('Orgc.id' => $data['Event']['orgc_id']), 'fields' => array('Orgc.uuid'), 'recursive' => -1));
            } else {
                $orgc = array('Orgc' => array('uuid' => $data['Event']['Orgc']['uuid']));
            }
            if ($this->OrgBlacklist->hasAny(array('OrgBlacklist.org_uuid' => $orgc['Orgc']['uuid']))) {
                return 'blocked';
            }
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
        if (isset($data['Event']['published']) && $data['Event']['published'] && $user['Role']['perm_publish'] == 0) {
            $data['Event']['published'] = 0;
        }
        if (isset($data['Event']['uuid'])) {
            // check if the uuid already exists
            $existingEvent = $this->find('first', array('conditions' => array('Event.uuid' => $data['Event']['uuid'])));
            if ($existingEvent) {
                // RESTful, set response location header so client can find right URL to edit
                if ($fromPull) {
                    return false;
                }
                if ($fromXml) {
                    $created_id = $existingEvent['Event']['id'];
                }
                return $existingEvent['Event']['id'];
            } else {
                if ($fromXml) {
                    $data = $this->__captureObjects($data, $user);
                }
                if ($data === false) {
                    $failedCapture = true;
                }
            }
        } else {
            if ($fromXml) {
                $data = $this->__captureObjects($data, $user);
            }
            if ($data === false) {
                $failedCapture = true;
            }
        }
        if (!empty($failedCapture)) {
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
            $this->Log->save(array(
                    'org' => $user['Organisation']['name'],
                    'model' => 'Event',
                    'model_id' => 0,
                    'email' => $user['email'],
                    'action' => 'add',
                    'user_id' => $user['id'],
                    'title' => 'Event could not be saved due to a failed sharing group capture.',
                    'change' => ''
            ));
            $validationErrors['Event'] = 'Issues saving a Sharing Group.';
            return json_encode($validationErrors);
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
                'disable_correlation',
                'extends_uuid'
            ),
            'Attribute' => $this->Attribute->captureFields,
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
                        'Server.unpublish_event',
                        'Server.publish_without_email'
                    )
                ));
                if ($server['Server']['publish_without_email'] == 0) {
                    $st = "enabled";
                } else {
                    $st = "disabled";
                }
                $this->Log->create();
                $this->Log->save(array(
                        'org' => $user['Organisation']['name'],
                        'model' => 'Event',
                        'model_id' => $saveResult['Event']['id'],
                        'email' => $user['email'],
                        'action' => 'add',
                        'user_id' => $user['id'],
                        'title' => 'Event pulled from Server(' . $server['Server']['id'] . ') - "' . $server['Server']['name'] . '" - Notification by mail ' . $st,
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
            $parentEvent = $this->find('first', array(
                'conditions' => array('Event.id' => $this->id),
                'recursive' => -1
            ));
            if (isset($data['Event']['Attribute']) && !empty($data['Event']['Attribute'])) {
                foreach ($data['Event']['Attribute'] as $k => $attribute) {
                    $block = false;
                    for ($i = 0; $i < $k; $i++) {
                        if (empty($data['Event']['Attribute'][$i])) {
                            continue;
                        }
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
                        $data['Event']['Attribute'][$k] = $this->Attribute->captureAttribute($attribute, $this->id, $user, 0, $this->Log, $parentEvent);
                    }
                }
                $data['Event']['Attribute'] = array_values($data['Event']['Attribute']);
            }
            $referencesToCapture = array();
            if (!empty($data['Event']['Object'])) {
                foreach ($data['Event']['Object'] as $object) {
                    $result = $this->Object->captureObject($object, $this->id, $user, $this->Log);
                }
                foreach ($data['Event']['Object'] as $object) {
                    if (isset($object['ObjectReference'])) {
                        foreach ($object['ObjectReference'] as $objectRef) {
                            $objectRef['source_uuid'] = $object['uuid'];
                            $referencesToCapture[] = $objectRef;
                        }
                    }
                }
            }
            foreach ($referencesToCapture as $referenceToCapture) {
                $result = $this->Object->ObjectReference->captureReference(
                    $referenceToCapture,
                    $this->id,
                    $user,
                    $this->Log
                );
            }
            // zeroq: check if sightings are attached and add to event
            if (isset($data['Sighting']) && !empty($data['Sighting'])) {
                $this->Sighting = ClassRegistry::init('Sighting');
                foreach ($data['Sighting'] as $s) {
                    $result = $this->Sighting->saveSightings($s['attribute_uuid'], false, $s['date_sighting'], $user, $s['type'], $s['source'], $s['uuid']);
                }
            }
            if ($fromXml) {
                $created_id = $this->id;
            }
            if (!empty($data['Event']['published']) && 1 == $data['Event']['published']) {
                // do the necessary actions to publish the event (email, upload,...)
                if (('true' != Configure::read('MISP.disablerestalert')) && (empty($server) || $server['Server']['publish_without_email'] == 0)) {
                    $this->sendAlertEmailRouter($this->getID(), $user);
                }
                $this->publish($this->getID(), $passAlong);
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
                                    $log = ClassRegistry::init('Log');
                                    $log->createLogEntry($user, 'tag', 'Event', $this->id, 'Attached tag (' . $tag_id . ') "' . $tag['Tag']['name'] . '" to event (' . $this->id . ')', 'Event (' . $this->id . ') tagged as Tag (' . $tag_id . ')');
                                }
                            }
                        }
                    }
                }
            }
            return true;
        } else {
            $validationErrors['Event'] = $this->validationErrors;
            return json_encode($validationErrors);
        }
    }

    public function _edit(&$data, $user, $id, $jobId = null, $passAlong = null)
    {
        $data = $this->cleanupEventArrayFromXML($data);
        unset($this->Attribute->validate['event_id']);
        unset($this->Attribute->validate['value']['unique']); // otherwise gives bugs because event_id is not set

        // reposition to get the event.id with given uuid
        if (isset($data['Event']['uuid'])) {
            $existingEvent = $this->findByUuid($data['Event']['uuid']);
        } else {
            $existingEvent = $this->findById($id);
        }
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
                if (!isset($data['Event']['timestamp'])) {
                    $data['Event']['timestamp'] = $date;
                }
                if (isset($data['Event']['distribution']) && $data['Event']['distribution'] == 4) {
                    if (!isset($data['Event']['SharingGroup'])) {
                        if (!isset($data['Event']['sharing_group_id'])) {
                            return(array('error' => 'Event could not be saved: Sharing group chosen as the distribution level, but no sharing group specified. Make sure that the event includes a valid sharing_group_id or change to a different distribution level.'));
                        }
                        if (!$this->SharingGroup->checkIfAuthorised($user, $data['Event']['sharing_group_id'])) {
                            return(array('error' => 'Event could not be saved: Invalid sharing group or you don\'t have access to that sharing group.'));
                        }
                    } else {
                        $data['Event']['sharing_group_id'] = $this->SharingGroup->captureSG($data['Event']['SharingGroup'], $user);
                        unset($data['Event']['SharingGroup']);
                        if ($data['Event']['sharing_group_id'] === false) {
                            return (array('error' => 'Event could not be saved: User not authorised to create the associated sharing group.'));
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
                if (!isset($data['Event'][$rF])) {
                    $data['Event'][$rF] = $existingEvent['Event'][$rF];
                }
            }
        } else {
            return (array('error' => 'Event could not be saved: Could not find the local event.'));
        }
        if (!empty($data['Event']['published']) && !$user['Role']['perm_publish']) {
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
            if (isset($data['Event']['EventTag'])) {
                $data['Event']['Tag'] = $data['Event']['EventTag']['Tag'];
                unset($data['Event']['EventTag']);
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
            // zeroq: if sightings then attach to event
            if (isset($data['Sighting']) && !empty($data['Sighting'])) {
                $this->Sighting = ClassRegistry::init('Sighting');
                foreach ($data['Sighting'] as $s) {
                    $result = $this->Sighting->saveSightings($s['attribute_uuid'], false, $s['date_sighting'], $user, $s['type'], $s['source'], $s['uuid']);
                }
            }
            // if published -> do the actual publishing
            if ((!empty($data['Event']['published']) && 1 == $data['Event']['published'])) {
                // The edited event is from a remote server ?
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
                            'Server.publish_without_email'
                        )
                    ));
                    if ($server['Server']['publish_without_email'] == 0) {
                        $st = "enabled";
                    } else {
                        $st = "disabled";
                    }
                    $this->Log->create();
                    $this->Log->save(array(
                        'org' => $user['Organisation']['name'],
                        'model' => 'Event',
                        'model_id' => $saveResult['Event']['id'],
                        'email' => $user['email'],
                        'action' => 'add',
                        'user_id' => $user['id'],
                        'title' => 'Event edited from Server(' . $server['Server']['id'] . ') - "' . $server['Server']['name'] . '" - Notification by mail ' . $st,
                        'change' => ''
                    ));
                } else {
                    $this->Log->create();
                    $this->Log->save(array(
                        'org' => $user['Organisation']['name'],
                        'model' => 'Event',
                        'model_id' => $saveResult['Event']['id'],
                        'email' => $user['email'],
                        'action' => 'add',
                        'user_id' => $user['id'],
                        'title' => 'Event edited (locally)',
                        'change' => ''
                    ));
                }
                // do the necessary actions to publish the event (email, upload,...)
                if ((true != Configure::read('MISP.disablerestalert')) && (empty($server) || $server['Server']['publish_without_email'] == 0)) {
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
        if (empty(Configure::read('MISP.host_org_id')) || !$server['Server']['internal'] || Configure::read('MISP.host_org_id') != $server['Server']['remote_org_id']) {
            if ($object[$context]['distribution'] < 2) {
                return false;
            }
        }
        if ($object[$context]['distribution'] == 4) {
            if ($context === 'Event') {
                return $this->SharingGroup->checkIfServerInSG($object['SharingGroup'], $server);
            } else {
                return $this->SharingGroup->checkIfServerInSG($object[$context]['SharingGroup'], $server);
            }
        }
        return true;
    }

    // Uploads this specific event or sightings to all remote servers
    public function uploadEventToServersRouter($id, $passAlong = null, $scope = 'events')
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
                'perm_sync' => 1
            ),
            'org_id' => $eventOrgcId['Event']['orgc_id']
        );
        $elevatedUser['Role']['perm_site_admin'] = 1;
        $elevatedUser['Role']['perm_sync'] = 1;
        $elevatedUser['Role']['perm_audit'] = 0;
        $event = $this->fetchEvent($elevatedUser, array('eventid' => $id, 'metadata' => 1));
        if (empty($event)) {
            return true;
        }
        $event = $event[0];
        $event['Event']['locked'] = 1;
        // get a list of the servers
        $this->Server = ClassRegistry::init('Server');
        if ($scope === 'sightings') {
            $conditions = array('push_sightings' => 1);
        } else {
            $conditions = array('push' => 1);
        }
        if ($passAlong) {
            $conditions[] = array('Server.id !=' => $passAlong);
        }
        $servers = $this->Server->find('all', array(
            'conditions' => $conditions,
            'order' => array('Server.priority ASC', 'Server.id ASC')
        ));
        // iterate over the servers and upload the event
        if (empty($servers)) {
            return true;
        }
        $uploaded = true;
        $failedServers = array();
        App::uses('SyncTool', 'Tools');
        foreach ($servers as &$server) {
            if (
                ($scope === 'events' &&
                    (!isset($server['Server']['internal']) || !$server['Server']['internal']) && $event['Event']['distribution'] < 2) ||
                ($scope === 'sightings' &&
                    (!isset($server['Server']['push_sightings']) || !$server['Server']['push_sightings']))
            ) {
                continue;
            }
            $syncTool = new SyncTool();
            $HttpSocket = $syncTool->setupHttpSocket($server);
            // Skip servers where the event has come from.
            if (($passAlong != $server['Server']['id'])) {
                $params = array();
                if (!empty($server['Server']['push_rules'])) {
                    $push_rules = json_decode($server['Server']['push_rules'], true);
                    if (!empty($push_rules['tags']['NOT'])) {
                        $params['blockedAttributeTags'] = $push_rules['tags']['NOT'];
                    }
                }
                $params = array_merge($params, array(
                    'eventid' => $id,
                    'includeAttachments' => true,
                    'includeAllTags' => true,
                    'deleted' => array(0,1),
                    'excludeGalaxy' => 1
                ));
                $event = $this->fetchEvent($elevatedUser, $params);
                $event = $event[0];
                $event['Event']['locked'] = 1;
                // attach sightings if needed
                if ($scope === 'sightings') {
                    $this->Sighting = ClassRegistry::init('Sighting');
                    $fakeSyncUser = array(
                        'org_id' => $server['Server']['remote_org_id'],
                        'Role' => array(
                            'perm_site_admin' => 0
                        )
                    );
                    $sightings = $this->Sighting->attachToEvent($event, $fakeSyncUser);
                    if (!empty($sightings)) {
                        $thisUploaded = $this->uploadSightingsToServer($sightings, $server, $event['Event']['uuid'], $HttpSocket);
                    } else {
                        $thisUploaded = true;
                    }
                } else {
                    $thisUploaded = $this->uploadEventToServer($event, $server, $HttpSocket, $scope);
                    if (isset($this->data['ShadowAttribute'])) {
                        $this->Server->syncProposals($HttpSocket, $server, null, $id, $this);
                    }
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
        } else {
            return true;
        }
    }

    public function __getPrioWorkerIfPossible()
    {
        $this->ResqueStatus = new ResqueStatus\ResqueStatus(Resque::redis());
        $workers = $this->ResqueStatus->getWorkers();
        $workerType = 'default';
        foreach ($workers as $worker) {
            if ($worker['queue'] === 'prio') {
                $workerType = 'prio';
            }
        }
        return $workerType;
    }

    public function publishRouter($id, $passAlong = null, $user, $scope = 'events')
    {
        if (Configure::read('MISP.background_jobs')) {
            $job_type = 'publish_' . $scope;
            $function = 'publish';
            $message = 'Publishing.';
            if ($scope === 'sightings') {
                $message = 'Publishing sightings.';
                $function = 'publish_sightings';
            }
            $job = ClassRegistry::init('Job');
            $job->create();
            $data = array(
                    'worker' => $this->__getPrioWorkerIfPossible(),
                    'job_type' => 'publish_event',
                    'job_input' => 'Event ID: ' . $id,
                    'status' => 0,
                    'retries' => 0,
                    'org_id' => $user['org_id'],
                    'org' => $user['Organisation']['name'],
                    'message' => $message
            );
            $job->save($data);
            $jobId = $job->id;
            $process_id = CakeResque::enqueue(
                    'prio',
                    'EventShell',
                    array($function, $id, $passAlong, $jobId, $user['id']),
                    true
            );
            $job->saveField('process_id', $process_id);
            return $process_id;
        } elseif ($scope === 'sightings') {
            $result = $this->publish_sightings($id, $passAlong);
            return $result;
        } else {
            $result = $this->publish($id, $passAlong);
            return $result;
        }
    }

    public function publish_sightings($id, $passAlong = null, $jobId = null)
    {
        if (is_numeric($id)) {
            $condition = array('Event.id' => $id);
        } else {
            $condition = array('Event.uuid' => $id);
        }
        $event = $this->find('first', array(
            'recursive' => -1,
            'conditions' => $condition
        ));
        if (empty($event)) {
            return false;
        }
        if ($jobId) {
            $this->Behaviors->unload('SysLogLogable.SysLogLogable');
        } else {
            // update the DB to set the sightings timestamp
            // for background jobs, this should be done already
            $fieldList = array('id', 'info', 'sighting_timestamp');
            $event['Event']['sighting_timestamp'] = time();
            $event['Event']['skip_zmq'] = 1;
            $event['Event']['skip_kafka'] = 1;
            $this->save($event, array('fieldList' => $fieldList));
        }
        $uploaded = $this->uploadEventToServersRouter($id, $passAlong, 'sightings');
        return $uploaded;
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
            $this->save($event, array('fieldList' => $fieldList));
        }
        $pubToZmq = Configure::read('Plugin.ZeroMQ_enable');
        $kafkaTopic = Configure::read('Plugin.Kafka_event_publish_notifications_topic');
        $pubToKafka = Configure::read('Plugin.Kafka_enable') && Configure::read('Plugin.Kafka_event_publish_notifications_enable') && !empty($kafkaTopic);
        if ($pubToZmq || $pubToKafka) {
            $hostOrg = $this->Org->find('first', array('conditions' => array('name' => Configure::read('MISP.org')), 'fields' => array('id')));
            if (!empty($hostOrg)) {
                $user = array('org_id' => $hostOrg['Org']['id'], 'Role' => array('perm_sync' => 0, 'perm_audit' => 0, 'perm_site_admin' => 0), 'Organisation' => $hostOrg['Org']);
                if ($pubToZmq) {
                    $params = array('eventid' => $id);
                    if (Configure::read('Plugin.ZeroMQ_include_attachments')) {
                        $params['includeAttachments'] = 1;
                    }
                    $fullEvent = $this->fetchEvent($user, $params);
                    if (!empty($fullEvent)) {
                        $pubSubTool = $this->getPubSubTool();
                        $pubSubTool->publishEvent($fullEvent[0], 'publish');
                    }
                }
                if ($pubToKafka) {
                    $params = array('eventid' => $id);
                    if (Configure::read('Plugin.Kafka_include_attachments')) {
                        $params['includeAttachments'] = 1;
                    }
                    $fullEvent = $this->fetchEvent($user, $params);
                    if (!empty($fullEvent)) {
                        $kafkaPubTool = $this->getKafkaPubTool();
                        $kafkaPubTool->publishJson($kafkaTopic, $fullEvent[0], 'publish');
                    }
                }
            }
        }
        $uploaded = $this->uploadEventToServersRouter($id, $passAlong);
        return $uploaded;
    }


    // Sends out an email to all people within the same org with the request to be contacted about a specific event.
    public function sendContactEmailRouter($id, $message, $creator_only, $user, $isSiteAdmin, $JobId = false)
    {
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

    public function generateLocked()
    {
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
            } elseif ($orgs[$k]['User']['count'] == 1) {
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

    public function generateThreatLevelFromRisk()
    {
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

    public function checkIfNewer($incomingEvent)
    {
        $localEvent = $this->find('first', array('conditions' => array('uuid' => $incomingEvent['uuid']), 'recursive' => -1, 'fields' => array('Event.uuid', 'Event.timestamp')));
        if (empty($localEvent) || $incomingEvent['timestamp'] > $localEvent['Event']['timestamp']) {
            return true;
        }
        return false;
    }

    public function removeOlder(&$eventArray, $scope = 'events')
    {
        if ($scope === 'sightings' ) {
            $field = 'sighting_timestamp';
        } else {
            $field = 'timestamp';
        }
        $uuidsToCheck = array();
        foreach ($eventArray as $k => &$event) {
            $uuidsToCheck[$event['uuid']] = $k;
        }
        $localEvents = array();
        $temp = $this->find('all', array('recursive' => -1, 'fields' => array('Event.uuid', 'Event.' . $field, 'Event.locked')));
        foreach ($temp as $e) {
            $localEvents[$e['Event']['uuid']] = array($field => $e['Event'][$field], 'locked' => $e['Event']['locked']);
        }
        foreach ($uuidsToCheck as $uuid => $eventArrayId) {
            // remove all events for the sighting sync if the remote is not aware of the new field yet
            if (!isset($eventArray[$eventArrayId][$field])) {
                unset($eventArray[$eventArrayId]);
            } else {
                if (isset($localEvents[$uuid])
                      && ($localEvents[$uuid][$field] >= $eventArray[$eventArrayId][$field]
                      || ($scope === 'events' && !$localEvents[$uuid]['locked'])))
                {
                    unset($eventArray[$eventArrayId]);
                }
            }
        }
    }

    public function getAccessibleEventIds($include, $exclude, $includedTags, $excludedTags)
    {
        $conditions = array();

        // get all of the event IDs based on include / exclude
        if (!empty($include)) {
            $conditions['OR'] = array('id' => $include);
        }
        if (!empty($exclude)) {
            $conditions['NOT'] = array('id' => $exclude);
        }
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

    public function generateRandomFileName()
    {
        return (new RandomTool())->random_str(false, 12);
    }


    public function sharingGroupRequired($field)
    {
        if ($this->data[$this->alias]['distribution'] == 4) {
            return (!empty($field));
        }
        return true;
    }

    // convenience method to check whether a user can see an event
    public function checkIfAuthorised($user, $id)
    {
        if (!isset($user['id'])) {
            throw new MethodNotAllowedException('Invalid user.');
        }
        $this->id = $id;
        if (!$this->exists()) {
            return false;
        }
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        $event = $this->find('first', array(
            'conditions' => array('id' => $id),
            'recursive' => -1,
            'fields' => array('id', 'sharing_group_id', 'distribution', 'org_id')
        ));
        if ($event['Event']['org_id'] == $user['org_id'] || ($event['Event']['distribution'] > 0 && $event['Event']['distribution'] < 4)) {
            return true;
        }
        if ($event['Event']['distribution'] == 4 && $this->SharingGroup->checkIfAuthorised($user, $event['Event']['sharing_group_id'])) {
            return true;
        }
        return false;
    }

    // expects a date string in the YYYY-MM-DD format
    // returns the passed string or false if the format is invalid
    // based on the fix provided by stevengoosensB
    public function dateFieldCheck($date)
    {
        // regex check for from / to field by stevengoossensB
        return (preg_match('/^[0-9]{4}-(0[1-9]|1[012])-(0[1-9]|1[0-9]|2[0-9]|3[01])$/', $date)) ? $date : false;
    }

    private function __prepareAttributeForView(
        $attribute,
        $correlatedAttributes,
        $correlatedShadowAttributes,
        $filterType = false,
        &$eventWarnings,
        $warningLists,
        $sightingsData
    ) {
        $attribute['objectType'] = 'attribute';
        $include = true;
        if ($filterType) {
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
            } else if (in_array($attribute['id'], $correlatedAttributes)) { // `include only`
                $include = $include && ($filterType['correlation'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['correlation'] == 2);
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
                $filterType['attributeFilter'] != 'all'
                && isset($this->Attribute->typeGroupings[$filterType['attributeFilter']])
                && !in_array($attribute['type'], $this->Attribute->typeGroupings[$filterType['attributeFilter']])
            ) {
                $include = false;
            }
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
                if ($result['include']) {
                    $temp[] = $result['data'];
                }
            }
            $attribute['ShadowAttribute'] = $temp;
        }
        $attribute = $this->__prepareGenericForView($attribute, $eventWarnings, $warningLists);

        /* warning */
        if ($filterType) {
            if ($filterType['warning'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (!empty($attribute['warnings']) || !empty($attribute['validationIssue'])) { // `include only`
                $include = $include && ($filterType['warning'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['warning'] == 2);
            }
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

        $include = $filterType['proposal'] != 2;

        /* correlation */
        if ($filterType['correlation'] == 0) { // `both`
            // pass, do not consider as `both` is selected
        } else if (in_array($proposal['id'], $correlatedShadowAttributes)) { // `include only`
            $include = $include && ($filterType['correlation'] == 1);
        } else { // `exclude`
            $include = $include && ($filterType['correlation'] == 2);
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
            $filterType['attributeFilter'] != 'all'
            && isset($this->Attribute->typeGroupings[$filterType['attributeFilter']])
            && !in_array($proposal['type'], $this->Attribute->typeGroupings[$filterType['attributeFilter']])
        ) {
            $include = false;
        }
        $proposal = $this->__prepareGenericForView($proposal, $eventWarnings, $warningLists);

        /* warning */
        if ($filterType) {
            if ($filterType['warning'] == 0) { // `both`
                // pass, do not consider as `both` is selected
            } else if (!empty($proposal['warnings']) || !empty($proposal['validationIssue'])) { // `include only`
                $include = $include && ($filterType['correlation'] == 1);
            } else { // `exclude`
                $include = $include && ($filterType['correlation'] == 2);
            }
        }
        return array('include' => $include, 'data' => $proposal);
    }

    private function __prepareObjectForView(
        $object,
        $correlatedAttributes,
        $correlatedShadowAttributes,
        $filterType = false,
        &$eventWarnings,
        $warningLists,
        $sightingsData
    ) {
        $object['category'] = $object['meta-category'];
        $proposal['objectType'] = 'object';

        $include = empty($filterType['attributeFilter']) || $filterType['attributeFilter'] == 'object' || $filterType['attributeFilter'] == 'all' || $object['meta-category'] === $filterType['attributeFilter'];

        if (!empty($object['Attribute'])) {
            $temp = array();
            foreach ($object['Attribute'] as $k => $proposal) {
                $result = $this->__prepareAttributeForView(
                    $proposal,
                    $correlatedAttributes,
                    $correlatedShadowAttributes,
                    false,
                    $eventWarnings,
                    $warningLists,
                    $sightingsData
                );
                if ($result['include']) {
                    $temp[] = $result['data'];
                }
            }
            $object['Attribute'] = $temp;
        }

        // filters depend on child objects
        if (in_array($filterType['attributeFilter'], array('correlation', 'proposal', 'warning'))
            || $filterType['correlation'] != 0
            || $filterType['proposal'] != 0
            || $filterType['warning'] != 0
            || $filterType['sighting'] != 0
            || $filterType['feed'] != 0
            || $filterType['server'] != 0
        ) {
            $include = $this->__checkObjectByFilter($object, $filterType, $correlatedAttributes, $correlatedShadowAttributes, $sightingsData);
        }

        return array('include' => $include, 'data' => $object);
    }

    private function __checkObjectByFilter($object, $filterType, $correlatedAttributes, $correlatedShadowAttributes, $sightingsData)
    {
        $include = true;

        if (empty($object['Attribute'])) { // reject empty object
            $include = false;
            return $include;
        }

        /* proposal */
        if ($filterType['proposal'] == 0) { // `both`
            // pass, do not consider as `both` is selected
        } else if ($filterType['proposal'] == 1 || $filterType['proposal'] == 2) {
            $flagKeep = false;
            foreach ($object['Attribute'] as $k => $attribute) { // check if object contains at least 1 proposal
                if (!empty($attribute['ShadowAttribute'])) {
                    $flagKeep = ($filterType['proposal'] == 1); // keep if proposal are included
                    break;
                }
            }
            if (!$flagKeep) {
                $include = false;
                return $include;
            }
        }

        /* warning */
        if ($filterType['warning'] == 0) { // `both`
            // pass, do not consider as `both` is selected
        } else if ($filterType['warning'] == 1 || $filterType['warning'] == 2) {
            $flagKeep = false;
            foreach ($object['Attribute'] as $k => $attribute) { // check if object contains at least 1 warning
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
                $include = false;
                return $include;
            }
        }

        /* correlation */
        if ($filterType['correlation'] == 0) { // `both`
            // pass, do not consider as `both` is selected
        } else if ($filterType['correlation'] == 1 || $filterType['correlation'] == 2) {
            $flagKeep = false;
            foreach ($object['Attribute'] as $k => $attribute) { // check if object contains at least 1 warning
                if (in_array($attribute['id'], $correlatedAttributes)) {
                    $flagKeep = ($filterType['correlation'] == 1); // keep if correlations are included
                } else {
                    $flagKeep = ($filterType['correlation'] == 2); // keep if correlations are excluded
                }
                if (!$flagKeep && !empty($attribute['ShadowAttribute'])) {
                    foreach ($attribute['ShadowAttribute'] as $k => $shadowAttribute) {
                        if (in_array($shadowAttribute['id'], $correlatedShadowAttributes)) {
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
                $include = false;
                return $include;
            }
        }

        /* sighting */
        if ($filterType['sighting'] == 0) { // `both`
            // pass, do not consider as `both` is selected
        } else if ($filterType['sighting'] == 1 || $filterType['sighting'] == 2) {
            $flagKeep = false;
            foreach ($object['Attribute'] as $k => $attribute) { // check if object contains at least 1 warning
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
                $include = false;
                return $include;
            }
        }

        /* feed */
        if ($filterType['feed'] == 0) { // `both`
            // pass, do not consider as `both` is selected
        } else if ($filterType['feed'] == 1 || $filterType['feed'] == 2) {
            $flagKeep = false;
            foreach ($object['Attribute'] as $k => $attribute) { // check if object contains at least 1 warning
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
                $include = false;
                return $include;
            }
        }

        /* server */
        if ($filterType['server'] == 0) { // `both`
            // pass, do not consider as `both` is selected
        } else if ($filterType['server'] == 1 || $filterType['server'] == 2) {
            $flagKeep = false;
            foreach ($object['Attribute'] as $k => $attribute) { // check if object contains at least 1 warning
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
                $include = false;
                return $include;
            }
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
        if (isset($object['distribution']) && $object['distribution'] != 4) {
            unset($object['SharingGroup']);
        }
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

    public function rearrangeEventForView(&$event, $passedArgs = array(), $all = false, $sightingsData=array())
    {
        $this->Warninglist = ClassRegistry::init('Warninglist');
        $warningLists = $this->Warninglist->fetchForEventView();
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
            'server' => isset($passedArgs['server']) ? $passedArgs['server'] : 0
        );
        // update proposal, correlation and warning accordingly
        if (in_array($filterType['attributeFilter'], array('proposal', 'correlation', 'warning'))) {
            $filterType[$filterType['attributeFilter']] = 1;
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
                $warningLists,
                $sightingsData
            );
            if ($result['include']) {
                $event['objects'][] = $result['data'];
            }
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
                    $warningLists,
                    $sightingsData
                );
                if ($result['include']) {
                    $event['objects'][] = $result['data'];
                }
            }
        }
        unset($event['Object']);
        unset($event['ShadowAttribute']);
        $referencedObjectFields = array('meta-category', 'name', 'uuid', 'id');
        $objectReferenceCount = 0;
        $referencedByArray = array();
        foreach ($event['objects'] as $object) {
            if (!in_array($object['objectType'], array('attribute', 'object'))) {
                continue;
            }
            if (!empty($object['ObjectReference'])) {
                foreach ($object['ObjectReference'] as $reference) {
                    if (isset($reference['referenced_uuid'])) {
                        $referencedByArray[$reference['referenced_uuid']][$object['objectType']][] = array(
                            'meta-category' => $object['meta-category'],
                            'name' => $object['name'],
                            'uuid' => $object['uuid'],
                            'id' => isset($object['id']) ? $object['id'] : 0,
                            'object_type' => $object['objectType'],
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
        $params = $customPagination->applyRulesOnArray($event['objects'], $passedArgs, 'events', 'category');
        foreach ($event['objects'] as $k => $object) {
            if (isset($referencedByArray[$object['uuid']])) {
                foreach ($referencedByArray[$object['uuid']] as $objectType => $references) {
                    $event['objects'][$k]['referenced_by'][$objectType] = $references;
                }
            }
        }
        $params['total_elements'] = count($event['objects']);
        $event['Event']['warnings'] = $eventWarnings;
        return $params;
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
            'fields' => array('Object.id', 'Object.uuid', 'Object.name')
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

    public function handleMispFormatFromModuleResult(&$result)
    {
        $defaultDistribution = 5;
        if (!empty(Configure::read('MISP.default_attribute_distribution'))) {
            $defaultDistribution = Configure::read('MISP.default_attribute_distribution');
            if ($defaultDistribution == 'event') {
                $defaultDistribution = 5;
            }
        }
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
            $object = array();
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
        foreach (array('Tag', 'Galaxy') as $field) {
            if (!empty($result['results'][$field])) {
                $event[$field] = $result['results'][$field];
            }
        }
        return $event;
    }

    private function __fillAttribute($attribute, $defaultDistribution)
    {
        if (!isset($attribute['category'])) {
            $attribute['category'] = $this->Event->Attribute->typeDefinitions[$attribute['type']]['default_category'];
        }
        if (!isset($attribute['to_ids'])) {
            $attribute['to_ids'] = $this->Event->Attribute->typeDefinitions[$attribute['type']]['to_ids'];
        }
        $attribute['value'] = $this->Attribute->runRegexp($attribute['type'], $attribute['value']);
        $attribute['distribution'] = (isset($attribute['distribution']) ? (int)$attribute['distribution'] : $defaultDistribution);
        $attribute['sharing_group_id'] = (isset($attribute['sharing_group_id']) ? (int)$attribute['sharing_group_id'] : 0);
        return $attribute;
    }

    public function export($user = false, $module = false, $options = array())
    {
        if (empty($user)) {
            return 'Invalid user.';
        }
        if (empty($module)) {
            return 'Invalid module.';
        }
        $this->Module = ClassRegistry::init('Module');
        $module = $this->Module->getEnabledModule($module, 'Export');
        $events = $this->fetchEvent($user, $options);
        if (empty($events)) {
            return 'Invalid event.';
        }
        $standard_format = false;
        $modulePayload = array('module' => $module['name']);
        if (!empty($module['meta']['require_standard_format'])) {
            $standard_format = true;
        }
        if (isset($module['meta']['config'])) {
            foreach ($module['meta']['config'] as $conf) {
                $modulePayload['config'][$conf] = Configure::read('Plugin.Export_' . $module['name'] . '_' . $conf);
            }
        }
        if ($standard_format) {
            App::uses('JSONConverterTool', 'Tools');
            $converter = new JSONConverterTool();
            foreach ($events as $k => $event) {
                $events[$k] = $converter->convert($event, false, true);
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

    public function getSightingData($event)
    {
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
                if ($sighting['type'] !== '0') {
                    continue;
                }
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
                if (!isset($startDates[$aid])) {
                    continue;
                }
                $startDate = $startDates[$aid];
                if (strtotime($startDate) < strtotime('-' . $range . ' days', time())) {
                    $startDate = date('Y-m-d');
                }
                $startDate = date('Y-m-d', strtotime("-3 days", strtotime($startDate)));
                $to = date('Y-m-d', time());
                $sighting = $data;
                for ($date = $startDate; strtotime($date) <= strtotime($to); $date = date('Y-m-d', strtotime("+1 day", strtotime($date)))) {
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

    public function setSimpleConditions($parameterKey, $parameterValue, $conditions, $restrictScopeToEvents = false)
    {
        if (is_array($parameterValue)) {
            $elements = $parameterValue;
        } else {
            $elements = explode('&&', $parameterValue);
        }
        App::uses('CIDRTool', 'Tools');
        $cidr = new CIDRTool();
        $subcondition = array();
        foreach ($elements as $v) {
            if ($v === '') {
                continue;
            }
            if (substr($v, 0, 1) === '!') {
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
                            'conditions' => array('name' => substr($v, 1)),
                        ));
                        foreach ($found_orgs as $o) {
                            $subcondition['AND'][] = array('Event.orgc_id !=' => $o['Org']['id']);
                        }
                    } elseif ($parameterKey === 'eventid') {
                        if ($restrictScopeToEvents) {
                            $subcondition['AND'][] = array('Event.id !=' => substr($v, 1));
                        } else {
                            $subcondition['AND'][] = array('Attribute.event_id !=' => substr($v, 1));
                        }
                    } elseif ($parameterKey === 'uuid') {
                        $subcondition['AND'][] = array('Event.uuid !=' => substr($v, 1));
                        $subcondition['AND'][] = array('Attribute.uuid !=' => substr($v, 1));
                    } else {
                        $lookup = substr($v, 1);
                        if (strlen($lookup) != strlen(trim($lookup, '%'))) {
                            $subcondition['AND'][] = array('Attribute.' . $parameterKey . ' NOT LIKE' => $lookup);
                        } else {
                            $subcondition['AND'][] = array('NOT' => array('Attribute.' . $parameterKey => $lookup));
                        }
                    }
                }
            } else {
                // check for an IPv4 address and subnet in CIDR notation (e.g. 127.0.0.1/8)
                if ($parameterKey === 'value' && $cidr->checkCIDR($v, 4)) {
                    $cidrresults = $cidr->CIDR($v);
                    foreach ($cidrresults as $result) {
                        if (!empty($result)) {
                            $subcondition['OR'][] = array('Attribute.value LIKE' => $result);
                        }
                    }
                } else {
                    if ($parameterKey === 'org') {
                        $found_orgs = $this->Org->find('all', array(
                                'recursive' => -1,
                                'conditions' => array('name' => $v),
                        ));
                        foreach ($found_orgs as $o) {
                            $subcondition['OR'][] = array('Event.orgc_id' => $o['Org']['id']);
                        }
                    } elseif ($parameterKey === 'eventid') {
                        if ($restrictScopeToEvents) {
                            $subcondition['OR'][] = array('Event.id' => $v);
                        } else {
                            $subcondition['OR'][] = array('Attribute.event_id' => $v);
                        }
                    } elseif ($parameterKey === 'uuid') {
                        $subcondition['OR'][] = array('Attribute.uuid' => $v);
                        $subcondition['OR'][] = array('Event.uuid' => $v);
                    } else {
                        if (!empty($v)) {
                            if (strlen($v) != strlen(trim($v, '%'))) {
                                $subcondition['AND'][] = array('Attribute.' . $parameterKey . ' LIKE' => $v);
                            } else {
                                $subcondition['AND'][] = array('Attribute.' . $parameterKey => $v);
                            }
                        }
                    }
                }
            }
        }
        if (!empty($subcondition)) {
            array_push($conditions['AND'], $subcondition);
        }
        return $conditions;
    }

    public function prepareEventForView()
    {
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
            } elseif ($m === 'Attribute') {
                $currentModel = $this->Attribute;
            }
            foreach ($variables as $alias => $variable) {
                $this->set($alias, $currentModel->{$variable});
            }
        }
    }

    public function cacheSgids($user, $useCache = false)
    {
        if ($useCache && isset($this->__assetCache['sgids'])) {
            return $this->__assetCache['sgids'];
        } else {
            $sgids = $this->SharingGroup->fetchAllAuthorised($user);
            if (empty($sgids)) {
                $sgids = array(-1);
            }
            if ($useCache) {
                $this->__assetCache['sgids'] = $sgids;
            }
            return $sgids;
        }
    }

    private function __cacheSharingGroupData($user, $useCache = false)
    {
        if ($useCache && isset($this->__assetCache['sharingGroupData'])) {
            return $this->__assetCache['sharingGroupData'];
        } else {
            $sharingGroupDataTemp = $this->SharingGroup->fetchAllAuthorised($user, 'simplified');
            $sharingGroupData = array();
            foreach ($sharingGroupDataTemp as $k => $v) {
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
                $sharingGroupData[$v['SharingGroup']['id']] = array('SharingGroup' => $v['SharingGroup']);
            }
            if ($useCache) {
                $this->__assetCache['sharingGroupData'] = $sharingGroupData;
            }
            return $sharingGroupData;
        }
    }

    private function __cachedelegatedEventIDs($user, $useCache = false)
    {
        if ($useCache && isset($this->__assetCache['delegatedEventIDs'])) {
            return $this->__assetCache['delegatedEventIDs'];
        } else {
            $this->EventDelegation = ClassRegistry::init('EventDelegation');
            $delegatedEventIDs = $this->EventDelegation->find('list', array(
                'conditions' => array('EventDelegation.org_id' => $user['org_id']),
                'fields' => array('event_id')
            ));
            if ($useCache) {
                $this->__assetCache['delegationEventIDs'] = $delegatedEventIDs;
            }
            return $delegatedEventIDs;
        }
    }

    private function __generateCachedTagFilters($tagRules, $useCache = false)
    {
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
            if ($useCache) {
                $this->__assetCache['tagFilters'] = $filters;
            }
            return $filters;
        }
    }

    private function __destroyCaches()
    {
        $this->__assetCache = array();
    }

    public function unpublishEvent($id, $proposalLock = false)
    {
        $event = $this->find('first', array(
            'recursive' => -1,
            'conditions' => array('Event.id' => $id)
        ));
        if (empty($event)) {
            return false;
        }
        $event['Event']['published'] = 0;
        $date = new DateTime();
        $event['Event']['timestamp'] = $date->getTimestamp();
        if ($proposalLock) {
            $event['Event']['proposal_email_lock'] = 0;
        }
        $event['Event']['unpublishAction'] = true;
        return $this->save($event);
    }

    public function upload_stix($user, $filename, $stix_version, $original_file, $publish)
    {
        App::uses('Folder', 'Utility');
        App::uses('File', 'Utility');
        if ($stix_version == '2') {
            $scriptFile = APP . 'files/scripts/stix2/stix2misp.py';
            $tempFilePath = APP . 'files/scripts/tmp/' . $filename;
            $shell_command = $this->getPythonVersion() . ' ' . $scriptFile . ' ' . $tempFilePath;
            $output_path = $tempFilePath . '.stix2';
            $stix_version = "STIX 2.0";
        } elseif ($stix_version == '1' || $stix_version == '1.1' || $stix_version == '1.2') {
            $scriptFile = APP . 'files/scripts/stix2misp.py';
            $tempFilePath = APP . 'files/scripts/tmp/' . $filename;
            $shell_command = $this->getPythonVersion() . ' ' . $scriptFile . ' ' . $filename;
            $output_path = $tempFilePath . '.json';
            $stix_version = "STIX 1.1";
        } else {
            throw new MethodNotAllowedException('Invalid STIX version');
        }
        $shell_command .=  ' ' . escapeshellarg(Configure::read('MISP.default_event_distribution')) . ' ' . escapeshellarg(Configure::read('MISP.default_attribute_distribution')) . ' 2>' . APP . 'tmp/logs/exec-errors.log';
        $result = shell_exec($shell_command);
        $tempFile = file_get_contents($tempFilePath);
        unlink($tempFilePath);
        if (trim($result) == '1') {
            $data = file_get_contents($output_path);
            $data = json_decode($data, true);
            if (empty($data['Event'])) {
                $data = array('Event' => $data);
            }
            unlink($output_path);
            $created_id = false;
            $validationIssues = false;
            $result = $this->_add($data, true, $user, '', null, false, null, $created_id, $validationIssues);
            if ($result) {
                if ($original_file) {
                    $this->add_original_file($tempFile, $original_file, $created_id, $stix_version);
                }
                if ($publish && $user['Role']['perm_publish']) {
                    $this->publish($this->getID(), null);
                }
                return $created_id;
            }
            return $validationIssues;
        } else {
            if (trim($result) == '2') {
                $response = __('Issues while loading the stix file. ');
            } elseif (trim($result) == '3') {
                $response = __('Issues with the maec library. ');
            } else {
                $response = __('Issues executing the ingestion script or invalid input. ');
            }
            if (!$user['Role']['perm_site_admin']) {
                $response .= __('Please ask your administrator to ');
            } else {
                $response .= __('Please ');
            }
            $response .= ' ' . __('check whether the dependencies for STIX are met via the diagnostic tool.');
            return $response;
        }
    }

    public function enrichmentRouter($options)
    {
        if (Configure::read('MISP.background_jobs')) {
            $job = ClassRegistry::init('Job');
            $job->create();
            $data = array(
                    'worker' => $this->__getPrioWorkerIfPossible(),
                    'job_type' => 'enrichment',
                    'job_input' => 'Event ID: ' . $options['event_id'] . ' modules: ' . json_encode($options['modules']),
                    'status' => 0,
                    'retries' => 0,
                    'org_id' => $options['user']['org_id'],
                    'org' => $options['user']['Organisation']['name'],
                    'message' => 'Enriching event.',
            );
            $job->save($data);
            $jobId = $job->id;
            $process_id = CakeResque::enqueue(
                    'prio',
                    'EventShell',
                    array('enrichment', $options['user']['id'], $options['event_id'], json_encode($options['modules']), $jobId),
                    true
            );
            $job->saveField('process_id', $process_id);
            return true;
        } else {
            $result = $this->enrichment($options);
            return __('#' . $result . ' attributes have been created during the enrichment process.');
        }
    }

    public function enrichment($params)
    {
        $option_fields = array('user', 'event_id', 'modules');
        foreach ($option_fields as $option_field) {
            if (empty($params[$option_field])) {
                throw new MethodNotAllowedException(__('%s not set', $params[$option_field]));
            }
        }
        $event = $this->fetchEvent($params['user'], array('eventid' => $params['event_id'], 'includeAttachments' => 1, 'flatten' => 1));
        $this->Module = ClassRegistry::init('Module');
        $enabledModules = $this->Module->getEnabledModules($params['user']);
        if (empty($enabledModules)) {
            return true;
        }
        $options = array();
        foreach ($enabledModules['modules'] as $k => $temp) {
            if (isset($temp['meta']['config'])) {
                $settings = array();
                foreach ($temp['meta']['config'] as $conf) {
                    $settings[$conf] = Configure::read('Plugin.Enrichment_' . $temp['name'] . '_' . $conf);
                }
                $enabledModules['modules'][$k]['config'] = $settings;
            }
        }
        if (empty($event)) {
            throw new MethodNotAllowedException('Invalid event.');
        }
        $attributes_added = 0;
        $initial_objects = array();
        $event_id = $event[0]['Event']['id'];
        foreach ($event[0]['Attribute'] as $attribute) {
            $object_id = $attribute['object_id'];
            foreach ($enabledModules['modules'] as $module) {
                if (in_array($module['name'], $params['modules'])) {
                    if (in_array($attribute['type'], $module['mispattributes']['input'])) {
                        $data = array('module' => $module['name'], 'event_id' => $event_id, 'attribute_uuid' => $attribute['uuid']);
                        if (!empty($module['config'])) {
                            $data['config'] = $module['config'];
                        }
                        if (!empty($module['mispattributes']['format']) && $module['mispattributes']['format'] == 'misp_standard') {
                            $data['attribute'] = $attribute;
                            if ($object_id != '0' && empty($initial_objects[$object_id])) {
                                $initial_objects[$object_id] = $this->fetchInitialObject($event_id, $object_id);
                            }
                        } else {
                            $data[$attribute['type']] = $attribute['value'];
                        }
                        $data = json_encode($data);
                        $result = $this->Module->queryModuleServer('/query', $data, false, 'Enrichment');
                        if (!$result) {
                            throw new MethodNotAllowedException(h($module['name']) . ' service not reachable.');
                        }
                        //if (isset($result['error'])) $this->Session->setFlash($result['error']);
                        if (!is_array($result)) {
                            throw new Exception($result);
                        }
                        if (!empty($module['mispattributes']['format']) && $module['mispattributes']['format'] == 'misp_standard') {
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

    public function massageTags($data, $dataType = 'Event', $excludeGalaxy = false, $cullGalaxyTags = false)
    {
        $data['Galaxy'] = array();
        if (empty($this->GalaxyCluster)) {
            $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
        }
        // unset empty event tags that got added because the tag wasn't exportable
        if (!empty($data[$dataType . 'Tag'])) {
            foreach ($data[$dataType . 'Tag'] as $k => &$dataTag) {
                if (empty($dataTag['Tag'])) {
                    unset($data[$dataType . 'Tag'][$k]);
                    continue;
                }
                $dataTag['Tag']['local'] = $dataTag['local'];
                if (!isset($excludeGalaxy) || !$excludeGalaxy) {
                    if (substr($dataTag['Tag']['name'], 0, strlen('misp-galaxy:')) === 'misp-galaxy:') {
                        $cluster = $this->GalaxyCluster->getCluster($dataTag['Tag']['name']);
                        if ($cluster) {
                            $found = false;
                            $cluster['GalaxyCluster']['local'] = isset($dataTag['local']) ? $dataTag['local'] : false;
                            foreach ($data['Galaxy'] as $j => $galaxy) {
                                if ($galaxy['id'] == $cluster['GalaxyCluster']['Galaxy']['id']) {
                                    $found = true;
                                    $temp = $cluster;
                                    unset($temp['GalaxyCluster']['Galaxy']);
                                    $data['Galaxy'][$j]['GalaxyCluster'][] = $temp['GalaxyCluster'];
                                    continue;
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

    private function __logUploadResult($server, $event, $newTextBody)
    {
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

    public function processFreeTextData($user, $attributes, $id, $default_comment = '', $force = false, $adhereToWarninglists = false, $jobId = false, $returnRawResults = false)
    {
        $event = $this->find('first', array(
            'conditions' => array('id' => $id),
            'recursive' => -1,
            'fields' => array('orgc_id', 'id', 'distribution', 'published', 'uuid'),
        ));
        if (empty($event)) {
            return false;
        }
        $results = array();
        if (!$user['Role']['perm_site_admin'] && !empty($event) && $event['Event']['orgc_id'] != $user['org_id']) {
            $objectType = 'ShadowAttribute';
        } elseif ($user['Role']['perm_site_admin'] && isset($force) && $force) {
            $objectType = 'ShadowAttribute';
        } else {
            $objectType = 'Attribute';
        }

        if ($adhereToWarninglists) {
            $this->Warninglist = ClassRegistry::init('Warninglist');
            $warninglists = $this->Warninglist->fetchForEventView();
        }
        $saved = 0;
        $failed = 0;
        $attributeSources = array('attributes', 'ontheflyattributes');
        $ontheflyattributes = array();
        $i = 0;
        $total = count($attributeSources);
        if ($jobId) {
            $this->Job = ClassRegistry::init('Job');
            $this->Job->id = $jobId;
        }
        foreach ($attributeSources as $sourceKey => $source) {
            foreach (${$source} as $k => $attribute) {
                if ($attribute['type'] == 'ip-src/ip-dst') {
                    $types = array('ip-src', 'ip-dst');
                } elseif ($attribute['type'] == 'ip-src|port/ip-dst|port') {
                    $types = array('ip-src|port', 'ip-dst|port');
                } elseif ($attribute['type'] == 'malware-sample') {
                    if (!isset($attribute['data_is_handled']) || !$attribute['data_is_handled']) {
                        $result = $this->Attribute->handleMaliciousBase64($id, $attribute['value'], $attribute['data'], array('md5', 'sha1', 'sha256'), $objectType == 'ShadowAttribute' ? true : false);
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
                    $this->$objectType->create();
                    $attribute['type'] = $type;
                    if (empty($attribute['comment'])) {
                        $attribute['comment'] = $default_comment;
                    }
                    $attribute['event_id'] = $id;
                    if ($objectType == 'ShadowAttribute') {
                        $attribute['org_id'] = $user['org_id'];
                        $attribute['event_org_id'] = $event['Event']['orgc_id'];
                        $attribute['email'] = $user['email'];
                        $attribute['event_uuid'] = $event['Event']['uuid'];
                    }
                    // adhere to the warninglist
                    if ($adhereToWarninglists) {
                        if (!$this->Warninglist->filterWarninglistAttributes($warninglists, $attribute)) {
                            if ($adhereToWarninglists === 'soft') {
                                $attribute['to_ids'] = 0;
                            } else {
                                // just ignore the attribute
                                continue;
                            }
                        }
                    }
                    $saved_attribute = $this->$objectType->save($attribute);
                    if ($saved_attribute) {
                        $results[] = $saved_attribute;
                        // If Tags, attach each tags to attribute
                        if (!empty($attribute['tags'])) {
                            foreach (explode(",", $attribute['tags']) as $tagName) {
                                $this->Tag = ClassRegistry::init('Tag');
                                $TagId = $this->Tag->captureTag(array('name' => $tagName), array('Role' => $user['Role']));
                                $this->AttributeTag = ClassRegistry::init('AttributeTag');
                                if (!$this->AttributeTag->attachTagToAttribute($saved_attribute['Attribute']['id'], $id, $TagId)) {
                                    throw new MethodNotAllowedException(__('Could not add tags.'));
                                }
                            }
                        }
                        $saved++;
                    } else {
                        $lastError = $this->$objectType->validationErrors;
                        $failed++;
                    }
                }
                if ($jobId) {
                    if ($i % 20 == 0) {
                        $this->Job->saveField('message', 'Attribute ' . $i . '/' . $total);
                        $this->Job->saveField('progress', $i * 80 / $total);
                    }
                }
            }
        }
        $emailResult = '';
        $messageScope = $objectType == 'ShadowAttribute' ? 'proposals' : 'attributes';
        if ($saved > 0) {
            if ($objectType != 'ShadowAttribute') {
                $event = $this->find('first', array(
                        'conditions' => array('Event.id' => $id),
                        'recursive' => -1
                ));
                if ($event['Event']['published'] == 1) {
                    $event['Event']['published'] = 0;
                }
                $date = new DateTime();
                $event['Event']['timestamp'] = $date->getTimestamp();
                $this->save($event);
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
            if ($i % 20 == 0) {
                $this->Job->saveField('message', 'Processing complete. ' . $message);
                $this->Job->saveField('progress', 100);
            }
        }
        if (!empty($returnRawResults)) {
            return $results;
        }
        return $message;
    }

    public function processModuleResultsData($user, $resolved_data, $id, $default_comment = '', $jobId = false, $adhereToWarninglists = false, $event_level = false)
    {
        if ($jobId) {
            $this->Job = ClassRegistry::init('Job');
            $this->Job->id = $jobId;

        }
        $failed_attributes = $failed_objects = $failed_object_attributes = 0;
        $saved_attributes = $saved_objects = $saved_object_attributes = 0;
        $items_count = 0;
        $failed = array();
        $recovered_uuids = array();
        foreach (array('Attribute', 'Object') as $feature) {
            if (isset($resolved_data[$feature])) {
                $items_count += count($resolved_data[$feature]);
            }
        }
        if (!empty($resolved_data['Tag'])) {
            foreach ($resolved_data['Tag'] as $tag) {
                $tag_id = $this->EventTag->Tag->captureTag($tag, $user);
                if ($tag_id) {
                    $this->EventTag->attachTagToEvent($id, $tag_id);
                }
            }
        }
        if (!empty($resolved_data['Attribute'])) {
            $total_attributes = count($resolved_data['Attribute']);
            foreach ($resolved_data['Attribute'] as $a => $attribute) {
                $this->Attribute->create();
                if (empty($attribute['comment'])) {
                    $attribute['comment'] = $default_comment;
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
                                $this->Attribute->AttributeTag->attachTagToAttribute($this->Attribute->id, $id, $tag_id);
                            }
                        }
                    }
                } else {
                    $failed_attributes++;
                    $lastAttributeError = $this->Attribute->validationErrors;
                    $original_uuid = $this->Object->Attribute->find('first', array(
                        'conditions' => array('Attribute.event_id' => $id, 'Attribute.object_id' => 0, 'Attribute.deleted' => 0,
                                              'Attribute.type' => $attribute['type'], 'Attribute.value' => $attribute['value']),
                        'recursive' => -1,
                        'fields' => array('Attribute.uuid')
                    ));
                    if (!empty($original_uuid)) {
                        $recovered_uuids[$attribute['uuid']] = $original_uuid['Attribute']['uuid'];
                    } else {
                        $failed[] = $attribute['uuid'];
                    }
                }
                if ($jobId) {
                    $current = ($a + 1);
                    $this->Job->saveField('message', 'Attribute ' . $current . '/' . $total_attributes);
                    $this->Job->saveField('progress', ($current * 100 / $items_count));
                }
            }
        } else {
            $total_attributes = 0;
        }
        if (!empty($resolved_data['Object'])) {
            $initial_object_id = isset($resolved_data['initialObject']) ? $resolved_data['initialObject']['Object']['id'] : "0";
            $total_objects = count($resolved_data['Object']);
            $references = array();
            foreach ($resolved_data['Object'] as $o => $object) {
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
                            if ($this->__saveObjectAttribute($object_attribute, $default_comment, $id, $initial_object_id, $user)) {
                                $saved_object_attributes++;
                            } else {
                                $failed_object_attributes++;
                                $lastObjectAttributeError = $this->Attribute->validationErrors;
                            }
                        }
                    }
                    if (!empty($object['ObjectReference'])) {
                        foreach ($object['ObjectReference'] as $object_reference) {
                            array_push($references, array('objectId' => $initial_object_id, 'reference' => $object_reference));
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
                                    if ($this->__saveObjectAttribute($object_attribute, $default_comment, $id, $object_id, $user)) {
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
                        foreach($object['ObjectReference'] as $object_reference) {
                            array_push($references, array('objectId' => $object_id, 'reference' => $object_reference));
                        }
                    }
                }
                if ($jobId) {
                    $current = ($o + 1);
                    $this->Job->saveField('message', 'Object ' . $current . '/' . $total_objects);
                    $this->Job->saveField('progress', (($current + $total_attributes) * 100 / $items_count));
                }
            }
        }
        if (!empty($references)) {
            $reference_errors = array();
            foreach($references as $reference) {
                $object_id = $reference['objectId'];
                $reference = $reference['reference'];
                if (in_array($reference['object_uuid'], $failed) || in_array($reference['referenced_uuid'], $failed)) {
                    continue;
                }
                if (isset($recovered_uuids[$reference['object_uuid']])) {
                    $reference['object_uuid'] = $recovered_uuids[$reference['object_uuid']];
                }
                if (isset($recovered_uuids[$reference['referenced_uuid']])) {
                    $reference['referenced_uuid'] = $recovered_uuids[$reference['referenced_uuid']];
                }
                $current_reference = $this->Object->ObjectReference->find('all', array(
                    'conditions' => array('ObjectReference.object_id' => $object_id,
                                          'ObjectReference.referenced_uuid' => $reference['referenced_uuid'],
                                          'ObjectReference.relationship_type' => $reference['relationship_type'],
                                          'ObjectReference.event_id' => $id, 'ObjectReference.deleted' => 0),
                    'recursive' => -1,
                    'fields' => ('ObjectReference.uuid')
                ));
                if (!empty($current_reference)) {
                    continue;
                }
                list($referenced_id, $referenced_uuid, $referenced_type) = $this->Object->ObjectReference->getReferencedInfo(
                        $reference['referenced_uuid'],
                        array('Event' => array('id' => $id)),
                        false
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
        if ($saved_attributes > 0 || $saved_objects > 0) {
            $event = $this->find('first', array(
                    'conditions' => array('Event.id' => $id),
                    'recursive' => -1
            ));
            if ($event['Event']['published'] == 1) {
                $event['Event']['published'] = 0;
            }
            $date = new DateTime();
            $event['Event']['timestamp'] = $date->getTimestamp();
            $this->save($event);
        }
        if ($event_level) {
            return $saved_attributes + $saved_object_attributes;
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
        if ($jobId) {
            $this->Job->saveField('message', 'Processing complete. ' . $message);
            $this->Job->saveField('progress', 100);
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

    private function __saveObjectAttribute($attribute, $default_comment, $event_id, $object_id, $user)
    {
        $attribute['object_id'] = $object_id;
        $attribute['event_id'] = $event_id;
        if (empty($attribute['comment'])) {
            $attribute['comment'] = $default_comment;
        }
        if (!empty($attribute['data']) && !empty($attribute['encrypt'])) {
            $attribute = $this->Attribute->onDemandEncrypt($attribute);
        }
        $this->Attribute->create();
        $attribute_save = $this->Attribute->save($attribute);
        if ($attribute_save) {
            if (!empty($attribute['Tag'])) {
                foreach ($attribute['Tag'] as $tag) {
                    $tag_id = $this->Attribute->AttributeTag->Tag->captureTag($tag, $user);
                    if ($tag_id) {
                        $this->Attribute->AttributeTag->attachTagToAttribute($this->Attribute->id, $event_id, $tag_id);
                    }
                }
            }
        }
        return $attribute_save;
    }

    public function processFreeTextDataRouter($user, $attributes, $id, $default_comment = '', $force = false, $adhereToWarninglists = false, $returnRawResults = false)
    {
        if (Configure::read('MISP.background_jobs')) {
            list($job, $randomFileName, $tempFile) = $this->__initiateProcessJob($user, $id);
            $tempData = array(
                    'user' => $user,
                    'attributes' => $attributes,
                    'id' => $id,
                    'default_comment' => $default_comment,
                    'force' => $force,
                    'adhereToWarninglists' => $adhereToWarninglists,
                    'jobId' => $job->id
            );

            $writeResult = $tempFile->write(json_encode($tempData));
            if (!$writeResult) {
                return ($this->processFreeTextData($user, $attributes, $id, $default_comment, $force, $adhereToWarninglists, false, $returnRawResults));
            }
            $tempFile->close();
            $process_id = CakeResque::enqueue(
                    'prio',
                    'EventShell',
                    array('processfreetext', $randomFileName),
                    true
            );
            $job->saveField('process_id', $process_id);
            return 'Freetext ingestion queued for background processing. Attributes will be added to the event as they are being processed.';
        } else {
            return $this->processFreeTextData($user, $attributes, $id, $default_comment, $force, $adhereToWarninglists, false, $returnRawResults);
        }
    }

    public function processModuleResultsDataRouter($user, $resolved_data, $id, $default_comment = '', $adhereToWarninglists = false)
    {
        if (Configure::read('MISP.background_jobs')) {
            list($job, $randomFileName, $tempFile) = $this->__initiateProcessJob($user, $id, 'module_results');
            $tempData = array(
                    'user' => $user,
                    'misp_format' => $resolved_data,
                    'id' => $id,
                    'default_comment' => $default_comment,
                    'jobId' => $job->id
            );
            $writeResult = $tempFile->write(json_encode($tempData));
            if ($writeResult) {
                $tempFile->close();
                $process_id = CakeResque::enqueue(
                        'prio',
                        'EventShell',
                        array('processmoduleresult', $randomFileName),
                        true
                );
                $job->saveField('process_id', $process_id);
                return 'Module results ingestion queued for background processing. Related data will be added to the event as it is being processed.';
            }
            $tempFile->delete();
        }
        return ($this->processModuleResultsData($user, $attributes, $id, $default_comment = ''));
    }

    private function __initiateProcessJob($user, $id, $format = 'freetext')
    {
        $job = ClassRegistry::init('Job');
        $job->create();
        $data = array(
                'worker' => 'default',
                'job_type' => __('process_' . $format . '_data'),
                'job_input' => 'Event: ' . $id,
                'status' => 0,
                'retries' => 0,
                'org_id' => $user['org_id'],
                'org' => $user['Organisation']['name'],
                'message' => 'Processing...'
        );
        $job->save($data);
        $randomFileName = $this->generateRandomFileName() . '.json';
        App::uses('Folder', 'Utility');
        App::uses('File', 'Utility');
        $tempdir = new Folder(APP . 'tmp/cache/ingest', true, 0755);
        $tempFile = new File(APP . 'tmp/cache/ingest' . DS . $randomFileName, true, 0644);
        return array($job, $randomFileName, $tempFile);
    }

    private function __attachReferences($user, &$event, $sgids, $fields)
    {
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
                            if (!$user['Role']['perm_site_admin'] && $user['org_id'] != $event['Event']['orgc_id']) {
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
    }

    public function restSearch($user, $returnFormat, $filters, $paramsOnly = false, $jobId = false, &$elementCounter = 0, &$renderView = false)
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

        if (empty($exportTool->non_restrictive_export)) {
            if (!isset($filters['to_ids'])) {
                $filters['to_ids'] = 1;
            }
            if (!isset($filters['published'])) {
                $filters['published'] = 1;
            }
            $filters['allow_proposal_blocking'] = 1;
        }

        if (!empty($exportTool->renderView)) {
            $renderView = $exportTool->renderView;
        }

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

        $subqueryElements = $this->harvestSubqueryElements($filters);
        $filters = $this->addFiltersFromSubqueryElements($filters, $subqueryElements);

        $filters['include_attribute_count'] = 1;
        $eventid = $this->filterEventIds($user, $filters, $elementCounter);
        $eventCount = count($eventid);
        $eventids_chunked = $this->__clusterEventIds($exportTool, $eventid);
        unset($eventid);
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
        $tmpfile = tmpfile();
        fwrite($tmpfile, $exportTool->header($exportToolParams));
        $i = 0;
        if (!empty($filters['withAttachments'])) {
            $filters['includeAttachments'] = 1;
        }
        $this->Whitelist = ClassRegistry::init('Whitelist');
        foreach ($eventids_chunked as $chunk_index => $chunk) {
            $filters['eventid'] = $chunk;
            if (!empty($filters['tags']['NOT'])) {
                $filters['blockedAttributeTags'] = $filters['tags']['NOT'];
            }
            $result = $this->fetchEvent(
                $user,
                $filters,
                true
            );
            if (!empty($result)) {
                foreach ($result as $event) {
                    if ($jobId && $i%10 == 0) {
                        $this->Job->saveField('progress', intval((100 * $i) / $eventCount));
                        $this->Job->saveField('message', 'Converting Event ' . $i . '/' . $eventCount . '.');
                    }
                    $result = $this->Whitelist->removeWhitelistedFromArray($result, false);
                    $temp = $exportTool->handler($event, $exportToolParams);
                    if ($temp !== '') {
                        if ($i !== 0) {
                            $temp = $exportTool->separator($exportToolParams) . $temp;
                        }
                        fwrite($tmpfile, $temp);
                        $i++;
                    }
                }
            }
        }
        unset($result);
        unset($temp);
        fwrite($tmpfile, $exportTool->footer($exportToolParams));
        fseek($tmpfile, 0);
        if (fstat($tmpfile)['size'] > 0) {
            $final = fread($tmpfile, fstat($tmpfile)['size']);
        } else {
            $final = 0;
        }
        fclose($tmpfile);
        return $final;
    }

    /*
     *  Receive a list of eventids in the id=>count format
     *  Chunk them by the attribute count to fit the memory limits
     *
     */
    private function __clusterEventIds($exportTool, $eventIds)
    {
        $memory_in_mb = $this->Attribute->convert_to_memory_limit_to_mb(ini_get('memory_limit'));
        $memory_scaling_factor = isset($exportTool->memory_scaling_factor) ? $exportTool->memory_scaling_factor : 100;
        $limit = $memory_in_mb * $memory_scaling_factor;
        $eventIdList = array();
        $continue = true;
        $i = 0;
        $current_chunk_size = 0;
        while (!empty($eventIds)) {
            foreach ($eventIds as $id => $count) {
                if ($current_chunk_size == 0 && $count > $limit) {
                    $eventIdList[$i][] = $id;
                    $current_chunk_size = $count;
                    unset($eventIds[$id]);
                    $i++;
                    break;
                } else {
                    if (($current_chunk_size + $count) > $limit) {
                        $i++;
                        $current_chunk_size = 0;
                        break;
                    } else {
                        $current_chunk_size += $count;
                        $eventIdList[$i][] = $id;
                        unset($eventIds[$id]);
                    }
                }
            }
        }
        return $eventIdList;
    }

    public function add_original_file($file, $original_filename, $event_id, $format)
    {
        if (!Configure::check('MISP.default_attribute_distribution') || Configure::read('MISP.default_attribute_distribution') === 'event') {
            $distribution = 5;
        } else {
            $distribution = Configure::read('MISP.default_attribute_distribution');
        }
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
        $this->Object->save($object);
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
                'data' => base64_encode($file),
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
        foreach ($attributes as $attribute) {
            $this->Attribute->create();
            $this->Attribute->save($attribute);
        }
        return true;
    }

    public function getRequiredTaxonomies()
    {
        $this->Taxonomy = ClassRegistry::init('Taxonomy');
        $required_taxonomies = $this->Taxonomy->find('list', array(
            'recursive' => -1,
            'conditions' => array('Taxonomy.required' => 1, 'Taxonomy.enabled' => 1),
            'fields' => array('Taxonomy.namespace')
        ));
        return $required_taxonomies;
    }

    public function checkIfPublishable($id)
    {
        $required_taxonomies = $this->getRequiredTaxonomies();
        if (!empty($required_taxonomies)) {
            $tags = $this->EventTag->find('all', array(
                'conditions' => array('EventTag.event_id' => $id),
                'recursive' => -1,
                'contain' => array('Tag')
            ));
            $missing = array();
            foreach ($required_taxonomies as $required_taxonomy) {
                $found = false;
                foreach ($tags as $tag) {
                    $name = explode(':', $tag['Tag']['name']);
                    if (count($name) > 1) {
                        if ($name[0] == $required_taxonomy) {
                            $found = true;
                            break;
                        }
                    }
                }
                if (!$found) {
                    $missing[] = $required_taxonomy;
                }
            }
            if (!empty($missing)) {
                return $missing;
            }
        }
        return true;
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

    public function addFiltersFromSubqueryElements($filters, $subqueryElements)
    {
        if (!empty($subqueryElements['galaxy'])) {
            $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
            $tagsFromGalaxyMeta = $this->GalaxyCluster->getClusterTagsFromMeta($subqueryElements['galaxy']);
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
}
