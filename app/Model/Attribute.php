<?php

App::uses('AppModel', 'Model');
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');
App::uses('FinancialTool', 'Tools');
App::uses('RandomTool', 'Tools');
App::uses('AttachmentTool', 'Tools');
App::uses('TmpFileTool', 'Tools');
App::uses('ComplexTypeTool', 'Tools');

/**
 * @property Event $Event
 * @property AttributeTag $AttributeTag
 * @property Sighting $Sighting
 * @property-read array $typeDefinitions
 * @property-read array $categoryDefinitions
 */
class Attribute extends AppModel
{
    public $combinedKeys = array('event_id', 'category', 'type');

    public $name = 'Attribute';             // TODO general

    public $actsAs = array(
        'AuditLog',
        'SysLogLogable.SysLogLogable' => array( // TODO Audit, logable
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'full'),
        'Trim',
        'Containable',
        'Regexp' => array('fields' => array('value')),
    );

    public $displayField = 'value';

    public $virtualFields = array(
            'value' => "CASE WHEN Attribute.value2 = '' THEN Attribute.value1 ELSE CONCAT(Attribute.value1, '|', Attribute.value2) END",
    ); // TODO hardcoded

    // explanations of certain fields to be used in various views
    public $fieldDescriptions = array(
            'signature' => array('desc' => 'Is this attribute eligible to automatically create an IDS signature (network IDS or host IDS) out of it ?'),
            'distribution' => array('desc' => 'Describes who will have access to the attribute.')
    );

    public $defaultFields = array(
        'id', 'event_id', 'object_id', 'object_relation', 'category', 'type', 'value', 'to_ids', 'uuid', 'timestamp', 'distribution', 'sharing_group_id', 'comment', 'deleted', 'disable_correlation', 'first_seen', 'last_seen'
    );

    public $editableFields = array('timestamp', 'category', 'value', 'value1', 'value2', 'to_ids', 'comment', 'distribution', 'sharing_group_id', 'deleted', 'disable_correlation', 'first_seen', 'last_seen');

    public $distributionDescriptions = array(
        0 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "This setting will only allow members of your organisation on this server to see it."),
        1 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "Organisations that are part of this MISP community will be able to see the event."),
        2 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "Organisations that are either part of this MISP community or part of a directly connected MISP community will be able to see the event."),
        3 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "This will share the event with all MISP communities, allowing the event to be freely propagated from one server to the next."),
        4 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "This distribution of this event will be handled by the selected sharing group."),
        5 => array('desc' => 'This field determines the current distribution of the event', 'formdesc' => "Inherit the event's distribution settings"),
    );

    public $distributionLevels = array();

    public $shortDist = array(0 => 'Organisation', 1 => 'Community', 2 => 'Connected', 3 => 'All', 4 => ' Sharing Group', 5 => 'Inherit');

    private $exclusions = null;

    public function __construct($id = false, $table = null, $ds = null)
    {
        parent::__construct($id, $table, $ds);

        $this->distributionLevels = array(
            0 => __('Your organisation only'),
            1 => __('This community only'),
            2 => __('Connected communities'),
            3 => __('All communities'),
            4 => __('Sharing group'),
            5 => __('Inherit event')
        );
    }


    // these are definitions of possible types + their descriptions and maybe later other behaviors
    // e.g. if the attribute should be correlated with others or not

    // if these then a category may have upload to be zipped
    public $zippedDefinitions = array(
            'malware-sample'
    );

    // if these then a category may have upload
    public $uploadDefinitions = array(
            'attachment'
    );

    // skip Correlation for the following types
    public $nonCorrelatingTypes = array(
            'comment',
            'http-method',
            'aba-rtn',
            'gender',
            'counter',
            'port',
            'nationality',
            'cortex',
            'boolean',
            'anonymised'
    );

    public $primaryOnlyCorrelatingTypes = array(
        'ip-src|port',
        'ip-dst|port',
        'hostname|port',
    );

    public $captureFields = array(
        'event_id',
        'category',
        'type',
        'value',
        'value1',
        'value2',
        'to_ids',
        'uuid',
        'timestamp',
        'distribution',
        'comment',
        'sharing_group_id',
        'deleted',
        'disable_correlation',
        'object_id',
        'object_relation',
        'first_seen',
        'last_seen'
    );

    public $searchResponseTypes = array(
        'xml' => array(
            'type' => 'xml',
            'layout' => 'xml/default',
            'header' => 'Content-Disposition: download; filename="misp.search.attribute.results.xml"'
        ),
        'json' => array(
            'type' => 'json',
            'layout' => 'json/default',
            'header' => 'Content-Disposition: download; filename="misp.search.attribute.results.json"'
        ),
        'openioc' => array(
            'type' => 'xml',
            'layout' => 'xml/default',
            'header' => 'Content-Disposition: download; filename="misp.search.attribute.results.openioc.xml"'
        ),
    );

    public $validFormats = array(
        'attack-sightings' => array('json', 'AttackSightingsExport', 'json'),
        'cache' => array('txt', 'CacheExport', 'cache'),
        'count' => array('txt', 'CountExport', 'txt'),
        'csv' => array('csv', 'CsvExport', 'csv'),
        'hashes' => array('txt', 'HashesExport', 'txt'),
        'json' => array('json', 'JsonExport', 'json'),
        'netfilter' => array('txt', 'NetfilterExport', 'sh'),
        'opendata' => array('txt', 'OpendataExport', 'txt'),
        'openioc' => array('xml', 'OpeniocExport', 'ioc'),
        'rpz' => array('txt', 'RPZExport', 'rpz'),
        'snort' => array('txt', 'NidsSnortExport', 'rules'),
        'suricata' => array('txt', 'NidsSuricataExport', 'rules'),
        'text' => array('txt', 'TextExport', 'txt'),
        'xml' => array('xml', 'XmlExport', 'xml'),
        'yara' => array('txt', 'YaraExport', 'yara'),
        'yara-json' => array('json', 'YaraExport', 'json')
    );

    // typeGroupings are a mapping to high level groups for attributes
    // for example, IP addresses, domain names, hostnames and e-mail addresses are network related attribute types
    // whilst filenames and hashes are file related attribute types
    // This helps generate quick filtering for the event view, but we may reuse this and enhance it in the future for other uses (such as the API?)
    public $typeGroupings = array(
        'file' => array('attachment', 'pattern-in-file', 'filename-pattern', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'ssdeep', 'imphash', 'telfhash', 'impfuzzy', 'authentihash', 'vhash', 'pehash', 'tlsh', 'cdhash', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|sha3-224', 'filename|sha3-256', 'filename|sha3-384', 'filename|sha3-512', 'filename|authentihash', 'filename|vhash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash', 'filename|pehash', 'malware-sample', 'x509-fingerprint-sha1', 'x509-fingerprint-sha256', 'x509-fingerprint-md5'),
        'network' => array('ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port', 'mac-address', 'mac-eui-64', 'hostname', 'hostname|port', 'domain', 'domain|ip', 'email-dst', 'url', 'uri', 'user-agent', 'http-method', 'AS', 'snort', 'bro', 'zeek',  'pattern-in-traffic', 'x509-fingerprint-md5', 'x509-fingerprint-sha1', 'x509-fingerprint-sha256','ja3-fingerprint-md5', 'jarm-fingerprint', 'favicon-mmh3', 'hassh-md5', 'hasshserver-md5', 'community-id'),
        'financial' => array('btc', 'xmr', 'iban', 'bic', 'bank-account-nr', 'aba-rtn', 'bin', 'cc-number', 'prtn', 'phone-number')
    );

    private $__fTool = false;

    public $order = array("Attribute.event_id" => "DESC");

    public $validate = array(
        'event_id' => array(
            'numeric' => array(
                'rule' => array('numeric')
            )
        ),
        'type' => array(
            'rule' => array('validateTypeValue'),
            'message' => 'Options depend on the selected category.',
            'required' => true
        ),
        'category' => array(
            'rule' => array('validCategory'),
            'message' => 'Options : Payload delivery, Antivirus detection, Payload installation, Files dropped ...'
        ),
        'value' => array(
            'stringNotEmpty' => array(
                'rule' => array('stringNotEmpty')
            ),
            'stringControlCharacters' => array(
                'rule' => array('stringNotControlCharacters'),
                'message' => 'Value provided consists purely of control characters and is therefore considered to be empty.'
            ),
            'validComposite' => array(
                'rule' => array('validComposite'),
                'message' => 'Composite type found but the value not in the composite (value1|value2) format.'
            ),
            'userdefined' => array(
                'rule' => array('validateAttributeValue'),
                'message' => 'Value not in the right type/format. Please double check the value or select type "other".'
            ),
            'uniqueValue' => array(
                'rule' => array('valueIsUnique'),
                'message' => 'A similar attribute already exists for this event.'
            ),
            'maxTextLength' => array(
                'rule' => array('maxTextLength')
            )
        ),
        'to_ids' => array(
            'boolean' => array(
                'rule' => array('boolean'),
                'required' => false
            )
        ),
        'uuid' => array(
            'uuid' => array(
                'rule' => 'uuid',
                'message' => 'Please provide a valid RFC 4122 UUID'
            ),
            'unique' => array(
                'rule' => 'isUnique',
                'message' => 'The UUID provided is not unique',
                'required' => 'create'
            )
        ),
        'distribution' => array(
                'rule' => array('inList', array('0', '1', '2', '3', '4', '5')),
                'message' => 'Options: Your organisation only, This community only, Connected communities, All communities, Sharing group, Inherit event',
                'required' => true
        ),
        'first_seen' => array(
            'rule' => array('datetimeOrNull'),
            'required' => false,
            'message' => array('Invalid ISO 8601 format')
        ),
        'last_seen' => array(
            'datetimeOrNull' => array(
                'rule' => array('datetimeOrNull'),
                'required' => false,
                'message' => array('Invalid ISO 8601 format')
            ),
            'validateLastSeenValue' => array(
                'rule' => array('validateLastSeenValue'),
                'required' => false,
                'message' => array('Last seen value should be greater than first seen value')
            ),
        )
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
            'Payload delivery' => array('File', 'CnC'),
            'Payload installation' => array('File'),
            'Artifacts dropped' => array('File'),
            'Network activity' => array('CnC'),
    );

    public $belongsTo = array(
        'Event' => array(
            'className' => 'Event',
            'foreignKey' => 'event_id',
            'conditions' => '',
            'fields' => '',
            //'counterCache' => 'attribute_count',
            //'counterScope' => array('Attribute.deleted' => 0),
            'order' => ''
        ),
        'SharingGroup' => array(
                'className' => 'SharingGroup',
                'foreignKey' => 'sharing_group_id'
        ),
        'Object' => array(
            'className' => 'MispObject',
            'foreignKey' => 'object_id'
        )
    );

    public $hasMany = [
        'AttributeTag' => [
            'dependent' => true
        ],
        'Correlation' => [
            'dependent' => false
        ],
        'Sighting' => [
                'className' => 'Sighting',
                'dependent' => true,
        ]
    ];

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

    public function afterFind($results, $primary = false)
    {
        foreach ($results as $k => $v) {
            if (isset($v['Attribute']['object_relation']) && $v['Attribute']['object_relation'] === null) {
                $results[$k]['Attribute']['object_relation'] = '';
            }
            $results[$k] = $this->UTCToISODatetime($results[$k], $this->alias);
        }
        return $results;
    }

    public function beforeSave($options = array())
    {
        if (!empty($this->data['Attribute']['id'])) {
            $this->old = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('Attribute.id' => $this->data['Attribute']['id'])
            ));
        } else {
            $this->old = false;
        }
        // explode value of composite type in value1 and value2
        // or copy value to value1 if not composite type
        if (!empty($this->data['Attribute']['type'])) {
            $compositeTypes = $this->getCompositeTypes();
            // explode composite types in value1 and value2
            if (in_array($this->data['Attribute']['type'], $compositeTypes)) {
                $pieces = explode('|', $this->data['Attribute']['value']);
                if (2 != count($pieces)) {
                    throw new InternalErrorException(__('Composite type, but value not explodable'));
                }
                $this->data['Attribute']['value1'] = $pieces[0];
                $this->data['Attribute']['value2'] = $pieces[1];
            } else {
                $this->data['Attribute']['value1'] = $this->data['Attribute']['value'];
                $this->data['Attribute']['value2'] = '';
            }
        }

        $this->data = $this->ISODatetimeToUTC($this->data, $this->alias);
        // always return true after a beforeSave()
        return true;
    }

    private function __alterAttributeCount($event_id, $increment = true)
    {
        return $this->Event->updateAll(
            array('Event.attribute_count' => $increment ? 'Event.attribute_count+1' : 'GREATEST(Event.attribute_count, 1) - 1'),
            array('Event.id' => $event_id)
        );
    }

    public function afterSave($created, $options = array())
    {
        $passedEvent = false;
        if (isset($options['parentEvent'])) {
            $passedEvent = $options['parentEvent'];
        }
        parent::afterSave($created, $options);
        // add attributeTags via the shorthand ID list
        if (!empty($this->data['Attribute']['tag_ids'])) {
            foreach ($this->data['Attribute']['tag_ids'] as $tag_id) {
                $this->AttributeTag->attachTagToAttribute($this->id, $this->data['Attribute']['event_id'], $tag_id);
            }
        }
        // update correlation...
        if (isset($this->data['Attribute']['deleted']) && $this->data['Attribute']['deleted']) {
            if (empty($this->Correlation)) {
                $this->Correlation = ClassRegistry::init('Correlation');
            }
            $this->Correlation->beforeSaveCorrelation($this->data['Attribute']);
            if (isset($this->data['Attribute']['event_id'])) {
                $this->__alterAttributeCount($this->data['Attribute']['event_id'], false);
            }
        } else {
            /*
             * Only recorrelate if:
             * - We are dealing with a new attribute OR
             * - The existing attribute's previous state is known AND
             *   value, type, disable correlation or distribution have changed
             * This will avoid recorrelations when it's not really needed, such as adding a tag
             */
            if (!$created) {
                if (
                    empty($this->old) ||
                    $this->data['Attribute']['value'] != $this->old['Attribute']['value'] ||
                    $this->data['Attribute']['disable_correlation'] != $this->old['Attribute']['disable_correlation'] ||
                    $this->data['Attribute']['type'] != $this->old['Attribute']['type'] ||
                    $this->data['Attribute']['distribution'] != $this->old['Attribute']['distribution'] ||
                    $this->data['Attribute']['sharing_group_id'] != $this->old['Attribute']['sharing_group_id']
                ) {
                    $this->Correlation->beforeSaveCorrelation($this->data['Attribute']);
                    $this->Correlation->afterSaveCorrelation($this->data['Attribute'], false, $passedEvent);
                }
            } else {
                $this->Correlation->afterSaveCorrelation($this->data['Attribute'], false, $passedEvent);
            }
        }
        $result = true;
        // if the 'data' field is set on the $this->data then save the data to the correct file
        if (isset($this->data['Attribute']['type']) && $this->typeIsAttachment($this->data['Attribute']['type']) && !empty($this->data['Attribute']['data'])) {
            $result = $result && $this->saveBase64EncodedAttachment($this->data['Attribute']); // TODO : is this correct?
        }
        $pubToZmq = Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_attribute_notifications_enable');
        $kafkaTopic = Configure::read('Plugin.Kafka_attribute_notifications_topic');
        $pubToKafka = Configure::read('Plugin.Kafka_enable') && Configure::read('Plugin.Kafka_attribute_notifications_enable') && !empty($kafkaTopic);
        if ($pubToZmq || $pubToKafka) {
            $attribute = $this->fetchAttribute($this->id);
            if (!empty($attribute)) {
                $user = array(
                    'org_id' => -1,
                    'Role' => array(
                        'perm_site_admin' => 1
                    )
                );
                $attribute['Attribute']['Sighting'] = $this->Sighting->attachToEvent($attribute, $user, $attribute);
                if (empty($attribute['Object']['id'])) {
                    unset($attribute['Object']);
                }
                $action = $created ? 'add' : 'edit';
                if (!empty($this->data['Attribute']['deleted'])) {
                    $action = 'soft-delete';
                }
                if ($pubToZmq) {
                    if (Configure::read('Plugin.ZeroMQ_include_attachments') && $this->typeIsAttachment($attribute['Attribute']['type'])) {
                        $attribute['Attribute']['data'] = $this->base64EncodeAttachment($attribute['Attribute']);
                    }
                    $pubSubTool = $this->getPubSubTool();
                    $pubSubTool->attribute_save($attribute, $action);
                    unset($attribute['Attribute']['data']);
                }
                if ($pubToKafka) {
                    if (Configure::read('Plugin.Kafka_include_attachments') && $this->typeIsAttachment($attribute['Attribute']['type'])) {
                        $attribute['Attribute']['data'] = $this->base64EncodeAttachment($attribute['Attribute']);
                    }
                    $kafkaPubTool = $this->getKafkaPubTool();
                    $kafkaPubTool->publishJson($kafkaTopic, $attribute, $action);
                }
            }
        }
        if (Configure::read('MISP.enable_advanced_correlations') && in_array($this->data['Attribute']['type'], array('ip-src', 'ip-dst')) && strpos($this->data['Attribute']['value'], '/')) {
            $this->setCIDRList();
        }
        if ($created && isset($this->data['Attribute']['event_id']) && empty($this->data['Attribute']['skip_auto_increment'])) {
            $this->__alterAttributeCount($this->data['Attribute']['event_id']);
        }
        return $result;
    }

    public function beforeDelete($cascade = true)
    {
        // delete attachments from the disk
        $this->read(); // first read the attribute from the db
        if ($this->typeIsAttachment($this->data['Attribute']['type'])) {
            $this->loadAttachmentTool()->delete($this->data['Attribute']['event_id'], $this->data['Attribute']['id']);
        }
        // update correlation..
        $this->Correlation->beforeDeleteCorrelation($this->data['Attribute']['id']);
        if (!empty($this->data['Attribute']['id'])) {
            if (Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_attribute_notifications_enable')) {
                $pubSubTool = $this->getPubSubTool();
                $pubSubTool->attribute_save($this->data, 'delete');
            }
            $kafkaTopic = Configure::read('Plugin.Kafka_attribute_notifications_topic');
            if (Configure::read('Plugin.Kafka_enable') && Configure::read('Plugin.Kafka_attribute_notifications_enable') && !empty($kafkaTopic)) {
                $kafkaPubTool = $this->getKafkaPubTool();
                $kafkaPubTool->publishJson($kafkaTopic, $this->data, 'delete');
            }
        }
    }

    public function afterDelete()
    {
        if (Configure::read('MISP.enable_advanced_correlations') && in_array($this->data['Attribute']['type'], array('ip-src', 'ip-dst')) && strpos($this->data['Attribute']['value'], '/')) {
            $this->setCIDRList();
        }
        if (isset($this->data['Attribute']['event_id'])) {
            if (empty($this->data['Attribute']['deleted'])) {
                $this->__alterAttributeCount($this->data['Attribute']['event_id'], false);
            }
        }
        if (!empty($this->data['Attribute']['id'])) {
            $this->Object->ObjectReference->deleteAll(
                array(
                    'ObjectReference.referenced_type' => 0,
                    'ObjectReference.referenced_id' => $this->data['Attribute']['id'],
                ),
                false
            );
            if ($this->data['Attribute']['type'] === 'ssdeep') {
                $this->FuzzyCorrelateSsdeep = ClassRegistry::init('FuzzyCorrelateSsdeep');
                $this->FuzzyCorrelateSsdeep->purge(null, $this->data['Attribute']['id']);
            }
        }
    }

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        if (!isset($this->data['Attribute']['type'])) {
            $this->validationErrors['type'] = ['No type set.'];
            return false;
        }
        if (is_array($this->data['Attribute']['value'])) {
            $this->validationErrors['type'] = ['Value is an array.'];
            return false;
        }
        App::uses('ComplexTypeTool', 'Tools');
        $this->data['Attribute']['value'] = ComplexTypeTool::refangValue($this->data['Attribute']['value'], $this->data['Attribute']['type']);

        if (!empty($this->data['Attribute']['object_id']) && empty($this->data['Attribute']['object_relation'])) {
            $this->validationErrors['type'] = ['Object attribute sent, but no object_relation set.'];
            return false;
        }
        // remove leading and trailing blanks
        $this->data['Attribute']['value'] = trim($this->data['Attribute']['value']);
        // make some last changes to the inserted value
        $this->data['Attribute']['value'] = $this->modifyBeforeValidation($this->data['Attribute']['type'], $this->data['Attribute']['value']);

        // set to_ids if it doesn't exist
        if (empty($this->data['Attribute']['to_ids'])) {
            $this->data['Attribute']['to_ids'] = 0;
        }

        if (empty($this->data['Attribute']['comment'])) {
            $this->data['Attribute']['comment'] = "";
        }
        // generate UUID if it doesn't exist
        if (empty($this->data['Attribute']['uuid'])) {
            $this->data['Attribute']['uuid'] = CakeText::uuid();
        } else {
            $this->data['Attribute']['uuid'] = strtolower($this->data['Attribute']['uuid']);
        }
        // generate timestamp if it doesn't exist
        if (empty($this->data['Attribute']['timestamp'])) {
            $date = new DateTime();
            $this->data['Attribute']['timestamp'] = $date->getTimestamp();
        }

        // parse first_seen different formats
        if (isset($this->data['Attribute']['first_seen'])) {
            $this->data['Attribute']['first_seen'] = $this->data['Attribute']['first_seen'] === '' ? null : $this->data['Attribute']['first_seen'];
        }
        // parse last_seen different formats
        if (isset($this->data['Attribute']['last_seen'])) {
            $this->data['Attribute']['last_seen'] = $this->data['Attribute']['last_seen'] === '' ? null : $this->data['Attribute']['last_seen'];
        }

        // TODO: add explanatory comment
        // TODO: i18n?
        $result = $this->runRegexp($this->data['Attribute']['type'], $this->data['Attribute']['value']);
        if ($result === false) {
            $this->invalidate('value', 'This value is blocked by a regular expression in the import filters.');
        } else {
            $this->data['Attribute']['value'] = $result;
        }

        // Set defaults for when some of the mandatory fields don't have defaults
        // These fields all have sane defaults either based on another field, or due to server settings
        if (!isset($this->data['Attribute']['distribution'])) {
            $this->data['Attribute']['distribution'] = Configure::read('MISP.default_attribute_distribution');
            if ($this->data['Attribute']['distribution'] == 'event') {
                $this->data['Attribute']['distribution'] = 5;
            }
        }

        if (!empty($this->data['Attribute']['type']) && empty($this->data['Attribute']['category'])) {
            $this->data['Attribute']['category'] = $this->typeDefinitions[$this->data['Attribute']['type']]['default_category'];
        }

        if (!isset($this->data['Attribute']['to_ids'])) {
            $this->data['Attribute']['to_ids'] = $this->typeDefinitions[$this->data['Attribute']['type']]['to_ids'];
        }

        if ($this->data['Attribute']['distribution'] != 4) {
            $this->data['Attribute']['sharing_group_id'] = 0;
        }
        // return true, otherwise the object cannot be saved
        return true;
    }

    public function validComposite($fields)
    {
        $compositeTypes = $this->getCompositeTypes();
        if (in_array($this->data['Attribute']['type'], $compositeTypes, true)) {
            if (substr_count($fields['value'], '|') !== 1) {
                return false;
            }
        }
        return true;
    }

    public function stringNotControlCharacters($fields)
    {
        if (ctype_cntrl($this->data['Attribute']['value'])) {
            return false;
        }
        if (in_array($this->data['Attribute']['type'], $this->getCompositeTypes())) {
            $values = explode('|', $this->data['Attribute']['value']);
            if (ctype_cntrl($values[0])) {
                return false;
            }
            if (!empty($values[1]) && ctype_cntrl($values[1])) {
                return false;
            }
        }
        return true;
    }

    public function maxTextLength($fields)
    {
        if (strlen($fields['value']) > 65535) {
            return __('The entered string is too long and would get truncated. Please consider adding the data as an attachment instead');
        }
        return true;
    }

    public function validCategory($fields)
    {
        return isset($this->categoryDefinitions[$fields['category']]);
    }

    /**
     * Check if the attribute already exists in the same event.
     *
     * @param array $fields
     * @return bool
     */
    public function valueIsUnique($fields)
    {
        if (isset($this->data['Attribute']['deleted']) && $this->data['Attribute']['deleted']) {
            return true;
        }
        // We escape this rule for objects as we can have the same category/type/value combination in different objects
        if (!empty($this->data['Attribute']['object_relation'])) {
            return true;
        }

        $eventId = $this->data['Attribute']['event_id'];
        $category = $this->data['Attribute']['category'];
        $type = $this->data['Attribute']['type'];

        $conditions = array(
            'Attribute.event_id' => $eventId,
            'Attribute.type' => $type,
            'Attribute.category' => $category,
            'Attribute.deleted' => 0,
            'Attribute.object_id' => 0,
        );

        $value = $fields['value'];
        if (in_array($type, $this->getCompositeTypes())) {
            $value = explode('|', $value);
            $conditions['Attribute.value1'] = $value[0];
            $conditions['Attribute.value2'] = $value[1];
        } else {
            $conditions['Attribute.value1'] = $value;
        }

        if (isset($this->data['Attribute']['id'])) {
            $conditions['Attribute.id !='] = $this->data['Attribute']['id'];
        }

        $params = array(
            'recursive' => -1,
            'fields' => array('id'),
            'conditions' => $conditions,
            'order' => false,
        );
        if (!empty($this->find('first', $params))) {
            // value isn't unique
            return false;
        }
        // value is unique
        return true;
    }

    public function validateTypeValue($fields)
    {
        $category = $this->data['Attribute']['category'];
        if (isset($this->categoryDefinitions[$category]['types'])) {
            return in_array($fields['type'], $this->categoryDefinitions[$category]['types'], true);
        }
        return false;
    }

    public function validateAttributeValue($fields)
    {
        $value = $fields['value'];
        return $this->runValidation($value, $this->data['Attribute']['type']);
    }

    // check whether the variable is null or datetime
    public function datetimeOrNull($fields)
    {
        $k = array_keys($fields)[0];
        $seen = $fields[$k];
        try {
            new DateTime($seen);
            $returnValue = true;
        } catch (Exception $e) {
            $returnValue = false;
        }
        return $returnValue || is_null($seen);
    }

    public function validateLastSeenValue($fields)
    {
        $ls = $fields['last_seen'];
        if (is_null($this->data['Attribute']['first_seen']) || is_null($ls)) {
            return true;
        }
        $converted = $this->ISODatetimeToUTC(['Attribute' => [
            'first_seen' => $this->data['Attribute']['first_seen'],
            'last_seen' => $ls
        ]], 'Attribute');
        if ($converted['Attribute']['first_seen'] > $converted['Attribute']['last_seen']) {
            return false;
        }
        return true;
    }

    private $__hexHashLengths = array(
        'authentihash' => 64,
        'md5' => 32,
        'imphash' => 32,
        'telfhash' => 70,
        'sha1' => 40,
        'git-commit-id' => 40,
        'x509-fingerprint-md5' => 32,
        'x509-fingerprint-sha1' => 40,
        'x509-fingerprint-sha256' => 64,
        'ja3-fingerprint-md5' => 32,
        'jarm-fingerprint' => 62,
        'hassh-md5' => 32,
        'hasshserver-md5' => 32,
        'pehash' => 40,
        'sha224' => 56,
        'sha256' => 64,
        'sha384' => 96,
        'sha512' => 128,
        'sha512/224' => 56,
        'sha512/256' => 64,
        'sha3-224' => 56,
        'sha3-256' => 64,
        'sha3-384' => 96,
        'sha3-512' => 128
    );

    public function runValidation($value, $type)
    {
        $returnValue = false;
        // check data validation
        switch ($type) {
            case 'md5':
            case 'imphash':
            case 'telfhash':
            case 'sha1':
            case 'sha224':
            case 'sha256':
            case 'sha384':
            case 'sha512':
            case 'sha512/224':
            case 'sha512/256':
            case 'sha3-224':
            case 'sha3-256':
            case 'sha3-384':
            case 'sha3-512':
            case 'authentihash':
            case 'ja3-fingerprint-md5':
            case 'jarm-fingerprint':
            case 'hassh-md5':
            case 'hasshserver-md5':
            case 'x509-fingerprint-md5':
            case 'x509-fingerprint-sha256':
            case 'x509-fingerprint-sha1':
            case 'git-commit-id':
                if ($this->isHashValid($type, $value)) {
                    return true;
                } else {
                    $length = $this->__hexHashLengths[$type];
                    return __('Checksum has an invalid length or format (expected: %s hexadecimal characters). Please double check the value or select type "other".', $length);
                }
            case 'tlsh':
                if (preg_match("#^[0-9a-f]{35,}$#", $value)) {
                    $returnValue = true;
                } else {
                    $returnValue = __('Checksum has an invalid length or format (expected: at least 35 hexadecimal characters). Please double check the value or select type "other".');
                }
                break;
            case 'pehash':
                if ($this->isHashValid('pehash', $value)) {
                    $returnValue = true;
                } else {
                    $returnValue = __('The input doesn\'t match the expected sha1 format (expected: 40 hexadecimal characters). Keep in mind that MISP currently only supports SHA1 for PEhashes, if you would like to get the support extended to other hash types, make sure to create a github ticket about it at https://github.com/MISP/MISP!');
                }
                break;
            case 'ssdeep':
                if (substr_count($value, ':') === 2) {
                    $parts = explode(':', $value);
                    if ($this->isPositiveInteger($parts[0])) {
                        return true;
                    }
                }
                return __('Invalid SSDeep hash. The format has to be blocksize:hash:hash');
            case 'impfuzzy':
                if (substr_count($value, ':') === 2) {
                    $parts = explode(':', $value);
                    if ($this->isPositiveInteger($parts[0])) {
                        $returnValue = true;
                    }
                }
                if (!$returnValue) {
                    $returnValue = __('Invalid impfuzzy format. The format has to be imports:hash:hash');
                }
                break;
            case 'cdhash':
                if (preg_match("#^[0-9a-f]{40,}$#", $value)) {
                    $returnValue = true;
                } else {
                    $returnValue = __('The input doesn\'t match the expected format (expected: 40 or more hexadecimal characters)');
                }
                break;
            case 'http-method':
                if (preg_match("#(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|VERSION-CONTROL|REPORT|CHECKOUT|CHECKIN|UNCHECKOUT|MKWORKSPACE|UPDATE|LABEL|MERGE|BASELINE-CONTROL|MKACTIVITY|ORDERPATCH|ACL|PATCH|SEARCH)#", $value)) {
                    $returnValue = true;
                } else {
                    $returnValue = __('Unknown HTTP method.');
                }
                break;
            case 'filename|pehash':
                // no newline
                if (preg_match("#^.+\|[0-9a-f]{40}$#", $value)) {
                    $returnValue = true;
                } else {
                    $returnValue = __('The input doesn\'t match the expected filename|sha1 format (expected: filename|40 hexadecimal characters). Keep in mind that MISP currently only supports SHA1 for PEhashes, if you would like to get the support extended to other hash types, make sure to create a github ticket about it at https://github.com/MISP/MISP!');
                }
                break;
            case 'filename|md5':
            case 'filename|sha1':
            case 'filename|imphash':
            case 'filename|sha224':
            case 'filename|sha256':
            case 'filename|sha384':
            case 'filename|sha512':
            case 'filename|sha512/224':
            case 'filename|sha512/256':
            case 'filename|sha3-224':
            case 'filename|sha3-256':
            case 'filename|sha3-384':
            case 'filename|sha3-512':
            case 'filename|authentihash':
                $parts = explode('|', $type);
                $length = $this->__hexHashLengths[$parts[1]];
                if (preg_match("#^.+\|[0-9a-f]{" . $length . "}$#", $value)) {
                    $returnValue = true;
                } else {
                    $returnValue = __('Checksum has an invalid length or format (expected: filename|%s hexadecimal characters). Please double check the value or select type "other".', $length);
                }
                break;
            case 'filename|ssdeep':
                if (substr_count($value, '|') != 1 || !preg_match("#^.+\|.+$#", $value)) {
                    $returnValue = __('Invalid composite type. The format has to be %s.', $type);
                } else {
                    $composite = explode('|', $value);
                    $value = $composite[1];
                    if (substr_count($value, ':') == 2) {
                        $parts = explode(':', $value);
                        if ($this->isPositiveInteger($parts[0])) {
                            $returnValue = true;
                        }
                    }
                    if (!$returnValue) {
                        $returnValue = __('Invalid SSDeep hash (expected: blocksize:hash:hash).');
                    }
                }
                break;
            case 'filename|tlsh':
                if (preg_match("#^.+\|[0-9a-f]{35,}$#", $value)) {
                    $returnValue = true;
                } else {
                    $returnValue = __('Checksum has an invalid length or format (expected: filename|at least 35 hexadecimal characters). Please double check the value or select type "other".');
                }
                break;
            case 'filename|vhash':
                if (preg_match('#^.+\|.+$#', $value)) {
                    $returnValue = true;
                } else {
                    $returnValue = __('Checksum has an invalid length or format (expected: filename|string characters). Please double check the value or select type "other".');
                }
                break;
            case 'ip-src':
            case 'ip-dst':
                if (strpos($value, '/') !== false) {
                    $parts = explode("/", $value);
                    if (count($parts) !== 2 || !$this->isPositiveInteger($parts[1])) {
                        return __('Invalid CIDR notation value found.');
                    }

                    if (filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        if ($parts[1] > 32) {
                            return __('Invalid CIDR notation value found, for IPv4 must be lower or equal 32.');
                        }
                    } else if (filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                        if ($parts[1] > 128) {
                            return __('Invalid CIDR notation value found, for IPv6 must be lower or equal 128.');
                        }
                    } else {
                        return __('IP address has an invalid format.');
                    }
                } else if (!filter_var($value, FILTER_VALIDATE_IP)) {
                    return  __('IP address has an invalid format.');
                }
                return true;

            case 'port':
                if (!$this->isPortValid($value)) {
                    $returnValue = __('Port numbers have to be integers between 1 and 65535.');
                } else {
                    $returnValue = true;
                }
                break;
            case 'ip-dst|port':
            case 'ip-src|port':
                $parts = explode('|', $value);
                if (!filter_var($parts[0], FILTER_VALIDATE_IP)) {
                    return __('IP address has an invalid format.');
                }
                if (!$this->isPortValid($parts[1])) {
                    return __('Port numbers have to be integers between 1 and 65535.');
                }
                return true;
            case 'mac-address':
                if (preg_match('/^([a-fA-F0-9]{2}[:]?){6}$/', $value)) {
                    $returnValue = true;
                }
                break;
            case 'mac-eui-64':
                if (preg_match('/^([a-fA-F0-9]{2}[:]?){8}$/', $value)) {
                    $returnValue = true;
                }
                break;
            case 'hostname':
            case 'domain':
                if ($this->isDomainValid($value)) {
                    $returnValue = true;
                } else {
                    $returnValue = __('%s has an invalid format. Please double check the value or select type "other".', ucfirst($type));
                }
                break;
            case 'hostname|port':
                $parts = explode('|', $value);
                if (!$this->isDomainValid($parts[0])) {
                    return __('Hostname has an invalid format.');
                }
                if (!$this->isPortValid($parts[1])) {
                    return __('Port numbers have to be integers between 1 and 65535.');
                }
                return true;
            case 'domain|ip':
                if (preg_match("#^[A-Z0-9.\-_]+\.[A-Z0-9\-]{2,}\|.*$#i", $value)) {
                    $parts = explode('|', $value);
                    if (filter_var($parts[1], FILTER_VALIDATE_IP)) {
                        $returnValue = true;
                    } else {
                        $returnValue = __('IP address has an invalid format.');
                    }
                } else {
                    $returnValue = __('Domain name has an invalid format.');
                }
                break;
            case 'email':
            case 'email-src':
            case 'eppn':
            case 'email-dst':
            case 'target-email':
            case 'whois-registrant-email':
            case 'dns-soa-email':
            case 'jabber-id':
                // we don't use the native function to prevent issues with partial email addresses
                if (preg_match("#^.*\@.*\..*$#i", $value)) {
                    $returnValue = true;
                } else {
                    $returnValue = __('Email address has an invalid format. Please double check the value or select type "other".');
                }
                break;
            case 'vulnerability':
                if (preg_match("#^(CVE-)[0-9]{4}(-)[0-9]{4,}$#", $value)) {
                    $returnValue = true;
                } else {
                    $returnValue = __('Invalid format. Expected: CVE-xxxx-xxxx...');
                }
                break;
            case 'weakness':
                if (preg_match("#^(CWE-)[0-9]{1,}$#", $value)) {
                    $returnValue = true;
                } else {
                    $returnValue = __('Invalid format. Expected: CWE-x...');
                }
                break;
            case 'named pipe':
                if (!preg_match("#\n#", $value)) {
                    $returnValue = true;
                }
                break;
            case 'windows-service-name':
            case 'windows-service-displayname':
                if (strlen($value) > 256 || preg_match('#[\\\/]#', $value)) {
                    $returnValue = __('Invalid format. Only values shorter than 256 characters that don\'t include any forward or backward slashes are allowed.');
                } else {
                    $returnValue = true;
                }
                break;
            case 'mutex':
            case 'process-state':
            case 'snort':
            case 'bro':
            case 'zeek':
            case 'community-id':
            case 'anonymised':
            case 'pattern-in-file':
            case 'pattern-in-traffic':
            case 'pattern-in-memory':
            case 'filename-pattern':
            case 'pgp-public-key':
            case 'pgp-private-key':
            case 'yara':
            case 'stix2-pattern':
            case 'sigma':
            case 'gene':
            case 'kusto-query':
            case 'mime-type':
            case 'identity-card-number':
            case 'cookie':
            case 'attachment':
            case 'malware-sample':
            case 'comment':
            case 'text':
            case 'other':
            case 'cpe':
            case 'email-attachment':
            case 'email-body':
            case 'email-header':
            case 'first-name':
            case 'middle-name':
            case 'last-name':
            case 'full-name':
                $returnValue = true;
                break;
            case 'link':
                // Moved to a native function whilst still enforcing the scheme as a requirement
                if (filter_var($value, FILTER_VALIDATE_URL, FILTER_FLAG_SCHEME_REQUIRED) && !preg_match("#\n#", $value)) {
                    $returnValue = true;
                }
                break;
            case 'hex':
                return ctype_xdigit($value);
            case 'target-user':
            case 'campaign-name':
            case 'campaign-id':
            case 'threat-actor':
            case 'target-machine':
            case 'target-org':
            case 'target-location':
            case 'target-external':
            case 'email-subject':
            case 'malware-type':
            // TODO: review url/uri validation
            case 'url':
            case 'uri':
            case 'user-agent':
            case 'regkey':
            case 'regkey|value':
            case 'filename':
            case 'pdb':
            case 'windows-scheduled-task':
            case 'whois-registrant-name':
            case 'whois-registrant-org':
            case 'whois-registrar':
            case 'whois-creation-date':
            case 'date-of-birth':
            case 'place-of-birth':
            case 'gender':
            case 'passport-number':
            case 'passport-country':
            case 'passport-expiration':
            case 'redress-number':
            case 'nationality':
            case 'visa-number':
            case 'issue-date-of-the-visa':
            case 'primary-residence':
            case 'country-of-residence':
            case 'special-service-request':
            case 'frequent-flyer-number':
            case 'travel-details':
            case 'payment-details':
            case 'place-port-of-original-embarkation':
            case 'place-port-of-clearance':
            case 'place-port-of-onward-foreign-destination':
            case 'passenger-name-record-locator-number':
            case 'email-dst-display-name':
            case 'email-src-display-name':
            case 'email-reply-to':
            case 'email-x-mailer':
            case 'email-mime-boundary':
            case 'email-thread-index':
            case 'email-message-id':
            case 'github-username':
            case 'github-repository':
            case 'github-organisation':
            case 'twitter-id':
            case 'dkim':
            case 'dkim-signature':
            case 'favicon-mmh3':
            case 'chrome-extension-id':
            case 'mobile-application-id':
                if (strpos($value, "\n") !== false) {
                    return __('Value must not contain new line character.');
                }
                return true;
            case 'datetime':
                try {
                    new DateTime($value);
                    $returnValue = true;
                } catch (Exception $e) {
                    $returnValue = __('Datetime has to be in the ISO 8601 format.');
                }
                break;
            case 'size-in-bytes':
            case 'counter':
                if ($this->isPositiveInteger($value)) {
                    return true;
                }
                return __('The value has to be a whole number greater or equal 0.');
            case 'targeted-threat-index':
                if (!is_numeric($value) || $value < 0 || $value > 10) {
                    $returnValue = __('The value has to be a number between 0 and 10.');
                } else {
                    $returnValue = true;
                }
                break;
            case 'iban':
            case 'bic':
            case 'btc':
            case 'dash':
            case 'xmr':
                if (preg_match('/^[a-zA-Z0-9]+$/', $value)) {
                    $returnValue = true;
                }
                break;
            case 'vhash':
                if (preg_match('/^.+$/', $value)) {
                    $returnValue = true;
                }
                break;
            case 'bin':
            case 'cc-number':
            case 'bank-account-nr':
            case 'aba-rtn':
            case 'prtn':
            case 'phone-number':
            case 'whois-registrant-phone':
                if (is_numeric($value)) {
                    $returnValue = true;
                }
                break;
            case 'cortex':
                json_decode($value);
                $returnValue = (json_last_error() == JSON_ERROR_NONE);
                break;
            case 'float':
                return is_numeric($value);
            case 'boolean':
                if ($value == 1 || $value == 0) {
                    $returnValue = true;
                }
                break;
            case 'AS':
                if ($this->isPositiveInteger($value) && $value <= 4294967295) {
                    return true;
                }
                return __('AS number have to be integers between 1 and 4294967295');
        }
        return $returnValue;
    }

    // do some last second modifications before the validation
    public function modifyBeforeValidation($type, $value)
    {
        $value = $this->handle4ByteUnicode($value);
        switch ($type) {
            case 'md5':
            case 'sha1':
            case 'sha224':
            case 'sha256':
            case 'sha384':
            case 'sha512':
            case 'sha512/224':
            case 'sha512/256':
            case 'sha3-224':
            case 'sha3-256':
            case 'sha3-384':
            case 'sha3-512':
            case 'ja3-fingerprint-md5':
            case 'jarm-fingerprint':
            case 'hassh-md5':
            case 'hasshserver-md5':
            case 'hostname':
            case 'pehash':
            case 'authentihash':
            case 'vhash':
            case 'imphash':
            case 'telfhash':
            case 'tlsh':
            case 'anonymised':
            case 'cdhash':
            case 'email':
            case 'email-src':
            case 'email-dst':
            case 'target-email':
            case 'whois-registrant-email':
                $value = strtolower($value);
                break;
            case 'domain':
                $value = strtolower($value);
                $value = trim($value, '.');
                // Domain is not valid, try to convert to punycode
                if (!$this->isDomainValid($value) && function_exists('idn_to_ascii')) {
                    $punyCode = idn_to_ascii($value);
                    if ($punyCode !== false) {
                        $value = $punyCode;
                    }
                }
                break;
            case 'domain|ip':
                $value = strtolower($value);
                $parts = explode('|', $value);
                $parts[0] = trim($parts[0], '.');
                // Domain is not valid, try to convert to punycode
                if (!$this->isDomainValid($parts[0]) && function_exists('idn_to_ascii')) {
                    $punyCode = idn_to_ascii($parts[0]);
                    if ($punyCode !== false) {
                        $parts[0] = $punyCode;
                    }
                }
                if (filter_var($parts[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    // convert IPv6 address to compressed format
                    $parts[1] = inet_ntop(inet_pton($value));
                }
                $value = implode('|', $parts);
                break;
            case 'filename|md5':
            case 'filename|sha1':
            case 'filename|imphash':
            case 'filename|sha224':
            case 'filename|sha256':
            case 'filename|sha384':
            case 'filename|sha512':
            case 'filename|sha512/224':
            case 'filename|sha512/256':
            case 'filename|sha3-224':
            case 'filename|sha3-256':
            case 'filename|sha3-384':
            case 'filename|sha3-512':
            case 'filename|authentihash':
            case 'filename|vhash':
            case 'filename|pehash':
            case 'filename|tlsh':
                $pieces = explode('|', $value);
                $value = $pieces[0] . '|' . strtolower($pieces[1]);
                break;
            case 'http-method':
            case 'hex':
                return strtoupper($value);
            case 'vulnerability':
            case 'weakness':
                $value = str_replace('–', '-', $value);
                return strtoupper($value);
            case 'cc-number':
            case 'bin':
                $value = preg_replace('/[^0-9]+/', '', $value);
                break;
            case 'iban':
            case 'bic':
                $value = strtoupper($value);
                $value = preg_replace('/[^0-9A-Z]+/', '', $value);
                break;
            case 'prtn':
            case 'whois-registrant-phone':
            case 'phone-number':
                if (substr($value, 0, 2) == '00') {
                    $value = '+' . substr($value, 2);
                }
                $value = preg_replace('/\(0\)/', '', $value);
                $value = preg_replace('/[^\+0-9]+/', '', $value);
                break;
            case 'x509-fingerprint-md5':
            case 'x509-fingerprint-sha256':
            case 'x509-fingerprint-sha1':
                $value = str_replace(':', '', $value);
                $value = strtolower($value);
                break;
            case 'ip-src':
            case 'ip-dst':
                if (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    // convert IPv6 address to compressed format
                    $value = inet_ntop(inet_pton($value));
                }
                break;
            case 'ip-dst|port':
            case 'ip-src|port':
                    if (substr_count($value, ':') >= 2) { // (ipv6|port) - tokenize ip and port
                        if (strpos($value, '|')) { // 2001:db8::1|80
                            $parts = explode('|', $value);
                        } elseif (strpos($value, '[') === 0 && strpos($value, ']') !== false) { // [2001:db8::1]:80
                            $ipv6 = substr($value, 1, strpos($value, ']')-1);
                            $port = explode(':', substr($value, strpos($value, ']')))[1];
                            $parts = array($ipv6, $port);
                        } elseif (strpos($value, '.')) { // 2001:db8::1.80
                            $parts = explode('.', $value);
                        } elseif (strpos($value, ' port ')) { // 2001:db8::1 port 80
                            $parts = explode(' port ', $value);
                        } elseif (strpos($value, 'p')) { // 2001:db8::1p80
                            $parts = explode('p', $value);
                        } elseif (strpos($value, '#')) { // 2001:db8::1#80
                            $parts = explode('#', $value);
                        } else { // 2001:db8::1:80 this one is ambiguous
                            $temp = explode(':', $value);
                            $parts = array(implode(':', array_slice($temp, 0, count($temp)-1)), end($temp));
                        }
                    } elseif (strpos($value, ':')) { // (ipv4:port)
                        $parts = explode(':', $value);
                    } elseif (strpos($value, '|')) { // (ipv4|port)
                        $parts = explode('|', $value);
                    } else {
                        return $value;
                    }
                    if (filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                        // convert IPv6 address to compressed format
                        $parts[0] = inet_ntop(inet_pton($parts[0]));
                    }
                    return $parts[0] . '|' . $parts[1];
            case 'mac-address':
            case 'mac-eui-64':
                $value = str_replace(array('.', ':', '-', ' '), '', strtolower($value));
                $value = wordwrap($value, 2, ':', true);
                break;
            case 'hostname|port':
                $value = strtolower($value);
                return str_replace(':', '|', $value);
            case 'boolean':
                if ('true' == trim(strtolower($value))) {
                    $value = 1;
                }
                if ('false' == trim(strtolower($value))) {
                    $value = 0;
                }
                $value = ($value) ? '1' : '0';
                break;
            case 'datetime':
                try {
                    $value = (new DateTime($value))->setTimezone(new DateTimeZone('GMT'))->format('Y-m-d\TH:i:s.uO'); // ISO8601 formating with microseconds
                } catch (Exception $e) {
                    // silently skip. Rejection will be done in runValidation()
                }
                break;
            case 'AS':
                if (strtoupper(substr($value, 0, 2)) === 'AS') {
                    $value = substr($value, 2); // remove 'AS'
                }
                if (strpos($value, '.') !== false) { // maybe value is in asdot notation
                    $parts = explode('.', $value);
                    if ($this->isPositiveInteger($parts[0]) && $this->isPositiveInteger($parts[1])) {
                        return $parts[0] * 65536 + $parts[1];
                    }
                }
                break;
        }
        return $value;
    }

    public function getCompositeTypes()
    {
        static $compositeTypes;

        if ($compositeTypes === null) {
            // build the list of composite Attribute.type dynamically by checking if type contains a |
            // default composite types
            $compositeTypes = array('malware-sample');  // TODO hardcoded composite
            // dynamically generated list
            foreach ($this->typeDefinitions as $type => $foo) {
                if (strpos($type, '|') !== false) {
                    $compositeTypes[] = $type;
                }
            }
        }
        return $compositeTypes;
    }

    public function getRelatedAttributes($user, $attribute, $fields=array(), $includeEventData = false)
    {
        // LATER getRelatedAttributes($attribute) this might become a performance bottleneck

        // exclude these specific categories from being linked
        switch ($attribute['category']) {
            case 'Antivirus detection':
                return null;
        }
        // exclude these specific types from being linked
        switch ($attribute['type']) {
            case 'other':
            case 'comment':
                return null;
        }

        // prepare the conditions
        $conditions = array(
                'Attribute.event_id !=' => $attribute['event_id'],
                'Attribute.deleted !=' => 1,
                );

        // prevent issues with empty fields
        if (empty($attribute['value1'])) {
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
        $baseConditions = $this->buildConditions($user);
        $baseConditions['AND'][] = $conditions;
        // do the search
        if (empty($fields)) {
            $fields = array('Attribute.*');
        }
        $params = array(
            'conditions' => $baseConditions,
            'fields' => $fields,
            'recursive' => 0,
            'group' => array('Attribute.id', 'Attribute.event_id', 'Attribute.object_id', 'Attribute.object_relation', 'Attribute.category', 'Attribute.type', 'Attribute.value', 'Attribute.uuid', 'Attribute.timestamp', 'Attribute.distribution', 'Attribute.sharing_group_id', 'Attribute.to_ids', 'Attribute.comment', 'Event.id', 'Event.uuid', 'Event.threat_level_id', 'Event.analysis', 'Event.info', 'Event.extends_uuid', 'Event.distribution', 'Event.sharing_group_id', 'Event.published', 'Event.date', 'Event.orgc_id', 'Event.org_id', 'Object.id', 'Object.uuid', 'Object.distribution', 'Object.name', 'Object.template_uuid', 'Object.distribution', 'Object.sharing_group_id'),
            'order' => 'Attribute.event_id DESC'
        );
        if (!empty($includeEventData)) {
            $params['contain'] = array(
                'Event' => array(
                    'fields' => array(
                        'Event.id', 'Event.uuid', 'Event.threat_level_id', 'Event.analysis', 'Event.info', 'Event.extends_uuid', 'Event.distribution', 'Event.sharing_group_id', 'Event.published', 'Event.date', 'Event.orgc_id', 'Event.org_id'
                    )
                ),
                'Object' => array(
                    'fields' => array(
                        'Object.id', 'Object.uuid', 'Object.distribution', 'Object.name', 'Object.template_uuid', 'Object.distribution', 'Object.sharing_group_id'
                    )
                )
            );
        }
        $similarEvents = $this->find(
            'all',
            $params
        );
        if (!empty($includeEventData)) {
            foreach ($similarEvents as $k => $similarEvent) {
                $similarEvents[$k] = array_merge(
                    $similarEvent['Attribute'],
                    array(
                        'Event' => $similarEvent['Event']
                    )
                );
            }
        }
        return $similarEvents;
    }

    public function typeIsMalware($type)
    {
        return in_array($type, $this->zippedDefinitions);
    }

    public function typeIsAttachment($type)
    {
        return in_array($type, $this->zippedDefinitions) || in_array($type, $this->uploadDefinitions);
    }

    public function getAttachment($attribute, $path_suffix='')
    {
        return $this->loadAttachmentTool()->getContent($attribute['event_id'], $attribute['id'], $path_suffix);
    }

    /**
     * @param array $attribute
     * @param string $path_suffix
     * @return File
     * @throws Exception
     */
    public function getAttachmentFile(array $attribute, $path_suffix='')
    {
        return $this->loadAttachmentTool()->getFile($attribute['event_id'], $attribute['id'], $path_suffix);
    }

    public function saveAttachment($attribute, $path_suffix='')
    {
        $result = $this->loadAttachmentTool()->save($attribute['event_id'], $attribute['id'], $attribute['data'], $path_suffix);
        if ($result) {
            $this->loadAttachmentScan()->backgroundScan(AttachmentScan::TYPE_ATTRIBUTE, $attribute);
        }
        return $result;
    }

    /**
     * Returns attribute attachment content as base64 encoded string. If file doesn't exists, empty string is returned.
     *
     * @param array $attribute
     * @return string
     */
    public function base64EncodeAttachment(array $attribute)
    {
        try {
            return base64_encode($this->getAttachment($attribute));
        } catch (NotFoundException $e) {
            $this->log($e->getMessage(), LOG_NOTICE);
            return '';
        }
    }

    public function saveBase64EncodedAttachment($attribute)
    {
        $attribute['data'] = base64_decode($attribute['data']);
        return $this->saveAttachment($attribute);
    }

    /**
     * Currently, as image are considered files with JPG (JPEG), PNG or GIF extension.
     * @param array $attribute
     * @return bool
     */
    public function isImage(array $attribute)
    {
        return $attribute['type'] === 'attachment' &&
            Validation::extension($attribute['value'], array('jpg', 'jpeg', 'png', 'gif'));
    }

    /**
     * @param array $attribute
     * @param bool $thumbnail
     * @param int $maxWidth - When $thumbnail is true
     * @param int $maxHeight - When $thumbnail is true
     * @return string
     * @throws Exception
     */
    public function getPictureData(array $attribute, $thumbnail=false, $maxWidth=200, $maxHeight=200)
    {
        if ($thumbnail && extension_loaded('gd')) {
            if ($maxWidth == 200 && $maxHeight == 200) {
                // Return thumbnail directly if already exists
                try {
                    return $this->getAttachment($attribute['Attribute'], $path_suffix = '_thumbnail');
                } catch (NotFoundException $e) {
                    // pass
                }
            }

            // Thumbnail doesn't exists, we need to generate it
            $imageData = $this->getAttachment($attribute['Attribute']);
            $imageData = $this->resizeImage($imageData, $maxWidth, $maxHeight);

            // Save just when requested default thumbnail size
            if ($maxWidth == 200 && $maxHeight == 200) {
                $attribute['Attribute']['data'] = $imageData;
                $this->saveAttachment($attribute['Attribute'], $path_suffix='_thumbnail');
            }
        } else {
            $imageData = $this->getAttachment($attribute['Attribute']);
        }

        return $imageData;
    }

    /**
     * @param string $data
     * @param int $maxWidth
     * @param int $maxHeight
     * @return string
     * @throws Exception
     */
    public function resizeImage($data, $maxWidth, $maxHeight)
    {
        $image = imagecreatefromstring($data);
        if ($image === false) {
            throw new Exception("Image is not valid.");
        }

        $currentWidth = imagesx($image);
        $currentHeight = imagesy($image);

        // Compute thumbnail size with keeping ratio
        if ($currentWidth > $currentHeight) {
            $newWidth = min($currentWidth, $maxWidth);
            $divisor = $currentWidth / $newWidth;
            $newHeight = floor($currentHeight / $divisor);
        } else {
            $newHeight = min($currentHeight, $maxHeight);
            $divisor = $currentHeight / $newHeight;
            $newWidth = floor($currentWidth / $divisor);
        }

        $imageThumbnail = imagecreatetruecolor($newWidth, $newHeight);

        // Allow transparent background
        imagealphablending($imageThumbnail, false);
        imagesavealpha($imageThumbnail, true);
        $transparent = imagecolorallocatealpha($imageThumbnail, 255, 255, 255, 127);
        imagefilledrectangle($imageThumbnail, 0, 0, $newWidth, $newHeight, $transparent);

        // Resize image
        imagecopyresampled($imageThumbnail, $image, 0, 0, 0, 0, $newWidth, $newHeight, $currentWidth, $currentHeight);
        imagedestroy($image);

        // Output image to string
        ob_start();
        imagepng($imageThumbnail, null, 9);
        $imageData = ob_get_contents();
        ob_end_clean();
        imagedestroy($imageThumbnail);

        return $imageData;
    }

    /**
     * @param array $user
     * @param array $resultArray
     */
    public function fetchRelated(array $user, array &$resultArray)
    {
        if (empty($resultArray)) {
            return;
        }

        $composeTypes = $this->getCompositeTypes();
        foreach ($resultArray as $key => $result) {
            if (in_array($result['default_type'], $composeTypes, true)) {
                $pieces = explode('|', $result['value']);
                if (in_array($result['default_type'], $this->primaryOnlyCorrelatingTypes, true)) {
                    $or = ['Attribute.value1' => $pieces[0], 'Attribute.value2' => $pieces[0]];
                } else {
                    $or = ['Attribute.value1' => $pieces, 'Attribute.value2' => $pieces];
                }
            } else {
                $or = ['Attribute.value1' => $result['value'], 'Attribute.value2' => $result['value']];
            }
            $options = array(
                'conditions' => [
                    'OR' => $or,
                    'NOT' => [
                        'Attribute.type' => $this->nonCorrelatingTypes,
                    ],
                    'Attribute.disable_correlation' => 0,
                ],
                'fields' => ['Attribute.type', 'Attribute.category', 'Attribute.value', 'Attribute.comment'],
                'order' => false,
                'limit' => 11,
                'flatten' => 1,
            );
            $resultArray[$key]['related'] = $this->fetchAttributes($user, $options);
        }
    }

    public function checkComposites()
    {
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

    public function ISODatetimeToUTC($data, $alias)
    {
        // convert into utc and micro sec
        if (!empty($data[$alias]['first_seen'])) {
            $d = new DateTime($data[$alias]['first_seen']);
            $d->setTimezone(new DateTimeZone('GMT'));
            $fs_sec = $d->format('U');
            $fs_micro = $d->format('u');
            $fs_micro = str_pad($fs_micro, 6, "0", STR_PAD_LEFT);
            $fs = $fs_sec . $fs_micro;
            $data[$alias]['first_seen'] = $fs;
        }
        if (!empty($data[$alias]['last_seen'])) {
            $d = new DateTime($data[$alias]['last_seen']);
            $d->setTimezone(new DateTimeZone('GMT'));
            $ls_sec = $d->format('U');
            $ls_micro = $d->format('u');
            $ls_micro = str_pad($ls_micro, 6, "0", STR_PAD_LEFT);
            $ls = $ls_sec . $ls_micro;
            $data[$alias]['last_seen'] = $ls;
        }
        return $data;
    }

    public function UTCToISODatetime($data, $alias)
    {
        if (!empty($data[$alias]['first_seen'])) {
            $fs = $data[$alias]['first_seen'];
            $fs_sec = intval($fs / 1000000); // $fs is in micro (10^6)
            $fs_micro = $fs % 1000000;
            $fs_micro = str_pad($fs_micro, 6, "0", STR_PAD_LEFT);
            $fs = $fs_sec . '.' . $fs_micro;
            $data[$alias]['first_seen'] = DateTime::createFromFormat('U.u', $fs)->format('Y-m-d\TH:i:s.uP');
        }
        if (!empty($data[$alias]['last_seen'])) {
            $ls = $data[$alias]['last_seen'];
            $ls_sec = intval($ls / 1000000); // $ls is in micro (10^6)
            $ls_micro = $ls % 1000000;
            $ls_micro = str_pad($ls_micro, 6, "0", STR_PAD_LEFT);
            $ls = $ls_sec . '.' . $ls_micro;
            $data[$alias]['last_seen'] = DateTime::createFromFormat('U.u', $ls)->format('Y-m-d\TH:i:s.uP');
        }
        return $data;
    }

    public function hids($user, $type, $tags = '', $from = false, $to = false, $last = false, $jobId = false, $enforceWarninglist = false)
    {
        if (empty($user)) {
            throw new MethodNotAllowedException(__('Could not read user.'));
        }
        // check if it's a valid type
        if ($type != 'md5' && $type != 'sha1' && $type != 'sha256') {
            throw new UnauthorizedException(__('Invalid hash type.'));
        }
        $conditions = array();
        $typeArray = array($type, 'filename|' . $type);
        if ($type == 'md5') {
            $typeArray[] = 'malware-sample';
        }
        $rules = array();
        $eventIds = $this->Event->fetchEventIds($user, [
            'from' => $from,
            'to' => $to,
            'last' => $last
        ]);
        if (!empty($tags)) {
            $tag = ClassRegistry::init('Tag');
            $args = $this->dissectArgs($tags);
            $tagArray = $tag->fetchEventTagIds($args[0], $args[1]);
            if (!empty($tagArray[0])) {
                foreach ($eventIds as $k => $v) {
                    if (!in_array($v['Event']['id'], $tagArray[0])) {
                        unset($eventIds[$k]);
                    }
                }
            }
            if (!empty($tagArray[1])) {
                foreach ($eventIds as $k => $v) {
                    if (in_array($v['Event']['id'], $tagArray[1])) {
                        unset($eventIds[$k]);
                    }
                }
            }
        }
        App::uses('HidsExport', 'Export');
        $continue = false;
        $eventCount = count($eventIds);
        if ($jobId) {
            $this->Job = ClassRegistry::init('Job');
            $this->Job->id = $jobId;
            if (!$this->Job->exists()) {
                $jobId = false;
            }
        }
        foreach ($eventIds as $k => $event) {
            $conditions['AND'] = array('Attribute.to_ids' => 1, 'Event.published' => 1, 'Attribute.type' => $typeArray, 'Attribute.event_id' => $event['Event']['id']);
            $options = array(
                    'conditions' => $conditions,
                    'group' => array('Attribute.type', 'Attribute.value1'),
                    'enforceWarninglist' => $enforceWarninglist,
                    'flatten' => true
            );
            $items = $this->fetchAttributes($user, $options);
            if (empty($items)) {
                continue;
            }
            $export = new HidsExport();
            $rules = array_merge($rules, $export->export($items, strtoupper($type), $continue));
            $continue = true;
            if ($jobId && ($k % 10 == 0)) {
                $this->Job->saveField('progress', $k * 80 / $eventCount);
            }
        }
        return $rules;
    }


    public function nids($user, $format, $id = false, $continue = false, $tags = false, $from = false, $to = false, $last = false, $type = false, $enforceWarninglist = false, $includeAllTags = false)
    {
        if (empty($user)) {
            throw new MethodNotAllowedException(__('Could not read user.'));
        }
        $eventIds = $this->Event->fetchEventIds($user, [
            'from' => $from,
            'to' => $to,
            'last' => $last
        ]);

        // If we sent any tags along, load the associated tag names for each attribute
        if ($tags) {
            $tag = ClassRegistry::init('Tag');
            $args = $this->dissectArgs($tags);
            $tagArray = $tag->fetchEventTagIds($args[0], $args[1]);
            if (!empty($tagArray[0])) {
                foreach ($eventIds as $k => $v) {
                    if (!in_array($v['Event']['id'], $tagArray[0])) {
                        unset($eventIds[$k]);
                    }
                }
            }
            if (!empty($tagArray[1])) {
                foreach ($eventIds as $k => $v) {
                    if (in_array($v['Event']['id'], $tagArray[1])) {
                        unset($eventIds[$k]);
                    }
                }
            }
        }

        if ($id) {
            foreach ($eventIds as $k => $v) {
                if ($v['Event']['id'] !== $id) {
                    unset($eventIds[$k]);
                }
            }
        }

        if ($format == 'suricata') {
            App::uses('NidsSuricataExport', 'Export');
        } else {
            App::uses('NidsSnortExport', 'Export');
        }

        $rules = array();
        foreach ($eventIds as $event) {
            $conditions['AND'] = array('Attribute.to_ids' => 1, "Event.published" => 1, 'Attribute.event_id' => $event['Event']['id']);
            $valid_types = array('ip-dst', 'ip-src', 'ip-dst|port', 'ip-src|port', 'eppn', 'email', 'email-src', 'email-dst', 'email-subject', 'email-attachment', 'domain', 'domain|ip', 'hostname', 'url', 'user-agent', 'snort');
            $conditions['AND']['Attribute.type'] = $valid_types;
            if (!empty($type)) {
                $conditions['AND'][] = array('Attribute.type' => $type);
            }

            $params = array(
                    'conditions' => $conditions, // array of conditions
                    'recursive' => -1, // int
                    'fields' => array('Attribute.id', 'Attribute.event_id', 'Attribute.type', 'Attribute.value'),
                    'contain' => array('Event'=> array('fields' => array('Event.id', 'Event.threat_level_id'))),
                    'group' => array('Attribute.type', 'Attribute.value1'), // fields to GROUP BY
                    'enforceWarninglist' => $enforceWarninglist,
                    'includeAllTags' => $includeAllTags,
                    'flatten' => true
            );
            $items = $this->fetchAttributes($user, $params);
            if (empty($items)) {
                continue;
            }
            // export depending on the requested type
            switch ($format) {
                case 'suricata':
                    $export = new NidsSuricataExport();
                    break;
                case 'snort':
                    $export = new NidsSnortExport();
                    break;
            }
            $rules = array_merge($rules, $export->export($items, $user['nids_sid'], $format, $continue));
            // Only prepend the comments once
            $continue = true;
        }
        return $rules;
    }

    public function set_filter_tags(&$params, $conditions, $options)
    {
        if (empty($params['tags'])) {
            return $conditions;
        }
        $tag = ClassRegistry::init('Tag');
        $params['tags'] = $this->dissectArgs($params['tags']);
        foreach (array(0, 1, 2) as $tag_operator) {
            $tagArray[$tag_operator] = $tag->fetchTagIdsSimple($params['tags'][$tag_operator]);
        }
        $temp = array();
        if (!empty($tagArray[0])) {
            if ($tagArray[0][0] === -1) {
                $conditions[] = array('Event.id' => -1);
            } else {
                $subquery_options = array(
                    'conditions' => array(
                        'tag_id' => $tagArray[0]
                    ),
                    'fields' => array(
                        'event_id'
                    )
                );
                $lookup_field = ($options['scope'] === 'Event') ? 'Event.id' : 'Attribute.event_id';
                $temp = array_merge(
                    $temp,
                    $this->subQueryGenerator($tag->EventTag, $subquery_options, $lookup_field)
                );
                $subquery_options = array(
                    'conditions' => array(
                        'tag_id' => $tagArray[0]
                    ),
                    'fields' => array(
                        $options['scope'] === 'Event' ? 'Event.id' : 'attribute_id'
                    )
                );
                $lookup_field = $options['scope'] === 'Event' ? 'Event.id' : 'Attribute.id';
                $temp = array_merge(
                    $temp,
                    $this->subQueryGenerator($tag->AttributeTag, $subquery_options, $lookup_field)
                );
            }
        }
        if (!empty($temp)) {
            $conditions['AND'][] = array('OR' => $temp);
        }
        $temp = array();
        if (!empty($tagArray[1])) {
            if ($options['scope'] == 'all' || $options['scope'] == 'Event') {
                $subquery_options = array(
                    'conditions' => array(
                        'tag_id' => $tagArray[1]
                    ),
                    'fields' => array(
                        'event_id'
                    )
                );
                $lookup_field = ($options['scope'] === 'Event') ? 'Event.id' : 'Attribute.event_id';
                $conditions['AND'][] = array_merge($temp, $this->subQueryGenerator($tag->EventTag, $subquery_options, $lookup_field, 1));
            }
            if ($options['scope'] == 'all' || $options['scope'] == 'Attribute') {
                $subquery_options = array(
                    'conditions' => array(
                        'tag_id' => $tagArray[1]
                    ),
                    'fields' => array(
                        $options['scope'] === 'Event' ? 'event.id' : 'attribute_id'
                    )
                );
                $lookup_field = $options['scope'] === 'Event' ? 'Event.id' : 'Attribute.id';
                $conditions['AND'][] = array_merge($temp, $this->subQueryGenerator($tag->AttributeTag, $subquery_options, $lookup_field, 1));
            }
        }
        $temp = array();
        if (!empty($tagArray[2])) {
            if ($tagArray[2][0] === -1) {
                $conditions[] = array('Event.id' => -1);
            } else {
                foreach ($tagArray[2] as $k => $anded_tag) {
                    $subquery_options = array(
                        'conditions' => array(
                            'tag_id' => $anded_tag
                        ),
                        'fields' => array(
                            'event_id'
                        )
                    );
                    $lookup_field = ($options['scope'] === 'Event') ? 'Event.id' : 'Attribute.event_id';
                    $temp[$k]['OR'] = array();
                    $temp[$k]['OR'] = array_merge(
                        $temp[$k]['OR'],
                        $this->subQueryGenerator($tag->EventTag, $subquery_options, $lookup_field)
                    );
                    $subquery_options = array(
                        'conditions' => array(
                            'tag_id' => $anded_tag
                        ),
                        'fields' => array(
                            $options['scope'] === 'Event' ? 'Event.id' : 'attribute_id'
                        )
                    );
                    $lookup_field = $options['scope'] === 'Event' ? 'Event.id' : 'Attribute.id';
                    $temp[$k]['OR'] = array_merge(
                        $temp[$k]['OR'],
                        $this->subQueryGenerator($tag->AttributeTag, $subquery_options, $lookup_field)
                    );
                }
            }
        }
        if (!empty($temp)) {
            $conditions['AND'][] = array('AND' => $temp);
        }
        $params['tags'] = array();
        if (!empty($tagArray[0]) && empty($options['pop'])) {
            $params['tags']['OR'] = $tagArray[0];
        }
        if (!empty($tagArray[1])) {
            $params['tags']['NOT'] = $tagArray[1];
        }
        if (!empty($tagArray[2]) && empty($options['pop'])) {
            $params['tags']['AND'] = $tagArray[2];
        }
        if (empty($params['tags'])) {
            unset($params['tags']);
        }
        return $conditions;
    }

    public function text($user, $type, $tags = false, $eventId = false, $allowNonIDS = false, $from = false, $to = false, $last = false, $enforceWarninglist = false, $allowNotPublished = false)
    {
        //permissions are taken care of in fetchAttributes()
        $conditions['AND'] = array();
        if ($allowNonIDS === false) {
            $conditions['AND']['Attribute.to_ids'] = 1;
            if ($allowNotPublished === false) {
                $conditions['AND']['Event.published'] = 1;
            }
        }
        if (!is_array($type) && $type !== 'all') {
            $conditions['AND']['Attribute.type'] = $type;
        }
        if ($from) {
            $conditions['AND']['Event.date >='] = $from;
        }
        if ($to) {
            $conditions['AND']['Event.date <='] = $to;
        }
        if ($last) {
            $conditions['AND']['Event.publish_timestamp >='] = $last;
        }

        if ($eventId !== false) {
            $conditions['AND'][] = array('Event.id' => $eventId);
        } elseif ($tags !== false) {
            $passed_param = array('tags' => $tags);
            $conditions = $this->set_filter_tags($passed_param, $conditions, array('scope' => 'Attribute'));
        }
        $attributes = $this->fetchAttributes($user, array(
                'conditions' => $conditions,
                'order' => 'Attribute.value1 ASC',
                'fields' => array('value'),
                'contain' => array('Event' => array(
                    'fields' => array('Event.id', 'Event.published', 'Event.date', 'Event.publish_timestamp'),
                )),
                'enforceWarninglist' => $enforceWarninglist,
                'flatten' => 1
        ));
        return $attributes;
    }

    public function rpz($user, $tags = false, $eventId = false, $from = false, $to = false, $enforceWarninglist = false)
    {
        // we can group hostname and domain as well as ip-src and ip-dst in this case
        $conditions['AND'] = array('Attribute.to_ids' => 1, 'Event.published' => 1);
        $typesToFetch = array('ip' => array('ip-src', 'ip-dst'), 'domain' => array('domain'), 'hostname' => array('hostname'));
        if ($from) {
            $conditions['AND']['Event.date >='] = $from;
        }
        if ($to) {
            $conditions['AND']['Event.date <='] = $to;
        }
        if ($eventId !== false) {
            $conditions['AND'][] = array('Event.id' => $eventId);
        }
        if ($tags !== false) {
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
            $tempConditions = $conditions;
            $tempConditions['type'] = $v;
            $temp = $this->fetchAttributes(
                    $user,
                    array(
                        'conditions' => $tempConditions,
                        'fields' => array('Attribute.value'), // array of field names
                        'enforceWarninglist' => $enforceWarninglist,
                        'flatten' => 1
                    )
            );
            if (empty($temp)) {
                continue;
            }
            if ($k == 'hostname') {
                foreach ($temp as $value) {
                    $found = false;
                    if (isset($values['domain'])) {
                        foreach ($values['domain'] as $domain) {
                            if (strpos($value['Attribute']['value'], $domain) != 0) {
                                $found = true;
                            }
                        }
                    }
                    if (!$found) {
                        $values[$k][] = $value['Attribute']['value'];
                    }
                }
            } else {
                foreach ($temp as $value) {
                    $values[$k][] = $value['Attribute']['value'];
                }
            }
            unset($temp);
        }
        return $values;
    }

    public function bro($user, $type, $tags = false, $eventId = false, $from = false, $to = false, $last = false, $enforceWarninglist = false, $skipHeader = false)
    {
        App::uses('BroExport', 'Export');
        $export = new BroExport();
        if ($type == 'all') {
            $types = array_keys($export->mispTypes);
        } else {
            $types = array($type);
        }
        $intel = array();
        foreach ($types as $type) {
            //restricting to non-private or same org if the user is not a site-admin.
            $conditions['AND'] = array('Attribute.to_ids' => 1, 'Event.published' => 1);
            if ($from) {
                $conditions['AND']['Event.date >='] = $from;
            }
            if ($to) {
                $conditions['AND']['Event.date <='] = $to;
            }
            if ($last) {
                $conditions['AND']['Event.publish_timestamp >='] = $last;
            }
            if ($eventId !== false) {
                $temp = array();
                $args = $this->dissectArgs($eventId);
                foreach ($args[0] as $accepted) {
                    $temp['OR'][] = array('Event.id' => $accepted);
                }
                $conditions['AND'][] = $temp;
                $temp = array();
                foreach ($args[1] as $rejected) {
                    $temp['AND'][] = array('Event.id !=' => $rejected);
                }
                $conditions['AND'][] = $temp;
            }
            if ($tags !== false) {
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
            $this->Allowedlist = ClassRegistry::init('Allowedlist');
            $this->allowedlist = $this->Allowedlist->getBlockedValues();
            $instanceString = 'MISP';
            if (Configure::read('MISP.host_org_id') && Configure::read('MISP.host_org_id') > 0) {
                $this->Event->Orgc->id = Configure::read('MISP.host_org_id');
                if ($this->Event->Orgc->exists()) {
                    $instanceString = $this->Event->Orgc->field('name') . ' MISP';
                }
            }
            $mispTypes = $export->getMispTypes($type);
            foreach ($mispTypes as $mispType) {
                $conditions['AND']['Attribute.type'] = $mispType[0];
                $intel = array_merge($intel, $this->__bro($user, $conditions, $mispType[1], $export, $this->allowedlist, $instanceString, $enforceWarninglist));
            }
        }
        natsort($intel);
        $intel = array_unique($intel);
        if (empty($skipHeader)) {
            array_unshift($intel, $export->header);
        }
        return $intel;
    }

    private function __bro($user, $conditions, $valueField, $export, $allowedlist, $instanceString, $enforceWarninglist)
    {
        $attributes = $this->fetchAttributes(
            $user,
            array(
                'conditions' => $conditions, // array of conditions
                'order' => 'Attribute.value' . $valueField . ' ASC',
                'recursive' => -1, // int
                'fields' => array('Attribute.id', 'Attribute.event_id', 'Attribute.type', 'Attribute.category', 'Attribute.comment', 'Attribute.to_ids', 'Attribute.value', 'Attribute.value' . $valueField),
                'contain' => array('Event' => array('fields' => array('Event.id', 'Event.threat_level_id', 'Event.orgc_id', 'Event.uuid'))),
                'enforceWarninglist' => $enforceWarninglist,
                'flatten' => 1
            )
        );
        $orgs = $this->Event->Orgc->find('list', array(
                'fields' => array('Orgc.id', 'Orgc.name')
        ));
        return $export->export($attributes, $orgs, $valueField, $allowedlist, $instanceString);
    }

    public function generateCorrelation($jobId = false, $startPercentage = 0, $eventId = false, $attributeId = false)
    {
        $this->Correlation = ClassRegistry::init('Correlation');
        $this->purgeCorrelations($eventId);

        $this->FuzzyCorrelateSsdeep = ClassRegistry::init('FuzzyCorrelateSsdeep');
        $this->FuzzyCorrelateSsdeep->purge($eventId, $attributeId);

        // get all attributes..
        if (!$eventId) {
            $eventIds = $this->Event->find('column', [
                'fields' => ['Event.id'],
                'conditions' => ['Event.disable_correlation' => 0],
            ]);
            $full = true;
        } else {
            $eventIds = array($eventId);
            $full = false;
        }
        $attributeCount = 0;
        if (Configure::read('MISP.background_jobs') && $jobId) {
            $this->Job = ClassRegistry::init('Job');
            $eventCount = count($eventIds);
        } else {
            $jobId = false;
        }
        foreach ($eventIds as $j => $id) {
            if ($jobId) {
                if ($attributeId) {
                    $message = 'Correlating Attribute ' . $attributeId;
                } else {
                    $message = 'Correlating Event ' . $id;
                }
                $this->Job->saveProgress($jobId, $message, $startPercentage + ($j / $eventCount * (100 - $startPercentage)));
            }
            $event = $this->Event->find('first', array(
                'recursive' => -1,
                'fields' => array('Event.distribution', 'Event.id', 'Event.info', 'Event.org_id', 'Event.date', 'Event.sharing_group_id', 'Event.disable_correlation'),
                'conditions' => array('id' => $id),
                'order' => false,
            ));
            $attributeConditions = array(
                'Attribute.event_id' => $id,
                'Attribute.deleted' => 0,
                'Attribute.disable_correlation' => 0,
                'NOT' => array(
                    'Attribute.type' => $this->nonCorrelatingTypes,
                ),
            );
            if ($attributeId) {
                $attributeConditions['Attribute.id'] = $attributeId;
            }
            $attributes = $this->find('all', [
                'recursive' => -1,
                'conditions' => $attributeConditions,
                // fetch just necessary fields to save memory
                'fields' => [
                    'Attribute.id',
                    'Attribute.event_id',
                    'Attribute.type',
                    'Attribute.value1',
                    'Attribute.value2',
                    'Attribute.distribution',
                    'Attribute.sharing_group_id',
                    'Attribute.disable_correlation',
                ],
                'order' => [],
            ]);
            foreach ($attributes as $attribute) {
                $this->Correlation->afterSaveCorrelation($attribute['Attribute'], $full, $event);
                $attributeCount++;
            }
        }
        if ($jobId) {
            $this->Job->saveStatus($jobId, true);
        }
        return $attributeCount;
    }

    public function purgeCorrelations($eventId = false, $attributeId = false)
    {
        if (!$eventId) {
            $this->query('TRUNCATE TABLE correlations;');
        } elseif (!$attributeId) {
            $this->Correlation = ClassRegistry::init('Correlation');
            $this->Correlation->deleteAll(
                array('OR' => array(
                'Correlation.1_event_id' => $eventId,
                'Correlation.event_id' => $eventId))
            );
        } else {
            $this->Correlation->deleteAll(
                array('OR' => array(
                'Correlation.1_attribute_id' => $attributeId,
                'Correlation.attribute_id' => $attributeId))
            );
        }
    }

    public function reportValidationIssuesAttributes($eventId)
    {
        $conditions = array();
        if ($eventId && is_numeric($eventId)) {
            $conditions = array('event_id' => $eventId);
        }

        // get all attributes..
        $attributes = $this->find('all', array('recursive' => -1, 'fields' => array('id'), 'conditions' => $conditions));
        // for all attributes..
        $result = array();
        $i = 0;
        foreach ($attributes as $a) {
            $attribute = $this->find('first', array('recursive' => -1, 'conditions' => array('id' => $a['Attribute']['id'])));
            $this->set($attribute);
            if (!$this->validates()) {
                $errors = $this->validationErrors;
                $result[$i]['id'] = $attribute['Attribute']['id'];
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
    public function dissectArgs($args)
    {
        if (empty($args)) {
            return array(0 => array(), 1 => array(), 2 => array());
        }
        if (!is_array($args)) {
            $args = explode('&&', $args);
        }
        $result = array(0 => array(), 1 => array(), 2 => array());
        if (isset($args['OR']) || isset($args['NOT']) || isset($args['AND'])) {
            if (!empty($args['OR'])) {
                $result[0] = $args['OR'];
            }
            if (!empty($args['NOT'])) {
                $result[1] = $args['NOT'];
            }
            if (!empty($args['AND'])) {
                $result[2] = $args['AND'];
            }
        } else {
            foreach ($args as $arg) {
                if (substr($arg, 0, 1) == '!') {
                    $result[1][] = substr($arg, 1);
                } else {
                    $result[0][] = $arg;
                }
            }
        }
        return $result;
    }

    public function checkForValidationIssues($attribute)
    {
        $this->set($attribute);
        if ($this->validates()) {
            return false;
        } else {
            return $this->validationErrors;
        }
    }


    public function checkTemplateAttributes($template, $data, $event_id)
    {
        $result = array();
        $errors = array();
        $attributes = array();
        if (isset($data['Template']['fileArray'])) {
            $fileArray = json_decode($data['Template']['fileArray'], true);
        }
        foreach ($template['TemplateElement'] as $element) {
            if ($element['element_definition'] == 'attribute') {
                $result = $this->__resolveElementAttribute($element['TemplateElementAttribute'][0], $data['Template']['value_' . $element['id']]);
            } elseif ($element['element_definition'] == 'file') {
                $temp = array();
                if (isset($fileArray)) {
                    foreach ($fileArray as $fileArrayElement) {
                        if ($fileArrayElement['element_id'] == $element['id']) {
                            $temp[] = $fileArrayElement;
                        }
                    }
                }
                $result = $this->__resolveElementFile($element['TemplateElementFile'][0], $temp);
                if ($element['TemplateElementFile'][0]['mandatory'] && empty($temp) && empty($errors[$element['id']])) {
                    $errors[$element['id']] = 'This field is mandatory.';
                }
            }
            if ($element['element_definition'] == 'file' || $element['element_definition'] == 'attribute') {
                if ($result['errors']) {
                    $errors[$element['id']] = $result['errors'];
                } else {
                    foreach ($result['attributes'] as &$a) {
                        $a['event_id'] = $event_id;
                        $a['distribution'] = 5;
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


    private function __resolveElementAttribute($element, $value)
    {
        $attributes = array();
        $results = array();
        $errors = null;
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
            if ($element['mandatory']) {
                $errors = __('This field is mandatory.');
            }
        }
        return array('attributes' => $results, 'errors' => $errors);
    }

    private function __resolveElementFile($element, $files)
    {
        $attributes = array();
        $errors = null;
        $element['complex'] = 0;
        if ($element['malware']) {
            $element['type'] = 'malware-sample';
            $element['to_ids'] = 1;
        } else {
            $element['type'] = 'attachment';
            $element['to_ids'] = 0;
        }
        foreach ($files as $file) {
            if (!$this->checkFilename($file['filename'])) {
                $errors = 'Filename not allowed.';
                continue;
            }
            if ($element['malware']) {
                $malwareName = $file['filename'] . '|' . hash_file('md5', APP . 'tmp/files/' . $file['tmp_name']);
                $tmp_file = new File(APP . 'tmp/files/' . $file['tmp_name']);
                if (!$tmp_file->readable()) {
                    $errors = 'File cannot be read.';
                } else {
                    $element['type'] = 'malware-sample';
                    $attributes[] = $this->__createAttribute($element, $malwareName);
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
                if (!$tmp_file->readable()) {
                    $errors = 'File cannot be read.';
                } else {
                    $attributes[count($attributes) - 1]['data'] = $file['tmp_name'];
                }
            }
        }
        return array('attributes' => $attributes, 'errors' => $errors, 'files' => $files);
    }

    private function __createAttribute($element, $value)
    {
        $attribute = array(
                'comment' => $element['name'],
                'to_ids' => $element['to_ids'],
                'category' => $element['category'],
                'value' => $value,
        );
        if ($element['complex']) {
            $complexTypeTool = new ComplexTypeTool();
            $result = $complexTypeTool->checkComplexRouter($value, ucfirst($element['type']));
            if (isset($result['multi'])) {
                $temp = $attribute;
                $attribute = array();
                foreach ($result['multi'] as $k => $r) {
                    $attribute['multi'][] = $temp;
                    $attribute['multi'][$k]['type'] = $r['type'];
                    $attribute['multi'][$k]['value'] = $r['value'];
                }
            } elseif ($result != false) {
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

    public function buildConditions($user)
    {
        $conditions = array();
        if (!$user['Role']['perm_site_admin']) {
            $sgids = $this->Event->cacheSgids($user, true);
            $eventConditions = $this->Event->createEventConditions($user);
            $conditions = array(
                'AND' => array(
                    $eventConditions['AND'],
                    array(
                        'OR' => array(
                            'Event.org_id' => $user['org_id'],
                            'Attribute.distribution' => array('1', '2', '3', '5'),
                            'AND '=> array(
                                'Attribute.distribution' => 4,
                                'Attribute.sharing_group_id' => $sgids,
                            )
                        )
                    ),
                    array(
                        'OR' => array(
                            'Attribute.object_id' => 0,
                            'Event.org_id' => $user['org_id'],
                            'Object.distribution' => array('1', '2', '3', '5'),
                            'AND' => array(
                                'Object.distribution' => 4,
                                'Object.sharing_group_id' => $sgids,
                            )
                        )
                    )
                )
            );
        }
        return $conditions;
    }

    /*
     * Unlike the other fetchers, this one foregoes any ACL checks.
     * the objective is simple: Fetch the given attribute with all related objects needed for the ZMQ output,
     * standardising on this function for fetching the attribute to be passed to Attribute->save()
     */
    public function fetchAttribute($id)
    {
        $attribute = $this->find('first', array(
            'recursive' => -1,
            'conditions' => array('Attribute.id' => $id),
            'contain' => array(
                'Event' => array(
                    'Orgc' => array(
                        'fields' => array('Orgc.id', 'Orgc.uuid', 'Orgc.name')
                    ),
                    'fields' => array('Event.id', 'Event.date', 'Event.info', 'Event.uuid', 'Event.published', 'Event.analysis', 'Event.threat_level_id', 'Event.org_id', 'Event.orgc_id', 'Event.distribution', 'Event.sharing_group_id')
                ),
                'AttributeTag' => array(
                    'Tag' => array('fields' => array('Tag.id', 'Tag.name', 'Tag.colour', 'Tag.exportable'))
                ),
                'Object'
            )
        ));
        if (!empty($attribute)) {
            if (!empty($attribute['AttributeTag'])) {
                foreach ($attribute['AttributeTag'] as $at) {
                    $attribute['Attribute']['Tag'][] = $at['Tag'];
                }
            }
            unset($attribute['AttributeTag']);
        }
        return $attribute;
    }

    /**
     * Fetches attributes that $user can see.
     *
     * @param array $user
     * @param array $options
     * @return array
     */
    public function fetchAttributesSimple(array $user, array $options = array())
    {
        $params = array(
            'conditions' => $this->buildConditions($user),
            'fields' => array(),
            'recursive' => -1,
            'contain' => ['Event', 'Object'], // by default include Event and Object, because it is required for conditions
        );
        if (isset($options['conditions'])) {
            $params['conditions']['AND'][] = $options['conditions'];
        }
        if (isset($options['fields'])) {
            $params['fields'] = $options['fields'];
        }
        if (isset($options['contain'])) {
            $params['contain'] = $options['contain'];
        }
        return $this->find('all', array(
            'conditions' => $params['conditions'],
            'recursive' => -1,
            'fields' => $params['fields'],
            'contain' => $params['contain'],
            'order' => false,
        ));
    }

    // Method that fetches all attributes for the various exports
    // very flexible, it's basically a replacement for find, with the addition that it restricts access based on user
    // options:
    //     fields
    //     contain
    //     conditions
    //     order
    //     group
    public function fetchAttributes($user, $options = array(), &$continue = true)
    {
        $params = array(
            'conditions' => $this->buildConditions($user),
            'recursive' => -1,
            'contain' => array(
                'Event' => array(
                    'fields' => array('id', 'info', 'org_id', 'orgc_id', 'uuid'),
                ),
                'AttributeTag', // tags are fetched separately, @see Attribute::__attachTagsToAttributes
                'Object' => array(
                    'fields' => array('id', 'distribution', 'sharing_group_id')
                )
            )
        );

        if (!empty($options['includeProposals'])) {
            $this->bindModel(
                array('hasMany' => array(
                        'ShadowAttribute' => array(
                            'className' => 'ShadowAttribute',
                            'foreignKey' => 'old_id',
                            'conditions' => array('ShadowAttribute.deleted' => 0)
                        )
                    )
                )
            );
            $params['contain']['ShadowAttribute'] = array('fields' => array(
                "id",
                "old_id",
                "event_id",
                "type",
                "category",
                "value1",
                "to_ids",
                "uuid",
                "value2",
                "org_id",
                "event_org_id",
                "comment",
                "event_uuid",
                "deleted",
                "timestamp",
                "proposal_to_delete",
                "disable_correlation",
                "value"
            ));
        }
        if (!empty($options['includeContext'])) {
            // include just event id for conditions, rest event data will be fetched later
            $params['contain']['Event']['fields'] = ['id'];
        }
        if (isset($options['contain'])) {
            // We may use a string instead of an array to ask for everything
            // instead of some specific attributes. If so, remove the array from
            // params, as we will later add the string.
            foreach($options['contain'] as $contain) {
                if (gettype($contain) == "string" && isset($params['contain'][$contain])) {
                    unset($params['contain'][$contain]);
                }
            }
            $params['contain'] = array_merge_recursive($params['contain'], $options['contain']);
        }
        if (isset($options['page'])) {
            $params['page'] = $options['page'];
        }
        if (isset($options['limit'])) {
            $params['limit'] = $options['limit'];
        }
        if (
            !empty($options['allow_proposal_blocking']) &&
            Configure::read('MISP.proposals_block_attributes')
        ) {
            $this->bindModel(array('hasMany' => array('ShadowAttribute' => array('foreignKey' => 'old_id'))));
            $proposalRestriction =  array(
                    'ShadowAttribute' => array(
                            'conditions' => array(
                                    'AND' => array(
                                            'ShadowAttribute.deleted' => 0,
                                            'OR' => array(
                                                    'ShadowAttribute.proposal_to_delete' => 1,
                                                    'ShadowAttribute.to_ids' => 0
                                            )
                                    )
                            ),
                            'fields' => array('ShadowAttribute.id', 'ShadowAttribute.value', 'ShadowAttribute.type', 'ShadowAttribute.category', 'ShadowAttribute.to_ids')
                    )
            );
            $params['contain'] = array_merge($params['contain'], $proposalRestriction);
        }
        if (isset($options['fields'])) {
            $params['fields'] = $options['fields'];
        }
        if (isset($options['conditions'])) {
            $params['conditions']['AND'][] = $options['conditions'];
        }
        if (empty($options['flatten'])) {
            $params['conditions']['AND'][] = array('Attribute.object_id' => 0);
        }
        if (isset($options['order'])) {
            $params['order'] = $options['order'];
        }
        if (!isset($options['withAttachments'])) {
            $options['withAttachments'] = false;
        } else ($params['order'] = array());
        if (!isset($options['enforceWarninglist'])) {
            $options['enforceWarninglist'] = false;
        }
        if (!isset($options['includeWarninglistHits'])) {
            $options['includeWarninglistHits'] = false;
        }
        if (!isset($options['includeDecayScore'])) {
            $options['includeDecayScore'] = false;
        }
        if (!isset($options['decayingModel'])) {
            $options['decayingModel'] = false;
        }
        if (!isset($options['modelOverrides'])) {
            $options['modelOverrides'] = array();
        }
        if (isset($options['score'])) {
            $options['modelOverrides']['threshold'] = $options['score'];
        }
        if (!isset($options['excludeDecayed'])) {
            $options['excludeDecayed'] = 0;
        } else {
            $options['includeDecayScore'] = true;
        }
        //Add EventTags to attributes to take them into account when calculating decay score
        if ($options['includeDecayScore']) {
            $options['includeEventTags'] = true;
        }
        if (!$user['Role']['perm_sync'] || !isset($options['deleted']) || !$options['deleted']) {
            $params['conditions']['AND']['Attribute.deleted'] = 0;
        } else {
            if ($options['deleted'] === "only") {
                $options['deleted'] = 1;
            }
            $params['conditions']['AND']['(Attribute.deleted + 0)'] = $options['deleted'];
        }
        if (isset($options['group'])) {
            $params['group'] = !empty($options['group']) ? $options['group'] : false;
        }
        // Site admin can access even unpublished event attributes if `unpublishedprivate` option is enabled
        if (!$user['Role']['perm_site_admin'] && Configure::read('MISP.unpublishedprivate')) {
            $params['conditions']['AND'][] = array('OR' => array('Event.published' => 1, 'Event.orgc_id' => $user['org_id'], 'Event.org_id' => $user['org_id']));
        }
        if (!empty($options['list'])) {
            if (!empty($options['event_ids'])) {
                return $this->find('column', [
                    'conditions' => $params['conditions'],
                    'contain' => array('Event', 'Object'),
                    'fields' => ['Attribute.event_id'],
                    'unique' => true,
                    'order' => false,
                ]);
            } else {
                return $this->find('list', array(
                    'conditions' => $params['conditions'],
                    'recursive' => -1,
                    'contain' => array('Event', 'Object'),
                    'fields' => array('Attribute.event_id'),
                    'order' => false
                ));
            }
        }

        if (($options['enforceWarninglist'] || $options['includeWarninglistHits']) && !isset($this->Warninglist)) {
            $this->Warninglist = ClassRegistry::init('Warninglist');
        }
        if (empty($params['limit'])) {
            $loopLimit = 50000;
            $loop = true;
            $params['limit'] = $loopLimit;
            $params['page'] = 0;
        } else {
            $loop = false;
        }
        $attributes = array();
        if (!empty($options['includeEventTags'])) {
            $eventTags = array();
        }
        while ($continue) {
            if ($loop) {
                $params['page'] = $params['page'] + 1;
                if (isset($results) && count($results) < $loopLimit) {
                    $continue = false;
                    continue;
                }
            }
            $results = $this->find('all', $params);

            if (!empty($options['includeContext']) && !empty($results)) {
                $eventIds = [];
                foreach ($results as $result) {
                    $eventIds[$result['Attribute']['event_id']] = true; // deduplicate
                }
                $eventsById = $this->__fetchEventsForAttributeContext($user, array_keys($eventIds), !empty($options['includeAllTags']));
                foreach ($results as &$result) {
                    $result['Event'] = $eventsById[$result['Attribute']['event_id']];
                }
                unset($eventsById, $result); // unset result is important, because it is reference
            }

            $this->__attachTagsToAttributes($results, $options);

            foreach ($results as $k => $result) {
                if (!empty($options['includeSightings'])) {
                    $temp = $result['Attribute'];
                    $temp['Event'] = $result['Event'];
                    $results[$k]['Attribute']['Sighting'] = $this->Sighting->attachToEvent($temp, $user, $temp['id']);
                }
                if (!empty($options['includeCorrelations'])) {
                    $attributeFields = array('id', 'event_id', 'object_id', 'object_relation', 'category', 'type', 'value', 'uuid', 'timestamp', 'distribution', 'sharing_group_id', 'to_ids', 'comment');
                    $results[$k]['Attribute']['RelatedAttribute'] = ($this->getRelatedAttributes($user, $results[$k]['Attribute'], $attributeFields, true));
                }
            }
            if (!$loop) {
                if (!empty($params['limit']) && count($results) < $params['limit']) {
                    $continue = false;
                }
                $break = true;
            }
            // return false if we're paginating
            if (isset($options['limit']) && empty($results)) {
                return array();
            }
            $results = array_values($results);
            $proposals_block_attributes = Configure::read('MISP.proposals_block_attributes');
            foreach ($results as $key => $attribute) {
                if ($options['enforceWarninglist'] && !$this->Warninglist->filterWarninglistAttribute($attribute['Attribute'])) {
                    unset($results[$key]); // Remove attribute that match any enabled warninglists
                    continue;
                }
                if (!empty($options['includeEventTags'])) {
                    $results = $this->__attachEventTagsToAttributes($eventTags, $results, $key, $options);
                }
                if ($options['includeWarninglistHits']) {
                    $results[$key]['Attribute'] = $this->Warninglist->checkForWarning($results[$key]['Attribute']);
                }
                if (!empty($options['includeAttributeUuid']) || !empty($options['includeEventUuid'])) {
                    $results[$key]['Attribute']['event_uuid'] = $results[$key]['Event']['uuid'];
                }
                if ($proposals_block_attributes) {
                    $this->__blockAttributeViaProposal($results, $key);
                }
                if ($options['withAttachments']) {
                    if ($this->typeIsAttachment($attribute['Attribute']['type'])) {
                        $encodedFile = $this->base64EncodeAttachment($attribute['Attribute']);
                        $results[$key]['Attribute']['data'] = $encodedFile;
                    }
                }
                if ($options['includeDecayScore']) {
                    $this->DecayingModel = ClassRegistry::init('DecayingModel');
                    $include_full_model = isset($options['includeFullModel']) && $options['includeFullModel'] ? 1 : 0;
                    if (empty($results[$key]['Attribute']['AttributeTag'])) {
                        $results[$key]['Attribute']['AttributeTag'] = isset($results[$key]['AttributeTag']) ? $results[$key]['AttributeTag'] : array();
                        $results[$key]['Attribute']['EventTag'] = isset($results[$key]['EventTag']) ? $results[$key]['EventTag'] : array();
                    }
                    $results[$key]['Attribute'] = $this->DecayingModel->attachScoresToAttribute($user, $results[$key]['Attribute'], $options['decayingModel'], $options['modelOverrides'], $include_full_model);
                    unset($results[$key]['Attribute']['AttributeTag']);
                    unset($results[$key]['Attribute']['EventTag']);
                    if ($options['excludeDecayed'] && !empty($results[$key]['Attribute']['decay_score'])) { // filter out decayed attribute
                        $decayed_flag = true;
                        foreach ($results[$key]['Attribute']['decay_score'] as $decayResult) { // remove attribute if ALL score results in a decay
                            $decayed_flag = $decayed_flag && $decayResult['decayed'];
                        }
                        if ($decayed_flag) {
                            unset($results[$key]);
                        }
                    }
                }
                if (!empty($results[$key])) {
                    if (!empty($options['includeGalaxy'])) {
                        $massaged_attribute = $this->Event->massageTags($user, $results[$key], 'Attribute');
                        $massaged_event = $this->Event->massageTags($user, $results[$key], 'Event');
                        $massaged_attribute['Galaxy'] = array_merge_recursive($massaged_attribute['Galaxy'], $massaged_event['Galaxy']);
                        $results[$key] = $massaged_attribute;
                    }
                    $attributes[] = $results[$key];
                }
            }
            if (!empty($break)) {
                break;
            }
        }
        return $attributes;
    }

    /**
     * @param array $user
     * @param array $eventIds
     * @param bool $includeAllTags
     * @return array
     * @throws Exception
     */
    private function __fetchEventsForAttributeContext(array $user, array $eventIds, $includeAllTags)
    {
        if (empty($eventIds)) {
            return [];
        }
        $events = $this->Event->fetchEvent($user, [
            'eventid' => $eventIds,
            'metadata' => true,
            'sgReferenceOnly' => true,
            'includeEventCorrelations' => false,
            'includeAllTags' => $includeAllTags,
        ]);
        $eventFields = ['id', 'orgc_id', 'org_id', 'date', 'threat_level_id', 'info', 'published', 'uuid', 'analysis', 'timestamp', 'distribution', 'publish_timestamp', 'sharing_group_id', 'extends_uuid'];
        $tagFields = ['id', 'name', 'colour', 'numerical_value'];

        $eventsById = [];
        // Reformat to required format
        foreach ($events as $event) {
            $newEvent = [];
            foreach ($eventFields as $eventField) {
                $newEvent[$eventField] = $event['Event'][$eventField];
            }
            $tags = [];
            foreach ($event['EventTag'] as $et) {
                $tag = ['local' => $et['local']];
                foreach ($tagFields as $tagField) {
                    $tag[$tagField] = $et['Tag'][$tagField];
                }
                $tags[] = $tag;
            }
            $newEvent['Tag'] = $tags;
            $newEvent['Orgc'] = $event['Orgc'];
            $eventsById[$newEvent['id']] = $newEvent;
        }
        return $eventsById;
    }

    private function __attachTagsToAttributes(array &$attributes, array $options)
    {
        $tagIdsToFetch = [];
        foreach ($attributes as $attribute) {
            foreach ($attribute['AttributeTag'] as $at) {
                $tagIdsToFetch[$at['tag_id']] = true;
            }
        }

        if (empty($tagIdsToFetch)) {
            return;
        }

        $conditions = ['Tag.id' => array_keys($tagIdsToFetch)];
        unset($tagIdsToFetch);
        if (empty($options['includeAllTags'])) {
            $conditions['Tag.exportable'] = 1;
        }

        $tagsToModify = $this->AttributeTag->Tag->find('all', [
            'conditions' => $conditions,
            'fields' => ['id', 'name', 'colour', 'numerical_value'],
            'recursive' => -1,
        ]);
        $tags = [];
        foreach ($tagsToModify as $tag) {
            $tags[$tag['Tag']['id']] = $tag['Tag'];
        }

        foreach ($attributes as $k => $attribute) {
            $tagCulled = false;
            foreach ($attribute['AttributeTag'] as $k2 => $at) {
                if (!isset($tags[$at['tag_id']])) {
                    unset($attributes[$k]['AttributeTag'][$k2]);
                    $tagCulled = true;
                } else {
                    $tag = $tags[$at['tag_id']];
                    $tag['local'] = $at['local'];
                    $attributes[$k]['AttributeTag'][$k2]['Tag'] = $tag;
                }
            }
            if ($tagCulled) {
                $attributes[$k]['AttributeTag'] = array_values($attributes[$k]['AttributeTag']);
            }
        }
    }

    private function __attachEventTagsToAttributes($eventTags, &$results, $key, $options)
    {
        if (!isset($eventTags[$results[$key]['Event']['id']])) {
            $tagConditions = array('EventTag.event_id' => $results[$key]['Event']['id']);
            if (empty($options['includeAllTags'])) {
                $tagConditions['Tag.exportable'] = 1;
            }
            $temp = $this->Event->EventTag->find('all', array(
                'recursive' => -1,
                'contain' => array('Tag'),
                'conditions' => $tagConditions
            ));
            foreach ($temp as $tag) {
                $tag['EventTag']['Tag'] = $tag['Tag'];
                unset($tag['Tag']);
                $eventTags[$results[$key]['Event']['id']][] = $tag;
            }
        }
        if (!empty($eventTags)) {
            foreach ($eventTags[$results[$key]['Event']['id']] as $eventTag) {
                $results[$key]['EventTag'][] = $eventTag['EventTag'];
            }
        }
        return $results;
    }

    private function __blockAttributeViaProposal(&$attributes, $k)
    {
        if (!empty($attributes[$k]['ShadowAttribute'])) {
            foreach ($attributes[$k]['ShadowAttribute'] as $sa) {
                if ($sa['value'] === $attributes[$k]['Attribute']['value'] &&
                    $sa['type'] === $attributes[$k]['Attribute']['type'] &&
                    $sa['category'] === $attributes[$k]['Attribute']['category'] &&
                    ($sa['to_ids'] == 0 || $sa['to_ids'] == '') &&
                    $attributes[$k]['Attribute']['to_ids'] == 1
                ) {
                    unset($attributes[$k]);
                }
            }
        } else {
            unset($attributes[$k]['ShadowAttribute']);
        }
    }

    // Method gets and converts the contents of a file passed along as a base64 encoded string with the original filename into a zip archive
    // The zip archive is then passed back as a base64 encoded string along with the md5 hash and a flag whether the transaction was successful
    // The archive is password protected using the "infected" password
    // The contents of the archive will be the actual sample, named <md5> and the original filename in a text file named <md5>.filename.txt
    public function handleMaliciousBase64($event_id, $original_filename, $base64, $hash_types, $proposal = false)
    {
        if (!is_numeric($event_id)) {
            throw new Exception(__('Something went wrong. Received a non-numeric event ID while trying to create a zip archive of an uploaded malware sample.'));
        }

        $content = base64_decode($base64);

        $attachmentTool = $this->loadAttachmentTool();
        $hashes = $attachmentTool->computeHashes($content, $hash_types);
        try {
            $encrypted = $attachmentTool->encrypt($original_filename, $content, $hashes['md5']);
        } catch (Exception $e) {
            $this->logException("Could not create encrypted malware sample.", $e);
            return array('success' => false);
        }

        $result = array_merge(array('data' => base64_encode($encrypted), 'success' => true), $hashes);
        return $result;
    }

    /**
     * @return bool Return true if at least one advanced extraction tool is available
     */
    public function isAdvancedExtractionAvailable()
    {
        try {
            $types = $this->loadAttachmentTool()->checkAdvancedExtractionStatus($this->getPythonVersion());
        } catch (Exception $e) {
            return false;
        }

        foreach ($types as $type => $missing) {
            if ($missing === false) {
                return true;
            }
        }

        return false;
    }

    public function resolveHashType($hash)
    {
        $hashTypes = $this->hashTypes;
        $validTypes = array();
        $length = strlen($hash);
        foreach ($hashTypes as $k => $hashType) {
            $temp = $hashType['lowerCase'] ? strtolower($hash) : $hash;
            if ($hashType['length'] == $length && preg_match($hashType['pattern'], $temp)) {
                $validTypes[] = $k;
            }
        }
        return $validTypes;
    }

    /**
     * @param array $attribute
     * @param bool $context
     * @return array|true
     */
    public function validateAttribute(array $attribute, $context = true)
    {
        $this->set($attribute);
        if (!$context) {
            unset($this->validate['event_id']);
            unset($this->validate['value']['uniqueValue']);
            unset($this->validate['uuid']['unique']);
        }
        if ($this->validates()) {
            return true;
        } else {
            return $this->validationErrors;
        }
    }

    public function restore($id, $user)
    {
        $this->id = $id;
        if (!$this->exists()) {
            return 'Attribute doesn\'t exist, or you lack the permission to edit it.';
        }
        $attribute = $this->find('first', array('conditions' => array('Attribute.id' => $id), 'recursive' => -1, 'contain' => array('Event')));
        if (!$user['Role']['perm_site_admin']) {
            if (!($attribute['Event']['orgc_id'] == $user['org_id'] && (($user['Role']['perm_modify'] && $attribute['Event']['user_id'] != $user['id']) || $user['Role']['perm_modify_org']))) {
                return 'Attribute doesn\'t exist, or you lack the permission to edit it.';
            }
        }
        unset($attribute['Attribute']['timestamp']);
        $attribute['Attribute']['deleted'] = 0;
        $date = new DateTime();
        $attribute['Attribute']['timestamp'] = $date->getTimestamp();
        if ($this->save($attribute['Attribute'])) {
            $attribute['Event']['published'] = 0;
            $attribute['Event']['timestamp'] = $date->getTimestamp();
            $this->Event->save($attribute['Event']);
            $this->__alterAttributeCount($attribute['Event']['id']);
            return true;
        } else {
            return 'Could not save changes.';
        }
    }

    public function saveAttributes($attributes, $user)
    {
        $defaultDistribution = 5;
        if (Configure::read('MISP.default_attribute_distribution') != null) {
            if (Configure::read('MISP.default_attribute_distribution') === 'event') {
                $defaultDistribution = 5;
            } else {
                $defaultDistribution = Configure::read('MISP.default_attribute_distribution');
            }
        }
        $saveResult = true;
        foreach ($attributes as $k => $attribute) {
            if (!empty($attribute['encrypt']) && $attribute['encrypt']) {
                $attribute = $this->onDemandEncrypt($attribute);
            }
            if (!isset($attribute['distribution'])) {
                $attribute['distribution'] = $defaultDistribution;
            }
            unset($attribute['Attachment']);
            $this->create();
            $currentSave = $this->save($attribute);
            $saveResult = $saveResult && $currentSave;
            if ($currentSave) {
                $attribute['id'] = $this->id;
                $this->AttributeTag->handleAttributeTags($user, $attribute, $attribute['event_id'], $capture=true);
            }
        }
        return $saveResult;
    }

    public function onDemandEncrypt($attribute)
    {
        if (strpos($attribute['value'], '|') !== false) {
            $temp = explode('|', $attribute['value']);
            $attribute['value'] = $temp[0];
        }
        $result = $this->handleMaliciousBase64($attribute['event_id'], $attribute['value'], $attribute['data'], array('md5'));
        $attribute['data'] = $result['data'];
        $attribute['value'] = $attribute['value'] . '|' . $result['md5'];
        return $attribute;
    }

    public function saveAndEncryptAttribute($attribute, $user = false)
    {
        $hashes = array('md5' => 'malware-sample', 'sha1' => 'filename|sha1', 'sha256' => 'filename|sha256');
        if ($attribute['encrypt']) {
            $result = $this->handleMaliciousBase64($attribute['event_id'], $attribute['value'], $attribute['data'], array_keys($hashes));
            if (!$result['success']) {
                return 'Could not handle the sample';
            }
            foreach ($hashes as $hash => $typeName) {
                if (!$result[$hash]) {
                    continue;
                }
                $attributeToSave = array(
                    'Attribute' => array(
                        'value' => $attribute['value'] . '|' . $result[$hash],
                        'category' => $attribute['category'],
                        'type' => $typeName,
                        'event_id' => $attribute['event_id'],
                        'comment' => $attribute['comment'],
                        'to_ids' => 1,
                        'distribution' => $attribute['distribution'],
                        'sharing_group_id' => isset($attribute['sharing_group_id']) ? $attribute['sharing_group_id'] : 0,
                    )
                );
                if ($hash == 'md5') {
                    $attributeToSave['Attribute']['data'] = $result['data'];
                }
                $this->create();
                if (!$this->save($attributeToSave)) {
                    return $this->validationErrors;
                }
            }
        }
        return true;
    }

    private function __createTagSubQuery($tag_id, $blocked = false, $scope = 'Event', $limitAttributeHitsTo = 'event')
    {
        $conditionKey = $blocked ? array('NOT' => array('EventTag.tag_id' => $tag_id)) : array('EventTag.tag_id' => $tag_id);
        $db = $this->getDataSource();
        $subQuery = $db->buildStatement(
            array(
                'fields' => array($scope . 'Tag.' . $limitAttributeHitsTo . '_id'),
                'table' => strtolower($scope) . '_tags',
                'alias' => $scope . 'Tag',
                'limit' => null,
                'offset' => null,
                'joins' => array(),
                'conditions' => array(
                    $scope . 'Tag.tag_id' => $tag_id
                ),
                'group' => array($scope . 'Tag.' . $limitAttributeHitsTo . '_id')
            ),
            $this
        );
        $subQuery = ucfirst($limitAttributeHitsTo) . '.id IN (' . $subQuery . ') ';
        $conditions = array(
            $db->expression($subQuery)->value
        );
        return $conditions;
    }

    public function setTagConditions($tags, $conditions, $limitAttributeHitsTo = 'event')
    {
        $args = $this->dissectArgs($tags);
        $tagArray = $this->AttributeTag->Tag->fetchTagIdsFromFilter($args[0], $args[1]);
        $temp = array();
        if (!empty($tagArray[0])) {
            $temp['OR'][] = $this->__createTagSubQuery($tagArray[0]);
            $temp['OR'][] = $this->__createTagSubQuery($tagArray[0], false, 'Attribute', $limitAttributeHitsTo);
        }
        if (!empty($tagArray[1])) {
            $temp['AND']['NOT'] = $this->__createTagSubQuery($tagArray[1], true);
            if ($limitAttributeHitsTo == 'attribute') {
                $temp['AND']['NOT'] = $this->__createTagSubQuery($tagArray[1], true, 'Attribute', $limitAttributeHitsTo);
            }
        }
        $conditions['AND'][] = $temp;
        return $conditions;
    }

    public function setTimestampConditions($timestamp, $conditions, $scope = 'Event.timestamp', $returnRaw = false)
    {
        if (is_array($timestamp)) {
            $timestamp[0] = intval($this->Event->resolveTimeDelta($timestamp[0]));
            $timestamp[1] = intval($this->Event->resolveTimeDelta($timestamp[1]));
            if ($timestamp[0] > $timestamp[1]) {
                $temp = $timestamp[0];
                $timestamp[0] = $timestamp[1];
                $timestamp[1] = $temp;
            }
            $conditions['AND'][] = array($scope . ' >=' => $timestamp[0]);
            $conditions['AND'][] = array($scope . ' <=' => $timestamp[1]);
        } else {
            $timestamp = intval($this->Event->resolveTimeDelta($timestamp));
            $conditions['AND'][] = array($scope . ' >=' => $timestamp);
        }
        if ($returnRaw) {
            return $timestamp;
        }
        return $conditions;
    }

    public function setTimestampSeenConditions($timestamp, $conditions, $scope = 'Attribute.first_seen', $returnRaw = false)
    {
        if (is_array($timestamp)) {
            $timestamp[0] = intval($this->Event->resolveTimeDelta($timestamp[0])) * 1000000; // seen in stored in micro-seconds in the DB
            $timestamp[1] = intval($this->Event->resolveTimeDelta($timestamp[1])) * 1000000; // seen in stored in micro-seconds in the DB
            if ($timestamp[0] > $timestamp[1]) {
                $temp = $timestamp[0];
                $timestamp[0] = $timestamp[1];
                $timestamp[1] = $temp;
            }
            $conditions['AND'][] = array($scope . ' >=' => $timestamp[0]);
            $conditions['AND'][] = array($scope . ' <=' => $timestamp[1]);
        } else {
            $timestamp = intval($this->Event->resolveTimeDelta($timestamp)) * 1000000; // seen in stored in micro-seconds in the DB
            if ($scope == 'Attribute.first_seen') {
                $conditions['AND'][] = array($scope . ' >=' => $timestamp);
            } else {
                $conditions['AND'][] = array($scope . ' <=' => $timestamp);
            }
        }
        if ($returnRaw) {
            return $timestamp;
        }
        return $conditions;
    }

    public function setToIDSConditions($to_ids, $conditions)
    {
        if ($to_ids === 'exclude') {
            $conditions['AND'][] = array('Attribute.to_ids' => 0);
        } else {
            $conditions['AND'][] = array('Attribute.to_ids' => 1);
        }
        return $conditions;
    }

    private function __getCIDRList()
    {
        return $this->find('column', array(
            'conditions' => array(
                'type' => array('ip-src', 'ip-dst'),
                'value1 LIKE' => '%/%'
            ),
            'fields' => array('Attribute.value1'),
            'unique' => true,
            'order' => false
        ));
    }

    public function setCIDRList()
    {
        $redis = $this->setupRedis();
        $cidrList = array();
        if ($redis) {
            $redis->del('misp:cidr_cache_list');
            $cidrList = $this->__getCIDRList();
            if (method_exists($redis, 'saddArray')) {
                $redis->sAddArray('misp:cidr_cache_list', $cidrList);
            } else {
                $pipeline = $redis->multi(Redis::PIPELINE);
                foreach ($cidrList as $cidr) {
                    $pipeline->sadd('misp:cidr_cache_list', $cidr);
                }
                $pipeline->exec();
            }
        }
        return $cidrList;
    }

    public function getSetCIDRList()
    {
        $redis = $this->setupRedis();
        if ($redis) {
            if (!$redis->exists('misp:cidr_cache_list')) {
                $cidrList = $this->setCIDRList();
            } else {
                $cidrList = $redis->smembers('misp:cidr_cache_list');
            }
        } else {
            $cidrList = $this->__getCIDRList();
        }
        return $cidrList;
    }

    public function fetchDistributionData($user)
    {
        $initialDistribution = 5;
        if (Configure::read('MISP.default_attribute_distribution') != null) {
            if (Configure::read('MISP.default_attribute_distribution') === 'event') {
                $initialDistribution = 5;
            } else {
                $initialDistribution = Configure::read('MISP.default_attribute_distribution');
            }
        }
        $sgs = $this->SharingGroup->fetchAllAuthorised($user, 'name', 1);
        $this->set('sharingGroups', $sgs);
        $distributionLevels = $this->distributionLevels;
        if (empty($sgs)) {
            unset($distributionLevels[4]);
        }
        return array('sgs' => $sgs, 'levels' => $distributionLevels, 'initial' => $initialDistribution);
    }

    public function simpleAddMalwareSample($event_id, $attribute_settings, $filename, $tmpfile)
    {
        $attributes = array(
            'malware-sample' => array('type' => 'malware-sample', 'data' => 1, 'category' => '', 'to_ids' => 1, 'disable_correlation' => 0, 'object_relation' => 'malware-sample'),
            'filename' => array('type' => 'filename', 'category' => '', 'to_ids' => 0, 'disable_correlation' => 0, 'object_relation' => 'filename'),
            'md5' => array('type' => 'md5', 'category' => '', 'to_ids' => 1, 'disable_correlation' => 0, 'object_relation' => 'md5'),
            'sha1' => array('type' => 'sha1', 'category' => '', 'to_ids' => 1, 'disable_correlation' => 0, 'object_relation' => 'sha1'),
            'sha256' => array('type' => 'sha256', 'category' => '', 'to_ids' => 1, 'disable_correlation' => 0, 'object_relation' => 'sha256'),
            'size-in-bytes' => array('type' => 'size-in-bytes', 'category' => 'Other', 'to_ids' => 0, 'disable_correlation' => 1, 'object_relation' => 'size-in-bytes')
        );
        $hashes = array('md5', 'sha1', 'sha256');
        $this->Object = ClassRegistry::init('MispObject');
        $this->ObjectTemplate = ClassRegistry::init('ObjectTemplate');
        $current = $this->ObjectTemplate->find('first', array(
            'fields' => array('MAX(version) AS version', 'uuid'),
            'conditions' => array('uuid' => '688c46fb-5edb-40a3-8273-1af7923e2215'),
            'recursive' => -1,
            'group' => array('uuid')
        ));
        if (!empty($current)) {
            $object_template = $this->ObjectTemplate->find('first', array(
                'conditions' => array(
                    'ObjectTemplate.uuid' => '688c46fb-5edb-40a3-8273-1af7923e2215',
                    'ObjectTemplate.version' => $current[0]['version']
                ),
                'recursive' => -1
            ));
        }
        if (empty($object_template)) {
            $object_template = array(
                'ObjectTemplate' => array(
                    'meta-category' => 'file',
                    'name' => 'file',
                    'uuid' => '688c46fb-5edb-40a3-8273-1af7923e2215',
                    'version' => 1,
                    'description' => 'File object describing a file with meta-information'
                )
            );
        }
        $object = array(
            'distribution' => $attribute_settings['distribution'],
            'sharing_group_id' => isset($attribute_settings['sharing_group_id']) ? $attribute_settings['sharing_group_id'] : 0,
            'meta-category' => $object_template['ObjectTemplate']['meta-category'],
            'name' => $object_template['ObjectTemplate']['name'],
            'template_version' => $object_template['ObjectTemplate']['version'],
            'description' => $object_template['ObjectTemplate']['description'],
            'template_uuid' => $object_template['ObjectTemplate']['uuid'],
            'event_id' => $event_id,
            'comment' => !empty($attribute_settings['comment']) ? $attribute_settings['comment'] : ''
        );
        $result = $this->handleMaliciousBase64($event_id, $filename, base64_encode($tmpfile->read()), $hashes);
        foreach ($attributes as $k => $v) {
            $attribute = array(
                'distribution' => 5,
                'category' => empty($v['category']) ? $attribute_settings['category'] : $v['category'],
                'type' => $v['type'],
                'to_ids' => $v['to_ids'],
                'disable_correlation' => $v['disable_correlation'],
                'object_id' => $this->Object->id,
                'event_id' => $event_id,
                'object_relation' => $v['object_relation']
            );
            if (isset($v['data'])) {
                $attribute['data'] = $result['data'];
            }
            if ($k == 'malware-sample') {
                $attribute['value'] = $filename . '|' . $result['md5'];
            } elseif ($k == 'size-in-bytes') {
                $attribute['value'] = $tmpfile->size();
            } elseif ($k == 'filename') {
                $attribute['value'] = $filename;
            } else {
                $attribute['value'] = $result[$v['type']];
            }
            $object['Attribute'][] = $attribute;
        }
        return array('Object' => array($object));
    }

    public function advancedAddMalwareSample($event_id, $attribute_settings, $filename, $tmpfile)
    {
        try {
            $result = $this->loadAttachmentTool()->advancedExtraction($this->getPythonVersion(), $tmpfile->path);
        } catch (Exception $e) {
            $this->logException("Could not finish advanced extraction", $e);
            return $this->simpleAddMalwareSample($event_id, $attribute_settings, $filename, $tmpfile);
        }

        if (isset($result['objects'])) {
            $result['Object'] = $result['objects'];
            unset($result['objects']);
        }
        if (isset($result['references'])) {
            $result['ObjectReference'] = $result['references'];
            unset($result['references']);
        }
        foreach ($result['Object'] as $k => $object) {
            $result['Object'][$k]['distribution'] = $attribute_settings['distribution'];
            $result['Object'][$k]['sharing_group_id'] = isset($attribute_settings['distribution']) ? $attribute_settings['distribution'] : 0;
            if (!empty($result['Object'][$k]['Attribute'])) {
                foreach ($result['Object'][$k]['Attribute'] as $k2 => $attribute) {
                    if ($attribute['value'] == $tmpfile->name) {
                        $result['Object'][$k]['Attribute'][$k2]['value'] = $filename;
                    }
                }
            }
        }

        return $result;
    }

    // gets an attribute, saves it
    // handles encryption, attaching to event/object, logging of issues, tag capturing
    public function captureAttribute($attribute, $eventId, $user, $objectId = false, $log = false, $parentEvent = false, &$validationErrors = false, $params = array())
    {
        if ($log == false) {
            $log = ClassRegistry::init('Log');
        }
        $attribute['event_id'] = $eventId;
        $attribute['object_id'] = $objectId ? $objectId : 0;
        if (!isset($attribute['to_ids'])) {
            $attribute['to_ids'] = $this->typeDefinitions[$attribute['type']]['to_ids'];
        }
        $attribute['to_ids'] = $attribute['to_ids'] ? 1 : 0;
        $attribute['disable_correlation'] = empty($attribute['disable_correlation']) ? 0 : 1;
        unset($attribute['id']);
        if (isset($attribute['base64'])) {
            $attribute['data'] = $attribute['base64'];
        }
        if (!empty($attribute['enforceWarninglist']) || !empty($params['enforceWarninglist'])) {
            $this->Warninglist = ClassRegistry::init('Warninglist');
            if (!$this->Warninglist->filterWarninglistAttribute($attribute)) {
                $this->validationErrors['warninglist'] = 'Attribute could not be saved as it trips over a warninglist and enforceWarninglist is enforced.';
                $validationErrors = $this->validationErrors['warninglist'];
                $log->create();
                $log->save(array(
                        'org' => $user['Organisation']['name'],
                        'model' => 'Attribute',
                        'model_id' => 0,
                        'email' => $user['email'],
                        'action' => 'add',
                        'user_id' => $user['id'],
                        'title' => 'Attribute dropped due to validation for Event ' . $eventId . ' failed',
                        'change' => 'Validation errors: ' . json_encode($this->validationErrors) . ' Full Attribute: ' . json_encode($attribute),
                ));
                return $attribute;
            }
        }
        if (isset($attribute['encrypt'])) {
            $result = $this->handleMaliciousBase64($eventId, $attribute['value'], $attribute['data'], array('md5'));
            $attribute['data'] = $result['data'];
            $attribute['value'] = $attribute['value'] . '|' . $result['md5'];
        }
        $fieldList = $this->captureFields;
        $this->create();
        if (!isset($attribute['distribution'])) {
            $attribute['distribution'] = Configure::read('MISP.default_attribute_distribution');
            if ($attribute['distribution'] == 'event') {
                $attribute['distribution'] = 5;
            }
        }
        $params = array(
            'fieldList' => $fieldList
        );
        if (!empty($parentEvent)) {
            $params['parentEvent'] = $parentEvent;
        }
        if (!empty($attribute['SharingGroup'])) {
            $attribute['sharing_group_id'] = $this->SharingGroup->captureSG($attribute['SharingGroup'], $user);
        } elseif (!empty($attribute['sharing_group_id'])) {
            if (!$this->SharingGroup->checkIfAuthorised($user, $attribute['sharing_group_id'])) {
                unset($attribute['sharing_group_id']);
            }
        }
        if (!$this->save($attribute, $params)) {
            $attribute_short = (isset($attribute['category']) ? $attribute['category'] : 'N/A') . '/' . (isset($attribute['type']) ? $attribute['type'] : 'N/A') . ' ' . (isset($attribute['value']) ? $attribute['value'] : 'N/A');
            $log->create();
            $log->save(array(
                    'org' => $user['Organisation']['name'],
                    'model' => 'Attribute',
                    'model_id' => 0,
                    'email' => $user['email'],
                    'action' => 'add',
                    'user_id' => $user['id'],
                    'title' => 'Attribute dropped due to validation for Event ' . $eventId . ' failed: ' . $attribute_short,
                    'change' => 'Validation errors: ' . json_encode($this->validationErrors) . ' Full Attribute: ' . json_encode($attribute),
            ));
        } else {
            $tags = array();
            if (isset($attribute['AttributeTag'])) {
                foreach ($attribute['AttributeTag'] as $at) {
                    unset($at['id']);
                    $this->AttributeTag->create();
                    $at['attribute_id'] = $this->id;
                    $at['event_id'] = $eventId;
                    $this->AttributeTag->save($at);
                }
            }
            if (isset($attribute['Tag'])) {
                if (!empty($attribute['Tag']['name'])) {
                    $attribute['Tag'] = array($attribute['Tag']);
                }
                foreach ($attribute['Tag'] as $tag) {
                    $tag_id = $this->AttributeTag->Tag->captureTag($tag, $user);
                    if ($tag_id) {
                        $this->AttributeTag->create();
                        $at = array();
                        $at['attribute_id'] = $this->id;
                        $at['event_id'] = $eventId;
                        $at['tag_id'] = $tag_id;
                        $this->AttributeTag->save($at);
                    }
                }
            }
            if (!empty($attribute['Sighting'])) {
                $this->Sighting->captureSightings($attribute['Sighting'], $this->id, $eventId, $user);
            }
        }
        if (!empty($this->validationErrors)) {
            $validationErrors = $this->validationErrors;
        }
        return $attribute;
    }

    public function editAttribute($attribute, $eventId, $user, $objectId, $log = false, $force = false, &$nothingToChange = false)
    {
        $attribute['event_id'] = $eventId;
        $attribute['object_id'] = $objectId;
        if (isset($attribute['encrypt'])) {
            $result = $this->handleMaliciousBase64($eventId, $attribute['value'], $attribute['data'], array('md5'));
            $attribute['data'] = $result['data'];
            $attribute['value'] = $attribute['value'] . '|' . $result['md5'];
        }
        unset($attribute['id']);
        if (isset($attribute['uuid'])) {
            $existingAttribute = $this->find('first', array(
                'conditions' => array('Attribute.uuid' => $attribute['uuid']),
                'contain' => array('AttributeTag' => 'Tag'),
                'recursive' => -1,
            ));
            $this->Log = ClassRegistry::init('Log');
            if (count($existingAttribute)) {
                if ($existingAttribute['Attribute']['event_id'] != $eventId || $existingAttribute['Attribute']['object_id'] != $objectId) {
                    $this->Log->create();
                    $result = $this->Log->save(array(
                            'org' => $user['Organisation']['name'],
                            'model' => 'Attribute',
                            'model_id' => 0,
                            'email' => $user['email'],
                            'action' => 'edit',
                            'user_id' => $user['id'],
                            'title' => 'Duplicate UUID found in attribute',
                            'change' => 'An attribute was blocked from being saved due to a duplicate UUID. The uuid in question is: ' . $attribute['uuid'] . '. This can also be due to the same attribute (or an attribute with the same UUID) existing in a different event / object)',
                    ));
                    return true;
                }
                // If a field is not set in the request, just reuse the old value
                $recoverFields = array('value', 'to_ids', 'distribution', 'category', 'type', 'comment', 'sharing_group_id', 'object_id', 'object_relation', 'first_seen', 'last_seen');
                foreach ($recoverFields as $rF) {
                    if (!isset($attribute[$rF])) {
                        $attribute[$rF] = $existingAttribute['Attribute'][$rF];
                    }
                }
                $attribute['id'] = $existingAttribute['Attribute']['id'];
                // Check if the attribute's timestamp is bigger than the one that already exists.
                // If yes, it means that it's newer, so insert it. If no, it means that it's the same attribute or older - don't insert it, insert the old attribute.
                // Alternatively, we could unset this attribute from the request, but that could lead with issues if we decide that we want to start deleting attributes that don't exist in a pushed event.
                if (isset($attribute['timestamp'])) {
                    if (!$force && $attribute['timestamp'] <= $existingAttribute['Attribute']['timestamp']) {
                        $nothingToChange = true;
                        return true;
                    }
                } else {
                    $date = new DateTime();
                    $attribute['timestamp'] = $date->getTimestamp();
                }
            } else {
                $this->create();
            }
        } else {
            $this->create();
        }
        $attribute['event_id'] = $eventId;
        if (isset($attribute['distribution']) && $attribute['distribution'] == 4) {
            if (!empty($attribute['SharingGroup'])) {
                $attribute['sharing_group_id'] = $this->SharingGroup->captureSG($attribute['SharingGroup'], $user);
            } elseif (!empty($attribute['sharing_group_id'])) {
                if (!$this->SharingGroup->checkIfAuthorised($user, $attribute['sharing_group_id'])) {
                    unset($attribute['sharing_group_id']);
                }
            }
            if (empty($attribute['sharing_group_id'])) {
                $attribute_short = (isset($attribute['category']) ? $attribute['category'] : 'N/A') . '/' . (isset($attribute['type']) ? $attribute['type'] : 'N/A') . ' ' . (isset($attribute['value']) ? $attribute['value'] : 'N/A');
                $this->Log = ClassRegistry::init('Log');
                $this->Log->create();
                $this->Log->save(array(
                    'org' => $user['Organisation']['name'],
                    'model' => 'Attribute',
                    'model_id' => 0,
                    'email' => $user['email'],
                    'action' => 'edit',
                    'user_id' => $user['id'],
                    'title' => 'Attribute dropped due to invalid sharing group for Event ' . $eventId . ' failed: ' . $attribute_short,
                    'change' => 'Validation errors: ' . json_encode($this->validationErrors) . ' Full Attribute: ' . json_encode($attribute),
                ));
                return 'Invalid sharing group choice.';
            }
        } else if (!isset($attribute['distribution'])) {
            $attribute['distribution'] = Configure::read('MISP.default_attribute_distribution');
            if ($attribute['distribution'] == 'event') {
                $attribute['distribution'] = 5;
            }
        }
        $fieldList = $this->editableFields;
        if (empty($existingAttribute)) {
            $addableFieldList = array('event_id', 'type', 'uuid');
            $fieldList = array_merge($fieldList, $addableFieldList);
        }
        if ($objectId) {
            $fieldList[] = 'object_id';
            $fieldList[] = 'object_relation';
        }
        if (!$this->save(array('Attribute' => $attribute), array('fieldList' => $fieldList))) {
            $attribute_short = (isset($attribute['category']) ? $attribute['category'] : 'N/A') . '/' . (isset($attribute['type']) ? $attribute['type'] : 'N/A') . ' ' . (isset($attribute['value']) ? $attribute['value'] : 'N/A');
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
            $this->Log->save(array(
                'org' => $user['Organisation']['name'],
                'model' => 'Attribute',
                'model_id' => 0,
                'email' => $user['email'],
                'action' => 'edit',
                'user_id' => $user['id'],
                'title' => 'Attribute dropped due to validation for Event ' . $eventId . ' failed: ' . $attribute_short,
                'change' => 'Validation errors: ' . json_encode($this->validationErrors) . ' Full Attribute: ' . json_encode($attribute),
            ));
            return $this->validationErrors;
        } else {
            if (isset($attribute['Sighting']) && !empty($attribute['Sighting'])) {
                $this->Sighting = ClassRegistry::init('Sighting');
                $this->Sighting->captureSightings($attribute['Sighting'], $this->id, $eventId, $user);
            }
            if ($user['Role']['perm_tagger']) {
                /*
                    We should uncomment the line below in the future once we have tag soft-delete
                    A solution to still keep the behavior for previous instance could be to not soft-delete the Tag if the remote instance
                    has a version below x
                */
                // $this->AttributeTag->pruneOutdatedAttributeTagsFromSync(isset($attribute['Tag']) ? $attribute['Tag'] : array(), $existingAttribute['AttributeTag']);
                if (isset($attribute['Tag'])) {
                    foreach ($attribute['Tag'] as $tag) {
                        $tag_id = $this->AttributeTag->Tag->captureTag($tag, $user);
                        if ($tag_id) {
                            $tag['id'] = $tag_id;
                            // fix the IDs here
                            $this->AttributeTag->handleAttributeTag($this->id, $attribute['event_id'], $tag);
                        } else {
                            // If we couldn't attach the tag it is most likely because we couldn't create it - which could have many reasons
                            // However, if a tag couldn't be added, it could also be that the user is a tagger but not a tag editor
                            // In which case if no matching tag is found, no tag ID is returned. Logging these is pointless as it is the correct behaviour.
                            if ($user['Role']['perm_tag_editor']) {
                                $this->Log->create();
                                $this->Log->save(array(
                                    'org' => $user['Organisation']['name'],
                                    'model' => 'Attrubute',
                                    'model_id' => $this->id,
                                    'email' => $user['email'],
                                    'action' => 'edit',
                                    'user_id' => $user['id'],
                                    'title' => 'Failed create or attach Tag ' . $tag['name'] . ' to the attribute.',
                                    'change' => ''
                                ));
                            }
                        }
                    }
                }
            }
        }
        return true;
    }

    public function deleteAttribute($id, $user, $hard = false)
    {
        $this->id = $id;
        if (!$this->exists()) {
            return false;
        }
        $result = $this->fetchAttributes($user, array(
            'conditions' => array('Attribute.id' => $id),
            'flatten' => 1,
            'deleted' => [0,1],
            'recursive' => -1,
            'contain' => array('Event')
        ));
        if (empty($result)) {
            throw new ForbiddenException(__('Invalid attribute'));
        }
        $result = $result[0];

        // check for permissions
        if (!$user['Role']['perm_site_admin']) {
            if ($result['Event']['locked']) {
                if ($user['org_id'] != $result['Event']['org_id'] || !$user['Role']['perm_sync']) {
                    throw new ForbiddenException(__('You do not have permission to do that.'));
                }
            } else {
                if ($user['org_id'] != $result['Event']['orgc_id']) {
                    throw new ForbiddenException(__('You do not have permission to do that.'));
                }
            }
        }
        $date = new DateTime();
        if ($hard) {
            $save = $this->delete($id);
        } else {
            if (Configure::read('Security.sanitise_attribute_on_delete')) {
                $result['Attribute']['category'] = 'Other';
                $result['Attribute']['type'] = 'comment';
                $result['Attribute']['value'] = 'deleted';
                $result['Attribute']['comment'] = '';
                $result['Attribute']['to_ids'] = 0;
            }
            $result['Attribute']['deleted'] = 1;
            $result['Attribute']['timestamp'] = $date->getTimestamp();
            $save = $this->save($result);
            $object_refs = $this->Object->ObjectReference->find('all', array(
                'conditions' => array(
                    'ObjectReference.referenced_type' => 0,
                    'ObjectReference.referenced_id' => $id,
                ),
                'recursive' => -1
            ));
            foreach ($object_refs as $ref) {
                $ref['ObjectReference']['deleted'] = 1;
                $this->Object->ObjectReference->save($ref);
            }
        }
        // attachment will be deleted with the beforeDelete() function in the Model
        if ($save) {
            // We have just deleted the attribute, let's also check if there are any shadow attributes that were attached to it and delete them
            $this->Event->ShadowAttribute->deleteAll(array('ShadowAttribute.old_id' => $id), false);

            // remove the published flag from the event
            $this->Event->unpublishEvent($result['Event']['id']);
            return true;
        } else {
            return false;
        }
    }

    public function attachValidationWarnings($adata)
    {
        if (!$this->__fTool) {
            $this->__fTool = new FinancialTool();
        }
        if (!$this->__fTool->validateRouter($adata['type'], $adata['value'])) {
            $adata['validationIssue'] = true;
        }
        return $adata;
    }

    public function buildFilterConditions($user, &$params)
    {
        $conditions = $this->buildConditions($user);
        if (isset($params['wildcard'])) {
            $temp = array();
            $options = array(
                'filter' => 'wildcard',
                'scope' => 'Attribute',
                'pop' => false,
                'context' => 'Event'
            );
            $conditions['AND'][] = array('OR' => $this->Event->set_filter_wildcard_attributes($params, $temp, $options));
        } else {
            $attribute_conditions = array();
            $object_conditions = array();
            if (isset($params['ignore'])) {
                $params['to_ids'] = array(0, 1);
                $params['published'] = array(0, 1);
            }
            $simple_params = array(
                'Attribute' => array(
                    'value' => array('function' => 'set_filter_value'),
                    'category' => array('function' => 'set_filter_simple_attribute'),
                    'type' => array('function' => 'set_filter_type'),
                    'object_relation' => array('function' => 'set_filter_simple_attribute'),
                    'tags' => array('function' => 'set_filter_tags', 'pop' => true),
                    'uuid' => array('function' => 'set_filter_uuid'),
                    'deleted' => array('function' => 'set_filter_deleted'),
                    'timestamp' => array('function' => 'set_filter_timestamp', 'pop' => true),
                    'attribute_timestamp' => array('function' => 'set_filter_timestamp'),
                    'first_seen' => array('function' => 'set_filter_seen'),
                    'last_seen' => array('function' => 'set_filter_seen'),
                    'to_ids' => array('function' => 'set_filter_to_ids'),
                    'comment' => array('function' => 'set_filter_comment')
                ),
                'Event' => array(
                    'eventid' => array('function' => 'set_filter_eventid'),
                    'eventinfo' => array('function' => 'set_filter_eventinfo'),
                    'ignore' => array('function' => 'set_filter_ignore'),
                    'from' => array('function' => 'set_filter_timestamp'),
                    'to' => array('function' => 'set_filter_timestamp'),
                    'date' => array('function' => 'set_filter_date'),
                    'tags' => array('function' => 'set_filter_tags'),
                    'last' => array('function' => 'set_filter_timestamp', 'pop' => true),
                    'timestamp' => array('function' => 'set_filter_timestamp', 'pop' => true),
                    'event_timestamp' => array('function' => 'set_filter_timestamp', 'pop' => true),
                    'publish_timestamp' => array('function' => 'set_filter_timestamp'),
                    'org' => array('function' => 'set_filter_org'),
                    'published' => array('function' => 'set_filter_published'),
                    'threat_level_id' => array('function' => 'set_filter_threat_level_id')
                ),
                'Object' => array(
                    'object_name' => array('function' => 'set_filter_object_name'),
                    'deleted' => array('function' => 'set_filter_deleted')
                )
            );
            foreach ($params as $param => $paramData) {
                foreach ($simple_params as $scope => $simple_param_scoped) {
                    if (isset($simple_param_scoped[$param]) && isset($params[$param]) && $params[$param] !== false) {
                        $options = array(
                            'filter' => $param,
                            'scope' => $scope,
                            'pop' => !empty($simple_param_scoped[$param]['pop']),
                            'context' => 'Attribute'
                        );
                        $conditions = $this->Event->{$simple_param_scoped[$param]['function']}($params, $conditions, $options);
                    }
                }
            }
        }
        return $conditions;
    }

    public function restSearch($user, $returnFormat, $filters, $paramsOnly = false, $jobId = false, &$elementCounter = 0, &$renderView = false)
    {
        if (!isset($this->validFormats[$returnFormat][1])) {
            throw new NotFoundException('Invalid output format.');
        }
        App::uses($this->validFormats[$returnFormat][1], 'Export');
        $exportTool = new $this->validFormats[$returnFormat][1]();
        if (!empty($exportTool->use_default_filters)) {
            $exportTool->setDefaultFilters($filters);
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
        if (!empty($filters['quickFilter'])) {
            $filters['searchall'] = $filters['quickFilter'];
            if (!empty($filters['value'])) {
                unset($filters['value']);
            }
        }
        if (!empty($exportTool->renderView)) {
            $renderView = $exportTool->renderView;
        }
        if (isset($filters['searchall'])) {
            if (!empty($filters['value'])) {
                $filters['wildcard'] = $filters['value'];
                unset($filters['value']);
            } else {
                $filters['wildcard'] = $filters['searchall'];
            }
        }

        $subqueryElements = $this->Event->harvestSubqueryElements($filters);
        $filters = $this->Event->addFiltersFromSubqueryElements($filters, $subqueryElements, $user);
        $filters = $this->Event->addFiltersFromUserSettings($user, $filters);
        $conditions = $this->buildFilterConditions($user, $filters);
        $params = array(
                'conditions' => $conditions,
                'fields' => array('Attribute.*', 'Event.org_id', 'Event.distribution'),
                'withAttachments' => !empty($filters['withAttachments']) ? $filters['withAttachments'] : 0,
                'enforceWarninglist' => !empty($filters['enforceWarninglist']) ? $filters['enforceWarninglist'] : 0,
                'includeAllTags' => !empty($filters['includeAllTags']) ? $filters['includeAllTags'] : 0,
                'flatten' => 1,
                'includeEventUuid' => !empty($filters['includeEventUuid']) ? $filters['includeEventUuid'] : 0,
                'includeEventTags' => !empty($filters['includeEventTags']) ? $filters['includeEventTags'] : 0,
                'includeProposals' => !empty($filters['includeProposals']) ? $filters['includeProposals'] : 0,
                'includeWarninglistHits' => !empty($filters['includeWarninglistHits']) ? $filters['includeWarninglistHits'] : 0,
                'includeContext' => !empty($filters['includeContext']) ? $filters['includeContext'] : 0,
                'includeSightings' => !empty($filters['includeSightings']) ? $filters['includeSightings'] : 0,
                'includeSightingdb' => !empty($filters['includeSightingdb']) ? $filters['includeSightingdb'] : 0,
                'includeCorrelations' => !empty($filters['includeCorrelations']) ? $filters['includeCorrelations'] : 0,
                'includeDecayScore' => !empty($filters['includeDecayScore']) ? $filters['includeDecayScore'] : 0,
                'includeFullModel' => !empty($filters['includeFullModel']) ? $filters['includeFullModel'] : 0,
                'allow_proposal_blocking' => !empty($filters['allow_proposal_blocking']) ? $filters['allow_proposal_blocking'] : 0
        );
        if (!empty($filters['attackGalaxy'])) {
            $params['attackGalaxy'] = $filters['attackGalaxy'];
        }
        if (isset($filters['include_event_uuid'])) {
            $params['includeEventUuid'] = $filters['include_event_uuid'];
        }
        if (isset($filters['limit'])) {
            $params['limit'] = $filters['limit'];
            if (!isset($filters['page'])) {
                $filters['page'] = 1;
            }
        }
        if (isset($filters['page'])) {
            $params['page'] = $filters['page'];
        }
        if (!empty($filters['deleted'])) {
            $params['deleted'] = $filters['deleted'];
        }
        if (!empty($filters['excludeDecayed'])) {
            $params['excludeDecayed'] = $filters['excludeDecayed'];
            $params['includeDecayScore'] = 1;
        }
        if (!empty($filters['decayingModel'])) {
            $params['decayingModel'] = $filters['decayingModel'];
        }
        if (!empty($filters['modelOverrides'])) {
            $params['modelOverrides'] = $filters['modelOverrides'];
        }
        if (!empty($filters['score'])) {
            $params['score'] = $filters['score'];
        }
        if ($paramsOnly) {
            return $params;
        }
        if (method_exists($exportTool, 'modify_params')) {
            $params = $exportTool->modify_params($user, $params);
        }
        $exportToolParams = array(
            'user' => $user,
            'params' => $params,
            'returnFormat' => $returnFormat,
            'scope' => 'Attribute',
            'filters' => $filters
        );
        if (!empty($exportTool->additional_params)) {
            $params = array_merge_recursive(
                $params,
                $exportTool->additional_params
            );
        }

        $tmpfile = new TmpFileTool();
        $tmpfile->write($exportTool->header($exportToolParams));
        $loop = false;
        if (empty($params['limit'])) {
            $memoryInMb = $this->convert_to_memory_limit_to_mb(ini_get('memory_limit'));
            $default_attribute_memory_coefficient = Configure::check('MISP.default_attribute_memory_coefficient') ? Configure::read('MISP.default_attribute_memory_coefficient') : 80;
            $memoryScalingFactor = isset($exportTool->memory_scaling_factor) ? $exportTool->memory_scaling_factor : $default_attribute_memory_coefficient;
            $params['limit'] = $memoryInMb * $memoryScalingFactor;
            $loop = true;
            $params['page'] = 1;
        }
        if (empty($exportTool->mock_query_only)) {
            $elementCounter = $this->__iteratedFetch($user, $params, $loop, $tmpfile, $exportTool, $exportToolParams);
        }
        $tmpfile->write($exportTool->footer($exportToolParams));
        return $tmpfile;
    }

    /**
     * @param array $user
     * @param array $params
     * @param bool $loop If true, data are fetched in loop to keep memory usage low
     * @param TmpFileTool $tmpfile
     * @param object $exportTool
     * @param array $exportToolParams
     * @return int Number of attributes
     * @throws Exception
     */
    private function __iteratedFetch(array $user, array $params, $loop, TmpFileTool $tmpfile, $exportTool, array $exportToolParams)
    {
        $this->Allowedlist = ClassRegistry::init('Allowedlist');
        $separator = $exportTool->separator($exportToolParams);
        $elementCounter = 0;
        $continue = true;
        do {
            $results = $this->fetchAttributes($user, $params, $continue);
            if (empty($results)) {
                break; // nothing found, skip rest
            }
            if ($params['includeSightingdb']) {
                $this->Sightingdb = ClassRegistry::init('Sightingdb');
                $results = $this->Sightingdb->attachToAttributes($results, $user);
            }
            $results = $this->Allowedlist->removeAllowedlistedFromArray($results, true);
            $elementCounter += count($results);
            foreach ($results as $attribute) {
                $handlerResult = $exportTool->handler($attribute, $exportToolParams);
                if ($handlerResult !== '') {
                    $tmpfile->writeWithSeparator($handlerResult, $separator);
                }
            }
            $params['page'] += 1;
        } while ($loop && $continue);

        return $elementCounter;
    }

    public function set_filter_uuid(&$params, $conditions, $options)
    {
        if (!empty($params['uuid'])) {
            $params['uuid'] = $this->convert_filters($params['uuid']);
            if (!empty($params['uuid']['OR'])) {
                $conditions['AND'][] = array(
                    'OR' => array(
                        'Event.uuid' => $params['uuid']['OR'],
                        'Attribute.uuid' => $params['uuid']['OR']
                    )
                );
            }
            if (!empty($params['uuid']['NOT'])) {
                $conditions['AND'][] = array(
                    'NOT' => array(
                        'Event.uuid' => $params['uuid']['NOT'],
                        'Attribute.uuid' =>  $params['uuid']['NOT']
                    )
                );
            }
        }
        return $conditions;
    }

    /**
     * @param array $attribute
     */
    public function removeGalaxyClusterTags(array &$attribute)
    {
        $galaxyTagIds = array();
        foreach ($attribute['Galaxy'] as $galaxy) {
            foreach ($galaxy['GalaxyCluster'] as $galaxyCluster) {
                $galaxyTagIds[$galaxyCluster['tag_id']] = true;
            }
        }

        if (empty($galaxyTagIds)) {
            return;
        }

        foreach ($attribute['AttributeTag'] as $k => $attributeTag) {
            $tagId = $attributeTag['Tag']['id'];
            if (isset($galaxyTagIds[$tagId])) {
                unset($attribute['AttributeTag'][$k]);
            }
        }
    }

    /**
     * @param string $value
     * @return bool
     */
    private function isDomainValid($value)
    {
        return preg_match("#^[A-Z0-9.\-_]+\.[A-Z0-9\-]{2,}$#i", $value) === 1;
    }

    /**
     * @param string $value
     * @return bool
     */
    private function isPortValid($value)
    {
        return $this->isPositiveInteger($value) && $value >= 1 && $value <= 65535;
    }

    /**
     * @param string $type
     * @param string $value
     * @return bool
     */
    private function isHashValid($type, $value)
    {
        if (!isset($this->__hexHashLengths[$type])) {
            throw new InvalidArgumentException("Invalid hash type '$type'.");
        }
        $length = $this->__hexHashLengths[$type];
        return strlen($value) === $length && ctype_xdigit($value);
    }

    /**
     * Returns true if input value is positive integer or zero.
     * @param int|string $value
     * @return bool
     */
    private function isPositiveInteger($value)
    {
        return (is_int($value) && $value >= 0) || ctype_digit($value);
    }

    public function typeToCategoryMapping()
    {
        $typeCategoryMapping = array();
        foreach ($this->categoryDefinitions as $k => $cat) {
            foreach ($cat['types'] as $type) {
                $typeCategoryMapping[$type][$k] = $k;
            }
        }
        foreach ($typeCategoryMapping as $k => $v) {
            $typeCategoryMapping[$k] = array_values($v);
        }
        return $typeCategoryMapping;
    }

    public function __isset($name)
    {
        if ($name === 'typeDefinitions' || $name === 'categoryDefinitions') {
            return true;
        }
        return parent::__isset($name);
    }

    public function __get($name)
    {
        if ($name === 'typeDefinitions') {
            $this->typeDefinitions = $this->generateTypeDefinitions();
            return $this->typeDefinitions;
        } else if ($name === 'categoryDefinitions') {
            $this->categoryDefinitions = $this->generateCategoryDefintions();
            return $this->categoryDefinitions;
        }
        return parent::__get($name);
    }

    /**
     * Generate just when really need
     * NOTE WHEN MODIFYING: please ensure to run the script 'tools/gen_misp_types_categories.py' to update the new definitions everywhere. (docu, website, RFC, ... )
     * @return array[]
     */
    private function generateCategoryDefintions()
    {
        return array(
            'Internal reference' => array(
                'desc' => __('Reference used by the publishing party (e.g. ticket number)'),
                'types' => array('text', 'link', 'comment', 'other', 'hex', 'anonymised', 'git-commit-id')
            ),
            'Targeting data' => array(
                'desc' => __('Internal Attack Targeting and Compromise Information'),
                'formdesc' => __('Targeting information to include recipient email, infected machines, department, and or locations.'),
                'types' => array('target-user', 'target-email', 'target-machine', 'target-org', 'target-location', 'target-external', 'comment', 'anonymised')
            ),
            'Antivirus detection' => array(
                'desc' => __('All the info about how the malware is detected by the antivirus products'),
                'formdesc' => __('List of anti-virus vendors detecting the malware or information on detection performance (e.g. 13/43 or 67%). Attachment with list of detection or link to VirusTotal could be placed here as well.'),
                'types' => array('link', 'comment', 'text', 'hex', 'attachment', 'other', 'anonymised')
            ),
            'Payload delivery' => array(
                'desc' => __('Information about how the malware is delivered'),
                'formdesc' => __('Information about the way the malware payload is initially delivered, for example information about the email or web-site, vulnerability used, originating IP etc. Malware sample itself should be attached here.'),
                'types' => array('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'ssdeep', 'imphash', 'telfhash', 'impfuzzy', 'authentihash', 'vhash', 'pehash', 'tlsh', 'cdhash', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|sha3-224', 'filename|sha3-256', 'filename|sha3-384', 'filename|sha3-512', 'filename|authentihash', 'filename|vhash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash','filename|impfuzzy', 'filename|pehash', 'mac-address', 'mac-eui-64', 'ip-src', 'ip-dst', 'ip-dst|port', 'ip-src|port', 'hostname', 'domain', 'email', 'email-src', 'email-dst', 'email-subject', 'email-attachment', 'email-body', 'url', 'user-agent', 'AS', 'pattern-in-file', 'pattern-in-traffic', 'filename-pattern', 'stix2-pattern', 'yara', 'sigma', 'mime-type', 'attachment', 'malware-sample', 'link', 'malware-type', 'comment', 'text', 'hex', 'vulnerability', 'cpe', 'weakness', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'ja3-fingerprint-md5', 'jarm-fingerprint', 'hassh-md5', 'hasshserver-md5', 'other', 'hostname|port', 'email-dst-display-name', 'email-src-display-name', 'email-header', 'email-reply-to', 'email-x-mailer', 'email-mime-boundary', 'email-thread-index', 'email-message-id', 'mobile-application-id', 'chrome-extension-id', 'whois-registrant-email', 'anonymised')
            ),
            'Artifacts dropped' => array(
                'desc' => __('Any artifact (files, registry keys etc.) dropped by the malware or other modifications to the system'),
                'types' => array('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'ssdeep', 'imphash', 'telfhash', 'impfuzzy', 'authentihash', 'vhash', 'cdhash', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|sha3-224', 'filename|sha3-256', 'filename|sha3-384', 'filename|sha3-512', 'filename|authentihash', 'filename|vhash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash', 'filename|impfuzzy','filename|pehash', 'regkey', 'regkey|value', 'pattern-in-file', 'pattern-in-memory', 'filename-pattern', 'pdb', 'stix2-pattern', 'yara', 'sigma', 'attachment', 'malware-sample', 'named pipe', 'mutex', 'process-state','windows-scheduled-task', 'windows-service-name', 'windows-service-displayname', 'comment', 'text', 'hex', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'other', 'cookie', 'gene', 'kusto-query', 'mime-type', 'anonymised', 'pgp-public-key', 'pgp-private-key')
            ),
            'Payload installation' => array(
                'desc' => __('Info on where the malware gets installed in the system'),
                'formdesc' => __('Location where the payload was placed in the system and the way it was installed. For example, a filename|md5 type attribute can be added here like this: c:\\windows\\system32\\malicious.exe|41d8cd98f00b204e9800998ecf8427e.'),
                'types' => array('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'ssdeep', 'imphash', 'telfhash', 'impfuzzy', 'authentihash', 'vhash', 'pehash', 'tlsh', 'cdhash', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|sha3-224', 'filename|sha3-256', 'filename|sha3-384', 'filename|sha3-512', 'filename|authentihash', 'filename|vhash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash', 'filename|impfuzzy', 'filename|pehash', 'pattern-in-file', 'pattern-in-traffic', 'pattern-in-memory', 'filename-pattern', 'stix2-pattern', 'yara', 'sigma', 'vulnerability', 'cpe','weakness', 'attachment', 'malware-sample', 'malware-type', 'comment', 'text', 'hex', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'mobile-application-id', 'chrome-extension-id', 'other', 'mime-type', 'anonymised')
            ),
            'Persistence mechanism' => array(
                'desc' => __('Mechanisms used by the malware to start at boot'),
                'formdesc' => __('Mechanisms used by the malware to start at boot. This could be a registry key, legitimate driver modification, LNK file in startup'),
                'types' => array('filename', 'regkey', 'regkey|value', 'comment', 'text', 'other', 'hex', 'anonymised')
            ),
            'Network activity' => array(
                'desc' => __('Information about network traffic generated by the malware'),
                'types' => array('ip-src', 'ip-dst', 'ip-dst|port', 'ip-src|port', 'port', 'hostname', 'domain', 'domain|ip', 'mac-address', 'mac-eui-64', 'email', 'email-dst', 'email-src', 'eppn', 'url', 'uri', 'user-agent', 'http-method', 'AS', 'snort', 'pattern-in-file', 'filename-pattern','stix2-pattern', 'pattern-in-traffic', 'attachment', 'comment', 'text', 'x509-fingerprint-md5', 'x509-fingerprint-sha1', 'x509-fingerprint-sha256', 'ja3-fingerprint-md5', 'jarm-fingerprint', 'hassh-md5', 'hasshserver-md5', 'other', 'hex', 'cookie', 'hostname|port', 'bro', 'zeek', 'anonymised', 'community-id', 'email-subject', 'favicon-mmh3', 'dkim', 'dkim-signature')
            ),
            'Payload type' => array(
                'desc' => __('Information about the final payload(s)'),
                'formdesc' => __('Information about the final payload(s). Can contain a function of the payload, e.g. keylogger, RAT, or a name if identified, such as Poison Ivy.'),
                'types' => array('comment', 'text', 'other', 'anonymised')
            ),
            'Attribution' => array(
                'desc' => __('Identification of the group, organisation, or country behind the attack'),
                'types' => array('threat-actor', 'campaign-name', 'campaign-id', 'whois-registrant-phone', 'whois-registrant-email', 'whois-registrant-name', 'whois-registrant-org', 'whois-registrar', 'whois-creation-date','comment', 'text', 'x509-fingerprint-sha1','x509-fingerprint-md5', 'x509-fingerprint-sha256', 'other', 'dns-soa-email', 'anonymised', 'email')
            ),
            'External analysis' => array(
                'desc' => __('Any other result from additional analysis of the malware like tools output'),
                'formdesc' => __('Any other result from additional analysis of the malware like tools output Examples: pdf-parser output, automated sandbox analysis, reverse engineering report.'),
                'types' => array('md5', 'sha1', 'sha256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha256', 'filename|sha3-224', 'filename|sha3-256', 'filename|sha3-384', 'filename|sha3-512', 'ip-src', 'ip-dst', 'ip-dst|port', 'ip-src|port', 'mac-address', 'mac-eui-64', 'hostname', 'domain', 'domain|ip', 'url', 'user-agent', 'regkey', 'regkey|value', 'AS', 'snort', 'bro', 'zeek', 'pattern-in-file', 'pattern-in-traffic', 'pattern-in-memory', 'filename-pattern','vulnerability', 'cpe', 'weakness', 'attachment', 'malware-sample', 'link', 'comment', 'text', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'ja3-fingerprint-md5', 'jarm-fingerprint', 'hassh-md5', 'hasshserver-md5', 'github-repository', 'other', 'cortex', 'anonymised', 'community-id')
            ),
            'Financial fraud' => array(
                'desc' => __('Financial Fraud indicators'),
                'formdesc' => __('Financial Fraud indicators, for example: IBAN Numbers, BIC codes, Credit card numbers, etc.'),
                'types' => array('btc', 'dash', 'xmr', 'iban', 'bic', 'bank-account-nr', 'aba-rtn', 'bin', 'cc-number', 'prtn', 'phone-number', 'comment', 'text', 'other', 'hex', 'anonymised'),
            ),
            'Support Tool' => array(
                'desc' => __('Tools supporting analysis or detection of the event'),
                'types' => array('link', 'text', 'attachment', 'comment', 'other', 'hex', 'anonymised')
            ),
            'Social network' => array(
                'desc' => __('Social networks and platforms'),
                // email-src and email-dst or should we go with a new email type that is neither / both?
                'types' => array('github-username', 'github-repository', 'github-organisation', 'jabber-id', 'twitter-id', 'email', 'email-src', 'email-dst', 'eppn','comment', 'text', 'other', 'whois-registrant-email', 'anonymised', 'pgp-public-key', 'pgp-private-key')
            ),
            'Person' => array(
                'desc' => __('A human being - natural person'),
                'types' => array('first-name', 'middle-name', 'last-name', 'full-name', 'date-of-birth', 'place-of-birth', 'gender', 'passport-number', 'passport-country', 'passport-expiration', 'redress-number', 'nationality', 'visa-number', 'issue-date-of-the-visa', 'primary-residence', 'country-of-residence', 'special-service-request', 'frequent-flyer-number', 'travel-details', 'payment-details', 'place-port-of-original-embarkation', 'place-port-of-clearance', 'place-port-of-onward-foreign-destination', 'passenger-name-record-locator-number', 'comment', 'text', 'other', 'phone-number', 'identity-card-number', 'anonymised', 'email', 'pgp-public-key', 'pgp-private-key')
            ),
            'Other' => array(
                'desc' => __('Attributes that are not part of any other category or are meant to be used as a component in MISP objects in the future'),
                'types' => array('comment', 'text', 'other', 'size-in-bytes', 'counter', 'datetime', 'cpe', 'port', 'float', 'hex', 'phone-number', 'boolean', 'anonymised', 'pgp-public-key', 'pgp-private-key')
            )
        );
    }

    /**
     * Generate just when really need
     * NOTE WHEN MODIFYING: please ensure to run the script 'tools/gen_misp_types_categories.py' to update the new definitions everywhere. (docu, website, RFC, ... )
     * @return array[]
     */
    private function generateTypeDefinitions()
    {
        return array(
            'md5' => array('desc' => __('A checksum in md5 format'), 'formdesc' => __("You are encouraged to use filename|md5 instead. A checksum in md5 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha1' => array('desc' => __('A checksum in sha1 format'), 'formdesc' => __("You are encouraged to use filename|sha1 instead. A checksum in sha1 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha256' => array('desc' => __('A checksum in sha256 format'), 'formdesc' => __("You are encouraged to use filename|sha256 instead. A checksum in sha256 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename' => array('desc' => __('Filename'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'pdb' => array('desc' => __('Microsoft Program database (PDB) path information'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'filename|md5' => array('desc' => __('A filename and an md5 hash separated by a |'), 'formdesc' => __("A filename and an md5 hash separated by a | (no spaces)"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha1' => array('desc' => __('A filename and an sha1 hash separated by a |'), 'formdesc' => __("A filename and an sha1 hash separated by a | (no spaces)"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha256' => array('desc' => __('A filename and an sha256 hash separated by a |'), 'formdesc' => __("A filename and an sha256 hash separated by a | (no spaces)"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'ip-src' => array('desc' => __("A source IP address of the attacker"), 'default_category' => 'Network activity', 'to_ids' => 1),
            'ip-dst' => array('desc' => __('A destination IP address of the attacker or C&C server'), 'formdesc' => __("A destination IP address of the attacker or C&C server. Also set the IDS flag on when this IP is hardcoded in malware"), 'default_category' => 'Network activity', 'to_ids' => 1),
            'hostname' => array('desc' => __('A full host/dnsname of an attacker'), 'formdesc' => __("A full host/dnsname of an attacker. Also set the IDS flag on when this hostname is hardcoded in malware"), 'default_category' => 'Network activity', 'to_ids' => 1),
            'domain' => array('desc' => __('A domain name used in the malware'), 'formdesc' => __("A domain name used in the malware. Use this instead of hostname when the upper domain is important or can be used to create links between events."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'domain|ip' => array('desc' => __('A domain name and its IP address (as found in DNS lookup) separated by a |'),'formdesc' => __("A domain name and its IP address (as found in DNS lookup) separated by a | (no spaces)"), 'default_category' => 'Network activity', 'to_ids' => 1),
            'email' => array('desc' => ('An e-mail address'), 'default_category' => 'Social network', 'to_ids' => 1),
            'email-src' => array('desc' => __("The source email address. Used to describe the sender when describing an e-mail."), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'eppn' => array('desc' => __("eduPersonPrincipalName - eppn - the NetId of the person for the purposes of inter-institutional authentication. Should be stored in the form of user@univ.edu, where univ.edu is the name of the local security domain."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'email-dst' => array('desc' => __("The destination email address. Used to describe the recipient when describing an e-mail."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'email-subject' => array('desc' => __("The subject of the email"), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-attachment' => array('desc' => __("File name of the email attachment."), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'email-body' => array('desc' => __('Email body'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'float' => array('desc' => __("A floating point value."), 'default_category' => 'Other', 'to_ids' => 0),
            'git-commit-id' => array('desc' => __("A git commit ID."), 'default_category' => 'Internal reference', 'to_ids' => 0),
            'url' => array('desc' => __('url'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'http-method' => array('desc' => __("HTTP method used by the malware (e.g. POST, GET, ...)."), 'default_category' => 'Network activity', 'to_ids' => 0),
            'user-agent' => array('desc' => __("The user-agent used by the malware in the HTTP request."), 'default_category' => 'Network activity', 'to_ids' => 0),
            'ja3-fingerprint-md5' => array('desc' => __("JA3 is a method for creating SSL/TLS client fingerprints that should be easy to produce on any platform and can be easily shared for threat intelligence."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'jarm-fingerprint' => array('desc' => __("JARM is a method for creating SSL/TLS server fingerprints."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'favicon-mmh3' => array('desc' => __("favicon-mmh3 is the murmur3 hash of a favicon as used in Shodan."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'hassh-md5' => array('desc' => __("hassh is a network fingerprinting standard which can be used to identify specific Client SSH implementations. The fingerprints can be easily stored, searched and shared in the form of an MD5 fingerprint."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'hasshserver-md5' => array('desc' => __("hasshServer is a network fingerprinting standard which can be used to identify specific Server SSH implementations. The fingerprints can be easily stored, searched and shared in the form of an MD5 fingerprint."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'regkey' => array('desc' => __("Registry key or value"), 'default_category' => 'Persistence mechanism', 'to_ids' => 1),
            'regkey|value' => array('desc' => __("Registry value + data separated by |"), 'default_category' => 'Persistence mechanism', 'to_ids' => 1),
            'AS' => array('desc' => __('Autonomous system'), 'default_category' => 'Network activity', 'to_ids' => 0),
            'snort' => array('desc' => __('An IDS rule in Snort rule-format'), 'formdesc' => __("An IDS rule in Snort rule-format. This rule will be automatically rewritten in the NIDS exports."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'bro' => array('desc' => __('An NIDS rule in the Bro rule-format'), 'formdesc' => __("An NIDS rule in the Bro rule-format."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'zeek' => array('desc' => __('An NIDS rule in the Zeek rule-format'), 'formdesc' => __("An NIDS rule in the Zeek rule-format."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'community-id' => array('desc' => __('a community ID flow hashing algorithm to map multiple traffic monitors into common flow id'), 'formdesc' => __("a community ID flow hashing algorithm to map multiple traffic monitors into common flow id"), 'default_category' => 'Network activity', 'to_ids' => 1),
            'pattern-in-file' => array('desc' => __('Pattern in file that identifies the malware'), 'default_category' => 'Payload installation', 'to_ids' => 1),
            'pattern-in-traffic' => array('desc' => __('Pattern in network traffic that identifies the malware'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'pattern-in-memory' => array('desc' => __('Pattern in memory dump that identifies the malware'), 'default_category' => 'Payload installation', 'to_ids' => 1),
            'pattern-filename' => array('desc' => __('A pattern in the name of a file'), 'default_category' => 'Payload installation', 'to_ids' => 1),
            'pgp-public-key' => array('desc' => __('A PGP public key'), 'default_category' => 'Person', 'to_ids' => 0),
            'pgp-private-key' => array('desc' => __('A PGP private key'), 'default_category' => 'Person', 'to_ids' => 0),
            'yara' => array('desc' => __('Yara signature'), 'default_category' => 'Payload installation', 'to_ids' => 1),
            'stix2-pattern' => array('desc' => __('STIX 2 pattern'), 'default_category' => 'Payload installation', 'to_ids' => 1),
            'sigma' => array('desc' => __('Sigma - Generic Signature Format for SIEM Systems'), 'default_category' => 'Payload installation', 'to_ids' => 1),
            'gene' => array('desc' => __('GENE - Go Evtx sigNature Engine'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'kusto-query' => array('desc' => __('Kusto query - Kusto from Microsoft Azure is a service for storing and running interactive analytics over Big Data.'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'mime-type' => array('desc' => __('A media type (also MIME type and content type) is a two-part identifier for file formats and format contents transmitted on the Internet'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'identity-card-number' => array('desc' => __('Identity card number'), 'default_category' => 'Person', 'to_ids' => 0),
            'cookie' => array('desc' => __('HTTP cookie as often stored on the user web client. This can include authentication cookie or session cookie.'), 'default_category' => 'Network activity', 'to_ids' => 0),
            'vulnerability' => array('desc' => __('A reference to the vulnerability used in the exploit'), 'default_category' => 'External analysis', 'to_ids' => 0),
            'cpe' => array('desc' => __('Common Platform Enumeration - structured naming scheme for information technology systems, software, and packages.'), 'default_category' => 'External analysis', 'to_ids' => 0),
            'weakness' => array('desc'=> __('A reference to the weakness used in the exploit'), 'default_category' => 'External analysis', 'to_ids' => 0),
            'attachment' => array('desc' => __('Attachment with external information'), 'formdesc' => __("Please upload files using the <em>Upload Attachment</em> button."), 'default_category' => 'External analysis', 'to_ids' => 0),
            'malware-sample' => array('desc' => __('Attachment containing encrypted malware sample'), 'formdesc' => __("Please upload files using the <em>Upload Attachment</em> button."), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'link' => array('desc' => __('Link to an external information'), 'default_category' => 'External analysis', 'to_ids' => 0),
            'comment' => array('desc' => __('Comment or description in a human language'), 'formdesc' => __('Comment or description in a human language.  This will not be correlated with other attributes'), 'default_category' => 'Other', 'to_ids' => 0),
            'text' => array('desc' => __('Name, ID or a reference'), 'default_category' => 'Other', 'to_ids' => 0),
            'hex' => array('desc' => __('A value in hexadecimal format'), 'default_category' => 'Other', 'to_ids' => 0),
            'other' => array('desc' => __('Other attribute'), 'default_category' => 'Other', 'to_ids' => 0),
            'named pipe' => array('desc' => __('Named pipe, use the format \\.\pipe\<PipeName>'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'mutex' => array('desc' => __('Mutex, use the format \BaseNamedObjects\<Mutex>'), 'default_category' => 'Artifacts dropped', 'to_ids' => 1),
            'process-state' => array('desc' => __('State of a process'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'target-user' => array('desc' => __('Attack Targets Username(s)'), 'default_category' => 'Targeting data', 'to_ids' => 0),
            'target-email' => array('desc' => __('Attack Targets Email(s)'), 'default_category' => 'Targeting data', 'to_ids' => 0),
            'target-machine' => array('desc' => __('Attack Targets Machine Name(s)'), 'default_category' => 'Targeting data', 'to_ids' => 0),
            'target-org' => array('desc' => __('Attack Targets Department or Organization(s)'), 'default_category' => 'Targeting data', 'to_ids' => 0),
            'target-location' => array('desc' => __('Attack Targets Physical Location(s)'), 'default_category' => 'Targeting data', 'to_ids' => 0),
            'target-external' => array('desc' => __('External Target Organizations Affected by this Attack'), 'default_category' => 'Targeting data', 'to_ids' => 0),
            'btc' => array('desc' => __('Bitcoin Address'), 'default_category' => 'Financial fraud', 'to_ids' => 1),
            'dash' => array('desc' => __('Dash Address'), 'default_category' => 'Financial fraud', 'to_ids' => 1),
            'xmr' => array('desc' => __('Monero Address'), 'default_category' => 'Financial fraud', 'to_ids' => 1),
            'iban' => array('desc' => __('International Bank Account Number'), 'default_category' => 'Financial fraud', 'to_ids' => 1),
            'bic' => array('desc' => __('Bank Identifier Code Number also known as SWIFT-BIC, SWIFT code or ISO 9362 code'), 'default_category' => 'Financial fraud', 'to_ids' => 1),
            'bank-account-nr' => array('desc' => __('Bank account number without any routing number'), 'default_category' => 'Financial fraud', 'to_ids' => 1),
            'aba-rtn' => array('desc' => __('ABA routing transit number'), 'default_category' => 'Financial fraud', 'to_ids' => 1),
            'bin' => array('desc' => __('Bank Identification Number'), 'default_category' => 'Financial fraud', 'to_ids' => 1),
            'cc-number' => array('desc' => __('Credit-Card Number'), 'default_category' => 'Financial fraud', 'to_ids' => 1),
            'prtn' => array('desc' => __('Premium-Rate Telephone Number'), 'default_category' => 'Financial fraud', 'to_ids' => 1),
            'phone-number' => array('desc' => __('Telephone Number'), 'default_category' => 'Person', 'to_ids' => 0),
            'threat-actor' => array('desc' => __('A string identifying the threat actor'), 'default_category' => 'Attribution', 'to_ids' => 0),
            'campaign-name' => array('desc' => __('Associated campaign name'), 'default_category' => 'Attribution', 'to_ids' => 0),
            'campaign-id' => array('desc' => __('Associated campaign ID'), 'default_category' => 'Attribution', 'to_ids' => 0),
            'malware-type' => array('desc' => '', 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'uri' => array('desc' => __('Uniform Resource Identifier'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'authentihash' => array('desc' => __('Authenticode executable signature hash'), 'formdesc' => __("You are encouraged to use filename|authentihash instead. Authenticode executable signature hash, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'vhash' => array('desc' => __('A VirusTotal checksum'), 'formdesc' => __("You are encouraged to use filename|vhash instead. A checksum from VirusTotal, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'ssdeep' => array('desc' => __('A checksum in ssdeep format'), 'formdesc' => __("You are encouraged to use filename|ssdeep instead. A checksum in the SSDeep format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'imphash' => array('desc' => __('Import hash - a hash created based on the imports in the sample.'), 'formdesc' => __("You are encouraged to use filename|imphash instead. A hash created based on the imports in the sample, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'telfhash' => array('desc' => __('telfhash is symbol hash for ELF files, just like imphash is imports hash for PE files.'), 'formdesc' => __("You are encouraged to use a file object with telfash"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'pehash' => array('desc' => __('PEhash - a hash calculated based of certain pieces of a PE executable file'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'impfuzzy' => array('desc' => __('A fuzzy hash of import table of Portable Executable format'), 'formdesc' => __("You are encouraged to use filename|impfuzzy instead. A fuzzy hash created based on the imports in the sample, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha224' => array('desc' => __('A checksum in sha-224 format'), 'formdesc' => __("You are encouraged to use filename|sha224 instead. A checksum in sha224 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha384' => array('desc' => __('A checksum in sha-384 format'), 'formdesc' => __("You are encouraged to use filename|sha384 instead. A checksum in sha384 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha512' => array('desc' => __('A checksum in sha-512 format'), 'formdesc' => __("You are encouraged to use filename|sha512 instead. A checksum in sha512 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha512/224' => array('desc' => __('A checksum in the sha-512/224 format'), 'formdesc' => __("You are encouraged to use filename|sha512/224 instead. A checksum in sha512/224 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha512/256' => array('desc' => __('A checksum in the sha-512/256 format'), 'formdesc' => __("You are encouraged to use filename|sha512/256 instead. A checksum in sha512/256 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha3-224' => array('desc' => __('A checksum in sha3-224 format'), 'formdesc' => __("You are encouraged to use filename|sha3-224 instead. A checksum in sha3-224 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha3-256' => array('desc' => __('A checksum in sha3-256 format'), 'formdesc' => __("You are encouraged to use filename|sha3-256 instead. A checksum in sha3-256 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha3-384' => array('desc' => __('A checksum in sha3-384 format'), 'formdesc' => __("You are encouraged to use filename|sha3-384 instead. A checksum in sha3-384 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha3-512' => array('desc' => __('A checksum in sha3-512 format'), 'formdesc' => __("You are encouraged to use filename|sha3-512 instead. A checksum in sha3-512 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'tlsh' => array('desc' => __('A checksum in the Trend Micro Locality Sensitive Hash format'), 'formdesc' => __("You are encouraged to use filename|tlsh instead. A checksum in the Trend Micro Locality Sensitive Hash format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'cdhash' => array('desc' => __('An Apple Code Directory Hash, identifying a code-signed Mach-O executable file'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|authentihash' => array('desc' => __('A checksum in md5 format'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|vhash' => array('desc' => __('A filename and a VirusTotal hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|ssdeep' => array('desc' => __('A checksum in ssdeep format'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|imphash' => array('desc' => __('Import hash - a hash created based on the imports in the sample.'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|impfuzzy' => array('desc' => __('Import fuzzy hash - a fuzzy hash created based on the imports in the sample.'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|pehash' => array('desc' => __('A filename and a PEhash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha224' => array('desc' => __('A filename and a sha-224 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha384' => array('desc' => __('A filename and a sha-384 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha512' => array('desc' => __('A filename and a sha-512 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha512/224' => array('desc' => __('A filename and a sha-512/224 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha512/256' => array('desc' => __('A filename and a sha-512/256 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha3-224' => array('desc' => __('A filename and an sha3-224 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha3-256' => array('desc' => __('A filename and an sha3-256 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha3-384' => array('desc' => __('A filename and an sha3-384 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha3-512' => array('desc' => __('A filename and an sha3-512 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|tlsh' => array('desc' => __('A filename and a Trend Micro Locality Sensitive Hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'windows-scheduled-task' => array('desc' => __('A scheduled task in windows'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'windows-service-name' => array('desc' => __('A windows service name. This is the name used internally by windows. Not to be confused with the windows-service-displayname.'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'windows-service-displayname' => array('desc' => __('A windows service\'s displayname, not to be confused with the windows-service-name. This is the name that applications will generally display as the service\'s name in applications.'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'whois-registrant-email' => array('desc' => __('The e-mail of a domain\'s registrant, obtained from the WHOIS information.'), 'default_category' => 'Attribution', 'to_ids' => 0),
            'whois-registrant-phone' => array('desc' => __('The phone number of a domain\'s registrant, obtained from the WHOIS information.'), 'default_category' => 'Attribution', 'to_ids' => 0),
            'whois-registrant-name' => array('desc' => __('The name of a domain\'s registrant, obtained from the WHOIS information.'), 'default_category' => 'Attribution', 'to_ids' => 0),
            'whois-registrant-org' => array('desc' => __('The org of a domain\'s registrant, obtained from the WHOIS information.'), 'default_category' => 'Attribution', 'to_ids' => 0),
            'whois-registrar' => array('desc' => __('The registrar of the domain, obtained from the WHOIS information.'), 'default_category' => 'Attribution', 'to_ids' => 0),
            'whois-creation-date' => array('desc' => __('The date of domain\'s creation, obtained from the WHOIS information.'), 'default_category' => 'Attribution', 'to_ids' => 0),
            // 'targeted-threat-index' => array('desc' => ''), // currently not mapped!
            // 'mailslot' => array('desc' => 'MailSlot interprocess communication'), // currently not mapped!
            // 'pipe' => array('desc' => 'Pipeline (for named pipes use the attribute type "named pipe")'), // currently not mapped!
            // 'ssl-cert-attributes' => array('desc' => 'SSL certificate attributes'), // currently not mapped!
            'x509-fingerprint-sha1' => array('desc' => __('X509 fingerprint in SHA-1 format'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'x509-fingerprint-md5' => array('desc' => __('X509 fingerprint in MD5 format'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'x509-fingerprint-sha256' => array('desc' => __('X509 fingerprint in SHA-256 format'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'dns-soa-email' => array('desc' => __('RFC1035 mandates that DNS zones should have a SOA (Statement Of Authority) record that contains an email address where a PoC for the domain could be contacted. This can sometimes be used for attribution/linkage between different domains even if protected by whois privacy'), 'default_category' => 'Attribution', 'to_ids' => 0),
            'size-in-bytes' => array('desc' => __('Size expressed in bytes'), 'default_category' => 'Other', 'to_ids' => 0),
            'counter' => array('desc' => __('An integer counter, generally to be used in objects'), 'default_category' => 'Other', 'to_ids' => 0),
            'datetime' => array('desc' => __('Datetime in the ISO 8601 format'), 'default_category' => 'Other', 'to_ids' => 0),
            'port' => array('desc' => __('Port number'), 'default_category' => 'Network activity', 'to_ids' => 0),
            'ip-dst|port' => array('desc' => __('IP destination and port number separated by a |'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'ip-src|port' => array('desc' => __('IP source and port number separated by a |'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'hostname|port' => array('desc' => __('Hostname and port number separated by a |'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'mac-address' => array('desc' => __('Mac address'), 'default_category' => 'Network activity', 'to_ids' => 0),
            'mac-eui-64' => array('desc' => __('Mac EUI-64 address'), 'default_category' => 'Network activity', 'to_ids' => 0),
            // verify IDS flag defaults for these
            'email-dst-display-name' => array('desc' => __('Email destination display name'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-src-display-name' => array('desc' => __('Email source display name'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-header' => array('desc' => __('Email header'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-reply-to' => array('desc' => __('Email reply to header'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-x-mailer' => array('desc' => __('Email x-mailer header'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-mime-boundary' => array('desc' => __('The email mime boundary separating parts in a multipart email'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-thread-index' => array('desc' => __('The email thread index header'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-message-id' => array('desc' => __('The email message ID'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'github-username' => array('desc' => __('A github user name'), 'default_category' => 'Social network', 'to_ids' => 0),
            'github-repository' => array('desc' => __('A github repository'), 'default_category' => 'Social network', 'to_ids' => 0),
            'github-organisation' => array('desc' => __('A github organisation'), 'default_category' => 'Social network', 'to_ids' => 0),
            'jabber-id' => array('desc' => __('Jabber ID'), 'default_category' => 'Social network', 'to_ids' => 0),
            'twitter-id' => array('desc' => __('Twitter ID'), 'default_category' => 'Social network', 'to_ids' => 0),
            'dkim' => array('desc' => __('DKIM public key'), 'default_category' => 'Network activity', 'to_ids' => 0),
            'dkim-signature'=> array('desc' => __('DKIM signature'), 'default_category' => 'Network activity', 'to_ids' => 0),
            'first-name' => array('desc' => __('First name of a natural person'), 'default_category' => 'Person', 'to_ids' => 0),
            'middle-name' => array('desc' => __('Middle name of a natural person'), 'default_category' => 'Person', 'to_ids' => 0),
            'last-name' => array('desc' => __('Last name of a natural person'), 'default_category' => 'Person', 'to_ids' => 0),
            'full-name' => array('desc' => __('Full name of a natural person'), 'default_category' => 'Person', 'to_ids' => 0),
            'date-of-birth' => array('desc' => __('Date of birth of a natural person (in YYYY-MM-DD format)'), 'default_category' => 'Person', 'to_ids' => 0),
            'place-of-birth' => array('desc' => __('Place of birth of a natural person'), 'default_category' => 'Person', 'to_ids' => 0),
            'gender' => array('desc' => __('The gender of a natural person (Male, Female, Other, Prefer not to say)'), 'default_category' => 'Person', 'to_ids' => 0),
            'passport-number' => array('desc' => __('The passport number of a natural person'), 'default_category' => 'Person', 'to_ids' => 0),
            'passport-country' => array('desc' => __('The country in which the passport was issued'), 'default_category' => 'Person', 'to_ids' => 0),
            'passport-expiration' => array('desc' => __('The expiration date of a passport'), 'default_category' => 'Person', 'to_ids' => 0),
            'redress-number' => array('desc' => __('The Redress Control Number is the record identifier for people who apply for redress through the DHS Travel Redress Inquiry Program (DHS TRIP). DHS TRIP is for travelers who have been repeatedly identified for additional screening and who want to file an inquiry to have erroneous information corrected in DHS systems'), 'default_category' => 'Person', 'to_ids' => 0),
            'nationality' => array('desc' => __('The nationality of a natural person'), 'default_category' => 'Person', 'to_ids' => 0),
            'visa-number' => array('desc' => __('Visa number'), 'default_category' => 'Person', 'to_ids' => 0),
            'issue-date-of-the-visa' => array('desc' => __('The date on which the visa was issued'), 'default_category' => 'Person', 'to_ids' => 0),
            'primary-residence' => array('desc' => __('The primary residence of a natural person'), 'default_category' => 'Person', 'to_ids' => 0),
            'country-of-residence' => array('desc' => __('The country of residence of a natural person'), 'default_category' => 'Person', 'to_ids' => 0),
            'special-service-request' => array('desc' => __('A Special Service Request is a function to an airline to provide a particular facility for A Passenger or passengers. '), 'default_category' => 'Person', 'to_ids' => 0),
            'frequent-flyer-number' => array('desc' => __('The frequent flyer number of a passenger'), 'default_category' => 'Person', 'to_ids' => 0),
            // Do we really need remarks? Or just use comment/text for this?
            //'remarks' => array('desc' => '', 'default_category' => 'Person', 'to_ids' => 0),
            'travel-details' => array('desc' => __('Travel details'), 'default_category' => 'Person', 'to_ids' => 0),
            'payment-details' => array('desc' => __('Payment details'), 'default_category' => 'Person', 'to_ids' => 0),
            'place-port-of-original-embarkation' => array('desc' => __('The original port of embarkation'), 'default_category' => 'Person', 'to_ids' => 0),
            'place-port-of-clearance' => array('desc' => __('The port of clearance'), 'default_category' => 'Person', 'to_ids' => 0),
            'place-port-of-onward-foreign-destination' => array('desc' => __('A Port where the passenger is transiting to'), 'default_category' => 'Person', 'to_ids' => 0),
            'passenger-name-record-locator-number' => array('desc' => __('The Passenger Name Record Locator is a key under which the reservation for a trip is stored in the system. The PNR contains, among other data, the name, flight segments and address of the passenger. It is defined by a combination of five or six letters and numbers.'), 'default_category' => 'Person', 'to_ids' => 0),
            'mobile-application-id' => array('desc' => __('The application id of a mobile application'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'chrome-extension-id' => array('desc' => __('Chrome extension id'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'cortex' => array('desc' => __('Cortex analysis result'), 'default_category' => 'External analysis', 'to_ids' => 0),
            'boolean' => array('desc' => __('Boolean value - to be used in objects'), 'default_category' => 'Other', 'to_ids' => 0),
            'anonymised' => array('desc' => __('Anonymised value - described with the anonymisation object via a relationship'),  'formdesc' => __('Anonymised value - described with the anonymisation object via a relationship.'), 'default_category' => 'Other', 'to_ids' => 0)
            // Not convinced about this.
            //'url-regex' => array('desc' => '', 'default_category' => 'Person', 'to_ids' => 0),
        );
    }
}
