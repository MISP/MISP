<?php

App::uses('AppModel', 'Model');
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');
App::uses('FinancialTool', 'Tools');
App::uses('RandomTool', 'Tools');
App::uses('AttachmentTool', 'Tools');
App::uses('TmpFileTool', 'Tools');
App::uses('ComplexTypeTool', 'Tools');
App::uses('AttributeValidationTool', 'Tools');
App::uses('JsonTool', 'Tools');

/**
 * @property Event $Event
 * @property AttributeTag $AttributeTag
 * @property Sighting $Sighting
 * @property MispObject $Object
 * @property SharingGroup $SharingGroup
 * @property Correlation $Correlation
 * @property-read array $typeDefinitions
 * @property-read array $categoryDefinitions
 */
class Attribute extends AppModel
{
    public $combinedKeys = array('event_id', 'category', 'type');

    public $name = 'Attribute';

    public $actsAs = array(
        'AuditLog',
        'SysLogLogable.SysLogLogable' => array( // TODO Audit, logable
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'full'),
        'Trim',
        'Containable',
        'Regexp' => array('fields' => array('value')),
        'LightPaginator',
        'AnalystDataParent',
    );

    public $displayField = 'value';

    public $virtualFields = array(
            'value' => "CASE WHEN Attribute.value2 = '' THEN Attribute.value1 ELSE CONCAT(Attribute.value1, '|', Attribute.value2) END",
    );

    // explanations of certain fields to be used in various views
    public $fieldDescriptions = array(
            'signature' => array('desc' => 'Is this attribute eligible to automatically create an IDS signature (network IDS or host IDS) out of it ?'),
            'distribution' => array('desc' => 'Describes who will have access to the attribute.')
    );

    const EDITABLE_FIELDS = [
        'timestamp',
        'category',
        'type',
        'value',
        'value1',
        'value2',
        'to_ids',
        'comment',
        'distribution',
        'sharing_group_id',
        'deleted',
        'disable_correlation',
        'first_seen',
        'last_seen',
    ];

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

    /** @var array */
    private $old;

    private $updateLookupTable = [];

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
    const ZIPPED_DEFINITION = ['malware-sample'];

    // if these then a category may have upload
    const UPLOAD_DEFINITIONS = ['attachment'];

    // skip Correlation for the following types
    const NON_CORRELATING_TYPES = [
        'comment',
        'http-method',
        'aba-rtn',
        'gender',
        'counter',
        'integer',
        'float',
        'port',
        'nationality',
        'cortex',
        'boolean',
        'anonymised'
    ];

    const PRIMARY_ONLY_CORRELATING_TYPES = array(
        'ip-src|port',
        'ip-dst|port',
        'hostname|port',
    );

    const CAPTURE_FIELDS = array(
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

    public $validFormats = array(
        'attack-sightings' => array('json', 'AttackSightingsExport', 'json'),
        'cache' => array('txt', 'CacheExport', 'cache'),
        'count' => array('txt', 'CountExport', 'txt'),
        'csv' => array('csv', 'CsvExport', 'csv'),
        'hashes' => array('txt', 'HashesExport', 'txt'),
        'hosts' => array('txt', 'HostsExport', 'txt'),
        'json' => array('json', 'JsonExport', 'json'),
        'netfilter' => array('txt', 'NetfilterExport', 'sh'),
        'opendata' => array('txt', 'OpendataExport', 'txt'),
        'openioc' => array('xml', 'OpeniocExport', 'ioc'),
        'rpz' => array('txt', 'RPZExport', 'rpz'),
        'snort' => array('txt', 'NidsSnortExport', 'rules'),
        'stix' => array('xml', 'Stix1Export', 'xml'),
        'stix-json' => array('json', 'Stix1Export', 'json'),
        'stix2' => array('json', 'Stix2Export', 'json'),
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
    const TYPE_GROUPINGS = [
        'file' => ['attachment', 'pattern-in-file', 'filename-pattern', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'ssdeep', 'imphash', 'telfhash', 'impfuzzy', 'authentihash', 'vhash', 'pehash', 'tlsh', 'cdhash', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|sha3-224', 'filename|sha3-256', 'filename|sha3-384', 'filename|sha3-512', 'filename|authentihash', 'filename|vhash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash', 'filename|pehash', 'malware-sample', 'x509-fingerprint-sha1', 'x509-fingerprint-sha256', 'x509-fingerprint-md5'],
        'network' => ['ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port', 'mac-address', 'mac-eui-64', 'hostname', 'hostname|port', 'domain', 'domain|ip', 'email-dst', 'url', 'uri', 'user-agent', 'http-method', 'AS', 'snort', 'bro', 'zeek',  'pattern-in-traffic', 'x509-fingerprint-md5', 'x509-fingerprint-sha1', 'x509-fingerprint-sha256','ja3-fingerprint-md5', 'jarm-fingerprint', 'favicon-mmh3', 'hassh-md5', 'hasshserver-md5', 'community-id'],
        'financial' => ['btc', 'xmr', 'iban', 'bic', 'bank-account-nr', 'aba-rtn', 'bin', 'cc-number', 'prtn', 'phone-number']
    ];

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
                'on' => 'create'
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

    const FILE_HASH_TYPES = array(
        'md5' => 32,
        'sha1' => 40,
        'sha256' => 64,
        'sha512' => 128,
    );

    public $fast_update = false;

    public function afterFind($results, $primary = false)
    {
        foreach ($results as &$v) {
            $attribute = &$v['Attribute'];
            if (!empty($attribute['first_seen'])) {
                $attribute['first_seen'] = $this->microTimestampToIso($attribute['first_seen']);
            }
            if (!empty($attribute['last_seen'])) {
                $attribute['last_seen'] = $this->microTimestampToIso($attribute['last_seen']);
            }
        }
        return $results;
    }

    public function beforeSave($options = array())
    {
        $attribute = &$this->data['Attribute'];
        if (empty($attribute['uuid'])) {
            $attribute['uuid'] = CakeText::uuid();
        }
        if (!$this->fast_update && !empty($attribute['id'])) {
            $this->old = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('Attribute.id' => $attribute['id']),
                'fields' => ['value', 'disable_correlation', 'type', 'distribution', 'sharing_group_id'],
            ));
        } else {
            $this->old = null;
        }
        // explode value of composite type in value1 and value2
        // or copy value to value1 if not composite type
        if (!empty($attribute['type'])) {
            // explode composite types in value1 and value2
            if (in_array($attribute['type'], $this->getCompositeTypes(), true)) {
                $pieces = explode('|', $attribute['value']);
                if (2 !== count($pieces)) {
                    throw new InternalErrorException(__('Composite type, but value not explodable'));
                }
                $attribute['value1'] = $pieces[0];
                $attribute['value2'] = $pieces[1];
            } else {
                $attribute['value1'] = $attribute['value'];
                $attribute['value2'] = '';
            }
        }

        $this->data = $this->ISODatetimeToUTC($this->data, $this->alias);
        // always return true after a beforeSave()
        return true;
    }

    /**
     * Append extension to filename if no extension provided. This is typical for attachments imported from STIX file.
     * @param array $attribute
     * @return void
     */
    private function checkAttachmentExtension(array &$attribute)
    {
        if (pathinfo($attribute['value'], PATHINFO_EXTENSION) !== '' || empty($attribute['data_raw'])) {
            return;
        }

        if (!class_exists('finfo')) {
            return;
        }

        $finfo = new finfo(FILEINFO_EXTENSION);
        $extension = explode('/', $finfo->buffer($attribute['data_raw']))[0];

        // Append recognized extension, that are considered as safe
        if (in_array($extension, ['png', 'jpeg', 'zip', 'gif', 'webp'], true)) {
            $attribute['value'] = rtrim($attribute['value'], '.') . $extension;
        }
    }

    /**
     * @param int $event_id
     * @param bool $increment True for increment, false for decrement,
     * @return bool
     */
    private function __alterAttributeCount($event_id, $increment = true)
    {
        // Temporary unbind models that we don't need to prevent deadlocks
        $this->Event->unbindModel([
            'belongsTo' => array_keys($this->Event->belongsTo),
        ]);
        try {
            return $this->Event->updateAll(
                array('Event.attribute_count' => $increment ? 'Event.attribute_count+1' : 'GREATEST(Event.attribute_count, 1) - 1'),
                array('Event.id' => $event_id)
            );
        } catch (Exception $e) {
            $this->logException('Exception when updating event attribute count', $e);
            return false;
        } finally {
            $this->Event->resetAssociations();
        }
    }

    public function afterSave($created, $options = array())
    {
        // Passing event in `parentEvent` field will speed up correlation
        $passedEvent = $options['parentEvent'] ?? false;

        $attribute = $this->data['Attribute'];

        // add attributeTags via the shorthand ID list
        if (!empty($attribute['tag_ids'])) {
            foreach ($attribute['tag_ids'] as $tagId) {
                $this->AttributeTag->attachTagToAttribute($this->id, $attribute['event_id'], $tagId);
            }
        }
        // Let's store all the uuid -> ID lookups so we can extract the IDs after a SaveMany() easily
        $this->updateLookupTable[$attribute['uuid']] = $attribute['id'];
        if (!$this->fast_update) {
            // update correlation...
            if (isset($attribute['deleted']) && $attribute['deleted']) {
                $this->Correlation->beforeSaveCorrelation($attribute);
                $this->Correlation->advancedCorrelationsUpdate($attribute);
                if (isset($attribute['event_id'])) {
                    $this->__alterAttributeCount($attribute['event_id'], false);
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
                        $attribute['value'] != $this->old['Attribute']['value'] ||
                        $attribute['disable_correlation'] != $this->old['Attribute']['disable_correlation'] ||
                        $attribute['type'] != $this->old['Attribute']['type'] ||
                        $attribute['distribution'] != $this->old['Attribute']['distribution'] ||
                        $attribute['sharing_group_id'] != $this->old['Attribute']['sharing_group_id']
                    ) {
                        $this->Correlation->beforeSaveCorrelation($attribute);
                        $this->Correlation->afterSaveCorrelation($attribute, false, $passedEvent);
                        $this->Correlation->advancedCorrelationsUpdate($attribute);
                    }
                } else {
                    $this->Correlation->afterSaveCorrelation($attribute, false, $passedEvent);
                    $this->Correlation->advancedCorrelationsUpdate($attribute);
                }
            }
        }
        $result = true;
        // if the 'data' field is set on the $attribute then save the data to the correct file
        if (isset($attribute['type']) && $this->typeIsAttachment($attribute['type'])) {
            if (isset($attribute['data_raw'])) {
                $attribute['data'] = $attribute['data_raw'];
                unset($attribute['data_raw']);
                $result = $this->saveAttachment($attribute);
            } elseif (isset($attribute['data'])) {
                $attribute['data'] = base64_decode($attribute['data']);
                $result = $this->saveAttachment($attribute);
            }
        }
        if (!$this->fast_update) {
            $pubToZmq = $this->pubToZmq('attribute');
            $kafkaTopic = $this->kafkaTopic('attribute');
            $isTriggerCallable = $this->isTriggerCallable('attribute-after-save');
            if ($pubToZmq || $kafkaTopic || $isTriggerCallable) {
                $attributeForPublish = $this->fetchAttribute($this->id);
                if (!empty($attributeForPublish)) {
                    $user = array(
                        'org_id' => -1,
                        'Role' => array(
                            'perm_site_admin' => 1
                        )
                    );
                    $attributeForPublish['Attribute']['Sighting'] = $this->Sighting->attachToEvent($attributeForPublish, $user, $attributeForPublish);
                    $action = $created ? 'add' : 'edit';
                    if (!empty($attribute['deleted'])) {
                        $action = 'soft-delete';
                    }
                    if ($pubToZmq) {
                        if (Configure::read('Plugin.ZeroMQ_include_attachments') && $this->typeIsAttachment($attributeForPublish['Attribute']['type'])) {
                            $attributeForPublish['Attribute']['data'] = $this->base64EncodeAttachment($attributeForPublish['Attribute']);
                        }
                        $pubSubTool = $this->getPubSubTool();
                        $pubSubTool->attribute_save($attributeForPublish, $action);
                        unset($attributeForPublish['Attribute']['data']);
                    }
                    if ($kafkaTopic) {
                        if (Configure::read('Plugin.Kafka_include_attachments') && $this->typeIsAttachment($attributeForPublish['Attribute']['type'])) {
                            $attributeForPublish['Attribute']['data'] = $this->base64EncodeAttachment($attributeForPublish['Attribute']);
                        }
                        $kafkaPubTool = $this->getKafkaPubTool();
                        $kafkaPubTool->publishJson($kafkaTopic, $attributeForPublish, $action);
                    }
                    if ($isTriggerCallable) {
                        $workflowErrors = [];
                        $logging = [
                            'model' => 'Attribute',
                            'action' => $action,
                            'id' => $attributeForPublish['Attribute']['id'],
                        ];
                        $triggerData = $attributeForPublish;
                        $this->executeTrigger('attribute-after-save', $triggerData, $workflowErrors, $logging);
                    }
                }
            }
        }
        if ($created && isset($attribute['event_id']) && empty($attribute['skip_auto_increment'])) {
            $this->__alterAttributeCount($attribute['event_id']);
        }
        return $result;
    }

    /**
     * This method is called after all data are successfully saved into database
     * @return void
     * @throws Exception
     */
    private function afterDatabaseSave(array $data)
    {
        $attribute = $data['Attribute'];
        if (isset($attribute['type']) && $this->typeIsAttachment($attribute['type'])) {
            $this->loadAttachmentScan()->backgroundScan(AttachmentScan::TYPE_ATTRIBUTE, $attribute);
        }
    }

    public function save($data = null, $validate = true, $fieldList = array())
    {
        $result = parent::save($data, $validate, $fieldList);
        if ($result) {
            $this->afterDatabaseSave($result);
        }
        return $result;
    }

    public function beforeDelete($cascade = true)
    {
        // delete attachments from the disk
        $attribute = $this->find('first', [
            'recursive' => -1,
            'conditions' => [
                'id' => $this->id,
            ]
        ]);
        if ($this->typeIsAttachment($attribute['Attribute']['type'])) {
            $this->loadAttachmentTool()->delete($attribute['Attribute']['event_id'], $attribute['Attribute']['id']);
        }
        // update correlation..
        $this->Correlation->beforeSaveCorrelation($attribute['Attribute']);

        if ($this->pubToZmq('attribute')) {
            $pubSubTool = $this->getPubSubTool();
            $pubSubTool->attribute_save($attribute, 'delete');
        }
        $kafkaTopic = $this->kafkaTopic('attribute');
        if ($kafkaTopic) {
            $kafkaPubTool = $this->getKafkaPubTool();
            $kafkaPubTool->publishJson($kafkaTopic, $attribute, 'delete');
        }
    }

    public function afterDelete()
    {
        if (Configure::read('MISP.enable_advanced_correlations') && in_array($this->data['Attribute']['type'], ['ip-src', 'ip-dst'], true) && strpos($this->data['Attribute']['value'], '/')) {
            $this->Correlation->updateCidrList();
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
        $attribute = &$this->data['Attribute'];
        if (empty($attribute['type'])) {
            $this->validationErrors['type'] = ['No type set.'];
            return false;
        }

        $type = $attribute['type'];
        if (!isset($this->typeDefinitions[$type])) {
            $this->validationErrors['type'] = ['Invalid type.'];
            return false;
        }

        if (is_array($attribute['value'])) {
            $this->validationErrors['value'] = ['Value is an array.'];
            return false;
        }

        if (!empty($attribute['object_id']) && empty($attribute['object_relation'])) {
            $this->validationErrors['object_relation'] = ['Object attribute sent, but no object_relation set.'];
            return false;
        }

        $attribute = $this->beforeValidateMassage($attribute);
        // return true, otherwise the object cannot be saved
        return true;
    }

    public function beforeValidateMassage($attribute)
    {
        $type = $attribute['type'];
        // If `value1` or `value2` provided and `value` is empty, merge them into `value` because of validation
        if (empty($attribute['value'])) {
            if (!empty($attribute['value1']) && !empty($attribute['value2'])) {
                $attribute['value'] = "{$attribute['value1']}|{$attribute['value2']}";
            } else if (!empty($attribute['value1'])) {
                $attribute['value'] = $attribute['value1'];
            }
        }

        // remove leading and trailing blanks and refang value and
        $attribute['value'] = ComplexTypeTool::refangValue(trim($attribute['value']), $type);
        // make some changes to the inserted value
        $attribute['value'] = AttributeValidationTool::modifyBeforeValidation($type, $attribute['value']);
        // Run user defined regexp to attribute value
        if (!$this->fast_update) {
            $result = $this->runRegexp($type, $attribute['value']);
            if ($result === false) {
                $this->invalidate('value', 'This value is blocked by a regular expression in the import filters.');
            } else {
                $attribute['value'] = $result;
            }
        }

        if (empty($attribute['comment'])) {
            $attribute['comment'] = "";
        }
        if (!empty($attribute['uuid'])) {
            $attribute['uuid'] = strtolower($attribute['uuid']);
        }
        // generate timestamp if it doesn't exist
        if (empty($attribute['timestamp'])) {
            $attribute['timestamp'] = time();
        }

        // parse first_seen different formats
        if (isset($attribute['first_seen'])) {
            $attribute['first_seen'] = $attribute['first_seen'] === '' ? null : $attribute['first_seen'];
        }
        // parse last_seen different formats
        if (isset($attribute['last_seen'])) {
            $attribute['last_seen'] = $attribute['last_seen'] === '' ? null : $attribute['last_seen'];
        }

        // Set defaults for when some of the mandatory fields don't have defaults
        // These fields all have sane defaults either based on another field, or due to server settings
        if (!isset($attribute['distribution'])) {
            $attribute['distribution'] = $this->defaultDistribution();
        }
        if ($attribute['distribution'] != 4) {
            $attribute['sharing_group_id'] = 0;
        }
        // If category is not provided, assign default category by type
        if (empty($attribute['category'])) {
            $attribute['category'] = $this->typeDefinitions[$type]['default_category'];
        }

        if (!isset($attribute['to_ids'])) {
            $attribute['to_ids'] = $this->typeDefinitions[$type]['to_ids'];
        }

        if ($type === 'attachment') {
            $this->checkAttachmentExtension($attribute);

            // Disable correlation for image attachment filename that often leads to false positive correlation becuase of
            // generic names
            if (!isset($attribute['disable_correlation']) && $this->isImage($attribute)) {
                $attribute['disable_correlation'] = true;
            }
        }
        return $attribute;
    }

    public function validComposite($fields)
    {
        if (in_array($this->data['Attribute']['type'], $this->getCompositeTypes(), true)) {
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
        if (in_array($this->data['Attribute']['type'], $this->getCompositeTypes(), true)) {
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
        // This is somewhat dangerous, fast_update assumes that you are just updating an existing attribute's
        // non uniqueness modifying fields (first/last seen, comment, tags, timestamp, etc)
        // By ignoring this warning, you are introducing potential duplicates.
        if ($this->fast_update) {
            return true;
        }

        if (!empty($this->data['Attribute']['deleted'])) {
            return true;
        }
        // We escape this rule for objects as we can have the same category/type/value combination in different objects
        if (!empty($this->data['Attribute']['object_relation'])) {
            return true;
        }

        $existingAttribute = $this->findAttributeByValue($this->data['Attribute']);

        return empty($existingAttribute);
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
        return AttributeValidationTool::validate($this->data['Attribute']['type'], $value);
    }

    // check whether the variable is null or datetime
    public function datetimeOrNull($fields)
    {
        $seen = current($fields);
        if ($seen === null) {
            return true;
        }
        return strtotime($seen) !== false;
    }

    public function validateLastSeenValue($fields)
    {
        $ls = $fields['last_seen'];
        if (!isset($this->data['Attribute']['first_seen']) || $ls === null) {
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

    /**
     * @return array
     */
    public function getNonAttachmentTypes()
    {
        $output = [];
        foreach ($this->typeDefinitions as $type => $foo) {
            if ($type === "attachment" || $type === "malware-sample") {
                continue;
            }
            $output[] = $type;
        }
        return $output;
    }

    public function typeIsMalware($type)
    {
        return in_array($type, self::ZIPPED_DEFINITION, true);
    }

    public function typeIsAttachment($type)
    {
        return in_array($type, self::ZIPPED_DEFINITION, true) || in_array($type, self::UPLOAD_DEFINITIONS, true);
    }

    public function getAttachment($attribute)
    {
        return $this->loadAttachmentTool()->getContent($attribute['event_id'], $attribute['id']);
    }

    /**
     * @param array $attribute
     * @param string $path_suffix
     * @return File
     * @throws Exception
     */
    public function getAttachmentFile(array $attribute)
    {
        return $this->loadAttachmentTool()->getFile($attribute['event_id'], $attribute['id']);
    }

    /**
     * @param array $attribute
     * @return bool
     * @throws Exception
     */
    private function saveAttachment(array $attribute)
    {
        if ($attribute['data'] === false) {
            $this->log("Invalid attachment data provided for attribute with ID {$attribute['id']}.");
            return false;
        }
        $result = $this->loadAttachmentTool()->save($attribute['event_id'], $attribute['id'], $attribute['data']);
        if ($result) {
            // Clean thumbnail cache
            if ($this->isImage($attribute) && Configure::read('MISP.thumbnail_in_redis')) {
                $redis = RedisTool::init();
                RedisTool::deleteKeysByPattern($redis, "misp:thumbnail:attribute:{$attribute['id']}:*");
            }
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

    /**
     * Currently, as image are considered files with JPG (JPEG), PNG, GIF or WEBP extension.
     * @param array $attribute
     * @return bool
     */
    public function isImage(array $attribute)
    {
        return $attribute['type'] === 'attachment' &&
            Validation::extension($attribute['value'], ['jpg', 'jpeg', 'png', 'gif', 'webp']);
    }

    /**
     * @param array $attribute
     * @return File
     * @throws Exception
     */
    public function getPictureData(array $attribute)
    {
        return $this->loadAttachmentTool()->getFile($attribute['Attribute']['event_id'], $attribute['Attribute']['id']);
    }

    /**
     * @param array $attribute
     * @param string $outputFormat Can be 'png' or 'webp'
     * @param int|null $maxWidth
     * @param int|null $maxHeight
     * @return string|File
     * @throws Exception
     */
    public function getThumbnail(array $attribute, $outputFormat = 'png', $maxWidth = null, $maxHeight = null)
    {
        if (!extension_loaded('gd')) {
            return $this->getPictureData($attribute);
        }

        // Use two times bigger thumbnail for webp to generate hires preview image
        $defaultMaxSize = $outputFormat === 'webp' ? 400 : 200;
        $maxWidth = $maxWidth ?: $defaultMaxSize;
        $maxHeight = $maxHeight ?: $defaultMaxSize;
        $suffix = null;

        if ($maxWidth == $defaultMaxSize && $maxHeight == $defaultMaxSize) {
            $thumbnailInRedis = Configure::read('MISP.thumbnail_in_redis');
            if ($thumbnailInRedis) {
                $redis = RedisTool::init();
                if ($data = $redis->get("misp:thumbnail:attribute:{$attribute['Attribute']['id']}:$outputFormat")) {
                    return $data;
                }
            } else {
                $suffix = $outputFormat === 'png' ? '_thumbnail' : '_thumbnail_' . $outputFormat;
                // Return thumbnail directly if already exists
                try {
                    return $this->loadAttachmentTool()->getFile($attribute['Attribute']['event_id'], $attribute['Attribute']['id'], $suffix);
                } catch (NotFoundException $e) {
                    // pass
                }
            }
        }

        // Thumbnail doesn't exists, we need to generate it
        $imageData = $this->getAttachment($attribute['Attribute']);
        $imageData = $this->loadAttachmentTool()->resizeImage($imageData, $maxWidth, $maxHeight, $outputFormat);

        // Save just when requested default thumbnail size
        if ($maxWidth == $defaultMaxSize && $maxHeight == $defaultMaxSize) {
            if ($thumbnailInRedis) {
                $redis->setex("misp:thumbnail:attribute:{$attribute['Attribute']['id']}:$outputFormat", 3600, $imageData);
            } else {
                $this->loadAttachmentTool()->save($attribute['Attribute']['event_id'], $attribute['Attribute']['id'], $imageData, $suffix);
            }
        }
        return $imageData;
    }

    /**
     * @param array $user
     * @param array $resultArray
     * @throws Exception
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
                if (in_array($result['default_type'], self::PRIMARY_ONLY_CORRELATING_TYPES, true)) {
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
                        'Attribute.type' => Attribute::NON_CORRELATING_TYPES,
                    ],
                    'Attribute.disable_correlation' => 0,
                ],
                'fields' => ['Attribute.uuid', 'Attribute.type', 'Attribute.category', 'Attribute.value', 'Attribute.comment'],
                'order' => false,
                'limit' => 11,
                'flatten' => 1,
                'contain' => ['AttributeTag' => false],
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
            $d = new DateTime($data[$alias]['first_seen'], new DateTimeZone('GMT'));
            $data[$alias]['first_seen'] = $d->format('Uu');
        }
        if (!empty($data[$alias]['last_seen'])) {
            $d = new DateTime($data[$alias]['last_seen'], new DateTimeZone('GMT'));
            $data[$alias]['last_seen'] = $d->format('Uu');
        }
        return $data;
    }

    /**
     * @param $data
     * @param $alias
     * @return array
     * @deprecated
     */
    public function UTCToISODatetime($data, $alias)
    {
        if (!empty($data[$alias]['first_seen'])) {
            $data[$alias]['first_seen'] = $this->microTimestampToIso($data[$alias]['first_seen']);
        }
        if (!empty($data[$alias]['last_seen'])) {
            $data[$alias]['last_seen'] = $this->microTimestampToIso($data[$alias]['last_seen']);
        }
        return $data;
    }

    public function set_filter_tags(&$params, $conditions, $options)
    {
        if (empty($params['tags']) && empty($params['event_tags'])) {
            return $conditions;
        }
        /** @var Tag $tag */
        $tag = ClassRegistry::init('Tag');
        $tag_key = !empty($params['tags']) ? 'tags' : 'event_tags';
        $params[$tag_key] = $this->dissectArgs($params[$tag_key]);
        foreach (array(0, 1, 2) as $tag_operator) {
            $tagArray[$tag_operator] = $tag->fetchTagIdsSimple($params[$tag_key][$tag_operator]);
            // If at least one of the ANDed tags is not found, invalidate the entire query by setting the lookup equal -1
            if ($tag_operator === 2) {
                if (count($params[$tag_key][2]) !== count($tagArray[2])) {
                    $tagArray[2] = [-1];
                }
            }
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
                if ($tag_key != 'event_tags') {
                    $subquery_options = array(
                        'conditions' => array(
                            'tag_id' => $tagArray[0]
                        ),
                        'fields' => array(
                            $options['scope'] === 'Event' ? 'event_id' : 'attribute_id'
                        )
                    );
                    $lookup_field = $options['scope'] === 'Event' ? 'Event.id' : 'Attribute.id';
                    $temp = array_merge(
                        $temp,
                        $this->subQueryGenerator($tag->AttributeTag, $subquery_options, $lookup_field)
                    );
                }
            }
        }
        if (!empty($temp)) {
            $conditions['AND'][] = array('OR' => $temp);
        }
        $temp = array();
        if (!empty($tagArray[1])) {
            /* 
             * If we didn't find the given negation tag, no need to use the -1 trick,
             * it is basically a hack to block the search from finding anything if no positive lookup was valid.
             * However, if none of the negated tags exist, there's nothing to filter here
             */
            if (count($tagArray[1]) !== 1 || $tagArray[1][0] != -1) {
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
                    if ($tag_key != 'event_tags') {
                        $subquery_options = array(
                            'conditions' => array(
                                'tag_id' => $anded_tag
                            ),
                            'fields' => array(
                                $options['scope'] === 'Event' ? 'event_id' : 'attribute_id'
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
        }
        if (!empty($temp)) {
            $conditions['AND'][] = array('AND' => $temp);
        }
        $params[$tag_key] = array();
        if (!empty($tagArray[0]) && empty($options['pop'])) {
            $params[$tag_key]['OR'] = $tagArray[0];
        }
        if (!empty($tagArray[1])) {
            $params[$tag_key]['NOT'] = $tagArray[1];
        }
        if (!empty($tagArray[2]) && empty($options['pop'])) {
            $params[$tag_key]['AND'] = $tagArray[2];
        }
        if (empty($params[$tag_key])) {
            unset($params[$tag_key]);
        }
        return $conditions;
    }

    /**
     * @param $jobId
     * @param $eventId
     * @param $attributeId
     * @return void
     * @throws Exception
     * @deprecated Use Correlation::generateCorrelation directly
     */
    public function generateCorrelation($jobId = false, $eventId = false, $attributeId = false)
    {
        $this->Correlation->generateCorrelation($jobId, $eventId, $attributeId);
    }

    /**
     * @param $eventId
     * @return void
     * @deprecated Use Correlation::purgeCorrelations directly
     */
    public function purgeCorrelations($eventId = false)
    {
        $this->Correlation->purgeCorrelations($eventId);
    }

    /**
     * This method is useful if you want to iterate all attributes sorted by ID
     * @param array $conditions
     * @param array $fields
     * @param bool|string $callbacks
     * @param int $chunk_size
     * @return Generator<array>|void
     */
    public function fetchAttributesInChunks(array $conditions = [], array $fields = [], $callbacks = true, $chunk_size = 500)
    {
        $query = [
            'recursive' => -1,
            'conditions' => $conditions,
            'limit' => $chunk_size,
            'order' => ['Attribute.id'],
            'fields' => $fields,
            'callbacks' => $callbacks,
        ];

        while (true) {
            $attributes = $this->find('all', $query);
            foreach ($attributes as $attribute) {
                yield $attribute;
            }
            $count = count($attributes);
            if ($count < $chunk_size) {
                return;
            }
            $lastAttribute = $attributes[$count - 1];
            $query['conditions']['Attribute.id >'] = $lastAttribute['Attribute']['id'];
        }
    }

        /**
     * This method is useful if you want something semi compatible to fetchAttributesInChunks, but with single iterations
     * @param array $conditions
     * @param array $fields
     * @param bool|string $callbacks
     * @param int $chunk_size
     * @param int $last_id
     * @param bool $continue
     * @return array
     */
    public function fetchAttributesInChunksSingle(array $conditions = [], array $fields = [], $callbacks = true, $chunk_size = 500, &$last_id = 0, &$continue = false)
    {
        $conditions['Attribute.id > '] = $last_id;
        $query = [
            'recursive' => -1,
            'conditions' => $conditions,
            'limit' => $chunk_size,
            'order' => ['Attribute.id'],
            'fields' => $fields,
            'callbacks' => $callbacks,
        ];
        $attributes = $this->find('all', $query);
        if (empty($attributes)) {
            $continue = false;
            return [];
        }
        $lastAttribute = $attributes[count($attributes) - 1];
        $last_id = $lastAttribute['Attribute']['id'];
        return $attributes;
    }

    /**
     * @param int|null $eventId
     * @return Generator
     */
    public function reportValidationIssuesAttributes($eventId = null)
    {
        $conditions = array();
        if ($eventId && is_numeric($eventId)) {
            $conditions = array('event_id' => $eventId);
        }

        $attributes = $this->fetchAttributesInChunks($conditions);

        foreach ($attributes as $attribute) {
            $this->set($attribute);
            if (!$this->validates()) {
                $resultErrors = [];
                foreach ($this->validationErrors as $field => $error) {
                    $resultErrors[$field] = ['value' => $attribute['Attribute'][$field], 'error' => $error[0]];
                }
                yield [
                    'id' => $attribute['Attribute']['id'],
                    'error' => $resultErrors,
                    'details' => 'Event ID: [' . $attribute['Attribute']['event_id'] . "] - Category: [" . $attribute['Attribute']['category'] . "] - Type: [" . $attribute['Attribute']['type'] . "] - Value: [" . $attribute['Attribute']['value'] . ']',
                ];
            }
        }
    }

    /**
     * @param bool $dryRun If true, no changes will be made to
     * @return Generator
     * @throws Exception
     */
    public function normalizeIpAddress($dryRun = false)
    {
        $attributes = $this->fetchAttributesInChunks([
            'Attribute.type' => ['ip-src', 'ip-dst', 'ip-dst|port', 'ip-src|port', 'domain|ip'],
        ]);

        foreach ($attributes as $attribute) {
            $value = $attribute['Attribute']['value'];
            $normalizedValue = AttributeValidationTool::modifyBeforeValidation($attribute['Attribute']['type'], $value);
            if ($value !== $normalizedValue) {
                if (!$dryRun) {
                    $attribute['Attribute']['value'] = $normalizedValue;
                    $this->save($attribute, true, ['value1', 'value2']);
                }

                yield [
                    'id' => (int) $attribute['Attribute']['id'],
                    'event_id' => (int) $attribute['Attribute']['event_id'],
                    'type' => $attribute['Attribute']['type'],
                    'value' => $value,
                    'normalized_value' => $normalizedValue,
                ];
            }
        }
    }

    /**
     * This method takes a string from an argument with several elements (separated by '&&' and negated by '!') and returns 2 arrays
     * array 1 will have all of the non negated terms and array 2 all the negated terms
     *
     * @param string|array $args
     * @return array[]
     */
    public function dissectArgs($args)
    {
        $result = array(0 => array(), 1 => array(), 2 => array());
        if (empty($args)) {
            return $result;
        }
        if (!is_array($args)) {
            $args = explode('&&', $args);
        }
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
                if (is_string($arg) && $arg[0] === '!') {
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
            $sgids = $this->SharingGroup->authorizedIds($user);
            $subQuery1 = [
                'conditions' => ['org_id' => $user['org_id']],
                'fields' => ['id']
            ];
            $subQuery2 = [
                'conditions' => [
                    'distribution IN' => [1, 2, 3]
                ],
                'fields' => ['id']
            ];
            $subQuery3 = [
                'conditions' => [
                    'Event.distribution' => 4,
                    'Event.sharing_group_id IN' => $sgids
                ],
                'fields' => ['id']
            ];
            if (Configure::read('MISP.unpublishedprivate')) {
                $subQuery2['conditions']['Event.published'] = 1;
                $subQuery3['conditions']['Event.published'] = 1;
            }
            $conditions = [
                'OR' => [
                    $this->subQueryGenerator($this->Event, $subQuery1, 'Attribute.event_id'),
                    'AND' => [
                        'OR' => [
                            $this->subQueryGenerator($this->Event, $subQuery2, 'Attribute.event_id'),
                            $this->subQueryGenerator($this->Event, $subQuery3, 'Attribute.event_id')
                        ],
                        [
                            'OR' => [
                                'Attribute.distribution' => [1, 2, 3, 5],
                                'AND '=> [
                                    'Attribute.distribution' => 4,
                                    'Attribute.sharing_group_id' => $sgids,
                                ]
                            ]
                        ],
                        [
                            'OR' => [
                                'Attribute.object_id' => 0,
                                'Object.distribution' => [1, 2, 3, 5],
                                'AND' => [
                                    'Object.distribution' => 4,
                                    'Object.sharing_group_id' => $sgids,
                                ]
                            ]
                        ]
                    ]
                ]
            ];
        }
        return $conditions;
    }

    /**
     * Unlike the other fetchers, this one foregoes any ACL checks.
     * the objective is simple: Fetch the given attribute with all related objects needed for the ZMQ output,
     * standardising on this function for fetching the attribute to be passed to Attribute->save()
     * @param int $id
     * @returns array
     */
    public function fetchAttribute($id)
    {
        $attribute = $this->find('first', array(
            'recursive' => -1,
            'order' => [],
            'conditions' => array('Attribute.id' => $id),
            'contain' => array(
                'Event' => array(
                    'Orgc' => array(
                        'fields' => array('Orgc.id', 'Orgc.uuid', 'Orgc.name')
                    ),
                    'fields' => array('Event.id', 'Event.date', 'Event.info', 'Event.uuid', 'Event.published', 'Event.analysis', 'Event.threat_level_id', 'Event.org_id', 'Event.orgc_id', 'Event.distribution', 'Event.sharing_group_id')
                ),
                'AttributeTag' => array(
                    'fields' => ['AttributeTag.tag_id'],
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

            if (empty($attribute['Object']['id'])) {
                unset($attribute['Object']);
            }
        }
        return $attribute;
    }

    /**
     * @param array $user
     * @param array $options
     * @return array
     */
    public function fetchAttributeSimple(array $user, array $options = [])
    {
        $query = [
            'recursive' => -1,
            'conditions' => $this->buildConditions($user),
            'contain' => ['Event', 'Object'], // by default include Event and Object, because it is required for conditions
        ];
        if (isset($options['conditions'])) {
            $query['conditions']['AND'][] = $options['conditions'];
        }
        if (isset($options['fields'])) {
            $query['fields'] = $options['fields'];
        }
        if (isset($options['contain'])) {
            $query['contain'] = $options['contain'];
        }
        return $this->find('first', $query);
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

    /**
     * Method that fetches all attributes for the various exports
     * very flexible, it's basically a replacement for find, with the addition that it restricts access based on user
     * options:
     *  - fields
     *  - contain
     *  - conditions
     *  - order
     *  - group
     *
     * @param array $user
     * @param array $options
     * @param int|false $result_count If false, count is not fetched
     * @param bool $real_count
     * @return array
     * @throws Exception
     */
    public function fetchAttributes(array $user, array $options = [], &$result_count = false, $real_count = false)
    {
        $params = array(
            'conditions' => $this->buildConditions($user),
            'recursive' => -1,
            'contain' => array(
                'Event' => array(
                    'fields' => array('id', 'info', 'org_id', 'orgc_id', 'uuid'),
                ),
                'AttributeTag', // tags are fetched separately, @see Attribute::attachTagsToAttributes
                'Object' => array(
                    'fields' => array('id', 'distribution', 'sharing_group_id')
                )
            )
        );

        if (!empty($options['includeProposals'])) {
            $this->bindModel(['hasMany' => array(
                'ShadowAttribute' => array(
                    'className' => 'ShadowAttribute',
                    'foreignKey' => 'old_id',
                    'conditions' => array('ShadowAttribute.deleted' => 0)
                )
            )]);
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
            foreach ($options['contain'] as $key => $contain) {
                if ($contain === false) {
                    unset($params['contain'][$key]);
                    unset($options['contain'][$key]);
                    if (($key = array_search($key, $params['contain'])) !== false) {
                        unset($params['contain'][$key]);
                    }
                } else if (is_string($contain)) {
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
        if (!empty($options['allow_proposal_blocking']) && Configure::read('MISP.proposals_block_attributes')) {
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
        if (!empty($options['conditions'])) {
            $params['conditions']['AND'][] = $options['conditions'];
        }
        if (empty($options['flatten'])) {
            $params['conditions']['AND'][] = array('Attribute.object_id' => 0);
        }
        $params['order'] = [];
        if (!empty($options['order'])) {
            $params['order'] = $this->findOrder(
                $options['order'],
                'Attribute',
                ['id', 'event_id', 'object_id', 'type', 'category', 'value', 'distribution', 'timestamp', 'object_relation']
            );
        }
        if (!isset($options['withAttachments'])) {
            $options['withAttachments'] = false;
        }
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
        // Add EventTags to attributes to take them into account when calculating decay score
        if ($options['includeDecayScore']) {
            $options['includeEventTags'] = true;
        }
        if (isset($options['deleted'])) {
            if ($options['deleted'] === "only") {
                $options['deleted'] = 1;
            }
            $params['conditions']['AND']['(Attribute.deleted + 0)'] = $options['deleted'];
        } elseif (!$user['Role']['perm_sync'] || !isset($options['deleted']) || !$options['deleted']) {
            $params['conditions']['AND']['Attribute.deleted'] = 0;
        }
        if (isset($options['group'])) {
            $params['group'] = !empty($options['group']) ? $options['group'] : false;
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
                    'contain' => array('Event', 'Object'),
                    'fields' => array('Attribute.event_id'),
                    'order' => false
                ));
            }
        }

        if (($options['enforceWarninglist'] || $options['includeWarninglistHits']) && !isset($this->Warninglist)) {
            $this->Warninglist = ClassRegistry::init('Warninglist');
        }
        // If no limit is provided, fetch attributes in bulk
        if (empty($params['limit'])) {
            $loopLimit = 50000;
            $loop = true;
            $params['limit'] = $loopLimit;
            $params['page'] = 1;
        } else {
            $loop = false;
        }

        // Do not fetch result count when `$result_count` is false
        if ($result_count !== false && $real_count == true) {
            $find_params = $params;
            unset($find_params['limit']);
            $result_count = $this->find('count', $find_params);
            if ($result_count === 0) { // skip early
                return [];
            }
        }
        $eventTags = []; // tag cache
        $attributes = [];
        $params['ignoreIndexHint'] = 'deleted';
        do {
            $results = $this->find('all', $params);
            if (empty($results)) {
                break;
            }
            $iteration_result_count = count($results);
            if ($real_count !== true) {
                $result_count += count($results);
            }
            if (!empty($options['includeContext'])) {
                $eventIds = [];
                foreach ($results as $result) {
                    $eventIds[$result['Attribute']['event_id']] = true; // deduplicate
                }
                $eventsById = $this->__fetchEventsForAttributeContext($user, array_keys($eventIds), !empty($options['includeAllTags']));
                unset($eventIds);
            }

            $this->attachTagsToAttributes($results, $options);
            $proposals_block_attributes = Configure::read('MISP.proposals_block_attributes');
            $sgids = $this->SharingGroup->authorizedIds($user);
            foreach ($results as &$attribute) {
                if (!empty($options['includeContext'])) {
                    $attribute['Event'] = $eventsById[$attribute['Attribute']['event_id']];
                }
                if (!empty($options['includeSightings'])) {
                    $temp = $attribute['Attribute'];
                    $temp['Event'] = $attribute['Event'];
                    $attribute['Attribute']['Sighting'] = $this->Sighting->attachToEvent($temp, $user, $temp['id']);
                }
                if (!empty($options['includeCorrelations'])) {
                    $attributeFields = array('id', 'event_id', 'object_id', 'object_relation', 'category', 'type', 'value', 'uuid', 'timestamp', 'distribution', 'sharing_group_id', 'to_ids', 'comment');
                    $attribute['Attribute']['RelatedAttribute'] = $this->Correlation->getRelatedAttributes($user, $sgids, $attribute['Attribute'], $attributeFields, true);
                }
                if ($options['enforceWarninglist'] && !$this->Warninglist->filterWarninglistAttribute($attribute['Attribute'])) {
                    continue;
                }
                if (!empty($options['includeEventTags'])) {
                    $attribute = $this->__attachEventTagsToAttributes($eventTags, $attribute, $options);
                }
                if ($options['includeWarninglistHits']) {
                    $attribute['Attribute'] = $this->Warninglist->checkForWarning($attribute['Attribute']);
                }
                if (!empty($options['includeAttributeUuid']) || !empty($options['includeEventUuid'])) {
                    $attribute['Attribute']['event_uuid'] = $attribute['Event']['uuid'];
                }
                if ($proposals_block_attributes) {
                    if ($this->__blockAttributeViaProposal($attribute)) {
                        continue;
                    }
                    unset($attribute['ShadowAttribute']);
                }
                if ($options['withAttachments'] && $this->typeIsAttachment($attribute['Attribute']['type'])) {
                    $encodedFile = $this->base64EncodeAttachment($attribute['Attribute']);
                    $attribute['Attribute']['data'] = $encodedFile;
                }
                if ($options['includeDecayScore']) {
                    $this->DecayingModel = ClassRegistry::init('DecayingModel');
                    $include_full_model = isset($options['includeFullModel']) && $options['includeFullModel'] ? 1 : 0;
                    if (empty($attribute['Attribute']['AttributeTag'])) {
                        $attribute['Attribute']['AttributeTag'] = isset($attribute['AttributeTag']) ? $attribute['AttributeTag'] : array();
                        $attribute['Attribute']['EventTag'] = isset($attribute['EventTag']) ? $attribute['EventTag'] : array();
                    }
                    $attribute['Attribute'] = $this->DecayingModel->attachScoresToAttribute($user, $attribute['Attribute'], $options['decayingModel'], $options['modelOverrides'], $include_full_model);
                    unset($attribute['Attribute']['AttributeTag']);
                    unset($attribute['Attribute']['EventTag']);
                    if ($options['excludeDecayed'] && !empty($attribute['Attribute']['decay_score'])) { // filter out decayed attribute
                        $decayed_flag = true;
                        foreach ($attribute['Attribute']['decay_score'] as $decayResult) { // remove attribute if ALL score results in a decay
                            $decayed_flag = $decayed_flag && $decayResult['decayed'];
                        }
                        if ($decayed_flag) {
                            continue;
                        }
                    }
                }
                if (!empty($options['includeGalaxy'])) {
                    $massaged_attribute = $this->Event->massageTags($user, $attribute, 'Attribute');
                    $massaged_event = $this->Event->massageTags($user, $attribute, 'Event');
                    $massaged_attribute['Galaxy'] = array_merge_recursive($massaged_attribute['Galaxy'], $massaged_event['Galaxy']);
                    $attribute = $massaged_attribute;
                }
                $attributes[] = $attribute;
            }
            unset($attribute);

            if ($loop) {
                if ($iteration_result_count < $loopLimit) { // we fetched fewer results than the limit, so we can exit the loop
                    break;
                }
                $params['page']++;
            }
        } while ($loop);
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

    /**
     * Options:
     *  - includeAllTags - if true, include also exportable tags
     *
     * @param array $attributes
     * @param array $options
     */
    public function attachTagsToAttributes(array &$attributes, array $options)
    {
        $tagIdsToFetch = [];
        foreach ($attributes as $attribute) {
            if (!empty($attribute['AttributeTag'])) {
                foreach ($attribute['AttributeTag'] as $at) {
                    $tagIdsToFetch[$at['tag_id']] = true;
                }
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

        $tags = $this->AttributeTag->Tag->find('all', [
            'conditions' => $conditions,
            'fields' => ['id', 'name', 'colour', 'numerical_value', 'is_galaxy'],
            'recursive' => -1,
        ]);
        $tags = array_column(array_column($tags, 'Tag'), null, 'id');

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

    /**
     * @param array $eventTags
     * @param array $attribute
     * @param array $options
     * @return array
     */
    private function __attachEventTagsToAttributes(&$eventTags, $attribute, $options)
    {
        $eventId = $attribute['Event']['id'];
        if (!isset($eventTags[$eventId])) {
            $tagConditions = array('EventTag.event_id' => $eventId);
            if (empty($options['includeAllTags'])) {
                $tagConditions['Tag.exportable'] = 1;
            }
            $temp = $this->Event->EventTag->find('all', array(
                'recursive' => -1,
                'contain' => ['Tag' => ['fields' => ['id', 'name', 'colour', 'numerical_value']]],
                'conditions' => $tagConditions,
            ));
            if (empty($temp)) {
                $eventTags[$eventId] = [];
            } else {
                foreach ($temp as $tag) {
                    $tag['Tag']['inherited'] = true;
                    $tag['EventTag']['Tag'] = $tag['Tag'];
                    $eventTags[$eventId][] = $tag['EventTag'];
                }
            }
        }
        $attribute['EventTag'] = $eventTags[$eventId];
        return $attribute;
    }

    /**
     * This method will update attribute and object timestamp and unpublish event
     * @param int|array $attribute
     * @return bool
     * @throws Exception
     */
    public function touch($attribute)
    {
        if (!isset($attribute['Attribute'])) {
            if (!is_numeric($attribute)) {
                throw new InvalidArgumentException("Attribute must be array or ID.");
            }
            $attribute = $this->find('first', [
                'conditions' => ['Attribute.id' => $attribute],
                'recursive' => -1,
            ]);
            if (empty($attribute)) {
                throw new NotFoundException("Attribute not found.");
            }
        }

        // If attribute array contains event, reuse it for event unpublishing
        $event = isset($attribute['Event']) ? $attribute : $attribute['Attribute']['event_id'];

        $timestamp = time();
        $attribute['Attribute']['timestamp'] = $timestamp;
        $saveSuccess = $this->save($attribute['Attribute'], ['fieldList' => ['timestamp'], 'skipAuditLog' => true]);
        if ($saveSuccess && $attribute['Attribute']['object_id'] != 0) {
            $saveSuccess = $this->Object->updateTimestamp($attribute['Attribute']['object_id'], $timestamp);
        }
        if ($saveSuccess) {
            $saveSuccess = $this->Event->unpublishEvent($event, false, $timestamp);
        }
        return $saveSuccess;
    }

    public function attachTagsFromAttributeAndTouch($attribute_id, $event_id, array $options, array $user)
    {
        $tags = $options['tags'];
        $local = $options['local'];
        $relationship = $options['relationship_type'];
        $touchAttribute = false;
        $success = false;
        $capturedTags = [];
        foreach ($tags as $tag_name) {
            $nothingToChange = false;
            $tag_id = $this->Event->captureTagWithCache(
                [
                    'name' => $tag_name,
                ],
                $user,
                $capturedTags
            );
            $saveSuccess = $this->AttributeTag->attachTagToAttribute($attribute_id, $event_id, $tag_id, $local, $relationship, $nothingToChange);
            $success = $success || !empty($saveSuccess);
            $touchAttribute = $touchAttribute || !$nothingToChange;
        }
        if ($touchAttribute) {
            return $this->touch($attribute_id);
        }
        return $success;
    }

    public function detachTagsFromAttributeAndTouch($attribute_id, $event_id, array $options)
    {
        $tags = $options['tags'];
        $local = $options['local'];
        $touchAttribute = false;
        $success = false;
        foreach ($tags as $tag_name) {
            $nothingToChange = false;
            $tag_id = $this->AttributeTag->Tag->lookupTagIdFromName($tag_name);
            if ($tag_id == -1) {
                $success = $success || true;
                continue;
            }
            $saveSuccess = $this->AttributeTag->detachTagFromAttribute($attribute_id, $event_id, $tag_id, $local, $nothingToChange);
            $success = $success || !empty($saveSuccess);
            $touchAttribute = $touchAttribute || !$nothingToChange;
        }
        if ($touchAttribute) {
            return $this->touch($attribute_id);
        }
        return $success;
    }

    private function __blockAttributeViaProposal($attribute)
    {
        if (!empty($attribute['ShadowAttribute'])) {
            foreach ($attribute['ShadowAttribute'] as $sa) {
                if ($sa['value'] === $attribute['Attribute']['value'] &&
                    $sa['type'] === $attribute['Attribute']['type'] &&
                    $sa['category'] === $attribute['Attribute']['category'] &&
                    ($sa['to_ids'] == 0 || $sa['to_ids'] == '') &&
                    $attribute['Attribute']['to_ids'] == 1
                ) {
                    return true;
                }
            }
        }
        return false;
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
     * @param string $originalFilename
     * @param string $content
     * @param array $hashTypes
     * @return array
     */
    private function handleMaliciousRaw($originalFilename, $content, array $hashTypes)
    {
        $attachmentTool = $this->loadAttachmentTool();
        $hashes = $attachmentTool->computeHashes($content, $hashTypes);
        try {
            $encrypted = $attachmentTool->encrypt($originalFilename, $content, $hashes['md5']);
        } catch (Exception $e) {
            $this->logException("Could not create encrypted malware sample.", $e);
            return ['success' => false];
        }

        $hashes['success'] = true;
        $hashes['data_raw'] = $encrypted;
        return $hashes;
    }

    /**
     * @return bool Return true if at least one advanced extraction tool is available
     */
    public function isAdvancedExtractionAvailable()
    {
        try {
            $types = $this->loadAttachmentTool()->checkAdvancedExtractionStatus();
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
        $validTypes = [];
        $length = strlen($hash);
        foreach (self::FILE_HASH_TYPES as $type => $hashLength) {
            if ($length === $hashLength && ctype_xdigit($hash)) {
                $validTypes[] = $type;
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
        $defaultDistribution = $this->defaultDistribution();
        $saveResult = true;
        foreach ($attributes as $attribute) {
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

    /**
     * @param array $attribute
     * @return array
     */
    public function onDemandEncrypt(array $attribute)
    {
        if (strpos($attribute['value'], '|') !== false) {
            $temp = explode('|', $attribute['value']);
            $attribute['value'] = $temp[0];
        }

        $content = base64_decode($attribute['data']);
        if ($content === false) {
            $this->log("Invalid attachment data provided for attribute with ID {$attribute['id']}.");
            return $attribute;
        }

        $result = $this->handleMaliciousRaw($attribute['value'], $content, array('md5'));
        $attribute['data_raw'] = $result['data_raw'];
        unset($attribute['data']);
        $attribute['value'] = $attribute['value'] . '|' . $result['md5'];
        return $attribute;
    }

    public function setTimestampConditions($timestamp, $conditions, $scope = 'Event.timestamp', $returnRaw = false)
    {
        if (is_array($timestamp)) {
            if (count($timestamp) !== 2) {
                throw new InvalidArgumentException('Invalid date specification, must be string or array with two elements');
            }

            $timestamp[0] = $this->resolveTimeDelta($timestamp[0]);
            $timestamp[1] = $this->resolveTimeDelta($timestamp[1]);
            if ($timestamp[0] > $timestamp[1]) {
                $temp = $timestamp[0];
                $timestamp[0] = $timestamp[1];
                $timestamp[1] = $temp;
            }
            if ($timestamp[0] != 0) {
                $conditions['AND'][] = array($scope . ' >=' => $timestamp[0]);
            }
            $conditions['AND'][] = array($scope . ' <=' => $timestamp[1]);
        } else {
            $timestamp = $this->resolveTimeDelta($timestamp);
            if ($timestamp !== 0) {
                $conditions['AND'][] = array($scope . ' >=' => $timestamp);
            }
        }
        if ($returnRaw) {
            return $timestamp;
        }
        return $conditions;
    }

    public function setTimestampSeenConditions($timestamp, $conditions, $scope = 'Attribute.first_seen', $returnRaw = false)
    {
        if (is_array($timestamp)) {
            $timestamp[0] = intval($this->resolveTimeDelta($timestamp[0])) * 1000000; // seen in stored in micro-seconds in the DB
            $timestamp[1] = intval($this->resolveTimeDelta($timestamp[1])) * 1000000; // seen in stored in micro-seconds in the DB
            if ($timestamp[0] > $timestamp[1]) {
                $temp = $timestamp[0];
                $timestamp[0] = $timestamp[1];
                $timestamp[1] = $temp;
            }
            $conditions['AND'][] = array($scope . ' >=' => $timestamp[0]);
            $conditions['AND'][] = array($scope . ' <=' => $timestamp[1]);
        } else {
            $timestamp = intval($this->resolveTimeDelta($timestamp)) * 1000000; // seen in stored in micro-seconds in the DB
            if ($scope == 'Attribute.first_seen' || $scope == 'Object.first_seen') {
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

    public function fetchDistributionData($user)
    {
        $initialDistribution = $this->defaultDistribution();
        $sgs = $this->SharingGroup->fetchAllAuthorised($user, 'name', 1);
        $distributionLevels = $this->distributionLevels;
        if (empty($sgs)) {
            unset($distributionLevels[4]);
        }
        return array('sgs' => $sgs, 'levels' => $distributionLevels, 'initial' => $initialDistribution);
    }

    public function simpleAddMalwareSample($event_id, $attribute_settings, $filename, $tmpfile)
    {
        $attributes = array(
            'malware-sample' => array('type' => 'malware-sample', 'category' => '', 'to_ids' => 1, 'disable_correlation' => 0, 'object_relation' => 'malware-sample'),
            'filename' => array('type' => 'filename', 'category' => '', 'to_ids' => 0, 'disable_correlation' => 0, 'object_relation' => 'filename'),
            'md5' => array('type' => 'md5', 'category' => '', 'to_ids' => 1, 'disable_correlation' => 0, 'object_relation' => 'md5'),
            'sha1' => array('type' => 'sha1', 'category' => '', 'to_ids' => 1, 'disable_correlation' => 0, 'object_relation' => 'sha1'),
            'sha256' => array('type' => 'sha256', 'category' => '', 'to_ids' => 1, 'disable_correlation' => 0, 'object_relation' => 'sha256'),
            'size-in-bytes' => array('type' => 'size-in-bytes', 'category' => 'Other', 'to_ids' => 0, 'disable_correlation' => 1, 'object_relation' => 'size-in-bytes')
        );
        $hashes = array('md5', 'sha1', 'sha256');
        $current = $this->Object->ObjectTemplate->find('first', array(
            'fields' => array('MAX(version) AS version', 'uuid'),
            'conditions' => array('uuid' => '688c46fb-5edb-40a3-8273-1af7923e2215'),
            'recursive' => -1,
            'group' => array('uuid')
        ));
        if (!empty($current)) {
            $object_template = $this->Object->ObjectTemplate->find('first', array(
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
        $result = $this->handleMaliciousRaw($filename, $tmpfile->read(), $hashes);
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
            if ($k === 'malware-sample') {
                $attribute['value'] = $filename . '|' . $result['md5'];
                $attribute['data_raw'] = $result['data_raw'];
            } elseif ($k === 'size-in-bytes') {
                $attribute['value'] = $tmpfile->size();
            } elseif ($k === 'filename') {
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
            $result = $this->loadAttachmentTool()->advancedExtraction($tmpfile->path);
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
        $attribute['event_id'] = $eventId;
        $attribute['object_id'] = $objectId ?: 0;
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
                $this->logDropped($user, $attribute);
                return $attribute;
            }
        }
        if (isset($attribute['encrypt'])) {
            $attribute = $this->onDemandEncrypt($attribute);
        }
        $this->create();
        if (!isset($attribute['distribution'])) {
            $attribute['distribution'] = $this->defaultDistribution();
        }
        $breakOnDuplicate = true;
        if (isset($params['breakOnDuplicate'])) {
            $breakOnDuplicate = (bool)$params['breakOnDuplicate'];
        }
        $params = array(
            'fieldList' => self::CAPTURE_FIELDS,
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
        // if breakOnDuplicate=false, try to find the existing attribute by value and set the id and uuid
        if ($breakOnDuplicate === false) {
            unset($this->validate['value']['uniqueValue']);
            $existingAttribute = $this->findAttributeByValue($attribute);
            if (!empty($existingAttribute)) {
                $attribute['id'] = $existingAttribute['Attribute']['id'];
                $attribute['uuid'] = $existingAttribute['Attribute']['uuid'];
                $this->id = $attribute['id'];
            }
        }
        $savedAttribute = $this->save(['Attribute' => $attribute], $params);
        if (!$savedAttribute) {
            $this->logDropped($user, $attribute);
        } else {
            if (!empty($attribute['AttributeTag'])) {
                $toSave = [];
                foreach ($attribute['AttributeTag'] as $at) {
                    unset($at['id']);
                    $at['attribute_id'] = $this->id;
                    $at['event_id'] = $eventId;
                    $toSave[] = $at;
                }
                if (!$this->AttributeTag->saveMany($toSave, ['validate' => true])) {
                    $this->log("Could not save tags when capturing attribute with ID {$this->id}.", LOG_WARNING);
                } else if (!empty($this->AttributeTag->validationErrors)) {
                    $this->log("Could not save some tags when capturing attribute with ID {$this->id}: " . json_encode($this->AttributeTag->validationErrors), LOG_WARNING);
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
                        $at = [
                            'attribute_id' => $this->id,
                            'event_id' => $eventId,
                            'tag_id' => $tag_id,
                            'relationship_type' => empty($tag['relationship_type']) ? null : $tag['relationship_type']
                        ];
                        $this->AttributeTag->save($at);
                    }
                }
            }
            if (!empty($attribute['Sighting'])) {
                $this->Sighting->captureSightings($attribute['Sighting'], $this->id, $eventId, $user);
            }
            $this->Event->captureAnalystData($user, $attribute, 'Attribute', $savedAttribute['Attribute']['uuid']);
        }
        if (!empty($this->validationErrors)) {
            $validationErrors = $this->validationErrors;
        }
        return $attribute;
    }

    public function editAttribute($attribute, array $event, $user, $objectId, $log = false, $force = false, &$nothingToChange = false, $server = null)
    {
        if ($this->fast_update) {
            $this->Behaviors->unload('SysLogLogable.SysLogLogable');
        }
        $eventId = $event['Event']['id'];
        $attribute['event_id'] = $eventId;
        $attribute['object_id'] = $objectId;
        if (isset($attribute['encrypt'])) {
            $attribute = $this->onDemandEncrypt($attribute);
        }
        $attribute['_materialChange'] = false;
        unset($attribute['id']);
        if (isset($attribute['uuid'])) {
            $existingAttribute = $this->find('first', array(
                'conditions' => array('Attribute.uuid' => $attribute['uuid']),
                'recursive' => -1,
            ));
            if (!empty($existingAttribute)) {
                if ($existingAttribute['Attribute']['event_id'] != $eventId || $existingAttribute['Attribute']['object_id'] != $objectId) {
                    $change = 'An attribute was blocked from being saved due to a duplicate UUID. The uuid in question is: ' . $attribute['uuid'] . '. This can also be due to the same attribute (or an attribute with the same UUID) existing in a different event / object)';
                    $this->loadLog()->createLogEntry($user, 'edit', 'Attribute', 0, 'Duplicate UUID found in attribute', $change);
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
                    $attribute['timestamp'] = time();
                }
                foreach (['value','type','distribution','sharing_group_id'] as $relevantField) {
                    if (isset($attribute[$relevantField]) && $existingAttribute['Attribute'][$relevantField] !== $attribute[$relevantField]) {
                        $attribute['_materialChange'] = true;
                    }
                }
            } else {
                $attribute['_materialChange'] = true;
                $this->create();
            }
        } else {
            $attribute['uuid'] = CakeText::uuid();
            $attribute['_materialChange'] = true;
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
                $this->loadLog()->createLogEntry($user, 'edit', 'Attribute', 0,
                    'Attribute dropped due to invalid sharing group for Event ' . $eventId . ' failed: ' . $attribute_short,
                    'Validation errors: ' . json_encode($this->validationErrors) . ' Full Attribute: ' . json_encode($attribute)
                );
                return true;
            }
        } else if (!isset($attribute['distribution'])) {
            $attribute['distribution'] = $this->defaultDistribution();
        }

        // This is somewhat dangerous, fast_update assumes that you are just updating an existing attribute's
        // non uniqueness modifying fields (first/last seen, comment, tags, timestamp, etc)
        // By ignoring this warning, you are introducing potential duplicates.
        if ($this->fast_update) {
            $saveOptions['skipAuditLog'] = true;
        }
        return $attribute;
    }

    public function editAttributeBulk($attributes, $event, $user)
    {
        $fieldList = self::EDITABLE_FIELDS;
        $addableFieldList = array('event_id', 'type', 'uuid', 'object_id', 'object_relation');
        $fieldList = array_merge($fieldList, $addableFieldList);
        $saveOptions = [
            'fieldList' => $fieldList,
            'parentEvent' => $event,
            'atomic' => true,
            'validate' => 'only'
        ];

        // run the beforevalidation massage at this point so we can skip validation in round 2
        foreach ($attributes as $k => $attribute) {
            $attributes[$k] = $this->beforeValidateMassage($attribute);
        }

        // validation only so we can cull the problematic attributes
        $this->saveAll($attributes, $saveOptions);
        if (!empty($this->validationErrors)) {
            foreach ($this->validationErrors as $key => $validationError) {
                $this->logDropped($user, $attributes[$key], 'edit', $validationError);
                unset($this->updateLookupTable[$attributes[$key]['uuid']]);
                unset($attributes[$key]);
            }
        }
        $saveOptions['validate'] = false;
        // actual save, though we still need to validate in order for the beforeValidate massaging scripts to fire.
        if (!empty($attributes)) {
            $this->saveMany($attributes, $saveOptions);
        }
        return $this->editAttributePostProcessing($attributes, $event, $user);
    }

    public function editAttributePostProcessing($attributes, $event, $user)
    {
        $eventId = $event['Event']['id'];
        $tagActions = [];
        foreach ($attributes as $attribute) {
            if (!isset($this->updateLookupTable[$attribute['uuid']])) {
                continue;
            }
            $attributeId = $this->updateLookupTable[$attribute['uuid']];
            if (!empty($attribute['Sighting'])) {
                $this->Sighting->captureSightings($attribute['Sighting'], $attributeId, $eventId, $user);
            }
            $this->Event->captureAnalystData($user, $attribute, 'Attribute', $attribute['uuid']);
            if ($user['Role']['perm_tagger']) {
                /*
                    We should unwrap the line below and remove the server option in the future once we have tag soft-delete
                    A solution to still keep the behavior for previous instance could be to not soft-delete the Tag if the remote instance
                    has a version below x
                */
                if (isset($server) && isset($server['Server']['remove_missing_tags']) && $server['Server']['remove_missing_tags']) {
                    $existingTags = $this->AttributeTag->find('all', [
                        'recursive' => -1,
                        'conditions' => ['attribute_id' => $attribute['id']]
                    ]);
                    $this->AttributeTag->pruneOutdatedAttributeTagsFromSync(isset($attribute['Tag']) ? $attribute['Tag'] : array(), $existingTags['AttributeTag']);
                }
                $tag_id_store = [];
                if (isset($attribute['Tag'])) {
                    foreach ($attribute['Tag'] as $tag) {
                        if (empty($tag_id_store[$tag['name']])) {
                            $tag_id = $this->AttributeTag->Tag->captureTag($tag, $user);
                            if ($tag_id) {
                                $tag_id_store[$tag['name']] = $tag_id;
                            }
                        } else {
                            $tag_id = $tag_id_store[$tag['name']];
                        }
                        if ($tag_id) {
                            $tag['id'] = $tag_id;
                            // fix the IDs here
                            $tag_result = $this->AttributeTag->handleAttributeTag($attributeId, $attribute['event_id'], $tag, true);
                            if (isset($tag_result['attach'])) {
                                $tagActions['attach'][$attributeId . '-' . $tag_id] = $tag_result['attach'];
                            } else if(isset($tag_result['detach'])) {
                                $tagActions['detach'][] = $tag_result['detach'];
                            }
                        } else {
                            // If we couldn't attach the tag it is most likely because we couldn't create it - which could have many reasons
                            // However, if a tag couldn't be added, it could also be that the user is a tagger but not a tag editor
                            // In which case if no matching tag is found, no tag ID is returned. Logging these is pointless as it is the correct behaviour.
                            if ($user['Role']['perm_tag_editor']) {
                                $this->loadLog()->createLogEntry($user, 'edit', 'Attribute', $attributeId, 'Failed create or attach Tag ' . $tag['name'] . ' to the attribute.');
                            }
                        }
                    }
                }
            }
        }
        if (!empty($tagActions['attach'])) {
            foreach ($tagActions['attach'] as $k => $attach) {
                $existingAssociation = $this->AttributeTag->find('first', [
                    'conditions' => [
                        'tag_id' => $attach['tag_id'],
                        'attribute_id' => $attach['attribute_id']
                    ],
                    'recursive' => -1
                ]);
                if (!empty($existingAssociation)) {
                    $attach['id'] = $existingAssociation['AttributeTag']['id'];
                    if ($attach['local'] == $existingAssociation['AttributeTag']['local'] && $attach['relationship_type'] == $existingAssociation['AttributeTag']['relationship_type']) {
                        unset($tagActions['attach'][$k]);
                    }
                }
            }
            if (!empty($tagActions['attach'])) {
                $this->AttributeTag->saveMany($tagActions['attach']);
            }

        }
        if (!empty($tagActions['detach'])) {
            foreach ($tagActions['detach'] as $detach) {
                $conditions = [
                    'attribute_id' => $detach['attribute_id'],
                    'tag_id' => $detach['tag_id']
                ];
                $this->AttributeTag->deleteAll($conditions, false);
            }
        }
        if ($this->fast_update) {
            // Let's recorrelate the event
            foreach ($attributes as $attribute) {
                if (!empty($attribute['_materialChange'])) {
                    $this->Correlation->generateCorrelation(false, $event['Event']['id'], $attributeId);
                }
            }
            // Instead of incrementing / decrementing the event
            $attribute_count = $this->find('count', [
                'conditions' => [
                    'Attribute.event_id' => $event['Event']['id'],
                    'Attribute.deleted' => 0
                ],
                'recursive' => -1
            ]);
            $temp_event = [
                'id' => $event['Event']['id'],
                'attribute_count' => $attribute_count
            ];
            $this->Event->save($temp_event);
            $this->__alterAttributeCount($event['Event']['id']);
        }
        return true;
    }


    /**
     * @param int $id Attribute ID
     * @param array $user
     * @param bool $hard
     * @return bool
     * @throws Exception
     */
    public function deleteAttribute($id, array $user, $hard = false)
    {
        $attribute = $this->find('first', [
            'conditions' => ['Attribute.id' => $id],
            'contain' => ['Event'],
            'recursive' => -1,
        ]);
        if (empty($attribute)) {
            throw new NotFoundException(__('Invalid attribute'));
        }

        // check for permissions
        if (!$user['Role']['perm_site_admin']) {
            if ($attribute['Event']['locked']) {
                if ($user['org_id'] != $attribute['Event']['org_id'] || !$user['Role']['perm_sync']) {
                    throw new ForbiddenException(__('You do not have permission to do that.'));
                }
            } else {
                if ($user['org_id'] != $attribute['Event']['orgc_id']) {
                    throw new ForbiddenException(__('You do not have permission to do that.'));
                }
            }
        }
        if ($hard) {
            $save = $this->delete($id);
        } else {
            if (Configure::read('Security.sanitise_attribute_on_delete')) {
                $attribute['Attribute']['category'] = 'Other';
                $attribute['Attribute']['type'] = 'comment';
                $attribute['Attribute']['value'] = 'deleted';
                $attribute['Attribute']['comment'] = '';
                $attribute['Attribute']['to_ids'] = 0;
            }
            $attribute['Attribute']['deleted'] = 1;
            $attribute['Attribute']['timestamp'] = time();
            $save = $this->save($attribute);
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
            $this->Event->unpublishEvent($attribute);
            return true;
        }
        return false;
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

    public function buildFilterConditions(array $user, array &$params, $skipBuildConditions = false)
    {
        // in some cases we'll build the user ACL conditions elsewhere,
        // for example when calling this function via restsearch
        if ($skipBuildConditions) {
            $conditions = [];
        } else {
            $conditions = $this->buildConditions($user);
        }
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
            if (isset($params['ignore'])) {
                unset($params['to_ids']);
                unset($params['published']);
            }
            $simple_params = array(
                'Attribute' => array(
                    'sharinggroup' => array('function' => 'set_filter_sharing_group'),
                    'value' => array('function' => 'set_filter_value'),
                    'value1' => array('function' => 'set_filter_simple_attribute'),
                    'value2' => array('function' => 'set_filter_simple_attribute'),
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
                    'sharinggroup' => array('function' => 'set_filter_sharing_group'),
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

    /**
     * @param array $user
     * @param string $returnFormat
     * @param array $filters
     * @param bool $paramsOnly
     * @param int $jobId Not used
     * @param int $elementCounter
     * @param bool $renderView
     * @return array|TmpFileTool Array when $paramsOnly is true
     * @throws Exception
     */
    public function restSearch(array $user, $returnFormat, $filters, $paramsOnly = false, $jobId = false, &$elementCounter = 0, &$renderView = false)
    {
        if (!isset($this->validFormats[$returnFormat][1])) {
            throw new NotFoundException('Invalid output format.');
        }
        $className = $this->validFormats[$returnFormat][1];
        App::uses($className, 'Export');
        $exportTool = new $className();
        if (method_exists($exportTool, 'setDefaultFilters')) {
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
        $conditions = $this->buildFilterConditions($user, $filters, true);
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
        if (!empty($filters['order'])) {
            $params['order'] = $this->findOrder(
                $filters['order'],
                'Attribute',
                ['id', 'event_id', 'object_id', 'type', 'category', 'value', 'distribution', 'timestamp', 'object_relation']
            );
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
     * @return int Number of all attributes that matches given conditions
     * @throws Exception
     */
    private function __iteratedFetch(array $user, array $params, $loop, TmpFileTool $tmpfile, $exportTool, array $exportToolParams)
    {
        $this->Allowedlist = ClassRegistry::init('Allowedlist');
        $separator = $exportTool->separator($exportToolParams);
        $elementCounter = 0;
        $real_count = false;
        $incrementTotalBy = $loop || $real_count ? 0 : 1;
        do {
            $results = $this->fetchAttributes($user, $params, $elementCounter, $real_count);
            if (!$real_count) {
                $totalCount = $params['limit'] * ($params['page'] - 1) + $elementCounter;
            } else {
                $totalCount = $elementCounter;
            }
            $elementCounter = false; // do not call `count` again
            if (empty($results)) {
                break; // nothing found, skip rest
            }
            if ($params['includeSightingdb']) {
                $this->Sightingdb = ClassRegistry::init('Sightingdb');
                $results = $this->Sightingdb->attachToAttributes($results, $user);
            }
            $results = $this->Allowedlist->removeAllowedlistedFromArray($results, true);
            foreach ($results as $attribute) {
                $handlerResult = $exportTool->handler($attribute, $exportToolParams);
                if ($handlerResult !== '') {
                    $tmpfile->writeWithSeparator($handlerResult, $separator);
                }
            }
            if (count($results) < $params['limit']) {
                $incrementTotalBy = 0;
                if ($loop) {
                    break; // do not continue if we received less results than limit
                }
            }
            $params['page'] += 1;
        } while ($loop);
        return $totalCount + $incrementTotalBy;
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

    public function set_filter_uuid(&$params, $conditions, $options)
    {
        if (!empty($params['uuid'])) {
            $params['uuid'] = $this->convert_filters($params['uuid']);
            if (!empty($params['uuid']['OR'])) {
                if ($options['scope'] == 'Attribute') {
                    $subQuery = [
                        'conditions' => ['uuid' => $params['uuid']['OR']],
                        'fields' => ['id']
                    ];
                    $pre_lookup = $this->Event->find('first', [
                        'conditions' => ['Event.uuid' => $params['uuid']['OR']],
                        'recursive' => -1,
                        'fields' => ['Event.id']
                    ]);
                    if (empty($pre_lookup)) {
                        $conditions['AND'][] = array(
                            'OR' => array(
                                'Attribute.uuid' => $params['uuid']['OR']
                            )
                        );
                    } else {
                        $conditions['AND'][] = array(
                            'OR' => array(
                                $this->subQueryGenerator($this->Event, $subQuery, 'Attribute.event_id'),
                                'Attribute.uuid' => $params['uuid']['OR']
                            )
                        );
                    }
                    
                } else {
                    $conditions['AND'][] = array(
                        'OR' => array(
                            'Event.uuid' => $params['uuid']['OR'],
                            'Attribute.uuid' => $params['uuid']['OR']
                        )
                    );
                }
            }
            if (!empty($params['uuid']['NOT'])) {
                if ($options['scope'] == 'Attribute') {
                    $subQuery = [
                        'conditions' => ['uuid' => $params['uuid']['OR']],
                        'fields' => ['id']
                    ];
                    $conditions['AND'][] = [
                        'NOT' => [
                            $this->subQueryGenerator($this->Event, $subQuery, 'Attribute.event_id'),
                            'Attribute.uuid' =>  $params['uuid']['NOT']
                        ]
                    ];
                } else {
                    $conditions['AND'][] = array(
                        'NOT' => array(
                            'Event.uuid' => $params['uuid']['NOT'],
                            'Attribute.uuid' =>  $params['uuid']['NOT']
                        )
                    );
                }
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

    /**
     * Fetch default distribution from `MISP.default_attribute_distribution` setting. If this setting is not defined,
     * default distribution is `5` (Inherit event)
     * @return int
     */
    public function defaultDistribution()
    {
        static $distribution;
        if ($distribution === null) {
            $distribution = Configure::read('MISP.default_attribute_distribution');
            if ($distribution === null || $distribution === 'event') {
                $distribution = 5;
            }
        }
        return $distribution;
    }

    /**
     * Log when attribute was dropped due to validation errors.
     *
     * @param array $user
     * @param array $attribute
     * @param string $action
     * @throws JsonException
     */
    public function logDropped(array $user, array $attribute, $action = 'add', $validationError = false)
    {
        $attribute_short = (isset($attribute['category']) ? $attribute['category'] : 'N/A') . '/' . (isset($attribute['type']) ? $attribute['type'] : 'N/A') . ' ' . (isset($attribute['value']) ? $attribute['value'] : 'N/A');
        if ($validationError === false) {
            $validationError = $this->validationErrors;
        }
        $eventId = $attribute['event_id'];
        $modelId = $action === 'add' ? 0 : $this->id;
        $this->loadLog()->createLogEntry($user, $action, 'Attribute',  $modelId,
            "Attribute dropped due to validation for Event $eventId failed: $attribute_short",
            'Validation errors: ' . JsonTool::encode($validationError) . ' Full Attribute: ' . JsonTool::encode($attribute)
        );
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
            $this->categoryDefinitions = $this->generateCategoryDefinitions();
            return $this->categoryDefinitions;
        }
        return parent::__get($name);
    }

    /**
     * Generate just when really need
     * NOTE WHEN MODIFYING: please ensure to run the script 'tools/gen_misp_types_categories.py' to update the new definitions everywhere. (docu, website, RFC, ... )
     * @return array[]
     */
    private function generateCategoryDefinitions()
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
                'types' => array('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'ssdeep', 'imphash', 'telfhash', 'impfuzzy', 'authentihash', 'vhash', 'pehash', 'tlsh', 'cdhash', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|sha3-224', 'filename|sha3-256', 'filename|sha3-384', 'filename|sha3-512', 'filename|authentihash', 'filename|vhash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash','filename|impfuzzy', 'filename|pehash', 'mac-address', 'mac-eui-64', 'ip-src', 'ip-dst', 'ip-dst|port', 'ip-src|port', 'hostname', 'domain', 'email', 'email-src', 'email-dst', 'email-subject', 'email-attachment', 'email-body', 'url', 'user-agent', 'AS', 'pattern-in-file', 'pattern-in-traffic', 'filename-pattern', 'stix2-pattern', 'yara', 'sigma', 'mime-type', 'attachment', 'malware-sample', 'link', 'malware-type', 'comment', 'text', 'hex', 'vulnerability', 'cpe', 'weakness', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'ja3-fingerprint-md5', 'jarm-fingerprint', 'hassh-md5', 'hasshserver-md5', 'other', 'hostname|port', 'email-dst-display-name', 'email-src-display-name', 'email-header', 'email-reply-to', 'email-x-mailer', 'email-mime-boundary', 'email-thread-index', 'email-message-id', 'azure-application-id', 'mobile-application-id', 'chrome-extension-id', 'whois-registrant-email', 'anonymised')
            ),
            'Artifacts dropped' => array(
                'desc' => __('Any artifact (files, registry keys etc.) dropped by the malware or other modifications to the system'),
                'types' => array('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'ssdeep', 'imphash', 'telfhash', 'impfuzzy', 'authentihash', 'vhash', 'cdhash', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|sha3-224', 'filename|sha3-256', 'filename|sha3-384', 'filename|sha3-512', 'filename|authentihash', 'filename|vhash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash', 'filename|impfuzzy','filename|pehash', 'regkey', 'regkey|value', 'pattern-in-file', 'pattern-in-memory', 'filename-pattern', 'pdb', 'stix2-pattern', 'yara', 'sigma', 'attachment', 'malware-sample', 'named pipe', 'mutex', 'process-state','windows-scheduled-task', 'windows-service-name', 'windows-service-displayname', 'comment', 'text', 'hex', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'other', 'cookie', 'gene', 'kusto-query', 'mime-type', 'anonymised', 'pgp-public-key', 'pgp-private-key')
            ),
            'Payload installation' => array(
                'desc' => __('Info on where the malware gets installed in the system'),
                'formdesc' => __('Location where the payload was placed in the system and the way it was installed. For example, a filename|md5 type attribute can be added here like this: c:\\windows\\system32\\malicious.exe|41d8cd98f00b204e9800998ecf8427e.'),
                'types' => array('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'ssdeep', 'imphash', 'telfhash', 'impfuzzy', 'authentihash', 'vhash', 'pehash', 'tlsh', 'cdhash', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|sha3-224', 'filename|sha3-256', 'filename|sha3-384', 'filename|sha3-512', 'filename|authentihash', 'filename|vhash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash', 'filename|impfuzzy', 'filename|pehash', 'pattern-in-file', 'pattern-in-traffic', 'pattern-in-memory', 'filename-pattern', 'stix2-pattern', 'yara', 'sigma', 'vulnerability', 'cpe','weakness', 'attachment', 'malware-sample', 'malware-type', 'comment', 'text', 'hex', 'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'azure-application-id', 'azure-application-id', 'mobile-application-id', 'chrome-extension-id', 'other', 'mime-type', 'anonymised')
            ),
            'Persistence mechanism' => array(
                'desc' => __('Mechanisms used by the malware to start at boot'),
                'formdesc' => __('Mechanisms used by the malware to start at boot. This could be a registry key, legitimate driver modification, LNK file in startup'),
                'types' => array('filename', 'regkey', 'regkey|value', 'comment', 'text', 'other', 'hex', 'anonymised')
            ),
            'Network activity' => array(
                'desc' => __('Information about network traffic generated by the malware'),
                'types' => array('ip-src', 'ip-dst', 'ip-dst|port', 'ip-src|port', 'port', 'hostname', 'domain', 'domain|ip', 'mac-address', 'mac-eui-64', 'email', 'email-dst', 'email-src', 'eppn', 'url', 'uri', 'user-agent', 'http-method', 'AS', 'snort', 'pattern-in-file', 'filename-pattern','stix2-pattern', 'pattern-in-traffic', 'attachment', 'comment', 'text', 'x509-fingerprint-md5', 'x509-fingerprint-sha1', 'x509-fingerprint-sha256', 'ja3-fingerprint-md5', 'jarm-fingerprint', 'hassh-md5', 'hasshserver-md5', 'other', 'hex', 'cookie', 'hostname|port', 'bro', 'zeek', 'anonymised', 'community-id', 'email-subject', 'favicon-mmh3', 'dkim', 'dkim-signature', 'ssh-fingerprint')
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
                'types' => array('comment', 'text', 'other', 'size-in-bytes', 'counter', 'integer', 'datetime', 'cpe', 'port', 'float', 'hex', 'phone-number', 'boolean', 'anonymised', 'pgp-public-key', 'pgp-private-key')
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
            'md5' => array('desc' => __('A checksum in MD5 format'), 'formdesc' => __("You are encouraged to use filename|md5 instead. A checksum in md5 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha1' => array('desc' => __('A checksum in SHA1 format'), 'formdesc' => __("You are encouraged to use filename|sha1 instead. A checksum in sha1 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha256' => array('desc' => __('A checksum in SHA256 format'), 'formdesc' => __("You are encouraged to use filename|sha256 instead. A checksum in sha256 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename' => array('desc' => __('Filename'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'pdb' => array('desc' => __('Microsoft Program database (PDB) path information'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'filename|md5' => array('desc' => __('A filename and an MD5 hash separated by a |'), 'formdesc' => __("A filename and an md5 hash separated by a | (no spaces)"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha1' => array('desc' => __('A filename and an SHA1 hash separated by a |'), 'formdesc' => __("A filename and an sha1 hash separated by a | (no spaces)"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha256' => array('desc' => __('A filename and an SHA256 hash separated by a |'), 'formdesc' => __("A filename and an sha256 hash separated by a | (no spaces)"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'ip-src' => array('desc' => __("A source IP address of the attacker"), 'default_category' => 'Network activity', 'to_ids' => 1),
            'ip-dst' => array('desc' => __('A destination IP address of the attacker or C&C server'), 'formdesc' => __("A destination IP address of the attacker or C&C server. Also set the IDS flag on when this IP is hardcoded in malware"), 'default_category' => 'Network activity', 'to_ids' => 1),
            'hostname' => array('desc' => __('A full host/dnsname of an attacker'), 'formdesc' => __("A full host/dnsname of an attacker. Also set the IDS flag on when this hostname is hardcoded in malware"), 'default_category' => 'Network activity', 'to_ids' => 1),
            'domain' => array('desc' => __('A domain name used in the malware'), 'formdesc' => __("A domain name used in the malware. Use this instead of hostname when the upper domain is important or can be used to create links between events."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'domain|ip' => array('desc' => __('A domain name and its IP address (as found in DNS lookup) separated by a |'),'formdesc' => __("A domain name and its IP address (as found in DNS lookup) separated by a | (no spaces)"), 'default_category' => 'Network activity', 'to_ids' => 1),
            'email' => array('desc' => ('An email address'), 'default_category' => 'Social network', 'to_ids' => 1),
            'email-src' => array('desc' => __("The source email address. Used to describe the sender when describing an e-mail."), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'eppn' => array('desc' => __("eduPersonPrincipalName - eppn - the NetId of the person for the purposes of inter-institutional authentication. Should be stored in the form of user@univ.edu, where univ.edu is the name of the local security domain."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'email-dst' => array('desc' => __("The destination email address. Used to describe the recipient when describing an e-mail."), 'default_category' => 'Network activity', 'to_ids' => 1),
            'email-subject' => array('desc' => __("The subject of the email"), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-attachment' => array('desc' => __("File name of the email attachment."), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'email-body' => array('desc' => __('Email body'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'float' => array('desc' => __("A floating point value."), 'default_category' => 'Other', 'to_ids' => 0),
            'git-commit-id' => array('desc' => __("A Git commit ID."), 'default_category' => 'Internal reference', 'to_ids' => 0),
            'url' => array('desc' => __('Uniform Resource Locator'), 'default_category' => 'Network activity', 'to_ids' => 1),
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
            'community-id' => array('desc' => __('A community ID flow hashing algorithm to map multiple traffic monitors into common flow id'), 'formdesc' => __("a community ID flow hashing algorithm to map multiple traffic monitors into common flow id"), 'default_category' => 'Network activity', 'to_ids' => 1),
            'pattern-in-file' => array('desc' => __('Pattern in file that identifies the malware'), 'default_category' => 'Payload installation', 'to_ids' => 1),
            'pattern-in-traffic' => array('desc' => __('Pattern in network traffic that identifies the malware'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'pattern-in-memory' => array('desc' => __('Pattern in memory dump that identifies the malware'), 'default_category' => 'Payload installation', 'to_ids' => 1),
            'filename-pattern' => array('desc' => __('A pattern in the name of a file'), 'default_category' => 'Payload installation', 'to_ids' => 1),
            'pgp-public-key' => array('desc' => __('A PGP public key'), 'default_category' => 'Person', 'to_ids' => 0),
            'pgp-private-key' => array('desc' => __('A PGP private key'), 'default_category' => 'Person', 'to_ids' => 0),
            'ssh-fingerprint' => array('desc' => __('A fingerprint of SSH key material'), 'default_category' => 'Network activity', 'to_ids' => 0),
            'yara' => array('desc' => __('YARA signature'), 'default_category' => 'Payload installation', 'to_ids' => 1),
            'stix2-pattern' => array('desc' => __('STIX 2 pattern'), 'default_category' => 'Payload installation', 'to_ids' => 1),
            'sigma' => array('desc' => __('Sigma - Generic Signature Format for SIEM Systems'), 'default_category' => 'Payload installation', 'to_ids' => 1),
            'gene' => array('desc' => __('GENE - Go Evtx sigNature Engine'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'kusto-query' => array('desc' => __('Kusto query - Kusto from Microsoft Azure is a service for storing and running interactive analytics over Big Data.'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'mime-type' => array('desc' => __('A media type (also MIME type and content type) is a two-part identifier for file formats and format contents transmitted on the Internet'), 'default_category' => 'Artifacts dropped', 'to_ids' => 0),
            'identity-card-number' => array('desc' => __('Identity card number'), 'default_category' => 'Person', 'to_ids' => 0),
            'cookie' => array('desc' => __('HTTP cookie as often stored on the user web client. This can include authentication cookie or session cookie.'), 'default_category' => 'Network activity', 'to_ids' => 0),
            'vulnerability' => array('desc' => __('A reference to the vulnerability used in the exploit'), 'default_category' => 'External analysis', 'to_ids' => 0),
            'cpe' => array('desc' => __('Common Platform Enumeration - structured naming scheme for information technology systems, software, and packages.'), 'default_category' => 'External analysis', 'to_ids' => 0),
            'weakness' => array('desc'=> __('A reference to the weakness (CWE) used in the exploit'), 'default_category' => 'External analysis', 'to_ids' => 0),
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
            'pehash' => array('desc' => __('peHash - a hash calculated based of certain pieces of a PE executable file'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'impfuzzy' => array('desc' => __('A fuzzy hash of import table of Portable Executable format'), 'formdesc' => __("You are encouraged to use filename|impfuzzy instead. A fuzzy hash created based on the imports in the sample, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha224' => array('desc' => __('A checksum in SHA-224 format'), 'formdesc' => __("You are encouraged to use filename|sha224 instead. A checksum in sha224 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha384' => array('desc' => __('A checksum in SHA-384 format'), 'formdesc' => __("You are encouraged to use filename|sha384 instead. A checksum in sha384 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha512' => array('desc' => __('A checksum in SHA-512 format'), 'formdesc' => __("You are encouraged to use filename|sha512 instead. A checksum in sha512 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha512/224' => array('desc' => __('A checksum in the SHA-512/224 format'), 'formdesc' => __("You are encouraged to use filename|sha512/224 instead. A checksum in sha512/224 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha512/256' => array('desc' => __('A checksum in the SHA-512/256 format'), 'formdesc' => __("You are encouraged to use filename|sha512/256 instead. A checksum in sha512/256 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha3-224' => array('desc' => __('A checksum in SHA3-224 format'), 'formdesc' => __("You are encouraged to use filename|sha3-224 instead. A checksum in sha3-224 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha3-256' => array('desc' => __('A checksum in SHA3-256 format'), 'formdesc' => __("You are encouraged to use filename|sha3-256 instead. A checksum in sha3-256 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha3-384' => array('desc' => __('A checksum in SHA3-384 format'), 'formdesc' => __("You are encouraged to use filename|sha3-384 instead. A checksum in sha3-384 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'sha3-512' => array('desc' => __('A checksum in SHA3-512 format'), 'formdesc' => __("You are encouraged to use filename|sha3-512 instead. A checksum in sha3-512 format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'tlsh' => array('desc' => __('A checksum in the Trend Micro Locality Sensitive Hash format'), 'formdesc' => __("You are encouraged to use filename|tlsh instead. A checksum in the Trend Micro Locality Sensitive Hash format, only use this if you don't know the correct filename"), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'cdhash' => array('desc' => __('An Apple Code Directory Hash, identifying a code-signed Mach-O executable file'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|authentihash' => array('desc' => __('A filename and Authenticode executable signature hash'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|vhash' => array('desc' => __('A filename and a VirusTotal hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|ssdeep' => array('desc' => __('A checksum in ssdeep format'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|imphash' => array('desc' => __('Import hash - a hash created based on the imports in the sample.'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|impfuzzy' => array('desc' => __('Import fuzzy hash - a fuzzy hash created based on the imports in the sample.'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|pehash' => array('desc' => __('A filename and a peHash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha224' => array('desc' => __('A filename and a SHA-224 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha384' => array('desc' => __('A filename and a SHA-384 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha512' => array('desc' => __('A filename and a SHA-512 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha512/224' => array('desc' => __('A filename and a SHa-512/224 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha512/256' => array('desc' => __('A filename and a SHA-512/256 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha3-224' => array('desc' => __('A filename and an SHA3-224 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha3-256' => array('desc' => __('A filename and an SHA3-256 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha3-384' => array('desc' => __('A filename and an SHA3-384 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'filename|sha3-512' => array('desc' => __('A filename and an SHA3-512 hash separated by a |'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
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
            'dns-soa-email' => array('desc' => __('RFC 1035 mandates that DNS zones should have a SOA (Statement Of Authority) record that contains an email address where a PoC for the domain could be contacted. This can sometimes be used for attribution/linkage between different domains even if protected by whois privacy'), 'default_category' => 'Attribution', 'to_ids' => 0),
            'size-in-bytes' => array('desc' => __('Size expressed in bytes'), 'default_category' => 'Other', 'to_ids' => 0),
            'counter' => array('desc' => __('An integer counter, generally to be used in objects'), 'default_category' => 'Other', 'to_ids' => 0),
            'integer' => array('desc' => __('A generic integer generally to be used in objects'), 'default_category' => 'Other', 'to_ids' => 0),
            'datetime' => array('desc' => __('Datetime in the ISO 8601 format'), 'default_category' => 'Other', 'to_ids' => 0),
            'port' => array('desc' => __('Port number'), 'default_category' => 'Network activity', 'to_ids' => 0),
            'ip-dst|port' => array('desc' => __('IP destination and port number separated by a |'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'ip-src|port' => array('desc' => __('IP source and port number separated by a |'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'hostname|port' => array('desc' => __('Hostname and port number separated by a |'), 'default_category' => 'Network activity', 'to_ids' => 1),
            'mac-address' => array('desc' => __('MAC address'), 'default_category' => 'Network activity', 'to_ids' => 0),
            'mac-eui-64' => array('desc' => __('MAC EUI-64 address'), 'default_category' => 'Network activity', 'to_ids' => 0),
            // verify IDS flag defaults for these
            'email-dst-display-name' => array('desc' => __('Email destination display name'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-src-display-name' => array('desc' => __('Email source display name'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-header' => array('desc' => __('Email header'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-reply-to' => array('desc' => __('Email reply to header'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-x-mailer' => array('desc' => __('Email x-mailer header'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-mime-boundary' => array('desc' => __('The email mime boundary separating parts in a multipart email'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-thread-index' => array('desc' => __('The email thread index header'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'email-message-id' => array('desc' => __('The email message ID'), 'default_category' => 'Payload delivery', 'to_ids' => 0),
            'github-username' => array('desc' => __('A GitHub user name'), 'default_category' => 'Social network', 'to_ids' => 0),
            'github-repository' => array('desc' => __('A Github repository'), 'default_category' => 'Social network', 'to_ids' => 0),
            'github-organisation' => array('desc' => __('A GitHub organisation'), 'default_category' => 'Social network', 'to_ids' => 0),
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
            'azure-application-id' => array('desc' => __('Azure Application ID.'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'chrome-extension-id' => array('desc' => __('Chrome extension id'), 'default_category' => 'Payload delivery', 'to_ids' => 1),
            'cortex' => array('desc' => __('Cortex analysis result'), 'default_category' => 'External analysis', 'to_ids' => 0),
            'boolean' => array('desc' => __('Boolean value - to be used in objects'), 'default_category' => 'Other', 'to_ids' => 0),
            'anonymised' => array('desc' => __('Anonymised value - described with the anonymisation object via a relationship'),  'formdesc' => __('Anonymised value - described with the anonymisation object via a relationship.'), 'default_category' => 'Other', 'to_ids' => 0)
            // Not convinced about this.
            //'url-regex' => array('desc' => '', 'default_category' => 'Person', 'to_ids' => 0),
        );
    }

    private function findAttributeByValue(array $attribute)
    {
        $type = $attribute['type'];
        $conditions = [
            'Attribute.event_id' => $attribute['event_id'],
            'Attribute.type' => $type,
            'Attribute.deleted' => 0,
            'Attribute.object_id' => 0,
        ];

        if (isset($attribute['category'])) {
            $conditions['Attribute.category'] = $attribute['category'];
        }

        if (in_array($type, $this->getCompositeTypes(), true)) {
            $value = explode('|', $attribute['value']);
            $conditions['Attribute.value1'] = $value[0];
            $conditions['Attribute.value2'] = $value[1];
        } else {
            $conditions['Attribute.value1'] = $attribute['value'];
        }

        if (isset($attribute['id'])) {
            $conditions['Attribute.id !='] = $attribute['id'];
        }

        return $this->find('first', [
            'recursive' => -1,
            'conditions' => $conditions,
            'fields' => ['Attribute.id', 'Attribute.uuid']
        ]);
    }

    public function enrichmentRouter($options)
    {
        if (Configure::read('MISP.background_jobs')) {

            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob(
                $options['user'],
                Job::WORKER_PRIO,
                'enrichment',
                'Attribute ID: ' . $options['id'] . ' modules: ' . json_encode($options['modules']),
                'Enriching attribute.'
            );

            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::PRIO_QUEUE,
                BackgroundJobsTool::CMD_EVENT,
                [
                    'attribute_enrichment',
                    $options['user']['id'],
                    $options['id'],
                    json_encode($options['modules']),
                    $jobId
                ],
                true,
                $jobId
            );
            return __('Job queued (job ID: %s).', $jobId);
        } else {
            $result = $this->enrichment($options);
            return __('#' . $result . ' attributes have been created during the enrichment process.');
        }
    }

    public function enrichment($params)
    {
        $option_fields = ['user', 'id', 'modules'];
        foreach ($option_fields as $option_field) {
            if (empty($params[$option_field])) {
                throw new MethodNotAllowedException(__('%s not set', $option_field));
            }
        }
        $attribute = $this->fetchAttributes($params['user'], [
            'conditions' => [
                'Attribute.id' => $params['id'],
            ],
            'withAttachments' => 1,
        ]);
        if (empty($attribute)) {
            throw new MethodNotAllowedException('Invalid attribute.');
        }
        $attribute = $attribute[0]['Attribute'];
        $this->Module = ClassRegistry::init('Module');
        $enabledModules = $this->Module->getEnabledModules($params['user']);
        if (empty($enabledModules) || is_string($enabledModules)) {
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
        $attributes_added = 0;
        $initial_objects = array();
        $event_id = $attribute['event_id'];
        $event = $this->Event->find('first', ['conditions' => ['Event.id' => $event_id], 'recursive' => -1]);
        if (empty($event)) {
            throw new MethodNotAllowedException('Invalid event.');
        }
        $object_id = $attribute['object_id'];
        if ($object_id != '0' && empty($initial_objects[$object_id])) {
            $initial_objects[$object_id] = $this->Event->fetchInitialObject($event_id, $object_id);
        }
        foreach ($enabledModules['modules'] as $module) {
            if (in_array($module['name'], $params['modules'])) {
                if (in_array($attribute['type'], $module['mispattributes']['input'])) {
                    $data = array('module' => $module['name'], 'event_id' => $event_id, 'attribute_uuid' => $attribute['uuid']);
                    if (!empty($module['config'])) {
                        $data['config'] = $module['config'];
                    }
                    if (!empty($module['mispattributes']['format']) && $module['mispattributes']['format'] == 'misp_standard') {
                        $data['attribute'] = $attribute;
                    } else {
                        $data[$attribute['type']] = $attribute['value'];
                    }
                    if ($object_id != '0' && !empty($initial_objects[$object_id])) {
                        $attribute['Object'] = $initial_objects[$object_id]['Object'];
                    }
                    $triggerData = $event;
                    $triggerData['Attribute'] = [$attribute];
                    $result = $this->Module->queryModuleServer($data, false, 'Enrichment', false, $triggerData);
                    if ($result === false) {
                        throw new MethodNotAllowedException(h($module['name']) . ' service not reachable.');
                    } else if (!is_array($result)) {
                        continue;
                    }
                    if (!empty($module['mispattributes']['format']) && $module['mispattributes']['format'] == 'misp_standard') {
                        if ($object_id != '0' && !empty($initial_objects[$object_id])) {
                            $result['initialObject'] = $initial_objects[$object_id];
                        }
                        $default_comment = $attribute['value'] . ': enriched via the ' . $module['name'] . ' module.';
                        $attributes_added += $this->Event->processModuleResultsData($params['user'], $result['results'], $event_id, $default_comment, false, false, true);
                    } else {
                        $attributes = $this->Event->handleModuleResult($result, $event_id);
                        foreach ($attributes as $a) {
                            $this->create();
                            $a['distribution'] = $attribute['distribution'];
                            $a['sharing_group_id'] = $attribute['sharing_group_id'];
                            $comment = 'Attribute #' . $attribute['id'] . ' enriched by ' . $module['name'] . '.';
                            if (!empty($a['comment'])) {
                                $a['comment'] .= PHP_EOL . $comment;
                            } else {
                                $a['comment'] = $comment;
                            }
                            $a['type'] = empty($a['default_type']) ? $a['types'][0] : $a['default_type'];
                            $result = $this->save($a);
                            if ($result) {
                                $attributes_added++;
                            }
                        }
                    }
                }
            }
        }
        return $attributes_added;
    }
}
