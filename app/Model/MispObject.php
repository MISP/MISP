<?php
App::uses('AppModel', 'Model');
App::uses('TmpFileTool', 'Tools');
App::uses('AttributeValidationTool', 'Tools');
App::uses('FileAccessTool', 'Tools');

/**
 * @property Event $Event
 * @property SharingGroup $SharingGroup
 * @property MispAttribute $Attribute
 * @property ObjectReference $ObjectReference
 * @property ObjectTemplate $ObjectTemplate
 */
class MispObject extends AppModel
{
    public $name = 'Object';
    public $alias = 'Object';

    public $useTable = 'objects';

    public $actsAs = array(
        'AuditLog',
        'Containable',
        'SysLogLogable.SysLogLogable' => array( // TODO Audit, logable
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'full'),
        'AnalystDataParent'
    );

    public $belongsTo = array(
        'Event' => array(
            'className' => 'Event',
            'foreignKey' => 'event_id'
        ),
        'SharingGroup' => array(
            'className' => 'SharingGroup',
            'foreignKey' => 'sharing_group_id'
        ),
        'ObjectTemplate' => array(
            'className' => 'ObjectTemplate',
            'foreignKey' => false,
            'dependent' => false,
            'conditions' => array('MispObject.template_uuid' => 'ObjectTemplate.uuid')
        )
    );

    public $hasMany = array(
        'Attribute' => array(
            'className' => 'MispAttribute',
            'dependent' => true,
        ),
        'ObjectReference' => array(
            'className' => 'ObjectReference',
            'dependent' => true,
            'foreignKey' => 'object_id'
        ),
    );

    public $validFormats = array(
        'json' => array('json', 'JsonExport', 'json')
    );

    public $shortDist = array(0 => 'Organisation', 1 => 'Community', 2 => 'Connected', 3 => 'All', 4 => ' Sharing Group', 5 => 'Inherit');

    public $validate = array(
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
        'event_id' => ['numeric'],
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
        ),
        'name' => array(
            'stringNotEmpty' => array(
                'rule' => array('stringNotEmpty'),
                'required' => true,
                'on' => 'create'
            ),
        ),
        'meta-category' => array(
            'stringNotEmpty' => array(
                'rule' => array('stringNotEmpty'),
                'required' => true,
                'on' => 'create'
            ),
        ),
        'description' => array(
            'stringNotEmpty' => array(
                'rule' => array('stringNotEmpty'),
                'on' => 'create'
            ),
        ),
        'template_uuid' => array(
            'uuid' => array(
                'rule' => 'uuid',
                'message' => 'Please provide a valid RFC 4122 UUID',
                'required' => true,
                'on' => 'create'
            ),
        ),
        'template_version' => array(
            'numeric' => array(
                'rule' => 'naturalNumber',
                'required' => true,
                'on' => 'create'
            )
        ),
    );

    private $__objectDuplicationCheckCache = [];

    public function buildFilterConditions(&$params)
    {
        $conditions = [];
        if (isset($params['wildcard'])) {
            $temp = array();
            $options = array(
                'filter' => 'wildcard',
                'scope' => 'Object',
                'pop' => false,
                'context' => 'Event'
            );
            $conditions['AND'][] = array('OR' => $this->Event->set_filter_wildcard_attributes($params, $temp, $options));
        } else {
            if (isset($params['ignore'])) {
                $params['to_ids'] = array(0, 1);
                $params['published'] = array(0, 1);
            }
            $simple_params = array(
                'Object' => array(
                    'object_name' => array('function' => 'set_filter_object_name'),
                    'object_template_uuid' => array('function' => 'set_filter_object_template_uuid'),
                    'object_template_version' => array('function' => 'set_filter_object_template_version'),
                    'first_seen' => array('function' => 'set_filter_seen'),
                    'last_seen' => array('function' => 'set_filter_seen'),
                    'deleted' => array('function' => 'set_filter_deleted')
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
                    'uuid' => array('function' => 'set_filter_uuid'),
                    'published' => array('function' => 'set_filter_published')
                ),
                'Attribute' => array(
                    'value' => array('function' => 'set_filter_value'),
                    'category' => array('function' => 'set_filter_simple_attribute'),
                    'type' => array('function' => 'set_filter_simple_attribute'),
                    'object_relation' => array('function' => 'set_filter_simple_attribute'),
                    'tags' => array('function' => 'set_filter_tags', 'pop' => true),
                    'uuid' => array('function' => 'set_filter_uuid'),
                    'deleted' => array('function' => 'set_filter_deleted'),
                    'timestamp' => array('function' => 'set_filter_timestamp'),
                    'attribute_timestamp' => array('function' => 'set_filter_timestamp'),
                    //'first_seen' => array('function' => 'set_filter_seen'),
                    //'last_seen' => array('function' => 'set_filter_seen'),
                    'to_ids' => array('function' => 'set_filter_to_ids'),
                    'comment' => array('function' => 'set_filter_comment')
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
                        if ($scope === 'Attribute') {
                            $subQueryOptions = array(
                                'fields' => ['Attribute.object_id'],
                                'group' => 'Attribute.object_id',
                                'recursive' => -1,
                                'conditions' => array(
                                    'Attribute.object_id NOT' => 0,
                                    $this->Event->{$simple_param_scoped[$param]['function']}($params, $conditions, $options)
                                )
                            );
                            $conditions['AND'][] = $this->subQueryGenerator($this->Attribute, $subQueryOptions, 'Object.id');
                        } else {
                            $conditions = $this->Event->{$simple_param_scoped[$param]['function']}($params, $conditions, $options);
                        }
                    }
                }
            }
        }
        return $conditions;
    }

     // check whether the variable is null or datetime
    public function datetimeOrNull($fields)
    {
        $seen = array_values($fields)[0];
        if ($seen === null) {
            return true;
        }
        return strtotime($seen) !== false;
    }

     public function validateLastSeenValue($fields)
     {
         $ls = $fields['last_seen'];
         if (!isset($this->data['Object']['first_seen']) || $ls === null) {
             return true;
         }
         $converted = $this->Attribute->ISODatetimeToUTC(['Object' => [
             'first_seen' => $this->data['Object']['first_seen'],
             'last_seen' => $ls
         ]], 'Object');
         if ($converted['Object']['first_seen'] > $converted['Object']['last_seen']) {
             return false;
         }
         return true;
     }

    public function afterFind($results, $primary = false)
    {
        foreach ($results as &$v) {
            $object = &$v['Object'];
            if (!empty($object['first_seen'])) {
                $object['first_seen'] = $this->microTimestampToIso($object['first_seen']);
            }
            if (!empty($object['last_seen'])) {
                $object['last_seen'] = $this->microTimestampToIso($object['last_seen']);
            }
        }
        return $results;
    }

    public function beforeSave($options = array())
    {
        // generate UUID if it doesn't exist
        if (empty($this->data['Object']['uuid'])) {
            $this->data['Object']['uuid'] = CakeText::uuid();
        }
        $this->data = $this->Attribute->ISODatetimeToUTC($this->data, $this->alias);
    }

    public function beforeValidate($options = array())
    {
        $object = &$this->data['Object'];
        if (empty($object['comment'])) {
            $object['comment'] = "";
        }
        // generate timestamp if it doesn't exist
        if (empty($object['timestamp'])) {
            $object['timestamp'] = time();
        }
        // parse first_seen different formats
        if (isset($object['first_seen'])) {
            $object['first_seen'] = $object['first_seen'] === '' ? null : $object['first_seen'];
        }
        // parse last_seen different formats
        if (isset($object['last_seen'])) {
            $object['last_seen'] = $object['last_seen'] === '' ? null : $object['last_seen'];
        }
        if (empty($object['template_version'])) {
            $object['template_version'] = 1;
        }
        if (isset($object['deleted']) && empty($object['deleted'])) {
            $object['deleted'] = 0;
        }
        if (!isset($object['distribution']) || $object['distribution'] != 4) {
            $object['sharing_group_id'] = 0;
        }
        if (!isset($object['distribution'])) {
            $object['distribution'] = 5;
        }
        return true;
    }

    public function afterSave($created, $options = array())
    {
        if (!Configure::read('MISP.completely_disable_correlation') && !$created) {
            $object = $this->data['Object'];
            $this->Attribute->Correlation->updateContainedCorrelations($object, 'object', $options);
        }
        if (!empty($this->data['Object']['deleted']) && !$created) {
            $attributes_to_delete = $this->Attribute->find('all', [
                'recursive' => -1,
                'conditions' => [
                    'Attribute.object_id' => $this->id,
                    'Attribute.deleted' => 0
                ]
            ]);
            foreach ($attributes_to_delete as &$attribute_to_delete) {
                $attribute_to_delete['Attribute']['deleted'] = 1;
                unset($attribute_to_delete['Attribute']['timestamp']);
            }
            $this->Attribute->saveMany($attributes_to_delete);
        }
        $workflowErrors = [];
        $logging = [
            'model' => 'Object',
            'action' => $created ? 'add' : 'edit',
            'id' => $this->data['Object']['id'],
        ];
        $this->executeTrigger('object-after-save', $this->data, $workflowErrors, $logging);
        $pubToZmq = $this->pubToZmq('object') && empty($this->data['Object']['skip_zmq']);
        $kafkaTopic = $this->kafkaTopic('object');
        $pubToKafka = $kafkaTopic && empty($this->data['Object']['skip_kafka']);
        if ($pubToZmq || $pubToKafka) {
            $object = $this->find('first', array(
                'conditions' => array('Object.id' => $this->id),
                'recursive' => -1
            ));
            $action = $created ? 'add' : 'edit';
            if (!empty($this->data['Object']['deleted'])) {
                $action = 'soft-delete';
            }
            if ($pubToZmq) {
                $pubSubTool = $this->getPubSubTool();
                $pubSubTool->object_save($object, $action);
            }
            if ($pubToKafka) {
                $kafkaPubTool = $this->getKafkaPubTool();
                $kafkaPubTool->publishJson($kafkaTopic, $object, $action);
            }
        }
        return true;
    }

    public function beforeDelete($cascade = true)
    {
        if (!empty($this->data['Object']['id'])) {
            $pubToZmq = $this->pubToZmq('object');
            $kafkaTopic = $this->kafkaTopic('object');
            if ($pubToZmq || $kafkaTopic) {
                $object = $this->find('first', array(
                    'recursive' => -1,
                    'conditions' => array('Object.id' => $this->data['Object']['id'])
                ));
                if ($pubToZmq) {
                    $pubSubTool = $this->getPubSubTool();
                    $pubSubTool->object_save($object, 'delete');
                }
                if ($kafkaTopic) {
                    $kafkaPubTool = $this->getKafkaPubTool();
                    $kafkaPubTool->publishJson($kafkaTopic, $object, 'delete');
                }
            }
        }
    }

    public function afterDelete()
    {
        if (!empty($this->data[$this->alias]['id'])) {
            $this->ObjectReference->deleteAll(
                array(
                    'ObjectReference.referenced_type' => 1,
                    'ObjectReference.referenced_id' => $this->data[$this->alias]['id'],
                ),
                false
            );
        }
    }

    /**
     * @param array $object
     * @param int $eventId
     * @param int $duplicatedObjectId
     * @param string $duplicateObjectUuid
     * @return bool
     */
    private function checkForDuplicateObjects($object, $eventId, &$duplicatedObjectId, &$duplicateObjectUuid)
    {
        $newObjectAttributes = array();
        if (isset($object['Object']['Attribute'])) {
            $attributeArray = $object['Object']['Attribute'];
        } else {
            $attributeArray = $object['Attribute'];
        }
        foreach ($attributeArray as $attribute) {
            $newObjectAttributes[] = $this->getObjectAttributeHash($attribute);
        }
        // Check for duplicate objects in the current data-set of new objects
        $newObjectAttributeCount = count($newObjectAttributes);
        if (!empty($this->__objectDuplicationCheckCache['new'][$object['Object']['template_uuid']])) {
            foreach ($this->__objectDuplicationCheckCache['new'][$object['Object']['template_uuid']] as $previousNewObject) {
                if ($newObjectAttributeCount === count($previousNewObject)) {
                    if (empty(array_diff($previousNewObject, $newObjectAttributes))) {
                        $duplicatedObjectId = $previousNewObject['Object']['id'];
                        $duplicateObjectUuid = $previousNewObject['Object']['uuid'];
                        return true;
                    }
                }
            }
        }
        $this->__objectDuplicationCheckCache['new'][$object['Object']['template_uuid']][] = $newObjectAttributes;
        if (!isset($this->__objectDuplicationCheckCache[$object['Object']['template_uuid']])) {
            $this->__objectDuplicationCheckCache[$object['Object']['template_uuid']] = $this->find('all', array(
                'recursive' => -1,
                'contain' => array(
                    'Attribute' => array(
                        'fields' => array('value', 'type', 'category', 'object_relation'),
                        'conditions' => array('Attribute.deleted' => 0)
                    )
                ),
                'fields' => array('template_uuid', 'uuid'),
                'conditions' => array('template_uuid' => $object['Object']['template_uuid'], 'Object.deleted' => 0, 'event_id' => $eventId)
            ));
        }
        foreach ($this->__objectDuplicationCheckCache[$object['Object']['template_uuid']] as $existingObject) {
            $temp = array();
            if (!empty($existingObject['Attribute']) && $newObjectAttributeCount === count($existingObject['Attribute'])) {
                foreach ($existingObject['Attribute'] as $existingAttribute) {
                    $temp[] = $this->getObjectAttributeHash($existingAttribute);
                }

                if (empty(array_diff($temp, $newObjectAttributes))) {
                    $duplicatedObjectId = $existingObject['Object']['id'];
                    $duplicateObjectUuid = $existingObject['Object']['uuid'];
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @param array $object
     * @param array $template
     * @return array
     */
    public function fillObjectDataFromTemplate(array $object, array $template)
    {
        $templateFields = array(
            'name' => 'name',
            'meta-category' => 'meta-category',
            'description' => 'description',
            'template_version' => 'version',
            'template_uuid' => 'uuid'
        );
        foreach ($templateFields as $objectField => $templateField) {
            $object['Object'][$objectField] = $template['ObjectTemplate'][$templateField];
        }
        return $object;
    }

    /**
     * @param array $object
     * @param int $eventId
     * @param array $template
     * @param array $user
     * @param string $errorBehaviour
     * @param bool $breakOnDuplicate
     * @return array|array[]|bool|int|mixed|string
     * @throws Exception
     */
    public function saveObject(array $object, $eventId, $template = false, array $user, $errorBehaviour = 'drop', $breakOnDuplicate = false)
    {
        $templateFields = array(
            'name' => 'name',
            'meta-category' => 'meta-category',
            'description' => 'description',
            'template_version' => 'version',
            'template_uuid' => 'uuid'
        );
        if ($template) {
            foreach ($templateFields as $k => $v) {
                $object['Object'][$k] = $template['ObjectTemplate'][$v];
            }
        } else {
            foreach ($templateFields as $k => $v) {
                if (!isset($object['Object'][$k])) {
                    return array('template' => array(__('No valid template found and object lacking template information. (%s)', $k)));
                }
            }
        }
        $object['Object']['event_id'] = $eventId;
        if ($breakOnDuplicate) {
            $duplicatedObjectId = null;
            $duplicateObjectUuid = null;
            $duplicate = $this->checkForDuplicateObjects($object, $eventId, $duplicatedObjectId, $duplicateObjectUuid);
            if ($duplicate) {
                return array('value' => array(__('Duplicate object found (id: %s, uuid: %s). Since breakOnDuplicate is set the object will not be added.', $duplicatedObjectId, $duplicateObjectUuid)));
            }
        }
        $this->create();
        $saveResult = $this->save($object);
        if ($saveResult) {
            $result = $this->id;
            foreach ($object['Attribute'] as $k => $attribute) {
                $object['Attribute'][$k]['object_id'] = $this->id;
                if (
                    (!array_key_exists('first_seen', $object['Attribute'][$k]) || is_null($object['Attribute'][$k]['first_seen'])) &&
                    (array_key_exists('first_seen', $object['Object']) && !is_null($object['Object']['first_seen']))
                ) {
                    $object['Attribute'][$k]['first_seen'] = $object['Object']['first_seen'];
                }
                if (
                    (!array_key_exists('last_seen', $object['Attribute'][$k]) || is_null($object['Attribute'][$k]['last_seen'])) &&
                    (array_key_exists('last_seen', $object['Object']) &&  !is_null($object['Object']['last_seen']))
                ) {
                    $object['Attribute'][$k]['last_seen'] = $object['Object']['last_seen'];
                }
            }
            $this->Attribute->saveAttributes($object['Attribute'], $user);
            $this->Event->captureAnalystData($user, $object['Object'], 'Object', $saveResult['Object']['uuid']);
        } else {
            $result = $this->validationErrors;
        }
        return $result;
    }

    public function buildConditions(array $user)
    {
        if ($user['Role']['perm_site_admin']) {
            return [];
        }

        $sgids = $this->SharingGroup->authorizedIds($user);
        return [
            'AND' => [
                'OR' => [
                    'Event.org_id' => $user['org_id'], // if event is owned by current user org, allow access to all objects
                    'AND' => [
                        $this->Event->createEventConditions($user),
                        'OR' => [
                            'Object.distribution' => array(1, 2, 3, 5),
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

    public function fetchObjectSimple(array $user, $options = array())
    {
        $params = array(
            'conditions' => $this->buildConditions($user),
            'fields' => array(),
        );
        if (isset($options['conditions'])) {
            $params['conditions']['AND'][] = $options['conditions'];
        }
        if (isset($options['fields'])) {
            $params['fields'] = $options['fields'];
        }
        $contain = [];
        if (isset($options['contain'])) {
            $contain = $options['contain'];
        }
        if (empty($contain['Event'])) {
            $contain = ['Event' => ['distribution', 'id', 'user_id', 'orgc_id', 'org_id']];
        }
        $results = $this->find('all', array(
            'conditions' => $params['conditions'],
            'recursive' => -1,
            'fields' => $params['fields'],
            'contain' => $contain,
            'sort' => false
        ));
        return $results;
    }

    // Method that fetches all objects
    // very flexible, it's basically a replacement for find, with the addition that it restricts access based on user
    // options:
    //     fields
    //     contain
    //     conditions
    //     order
    //     group
    public function fetchObjects(array $user, array $options = array())
    {
        $attributeConditions = array();
        if (!$user['Role']['perm_site_admin']) {
            $sgids = $this->SharingGroup->authorizedIds($user);
            $attributeConditions = array(
                'OR' => array(
                    array(
                        '(SELECT events.org_id FROM events WHERE events.id = Attribute.event_id)' => $user['org_id']
                    ),
                    array(
                        'OR' => array(
                            'Attribute.distribution' => array(1, 2, 3, 5),
                            array(
                                'Attribute.distribution' => 4,
                                'Attribute.sharing_group_id' => $sgids,
                            )
                        )
                    )
                )
            );
        }
        $params = array(
            'conditions' => $this->buildConditions($user),
            'recursive' => -1,
            'contain' => array(
                'Event' => array(
                    'fields' => array('id', 'info', 'org_id', 'orgc_id'),
                ),
                'Attribute' => array(
                    'conditions' => $attributeConditions,
                    //'ShadowAttribute',
                    'AttributeTag' => array(
                        'Tag'
                    )
                )
            ),
        );
        if (!empty($options['metadata'])) {
            unset($params['contain']['Attribute']);
        }
        if (empty($options['metadata']) && empty($options['includeAllTags'])) {
            $params['contain']['Attribute']['AttributeTag']['Tag']['conditions']['exportable'] = 1;
        }
        if (isset($options['contain'])) {
            $params['contain'] = array_merge_recursive($params['contain'], $options['contain']);
        }
        if (
            empty($options['metadata']) &&
            Configure::read('MISP.proposals_block_attributes') &&
            isset($options['conditions']['AND']['Attribute.to_ids']) &&
            $options['conditions']['AND']['Attribute.to_ids'] == 1
        ) {
            $this->Attribute->bindModel(array('hasMany' => array('ShadowAttribute' => array('foreignKey' => 'old_id'))));
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
                            'fields' => array('ShadowAttribute.id')
                    )
            );
            $params['contain'] = array_merge($params['contain']['Attribute'], $proposalRestriction);
        }
        if (isset($options['conditions'])) {
            $params['conditions']['AND'][] = $options['conditions'];
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
        if (empty($options['metadata']) && (!$user['Role']['perm_sync'] || !isset($options['deleted']) || !$options['deleted'])) {
            $params['contain']['Attribute']['conditions']['AND']['Attribute.deleted'] = 0;
        }
        if (isset($options['group'])) {
            $params['group'] = array_merge(array('Object.id'), $options['group']);
        }
        if (isset($options['limit'])) {
            $params['limit'] = $options['limit'];
            if (isset($options['page'])) {
                $params['page'] = $options['page'];
            }
        }
        $results = $this->find('all', $params);
        if ($options['enforceWarninglist'] && !isset($this->Warninglist)) {
            $this->Warninglist = ClassRegistry::init('Warninglist');
        }
        $proposals_block_attributes = Configure::read('MISP.proposals_block_attributes');
        if (empty($options['metadata'])) {
            foreach ($results as $key => $object) {
                foreach ($object['Attribute'] as $key2 => $attribute) {
                    if ($options['enforceWarninglist'] && !$this->Warninglist->filterWarninglistAttribute($attribute['Attribute'])) {
                        unset($results[$key][$key2]);
                        continue;
                    }
                    if ($proposals_block_attributes) {
                        if (!empty($attribute['ShadowAttribute'])) {
                            unset($results[$key][$key2]);
                        } else {
                            unset($results[$key][$key2]['ShadowAttribute']);
                        }
                    }
                    if ($options['withAttachments']) {
                        if ($this->Attribute->typeIsAttachment($attribute['type'])) {
                            $encodedFile = $this->Attribute->base64EncodeAttachment($attribute);
                            $results[$key]['Attribute'][$key2]['data'] = $encodedFile;
                        }
                    }
                }
            }
        }
        return $results;
    }

    /**
     * Prepare the template form view's data, setting defaults, sorting elements
     * @param array $template
     * @param array $request
     * @return array
     */
    public function prepareTemplate(array $template, array $request = array())
    {
        usort($template['ObjectTemplateElement'], function ($a, $b) {
            return $a['ui-priority'] < $b['ui-priority'];
        });
        $request_rearranged = array();
        $template_object_elements = $template['ObjectTemplateElement'];
        unset($template['ObjectTemplateElement']);
        if (!empty($request['Attribute'])) {
            foreach ($request['Attribute'] as $attribute) {
                $request_rearranged[$attribute['object_relation']][] = $attribute;
            }
        }
        $typeDefinitions = $this->Event->Attribute->typeDefinitions;
        $categoryDefinitions = $this->Event->Attribute->categoryDefinitions;
        foreach ($template_object_elements as $v) {
            if (empty($request_rearranged[$v['object_relation']])) {
                if (isset($typeDefinitions[$v['type']])) {
                    $v['default_category'] = $typeDefinitions[$v['type']]['default_category'];
                    $v['to_ids'] = $typeDefinitions[$v['type']]['to_ids'];
                    if (empty($v['categories'])) {
                        $v['categories'] = array();
                        foreach ($categoryDefinitions as $catk => $catv) {
                            if (in_array($v['type'], $catv['types'], true)) {
                                $v['categories'][] = $catk;
                            }
                        }
                    }
                    $template['ObjectTemplateElement'][] = $v;
                } else {
                    $template['warnings'][] = 'Missing attribute type "' . $v['type'] . '" found. Omitted template element ("' . $v['object_relation'] . '") that would not pass validation due to this.';
                }
            } else {
                foreach ($request_rearranged[$v['object_relation']] as $request_item) {
                    if (isset($typeDefinitions[$v['type']])) {
                        $v['default_category'] = $request_item['category'];
                        $v['value'] = $request_item['value'];
                        $v['to_ids'] = $request_item['to_ids'];
                        $v['comment'] = $request_item['comment'];
                        if (!empty($request_item['uuid'])) {
                            $v['uuid'] = $request_item['uuid'];
                        }
                        if (isset($request_item['data'])) {
                            $v['data'] = $request_item['data'];
                        }
                        if (empty($v['categories'])) {
                            $v['categories'] = array();
                            foreach ($categoryDefinitions as $catk => $catv) {
                                if (in_array($v['type'], $catv['types'], true)) {
                                    $v['categories'][] = $catk;
                                }
                            }
                        }
                        $v['disable_correlation'] = $request_item['disable_correlation'];
                        $template['ObjectTemplateElement'][] = $v;
                        unset($v['uuid']); // force creating a new attribute if template element entry gets reused
                    } else {
                        $template['warnings'][] = 'Missing attribute type "' . $v['type'] . '" found. Omitted template element ("' . $v['object_relation'] . '") that would not pass validation due to this.';
                    }
                }
            }
        }
        return $template;
    }

    /**
     * Clean the attribute list up from artifacts introduced by the object form
     * @param array $attributes
     * @return array
     * @throws InternalErrorException
     * @throws Exception
     */
    public function attributeCleanup(array $attributes)
    {
        if (empty($attributes['Attribute'])) {
            return $attributes;
        }
        foreach ($attributes['Attribute'] as $k => $attribute) {
            if (isset($attribute['save']) && $attribute['save'] == 0) {
                unset($attributes['Attribute'][$k]);
                continue;
            }
            if (isset($attribute['value_select'])) {
                if ($attribute['value_select'] !== 'Enter value manually') {
                    $attributes['Attribute'][$k]['value'] = $attribute['value_select'];
                }
                unset($attributes['Attribute'][$k]['value_select']);
            }
            if (isset($attribute['Attachment'])) {
                // Check if there were problems with the file upload
                // only keep the last part of the filename, this should prevent directory attacks
                if ((isset($attribute['Attachment']['error']) && $attribute['Attachment']['error'] == 0) ||
                    (!empty($attribute['Attachment']['tmp_name']) && $attribute['Attachment']['tmp_name'] != 'none')
                ) {
                    if (!is_uploaded_file($attribute['Attachment']['tmp_name'])) {
                        throw new InternalErrorException('PHP says file was not uploaded. Are you attacking me?');
                    }
                } else {
                    throw new InternalErrorException('Issues with the file attachment for the ' . $attribute['object_relation'] . ' attribute. The error code returned is ' . $attribute['Attachment']['error']);
                }
                $attributes['Attribute'][$k]['value'] = $attribute['Attachment']['name'];
                unset($attributes['Attribute'][$k]['Attachment']);
                $attributes['Attribute'][$k]['encrypt'] = $attribute['type'] === 'malware-sample' ? 1 : 0;
                $attributes['Attribute'][$k]['data'] = base64_encode(FileAccessTool::readAndDelete($attribute['Attachment']['tmp_name']));
            }
            if (!isset($attributes['Attribute'][$k]['first_seen'])) {
                $attributes['Attribute'][$k]['first_seen'] = null;
            }
            if (!isset($attributes['Attribute'][$k]['last_seen'])) {
                $attributes['Attribute'][$k]['last_seen'] = null;
            }
            unset($attributes['Attribute'][$k]['save']);
        }
        return $attributes;
    }

    /**
     * @param array $user
     * @param int $eventId
     * @param array $attributes
     * @param array $template
     * @param int $threshold
     * @return array
     */
    public function findSimilarObjects(array $user, $eventId, array $attributes, array $template, $threshold = 15)
    {
        $attributeValues = array_column($attributes, 'value');
        $conditions = array(
            'event_id' => $eventId,
            'value1' => $attributeValues,
            'object_id !=' => 0,
        );
        $similarObjects = $this->Attribute->find('all', array(
            'conditions' => $conditions,
            'recursive' => -1,
            'fields' => 'object_id, count(object_id) as similarity_amount',
            'group' => 'object_id',
            'order' => 'similarity_amount DESC'
        ));

        if (empty($similarObjects)) {
            return [0, [], [], []];
        }

        $similar_object_ids = array();
        $similar_object_similarity_amount = array();
        foreach ($similarObjects as $obj) {
            $similar_object_ids[] = $obj['Attribute']['object_id'];
            $similar_object_similarity_amount[$obj['Attribute']['object_id']] = (int)$obj[0]['similarity_amount'];
        }
        $similar_objects_count = count($similar_object_ids);
        $similar_object_ids = array_slice($similar_object_ids, 0, $threshold); // slice to honor the threshold
        $similar_objects = $this->fetchObjects($user, array(
            'conditions' => array(
                'Object.id' => $similar_object_ids,
                'Object.template_uuid' => $template['ObjectTemplate']['uuid']
            )
        ));
        foreach ($similar_objects as $key => $obj) {
            $similar_objects[$key]['Object']['similarity_amount'] = $similar_object_similarity_amount[$obj['Object']['id']]; // sorting function cannot use external variables
        }
        usort($similar_objects, function ($a, $b) { // fetch Object returns object sorted by IDs, force the sort by the similarity amount
            if ($a['Object']['similarity_amount'] == $b['Object']['similarity_amount']) {
                return 0;
            }
            return ($a['Object']['similarity_amount'] > $b['Object']['similarity_amount']) ? -1 : 1;
        });

        $simple_flattened_attribute = [];
        $simple_flattened_attribute_noval = [];
        foreach ($attributes as $k => $attribute) {
            $curFlat = $attribute['object_relation'] . '.' . $attribute['type'] . '.' .$attribute['value'];
            $simple_flattened_attribute[$curFlat] = $k;
            $curFlatNoval = $attribute['object_relation'] . '.' . $attribute['type'];
            $simple_flattened_attribute_noval[$curFlatNoval] = $k;
        }

        return [$similar_objects_count, $similar_objects, $simple_flattened_attribute, $simple_flattened_attribute_noval];
    }

    // Set Object's *-seen (and ObjectAttribute's *-seen and ObjectAttribute's value if requested) to the provided *-seen value
    // Therefore, synchronizing the 3 values
    public function syncObjectAndAttributeSeen($object, $forcedSeenOnElements, $applyOnAttribute=True) {
        if (empty($forcedSeenOnElements)) {
            return $object;
        }
        if (isset($forcedSeenOnElements['first_seen'])) {
            $object['Object']['first_seen'] = $forcedSeenOnElements['first_seen'];
        }
        if (isset($forcedSeenOnElements['last_seen'])) {
            $object['Object']['last_seen'] = $forcedSeenOnElements['last_seen'];
        }
        if ($applyOnAttribute) {
            if (isset($object['Attribute'])) {
                $attributes = $object['Attribute'];
            } else {
                $attributes = $this->find('first', array(
                    'conditions' => array('id' => $object['Object']['id']),
                    'contain' => array('Attribute')
                ))['Attribute'];
            }
            foreach($attributes as $i => $attribute) {
                if (isset($forcedSeenOnElements['first_seen'])) {
                    $attributes[$i]['first_seen'] = $forcedSeenOnElements['first_seen'];
                    if ($attribute['object_relation'] == 'first-seen') {
                        $attributes[$i]['value'] = $forcedSeenOnElements['first_seen'];
                    }
                } elseif (isset($forcedSeenOnElements['last_seen'])) {
                    $attributes[$i]['last_seen'] = $forcedSeenOnElements['last_seen'];
                    if ($attribute['object_relation'] == 'last-seen') {
                        $attributes[$i]['value'] = $forcedSeenOnElements['last_seen'];
                    }
                }
            }
            $object['Attribute'] = $attributes;
        }
        return $object;
    }

    /**
     * @param array $object
     * @param array $objectToSave
     * @param bool $onlyAddNewAttribute
     * @param array $user
     * @return array|int
     * @throws JsonException
     */
    public function deltaMerge(array $object, array $objectToSave, $onlyAddNewAttribute=false, array $user)
    {
        if (!isset($objectToSave['Object'])) {
            $dataToBackup = array('ObjectReferences', 'Attribute', 'ShadowAttribute');
            $backup = array();
            foreach ($dataToBackup as $dtb) {
                if (isset($objectToSave[$dtb])) {
                    $backup[$dtb] = $objectToSave[$dtb];
                    unset($objectToSave[$dtb]);
                }
            }
            $objectToSave = array('Object' => $objectToSave);
            foreach ($dataToBackup as $dtb) {
                if (isset($backup[$dtb])) {
                    $objectToSave[$dtb] = $backup[$dtb];
                }
            }
            unset($dataToBackup);
        }
        if (isset($objectToSave['Object']['comment'])) {
            $object['Object']['comment'] = $objectToSave['Object']['comment'];
        }
        if (isset($objectToSave['Object']['template_version'])) {
            $object['Object']['template_version'] = $objectToSave['Object']['template_version'];
        }
        if (isset($objectToSave['Object']['distribution'])) {
            $object['Object']['distribution'] = $objectToSave['Object']['distribution'];
            if ($object['Object']['distribution'] == 4) {
                $object['Object']['sharing_group_id'] = $objectToSave['Object']['sharing_group_id'];
            }
        }
        $time = time();
        $object['Object']['timestamp'] = $time;
        $forcedSeenOnElements = array();
        if (isset($objectToSave['Object']['first_seen'])) {
            $forcedSeenOnElements['first_seen'] = $objectToSave['Object']['first_seen'];
        }
        if (isset($objectToSave['Object']['last_seen'])) {
            $forcedSeenOnElements['last_seen'] = $objectToSave['Object']['last_seen'];
        }
        $object = $this->syncObjectAndAttributeSeen($object, $forcedSeenOnElements, false);
        $saveResult = $this->save($object);
        if ($saveResult === false) {
            return $this->validationErrors;
        }

        $this->Event->captureAnalystData($user, $objectToSave['Object'], 'Object', $saveResult['Object']['uuid']);

        if (!$onlyAddNewAttribute) {
            $checkFields = array('category', 'value', 'to_ids', 'distribution', 'sharing_group_id', 'comment', 'disable_correlation', 'first_seen', 'last_seen');
            if (!empty($objectToSave['Attribute'])) {
                foreach ($objectToSave['Attribute'] as $newKey => $newAttribute) {
                    foreach ($object['Attribute'] as $origKey => $originalAttribute) {
                        if (!empty($newAttribute['uuid'])) {
                            if ($newAttribute['uuid'] == $originalAttribute['uuid']) {
                                $different = false;
                                foreach ($checkFields as $f) {
                                    if ($f == 'sharing_group_id' && empty($newAttribute[$f])) {
                                        $newAttribute[$f] = 0;
                                    }
                                    if (isset($newAttribute[$f]) && $this->attributeValueDifferent($originalAttribute[$f], $newAttribute[$f], $f)) {
                                        $different = true;
                                    }
                                }
                                if ($different) {
                                    $newAttribute['id'] = $originalAttribute['id'];
                                    $newAttribute['event_id'] = $object['Object']['event_id'];
                                    $newAttribute['object_id'] = $object['Object']['id'];
                                    $newAttribute['timestamp'] = $time;
                                    $result = $this->Event->Attribute->save(array('Attribute' => $newAttribute), array('fieldList' => MispAttribute::EDITABLE_FIELDS));
                                    if ($result) {
                                        $this->Event->Attribute->AttributeTag->handleAttributeTags($user, $newAttribute, $newAttribute['event_id'], $capture=true);
                                    } else {
                                        $this->Event->Attribute->logDropped($user, $newAttribute, 'edit');
                                    }
                                }
                                unset($object['Attribute'][$origKey]);
                                continue 2;
                            }
                        }
                    }
                    $newAttribute['event_id'] = $object['Object']['event_id'];
                    $newAttribute['object_id'] = $object['Object']['id'];
                    // Set seen of object at attribute level
                    if (isset($forcedSeenOnElements['first_seen'])) {
                        $newAttribute['first_seen'] = empty($newAttribute['first_seen']) ? $forcedSeenOnElements['first_seen'] : $newAttribute['first_seen'];
                        if ($newAttribute['object_relation'] == 'first-seen') {
                            $newAttribute['value'] = $forcedSeenOnElements['first_seen'];
                        }
                    }
                    if (isset($forcedSeenOnElements['last_seen'])) {
                        $newAttribute['last_seen'] = empty($newAttribute['last_seen']) ? $forcedSeenOnElements['last_seen'] : $newAttribute['last_seen'];
                        if ($newAttribute['object_relation'] == 'last-seen') {
                            $newAttribute['value'] = $forcedSeenOnElements['last_seen'];
                        }
                    }
                    if (!isset($newAttribute['distribution'])) {
                        $newAttribute['distribution'] = $this->Event->Attribute->defaultDistribution();
                    }
                    $this->Event->Attribute->create();
                    $saveResult = $this->Event->Attribute->save($newAttribute);
                    if ($saveResult) {
                        $newAttribute['id'] = $this->Event->Attribute->id;
                        $this->Event->Attribute->AttributeTag->handleAttributeTags($user, $newAttribute, $newAttribute['event_id'], $capture=true);
                    } else {
                        $this->Event->Attribute->logDropped($user, $newAttribute, 'add');
                    }
                    unset($objectToSave['Attribute'][$newKey]);
                }
                foreach ($object['Attribute'] as $originalAttribute) {
                    $originalAttribute['deleted'] = 1;
                    $this->Event->Attribute->save($originalAttribute, array('fieldList' => MispAttribute::EDITABLE_FIELDS));
                }
            }
        } else { // we only add the new attribute
            $newAttribute = $objectToSave['Attribute'][0];
            $newAttribute['event_id'] = $object['Object']['event_id'];
            $newAttribute['object_id'] = $object['Object']['id'];
            // Set seen of object at attribute level
            if (
                (!array_key_exists('first_seen', $newAttribute) || is_null($newAttribute['first_seen'])) &&
                (!array_key_exists('first_seen', $object['Object']) && !is_null($object['Object']['first_seen']))
            ) {
                $newAttribute['first_seen'] = $object['Object']['first_seen'];
            }
            if (
                (!array_key_exists('last_seen', $newAttribute) || is_null($newAttribute['last_seen'])) &&
                (!array_key_exists('last_seen', $object['Object']) && !is_null($object['Object']['last_seen']))
            ) {
                $newAttribute['last_seen'] = $object['Object']['last_seen'];
            }
            $saveAttributeResult = $this->Attribute->saveAttributes(array($newAttribute), $user);
            return $saveAttributeResult ? $this->id : $this->Attribute->validationErrors;
        }
        return $this->id;
    }

    /**
     * @param array $object
     * @param int $eventId
     * @param array $user
     * @param bool $unpublish
     * @param false $breakOnDuplicate
     * @param array|false $parentEvent
     * @return bool|string
     * @throws Exception
     */
    public function captureObject($object, $eventId, $user, $unpublish = true, $breakOnDuplicate = false, $parentEvent = false)
    {
        $this->create();
        if (!isset($object['Object'])) {
            $object = array('Object' => $object);
        }
        if (!empty($object['Object']['breakOnDuplicate']) || $breakOnDuplicate) {
            $duplicatedObjectId = null;
            $duplicateObjectUuid = null;
            $duplicate = $this->checkForDuplicateObjects($object, $eventId, $duplicatedObjectId, $duplicateObjectUuid);
            if ($duplicate) {
                $this->loadLog()->createLogEntry($user, 'add', 'Object', 0,
                    __('Object dropped due to it being a duplicate (ID: %s, UUID: %s) and breakOnDuplicate being requested for Event %s', $duplicatedObjectId, $duplicateObjectUuid, $eventId),
                    'Duplicate object found.'
                );
                return true;
            }
        }
        unset($object['Object']['id']);
        $object['Object']['event_id'] = $eventId;
        if (!$this->save($object)) {
            $this->loadLog()->createLogEntry($user, 'add', 'Object', 0,
                'Object dropped due to validation for Event ' . $eventId . ' failed: ' . $object['Object']['name'],
                'Validation errors: ' . json_encode($this->validationErrors) . ' Full Object: ' . json_encode($object)
            );
            return 'fail';
        }
        if ($unpublish) {
            $this->Event->unpublishEvent($eventId);
        }
        $objectId = $this->id;
        if (!empty($object['Object']['Attribute'])) {
            foreach ($object['Object']['Attribute'] as $attribute) {
                if (!empty($object['Object']['deleted'])) {
                    $attribute['deleted'] = 1;
                }
                $this->Attribute->captureAttribute($attribute, $eventId, $user, $objectId, false, $parentEvent);
            }
        }
        if (empty($object['Object']['uuid'])) {
            $t = $this->find('first', [
                'recursive' => -1,
                'fields' => ['uuid'],
                'conditions' => ['id' => $objectId]
            ]);
            $object['Object']['uuid'] = $t['Object']['uuid'];
        }
        $this->Event->captureAnalystData($user, $object['Object'], 'Object', $object['Object']['uuid']);
        return true;
    }

    public function editObject($object, array $event, $user, $log, $force = false, &$nothingToChange = false)
    {
        $eventId = $event['Event']['id'];
        $object['event_id'] = $eventId;
        if (isset($object['distribution']) && $object['distribution'] == 4) {
            if (!empty($object['SharingGroup'])) {
                $object['sharing_group_id'] = $this->SharingGroup->captureSG($object['SharingGroup'], $user);
            } elseif (!empty($object['sharing_group_id'])) {
                if (!$this->SharingGroup->checkIfAuthorised($user, $object['sharing_group_id'])) {
                    unset($object['sharing_group_id']);
                }
            }
            if (empty($object['sharing_group_id'])) {
                $object_short = (isset($object['meta-category']) ? $object['meta-category'] : 'N/A') . '/' . (isset($object['name']) ? $object['name'] : 'N/A') . ' ' . (isset($object['uuid']) ? $object['uuid'] : 'N/A');
                $this->loadLog()->createLogEntry($user, 'edit', 'MispObject', 0,
                    'Object dropped due to invalid sharing group for Event ' . $eventId . ' failed: ' . $object_short,
                    'Validation errors: ' . json_encode($this->validationErrors) . ' Full Object: ' . json_encode($object)
                );
                return 'Invalid sharing group choice.';
            }
        }
        if (isset($object['uuid'])) {
            $existingObject = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('Object.uuid' => $object['uuid'])
            ));
            if (empty($existingObject)) {
                return $this->captureObject($object, $eventId, $user);
            } else {
                if ($existingObject['Object']['event_id'] != $eventId) {
                    $change = 'An object was blocked from being saved due to a duplicate UUID. The uuid in question is: ' . $object['uuid'] . '. This can also be due to the same object (or an object with the same UUID) existing in a different event)';
                    $this->loadLog()->createLogEntry($user, 'edit','MispObject', 0, 'Duplicate UUID found in object', $change);
                    return true;
                }
                if (isset($object['timestamp'])) {
                    if ($force || $existingObject['Object']['timestamp'] >= $object['timestamp']) {
                        $nothingToChange = true;
                        return true;
                    }
                } else {
                    $object['timestamp'] = time();
                }
            }
        } else {
            return $this->captureObject($object, $eventId, $user);
        }
        // At this point we have an existingObject that we can edit
        $recoverFields = array(
            'name',
            'meta-category',
            'description',
            'template_uuid',
            'template_version',
            'distribution',
            'sharing_group_id',
            'comment',
            'deleted'
        );
        foreach ($recoverFields as $rF) {
            if (!isset($object[$rF])) {
                $object[$rF] = $existingObject['Object'][$rF];
            }
        }
        $object['id'] = $existingObject['Object']['id'];
        $object['uuid'] = $existingObject['Object']['uuid'];
        $object['event_id'] = $eventId;
        if ($object['distribution'] == 4) {
            $object['sharing_group_id'] = $this->SharingGroup->captureSG($object['SharingGroup'], $user);
        }
        if (!$this->save($object)) {
            $this->loadLog()->createLogEntry($user, 'edit', 'MispObject', 0,
                'Object dropped due to validation for Event ' . $eventId . ' failed: ' . $object['name'],
                'Validation errors: ' . json_encode($this->validationErrors) . ' Full Object: ' . json_encode($object)
            );
            return $this->validationErrors;
        }
        $this->Event->captureAnalystData($user, $object, 'Object', $object['uuid']);
        if (!empty($object['Attribute'])) {
            $attributes = [];
            foreach ($object['Attribute'] as $attribute) {
                if (!empty($object['deleted'])) {
                    $attribute['deleted'] = 1;
                }
                $result = $this->Attribute->editAttribute($attribute, $event, $user, $object['id'], false, $force);
                if (is_array($result)) {
                    $attributes[] = $result;
                }
            }
            $this->Attribute->editAttributeBulk($attributes, $event, $user);
            $this->Attribute->editAttributePostProcessing($attributes, $event, $user);
        }
        return true;
    }

    public function deleteObject(array $object, $hard=false, $unpublish=true)
    {
        $id = $object['Object']['id'];
        if ($hard) {
            // For a hard delete, simply run the delete, it will cascade
            $this->delete($id);
        } else {
            // For soft deletes, sanitise the object first if the setting is enabled
            if (Configure::read('Security.sanitise_attribute_on_delete')) {
                $object['Object']['name'] = 'N/A';
                $object['Object']['category'] = 'N/A';
                $object['Object']['description'] = 'N/A';
                $object['Object']['template_uuid'] = 'N/A';
                $object['Object']['template_version'] = 0;
                $object['Object']['comment'] = '';
            }
            $date = new DateTime();
            $object['Object']['deleted'] = 1;
            $object['Object']['timestamp'] = $date->getTimestamp();
            $saveResult = $this->save($object);
            if (!$saveResult) {
                return $saveResult;
            }
            foreach ($object['Attribute'] as $attribute) {
                if (Configure::read('Security.sanitise_attribute_on_delete')) {
                    $attribute['category'] = 'Other';
                    $attribute['type'] = 'comment';
                    $attribute['value'] = 'deleted';
                    $attribute['comment'] = '';
                    $attribute['to_ids'] = 0;
                }
                $attribute['deleted'] = 1;
                $attribute['timestamp'] = $date->getTimestamp();
                $this->Attribute->save(array('Attribute' => $attribute));
                $this->Event->ShadowAttribute->deleteAll(
                    array('ShadowAttribute.old_id' => $attribute['id']),
                    false
                );
            }
            if ($unpublish) {
                $this->Event->unpublishEvent($object['Event']['id']);
            }
            $object_refs = $this->ObjectReference->find('all', array(
                'conditions' => array(
                    'ObjectReference.referenced_type' => 1,
                    'ObjectReference.referenced_id' => $id,
                ),
                'recursive' => -1
            ));
            foreach ($object_refs as $ref) {
                $ref['ObjectReference']['deleted'] = 1;
                $this->ObjectReference->save($ref);
            }
        }
        return true;
    }

    /**
     * @param int $id
     * @param false|int $timestamp
     * @return array|bool|mixed|null
     * @throws Exception
     */
    public function updateTimestamp($id, $timestamp = false)
    {
        $object = [
            'Object' => [
                'id' => $id,
                'timestamp' => $timestamp === false ? time() : $timestamp,
                'skip_zmq' => 1,
                'skip_kafka' => 1,
            ],
        ];
        return $this->save($object, ['fieldList' => ['timestamp'], 'skipAuditLog' => true]);
    }

    // Hunt down all LEDA and CASTOR clones
    public function removeOrphanedObjects()
    {
        $orphans = $this->find('list', array(
            'fields' => array('Object.id', 'Object.id'),
            'conditions' => array('Event.id' => null),
            'contain' => array('Event' => array('fields' => array('id')))
        ));
        foreach ($orphans as $orphan) {
            $this->delete($orphan);
        }
        return count($orphans);
    }

    /**
     * @param array $user
     * @param int $eventId
     * @param array $selectedAttributeIds
     * @return array|array[]
     * @throws Exception
     */
    public function validObjectsFromAttributeTypes(array $user, $eventId, array $selectedAttributeIds)
    {
        $attributes = $this->Attribute->fetchAttributesSimple($user, [
            'conditions' => [
                'Attribute.id' => $selectedAttributeIds,
                'Attribute.event_id' => $eventId,
                'Attribute.object_id' => 0,
            ],
            'fields' => ['Attribute.type'],
        ]);
        if (empty($attributes)) {
            return array('templates' => array(), 'types' => array());
        }

        $attributeTypes = array_column(array_column($attributes, 'Attribute'), 'type');
        return $this->ObjectTemplate->fetchPossibleTemplatesBasedOnTypes($attributeTypes);
    }

    public function groupAttributesIntoObject(array $user, $event_id, array $object, $template, array $selected_attribute_ids, array $selected_object_relation_mapping, $hard_delete_attribute)
    {
        $saved_object_id = $this->saveObject($object, $event_id, $template, $user);
        if (!is_numeric($saved_object_id)) {
            return $saved_object_id;
        }

        $existing_attributes = $this->Attribute->fetchAttributes($user, array('conditions' => array(
            'Attribute.id' => $selected_attribute_ids,
            'Attribute.event_id' => $event_id,
            'Attribute.object_id' => 0
        )));

        if (empty($existing_attributes)) {
            return __('Selected Attributes do not exist.');
        }
        $event = array('Event' => $existing_attributes[0]['Event']);

        // Duplicate the attribute and its context, otherwise connected instances will drop the duplicated UUID
        foreach ($existing_attributes as $existing_attribute) {
            if (isset($selected_object_relation_mapping[$existing_attribute['Attribute']['id']])) {
                $sightings = $this->Event->Sighting->attachToEvent($event, $user, $existing_attribute['Attribute']['id']);
                $object_relation = $selected_object_relation_mapping[$existing_attribute['Attribute']['id']];
                $created_attribute = $existing_attribute['Attribute'];
                unset($created_attribute['timestamp']);
                unset($created_attribute['id']);
                unset($created_attribute['uuid']);
                $created_attribute['object_relation'] = $object_relation;
                $created_attribute['object_id'] = $saved_object_id;
                if (isset($existing_attribute['AttributeTag'])) {
                    $created_attribute['AttributeTag'] = $existing_attribute['AttributeTag'];
                }
                if (!empty($sightings)) {
                    $created_attribute['Sighting'] = $sightings;
                }
                $this->Attribute->captureAttribute($created_attribute, $event_id, $user, $saved_object_id);
                $this->Attribute->deleteAttribute($existing_attribute['Attribute']['id'], $user, $hard_delete_attribute);
            }
        }
        return $saved_object_id;
    }

    public function resolveUpdatedTemplate($template, $object, $update_template_available = false)
    {
        $toReturn = array(
            'updateable_attribute' => false,
            'not_updateable_attribute' => false,
            'newer_template_version' => false,
            'original_template_unkown' => false,
            'template' => $template
        );
        $newer_template = $this->ObjectTemplate->find('first', array(
            'conditions' => array(
                'ObjectTemplate.uuid' => $object['Object']['template_uuid'],
                'ObjectTemplate.version >' => $object['Object']['template_version'],
            ),
            'recursive' => -1,
            'contain' => array(
                'ObjectTemplateElement'
            ),
            'order' => array('ObjectTemplate.version DESC')
        ));
        $template_difference = array();
        if (!empty($newer_template)) {
            $toReturn['newer_template_version'] = $newer_template['ObjectTemplate']['version'];
            $newer_template_temp = Hash::remove(Hash::remove($newer_template['ObjectTemplateElement'], '{n}.id'), '{n}.object_template_id');
            if (!empty($template)) {
                // ignore IDs for comparison
                $cur_template_temp = Hash::remove(Hash::remove($template['ObjectTemplateElement'], '{n}.id'), '{n}.object_template_id');

                // check how current template is included in the newer
                foreach ($cur_template_temp as $cur_obj_rel) {
                    $flag_sim = false;
                    foreach ($newer_template_temp as $newer_obj_rel) {
                        $tmp = Hash::diff($cur_obj_rel, $newer_obj_rel);
                        if (count($tmp) == 0) {
                            $flag_sim = true;
                            break;
                        }
                    }
                    if (!$flag_sim) {
                        $template_difference[] = $cur_obj_rel;
                    }
                }
            } else { // original template unkown
                $toReturn['original_template_unkown'] = true;
                $unmatched_attributes = array();
                foreach ($object['Attribute'] as $i => $attribute) {
                    $flag_match = false;
                    foreach ($newer_template_temp as $newer_obj_rel) {
                        if (
                            $newer_obj_rel['object_relation'] == $attribute['object_relation'] &&
                            $newer_obj_rel['type'] == $attribute['type']
                        ) {
                            $flag_match = true;
                            break;
                        }
                    }
                    if (!$flag_match) {
                        $unmatched_attributes[] = $attribute;
                    }
                }

                // simulate unkown template from the attribute
                foreach ($unmatched_attributes as $unmatched_attribute) {
                    $template_difference[] = [
                        'object_relation' => $unmatched_attribute['object_relation'],
                        'type' => $unmatched_attribute['type']
                    ];
                }
            }
            $toReturn['updateable_attribute'] = $object['Attribute'];
            $toReturn['not_updateable_attribute'] = array();

            if (!empty($template_difference)) { // older template not completely embeded in newer
                foreach ($template_difference as $temp_diff_element) {
                    foreach ($object['Attribute'] as $i => $attribute) {
                        if (
                            $attribute['object_relation'] == $temp_diff_element['object_relation']
                            && $attribute['type'] == $temp_diff_element['type']
                        ) { // This attribute cannot be merged automatically
                            $attribute['merge-possible'] = false;
                            $toReturn['not_updateable_attribute'][] = $attribute;
                            unset($toReturn['updateable_attribute'][$i]);
                        }
                    }
                }
            }
        }

        if ($update_template_available) { // template version bump requested
            $toReturn['template'] = $newer_template; // bump the template version
        }
        return $toReturn;
    }

    public function reviseObject($revised_object, $object, $template)
    {
        $revised_object_both = array('mergeable' => array(), 'notMergeable' => array());

        // Loop through attributes to inject and perform the correct action
        // (inject, duplicate, add warnings, ...) when applicable
        foreach ($revised_object['Attribute'] as $attribute_to_inject) {
            $flag_no_collision = true;
            foreach ($object['Attribute'] as $attribute) {
                if (
                    $attribute['object_relation'] == $attribute_to_inject['object_relation']
                    && $attribute['type'] == $attribute_to_inject['type']
                    && $attribute['value'] !== $attribute_to_inject['value']
                ) { // Collision on value
                    $multiple = !empty(Hash::extract($template['ObjectTemplateElement'], sprintf('{n}[object_relation=%s][type=%s][multiple=true]', $attribute['object_relation'], $attribute['type'])));
                    if ($multiple) { // if multiple is set, check if an entry exists already
                        $flag_entry_exists = false;
                        foreach ($object['Attribute'] as $attr) {
                            if (
                                $attr['object_relation'] == $attribute_to_inject['object_relation']
                                && $attr['type'] == $attribute_to_inject['type']
                                && $attr['value'] === $attribute_to_inject['value']
                            ) {
                                $flag_entry_exists = true;
                                break;
                            }
                        }
                        if (!$flag_entry_exists) { // entry does no exists, can be duplicated
                            $attribute_to_inject['is_multiple'] = true;
                            $revised_object_both['mergeable'][] = $attribute_to_inject;
                            $object['Attribute'][] = $attribute_to_inject;
                        }
                    } else { // Collision on value, multiple not set => propose overwrite
                        $attribute_to_inject['current_value'] = $attribute['value'];
                        $attribute_to_inject['merge-possible'] = true; // the user can still swap value
                        $revised_object_both['notMergeable'][] = $attribute_to_inject;
                    }
                    $flag_no_collision = false;
                } else if (
                    $attribute['object_relation'] == $attribute_to_inject['object_relation']
                     && $attribute['type'] == $attribute_to_inject['type']
                     && $attribute['value'] === $attribute_to_inject['value']
                ) { // all good, they are basically the same, do nothing
                    $revised_object_both['mergeable'][] = $attribute_to_inject;
                    $flag_no_collision = false;
                }
            }
            if ($flag_no_collision) { // no collision, nor equalities => inject it straight away
                $revised_object_both['mergeable'][] = $attribute_to_inject;
                $object['Attribute'][] = $attribute_to_inject;
            }
        }
        return array(
            'object' => $object,
            'revised_object_both' => $revised_object_both
        );
    }

    public function restSearch($user, $returnFormat, $filters, $paramsOnly = false, $jobId = false, &$elementCounter = 0, &$renderView = false)
    {
        if (!isset($this->validFormats[$returnFormat][1])) {
            throw new NotFoundException('Invalid output format.');
        }
        App::uses($this->validFormats[$returnFormat][1], 'Export');
        $exportTool = new $this->validFormats[$returnFormat][1]();
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
        $conditions = $this->buildFilterConditions($filters);
        $params = array(
            'conditions' => $conditions,
            'fields' => array('Attribute.*', 'Event.org_id', 'Event.distribution', 'Object.*'),
            'withAttachments' => !empty($filters['withAttachments']) ? $filters['withAttachments'] : 0,
            'enforceWarninglist' => !empty($filters['enforceWarninglist']) ? $filters['enforceWarninglist'] : 0,
            'includeAllTags' => !empty($filters['includeAllTags']) ? $filters['includeAllTags'] : 0,
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
            'allow_proposal_blocking' => !empty($filters['allow_proposal_blocking']) ? $filters['allow_proposal_blocking'] : 0,
            'metadata' => !empty($filters['metadata']) ? $filters['metadata'] : 0,
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
        if (isset($filters['deleted'])) {
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
        if (!empty($filters['metadata'])) {
            $params['metadata'] = $filters['metadata'];
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
            'scope' => 'Object',
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
            $memory_in_mb = $this->convert_to_memory_limit_to_mb(ini_get('memory_limit'));
            $default_attribute_memory_coefficient = Configure::check('MISP.default_attribute_memory_coefficient') ? Configure::read('MISP.default_attribute_memory_coefficient') : 80;
            $memory_scaling_factor = isset($exportTool->memory_scaling_factor) ? $exportTool->memory_scaling_factor : $default_attribute_memory_coefficient;
            $params['limit'] = $memory_in_mb * $memory_scaling_factor / 10;
            $loop = true;
            $params['page'] = 1;
        }
        $this->__iteratedFetch($user, $params, $loop, $tmpfile, $exportTool, $exportToolParams, $elementCounter);
        $tmpfile->write($exportTool->footer($exportToolParams));
        return $tmpfile;
    }

    private function __iteratedFetch($user, &$params, &$loop, TmpFileTool $tmpfile, $exportTool, $exportToolParams, &$elementCounter = 0)
    {
        $continue = true;
        while ($continue) {
            $temp = '';
            $this->Allowedlist = ClassRegistry::init('Allowedlist');
            $results = $this->fetchObjects($user, $params, $continue);
            if (empty($results)) {
                $loop = false;
                return true;
            }
            if ($elementCounter !== 0 && !empty($results)) {
                $temp .= $exportTool->separator($exportToolParams);
            }
            if ($params['includeSightingdb']) {
                $this->Sightingdb = ClassRegistry::init('Sightingdb');
                $results = $this->Sightingdb->attachToObjects($results, $user);
            }
            $params['page'] += 1;
            foreach ($results as $k => $result) {
                $results[$k]['Attribute'] = $this->Allowedlist->removeAllowedlistedFromArray($result['Attribute'], true);
            }
            $results = array_values($results);
            $i = 0;
            foreach ($results as $object) {
                $elementCounter++;
                $handlerResult = $exportTool->handler($object, $exportToolParams);
                $temp .= $handlerResult;
                if ($handlerResult !== '') {
                    if ($i != count($results) -1) {
                        $temp .= $exportTool->separator($exportToolParams);
                    }
                }
                $i++;
            }
            if (!$loop) {
                $continue = false;
            }
            $tmpfile->write($temp);
        }
        return true;
    }

    private function attributeValueDifferent($newValue, $originalValue, $field)
    {
        if (in_array($field, ['first_seen', 'last_seen'])) {
            return new DateTime($newValue) != new DateTime($originalValue);
        } else {
            return $newValue != $originalValue;
        }
    }

    private function getObjectAttributeHash($attribute)
    {
        if ($attribute['type'] === 'malware-sample') {
            if (!str_contains($attribute['value'], '|') && !empty($attribute['data'])) {
                $attribute['value'] = $attribute['value'] . '|' . md5(base64_decode($attribute['data']));
            }
        }
        $attributeValueAfterModification = AttributeValidationTool::modifyBeforeValidation($attribute['type'], $attribute['value']);
        $attributeValueAfterModification = $this->Attribute->runRegexp($attribute['type'], $attributeValueAfterModification);

        return sha1($attribute['object_relation'] . $attribute['category'] . $attribute['type'] . $attributeValueAfterModification, true);
    }
}
