<?php

App::uses('AppModel', 'Model');

class MispObject extends AppModel
{
    public $name = 'Object';
    public $alias = 'Object';

    public $useTable = 'objects';

    public $actsAs = array(
            'Containable',
            'SysLogLogable.SysLogLogable' => array( // TODO Audit, logable
                'userModel' => 'User',
                'userKey' => 'user_id',
                'change' => 'full'),
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
            'className' => 'Attribute',
            'dependent' => true,
        ),
        'ObjectReference' => array(
            'className' => 'ObjectReference',
            'dependent' => true,
            'foreignKey' => 'object_id'
        ),
    );

    public $validate = array(
        'uuid' => array(
            'uuid' => array(
                'rule' => array('custom', '/^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/'),
                'message' => 'Please provide a valid UUID'
            ),
            'unique' => array(
                'rule' => 'isUnique',
                'message' => 'The UUID provided is not unique',
                'required' => 'create'
            )
        )
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        if (empty($this->data[$this->alias]['comment'])) {
            $this->data[$this->alias]['comment'] = "";
        }
        // generate UUID if it doesn't exist
        if (empty($this->data[$this->alias]['uuid'])) {
            $this->data[$this->alias]['uuid'] = CakeText::uuid();
        }
        // generate timestamp if it doesn't exist
        if (empty($this->data[$this->alias]['timestamp'])) {
            $date = new DateTime();
            $this->data[$this->alias]['timestamp'] = $date->getTimestamp();
        }
        if (empty($this->data[$this->alias]['template_version'])) {
            $this->data[$this->alias]['template_version'] = 1;
        }
        if (isset($this->data[$this->alias]['deleted']) && empty($this->data[$this->alias]['deleted'])) {
            $this->data[$this->alias]['deleted'] = 0;
        }
        if (!isset($this->data[$this->alias]['distribution']) || $this->data['Object']['distribution'] != 4) {
            $this->data['Object']['sharing_group_id'] = 0;
        }
        if (!isset($this->data[$this->alias]['distribution'])) {
            $this->data['Object']['distribution'] = 5;
        }
        return true;
    }

    public function afterSave($created, $options = array())
    {
        $pubToZmq = Configure::read('Plugin.ZeroMQ_enable') &&
            Configure::read('Plugin.ZeroMQ_object_notifications_enable') &&
            empty($this->data['Object']['skip_zmq']);
        $kafkaTopic = Configure::read('Plugin.Kafka_object_notifications_topic');
        $pubToKafka = Configure::read('Plugin.Kafka_enable') &&
            Configure::read('Plugin.Kafka_object_notifications_enable') &&
            !empty($kafkaTopic) &&
            empty($this->data['Object']['skip_kafka']);
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
            $pubToZmq = Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_object_notifications_enable');
            $kafkaTopic = Configure::read('Plugin.Kafka_object_notifications_topic');
            $pubToKafka = Configure::read('Plugin.Kafka_enable') && Configure::read('Plugin.Kafka_object_notifications_enable') && !empty($kafkaTopic);
            if ($pubToZmq || $pubToKafka) {
                $object = $this->find('first', array(
                    'recursive' => -1,
                    'conditions' => array('Object.id' => $this->data['Object']['id'])
                ));
                if ($pubToZmq) {
                    $pubSubTool = $this->getPubSubTool();
                    $pubSubTool->object_save($object, 'delete');
                }
                if ($pubToKafka) {
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

    public function saveObject($object, $eventId, $template = false, $user, $errorBehaviour = 'drop')
    {
        $this->create();
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
                    return 'No valid template found and object lacking template information. (' . $k . ')';
                }
            }
        }
        $object['Object']['event_id'] = $eventId;
        $result = false;
        if ($this->save($object)) {
            $result = $this->id;
            foreach ($object['Attribute'] as $k => $attribute) {
                $object['Attribute'][$k]['object_id'] = $this->id;
            }
            $this->Attribute->saveAttributes($object['Attribute']);
        } else {
            $result = $this->validationErrors;
        }
        return $result;
    }

    public function buildEventConditions($user, $sgids = false)
    {
        if ($user['Role']['perm_site_admin']) {
            return array();
        }
        if ($sgids == false) {
            $sgsids = $this->SharingGroup->fetchAllAuthorised($user);
        }
        return array(
            'OR' => array(
                array(
                    'AND' => array(
                        'Event.distribution >' => 0,
                        'Event.distribution <' => 4,
                        Configure::read('MISP.unpublishedprivate') ? array('Event.published' => 1) : array(),
                    ),
                ),
                array(
                    'AND' => array(
                        'Event.sharing_group_id' => $sgids,
                        'Event.distribution' => 4,
                        Configure::read('MISP.unpublishedprivate') ? array('Event.published' => 1) : array(),
                    )
                )
            )
        );
    }

    public function buildConditions($user, $sgids = false)
    {
        $conditions = array();
        if (!$user['Role']['perm_site_admin']) {
            if ($sgids === false) {
                $sgsids = $this->SharingGroup->fetchAllAuthorised($user);
            }
            $conditions = array(
                'AND' => array(
                    'OR' => array(
                        array(
                            'AND' => array(
                                'Event.org_id' => $user['org_id'],
                            )
                        ),
                        array(
                            'AND' => array(
                                $this->buildEventConditions($user, $sgids),
                                'OR' => array(
                                    'Object.distribution' => array('1', '2', '3', '5'),
                                    'AND '=> array(
                                        'Object.distribution' => 4,
                                        'Object.sharing_group_id' => $sgsids,
                                    )
                                )
                            )
                        )
                    )
                )
            );
        }
        return $conditions;
    }


    // Method that fetches all objects
    // very flexible, it's basically a replacement for find, with the addition that it restricts access based on user
    // options:
    //     fields
    //     contain
    //     conditions
    //     order
    //     group
    public function fetchObjects($user, $options = array())
    {
        $sgsids = $this->SharingGroup->fetchAllAuthorised($user);
        $attributeConditions = array();
        if (!$user['Role']['perm_site_admin']) {
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
                                'Attribute.sharing_group_id' => $sgsids
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
            )
        );
        if (empty($options['includeAllTags'])) {
            $params['contain']['Attribute']['AttributeTag']['Tag']['conditions']['exportable'] = 1;
        }
        if (isset($options['contain'])) {
            $params['contain'] = array_merge_recursive($params['contain'], $options['contain']);
        } else {
            $option['contain']['Event']['fields'] = array('id', 'info', 'org_id', 'orgc_id');
        }
        if (Configure::read('MISP.proposals_block_attributes') && isset($options['conditions']['AND']['Attribute.to_ids']) && $options['conditions']['AND']['Attribute.to_ids'] == 1) {
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
        if (isset($options['fields'])) {
            $params['fields'] = $options['fields'];
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
        if (!$user['Role']['perm_sync'] || !isset($options['deleted']) || !$options['deleted']) {
            $params['contain']['Attribute']['conditions']['AND']['Attribute.deleted'] = 0;
        }
        if (isset($options['group'])) {
            $params['group'] = array_merge(array('Object.id'), $options['group']);
        }
        if (Configure::read('MISP.unpublishedprivate')) {
            $params['conditions']['AND'][] = array('OR' => array('Event.published' => 1, 'Event.orgc_id' => $user['org_id']));
        }
        $results = $this->find('all', $params);
        if ($options['enforceWarninglist']) {
            $this->Warninglist = ClassRegistry::init('Warninglist');
            $warninglists = $this->Warninglist->fetchForEventView();
        }
        $results = array_values($results);
        $proposals_block_attributes = Configure::read('MISP.proposals_block_attributes');
        foreach ($results as $key => $objects) {
            foreach ($objects as $key2 => $attribute) {
                if ($options['enforceWarninglist'] && !$this->Warninglist->filterWarninglistAttributes($warninglists, $attribute['Attribute'], $this->Warninglist)) {
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
                    if ($this->typeIsAttachment($attribute['Attribute']['type'])) {
                        $encodedFile = $this->base64EncodeAttachment($attribute['Attribute']);
                        $results[$key][$key2]['Attribute']['data'] = $encodedFile;
                    }
                }
            }
        }
        return $results;
    }

    /*
     * Prepare the template form view's data, setting defaults, sorting elements
     */
    public function prepareTemplate($template, $request = array())
    {
        $temp = array();
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
        foreach ($template_object_elements as $k => $v) {
            if (empty($request_rearranged[$v['object_relation']])) {
                if (isset($this->Event->Attribute->typeDefinitions[$v['type']])) {
                    $v['default_category'] = $this->Event->Attribute->typeDefinitions[$v['type']]['default_category'];
                    $v['to_ids'] = $this->Event->Attribute->typeDefinitions[$v['type']]['to_ids'];
                    if (empty($v['categories'])) {
                        $v['categories'] = array();
                        foreach ($this->Event->Attribute->categoryDefinitions as $catk => $catv) {
                            if (in_array($v['type'], $catv['types'])) {
                                $v['categories'][] = $catk;
                            }
                        }
                    }
                    $template['ObjectTemplateElement'][] = $v;
                } else {
                    $template['warnings'][] = 'Missing attribute type "' . $v['type'] . '" found. Omitted template element ("' . $template_object_elements[$k]['object_relation'] . '") that would not pass validation due to this.';
                }
            } else {
                foreach ($request_rearranged[$v['object_relation']] as $request_item) {
                    if (isset($this->Event->Attribute->typeDefinitions[$v['type']])) {
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
                            foreach ($this->Event->Attribute->categoryDefinitions as $catk => $catv) {
                                if (in_array($v['type'], $catv['types'])) {
                                    $v['categories'][] = $catk;
                                }
                            }
                        }
                        $v['disable_correlation'] = $request_item['disable_correlation'];
                        $template['ObjectTemplateElement'][] = $v;
                        unset($v['uuid']); // force creating a new attribute if template element entry gets reused
                    } else {
                        $template['warnings'][] = 'Missing attribute type "' . $v['type'] . '" found. Omitted template element ("' . $template_object_elements[$k]['object_relation'] . '") that would not pass validation due to this.';
                    }
                }
            }
        }
        return $template;
    }

    /*
     * Clean the attribute list up from artifacts introduced by the object form
     */
    public function attributeCleanup($attributes)
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
                $filename = basename($attribute['Attachment']['name']);
                $tmpfile = new File($attribute['Attachment']['tmp_name']);
                if ((isset($attribute['Attachment']['error']) && $attribute['Attachment']['error'] == 0) ||
                    (!empty($attribute['Attachment']['tmp_name']) && $attribute['Attachment']['tmp_name'] != 'none')
                ) {
                    if (!is_uploaded_file($tmpfile->path)) {
                        throw new InternalErrorException('PHP says file was not uploaded. Are you attacking me?');
                    }
                } else {
                    return 'Issues with the file attachment for the ' . $attribute['object_relation'] . ' attribute. The error code returned is ' . $attribute['Attachment']['error'];
                }
                $attributes['Attribute'][$k]['value'] = $attribute['Attachment']['name'];
                unset($attributes['Attribute'][$k]['Attachment']);
                $attributes['Attribute'][$k]['encrypt'] = $attribute['type'] == 'malware-sample' ? 1 : 0;
                $attributes['Attribute'][$k]['data'] = base64_encode($tmpfile->read());
                $tmpfile->delete();
                $tmpfile->close();
            }
            unset($attributes['Attribute'][$k]['save']);
        }
        return $attributes;
    }

    public function deltaMerge($object, $objectToSave)
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
        $object['Object']['comment'] = $objectToSave['Object']['comment'];
        $object['Object']['distribution'] = $objectToSave['Object']['distribution'];
        if ($object['Object']['distribution'] == 4) {
            $object['Object']['sharing_group_id'] = $objectToSave['Object']['sharing_group_id'];
        }
        $date = new DateTime();
        $object['Object']['timestamp'] = $date->getTimestamp();
        $this->save($object);
        $checkFields = array('category', 'value', 'to_ids', 'distribution', 'sharing_group_id', 'comment', 'disable_correlation');
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
                                if ($newAttribute[$f] != $originalAttribute[$f]) {
                                    $different = true;
                                }
                            }
                            if ($different) {
                                $newAttribute['id'] = $originalAttribute['id'];
                                $newAttribute['event_id'] = $object['Object']['event_id'];
                                $newAttribute['object_id'] = $object['Object']['id'];
                                $newAttribute['timestamp'] = $date->getTimestamp();
                                $result = $this->Event->Attribute->save(array('Attribute' => $newAttribute), array(
                                    'category',
                                    'value',
                                    'to_ids',
                                    'distribution',
                                    'sharing_group_id',
                                    'comment',
                                    'timestamp',
                                    'object_id',
                                    'event_id',
                                    'disable_correlation'
                                ));
                            }
                            unset($object['Attribute'][$origKey]);
                            continue 2;
                        }
                    }
                }
                $this->Event->Attribute->create();
                $newAttribute['event_id'] = $object['Object']['event_id'];
                $newAttribute['object_id'] = $object['Object']['id'];
                if (!isset($newAttribute['timestamp'])) {
                    $newAttribute['distribution'] = Configure::read('MISP.default_attribute_distribution');
                    if ($newAttribute['distribution'] == 'event') {
                        $newAttribute['distribution'] = 5;
                    }
                }
                $this->Event->Attribute->save($newAttribute);
                $attributeArrays['add'][] = $newAttribute;
                unset($objectToSave['Attribute'][$newKey]);
            }
            foreach ($object['Attribute'] as $origKey => $originalAttribute) {
                $originalAttribute['deleted'] = 1;
                $this->Event->Attribute->save($originalAttribute);
            }
        }
        return $this->id;
    }

    public function captureObject($object, $eventId, $user, $log = false)
    {
        $this->create();
        if (!isset($object['Object'])) {
            $object = array('Object' => $object);
        }
        if (empty($log)) {
            $log = ClassRegistry::init('Log');
        }
        if (isset($object['Object']['id'])) {
            unset($object['Object']['id']);
        }
        $object['Object']['event_id'] = $eventId;
        if ($this->save($object)) {
            $this->Event->unpublishEvent($eventId);
            $objectId = $this->id;
            $partialFails = array();
            if (!empty($object['Object']['Attribute'])) {
                foreach ($object['Object']['Attribute'] as $attribute) {
                    $this->Attribute->captureAttribute($attribute, $eventId, $user, $objectId, $log);
                }
            }
            return true;
        } else {
            $log->create();
            $log->save(array(
                    'org' => $user['Organisation']['name'],
                    'model' => 'Object',
                    'model_id' => 0,
                    'email' => $user['email'],
                    'action' => 'add',
                    'user_id' => $user['id'],
                    'title' => 'Object dropped due to validation for Event ' . $eventId . ' failed: ' . $object['Object']['name'],
                    'change' => 'Validation errors: ' . json_encode($this->validationErrors) . ' Full Object: ' . json_encode($object),
            ));
        }
        return 'fail';
    }

    public function editObject($object, $eventId, $user, $log)
    {
        $object['event_id'] = $eventId;
        if (isset($object['uuid'])) {
            $existingObject = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('Object.uuid' => $object['uuid'])
            ));
            if (empty($existingObject)) {
                return $this->captureObject($object, $eventId, $user, $log);
            } else {
                if ($existingObject['Object']['event_id'] != $eventId) {
                    $log->create();
                    $log->save(array(
                            'org' => $user['Organisation']['name'],
                            'model' => 'Object',
                            'model_id' => 0,
                            'email' => $user['email'],
                            'action' => 'edit',
                            'user_id' => $user['id'],
                            'title' => 'Duplicate UUID found in object',
                            'change' => 'An object was blocked from being saved due to a duplicate UUID. The uuid in question is: ' . $object['uuid'] . '. This can also be due to the same object (or an object with the same UUID) existing in a different event)',
                    ));
                    return true;
                }
                if (isset($object['timestamp'])) {
                    if ($existingObject['Object']['timestamp'] >= $object['timestamp']) {
                        return true;
                    }
                } else {
                    $date = new DateTime();
                    $object['timestamp'] = $date->getTimestamp();
                }
            }
        } else {
            return $this->captureObject($object, $eventId, $user, $log);
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
            $log->create();
            $log->save(array(
                'org' => $user['Organisation']['name'],
                'model' => 'Object',
                'model_id' => 0,
                'email' => $user['email'],
                'action' => 'edit',
                'user_id' => $user['id'],
                'title' => 'Attribute dropped due to validation for Event ' . $eventId . ' failed: ' . $object['name'],
                'change' => 'Validation errors: ' . json_encode($this->validationErrors) . ' Full Object: ' . json_encode($attribute),
            ));
            return $this->validationErrors;
        }
        if (!empty($object['Attribute'])) {
            foreach ($object['Attribute'] as $attribute) {
                $result = $this->Attribute->editAttribute($attribute, $eventId, $user, $object['id'], $log);
            }
        }
        return true;
    }

    public function updateTimestamp($id, $timestamp = false)
    {
        $date = new DateTime();
        $object = $this->find('first', array(
            'recursive' => -1,
            'conditions' => array('Object.id' => $id)
        ));
        $object['Object']['timestamp'] = $timestamp == false ? $date->getTimestamp() : $timestamp;
        $object['Object']['skip_zmq'] = 1;
        $object['Object']['skip_kafka'] = 1;
        $result = $this->save($object);
        return $result;
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

    public function validObjectsFromAttributeTypes($user, $event_id, $selected_attribute_ids)
    {
        $attributes = $this->Attribute->fetchAttributes($user,
            array(
                'conditions' => array(
                    'Attribute.id' => $selected_attribute_ids,
                    'Attribute.event_id' => $event_id,
                    'Attribute.object_id' => 0
                ),
            )
        );
        if (empty($attributes)) {
            return array('templates' => array(), 'types' => array());
        }
        $attribute_types = array();
        foreach ($attributes as $i => $attribute) {
            $attribute_types[$attribute['Attribute']['type']] = 1;
            $attributes[$i]['Attribute']['object_relation'] = $attribute['Attribute']['type'];
        }
        $attribute_types = array_keys($attribute_types);

        $potential_templates = $this->ObjectTemplate->find('list', array(
            'recursive' => -1,
            'fields' => array(
                'ObjectTemplate.id',
                'COUNT(ObjectTemplateElement.type) as type_count'
            ),
            'conditions' => array(
                'ObjectTemplate.active' => true,
                'ObjectTemplateElement.type' => $attribute_types
            ),
            'joins' => array(
                array(
                    'table' => 'object_template_elements',
                    'alias' => 'ObjectTemplateElement',
                    'type' => 'RIGHT',
                    'fields' => array('ObjectTemplateElement.object_relation', 'ObjectTemplateElement.type'),
                    'conditions' => array('ObjectTemplate.id = ObjectTemplateElement.object_template_id')
                )
            ),
            'group' => 'ObjectTemplate.id',
            'order' => 'type_count DESC'
        ));

        $potential_template_ids = array_keys($potential_templates);
        $templates = $this->ObjectTemplate->find('all', array(
            'recursive' => -1,
            'conditions' => array('id' => $potential_template_ids),
            'contain' => 'ObjectTemplateElement'
        ));

        foreach ($templates as $i => $template) {
            $res = $this->ObjectTemplate->checkTemplateConformityBasedOnTypes($template, $attributes);
            $templates[$i]['ObjectTemplate']['compatibility'] = $res['valid'] ? true : $res['missingTypes'];
            $templates[$i]['ObjectTemplate']['invalidTypes'] = $res['invalidTypes'];
            $templates[$i]['ObjectTemplate']['invalidTypesMultiple'] = $res['invalidTypesMultiple'];
        }
        return array('templates' => $templates, 'types' => $attribute_types);
    }

    public function groupAttributesIntoObject($user, $event_id, $object, $template, $selected_attribute_ids, $selected_object_relation_mapping, $hard_delete_attribute)
    {
        $saved_object_id = $this->saveObject($object, $event_id, $template, $user);
        if (!is_numeric($saved_object_id)) {
            return $saved_object_id;
        }

        $saved_object = $this->find('first', array(
            'recursive' => -1,
            'conditions' => array('Object.id' => $saved_object_id)
        ));

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
        foreach ($existing_attributes as $i => $existing_attribute) {
            if (isset($selected_object_relation_mapping[$existing_attribute['Attribute']['id']])) {
                $sightings = $this->Event->Sighting->attachToEvent($event, $user, $existing_attribute['Attribute']['id']);
                $object_relation = $selected_object_relation_mapping[$existing_attribute['Attribute']['id']];
                $created_attribute = $existing_attribute['Attribute'];
                unset($created_attribute['timestamp']);
                unset($created_attribute['id']);
                unset($created_attribute['uuid']);
                $created_attribute['object_relation'] = $object_relation;
                $created_attribute['object_id'] = $saved_object['Object']['id'];
                if (isset($existing_attribute['AttributeTag'])) {
                    $created_attribute['AttributeTag'] = $existing_attribute['AttributeTag'];
                }
                if (!empty($sightings)) {
                    $created_attribute['Sighting'] = $sightings;
                }
                $saved_object['Attribute'][$i] = $created_attribute;
                $this->Attribute->captureAttribute($created_attribute, $event_id, $user, $saved_object['Object']['id']);
                $this->Attribute->deleteAttribute($existing_attribute['Attribute']['id'], $user, $hard_delete_attribute);
            }
        }
        return $saved_object['Object']['id'];

    }

    public function resolveUpdatedTemplate($template, $object, $update_template_available = false)
    {
        $toReturn = array(
            'updateable_attribute' => false,
            'not_updateable_attribute' => false,
            'newer_template_version' => false,
            'template' => $template
        );
        if (!empty($template)) {
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
            if (!empty($newer_template)) {
              $toReturn['newer_template_version'] = $newer_template['ObjectTemplate']['version'];
              // ignore IDs for comparison
              $cur_template_temp = Hash::remove(Hash::remove($template['ObjectTemplateElement'], '{n}.id'), '{n}.object_template_id');
              $newer_template_temp = Hash::remove(Hash::remove($newer_template['ObjectTemplateElement'], '{n}.id'), '{n}.object_template_id');

              $template_difference = array();
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

              $toReturn['updateable_attribute'] = $object['Attribute'];
              $toReturn['not_updateable_attribute'] = array();
            } else {
              $toReturn['newer_template_version'] = false;
            }
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
            if ($update_template_available) { // template version bump requested
                $toReturn['template'] = $newer_template; // bump the template version
            }
        }
        return $toReturn;
    }

    public function reviseObject($revised_object, $object) {
        $revised_object = json_decode(base64_decode($revised_object), true);
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
}
