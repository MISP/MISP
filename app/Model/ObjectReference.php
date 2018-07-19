<?php

App::uses('AppModel', 'Model');

class ObjectReference extends AppModel
{
    public $actsAs = array(
            'Containable',
            'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
                'userModel' => 'User',
                'userKey' => 'user_id',
                'change' => 'full'),
    );

    public $belongsTo = array(
        'Object' => array(
            'className' => 'MispObject',
            'foreignKey' => 'object_id'
        ),
        'ReferencedObject' => array(
            'className' => 'MispObject',
            'foreignKey' => false,
            'conditions' => array(
                'ReferencedObject.id' => 'ObjectReference.referenced_id',
                1 => 'ObjectReference.referenced_type'
            ),
        ),
        'ReferencedAttribute' => array(
            'className' => 'Attribute',
            'foreignKey' => false,
            'conditions' => array(
                'ReferencedAttribute.id' => 'ObjectReference.referenced_id',
                0 => 'ObjectReference.referenced_type'
            ),
        )
    );


    public $validate = array(
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        if (empty($this->data['ObjectReference']['uuid'])) {
            $this->data['ObjectReference']['uuid'] = CakeText::uuid();
        }
        $date = new DateTime();
        $this->data['ObjectReference']['timestamp'] = $date->getTimestamp();
        if (!isset($this->data['ObjectReference']['comment'])) {
            $this->data['ObjectReference']['comment'] = '';
        }
        return true;
    }

    public function afterSave($created, $options = array())
    {
        if (Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_object_reference_notifications_enable')) {
            $pubSubTool = $this->getPubSubTool();
            $object_reference = $this->find('first', array(
                'conditions' => array('ObjectReference.id' => $this->id),
                'recursive' => -1
            ));
            $action = $created ? 'add' : 'edit';
            if (!empty($this->data['ObjectReference']['deleted'])) {
                $action = 'soft-delete';
            }
            $pubSubTool->object_reference_save($object_reference, $action);
        }
        return true;
    }

    public function updateTimestamps($id, $objectReference = false)
    {
        if (!$objectReference) {
            $objectReference = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('ObjectReference.id' => $id),
                'fields' => array('event_id', 'object_id')
            ));
        }
        if (empty($objectReference)) {
            return false;
        }
        if (!isset($objectReference['ObjectReference'])) {
            $objectReference = array('ObjectReference' => $objectReference);
        }
        $this->Object->updateTimestamp($objectReference['ObjectReference']['object_id']);
        $this->Object->Event->unpublishEvent($objectReference['ObjectReference']['event_id']);
    }

    public function smartDelete($id, $hard = false)
    {
        if ($hard) {
            $result = $this->delete($id);
            if ($result) {
                $this->updateTimestamps($id);
            }
            return $result;
        } else {
            $reference = $this->find('first', array(
                'conditions' => array('ObjectReference.id' => $id),
                'recursive' => -1
            ));
            if (empty($reference)) {
                return array('Invalid object reference.');
            }
            $reference['ObjectReference']['deleted'] = 1;
            $result = $this->save($reference);
            if ($result) {
                $this->updateTimestamps($id);
                return true;
            }
            return $this->validationErrors;
        }
    }

    public function smartSave($objectReference, $eventId)
    {
        $sides = array('object', 'referenced');
        $data = array();
        foreach ($sides as $side) {
            $data[$side] = $this->Object->find('first', array(
                'conditions' => array(
                    'Object.uuid' => $objectReference[$side . '_uuid'],
                    'Object.event_id' => $eventId
                ),
                'recursive' => -1,
                'fields' => array('Object.id')
            ));
            if (empty($data[$side]) && $side == 'referenced') {
                $data[$side] = $this->Attribute->find('first', array(
                    'conditions' => array(
                        'Attribute.uuid' => $objectReference[$side . '_uuid'],
                        'Attribute.event_id' => $eventId
                    ),
                    'recursive' => -1,
                    'fields' => array('Attribute.id')
                ));
                $referenced_id = $data[$side]['Attribute']['id'];
                $referenced_type = 0;
            } elseif (!empty($data[$side]) && $side == 'referenced') {
                $referenced_id = $data[$side]['Object']['id'];
                $referenced_type = 1;
            } elseif (!empty($data[$side]) && $side = 'object') {
                $object_id = $data[$side]['Object']['id'];
            } else {
                return 'Invalid ' . $side . ' uuid';
            }
        }
        $this->create();
        $objectReference['referenced_type'] = $referenced_type;
        $objectReference['referenced_id'] = $referenced_id;
        $objectReference['object_id'] = $object_id;
        $objectReference['event_id'] = $eventId;
        $result = $this->save(array('ObjectReference' => $objectReference));
        if (!$result) {
            return $this->validationErrors;
        } else {
            $this->updateTimestamps($this->id, $objectReference);
        }
        return true;
    }

    public function captureReference($reference, $eventId, $user, $log = false)
    {
        if ($log == false) {
            $log = ClassRegistry::init('Log');
        }
        if (isset($reference['uuid'])) {
            $existingReference = $this->find('first', array(
                'conditions' => array('ObjectReference.uuid' => $reference['uuid']),
                'recursive' => -1
            ));
            if (!empty($existingReference)) {
                // ObjectReference not newer than existing one
                if (isset($reference['timestamp']) && $reference['timestamp'] <= $existingReference['ObjectReference']['timestamp']) {
                    return true;
                }
                $fieldsToUpdate = array('timestamp', 'relationship_type', 'comment', 'deleted');
                foreach ($fieldsToUpdate as $field) {
                    if (isset($reference[$field])) {
                        $existingReference['ObjectReference'][$field] = $reference[$field];
                    }
                }
                $result = $this->save($existingReference);
                if ($result) {
                    return true;
                } else {
                    return $this->validationErrors;
                }
            }
        }
        if (isset($reference['object_uuid'])) {
            $conditions = array('Object.uuid' => $reference['object_uuid']);
        } elseif (isset($reference['object_id'])) {
            $conditions = array('Object.id' => $reference['object_id']);
        } else {
            return true;
        }
        $sourceObject = $this->Object->find('first', array(
            'recursive' => -1,
            'conditions' => $conditions
        ));
        if (isset($reference['referenced_uuid'])) {
            $conditions[0] = array('Attribute.uuid' => $reference['referenced_uuid']);
            $conditions[1] = array('Object.uuid' => $reference['referenced_uuid']);
        } elseif (isset($reference['object_id'])) {
            if ($reference['referenced_type'] == 1) {
                $conditions[0] = array('Attribute.id' => $reference['referenced_id']);
                $conditions[1] = array('Object.id' => $reference['referenced_id']);
            } else {
                $conditions = false;
            }
        } else {
            return true;
        }
        if ($conditions) {
            $referencedObject = $this->Object->find('first', array(
                'recursive' => -1,
                'conditions' => $conditions[1]
            ));
        }
        if (empty($referencedObject)) {
            $referencedObject = $this->Object->Attribute->find('first', array(
                'recursive' => -1,
                'conditions' => $conditions[0]
            ));
            if (empty($referencedObject)) {
                return true;
            }
            $referenced_type = 0;
        } else {
            $referenced_type = 1;
        }
        $objectTypes = array('Attribute', 'Object');
        if (!isset($sourceObject['Object']) || $sourceObject['Object']['event_id'] != $eventId) {
            return true;
        }
        if ($referencedObject[$objectTypes[$referenced_type]]['event_id'] != $eventId) {
            return true;
        }
        $this->create();
        unset($reference['id']);
        $reference['referenced_type'] = $referenced_type;
        $reference['object_id'] = $sourceObject['Object']['id'];
        $reference['referenced_id'] = $referencedObject[$objectTypes[$referenced_type]]['id'];
        $reference['referenced_uuid'] = $referencedObject[$objectTypes[$referenced_type]]['uuid'];
        $reference['object_uuid'] = $sourceObject['Object']['uuid'];
        $reference['event_id'] = $eventId;
        $this->save(array('ObjectReference' => $reference));
        return true;
    }
}
