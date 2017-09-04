<?php

App::uses('AppModel', 'Model');

class ObjectReference extends AppModel {
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

	public function beforeValidate($options = array()) {
		parent::beforeValidate();
		if (empty($this->data['ObjectReference']['uuid'])) {
			$this->data['ObjectReference']['uuid'] = CakeText::uuid();
		}
		$date = date('Y-m-d H:i:s');
		$this->data['Organisation']['timestamp'] = $date;
		return true;
	}

	public function smartDelete($id, $hard = false) {
		if ($hard) {
			return $this->delete($id);
		} else {
			$reference = $this->find('first', array(
				'conditions' => array('ObjectReference.id' => $id),
				'recursive' => -1
			));
			if (empty($reference)) return array('Invalid object reference.');
			$reference['ObjectReference']['deleted'] = 1;
			$result = $this->save($reference);
			if ($result) return true;
			return $this->validationErrors;
		}
	}

	public function smartSave($objectReference, $eventId) {
		$sides = array('source', 'destination');
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
			if (empty($data[$side]) && $side == 'destination') {
				$data[$side] = $this->Attribute->find('first', array(
					'conditions' => array(
						'Attribute.uuid' => $objectReference[$side . '_uuid'],
						'Attribute.event_id' => $eventId
					),
					'recursive' => -1,
					'fields' => array('Attribute.id')
				));
				$destination_id = $data[$side]['Attribute']['id'];
				$destination_type = 0;
			} else if (!empty($data[$side]) && $side == 'destination') {
				$destination_id = $data[$side]['Object']['id'];
				$destination_type = 1;
			} else if (!empty($data[$side]) && $side = 'source') {
				$object_id = $data[$side]['Object']['id'];
			} else {
				return 'Invalid ' . $side . ' uuid';
			}
		}
		$this->create();
		$objectReference['destination_type'] = $destination_type;
		$objectReference['destination_id'] = $destination_id;
		$objectReference['object_id'] = $object_id;
		$result = $this->save(array('ObjectReference' => $ojectReference));
		if (!$result) {
			return $this->validationErrors;
		}
		return true;
	}

	public function captureReference($reference, $eventId, $user, $log = false) {
		if ($log == false) {
			$log = ClassRegistry::init('Log');
		}
		if (isset($reference['uuid'])) {
			$existingReference = $this->find('first', array(
				'conditions' => array('ObjectReference.uuid' => $reference['uuid'])
			));
			if (empty($reference)) {
				return true;
			}
			// ObjectReference not newer than existing one
			if (isset($reference['timestamp']) && $reference['timestamp'] <= $existingReference['ObjectReference']['timestamp']) {
				return true;
			}
			$fieldsToUpdate = array('timestamp', 'relationship_type', 'comment', 'deleted');
			foreach ($fieldsToUpdate as $field) {
				if (isset($reference[$field])) $existingReference['ObjectReference'][$field] = $reference[$field];
			}
			$result = $this->save($existingReference);
			if ($result) {
				return true;
			} else {
				return $this->validationErrors;
			}
		} else {
			if (isset($reference['source_uuid'])) {
				$conditions = array('Object.uuid' => $reference['source_uuid']);
			} else if (isset($reference['object_id'])) {
				$conditions = array('Object.id' => $reference['object_id']);
			} else {
				return true;
			}
			$sourceObject = $this->Object->find('first', array(
				'recursive' => -1,
				'conditions' => $conditions
			));
			if (isset($reference['destination_uuid'])) {
				$conditions[0] = array('Attribute.uuid' => $reference['destination_uuid']);
				$conditions[1] = array('Object.uuid' => $reference['destination_uuid']);
			} else if (isset($reference['object_id'])) {
				if ($reference['object_type'] == 1) {
					$conditions[0] = array('Attribute.id' => $reference['object_id']);
					$conditions[1] = array('Object.id' => $reference['object_id']);
				} else {
					$conditions = false;
				}
			} else {
				return true;
			}
			if ($conditions) {
				$destinationObject = $this->Object->find('first', array(
					'recursive' => -1,
					'conditions' => $conditions[1]
				));
			}
			if (!isset($destinationObject)) {
				$destinationObject = $this->Attribute->find('first', array(
					'recursive' => -1,
					'conditions' => $conditions[0]
				));
				if (empty($destinationObject)) return true;
				$object_type = 0;
			} else {
				$object_type = 1;
			}
			$objectTypes = array('Attribute', 'Object');
			if ($sourceObject['Object']['event_id'] != $eventId) return true;
			if ($destinationObject[$objectTypes[$object_type]]['event_id'] != $eventId) return true;
			$this->create();
			unset($reference['id']);
			$reference['referenced_type'] = $object_type;
			$reference['object_id'] = $sourceObject['Object']['id'];
			$reference['referenced_id'] = $destinationObject[$objectTypes[$object_type]]['id'];
			$reference['destination_uuid'] = $destinationObject[$objectTypes[$object_type]]['uuid'];
			$reference['source_uuid'] = $sourceObject['Object']['uuid'];
			$this->save(array('ObjectReference' => $reference));
			return true;
		}
	}
}
