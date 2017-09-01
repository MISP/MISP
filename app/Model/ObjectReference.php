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
}
