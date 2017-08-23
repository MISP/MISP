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
}
