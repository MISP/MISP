<?php

App::uses('AppModel', 'Model');

class ObjectRelationship extends AppModel {
	public $actsAs = array(
			'Containable',
			'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
				'userModel' => 'User',
				'userKey' => 'user_id',
				'change' => 'full'),
	);

	public $validate = array(
		'name' => array(
			'unique' => array(
				'rule' => 'isUnique',
				'message' => 'A relationship with this name already exists.'
			),
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
			),
		),
	);


	public function beforeValidate($options = array()) {
		parent::beforeValidate();
		return true;
	}

	public function afterFind($results, $primary = false) {
		foreach ($results as $k => $result) {
			if (!empty($results[$k]['ObjectRelationship']['format'])) {
				$results[$k]['ObjectRelationship']['format'] = json_decode($results[$k]['ObjectRelationship']['format'], true);
			}
		}
		return $results;
	}

	public function update() {
		$relationsFile = APP . 'files/misp-objects/relationships/definition.json';
		if (file_exists($relationsFile)) {
			$file = new File($relationsFile);
			$relations = json_decode($file->read(), true);
			if (!isset($relations['version'])) $relations['version'] = 1;
			$this->deleteAll(array('version <' => $relations['version']));
			foreach ($relations['values'] as $k => $relation) {
				$relation['format'] = json_encode($relation['format'], true);
				$relation['version'] = $relations['version'];
				$this->create();
				$this->save($relation);
			}
		}
		return true;
	}
}
