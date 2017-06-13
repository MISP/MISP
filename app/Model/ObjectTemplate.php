<?php

App::uses('AppModel', 'Model');

class Object extends AppModel {
	public $actsAs = array(
			'Containable',
			'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
					'roleModel' => 'Object',
					'roleKey' => 'object_id',
					'change' => 'full'
			),
	);

	public $belongsTo = array(
		'User' => array(
			'className' => 'User',
			'foreignKey' => 'user_id'
		),
		'Org' => array(
				'className' => 'Org',
				'foreignKey' => 'org_id'
		)
	);
	public $hasMany = array(
		'Attribute' => array(
			'className' => 'Attribute',
			'dependent' => true,
		),
		'ObjectTemplateElement' => array(
			'className' => 'ObjectTemplateElement',
			'dependent' => true,
		),
	);
	public $validate = array(
	);

	public function update() {
		$objectsDir = APP . 'files/misp-objects/objects';
		$directories = glob($objectsDir . '/*', GLOB_ONLYDIR);
		foreach ($directories as $k => $dir) {
			$dir = str_replace($objectsDir, '', $dir);
			$directories[$k] = $dir;
		}
		$updated = array();
		foreach ($directories as $dir) {
			if (!file_exists($objectsDir . DS . $dir . DS . 'definition.json')) {
				continue;
			}
			$file = new File($objectsDir . DS . $dir . DS . 'definition.json');
			$template = json_decode($file->read(), true);
			$file->close();
			if (!isset($template['version'])) $template['version'] = 1;
			$current = $this->find('first', array(
				'conditions' => array('uuid' => $template['uuid']),
				'recursive' => -1,
				'fields' => array('version', 'uuid', 'name')
			));
			if (empty($current) || $template['version'] > $current['ObjectTemplate']['version']) {
				$result = $this->__updateObjectTemplate($template, $current);
				if (is_numeric($result)) {
					$updated['success'][$result] = array('name' => $template['name'], 'new' => $template['version']);
					if (!empty($current)) $updated['success'][$result]['old'] = $current['ObjectTemplate']['version'];
				} else {
					$updated['fails'][] = array('name' => $template['name'], 'fail' => json_encode($result));
				}
			}
		}
		return $updated;
	}

}
