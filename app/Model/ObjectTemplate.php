<?php

App::uses('AppModel', 'Model');

class ObjectTemplate extends AppModel {
	public $actsAs = array(
			'Containable',
			'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
				'userModel' => 'User',
				'userKey' => 'user_id',
				'change' => 'full'),
	);

	public $belongsTo = array(
		'User' => array(
			'className' => 'User',
			'foreignKey' => 'user_id'
		),
		'Organisation' => array(
				'className' => 'Organisation',
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

	public function afterFind($results, $primary = false) {
		foreach ($results as $k => $result) {
			if (isset($results[$k]['ObjectTemplate']['requirements'])) {
				$results[$k]['ObjectTemplate']['requirements'] = json_decode($results[$k]['ObjectTemplate']['requirements'], true);
			}
		}
		return $results;
	}

	public function beforeSave($options = array()) {
		$this->data['ObjectTemplate']['requirements'] = empty($this->data['ObjectTemplate']['requirements']) ? '[]' : json_encode($this->data['ObjectTemplate']['requirements']);
		return true;
	}

	public function update($user) {
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
				'recursive' => -1
			));
			if (empty($current) || $template['version'] > $current['ObjectTemplate']['version']) {
				$result = $this->__updateObjectTemplate($template, $current, $user);
				if ($result === true) {
					$updated['success'][$result] = array('name' => $template['name'], 'new' => $template['version']);
					if (!empty($current)) $updated['success'][$result]['old'] = $current['ObjectTemplate']['version'];
				} else {
					$updated['fails'][] = array('name' => $template['name'], 'fail' => json_encode($result));
				}
			}
		}
		return $updated;
	}

	private function __updateObjectTemplate($template, $current, $user) {
		$success = false;
		$template['requirements'] = array();
		$requirementFields = array('required', 'requiredOneOf');
		foreach ($requirementFields as $field) {
			if (isset($template[$field])) {
				$template['requirements'][$field] = $template[$field];
			}
		}
		if (empty($current)) {
			$template['user_id'] = $user['id'];
			$template['org_id'] = $user['org_id'];
			$template['fixed'] = 1;
			$this->create();
			$result = $this->save($template);
		} else {
			$fieldsToUpdate = array('version', 'description', 'meta-category', 'name', 'requirements', 'fixed');
			foreach ($fieldsToUpdate as $field) {
				if (isset($template[$field]) && $current['ObjectTemplate'][$field] != $template[$field]) {
					$current['ObjectTemplate'][$field] = $template[$field];
				}
			}
			$result = $this->save($current);
		}
		if (!$result) {
			return $this->validationErrors;
		}
		$id = $this->id;
		$existingTemplateElementsTemp = $this->ObjectTemplateElement->find('all', array(
			'recursive' => -1,
			'conditions' => array('object_template_id' => $id)
		));
		$existingTemplateElements = array();
		if (!empty($existingTemplateElementsTemp)) {
			foreach ($existingTemplateElementsTemp as $k => $v) {
				$existingTemplateElements[$v['ObjectTemplateElement']['in-object-name']] = $v['ObjectTemplateElement'];
			}
		}
		unset($existingTemplateElementsTemp);
		$fieldsToCompare = array('in-object-name', 'type', 'ui-priority', 'categories', 'sane_default', 'values_list');
		foreach ($template['attributes'] as $k => $attribute) {
			$attribute['in-object-name'] = $k;
			$attribute = $this->__convertJSONToElement($attribute);
			if (isset($existingTemplateElements[$k])) {
				$update_required = false;
				foreach ($fieldsToCompare as $field) {
					if (isset($attribute[$field])) {
						if ($existingTemplateElements[$k][$field] != $attribute[$field]) {
							$update_required = true;
						}
					}
				}
				if ($update_required) {
					$attribute = $existingTemplateElements[$k];
					unset($existingTemplateElements);
					$attribute['object_template_id'] = $id;
					$this->ObjectTemplateElement->save(array('ObjectTemplateElement' => $attribute));
				}
				unset($existingTemplateElements[$k]);
			} else {
				$this->ObjectTemplateElement->create();
				$attribute['object_template_id'] = $id;
				$this->ObjectTemplateElement->save(array('ObjectTemplateElement' => $attribute));
			}
		}
		if (!empty($existingTemplateElements)) {
			foreach ($existingTemplateElements as $k2 => $v2) {
				$this->ObjectTemplateElement->delete($v2['id']);
			}
		}
		return true;
	}

	private function __convertJSONToElement($attribute) {
		$result = array();
		$translation_table = array(
				'misp-usage-frequency' => 'frequency',
				'misp-attribute' => 'type',
				'description' => 'description',
				'ui-priority' => 'ui-priority',
				'type' => 'type',
				'disable_correlation' => 'disable_correlation',
				'in-object-name' => 'in-object-name',
				'categories' => 'categories',
				'sane_default' => 'sane_default',
				'values_list' => 'values_list'
		);
		foreach ($translation_table as $from => $to) {
			if (isset($attribute[$from])) {
				$result[$to] = $attribute[$from];
			}
		}
		return $result;
	}

	public function checkTemplateConformity($template, $attributes) {
		if (!empty($template['ObjectTemplate']['requirements'])) {
			if (!empty($template['ObjectTemplate']['requirements']['required'])) {
				foreach ($template['ObjectTemplate']['requirements']['required'] as $requiredField) {
					$found = false;
					foreach ($attributes['Attribute'] as $attribute) {
						if ($attribute['object_relation'] == $requiredField) {
							$found = true;
						}
					}
					if (!$found) return 'Could not save the object as a required attribute is not set (' . $requiredField . ')';
				}
			}
			if (!empty($template['ObjectTemplate']['requirements']['requiredOneOf'])) {
				$found = false;
				foreach ($template['ObjectTemplate']['requirements']['requiredOneOf'] as $requiredField) {
					foreach ($attributes['Attribute'] as $attribute) {
						if ($attribute['object_relation'] == $requiredField) {
							$found = true;
						}
					}
				}
				if (!$found) return 'Could not save the object as it requires at least one of the following attributes to be set: ' . implode(', ', $template['ObjectTemplate']['requirements']['requiredOneOf']);
			}
		}
		return true;
	}
}
