<?php

App::uses('AppModel', 'Model');

class ObjectTemplateElement extends AppModel {
	public $actsAs = array(
			'Containable',
			'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
				'userModel' => 'User',
				'userKey' => 'user_id',
				'change' => 'full'),
	);

	public $belongsTo = array(
	);

	public $validate = array(
	);

	public function afterFind($results, $primary = false) {
		foreach ($results as $k => $result) {
			$results[$k]['ObjectTemplateElement']['categories'] = json_decode($results[$k]['ObjectTemplateElement']['categories'], true);
			$results[$k]['ObjectTemplateElement']['values_list'] = json_decode($results[$k]['ObjectTemplateElement']['values_list'], true);
			$results[$k]['ObjectTemplateElement']['sane_default'] = json_decode($results[$k]['ObjectTemplateElement']['sane_default'], true);
		}
		return $results;
	}

	public function beforeSave($options = array()) {
		if (empty($this->data['ObjectTemplateElement']['description'])) {
			$this->data['ObjectTemplateElement']['description'] = '';
		}
		$json_fields = array('categories', 'values_list', 'sane_default');
		foreach ($json_fields as $field) {
			$this->data['ObjectTemplateElement'][$field] = empty($this->data['ObjectTemplateElement'][$field]) ? '[]' : json_encode($this->data['ObjectTemplateElement'][$field]);
		}
		return true;
	}
}
