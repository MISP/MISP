<?php
App::uses('AppModel', 'Model');
class Warninglist extends AppModel{
	public $useTable = 'warninglists';
	public $recursive = -1;
	public $actsAs = array(
			'Containable',
	);

	public $validate = array(
		'name' => array(
			'rule' => array('valueNotEmpty'),
		),
		'description' => array(
			'rule' => array('valueNotEmpty'),
		),
		'version' => array(
			'rule' => array('numeric'),
		),
		
	);
	
	public $hasMany = array(
			'WarninglistEntry' => array(
				'dependent' => true
			),
			'WarninglistType' => array(
				'dependent' => true
			)
	);

	public function beforeValidate($options = array()) {
		parent::beforeValidate();
		return true;
	}
	
	public function checkValidTypeJSON($check) {
		return true;
	}
	
	public function update() {
		$directories = glob(APP . 'files' . DS . 'warninglists' . DS . 'lists' . DS . '*', GLOB_ONLYDIR);
		$updated = array();
		foreach ($directories as &$dir) {
			$file = new File ($dir . DS . 'list.json');
			$list = json_decode($file->read(), true);
			$file->close();
			if (!isset($list['version'])) $list['version'] = 1;
			if (!isset($list['type'])) $list['type'] = 'string';
			else if (is_array($list['type'])) $list['type'] = $list['type'][0];
			$current = $this->find('first', array(
					'conditions' => array('name' => $list['name']),
					'recursive' => -1,
					'fields' => array('*')
			));
			if (empty($current) || $list['version'] > $current['Warninglist']['version']) {
				$result = $this->__updateList($list, $current);
				if (is_numeric($result)) {
					$updated['success'][$result] = array('name' => $list['name'], 'new' => $list['version']);
					if (!empty($current)) $updated['success'][$result]['old'] = $current['Warninglist']['version'];
				} else {
					$updated['fails'][] = array('name' => $list['name'], 'fail' => json_encode($result));
				}
			}
		}
		return $updated;
	}
	
	private function __updateList($list, $current) {
		$list['enabled'] = false;
		$warninglist = array();
		if (!empty($current)) {
			if ($current['Warninglist']['enabled']) $list['enabled'] = true;
			$this->deleteAll(array('Warninglist.id' => $current['Warninglist']['id']));
		}
		$fieldsToSave = array('name', 'version', 'description', 'type', 'enabled');
		foreach ($fieldsToSave as $fieldToSave) $warninglist['Warninglist'][$fieldToSave] = $list[$fieldToSave];
		$this->create();
		if ($this->save($warninglist)) {
			foreach ($list['list'] as $value) {
				$this->WarninglistEntry->create();
				$this->WarninglistEntry->save(array('WarninglistEntry' => array('value' => $value, 'warninglist_id' => $this->id)));
			}
			if (!empty($list['matching_attributes'])) {
				foreach ($list['matching_attributes'] as $type) {
					$this->WarninglistType->create();
					$this->WarninglistType->save(array('WarninglistType' => array('type' => $type, 'warninglist_id' => $this->id)));
				}
			} else {
				$this->WarninglistType->create();
				$this->WarninglistType->save(array('WarninglistType' => array('type' => 'ALL', 'warninglist_id' => $this->id)));
			}
			return $this->id;
		} else return $this->validationErrors;
	}
	
	public function fetchForEventView() {
		$warninglists = $this->find('all', array('contain' => array('WarninglistType'), 'conditions' => array('enabled' => true)));
		if (empty($warninglists)) return array();		
		$results = array();
		foreach ($warninglists as $k => &$t) {
			$t['values'] = $this->WarninglistEntry->find('list', array(
					'recursive' => -1,
					'conditions' => array('warninglist_id' => $t['Warninglist']['id']),
					'fields' => array('value')
			));
			$t['values'] = array_values($t['values']);
			foreach ($t['WarninglistType'] as &$wt) $t['types'][] = $wt['type'];
			unset($warninglists[$k]['WarninglistType']);
		}
		return $warninglists;
	}
	
	public function setWarnings(&$event, &$warninglists) {
		if (empty($event['objects'])) return $event;
		$eventWarnings = array();
		debug($warninglists);
		foreach ($event['objects'] as &$object) {
			foreach ($warninglists as &$list) {
				if (in_array($object['type'], $list['types'])) {
					$result = $this->__checkValue($list['values'], $object['value'], $object['type'], $list['Warninglist']['type']);
					if (!empty($result)) {
						$object['warnings'] = $result;
						if (!in_array($list['Warninglist']['name'], $eventWarnings)) $eventWarnings[] = $list['Warninglist']['name'];
					}
				}
			}
		}
		return $event;
	}
	
	private function __checkValue(&$listValues, $value, $type, $listType) {
		if (strpos($type, '|')) $value = explode('|', $value);
		else $value = array($value);
		$components = array(0, 1);
		foreach ($components as $component) {
			if (!isset($value[$component])) continue;
			debug($value);
			debug($component);
			if ($listType === 'cidr') $result = $this->__evalCIDR($listValues, $value[$component]);
			else if ($listType === 'string') $result = $this->__evalString($listValues, $value[$component]);
			if ($result) return ($component + 1);
		}
		return false;
	}
	
	private function __evalCIDR(&$listValues, $value) {
		
		return false;
	}
	
	private function __evalString(&$listValues, $value) {
		if (in_array($value, $listValues)) return true;
		return false;
	}
	
	private function __checkCIDR(&$listValues, $value, $type) {
		if (strpos($type, '|')) $value = explode('|', $value);
		else $value = array($value);
		$components = array(0, 1);
	}
}