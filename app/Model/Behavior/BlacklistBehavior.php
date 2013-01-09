<?php

App::uses('Blacklist', 'Model');

/**
 * Behavior to blacklist all string input fields in a model
 *
 * @author noud
 *
 */
class BlacklistBehavior extends ModelBehavior {

/**
 *
 * @param Model $Model
 * @param unknown_type $settings
 */
	public function setup(Model $Model, $settings = array()) {
		if (!isset($this->settings[$Model->alias])) {
			$this->settings[$Model->alias] = array(
				'fields' => array(),
			);
		}
		$this->settings[$Model->alias] = array_merge(
			$this->settings[$Model->alias], (array)$settings);
	}

/**
 *
 * @param $options
 */
	public function beforeValidate(Model $Model, $options = array()) {
		$returnValue = true;
		// process some..
		$returnValue = $this->blacklistStringFields($Model);

		return $returnValue;
	}

/**
 * Trim String Fields
 *
 * @param Model $Model
 * @param unknown_type $array
 */
	public function blacklistStringFields(Model $Model) {
		$returnValue = true;
		foreach ($Model->data[$Model->name] as $key => $field) {
			if ($returnValue && is_string($field)) {
			//if ($returnValue && in_array($key, $this->settings[$Model->alias]['fields']) && is_string($field)) { // TODO fields
				$returnValue = $this->replaceWindowsSpecific($Model, $field);
			}
		}
		return $returnValue;
	}

/**
 * Replace Windows specific info in a $string with environment variables en registry keys
 *
 * @var string
 *
 * @return string
 */
	public function replaceWindowsSpecific(Model $Model, $string) {
		$returnValue = true;
		$blacklist = new Blacklist();
		$allBlacklist = $blacklist->find('all'); // TODO REGEXP INIT LOAD ARRAY
		foreach ($allBlacklist as $item) {
			if ($item['Blacklist']['name'] == $string) {
				App::uses('SessionComponent', 'Controller/Component');
				SessionComponent::setFlash('Blacklisted value!');
				$returnValue = false;
			}
		}
		return $returnValue;
	}
}
