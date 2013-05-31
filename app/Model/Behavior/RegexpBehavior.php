<?php

App::uses('Regexp', 'Model');

/**
 * Behavior to regexp all string fields in a model
 *
 * @author noud
 *
 */
class RegexpBehavior extends ModelBehavior {

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
		$returnValue = $this->regexpStringFields($Model);
		return $returnValue;
	}

/**
 * Trim String Fields
 *
 * @param Model $Model
 * @param unknown_type $array
 */
	public function regexpStringFields(Model $Model) {
		$returnValue = true;
		foreach ($Model->data[$Model->name] as $key => $field) {
			if (in_array($key, $this->settings[$Model->alias]['fields']) && is_string($field)) {
				$returnValue = $this->replaceWindowsSpecific($Model, $field);
				$Model->data[$Model->name][$key] = $returnValue;
			}
		}
		if ($returnValue != false) $returnValue = true;
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
		$returnValue = $string;
		$regexp = new Regexp();
		$allRegexp = $regexp->find('all'); // TODO INIT LOAD ARRAY
		foreach ($allRegexp as $regexp) {
			if (strlen($regexp['Regexp']['replacement'] && strlen($regexp['Regexp']['regexp']))) {
				$string = preg_replace($regexp['Regexp']['regexp'], $regexp['Regexp']['replacement'], $string);
				$returnValue = $string;
			}
			if (!strlen($regexp['Regexp']['replacement']) && preg_match($regexp['Regexp']['regexp'], $string)) {
				App::uses('SessionComponent', 'Controller/Component');
				SessionComponent::setFlash('Blacklisted value!');
				return false;
			}
		}
		return $returnValue;
	}
}
