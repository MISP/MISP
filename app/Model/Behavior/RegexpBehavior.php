<?php

App::uses('Regexp', 'Model');

/**
 * Behavior to regexp all string fields in a model
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
		$regexp = new Regexp();
		$allRegexp = $regexp->find('all');
		// Go through all the fields from the validated model
		foreach ($Model->data[$Model->name] as $key => $field) {
			// if a field is marked for regexp checks, do a regexp check
			if (in_array($key, $this->settings[$Model->alias]['fields'])) {
				$returnValue = $this->__replaceWindowsSpecific($Model, $field, $allRegexp);
				// if replaceWindowsSpecific returns false, it means that we ran into a blacklisted value. Return false to let the validation fail.
				if (!$returnValue) return false;
				// if it wasn't false, change the value to the replacement
				$Model->data[$Model->name][$key] = $returnValue;
			}
		}
		return true;
	}

/**
 * Replace Windows specific info in a $string with environment variables en registry keys
 *
 * @var string
 *
 * @return string
 */
	private function __replaceWindowsSpecific(Model $Model, $string, $allRegexp) {
		foreach ($allRegexp as $regexp) {
			if (!empty($regexp['Regexp']['replacement']) && !empty($regexp['Regexp']['regexp'])) {
				$string = preg_replace($regexp['Regexp']['regexp'], $regexp['Regexp']['replacement'], $string);
			}
			if (empty($regexp['Regexp']['replacement']) && preg_match($regexp['Regexp']['regexp'], $string)) {
				App::uses('SessionComponent', 'Controller/Component');
				SessionComponent::setFlash('Blacklisted value (blocked through a regular expression entry)!');
				return false;
			}
		}
		return $string;
	}
}
