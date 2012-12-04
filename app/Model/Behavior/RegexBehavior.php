<?php

App::uses('Regex', 'Model');

/**
 * Behavior to trim all string fields in a model
 *
 * @author noud
 *
 */
class RegexBehavior extends ModelBehavior {

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
		$returnValue = $this->regexStringFields(&$Model);

		return $returnValue;
	}

/**
 * Trim String Fields
 *
 * @param Model $Model
 * @param unknown_type $array
 */
	public function regexStringFields(Model $Model) {
		$returnValue = true;
		foreach ($Model->data[$Model->name] as $key => &$field) {
			if (in_array($key, $this->settings[$Model->alias]['fields']) && is_string($field)) {
				$returnValue = $this->replaceWindowsSpecific($Model, &$field);
//				if (!$returnValue) {
//					$Model->blacklistErrors[] = array($key, $field);
//				}
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
		$regex = new Regex();
		$allRegex = $regex->getAll();
		foreach($allRegex as $regex) {
			if (strlen($regex['Regex']['replacement'])) {
				$string = preg_replace($regex['Regex']['regex'], $regex['Regex']['replacement'], $string);
			}
			if (!strlen($regex['Regex']['replacement']) && preg_match($regex['Regex']['regex'], $string)) {
				App::uses('SessionComponent', 'Controller/Component');
				SessionComponent::setFlash('Blacklisted value!');
            	$returnValue = false;
			}
		}
		return $returnValue;
	}
}
