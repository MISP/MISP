<?php

App::uses('Regexp', 'Model');

/**
 * Behavior to regexp all string fields in a model
 *
 */
class RegexpBehavior extends ModelBehavior {

	private $__allRegexp = array();

	public $excluded_types = array('sigma', 'float');

	public function setup(Model $model, $config = null) {
		$regexp = new Regexp();
		$this->__allRegexp = $regexp->find('all', array('order' => 'id ASC'));
	}

/**
 * replace the current value according to the regexp rules, or block blacklisted regular expressions
 *
 * @param Model $Model
 * @param unknown_type $array
 */
	public function runRegexp(Model $Model, $type, $value) {
		if (in_array($type, $this->excluded_types)) {
			return $value;
		}
		foreach ($this->__allRegexp as $regexp) {
			if (!empty($regexp['Regexp']['replacement']) && !empty($regexp['Regexp']['regexp']) && ($regexp['Regexp']['type'] === 'ALL' || $regexp['Regexp']['type'] === $type)) {
				$value = preg_replace($regexp['Regexp']['regexp'], $regexp['Regexp']['replacement'], $value);
			}
			if (empty($regexp['Regexp']['replacement']) && preg_match($regexp['Regexp']['regexp'], $value) && ($regexp['Regexp']['type'] === 'ALL' || $regexp['Regexp']['type'] === $type)) {
				return false;
			}
		}
		return $value;
	}
}
