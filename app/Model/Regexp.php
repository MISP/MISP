<?php

App::uses('AppModel', 'Model');

/**
 * Regexp Model
 *
 */
class Regexp extends AppModel {

	public $actsAs = array(
			'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
					'roleModel' => 'Role',
					'roleKey' => 'role_id',
					'change' => 'full'
			),
	);
/**
 * Use table
 *
 * @var mixed False or table name
 */
	public $useTable = 'regexp';

	// this checks whether the regexp would fail and if yes, the entry is blocked from being entered.
	public function beforeValidate($options = array()) {
		$test = preg_replace($this->data['Regexp']['regexp'], 'success', $this->data['Regexp']['regexp']);
		if ($test == null) return false;
		return true;
	}
}