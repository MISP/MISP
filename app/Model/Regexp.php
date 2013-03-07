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
}