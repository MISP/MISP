<?php
App::uses('AppModel', 'Model');
/**
 * Log Model
 *
 */
class Log extends AppModel {

	public $validate = array(
			'action' => array(
			'rule' => array('inList', array(
							'login',
							'logout',
							'add',
							'edit',
							'change_pw',
							'delete',
							'publish'
						)),
			'message' => 'Options : ...'
		)
	);

	public $actionDefinitions = array(
		'login' => array('desc' => 'Login action', 'formdesc' => "Login action"),
		'logout' => array('desc' => 'Logout action', 'formdesc' => "Logout action"),
		'add' => array('desc' => 'Add action', 'formdesc' => "Add action"),
		'edit' => array('desc' => 'Edit action', 'formdesc' => "Edit action"),
		'change_pw' => array('desc' => 'Change_pw action', 'formdesc' => "Change_pw action"),
		'delete' => array('desc' => 'Delete action', 'formdesc' => "Delete action"),
		'publish' => array('desc' => "Publish action", 'formdesc' => "Publish action")
	);
}