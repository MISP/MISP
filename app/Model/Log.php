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
							'delete',
							'publish' // FIXME remove this once all attributes have a category. Otherwise sigs without category are not shown in the list
						)),
			'message' => 'Options : ...'
		)
	);

	public $actionDefinitions = array(
		'login' => array('desc' => 'Login action', 'formdesc' => "Login action"),
		'logout' => array('desc' => 'Logout action', 'formdesc' => "Logout action"),
		'add' => array('desc' => 'Add action', 'formdesc' => "Add action"),
		'edit' => array('desc' => 'Edit action', 'formdesc' => "Edit action"),
		'delete' => array('desc' => 'Delete action', 'formdesc' => "Delete action"),
		'publish' => array('desc' => "Publish action", 'formdesc' => "Publish action")
	);
}