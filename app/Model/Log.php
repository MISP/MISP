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
							'login_fail',
							'logout',
							'add',
							'edit',
							'change_pw',
							'delete',
							'publish',
							'accept',
							'discard',
							'pull',
							'push',
							'blacklisted',
							'admin_email',
							'tag',
							'publish alert',
							'warning',
							'error',
							'email',
							'serverSettingsEdit',
							'remove_dead_workers',
							'upload_sample',
							'update_database',
							'upgrade_24',
							'version_warning',
							'auth',
							'auth_fail',
							'reset_auth_key',
							'update',
							'enable',
							'disable',
							'accept_delegation',
							'request_delegation',
							'merge',
							'undelete'
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

	public $logMeta = array(
		'email' => array('values' => array('email'), 'name' => 'Emails'),
		'auth_issues' => array('values' => array('login_fail', 'auth_fail'), 'name' => 'Authentication issues')
	);

	public $logMetaAdmin = array(
		'update' => array('values' => array('update_database'), 'name' => 'MISP Update results'),
		'settings' => array('values' => array('serverSettingsEdit', 'remove_dead_workers'), 'name' => 'Setting changes'),
		'errors' => array('values' => array('warning', 'errors', 'version_warning'), 'name' => 'Warnings and errors'),
		'email' => array('values' => array('admin_email'))
	);

	public function beforeSave($options = array()) {
		if (Configure::read('MISP.log_client_ip') && isset($_SERVER['REMOTE_ADDR'])) $this->data['Log']['ip'] = $_SERVER['REMOTE_ADDR'];
		$setEmpty = array('title' => '', 'model' => '', 'model_id' => 0, 'action' => '', 'user_id' => 0, 'change' => '', 'email' => '', 'org' => '', 'description' => '');
		foreach ($setEmpty as $field => $empty) {
			if (!isset($this->data['Log'][$field]) || empty($this->data['Log'][$field])) $this->data['Log'][$field] = $empty;
		}
		if (!isset($this->data['Log']['created'])) $this->data['Log']['created'] =  time();
		return true;
	}

	public function returnDates($org = 'all') {
		$conditions = array();
		$this->Organisation = ClassRegistry::init('Organisation');
		if ($org !== 'all') {
			$org = $this->Organisation->find('first', array('fields' => array('name'), 'recursive' => -1, 'conditions' => array('UPPER(Organisation.name) LIKE' => strtoupper($org))));
			if (empty($org)) return MethodNotAllowedException('Invalid organisation.');
			$conditions['org'] = $org['Organisation']['name'];
		}
		$conditions['AND']['NOT'] = array('action' => array('login', 'logout', 'changepw'));
		$validDates = $this->find('all', array(
				'fields' => array('DISTINCT UNIX_TIMESTAMP(DATE(created)) AS Date', 'count(id) AS count'),
				'conditions' => $conditions,
				'group' => array('DATE(created)'),
				'order' => array('Date')
		));
		$data = array();
		foreach ($validDates as $k => $date) {
			$data[$date[0]['Date']] = intval($date[0]['count']);
		}
		return $data;
	}

	public function createLogEntry($user = array('Organisation' => array('name' => 'SYSTEM'), 'email' => 'SYSTEM', 'id' => 0), $action, $model, $model_id = 0, $title = '', $change = '') {
		$this->create();
		$this->save(array(
				'org' => $user['Organisation']['name'],
				'email' =>$user['email'],
				'user_id' => $user['id'],
				'action' => $action,
				'title' => $title,
				'change' => $change,
				'model' => $model,
				'model_id' => $model_id,
		));
	}
}
