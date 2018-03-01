<?php

App::uses('AppModel', 'Model');

class Log extends AppModel {
	public $warningActions = array(
		'warning',
		'change_pw',
		'login_fail',
		'version_warning',
		'auth_fail'
	);
	public $errorActions = array(
		'error'
	);
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
							'undelete',
							'file_upload',
							'export',
							'pruneUpdateLogs',
							'galaxy'
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

	public function beforeValidete() {
		parent::beforeValidate();
		if (!isset($this->data['Log']['org']) || empty($this->data['Log']['org'])) {
			$this->data['Log']['org'] = 'SYSTEM';
		}
	}

	public function beforeSave($options = array()) {
		if (Configure::read('MISP.log_client_ip') && isset($_SERVER['REMOTE_ADDR'])) $this->data['Log']['ip'] = $_SERVER['REMOTE_ADDR'];
		$setEmpty = array('title' => '', 'model' => '', 'model_id' => 0, 'action' => '', 'user_id' => 0, 'change' => '', 'email' => '', 'org' => '', 'description' => '');
		foreach ($setEmpty as $field => $empty) {
			if (!isset($this->data['Log'][$field]) || empty($this->data['Log'][$field])) $this->data['Log'][$field] = $empty;
		}
		if (!isset($this->data['Log']['created'])) $this->data['Log']['created'] = date('Y-m-d H:i:s');
		if (!isset($this->data['Log']['org'])) $this->data['Log']['org'] = 'SYSTEM';
		$truncate_fields = array('title', 'change', 'description');
		foreach ($truncate_fields as $tf) {
			if (isset($this->data['Log'][$tf]) && strlen($this->data['Log'][$tf]) >= 65535) {
				$this->data['Log'][$tf] = substr($this->data['Log'][$tf], 0, 65532) . '...';
			}
		}
		$this->logData($this->data);
		return true;
	}

	public function returnDates($org = 'all') {
		$dataSourceConfig = ConnectionManager::getDataSource('default')->config;
		$dataSource = $dataSourceConfig['datasource'];
		$conditions = array();
		$this->Organisation = ClassRegistry::init('Organisation');
		if ($org !== 'all') {
			$org = $this->Organisation->find('first', array('fields' => array('name'), 'recursive' => -1, 'conditions' => array('UPPER(Organisation.name) LIKE' => strtoupper($org))));
			if (empty($org)) return MethodNotAllowedException('Invalid organisation.');
			$conditions['org'] = $org['Organisation']['name'];
		}
		$conditions['AND']['NOT'] = array('action' => array('login', 'logout', 'changepw'));
		if ($dataSource == 'Database/Mysql') {
			$validDates = $this->find('all', array(
					'fields' => array('DISTINCT UNIX_TIMESTAMP(DATE(created)) AS Date', 'count(id) AS count'),
					'conditions' => $conditions,
					'group' => array('Date'),
					'order' => array('Date')
			));
		} else if ($dataSource == 'Database/Postgres') {
			// manually generate the query for Postgres
			// cakephp ORM would escape "DATE" datatype in CAST expression
			$condnotinaction = "'" . implode("', '", $conditions['AND']['NOT']['action']) . "'";
			if (!empty($conditions['org'])) $condOrg = ' AND org = "' . $conditions['org'] . '"';
			else $condOrg = '';
			$sql = 'SELECT DISTINCT EXTRACT(EPOCH FROM CAST(created AS DATE)) AS "Date",
									COUNT(id) AS count
					FROM logs
					WHERE action NOT IN (' . $condnotinaction . ')
					' . $condOrg . '
					GROUP BY "Date" ORDER BY "Date"';
			$validDates = $this->query($sql);
		}
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

	// to combat a certain bug that causes the upgrade scripts to loop without being able to set the correct version
	// this function remedies a fixed upgrade bug instance by eliminating the massive number of erroneous upgrade log entries
	public function pruneUpdateLogs($jobId = false, $user) {
		$max = $this->find('first', array('fields' => array('MAX(id) AS lastid')));
		if (!empty($max)) {
			$max = $max[0]['lastid'];
		}
		if ($jobId) {
			$this->Job = ClassRegistry::init('Job');
			$this->Job->id = $jobId;
			if (!$this->Job->exists()) {
				$jobId = false;
			}
		}
		$iterations = ($max / 1000);
		for ($i = 0; $i < $iterations; $i++) {
			$this->deleteAll(array(
				'OR' => array(
						'action' => 'update_database',
						'AND' => array(
							'action' => 'edit',
							'model' => 'AdminSetting'
						)
				),
				'id >' => $i * 1000,
				'id <' => ($i+1) * 1000));
			if ($jobId) {
				$this->Job->saveField('progress', $i * 100 / $iterations);
			}
		}
		$this->create();
		$this->save(array(
				'org' => $user['Organisation']['name'],
				'email' =>$user['email'],
				'user_id' => $user['id'],
				'action' => 'pruneUpdateLogs',
				'title' => 'Pruning updates',
				'change' => 'Pruning completed in ' . $i . ' iteration(s).',
				'model' => 'Log',
				'model_id' => 0
		));
	}


	public function pruneUpdateLogsRouter($user) {
		if (Configure::read('MISP.background_jobs')) {
			$job = ClassRegistry::init('Job');
			$job->create();
			$data = array(
					'worker' => 'default',
					'job_type' => 'prune_update_logs',
					'job_input' => 'All update entries',
					'status' => 0,
					'retries' => 0,
					'org_id' => $user['org_id'],
					'org' => $user['Organisation']['name'],
					'message' => 'Purging the heretic.',
			);
			$job->save($data);
			$jobId = $job->id;
			$process_id = CakeResque::enqueue(
					'default',
					'AdminShell',
					array('prune_update_logs', $jobId, $user['id']),
					true
			);
			$job->saveField('process_id', $process_id);
			return $process_id;
		} else {
			$result = $this->pruneUpdateLogs(false, $user);
			return $result;
		}
	}

	function logData($data) {
		if (Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_user_notifications_enable')) {
			$pubSubTool = $this->getPubSubTool();
			$pubSubTool->publish($data, 'audit', 'log');
		}
		if (Configure::read('Security.syslog')) {
			// write to syslogd as well
			$syslog = new SysLog();
			$action = 'info';
			if (isset($data['Log']['action'])) {
				if (in_array($data['Log']['action'], $this->errorActions)) {
					$action = 'err';
				}
				if (in_array($data['Log']['action'], $this->warningActions)) {
					$action = 'warning';
				}
			}

			$entry = $data['Log']['action'];
			if (!empty($data['Log']['description'])) {
				$entry .= sprintf(' -- %s', $data['Log']['description']);
			}
			$syslog->write($action, $entry);
		}
		return true;
	}
}
