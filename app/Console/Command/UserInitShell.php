<?php
class UserInitShell extends AppShell {
	public $uses = array('User', 'Role', 'Organisation', 'Server', 'ConnectionManager');
	public function main() {
		if (!Configure::read('Security.salt')) {
			$this->loadModel('Server');
			$this->Server->serverSettingsSaveValue('Security.salt', $this->User->generateRandomPassword(32));
		}
		$dataSourceConfig = ConnectionManager::getDataSource('default')->config;
		$dataSource = $dataSourceConfig['datasource'];
		$this->Role->Behaviors->unload('SysLogLogable.SysLogLogable');
		$this->User->Behaviors->unload('SysLogLogable.SysLogLogable');
		// populate the DB with the first role (site admin) if it's empty
		if ($this->Role->find('count') == 0 ) {
			$siteAdmin = array('Role' => array(
					'id' => 1,
					'name' => 'Site Admin',
					'permission' => 3,
					'perm_add' => 1,
					'perm_modify' => 1,
					'perm_modify_org' => 1,
					'perm_publish' => 1,
					'perm_sync' => 1,
					'perm_admin' => 1,
					'perm_audit' => 1,
					'perm_auth' => 1,
					'perm_site_admin' => 1,
					'perm_regexp_access' => 1,
					'perm_sharing_group' => 1,
					'perm_tagger' => 1,
					'perm_template' => 1
			));
			$this->Role->save($siteAdmin);
			// PostgreSQL: update value of auto incremented serial primary key after setting the column by force
			if ($dataSource == 'Database/Postgres') {
				$sql = "SELECT setval('roles_id_seq', (SELECT MAX(id) FROM roles));";
				$this->Role->query($sql);
			}
		}

		if ($this->Organisation->find('count', array('conditions' => array('Organisation.local' => true))) == 0) {
			$date = date('Y-m-d H:i:s');
			$org = array('Organisation' => array(
					'id' => 1,
					'name' => !empty(Configure::read('MISP.org')) ? Configure::read('MISP.org') : 'ADMIN',
					'description' => 'Automatically generated admin organisation',
					'type' => 'ADMIN',
					'date_created' => $date,
					'uuid' => CakeText::uuid(),
					'local' => 1
			));
			$this->Organisation->save($org);
			// PostgreSQL: update value of auto incremented serial primary key after setting the column by force
			if ($dataSource == 'Database/Postgres') {
				$sql = "SELECT setval('organisations_id_seq', (SELECT MAX(id) FROM organisations));";
				$this->Organisation->query($sql);
			}
			$org_id = $this->Organisation->id;
		} else {
			$hostOrg = $this->Organisation->find('first', array('conditions' => array('Organisation.name' => Configure::read('MISP.org')), 'recursive' => -1));
			if (!empty($hostOrg)) $org_id = $hostOrg['Organisation']['id'];
			else {
				$firstOrg = $this->Organisation->find('first', array('conditions' => array('Organisation.local' => true), 'order' => 'Organisation.id ASC'));
				$org_id = $firstOrg['Organisation']['id'];
			}
		}

		// populate the DB with the first user if it's empty
		if ($this->User->find('count') == 0 ) {
			$authkey = $this->User->generateAuthKey();
			$admin = array('User' => array(
					'id' => 1,
					'email' => 'admin@admin.test',
					'org_id' => $org_id,
					'password' => 'admin',
					'confirm_password' => 'admin',
					'authkey' => $authkey,
					'nids_sid' => 4000000,
					'newsread' => 0,
					'role_id' => 1,
					'change_pw' => 0,
					'termsaccepted' => 1
			));
			$this->User->validator()->remove('password'); // password is to simple, remove validation
			$this->User->save($admin);
			// PostgreSQL: update value of auto incremented serial primary key after setting the column by force
			if ($dataSource == 'Database/Postgres') {
				$sql = "SELECT setval('users_id_seq', (SELECT MAX(id) FROM users));";
				$this->User->query($sql);
			}
			echo $authkey . PHP_EOL;
		} else {
			echo 'Script aborted: MISP instance already initialised.' . PHP_EOL;
		}
	}
}
