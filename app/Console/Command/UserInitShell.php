<?php
class UserInitShell extends AppShell {
	public $uses = array('User', 'Role');
	public function main() {
		$this->Role->Behaviors->unload('SysLogLogable.SysLogLogable');
		$this->User->Behaviors->unload('SysLogLogable.SysLogLogable');
		// populate the DB with the first role (site admin) if it's empty
		if ($this->Role->find('count') == 0 ) {
			$siteAdmin = array('Role' => array(
					'id' => 1,
					'name' => 'Site Admin',
					'permission' => 3,
					'perm_sync' => 1,
					'perm_admin' => 1,
					'perm_audit' => 1,
					'perm_auth' => 1,
					'perm_site_admin' => 1,
					'perm_regexp_access' => 1,
					'perm_tagger' => 1,
					'perm_template' => 1,
					'perm_site_admin' => 1
			));
			$this->Role->save($siteAdmin);
		}
		// populate the DB with the first user if it's empty
		if ($this->User->find('count') == 0 ) {
			$authkey = $this->User->generateAuthKey();
			$admin = array('User' => array(
					'id' => 1,
					'email' => 'admin@admin.test',
					'org' => 'ADMIN',
					'password' => 'admin',
					'confirm_password' => 'admin',
					'authkey' => $authkey,
					'nids_sid' => 4000000,
					'newsread' => date('Y-m-d'),
					'role_id' => 1,
					'change_pw' => 0,
					'termsaccepted' => 1
			));
			$this->User->validator()->remove('password'); // password is to simple, remove validation
			$this->User->save($admin);
			echo $authkey . PHP_EOL;
		} else {
			echo 'Script aborted: MISP instance already initialised.' . PHP_EOL;			
		}
	}
}
