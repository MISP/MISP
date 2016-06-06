<?php
App::import('Controller', 'Roles');

class RolesTask extends Shell {

	public $uses = array('Role');

	public $Roles;

	public function execute() {
		$this->Roles = new RolesController();
		$this->Roles->constructClasses();

		$roles = ClassRegistry::init('Role');
		$roles->create();
		$roles->save(array('Role' => array('name' => 'admin', 'perm_add' => true, 'perm_modify' => true, 'perm_publish' => true, 'perm_full' => true, 'perm_sync' => true, 'perm_audit' => true, 'perm_auth' =>true)));
		$roles->create();
		$roles->save(array('Role' => array('name' => 'org_admin', 'perm_add' => true, 'perm_modify' => true, 'perm_publish' => false, 'perm_full' => false, 'perm_sync' => true, 'perm_audit' => true, 'perm_auth' =>true)));
		$roles->create();
		$roles->save(array('Role' => array('name' => 'User', 'perm_add' => true, 'perm_modify' => true, 'perm_publish' => false, 'perm_full' => false, 'perm_sync' => true, 'perm_audit' => true, 'perm_auth' =>false)));
		$roles->create();
		$roles->save(array('Role' => array('name' => 'Sync', 'perm_add' => true, 'perm_modify' => true, 'perm_publish' => true, 'perm_full' => false, 'perm_sync' => true, 'perm_audit' => true, 'perm_auth' =>true)));
	}
}
