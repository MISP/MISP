<?php
App::uses('RolesController', 'Controller');

class RolesTask extends Shell {

	public $uses = array('Role');

	public $Roles;

	public function execute() {
		$this->Roles = new RolesController();
		$this->Roles->constructClasses();

		$roles = ClassRegistry::init('Role');
		$roles->create();
		$roles->save(array('Role' => array('name' => 'admin', 'perm_add' => 1, 'perm_modify' => 1, 'perm_publish' => 1, 'perm_full' => 1, 'perm_sync' => 1, 'perm_audit' => 1, 'perm_auth' => 1)));
		$roles->create();
		$roles->save(array('Role' => array('name' => 'org_admin', 'perm_add' => 1, 'perm_modify' => 1, 'perm_publish' => 0, 'perm_full' => 0, 'perm_sync' => 1, 'perm_audit' => 1, 'perm_auth' => 1)));
		$roles->create();
		$roles->save(array('Role' => array('name' => 'User', 'perm_add' => 1, 'perm_modify' => 1, 'perm_publish' => 0, 'perm_full' => 0, 'perm_sync' => 1, 'perm_audit' => 1, 'perm_auth' => 0)));
		$roles->create();
		$roles->save(array('Role' => array('name' => 'Sync', 'perm_add' => 1, 'perm_modify' => 1, 'perm_publish' => 1, 'perm_full' => 0, 'perm_sync' => 1, 'perm_audit' => 1, 'perm_auth' => 1)));
	}
}
