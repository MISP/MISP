<?php
App::uses('RolesController', 'Controller');

class RoleToAroAcoTask extends Shell {

	public $uses = array('Role');

	public $Roles;

	public function execute() {
		$this->Roles = new RolesController();
		$this->Roles->constructClasses();

		$roles = $this->Role->find('all');
		foreach ($roles as $role) {
			$this->Roles->saveAcl(array('model' => 'Role', 'foreign_key' => $role['Role']['id']), $role['Role']['perm_add'], $role['Role']['perm_modify'], $role['Role']['perm_publish'], $role['Role']['perm_admin'], $role['Role']['perm_sync'], $role['Role']['perm_auth'], $role['Role']['perm_audit']);
		}
	}
}
