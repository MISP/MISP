<?php
App::import('Controller', 'Roles');

class RoleToAroAcoTask extends Shell {

	var $uses = array('Role');
	var $Roles;

	public function execute() {
		$this->Roles = new RolesController();
		$this->Roles->constructClasses();

		$roles = $this->Role->find('all');
		foreach ($roles as $role) {
			$this->Roles->saveAcl(array('model' => 'Role', 'foreign_key' => $role['Role']['id']), $role['Role']['perm_add'], $role['Role']['perm_modify'], $role['Role']['perm_publish']);
		}
	}
}