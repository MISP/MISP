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
		$roles->save(array('Role' => array('name' => 'malware analyst', 'perm_add' => true, 'perm_modify' => true, 'perm_publish' => false, 'perm_full' => false)));
		$roles->create();
		$roles->save(array('Role' => array('name' => 'admin', 'perm_add' => true, 'perm_modify' => true, 'perm_publish' => true, 'perm_full' => true)));
		$roles->create();
		$roles->save(array('Role' => array('name' => 'IDS analyst', 'perm_add' => true, 'perm_modify' => true, 'perm_publish' => true, 'perm_full' => false)));
		$roles->create();
		$roles->save(array('Role' => array('name' => 'guest', 'perm_add' => false, 'perm_modify' => false, 'perm_publish' => false, 'perm_full' => false)));
	}
}