<?php
App::import('Controller', 'Users');

class UsersTask extends Shell {

	public $uses = array('User');

	public $Users;

	public function execute() {
		$this->Users = new UsersController();
		$this->Users->constructClasses();

		$users = ClassRegistry::init('User');
		// perform clean
		$users->checkAndCorrectPgps();
		//$users->create();
		//$users->save(array('User' => array('name' => 'malware analyst', 'perm_add' => true, 'perm_modify' => true, 'perm_publish' => false, 'perm_full' => false)));
	}
}