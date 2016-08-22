<?php
App::import('Controller', 'Users');

class RoleIdTask extends Shell {

	public $uses = array('User');

	public $Users;

	public function execute($fk = '1') {
		$this->Users = new UsersController();
		$this->Users->constructClasses();
		$this->Users->setRoleId($fk);
		//$this->Users->generateAllForRoleId($fk); // TODO
	}
}
