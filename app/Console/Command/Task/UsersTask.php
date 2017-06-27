<?php
App::uses('UsersController', 'Controller');

class UsersTask extends Shell {

	public $uses = array('User');

	public $Users;

	public function execute() {
		$this->Users = new UsersController();
		$this->Users->constructClasses();

		$users = ClassRegistry::init('User');
		// perform clean
		$users->checkAndCorrectPgps();
	}
}
