<?php

namespace Console\Command\Task;

class UsersTask extends Shell {

	public $uses = array('User');

	public $Users;

	public function main() {
		$this->Users = new UsersController();
		$this->Users->constructClasses();

		$users = ClassRegistry::init('User');
		// perform clean
		$users->checkAndCorrectPgps();
	}
}
