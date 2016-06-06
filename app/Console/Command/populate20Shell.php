<?php

class Populate023Shell extends AppShell {

	public $tasks = array('Roles', 'RoleToAroAco', 'RoleId', 'Users');

	public function main() {
		// perform tasks
		sleep(30);
		$this->Roles->execute();
		$this->RoleId->execute('2');
		$this->RoleToAroAco->execute();
		// on user data
		$this->Users->execute();
	}
}
