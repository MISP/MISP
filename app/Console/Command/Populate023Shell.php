<?php

class Populate023Shell extends AppShell {

	public $tasks = array('Roles', 'RoleToAroAco', 'RoleId');

	public function main() {
		// perform tasks
		sleep(30);
		$this->Roles->execute();
		$this->RoleId->execute('2');
		$this->RoleToAroAco->execute();
	}
}