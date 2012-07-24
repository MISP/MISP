<?php
App::import('Controller', 'Users');

class GroupIdTask extends Shell {

	var $uses = array('User');
	var $Users;

	public function execute($fk = '1') {
		$this->Users = new UsersController();
        $this->Users->constructClasses();
        $this->Users->setgroupid($fk);
	}
}