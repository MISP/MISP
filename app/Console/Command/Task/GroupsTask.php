<?php
App::import('Controller', 'Groups');

class GroupsTask extends Shell {

	var $uses = array('Group');
	var $Groups;

	public function execute() {
		$this->Groups = new GroupsController();
        $this->Groups->constructClasses();
		
		$groups = ClassRegistry::init('Group');
		$groups->create();
		$groups->save(array('Group' => array('name' => 'malware analyst', 'perm_add' => true, 'perm_modify' => true, 'perm_publish' => false, 'perm_full' => false)));    	
    	$groups->create();
    	$groups->save(array('Group' => array('name' => 'admin', 'perm_add' => true, 'perm_modify' => true, 'perm_publish' => true, 'perm_full' => true)));
    	$groups->create();
    	$groups->save(array('Group' => array('name' => 'IDS analyst', 'perm_add' => true, 'perm_modify' => true, 'perm_publish' => true, 'perm_full' => false)));
    	$groups->create();
    	$groups->save(array('Group' => array('name' => 'guest', 'perm_add' => false, 'perm_modify' => false, 'perm_publish' => false, 'perm_full' => false)));
		
	}
}