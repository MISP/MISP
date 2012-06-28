<?php
App::import('Controller', 'Groups');

class GroupToAroAcoTask extends Shell {

	var $uses = array('Group');
	var $Groups;

	public function execute() {
		$this->Groups = new GroupsController();
        $this->Groups->constructClasses();

    	$groups = $this->Group->find('all');
        foreach ($groups as $group) {
        	$this->Groups->saveAcl(array('model' => 'Group', 'foreign_key' => $group['Group']['id']), $group['Group']['perm_add'], $group['Group']['perm_modify'], $group['Group']['perm_publish']);
    	}
	}
}