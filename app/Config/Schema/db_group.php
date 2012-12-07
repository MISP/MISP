<?php
class DbGroupSchema extends CakeSchema {

	public $name = 'DbGroup';

	public function before($event = array()) {
		return true;
	}

	public function after($event = array()) {
		if (isset($event['create'])) {
		        switch ($event['create']) {
		            case 'groups':
		            	// populate groups
//		                $groups = ClassRegistry::init('Group');
//		                $groups->create();
//		                $groups->save(array('Group' => array('name' => 'malware analyst', 'perm_add' => true, 'perm_modify' => true, 'perm_publish' => false, 'perm_full' => false)));
//		                $groups->create();
//		                $groups->save(array('Group' => array('name' => 'admin', 'perm_add' => true, 'perm_modify' => true, 'perm_publish' => true, 'perm_full' => true)));
//		                $groups->create();
//		                $groups->save(array('Group' => array('name' => 'IDS analyst', 'perm_add' => true, 'perm_modify' => true, 'perm_publish' => true, 'perm_full' => false)));
//		                $groups->create();
//		                $groups->save(array('Group' => array('name' => 'guest', 'perm_add' => false, 'perm_modify' => false, 'perm_publish' => false, 'perm_full' => false)));
		            	// populate Users.group_id
//		                $users = ClassRegistry::init('User');
//			        	$user = $users->read(null, '1');
//			        	$users->saveField('group_id', '2');	// $user['User']['group_id'] = '2';
		                break;
		        }
		}
	}

	public $groups = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary'),
		'name' => array('type' => 'string', 'null' => false, 'default' => NULL, 'length' => 100, 'collate' => 'latin1_swedish_ci', 'charset' => 'latin1'),
		'created' => array('type' => 'datetime', 'null' => true, 'default' => NULL),
		'modified' => array('type' => 'datetime', 'null' => true, 'default' => NULL),
		'perm_add' => array('type' => 'boolean', 'null' => true, 'default' => NULL),
		'perm_modify' => array('type' => 'boolean', 'null' => true, 'default' => NULL),
		'perm_modify_org' => array('type' => 'boolean', 'null' => true, 'default' => NULL),
		'perm_publish' => array('type' => 'boolean', 'null' => true, 'default' => NULL),
		'perm_sync' => array('type' => 'boolean', 'null' => true, 'default' => NULL),
		'perm_full' => array('type' => 'boolean', 'null' => true, 'default' => NULL),
		'indexes' => array('PRIMARY' => array('column' => 'id', 'unique' => 1)),
		'tableParameters' => array('charset' => 'latin1', 'collate' => 'latin1_swedish_ci', 'engine' => 'InnoDB')
	);
}
