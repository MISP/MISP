<?php
class DbRoleSchema extends CakeSchema {

	public $name = 'DbRole';

	public function before($event = array()) {
		return true;
	}

	public function after($event = array()) {
		if (isset($event['create'])) {
			switch ($event['create']) {
				case 'roles':
					// populate roles
					//$roles = ClassRegistry::init('Role');
					//$roles->create();
					//$roles->save(array('Role' => array('name' => 'malware analyst', 'perm_add' => true, 'perm_modify' => true, 'perm_publish' => false, 'perm_full' => false)));
					//$roles->create();
					//$roles->save(array('Role' => array('name' => 'admin', 'perm_add' => true, 'perm_modify' => true, 'perm_publish' => true, 'perm_full' => true)));
					//$roles->create();
					//$roles->save(array('Role' => array('name' => 'IDS analyst', 'perm_add' => true, 'perm_modify' => true, 'perm_publish' => true, 'perm_full' => false)));
					//$roles->create();
					//$roles->save(array('Role' => array('name' => 'guest', 'perm_add' => false, 'perm_modify' => false, 'perm_publish' => false, 'perm_full' => false)));
					// populate Users.role_id
					//$users = ClassRegistry::init('User');
					//$user = $users->read(null, '1');
					//$users->saveField('role_id', '2');	// $user['User']['role_id'] = '2';
					break;
			}
		}
	}

	public $roles = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => null, 'key' => 'primary'),
		'name' => array('type' => 'string', 'null' => false, 'default' => null, 'length' => 100, 'collate' => 'latin1_swedish_ci', 'charset' => 'latin1'),
		'created' => array('type' => 'datetime', 'null' => true, 'default' => null),
		'modified' => array('type' => 'datetime', 'null' => true, 'default' => null),
		'perm_add' => array('type' => 'boolean', 'null' => true, 'default' => null),
		'perm_modify' => array('type' => 'boolean', 'null' => true, 'default' => null),
		'perm_modify_org' => array('type' => 'boolean', 'null' => true, 'default' => null),
		'perm_publish' => array('type' => 'boolean', 'null' => true, 'default' => null),
		'perm_sync' => array('type' => 'boolean', 'null' => true, 'default' => null),
		'perm_admin' => array('type' => 'boolean', 'null' => true, 'default' => null),
		'perm_audit' => array('type' => 'boolean', 'null' => true, 'default' => null),
		'perm_full' => array('type' => 'boolean', 'null' => true, 'default' => null),
		'indexes' => array('PRIMARY' => array('column' => 'id', 'unique' => 1)),
		'tableParameters' => array('charset' => 'latin1', 'collate' => 'latin1_swedish_ci', 'engine' => 'InnoDB')
	);
}