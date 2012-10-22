<?php 
class DbLogSchema extends CakeSchema {
	
	public $name = 'DbLog';
	
	public function before($event = array()) {
		return true;
	}

	public function after($event = array()) {
	}

	public $logs = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary'),
		'title' => array('type' => 'string', 'null' => true, 'default' => NULL, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'created' => array('type' => 'datetime', 'null' => true, 'default' => NULL),
		'model' => array('type' => 'string', 'null' => true, 'default' => NULL, 'length' => 20, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'model_id' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'action' => array('type' => 'string', 'null' => true, 'default' => NULL, 'length' => 20, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'user_id' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'change' => array('type' => 'string', 'null' => true, 'default' => NULL, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'email' => array('type' => 'string', 'null' => true, 'default' => NULL, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'org' => array('type' => 'string', 'null' => true, 'default' => NULL, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'description' => array('type' => 'string', 'null' => true, 'default' => NULL, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'indexes' => array('PRIMARY' => array('column' => 'id', 'unique' => 1)),
		'tableParameters' => array('charset' => 'utf8', 'collate' => 'utf8_bin', 'engine' => 'MyISAM')
	);
}
