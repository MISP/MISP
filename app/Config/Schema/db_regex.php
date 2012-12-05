<?php
class DbRegexSchema extends CakeSchema {

	public $name = 'DbRegex';

	public function before($event = array()) {
		return true;
	}

	public function after($event = array()) {
	}

	public $regex = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary'),
		'regex' => array('type' => 'string', 'null' => false, 'default' => NULL, 'length' => 255, 'collate' => 'latin1_swedish_ci', 'charset' => 'latin1'),
		'replacement' => array('type' => 'string', 'null' => false, 'default' => NULL, 'length' => 255, 'collate' => 'latin1_swedish_ci', 'charset' => 'latin1'),
		'indexes' => array('PRIMARY' => array('column' => 'id', 'unique' => 1)),
		'tableParameters' => array('charset' => 'utf8', 'collate' => 'utf8_bin', 'engine' => 'MyISAM')
	);
}
