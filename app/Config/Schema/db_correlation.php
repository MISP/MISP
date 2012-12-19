<?php
class DbCorrelationSchema extends CakeSchema {

	public $name = 'DbCorrelation';

	public function before($event = array()) {
		return true;
	}

	public function after($event = array()) {
	}

	public $correlations = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => null, 'key' => 'primary'),
		'1_event_id' => array('type' => 'integer', 'null' => false, 'default' => null, 'key' => 'index'),
		'1_attribute_id' => array('type' => 'integer', 'null' => false, 'default' => null, 'key' => 'index'),
		'1_private' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
		'event_id' => array('type' => 'integer', 'null' => false, 'default' => null, 'key' => 'index'),
		'attribute_id' => array('type' => 'integer', 'null' => false, 'default' => null, 'key' => 'index'),
		'org' => array('type' => 'string', 'null' => false, 'default' => null, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'private' => array('type' => 'boolean', 'null' => false, 'default' => null),
		'cluster' => array('type' => 'boolean', 'null' => false, 'default' => null),
		'date' => array('type' => 'date', 'null' => false, 'default' => null),
		'indexes' => array('PRIMARY' => array('column' => 'id', 'unique' => 1)),
		'tableParameters' => array('charset' => 'utf8', 'collate' => 'utf8_bin', 'engine' => 'MyISAM')
	);
}