<?php
/**
 * ThreatLevelFixture
 *
 */
class ThreatLevelFixture extends CakeTestFixture {

/**
 * Fields
 *
 * @var array
 */
	public $fields = array(
		'id' => array('type' => 'boolean', 'null' => false, 'default' => null, 'key' => 'primary'),
		'name' => array('type' => 'string', 'null' => false, 'length' => 50, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'description' => array('type' => 'string', 'null' => true, 'default' => null, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'form_description' => array('type' => 'string', 'null' => false, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'indexes' => array(
			'PRIMARY' => array('column' => 'id', 'unique' => 1)
		),
		'tableParameters' => array('charset' => 'latin1', 'collate' => 'latin1_swedish_ci', 'engine' => 'InnoDB')
	);

/**
 * Records
 *
 * @var array
 */
	public $records = array(
		array(
			'id' => 1,
			'name' => 'High',
			'description' => '*high* means immediate attention',
			'form_description' => 'Needs immediate attention'
		),
		array(
			'id' => 2,
			'name' => 'Medium',
			'description' => '*medium* means needs attention today',
			'form_description' => 'Needs attention today'
		),
		array(
			'id' => 3,
			'name' => 'Low',
			'description' => 'Urgency levels: *low* means needs attention this week',
			'form_description' => 'Needs attention this week'
		),
		array(
			'id' => 4,
			'name' => 'Undefined',
			'description' => '*undefined* no risk',
			'form_description' => 'No risk'
		),
	);

}
