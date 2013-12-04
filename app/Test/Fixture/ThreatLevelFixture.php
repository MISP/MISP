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
			'description' => '*high* means sophisticated APT malware or 0-day attack',
			'form_description' => 'Sophisticated APT malware or 0-day attack'
		),
		array(
			'id' => 2,
			'name' => 'Medium',
			'description' => '*medium* means APT malware',
			'form_description' => 'APT malware'
		),
		array(
			'id' => 3,
			'name' => 'Low',
			'description' => '*low* means mass-malware',
			'form_description' => 'Mass-malware'
		),
		array(
			'id' => 4,
			'name' => 'Undefined',
			'description' => '*undefined* no risk',
			'form_description' => 'No risk'
		),
	);

}
