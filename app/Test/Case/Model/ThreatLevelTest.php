<?php
App::uses('ThreatLevel', 'Model');

/**
 * ThreatLevel Test Case
 *
 */
class ThreatLevelTest extends CakeTestCase {

/**
 * Fixtures
 *
 * @var array
 */
	public $fixtures = array(
		'app.threat_level',
		'app.event',
		'app.user',
		'app.role',
		'app.post',
		'app.thread',
		'app.attribute',
		'app.shadow_attribute'
	);

/**
 * setUp method
 *
 * @return void
 */
	public function setUp() {
		parent::setUp();
		$this->ThreatLevel = ClassRegistry::init('ThreatLevel');
	}

/**
 * tearDown method
 *
 * @return void
 */
	public function tearDown() {
		unset($this->ThreatLevel);

		parent::tearDown();
	}

}
