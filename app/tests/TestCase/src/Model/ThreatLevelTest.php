<?php

/**
 * ThreatLevel Test Case
 *
 */
namespace Test\Case\Model;

class ThreatLevelTest extends TestCase {

/**
 * Fixtures
 *
 * @var array
 */
	public $fixtures = array(
		'app.threat_levels',
		'app.events',
		'app.users',
		'app.roles',
		'app.posts',
		'app.threads',
		'app.attributes',
		'app.shadow_attributes'
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
