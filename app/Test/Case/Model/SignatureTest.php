<?php
App::uses('Signature', 'Model');

/**
 * Signature Test Case
 *
 */
class SignatureTestCase extends CakeTestCase {
/**
 * Fixtures
 *
 * @var array
 */
	public $fixtures = array('app.signature', 'app.event');

/**
 * setUp method
 *
 * @return void
 */
	public function setUp() {
		parent::setUp();
		$this->Signature = ClassRegistry::init('Signature');
	}

/**
 * tearDown method
 *
 * @return void
 */
	public function tearDown() {
		unset($this->Signature);

		parent::tearDown();
	}

}
