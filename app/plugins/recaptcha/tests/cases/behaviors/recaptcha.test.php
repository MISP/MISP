<?php
/**
 * Copyright 2009-2010, Cake Development Corporation (http://cakedc.com)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright Copyright 2009-2010, Cake Development Corporation (http://cakedc.com)
 * @license MIT License (http://www.opensource.org/licenses/mit-license.php)
 */

App::import('Behavior', 'Recaptcha.Recaptcha');

/**
 * Slugged Article
 */
class RecaptchaArticle extends CakeTestModel {
	public $name = 'RecaptchaArticle';
	public $actsAs = array('Recaptcha.Recaptcha');
	public $useTable = 'articles';
}

/**
 * Recaptcha Test case
 */
class RecaptchaBehaviorTest extends CakeTestCase {

/**
 * fixtures property
 *
 * @var array
 */
	public $fixtures = array('plugin.recaptcha.article');

/**
 * Creates the model instance
 *
 * @return void
 */
	public function startTest() {
		$this->Model = new RecaptchaArticle();
		$this->Behavior = new RecaptchaBehavior();
	}

/**
 * Destroy the model instance
 *
 * @return void
 */
	public function endTest() {
		unset($this->Model);
		unset($this->Behavior);
		ClassRegistry::flush();
	}

/**
 * testValidateCaptcha
 *
 * @return void
 */
	public function testValidateCaptcha() {
		$this->Model->validateCaptcha();
		$result = $this->Model->invalidFields();
		$this->assertTrue(empty($result));

		$this->Model->recaptcha = false;
		$this->Model->recaptchaError = 'Invalid Recaptcha';
		$this->Model->validateCaptcha();
		$result = $this->Model->invalidFields();
		$this->assertEqual($result, array('recaptcha' => 'Invalid Recaptcha'));
	}

}