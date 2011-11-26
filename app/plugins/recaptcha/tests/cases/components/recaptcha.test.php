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

App::import('Lib', 'AppTestCase');
App::import('Core', 'Controller');
App::import('Component', 'Recaptcha.Recaptcha');

Mock::generatePartial('Recaptcha', 'RecaptchaMock', array('_getApiResponse'));

if (!class_exists('ArticlesTestController')) {
	class ArticleTestController extends Controller {
		public $name = 'ArticleTests';
		public $components = array('Recaptcha.Recaptcha');
		public $uses = array('RecaptchaTestArticle');
		public function test_captcha() {
		}
	}
}

if (!class_exists('RecaptchaTestArticle')) {
	class RecaptchaTestArticle extends CakeTestModel {
		public $name = 'RecaptchaTestArticle';
		public $actsAs = array('Recaptcha.Recaptcha');
		public $useTable = 'articles';
	}
}

/**
 * RecaptchaTestCase
 *
 * @package recaptcha
 * @subpackage recaptcha.tests.cases.components
 */
class RecaptchaTestCase extends AppTestCase {
/**
 * fixtures property
 *
 * @var array
 */
	public $fixtures = array('plugin.recaptcha.article');

/**
 * startTest
 *
 * @return void
 */
	function startTest() {
		$this->Controller = new ArticleTestController();
		$this->Controller->constructClasses();
		//$this->Controller->modelClass = 'RecaptchaTestArticle';
		$this->Controller->Component->init($this->Controller);
		$this->Controller->Component->initialize($this->Controller);
	}

/**
 * endTest
 *
 * @return void
 */
	function endTest() {
		unset($this->Controller);
		ClassRegistry::flush();
	}

/**
 * testRecaptcha
 *
 * @return void
 */
	public function testRecaptcha() {
		$this->Controller->params['form']['recaptcha_challenge_field'] = 'something';
		$this->Controller->params['form']['recaptcha_response_field'] = 'something';
		$this->assertFalse($this->Controller->Recaptcha->verify());
	}

}
