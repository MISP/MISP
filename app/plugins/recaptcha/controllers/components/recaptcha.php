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

/**
 * CakePHP Recaptcha component
 *
 * @package recaptcha
 * @subpackage recaptcha.controllers.components
 */
class RecaptchaComponent extends Object {

/**
 * Name
 *
 * @var string
 */
	public $Controller = null;

/**
 * Recaptcha API Url
 *
 * @var string
 */
	public $apiUrl = 'http://api-verify.recaptcha.net/verify';

/**
 * Private API Key
 *
 * @var string
 */
	public $privateKey = '';

/**
 * Error coming back from Recaptcha
 *
 * @var string
 */
	public $error = null;

/**
 * Actions that should automatically checked for a recaptcha input
 *
 * @var array
 */
	public $actions = array();

/**
 * Settings
 *
 * @var array
 */
	public $settings = array();

 /**
 * Callback
 *
 * @param object Controller object
 */
	public function initialize(Controller $controller, $settings = array()) {
		$this->privateKey = Configure::read('Recaptcha.privateKey');
		$this->Controller = $controller;

		if (empty($this->privateKey)) {
			throw new Exception(__d('recaptcha', "You must set your private recaptcha key using Configure::write('Recaptcha.privateKey', 'your-key');!", true));
		}

		$defaults = array(
			'modelClass' => $this->Controller->modelClass,
			'errorField' => 'recaptcha',
			'actions' => array());

		$this->settings = array_merge($defaults, $settings);
		$this->actions = array_merge($this->actions, $this->settings['actions']);
		extract($this->settings);

		if ($this->enabled == true) {
			$this->Controller->helpers[] = 'Recaptcha.Recaptcha';
			$this->Controller->{$modelClass}->Behaviors->attach('Recaptcha.Recaptcha', array(
				'field' => $errorField));

			$this->Controller->{$modelClass}->recaptcha = true;
			if (in_array($this->Controller->action, $this->actions)) {
				if (!$this->verify()) {
					$this->Controller->{$modelClass}->recaptcha = false;
					$this->Controller->{$modelClass}->recaptchaError = $this->error;
				}
			}
		}
	}

/**
 * Verifies the recaptcha input
 *
 * Please note that you still have to pass the result to the model and do
 * the validation there to make sure the data is not saved!
 *
 * @return boolean True if the response was correct
 */
	public function verify() {
		if (isset($this->Controller->params['form']['recaptcha_challenge_field']) && 
			isset($this->Controller->params['form']['recaptcha_response_field'])) {

			$response = $this->_getApiResponse();
			$response = explode("\n", $response);

			if ($response[0] == 'true') {
				return true;
			}

			if ($response[1] == 'incorrect-captcha-sol') {
				$this->error = __d('recaptcha', 'Incorrect captcha', true);
			} else {
				$this->error = $response[1];
			}

			return false;
		}
	}

/**
 * Queries the Recaptcha API and and returns the raw response
 *
 * @return string
 */
	protected function _getApiResponse() {
		App::import('Core', 'HttpSocket');
		$Socket = new HttpSocket();
		return $Socket->post($this->apiUrl, array(
			'privatekey'=> $this->privateKey,
			'remoteip' => env('REMOTE_ADDR'),
			'challenge' => $this->Controller->params['form']['recaptcha_challenge_field'],
			'response' => $this->Controller->params['form']['recaptcha_response_field']));
	}

}
