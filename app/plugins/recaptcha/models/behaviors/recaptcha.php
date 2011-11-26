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
 * CakePHP Recaptcha Behavior
 *
 * @package recaptcha
 * @subpackage recaptcha.models.behaviors
 */
class RecaptchaBehavior extends ModelBehavior {
/**
 * Settings array
 *
 * @var array
 */
	public $settings = array();

/**
 * Default settings
 *
 * @var array
 */
	public $defaults = array(
		'errorField' => 'recaptcha');

/**
 * Setup
 *
 * @param AppModel $model
 * @param array $settings
 */
	public function setup(Model $Model, $settings = array()) {
		if (!isset($this->settings[$Model->alias])) {
			$this->settings[$Model->alias] = $this->defaults;
		}
		$this->settings[$Model->alias] = array_merge($this->settings[$Model->alias], ife(is_array($settings), $settings, array()));
	}

/**
 * Validates the captcha responses status set by the component to the model
 *
 * @object Model instance
 * @return boolean
 * @see RecaptchaComponent::initialize()
 */
	public function validateCaptcha(Model $Model) {
		if (isset($Model->recaptcha) && $Model->recaptcha === false) {
			$Model->invalidate($this->settings[$Model->alias]['errorField'], $Model->recaptchaError);
		}
		return true;
	}

/**
 * Validates the captcha
 *
 * @object Model instance
 * @return void;
 */
	public function beforeValidate(Model $Model) {
		$this->validateCaptcha($Model);
		return true;
	}
}