<?php

App::uses('AuthComponent', 'Controller/Component');

class ApacheSecureAuthComponent extends AuthComponent {

	/**
	 * No brute force safeguard needed because Apache does the job
	 *
	 * If $user is provided that data will be stored as the logged in user.  If $user is empty or not
	 * specified, the request will be used to identify a user. If the identification was successful,
	 * the user record is written to the session key specified in AuthComponent::$sessionKey. Logging in
	 * will also change the session id in order to help mitigate session replays.
	 *
	 * @param mixed $user Either an array of user data or null to identify a user using the current request.
	 * @return boolean True on login success, false on failure
	 * @link http://book.cakephp.org/2.0/en/core-libraries/components/authentication.html#identifying-users-and-logging-them-in
	 * @throws ForbiddenException
	 */
	public function login($user = null) {
		$this->_setDefaults();
		if (empty($user)) {
			// "envvar" is defined in AppController.php
			$usernameField = $this->authenticate['Apache']['fields']['envvar'];
			if (isset($_SERVER[$usernameField])) {
				$username = $_SERVER[$usernameField];
				// check if the user credentials are valid
				$user = $this->identify($this->request, $this->response);
				unset($user['gpgkey']);
			}
		}
		if ($user) {
			$this->Session->renew();
			$this->Session->write(self::$sessionKey, $user);
		}
		return $this->loggedIn();
	}

}
