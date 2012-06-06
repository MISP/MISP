<?php

App::uses('AuthComponent', 'Controller/Component');

class SecureAuthComponent extends AuthComponent {


    /**
     * Log a user in using anti-brute-force protection.
     * If a $user is provided that data will be stored as the logged in user.  If `$user` is empty or not
     * specified, the request will be used to identify a user. If the identification was successful,
     * the user record is written to the session key specified in AuthComponent::$sessionKey. Logging in
     * will also change the session id in order to help mitigate session replays.
     *
     * @param mixed $user Either an array of user data, or null to identify a user using the current request.
     * @return boolean True on login success, false on failure
     * @link http://book.cakephp.org/2.0/en/core-libraries/components/authentication.html#identifying-users-and-logging-them-in
     */
    public function login($user = null) {
        $this->_setDefaults();

        if (empty($user)) {
            $this->Bruteforce = ClassRegistry::init('Bruteforce');
            // do the anti-bruteforce checks
            $username_field = $this->authenticate['Form']['fields']['username'];
            if (isset($this->request->data['User'][$username_field])) {
                $username = $this->request->data['User'][$username_field];
                if (!$this->Bruteforce->isBlacklisted($_SERVER['REMOTE_ADDR'], $username)) {
                    // user - ip combination is not blacklisted
                    // check if the user credentials are valid
                    $user = $this->identify($this->request, $this->response);
                    if ($user === false) {
                        // insert row in Bruteforce table
                        $this->Bruteforce->insert($_SERVER['REMOTE_ADDR'], $username);
                        // do nothing as user is not logged in
                    }
                } else {
                    // user - ip combination has reached the amount of maximum attempts in the timeframe
                    throw new ForbiddenException('You have reached the maximum number of login attempts. Please wait '.Configure::read('SecureAuth.expire').' seconds and try again.');
                }
            } else {
                // user didn't fill in all the form fields, nothing to do
            }
        }
        if ($user) {
            $this->Session->renew();
            $this->Session->write(self::$sessionKey, $user);
        }
        return $this->loggedIn();
    }

}