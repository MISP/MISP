<?php

App::uses('BaseAuthenticate', 'Controller/Component/Auth');
App::uses('LinOTP', 'LinOTPAuth.Lib');

/**
 * @package       Controller.Component.Auth
 * @since 2.0
 * @see ApacheAuthComponent::$authenticate
 */
class LinOTPAuthenticate extends BaseAuthenticate
{

    private static $user = null;

    /*
     * Try to authenticate the incoming request against the LinOTP backend.
     * The function may redirect the user if there are more authentication steps required that do not fit the standard function signature.
     * @return array|bool
     */
    public function authenticate(CakeRequest $request, CakeResponse $response)
    {
        $user = false;

        if (!array_key_exists("User", $request->data)) {
            return false;
        }

        $userFields = $request->data['User'];
        $email = $userFields['email'];
        $password = $userFields['password'];
        CakeLog::debug("getUser email: ${email}");

        $linotp = new LinOTP(
            Configure::read("LinOTPAuth.baseUrl"),
            Configure::read("LinOTPAuth.realm")
        );

        $response = $linotp->validate_check($email, $password);

        // If LinOTP didn't reject the request we can go on to further authentication steps, user login or creation
        if ($response !== false) {
            if ($response['value'] === true) { // user can be logged in, authentication successful
                $this->settings['fields'] = array('username' => "email");

                $user = $this->_findUser($email);
                if ($user) {
                    // When the user logs in for the first time a password prompt will appear
                    // To avoid that very prompt we are changing the `change_pw` value to '0'.
                    if ($user['change_pw'] === "1") {
                        $userModel = ClassRegistry::init($this->settings['userModel']);
                        $user['change_pw'] = '0';
                        $userModel->set(array(
                            "id" => $user['id'],
                            "change_pw" => $user['change_pw'],
                        ));
                        $userModel->save(array('User' => $user), false);

                        $user = $this->_findUser($email);
                    }
                } else {
                    CakeLog::error("User ${email} authenticated but not found in database.");
                    $user = false;
                }
            }
        }

        self::$user = $user;

        return $user;
    }

    /*
     * Retrieve a user by validating the request data
     */
    public function getUser(CakeRequest $request)
    {
        if (self::$user !== null) {
            return self::$user;
        }

        return false;
    }
}