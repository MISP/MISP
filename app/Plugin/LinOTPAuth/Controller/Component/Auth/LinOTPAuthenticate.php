<?php

App::uses('BaseAuthenticate', 'Controller/Component/Auth');
App::uses('HttpSocket', 'Network/Http');

/**
 * @package       Controller.Component.Auth
 * @since 2.0
 * @see ApacheAuthComponent::$authenticate
 */
class LinOTPAuthenticate extends BaseAuthenticate
{
    /**
	 * Holds the user information
	 *
	 * @var array
	 */
	protected static $user = false;

    /*
     * Try to authenticate the incoming request against the LinOTP backend.
     * The function may redirect the user if there are more authentication steps required that do not fit the standard function signature.
     * @return array|bool
     */
    public function authenticate(CakeRequest $request, CakeResponse $response)
    {
        $user = $this->getUser($request);
        return $user;
    }

    /*
     * Query LinOTP
     */
    private static function _linotp_verify($baseUrl, $realm, $user, $password, $verifyssl)
    {
        $params = array();
        $params['ssl_allow_self_signed'] = !$verifyssl;
        $params['ssl_verify_peer_name'] = $verifyssl;
        $params['ssl_verify_peer'] = $verifyssl;

        $HttpSocket = new HttpSocket($params);

        // POST data
        $data = array(
            "user" => $email,
            "pass" => $otp,
            "realm" => $realm,
        );

        $url = "$baseUrl/validate/check";

        CakeLog::debug( "Sending POST request to ${url}");
        $results = $HttpSocket->post($url, $data);
        $response = json_decode($results->body());

        return $response;
    }

    /*
     * Retrieve a user by validating the request data
     */
    public function getUser(CakeRequest $request)
    {
        if (!array_key_exists("User", $request->data)) {
            return false;
        }

        $userFields = $request->data['User'];
        $email = $userFields['email'];
        $password = $userFields['password'];
        CakeLog::debug("getUser email: ${email}");

        $linOTP_baseUrl = rtrim(Configure::read("LinOTPAuth.baseUrl"), "/");
        $linOTP_realm = Configure::read("LinOTPAuth.realm");
        $linOTP_verifyssl = Configure::read("LinOTPAuth.verifyssl");

        $response = $this->_linotp_verify(
            $linOTP_baseUrl,
            $linOTP_realm,
            $email,
            $password,
            $linOTP_verifyssl
        );

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

                    // Set instance user to prevent OTP lookup twice
                    self::$user = $user;
                } else {
                    CakeLog::error("User ${email} authenticated but not found in database.");
                    self::$user = false;
                }
            }
        }

        return self::$user;
    }
}