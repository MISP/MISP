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
            "user" => $user,
            "pass" => $password,
            "realm" => $realm,
        );

        $url = "$baseUrl/validate/check";

        CakeLog::debug( "Sending POST request to ${url}");
        try {
            $results = $HttpSocket->post($url, $data);
        }
        catch (SocketException $ex) {
            CakeLog::error("LinOTP: {$ex->getMessage()}.");
            return false;
        }
        if ($results->code != "200") {
            return false;
        }
        $response = json_decode($results->body());

        if ($response == false) {
            CakeLog::error("LinOTP request for user ${user} failed.");
            return false;
        } else {
            if (gettype($response) !== "object") {
                CakeLog::error("Response from LinOTP is not an JSON dictionary/array. Got an " .gettype($response). ": ".$response);
                return false;
            }

            if (!property_exists($response,"result")) {
                CakeLog::error("Missing 'result' key in LinOTP response.");
                return false;
            }
            $result = $response->result;

            if (!property_exists($result,"status")) {
                CakeLog::error("Missing 'status' key in result envelope from LinOTP.");
                return false;
            }
            $status = $result->status;

            if (!property_exists($result, "value")) {
                CakeLog::error("Missing 'value' key in result envelop from LinOTP.");
                return false;
            }
            $value = $result->value;

            $ret = array(
                "status" => $status,
                "value" => $value,
            );

            if (property_exists($result, 'detail')) {
                $ret['detail'] = $result->detail;
            }

            CakeLog::debug("user: ${user} - status: ${status} value: ${value}");
            // CakeLog::debug(var_dump($ret));
            return $ret;
        }
        // If bad things happens
        CakeLog::debug("LinOTP-Plugin couldn't parse results from LinOTP API. Check logs.");
        return false;
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
        $otp = $userFields['otp'];

        CakeLog::debug("getUser email: ${email}");

        $linOTP_enabled = Configure::read("LinOTPAuth.enabled");
        if (is_null($linOTP_enabled)) {
            $linOTP_enabled = TRUE;
        }
        if (!$linOTP_enabled) {
            return false;
        }
        $linOTP_baseUrl = rtrim(Configure::read("LinOTPAuth.baseUrl"), "/");
        $linOTP_realm = Configure::read("LinOTPAuth.realm");
        $linOTP_verifyssl = Configure::read("LinOTPAuth.verifyssl");
        $mixedauth = Configure::read("LinOTPAuth.mixedauth");

        if (!$linOTP_baseUrl || $linOTP_baseUrl === "") {
            CakeLog::error("LinOTP: Please configure baseUrl.");
            if ($mixedauth) {
                throw new ForbiddenException(__('LinOTP: Missing "baseUrl" configuration - access denied!'));
            } else {
                return false;
            }
        }

        // If not mixed auth mode - concat password with otp
        if (!$mixedauth) {
            $password = $password . $otp;
            $response = $this->_linotp_verify(
                $linOTP_baseUrl,
                $linOTP_realm,
                $email,
                $password,
                $linOTP_verifyssl
            );
        } else {
            // Enforce OTP token by Authentication Form
            if (!$otp || $otp === "") {
                throw new ForbiddenException(__('Missing OTP Token.'));
            }

            $response = $this->_linotp_verify(
                $linOTP_baseUrl,
                $linOTP_realm,
                $email,
                $otp,
                $linOTP_verifyssl
            );
        }

        // If LinOTP didn't reject the request we can go on to further authentication steps, user login or creation
        if ($response !== false) {
            if ($response['value'] === true) { // user can be logged in, authentication successful
                $this->settings['fields'] = array('username' => "email");

                if ($mixedauth) {
                    $this->settings['fields'] += array('password' => "password");
                    $this->settings['passwordHasher'] = "BlowfishConstant";
                    $user = $this->_findUser($email, $password);
                } else {
                    $user = $this->_findUser($email);
                }
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
        // Don't fall back to FormAuthenticate in mixedauth mode.
        // This enforces the second factor.
        if ($mixedauth && !self::$user) {
            throw new UnauthorizedException(__('User could not be authenticated by LinOTP.'));
        }
        return self::$user;
    }
}