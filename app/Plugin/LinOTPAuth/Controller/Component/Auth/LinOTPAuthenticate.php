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
     * Handle the login from the Username and Password form.
     *
     * Returns the user array on successful login with any additional LinOTP challenge data that we might have received.
     *
     * @return array|bool
     */
    private function _authenticateUsernamePassword(CakeRequest $request, CakeResponse $response) {
        $user = false;
        $userFields = $request->data['LinOTPUserPassword'];
        $email = $userFields['email'];
        $password = $userFields['password'];
        $this->settings['fields'] = array('username' => "email");
        $user = $this->_findUser($email);

        if (!$user) {
            // if the user isn't known in MISP do not bother going further
            return false;
        }

        $linotp = $this->_getLinOTP();
        $response = $linotp->validate_check($email, $password);

        // If LinOTP didn't reject the request we can go on to further authentication steps, user login or creation
        if ($response === false) {
            return false;
        }

        if ($response['status'] === false) {
            CakeLog::error("LinOTP returned status == false. Authentication failed");
            return false;
        }

        // LinOTP only returns details if the provided credentials were okay,
        // the value might still be false in that case indicating that the authentication didn't succeed.
        // We treat it as success since there isn't really a tri-state in this authentication interface.
        // For now this auth backend should only be used with the custom view that knows how to deal with these
        // situations.
        $hasDetail = array_key_exists("detail", $response);

        // Login failed and no details given is the simplest error case we fail authentication here.
        if ($response['value'] === false && !$hasDetail) {
            return false;
        }

        // user can be logged in, authentication successful
        // Check if we have additional details from LinOTP
        // Those must be passed on so other parts of the authentication chain (the Login view) can route based
        // on those.
        if ($hasDetail) {
            $user['LinOTPChallenges'] = $response['detail'];
        }

        // When the user logs in for the first time a password prompt will appear
        // To avoid that very prompt we are changing the `change_pw` value to '0'.
        if ($user['change_pw'] === "1") {
            $userModel = ClassRegistry::init($this->settings['userModel']);
            $user['change_pw'] = '0';
            $userModel->set(array(
                "id" => $user['id'],
                "change_pw" => '0',
            ));
            $userModel->save(array('User' => $user), false);
            $user = $this->_findUser($email);
        }

        if (!$user) {
            // normalise the negative case to false
            return false;
        }

        return $user;
    }

    /*
     * Handle the second stage login. This is usually an OTP the user was asked for.
     *
     * It does return the user array if the authentication can be considered successful. Otherwise returns false.
     *
     * @return array|bool
     */
    private function _authenticateSecondFactor(CakeRequest $request, CakeResponse $response) {
        $transactionId = $request->params['LinOTPTransactionId'];
        $username = $request->params['LinOTPUserName'];

        if (!$transactionId || !$username) {
            CakeLog::error("transactionId or username not set. Aborting authentication.");
            return false;
        }

        $data = $request->data['LinOTPOTP'];
        $otp = $data['OTP'];
        if (!$data || !$otp) {
            CakeLog::error("LinOTP second stage data missing. Aborting authentication.");
            return false;
        }

        $this->settings['fields'] = array('username' => "email");
        $user = $this->_findUser($username);

        if (!$user) {
            // user not found in database. Refuse authentication
            CakeLog::error("User not found in database. Aborting authentication.");
            return false;
        }

        $linotp = $this->_getLinOTP();

        $response = $linotp->validate_check($username, $otp, $transactionId);

        if ($response === false) {
            return false;
        }

        if ($response['status'] !== true) {
            CakeLog::error("LinOTP authentication failed. LinOTP reported some internal error.");
            return false;
        }

        if ($response['value'] !== true) {
            return false;
        }

        $hasDetail = array_key_exists("detail", $response);
        if ($hasDetail) {
            CakeLog::error("LinOTP accepted our additional factor but still wants more. Not implemented.");
            return false;
        }

        CakeLog::debug("YAY! We are authenticated!");
        return $user;
    }

    /*
     * Try to authenticate the incoming request against the LinOTP backend.
     * The function may redirect the user if there are more authentication steps required that do not fit the standard function signature.
     * @return array|bool
     */
    public function authenticate(CakeRequest $request, CakeResponse $response)
    {
        // Initialize a save default. All authentication requests that fail for whatever reason should be invalid.
        $user = false;

        // Check for any of the known 'Models' from the Login view.
        // The `LinOTPUserPassword` model is the classical username and password login.
        // The `LinOTPOTP` model is any additional response to a challenge that was previously requested by LinOTP.
        // For the second case we also require a valid transaction id within the request params.
        if (array_key_exists("LinOTPUserPassword", $request->data)) {
            $user = $this->_authenticateUsernamePassword($request, $response);
        } else if (
            array_key_exists("LinOTPOTP", $request->data) &&
            // the two following fields are a bit of a hack.. We can either use the singleton CakeSession or pass it in
            // from the view using these params.
            array_key_exists('LinOTPTransactionId', $request->params) &&
            array_key_exists("LinOTPUserName" , $request->params)
        ) {
            $user = $this->_authenticateSecondFactor($request, $response);
        }

        // Cache the result for further calls to `getUser`. We never want to run the same authentication twice without
        // the user asking us to do so twice.
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

    /*
     * Retrieve a configured instance of the LinOTP class
     */
    private function _getLinOTP() {
        $linotp = new LinOTP(
            Configure::read("LinOTPAuth.baseUrl"),
            Configure::read("LinOTPAuth.realm")
        );
        return $linotp;
    }
}