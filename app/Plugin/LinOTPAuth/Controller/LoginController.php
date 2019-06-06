<?php

App::uses("LinOTPAuthenticate", "LinOTPAuth");
App::uses('LinOTP', 'LinOTPAuth.Lib');

class LoginController extends AppController
{
    public $components = array(
        'Auth' => array(
            // we must override the className so that we end up with an Auth object that is configured in a similar
            // fashion as the standard MISP Auth component. If we do not do this our own LinOTPAuthenticate class
            // will not be listed :/
            'className' => 'MISPAuth',
        ),
        'Flash',
        'Session'
    );

    private const LINOTP_TRANSACTION_ID_KEY = 'LinOTPTransactionId';
    private const LINOTP_USER_NAME_KEY = 'LinOTPUserName';

    /*
     * Cache for the identify result of the current request. We want to avoid hitting the backend multiple times.
     * Since the authentication backends are restricted to a simple interface we try to communicate additional information
     * in the return values of those functions. The additional information should not be present when the authentication
     * was successful.
     */
    private static $_identifyResult = null;

    public function beforeFilter()
    {
        // Setup some of the view parameters that are used throughout all the views
        $this->_setupDebugMode();
        $this->_setupBaseurl();
        $this->set('me', false);

        // load the authentication plugins, That list should contain the LinOTPAuth module amongst
        // one of the first entries. If that isn't the case we should not attempt to authenticate via this view.
        $this->_loadAuthenticationPlugins();
        if (!$this->Auth) {
            CakeLog::error("LinOTP Authentication requested but \$this->Auth is not set. Aborting.");
            throw new InternalErrorException("Configuration error.");
        }

        // If we somehow end up here make sure we do not proceed without the required Authentication backend.
        // We could add it to the list here but that might be worse. Lets try to enforce a homogeneous
        // authentication backend configuration within the application.
        if (!$this->Auth->authenticate || !in_array("LinOTPAuth.LinOTP", $this->Auth->authenticate)) {
            CakeLog::error("LinOTPAUth.LinOTP is missing from the Configuration in Security.auth!");
            throw new InternalErrorException("Configuration error.");
        }

        // if there is a transaction id and username add it to the request while removing it from the session
        if ($this->Session->check(self::LINOTP_TRANSACTION_ID_KEY) &&
            $this->Session->check(self::LINOTP_USER_NAME_KEY)
        ) {
            $this->request->params['LinOTPTransactionId'] = $this->Session->consume(self::LINOTP_TRANSACTION_ID_KEY);
            $this->request->params['LinOTPUserName'] = $this->Session->consume(self::LINOTP_USER_NAME_KEY);
        }

        // store the identify result for further inspection during the request,
        // we do not call that function again to avoid incrementing the failure count on the authentication
        // backend.
        self::$_identifyResult = $this->Auth->identify($this->request, $this->response);
        $challengeData = $this->_getLinOTPChallengeData();

        // wipe out any previously known user data from the session
        $this->Session->delete(AuthComponent::$sessionKey);

        if (self::$_identifyResult && $challengeData === false) {
            // This line feels very specific to logging users in yet it is found in multiple places throughout the code:
            // Can we reduce the amount of duplications?
            // It can also be found in the newly introduced `_loadAuthenticationPlugins` method. It should probably not be in there.
            $this->Session->write(AuthComponent::$sessionKey, self::$_identifyResult);

            // after we decided that we can set the "standard" login session field we reset our own session data to avoid
            // issues when logging in again
            $this->_resetSessionData();

            // Finally redirect the user to the location they wanted to access.
            $this->redirect($this->Auth->redirectUrl());
        } else if (is_object($challengeData) && isset($challengeData->transactionid)) {
            // We got some challenge data, store it in the session so we can pass
            $this->Session->write(self::LINOTP_TRANSACTION_ID_KEY, $challengeData->transactionid);

            // also store the email of the user so we can retrieve the full object after an successful login.
            $email = self::$_identifyResult['email'];
            if (!$email) {
                CakeLog::error("got an identification result but the email doesn't exist. Deleting all the login session data");
                $this->_resetSessionData();
            } else {
                $this->Session->write(self::LINOTP_USER_NAME_KEY, $email);
            }
        }
    }

    /*
     * Reset the LinOTP Auth specific session data.
     *
     * We always use this function if we are aborting the login. The idea is to only maintain one location with the
     * logic to wipe all the session data.
     */
    private function _resetSessionData()
    {
        $this->Session->delete(self::LINOTP_USER_NAME_KEY);
        $this->Session->delete(self::LINOTP_TRANSACTION_ID_KEY);
    }

    public function index()
    {
        // Expose the configured LinOTP base URL. This allows us to produce a link to the self-service portal.
        $this->set('linotpBaseUrl', $this->_getLinOTPBaseUrl());

        // check if we are handling a login request that requires additional responses from the user
        // If the login was successful we wouldn't be here. If it was wrong there wouldn't be any additional challenges.
        $challengeData = $this->_getLinOTPChallengeData();
        if ($challengeData) {
            $this->set('challenges', $challengeData);
            $this->render('mfa');
            return;
        }

        // in all other cases just render the "index" aka first stage login form
        $this->render("index");
    }

    /*
     * Retrieve the configured LinOTP base url
     *
     * @return string
     */
    private function _getLinOTPBaseUrl()
    {
        $config = Configure::read('LinOTPAuth');

        if ($config !== null && array_key_exists("baseUrl", $config)) {
            return $config['baseUrl'];
        } else {
            return null;
        }
    }


    /*
     * Extract the LinOTP Challenge data from the identification result that we collect during beforeFilter
     *
     * @return array|false
     */
    private function _getLinOTPChallengeData() {
        // extract data from array or return false if not present. The (??)-operator is PHP7+ only.
        return self::$_identifyResult['LinOTPChallenges'] ?? false;
    }
}
