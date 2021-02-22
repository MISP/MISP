<?php

App::uses('BaseAuthenticate', 'Controller/Component/Auth');
App::uses('RandomTool', 'Tools');

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

//  Generating a new session will fail the further flow of open id connect / oauth.
//	session_regenerate_id();

class OpenIDConnectAuthenticate extends BaseAuthenticate
{

    /**
     * Holds the client id
     *
     * @var string
     */
    protected static $client_id;

    /**
     * IDP url where metadata can be found (e.g. endpoints for authorization, userinfo)
     *
     * @var string
     */
    protected static $idp_metadata_url;

    /**
     * Client Secret
     *
     * @var string
     */
    protected static $client_secret;

    /**
     * Redirect URI
     *
     * @var string
     */
    protected static $redirect_uri;

    public function __construct()
    {
        self::$idp_metadata_url = Configure::read('OICAuth.idp_metadata_url');
        self::$client_id = Configure::read('OICAuth.client_id');
        self::$client_secret = Configure::read('OICAuth.client_secret');
        self::$redirect_uri = Configure::read('MISP.baseurl') . '/users/login';

        $this->Log = ClassRegistry::init('Log');
        $this->Log->create();

        $this->settings['fields'] = array('username' => 'email');
    }

    /**
     * Log to MISP and Cake
     *
     * @param string $level Log level
     * @param string $logmessage Message to log
     * @return bool result of the log action
     */
    private function _log($level, $logmessage)
    {
        $log = array(
            'org' => 'SYSTEM',
            'model' => 'User',
            'model_id' => 0,
            'email' => false,
            'action' => 'auth',
            'title' => $logmessage
        );
        $this->Log->save($log);
        CakeLog::write($level, $logmessage);

        return true;
    }

    /**
     * Find the user to authenticate with
     *
     * @param CakeRequest $request The request that contains login information.
     * @return mixed False on login failure. An array of User data on success.
     */
    public function getUser(CakeRequest $request)
    {
        // we only proceed if called with a request to authenticate via open id connect
        if (array_key_exists('oic', $request->query) and $request->query['oic'] == 'enable') {
            $user = $this->_getUserIDP($request);
            return $user;
        } elseif (array_key_exists('code', $request->query))  // in the IDP flow
        {
            $user = $this->_getUserIDP($request);
            return $user;
        }
        return false;
    }

    /**
     * Authenticate
     *
     * @param CakeRequest $request The request that contains login information.
     * @param CakeResponse $response Unused response object.
     * @return mixed False on login failure. An array of User data on success.
     */
    public function authenticate(CakeRequest $request, CakeResponse $response)
    {
        return self::getUser($request);
    }

    /**
     * Get the IDP user
     *
     * @param CakeRequest $request The request that contains login information.
     * @return mixed False on login failure. An array of User data on success.
     */
    private function _getUserIDP(CakeRequest $request)
    {
        $raw_idp_metadata = file_get_contents(self::$idp_metadata_url, false);
        if ($raw_idp_metadata === false) {
            $this->_log("error", "Could not receive metadata from idp provider");
            // For debug : "PHP_Error" => error_get_last(), "\$_GET[]" => $_GET, "HTTP_msg" => $options), "");
            return false;
        }
        $idp_metadata = json_decode($raw_idp_metadata, true);

        if (!headers_sent()) {
            if (!isset($_GET["code"]) and !isset($_GET["error"])) {
                $url = $idp_metadata['authorization_endpoint'] . "?";
                $url .= "state=" . session_id();
                $url .= "&scope=email";
                $url .= "&response_type=code";
                $url .= "&approval_prompt=auto";
                $url .= "&client_id=" . self::$client_id;
                $url .= "&redirect_uri=" . urlencode(self::$redirect_uri);
                header("Location: " . $url);  //So off you go my dear browser and welcome back for round two after some redirects at IDP end
                $this->_log("info", "Redirect to IDP for authentication.");
                exit; // we need to exit once the header to redirect to IDP is sent

            } elseif (isset($_GET["error"])) {  //Second load of this page begins, but hopefully we end up to the next elseif section...
                $this->_log("warning", "Return from Aure redirect. Error received at the beginning of second stage. _GET: " . http_build_query($_GET, '', '  -  '));
                return false;
            } elseif (strcmp(session_id(), $_GET["state"]) == 0) {
                //Verifying the received tokens with IDP and finalizing the authentication part
                $content = "grant_type=authorization_code";
                $content .= "&client_id=" . self::$client_id;
                $content .= "&redirect_uri=" . urlencode(self::$redirect_uri);
                $content .= "&code=" . $_GET["code"];
                $content .= "&client_secret=" . urlencode(self::$client_secret);
                $options = array(
                    "http" => array(  //Use "http" even if you send the request with https
                        "method" => "POST",
                        "header" => "Content-Type: application/x-www-form-urlencoded\r\n" .
                            "Content-Length: " . strlen($content) . "\r\n",
                        "content" => $content
                    )
                );

                $context = stream_context_create($options);
                $json = file_get_contents($idp_metadata['token_endpoint'], false, $context);
                if ($json === false) {
                    $this->_log("warning", "Error received during Bearer token fetch (context).");
                    // For debug : "PHP_Error" => error_get_last(), "\$_GET[]" => $_GET, "HTTP_msg" => $options), "");
                    return false;
                }

                $authdata = json_decode($json, true);
                if (isset($authdata["error"])) {
                    $this->_log("warning", "Error received during Bearer token fetch (authdata).");
                    // For debug : "\$authdata[]" => $authdata, "\$_GET[]" => $_GET, "HTTP_msg" => $options), $error_email);
                    return false;
                }

                $options = array(
                    "http" => array(  //Use "http" even if you send the request with https
                        "method" => "GET",
                        "header" => "Accept: application/json\r\n" .
                            "Authorization: Bearer " . $authdata["access_token"] . "\r\n"
                    )
                );

                $context = stream_context_create($options);
                $this->_log("info", "Fetching user data from IDP.");
                $json = file_get_contents($idp_metadata['userinfo_endpoint'], false, $context);
                if ($json === false) {
                    $this->_log("warning", "Error received during user data fetch.");
                    // For debug : "PHP_Error" => error_get_last(), "\$_GET[]" => $_GET, "HTTP_msg" => $options), $error_email);
                    return false;
                }

                $userdata = json_decode($json, true);  //This should now contain your logged on user information
                if (isset($userdata["error"])) {
                    $this->_log("warning", "User data fetch contained an error.");
                    // For debug : "\$userdata[]" => $userdata, "\$authdata[]" => $authdata, "\$_GET[]" => $_GET, "HTTP_msg" => $options), $error_email);
                    return false;
                }

                if (isset($userdata["email"])) {
                    $mispUsername = $userdata["email"];

                    /*
                     * TODO: add code to create users that exist in the IDP but not in MISP
                     * 		 similar as in ApacheShibbAuthenticate
                     */

                    if ($mispUsername) {
                        $this->_log("info", "Attempt authentication for ${mispUsername}");
                        return $this->_findUser($mispUsername);
                    }
                }
            }
        }

        // fall back
        return false;
    }
}
