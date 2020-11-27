<?php

App::uses('BaseAuthenticate', 'Controller/Component/Auth');
App::uses('RandomTool', 'Tools');

if (session_status() == PHP_SESSION_NONE) {
	session_start();
}

//  Generating a new session will fail the further flow of AAD. 
//	session_regenerate_id();

class AadAuthenticateAuthenticate extends BaseAuthenticate {	

	/**
	 * Holds the application ID
	 *
	 * @var string
	 */
	protected static $client_id;

	/**
	 * Azure Active Directory Tenant ID, with Multitenant apps you can use "common" as Tenant ID, but using specific endpoint is recommended when possible
	 *
	 * @var string
	 */
	protected static $ad_tenant;

	/**
	 * Client Secret, remember that this expires someday unless you haven't set it not to do so
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

	/**
	 * Provider authentication URL
	 *
	 * @var string
	 */	
	protected static $auth_provider;

	/**
	 * Provider URL for additional user details
	 *
	 * @var string
	 */	
	protected static $auth_provider_user;

	/**
	 * Flag that indicates if we need to check for AD groups for defining MISP access
	 *
	 * @var bool
	 */	
	protected static $check_ad_groups;

	/**
	 * AD group MISP user
	 *
	 * @var string
	 */	
	protected static $misp_user;

	/**
	 * AD group MISP org admin
	 *
	 * @var string
	 */		
	protected static $misp_orgadmin;

	/**
	 * AD group MISP siteadmin
	 *
	 * @var string
	 */		
	protected static $misp_siteadmin;


	public function __construct()
	{
		self::$client_id = Configure::read('AadAuth.client_id');
		self::$ad_tenant =  Configure::read('AadAuth.ad_tenant');
		self::$client_secret =  Configure::read('AadAuth.client_secret');
		self::$redirect_uri =  Configure::read('AadAuth.redirect_uri');
		self::$auth_provider =  Configure::read('AadAuth.auth_provider');
		self::$auth_provider_user =  Configure::read('AadAuth.auth_provider_user');
		self::$misp_user =  Configure::read('AadAuth.misp_user');
		self::$misp_orgadmin =  Configure::read('AadAuth.misp_orgadmin');
		self::$misp_siteadmin =  Configure::read('AadAuth.misp_siteadmin');
		self::$check_ad_groups =  Configure::read('AadAuth.check_ad_groups');

		$this->Log = ClassRegistry::init('Log');
		$this->Log->create();

		$this->settings['fields'] = array('username' => 'email');
	}

	/**
	 * Log to MISP and Cake
	 * 
	 * @param string $level			Log level
	 * @param string $logmessage	Message to log
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
		// we only proceed if called with a request to authenticate via AAD
		if (array_key_exists('AzureAD', $request->query) and $request->query['AzureAD'] == 'enable') {
			$user = $this->_getUserAad($request);
			return $user;
		}
		elseif (array_key_exists('code', $request->query))  // in the Azure flow
		{
			$user = $this->_getUserAad($request);
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
	 * Get the AAD user
	 * 
	 * @param CakeRequest $request The request that contains login information.
	 * @return mixed False on login failure. An array of User data on success.
	 */		
	private function _getUserAad(CakeRequest $request)
	{
		if (!headers_sent()) {			
			if (!isset($_GET["code"]) and !isset($_GET["error"])) {
				$url = self::$auth_provider . self::$ad_tenant . "/oauth2/v2.0/authorize?";
				$url .= "state=" . session_id();
				$url .= "&scope=User.Read";
				$url .= "&response_type=code";
				$url .= "&approval_prompt=auto";
				$url .= "&client_id=" . self::$client_id;
				$url .= "&redirect_uri=" . urlencode(self::$redirect_uri);
				header("Location: " . $url);  //So off you go my dear browser and welcome back for round two after some redirects at Azure end
				$this->_log("info", "Redirect to Azure for authentication.");
				exit; // we need to exit once the header to redirect to Azure is sent

			} 
			elseif (isset($_GET["error"])) {  //Second load of this page begins, but hopefully we end up to the next elseif section...
				$this->_log("warning", "Return from Aure redirect. Error received at the beginning of second stage. _GET: " . http_build_query($_GET,'','  -  '));
				return false;
			}
			elseif (strcmp(session_id(), $_GET["state"]) == 0) {
				//Verifying the received tokens with Azure and finalizing the authentication part
				$content = "grant_type=authorization_code";
				$content .= "&client_id=" . self::$client_id;
				$content .= "&redirect_uri=" . urlencode(self::$redirect_uri);
				$content .= "&code=" . $_GET["code"];
				$content .= "&client_secret=" . urlencode(self::$client_secret);
				$options = array(
					"http" => array(  //Use "http" even if you send the request with https
					"method"  => "POST",
					"header"  => "Content-Type: application/x-www-form-urlencoded\r\n" .
						"Content-Length: " . strlen($content) . "\r\n",
					"content" => $content
					)
				);
				
				$context  = stream_context_create($options);
				$json = file_get_contents(self::$auth_provider . self::$ad_tenant . "/oauth2/v2.0/token", false, $context);
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
				$this->_log("info", "Fetching user data from Azure.");
				$json = file_get_contents(self::$auth_provider_user . "/v1.0/me", false, $context);
				if ($json === false) {
					$this->_log("warning", "Error received during user data fetch.");
					// For debug : "PHP_Error" => error_get_last(), "\$_GET[]" => $_GET, "HTTP_msg" => $options), $error_email);
					return false;
				}

				$userdata = json_decode($json, true);  //This should now contain your logged on user information
				if (isset($userdata["error"])){
					$this->_log("warning", "User data fetch contained an error.");
					// For debug : "\$userdata[]" => $userdata, "\$authdata[]" => $authdata, "\$_GET[]" => $_GET, "HTTP_msg" => $options), $error_email);
					return false;
				} 

				$mispUsername = false;
				if (isset($userdata["userPrincipalName"])){
					$userPrincipalName = $userdata["userPrincipalName"];

					/*
					 * TODO: add code to create users that exist in AAD but not in MISP
					 * 		 similar as in ApacheShibbAuthenticate
					 */

					if (self::$check_ad_groups) {
						if ($this->_checkAdGroup($authdata)) {
							$mispUsername = $userPrincipalName;
						}
					}
					else {
						$mispUsername = $userPrincipalName;
					}

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

	/**
	 * Lookup the AAD groups this user belongs to
	 * 
	 * @param array $authdata The authdata array received from Azure
	 * @return mixed False if no MISP groups have been found; String if a group was found
	 */		
	private function _checkAdGroup($authdata) 
	{
		$options = array(
			"http" => array( //Use "http" even if you send the request with https
			  "method" => "GET",
			  "header" => "Accept: application/json\r\n" .
				"Authorization: Bearer " . $authdata["access_token"] . "\r\n"
			)
		  );

		$context = stream_context_create($options);
		$this->_log("info", "Fetching user group data from Azure.");
		$json = file_get_contents(self::$auth_provider_user . "/v1.0/me/memberOf", false, $context);
		if ($json === false) {
			$this->_log("warning", "Error received during user group data fetch.");	
			// For debug : "PHP_Error" => error_get_last(), "\$_GET[]" => $_GET, "HTTP_msg" => $options), $error_email);
			return false;
		} 

		$groupdata = json_decode($json, true);  //This should now contain your logged on user memberOf (groups) information
		if (isset($groupdata["error"])) {
			$this->_log("warning", "Group data fetch contained an error.");
			// For debug : "\$groupdata[]" => $groupdata, "\$authdata[]" => $authdata, "\$_GET[]" => $_GET, "HTTP_msg" => $options), $error_email);
			return false;
		} 

		// Now check if the user has any of the MISP AAD groups enabled
		foreach ($groupdata["value"] as $group) {
			$groupdisplayName = $group["displayName"];
			if ($groupdisplayName == self::$misp_siteadmin) {
				return self::$misp_siteadmin;
			}			  
			if ($groupdisplayName == self::$misp_orgadmin) {
				return self::$misp_orgadmin;
			}
			if ($groupdisplayName == self::$misp_user) {
				return self::$misp_user;
			}
		}

		return false;
	}

}
