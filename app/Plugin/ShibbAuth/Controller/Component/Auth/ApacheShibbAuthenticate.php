<?php

App::uses('BaseAuthenticate', 'Controller/Component/Auth');
App::uses('RandomTool', 'Tools');

if (session_status() == PHP_SESSION_NONE) {
	session_start();
}
session_regenerate_id();
/*
 * custom class for Apache-based authentication
 *
 * User for ApacheAuthenticate you can pass in settings to which fields, model and additional conditions
 * are used. See FormAuthenticate::$settings for more information.
 * TODO: clarification needed, text almost the same as in lib/Cake/Controller/Component/Auth/FormAuthenticate.php
 *
 * CakePHP version 2.8.5
 *
 * @package       Controller.Component.Auth
 * @since 2.0
 * @see ApacheAuthComponent::$authenticate
 */

class ApacheShibbAuthenticate extends BaseAuthenticate {


	/**
	 * Authentication class
	 *
	 * Configuration in app/Config/Config.php is:
	 *
	 * 'ApacheShibbAuth' =>                      // Configuration for shibboleth authentication
	 *     array(
	 *      'MailTag' => 'EMAIL_TAG',
	 *      'OrgTag' => 'FEDERATION_TAG',
	 *      'GroupTag' => 'GROUP_TAG',
	 *      'GroupSeparator' => ';',
	 *      'GroupRoleMatching' => array(                // 3:User, 1:admin. May be good to set "1" for the first user
	 *          'group_three' => '3',
	 *          'group_two' => 2,
	 *          'group_one' => 1,
	 *       ),
	 *      'DefaultOrg' => 'MY_ORG',
	 * ),
	 * @param CakeRequest $request The request that contains login information.
	 * @param CakeResponse $response Unused response object.
	 * @return mixed False on login failure. An array of User data on success.
	 */

	public function authenticate(CakeRequest $request, CakeResponse $response)
	{
		return self::getUser($request);
	}

	/**
	 * @return array|bool
	 */
	public function getUser(CakeRequest $request)
	{

		//If the url contains sso=disable we return false so the main misp authentication form is used to log in
		if (array_key_exists('sso', $request->query) && $request->query['sso'] == 'disable' || (isset($_SESSION["sso_disable"]) &&  $_SESSION["sso_disable"] === True)) {
			$_SESSION["sso_disable"]=True;
			return false;
		}

		// Get Default parameters
		$roleId = -1;
		$org = Configure::read('ApacheShibbAuth.DefaultOrg');
		$useDefaultOrg = Configure::read('ApacheShibbAuth.UseDefaultOrg');
		// Get tags from SSO config
		$mailTag = Configure::read('ApacheShibbAuth.MailTag');
		$OrgTag = Configure::read('ApacheShibbAuth.OrgTag');
		$groupTag = Configure::read('ApacheShibbAuth.GroupTag');
		$groupRoleMatching = Configure::read('ApacheShibbAuth.GroupRoleMatching');

		// Get user values
		if (!isset($_SERVER[$mailTag]) || filter_var($_SERVER[$mailTag], FILTER_VALIDATE_EMAIL) === FALSE) {
			CakeLog::write('error', 'Mail tag is not given by the SSO SP. Not processing login.');
			return false;
		}

		$mispUsername = $_SERVER[$mailTag];
		CakeLog::write('info', "Trying login of user: ${mispUsername}.");

		//Change username column for email (username in shibboleth attributes corresponds to the email in MISPs DB)
		$this->settings['fields'] = array('username' => 'email');

		// Find user with real username (mail)
		$user = $this->_findUser($mispUsername);

		//Obtain default org. If default is not enforced and it is given, org keeps the default value
		if (!$useDefaultOrg && isset($_SERVER[$OrgTag])) {
			$org = $_SERVER[$OrgTag];
		}

		//Check if the organization exits and create it if not
		$org = $this->checkOrganization($org, $user);

		//Get user role from its list of groups
		list($roleChanged, $roleId) = $this->getUserRoleFromGroup($groupTag, $groupRoleMatching, $roleId);
		if($roleId < 0) {
			CakeLog::write('error', 'No role was assigned, no egorup matched the configuration.');
			return false; //Deny if the user is not in any egroup
		}

		// Database model object
		$userModel = ClassRegistry::init($this->settings['userModel']);

		if ($user) { // User already exists
			CakeLog::write('info', "User ${mispUsername} found in database.");
			$user = $this->updateUserRole($roleChanged, $user, $roleId, $userModel);
			$user = $this->updateUserOrg($org, $user, $userModel);
			CakeLog::write('info', "User ${mispUsername} logged in.");
			return $user;
		}

		CakeLog::write('info', "User ${mispUsername} not found in database.");
		//Insert user in database if not existent

		// Generate random password
		$password = $userModel->generateRandomPassword();
		// Generate random auth key
		$authKey = $userModel->generateAuthKey();
		// get maximum nids value
		$nidsMax = $userModel->find('all', array(
			'fields' => array('MAX(User.nids_sid) AS nidsMax'),
			)
		);
		// create user
		$userData = array('User' => array(
			'email' => $mispUsername,
			'org_id' => $org,
			'password' => $password, //Since it is done via shibboleth the password will be a random 40 character string
			'confirm_password' => $password,
			'authkey' => $authKey,
			'nids_sid' => ((int)$nidsMax[0][0]['nidsMax'])+1,
			'newsread' => time(),
			'role_id' => $roleId,
			'change_pw' => 0
		));

		// save user
		$userModel->save($userData, false);
		CakeLog::write('info', "User ${mispUsername} saved in database.");
		CakeLog::write('info', "User ${mispUsername} logged in.");
		return $this->_findUser(
			$mispUsername
		);
	}

	/**
	 * @param $roleChanged
	 * @param $user
	 * @param $roleId
	 * @param $userModel
	 * @return mixed
	 */
	public function updateUserRole($roleChanged, $user, $roleId, $userModel)
	{
		if ($roleChanged && $user['role_id'] != $roleId) {
			CakeLog::write('warning', "User role changed from ${user['role_id']} to ${roleId}.");
			$user['role_id'] = $roleId; // Different role either increase or decrease permissions
			$userUpdatedData = array('User' => $user);
			$userModel->set(array(
				'role_id' => $roleId,
				'id' => $user['id'],
			)); // Update the user
			$userModel->save($userUpdatedData, false);
			return $user;
		}
		return $user;
	}

	/**
	 * @param $groupTag
	 * @param $groupRoleMatching
	 * @param $roleId
	 * @return array
	 */
	public function getUserRoleFromGroup($groupTag, $groupRoleMatching, $roleId)
	{
		//Check the role mapping to get the user's role level and update it if needed
		$roleChanged = false;
		if (isset($_SERVER[$groupTag])) {
			$groupSeparator = Configure::read('ApacheShibbAuth.GroupSeparator');
			$groupList = explode($groupSeparator, $_SERVER[$groupTag]);
			//Check user roles and egroup match and update if needed
			foreach ($groupList as $group) {
				//TODO: Can be optimized inverting the search group and using only array_key_exists
				if (array_key_exists($group, $groupRoleMatching)) { //In case there is an group not defined in the config.php file
					CakeLog::write('info', "User group ${group} found.");
					$roleVal = $groupRoleMatching[$group];
					if ($roleVal <= $roleId || $roleId == -1) {
						$roleId = $roleVal;
						$roleChanged = true;
					}
					CakeLog::write('info', "User role ${roleId} assigned.");
				}
			}
			return array($roleChanged, $roleId);
		}
		return array($roleChanged, $roleId);
	}

	/**
	 * @param $org
	 * @param $user
	 * @return array|bool|int|mixed|string
	 */
	public function checkOrganization($org, $user)
	{
		$orgModel = ClassRegistry::init('Organisation');
		$orgAux = $orgModel->find('first', array(
				'fields' => array('Organisation.id'),
				'conditions' => array('name' => $org),
			)
		);
		if ($orgAux == null) {
			$organisations = new Organisation();
			$orgUserId = 1; //By default created by the admin
			if ($user) $orgUserId = $user['id'];
			$orgId = $organisations->createOrgFromName($org, $orgUserId, 0); //Created with local set to 0 by default
			CakeLog::write('info', "User organisation ${org} created with id ${orgId}.");
		} else {
			$orgId = $orgAux['Organisation']['id'];
			CakeLog::write('info', "User organisation ${org} found with id ${orgId}.");
		}
		return $orgId;
	}

	private function updateUserOrg($org, $user, $userModel)
	{
		if ($user['org_id'] != $org) {
			CakeLog::write('warning', "User organisation ${org} changed.");
			$user['org_id'] = $org; // Different role either increase or decrease permissions
			$userUpdatedData = array('User' => $user);
			$userModel->set(array(
				'org_id' => $org,
				'id' => $user['id'],
			)); // Update the user
			$userModel->save($userUpdatedData, false);
			return $user;
		}
		return $user;
	}
}
