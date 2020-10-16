<?php
App::uses('BaseAuthenticate', 'Controller/Component/Auth');

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

class ApacheShibbAuthenticate extends BaseAuthenticate
{
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
		return $this->getUser($request);
	}

    /**
     * @param CakeRequest $request
     * @return array|bool
     * @throws Exception
     */
	public function getUser(CakeRequest $request)
	{
		// If the url contains sso=disable we return false so the main misp authentication form is used to log in
		if (array_key_exists('sso', $request->query) && $request->query['sso'] == 'disable' || (isset($_SESSION["sso_disable"]) &&  $_SESSION["sso_disable"] === true)) {
			$_SESSION["sso_disable"] = true;
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
		if (!isset($_SERVER[$mailTag]) || filter_var($_SERVER[$mailTag], FILTER_VALIDATE_EMAIL) === false) {
			CakeLog::write('error', 'Mail tag is not given by the SSO SP. Not processing login.');
			return false;
		}

		$mispUsername = $_SERVER[$mailTag];
		CakeLog::write('info', "Trying login of user: ${mispUsername}.");

		// Change username column for email (username in shibboleth attributes corresponds to the email in MISPs DB)
		$this->settings['fields'] = array('username' => 'email');

		// Find user with real username (mail)
		$user = $this->_findUser($mispUsername);

		// Obtain default org. If default is not enforced and it is given, org keeps the default value
		if (!$useDefaultOrg && isset($_SERVER[$OrgTag])) {
			$org = $_SERVER[$OrgTag];
		}

		// Check if the organization exits and create it if not
		$orgId = $this->checkOrganization($org, $user);

		// Get user role from its list of groups
		list($roleChanged, $roleId) = $this->getUserRoleFromGroup($groupTag, $groupRoleMatching, $roleId);
		if ($roleId < 0) {
			CakeLog::write('error', 'No role was assigned, no egroup matched the configuration.');
			return false; //Deny if the user is not in any egroup
		}

        /** @var User $userModel */
		$userModel = ClassRegistry::init($this->settings['userModel']);

		if ($user) { // User already exists
			CakeLog::write('info', "User ${mispUsername} found in database.");
			$user = $this->updateUserRole($roleChanged, $user, $roleId, $userModel);
			$user = $this->updateUserOrg($orgId, $user, $userModel);
			CakeLog::write('info', "User ${mispUsername} logged in.");
			return $user;
		}

		CakeLog::write('info', "User ${mispUsername} not found in database.");
		// Insert user in database if not existent
		$userData = array('User' => array(
			'email' => $mispUsername,
			'org_id' => $orgId,
			'role_id' => $roleId,
			'change_pw' => 0,
			'date_created' => time(),
		));

		// save user
		$userModel->save($userData);
		CakeLog::write('info', "User ${mispUsername} saved in database.");
		CakeLog::write('info', "User ${mispUsername} logged in.");

		return $this->_findUser($mispUsername);
	}

    /**
     * @param $roleChanged
     * @param array $user
     * @param int $roleId
     * @param User $userModel
     * @return array
     * @throws Exception
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
	 * @param string $groupTag
	 * @param array $groupRoleMatching
	 * @param int $roleId
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
	 * @param string $orgName
	 * @param $user
	 * @return int
	 */
	public function checkOrganization($orgName, $user)
	{
	    /** @var Organisation $orgModel */
		$orgModel = ClassRegistry::init('Organisation');
		$orgAux = $orgModel->find('first', array(
            'fields' => array('Organisation.id'),
            'conditions' => array('name' => $orgName),
        ));
		if ($orgAux == null) {
			$orgUserId = 1; // By default created by the admin
			if ($user) $orgUserId = $user['id'];
			$orgId = $orgModel->createOrgFromName($orgName, $orgUserId, 0); // Created with local set to 0 by default
			CakeLog::write('info', "User organisation ${orgName} created with ID ${orgId}.");
		} else {
			$orgId = $orgAux['Organisation']['id'];
			CakeLog::write('info', "User organisation ${orgName} found with ID ${orgId}.");
		}
		return $orgId;
	}

    /**
     * @param int $orgId
     * @param array $user
     * @param User $userModel
     * @return array
     * @throws Exception
     */
	private function updateUserOrg($orgId, $user, $userModel)
	{
		if ($user['org_id'] != $orgId) {
			CakeLog::write('warning', "User organisation changed from {$user['org_id']} to $orgId.");
			$user['org_id'] = $orgId; // Different role either increase or decrease permissions
			$userUpdatedData = array('User' => $user);
			$userModel->set(array(
				'org_id' => $orgId,
				'id' => $user['id'],
			)); // Update the user
			$userModel->save($userUpdatedData, false);
		}
		return $user;
	}
}
