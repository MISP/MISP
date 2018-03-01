<?php

App::uses('BaseAuthenticate', 'Controller/Component/Auth');

/*
 * custom class for Apache-based authentication
 *
 * User for ApacheAuthenticate you can pass in settings to which fields, model and additional conditions
 * are used. See FormAuthenticate::$settings for more information.
 * TODO: clarification needed, text almost the same as in lib/Cake/Controller/Component/Auth/FormAuthenticate.php
 *
 * @package       Controller.Component.Auth
 * @since 2.0
 * @see ApacheAuthComponent::$authenticate
 */

class ApacheAuthenticate extends BaseAuthenticate {

	/**
	 * Authentication class
	 *
	 * @param CakeRequest $request The request that contains login information.
	 * @param CakeResponse $response Unused response object.
	 * @return mixed False on login failure. An array of User data on success.
	 */
	private function isUserMemberOf($group, $ldapUserData) {
	// return true of false depeding on if user is a member of group.
		$returnCode = false;
		unset($ldapUserData[0]['memberof']["count"]);
		foreach ($ldapUserData[0]['memberof'] as $result) {
			$r = explode(",", $result, 2);
			$ldapgroup = explode("=", $r[0]);
			if ($ldapgroup[1] == $group) {
				$returnCode = true;
			}
		}
		return $returnCode;
	}

	public function authenticate(CakeRequest $request, CakeResponse $response) {

		// Get information user for MISP auth
		$envvar = $this->settings['fields']['envvar'];
		$mispUsername = $_SERVER[$envvar];

		// make LDAP request to get user email required for MISP auth
		$ldapdn = Configure::read('ApacheSecureAuth.ldapDN');
		$ldaprdn = Configure::read('ApacheSecureAuth.ldapReaderUser');     // DN ou RDN LDAP
		$ldappass = Configure::read('ApacheSecureAuth.ldapReaderPassword');
		$ldapSearchFilter = Configure::read('ApacheSecureAuth.ldapSearchFilter');
		// LDAP connection
		$ldapconn = ldap_connect(Configure::read('ApacheSecureAuth.ldapServer'))
				or die('LDAP server connection failed');

		// LDAP protocol configuration
		ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, Configure::read('ApacheSecureAuth.ldapProtocol'));
		ldap_set_option($ldapconn, LDAP_OPT_REFERRALS, Configure::read('ApacheSecureAuth.ldapAllowReferrals', true));

		if ($ldapconn) {
			// LDAP bind
			$ldapbind = ldap_bind($ldapconn, $ldaprdn, $ldappass);
			// authentication verification
			if (!$ldapbind) {
				die("LDAP bind failed");
			}
			// example for searchFiler: '(objectclass=InetOrgPerson)(!(nsaccountlock=True))(memberOf=cn=misp,cn=groups,cn=accounts,dc=example,dc=com)'
			// example for searchAttribut: '(uuid=ApacheUser)'
			if (!empty($ldapSearchFilter)) {
				$filter = '(&' . $ldapSearchFilter . '(' . Configure::read('ApacheSecureAuth.ldapSearchAttribut') . '=' . $_SERVER[$envvar] . '))';
			} else {
				$filter = '(' . Configure::read('ApacheSecureAuth.ldapSearchAttribut') . '=' . $_SERVER[$envvar] . ')';
			}
			// example: mail
			$getLdapUserInfo = Configure::read('ApacheSecureAuth.ldapFilter');

			$result = ldap_search($ldapconn, $ldapdn, $filter, $getLdapUserInfo)
					or die("Error in LDAP search query: " . ldap_error($ldapconn));

			$ldapUserData = ldap_get_entries($ldapconn, $result);

			// the request returns only 1 field
			if (isset($ldapUserData[0]['mail'][0])) {
				// assign the real user for MISP
				$mispUsername = $ldapUserData[0]['mail'][0];
			} else {
				die("User not found in LDAP");
			}
			// close LDAP connection
			ldap_close($ldapconn);
		}

		// Find user with real username (mail)
		$user = $this->_findUser($mispUsername);

		if ($user) {
	           if (!Configure::read('ApacheSecureAuth.updateUser')) {
		        return $user;
                   }
		}

		// insert user in database if not existent
		$userModel = ClassRegistry::init($this->settings['userModel']);
		$org_id = Configure::read('ApacheSecureAuth.ldapDefaultOrg');
		// If not in config, take default org
		if (!isset($org_id)) {
			$firstOrg = $userModel->Organisation->find(
				'first', array(
					'conditions' => array(
						'Organisation.local' => true),
					'order' => 'Organisation.id ASC'
				)
			);
			$org_id = $firstOrg['Organisation']['id'];
		}

		 // Set roleid depending on group membership
		$roleIds = Configure::read('ApacheSecureAuth.ldapDefaultRoleId');
		if (is_array($roleIds)) {
			foreach ($roleIds as $key => $id) {
				if ($this->isUserMemberOf($key, $ldapUserData)) {
					$roleId = $roleIds[$key];
				}
			}
		} else {
			$roleId = $roleIds;
		}

		if (!$user) {
			// create user
			$userData = array('User' => array(
				'email' => $mispUsername,
				'org_id' => $org_id,
				'password' => '',
				'confirm_password' => '',
				'authkey' => $userModel->generateAuthKey(),
				'nids_sid' => 4000000,
				'newsread' => 0,
				'role_id' => $roleId,
				'change_pw' => 0
			));
			// save user
			$userModel->save($userData, false);
		} else {
			if (!isset($roleId)) {
			   // User has no role anymore, disable user
			   $user['disabled'] = 1;
			   return false;
			} else {
			   // Update existing user
			   $user['email'] = $mispUsername;
			   $user['org_id'] = $org_id;
			   $user['role_id'] = $roleId;
			   # Reenable user in case it has been disabled
			   $user['disabled'] = 0;
			}

			$userModel->save($user, false);
		}

		return $this->_findUser(
			$mispUsername
		);
	}

}
