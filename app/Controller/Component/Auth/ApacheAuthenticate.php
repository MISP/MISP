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

class ApacheAuthenticate extends BaseAuthenticate
{
    /**
     * @param CakeRequest $request The request that contains login information.
     * @param CakeResponse $response Unused response object.
     * @return array|bool False on login failure. An array of User data on success.
     * @throws Exception
     */
    public function authenticate(CakeRequest $request, CakeResponse $response)
    {
        if (!function_exists('ldap_connect')) {
            throw new Exception("LDAP support is not enabled in PHP.");
        }

        $envvar = $this->settings['fields']['envvar'];
        $mispUsername = $_SERVER[$envvar];

        list($userEmail, $ldapUserData) = $this->getUserFromLdap($mispUsername);

        $ldapUserGroup = Configure::read('ApacheSecureAuth.ldapUserGroup');
        if ($ldapUserGroup && !$this->isUserMemberOf($ldapUserData, $ldapUserGroup)) {
            CakeLog::notice("User '$mispUsername' exists, but required group '$ldapUserGroup' is not assigned to that account.");
            return false;
        }

        // Find user with MISP username (mail address)
        $user = $this->_findUser($userEmail);

        if ($user && !Configure::read('ApacheSecureAuth.updateUser')) {
            return $user;
        }

        return $this->createOrUpdateUser($userEmail, $user, $ldapUserData);
    }

    /**
     * @param string $ldapUsername
     * @return array
     * @throws Exception
     */
    private function getUserFromLdap(string $ldapUsername): array
    {
        // make LDAP request to get user email required for MISP auth
        $ldapServer = Configure::read('ApacheSecureAuth.ldapServer');
        if (!$ldapServer) {
            throw new Exception("Configuration value 'ApacheSecureAuth.ldapServer' is required, but it is not provided.");
        }

        $ldapDn = Configure::read('ApacheSecureAuth.ldapDN');
        if (!$ldapDn) {
            throw new Exception("Configuration value 'ApacheSecureAuth.ldapDN' is required, but it is not provided.");
        }

        $ldapBindUsername = Configure::read('ApacheSecureAuth.ldapReaderUser'); // DN ou RDN LDAP
        $ldapBindPassword = Configure::read('ApacheSecureAuth.ldapReaderPassword');
        $ldapSearchFilter = Configure::read('ApacheSecureAuth.ldapSearchFilter');

        $ldapSearchAttribute = Configure::read('ApacheSecureAuth.ldapSearchAttribute');
        $ldapSearchAttribute = $ldapSearchAttribute ?: Configure::read('ApacheSecureAuth.ldapSearchAttribut'); // for BC compatibility
        $ldapSearchAttribute = $ldapSearchAttribute ?: 'uid';

        $ldapEmailField = Configure::read('ApacheSecureAuth.ldapEmailField') ?: array('mail');
        if (!is_array($ldapEmailField)) {
            $ldapEmailField = array($ldapEmailField);
        }

        $ldapFilter = Configure::read('ApacheSecureAuth.ldapFilter') ?: array('mail', 'memberof');
        if (!is_array($ldapFilter)) {
            $ldapFilter = array($ldapFilter);
        }

        // LDAP connection
        ldap_set_option(null, LDAP_OPT_NETWORK_TIMEOUT, Configure::read('ApacheSecureAuth.ldapNetworkTimeout') ?: 5);
        $connection = @ldap_connect($ldapServer);
        if (!$connection) {
            throw $this->ldapException($connection, 'Provided LDAP URI is invalid');
        }

        // LDAP protocol configuration
        $protocolVersion = Configure::read('ApacheSecureAuth.ldapProtocol') ?: 3;
        if (!ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, $protocolVersion)) {
            throw $this->ldapException($connection, "Failed to set LDAP Protocol version to $protocolVersion");
        }
        ldap_set_option($connection, LDAP_OPT_REFERRALS, Configure::read('ApacheSecureAuth.ldapAllowReferrals'));

        if (Configure::read('ApacheSecureAuth.ldapStartTls')) {
            if (!ldap_start_tls($connection)) {
                throw $this->ldapException($connection, "Unable to use STARTTLS.");
            }
        }

        $ldapbind = @ldap_bind($connection, $ldapBindUsername, $ldapBindPassword);
        if (!$ldapbind) {
            throw $this->ldapException($connection, "Unable to bind to server as user '$ldapBindUsername'");
        }

        // example for searchFiler: '(objectclass=InetOrgPerson)(!(nsaccountlock=True))(memberOf=cn=misp,cn=groups,cn=accounts,dc=example,dc=com)'
        // example for searchAttribute: '(uuid=ApacheUser)'
        $filter = '(' . $ldapSearchAttribute . '=' . ldap_escape($ldapUsername, "", LDAP_ESCAPE_FILTER) . ')';
        if (!empty($ldapSearchFilter)) {
            $filter = '(&' . $ldapSearchFilter . $filter . ')';
        }

        $result = @ldap_search($connection, $ldapDn, $filter, $ldapFilter);
        if (!$result) {
            throw $this->ldapException($connection, "Error during LDAP search with query '$filter'");
        }

        $ldapUserData = @ldap_get_entries($connection, $result);
        if (!$ldapUserData) {
            throw $this->ldapException($connection, "Could not get entries from LDAP server");
        }

        if (!isset($ldapUserData[0])) {
            throw new Exception("User '$ldapUsername' not found in LDAP.");
        }

        // find the email address in the query's result
        $userEmail = $this->getEmailAddress($ldapUserData, $ldapEmailField);
        if (!$userEmail) {
            throw new Exception("Email address for user '$ldapUsername' not found in fields " . json_encode($ldapEmailField) . ".");
        }

        return array($userEmail, $ldapUserData);
    }

    /**
     * @param resource $ldapConnection
     * @param string $message
     * @return Exception
     */
    private function ldapException($ldapConnection, string $message): Exception {
        $message .= ": " . ldap_error($ldapConnection);
        ldap_get_option($ldapConnection, LDAP_OPT_DIAGNOSTIC_MESSAGE, $extendedError);
        if ($extendedError) {
            $message .= " (diagnostic message: $extendedError)";
        }

        return new Exception($message, ldap_errno($ldapConnection));
    }

    /**
     * @param string $userEmail
     * @param array|bool $user
     * @param array $ldapUserData
     * @return array|bool
     * @throws Exception
     */
    private function createOrUpdateUser(string $userEmail, $user, array $ldapUserData)
    {
        $userModel = ClassRegistry::init($this->settings['userModel']);
        $orgId = Configure::read('ApacheSecureAuth.ldapDefaultOrg');
        if ($orgId) {
            if (!$userModel->Organisation->findById($orgId)) {
                throw new Exception("Default organisation ID for LDAP users is se to '$orgId', but organisation with this ID doesn't exists.");
            }

        } else  { // If not in config, take default org
            $firstOrg = $userModel->Organisation->find(
                'first',
                array(
                    'conditions' => array(
                        'Organisation.local' => true,
                    ),
                    'order' => 'Organisation.id ASC',
                )
            );
            $orgId = $firstOrg['Organisation']['id'];
        }

        // Set roleid depending on group membership
        $roleId = $this->findRoleId($ldapUserData);
        if (!$roleId) {
            if ($user) {
                // User has no role anymore, disable user
                $user['disabled'] = 1;
                $userModel->save($user, false);
            }
            CakeLog::notice("User '$userEmail' exists, but no MISP role is assigned.");
            return false;
        }

        if (!$userModel->Role->findById($roleId)) {
            throw new Exception("Role for user '$userEmail' is set to '$roleId', but role with this ID doesn't exists.");
        }

        if (!$user) {
            // User doesnt exists in MISP, create new account
            $user = array('User' => array(
                'email' => $userEmail,
                'org_id' => $orgId,
                'password' => '',
                'confirm_password' => '',
                'authkey' => $userModel->generateAuthKey(),
                'nids_sid' => 4000000,
                'newsread' => 0,
                'role_id' => $roleId,
                'change_pw' => 0,
                'created' => time(),
                'date_modified' => time(),
            ));

        } else {
            // Update existing user
            $user['email'] = $userEmail;
            $user['org_id'] = $orgId;
            $user['role_id'] = $roleId;
            // Reenable user in case it has been disabled
            $user['disabled'] = 0;
        }

        $userModel->save($user, false);

        return $this->_findUser($userEmail);
    }

    /**
     * @param array $ldapUserData
     * @return int|null
     * @throws Exception
     */
    private function findRoleId(array $ldapUserData) {
        $roleIds = Configure::read('ApacheSecureAuth.ldapDefaultRoleId');
        if (is_array($roleIds)) {
            // Get role ID depending on group membership
            foreach ($roleIds as $key => $id) {
                if ($this->isUserMemberOf($ldapUserData, $key)) {
                    return $id;
                }
            }
            return null;
        } else {
            return $roleIds;
        }
    }

    /**
     * @param array $ldapUserData
     * @param string $group Name (CN) of the group or the whole group DN
     * @return bool
     * @throws Exception
     */
    private function isUserMemberOf(array $ldapUserData, string $group): bool
    {
        if (!isset($ldapUserData[0]['memberof'])) {
            throw new Exception("Data from LDAP doesn't contain 'memberof' field. Maybe you need to tune 'ApacheSecureAuth.ldapFilter' config.");
        }

        unset($ldapUserData[0]['memberof']['count']);
        foreach ($ldapUserData[0]['memberof'] as $memberof) {
            if ($memberof === $group) {
                return true;
            }

            $parts = ldap_explode_dn($memberof, 1);
            if ($parts[0] === $group) {
                return true;
            }
        }
        return false;
    }

    /**
     * Return the email address of an LDAP user if one of the fields in $ldapEmaiLField exists
     * @param array $ldapUserData
     * @param array $ldapEmailField
     * @return string|null
     */
    private function getEmailAddress(array $ldapUserData, array $ldapEmailField)
    {
        foreach($ldapEmailField as $field) {
            if (isset($ldapUserData[0][$field][0])) {
                return $ldapUserData[0][$field][0];
            }
        }
        return null;
    }
}
