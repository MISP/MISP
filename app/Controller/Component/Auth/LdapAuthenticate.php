<?php
App::uses('FormAuthenticate', 'Controller/Component/Auth');

class LdapAuthenticate extends FormAuthenticate
{
    /**
     * @param ComponentCollection $collection
     * @param array $settings
     * @throws Exception
     */
    public function __construct(ComponentCollection $collection, $settings)
    {
        if (!function_exists('ldap_connect')) {
            throw new Exception("LDAP support is not enabled in PHP.");
        }

        parent::__construct($collection, $settings);
    }

    /**
     * Checks if user is still valid LDAP user according to 'ldap_dn' attribute.
     * @param array $user
     * @return bool
     * @throws Exception
     */
    public static function isUserValid(array $user)
    {
        if (!isset($user['ldap_dn']) || empty($user['ldap_dn'])) {
            throw new InvalidArgumentException("Given user doesn't have 'ldap_dn' attribute or this attribute is empty.");
        }

        $ldapDn = $user['ldap_dn'];
        if (ldap_explode_dn($ldapDn, 1) === false) {
            throw new InvalidArgumentException("Given user has invalid 'ldap_dn' attribute.");
        }

        $connection = self::ldapConnectionCreate();

        $ldapSearchFilter = self::getConfig('ldapSearchFilter', '');
        $ldapUser = self::ldapGetFirstUser($connection, $ldapDn, $ldapSearchFilter);
        if ($ldapUser === false) {
            self::disableUser($user, 'User doesn\'t exist or is disabled.');
            CakeLog::debug("Could not validate '$ldapDn': User doesn't exist or is disabled.");
            return false;
        } else {
            list ($userEmail, $ldapUserData) = $ldapUser;
        }

        $ldapUserGroup = self::getConfig('ldapUserGroup');
        if ($ldapUserGroup && !self::isUserMemberOf($ldapUserData, $ldapUserGroup)) {
            self::disableUser($user, 'Required group is not assigned to user.');
            CakeLog::notice("Could not validate '$userEmail' (DN '$ldapDn'): User exists in LDAP, but required group '$ldapUserGroup' is not assigned to that account.");
            return false;
        }

        if (!self::getConfig('updateUser', false)) {
            return true;
        }

        // Set roleid depending on group membership
        $roleId = self::findRoleId($ldapUserData);
        if (!$roleId) {
            self::disableUser($user, 'No role assigned.');
            CakeLog::notice("Could not validate '$userEmail' (DN '$ldapDn'): User exists, but no MISP role is assigned.");
            return false;
        }

        self::updateUser($user, $userEmail, $roleId);

        return true;
    }

    /**
     * @param array|string $username LDAP username
     * @param string|null $password LDAP password
     * @return array|bool
     * @throws Exception
     */
    protected function _findUser($username, $password = null)
    {
        if ($password === null) {
            throw new InvalidArgumentException("Password cannot be empty.");
        }

        $ldapUserDn = self::getConfig('ldapDN', null, true);
        $connection = $this->ldapConnectionCreate();

        $ldapSearchAttribute = self::getConfig('ldapSearchAttribute', 'uid');
        $filter = "($ldapSearchAttribute=" . ldap_escape($username, "", LDAP_ESCAPE_FILTER) . ')';
        $ldapSearchFilter = self::getConfig('ldapSearchFilter');
        if (!empty($ldapSearchFilter)) {
            $filter = "(&{$ldapSearchFilter}{$filter})";
        }

        $ldapUser = self::ldapGetFirstUser($connection, $ldapUserDn, $filter);
        if ($ldapUser === false) {
            // It is not possible to disable MISP user account, because we dont know what MISP user we should disable.
            CakeLog::debug("Could not authenticate '$username': User doesn't exist or is disabled in LDAP.");
            return false;
        } else {
            list ($userEmail, $ldapUserData) = $ldapUser;
        }

        if (!isset($ldapUserData['dn'])) {
            throw new Exception("LDAP data doesn't contains 'dn' field.");
        }

        $ldapUserDn = $ldapUserData['dn'];
        if (!@ldap_bind($connection, $ldapUserDn, $password)) {
            return false; // Probably invalid password.
        }

        $user = parent::_findUser(array('ldap_dn' => $ldapUserDn));

        if (!$user) { // User managed by LDAP in MISP doesnt exists, we will try to find user according to e-mail address.
            $user = parent::_findUser($userEmail);
        }

        $ldapUserGroup = self::getConfig('ldapUserGroup');
        if ($ldapUserGroup && !self::isUserMemberOf($ldapUserData, $ldapUserGroup)) {
            if ($user) {
                self::disableUser($user, 'Required group is not assigned to user.');
            }
            CakeLog::notice("Could not authenticate '$username': User exists in LDAP, but required group '$ldapUserGroup' is not assigned to that account.");
            return false;
        }

        if ($user && !self::getConfig('updateUser', false)) {
            // Even when updateUser is disabled, it is necessary to fill 'ldap_dn' attribute if doesnt exists or when is different.
            if ($user['ldap_dn'] !== $ldapUserDn) {
                $oldLdapDn = $user['ldap_dn'];
                $user['ldap_dn'] = $ldapUserDn;
                $userModel = ClassRegistry::init($this->settings['userModel']);
                if (!$userModel->save($user)) {
                    throw new Exception("Could not save LDAP information to user $username.");
                }
                $log = ClassRegistry::init('Log');
                $log->createLogEntry('SYSTEM', 'edit', 'User', $user['id'], 'User managed by LDAP', array('ldap_dn' => array($oldLdapDn => $ldapUserDn)));
            }
            return $user;
        }

        if (!$user && !self::getConfig('createUser', true)) {
            CakeLog::notice("Could not authenticate '$username': User exists in LDAP and not in MISP, but creating new accounts is disabled.");
            return false;
        }

        return $this->createOrUpdateUser($userEmail, $user, $ldapUserData);
    }

    /**
     * @return resource
     * @throws Exception
     */
    private static function ldapConnectionCreate()
    {
        // LDAP connection
        ldap_set_option(null, LDAP_OPT_NETWORK_TIMEOUT, self::getConfig('ldapNetworkTimeout', 5));
        $ldapServer = self::getConfig('ldapServer', null, true);
        $connection = @ldap_connect($ldapServer);
        if (!$connection) {
            throw self::ldapException($connection, 'Provided LDAP URI is invalid');
        }

        // LDAP protocol configuration
        $protocolVersion = self::getConfig('ldapProtocol', 3);
        if (!ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, $protocolVersion)) {
            throw self::ldapException($connection, "Failed to set LDAP Protocol version to $protocolVersion");
        }
        ldap_set_option($connection, LDAP_OPT_REFERRALS, self::getConfig('ldapAllowReferrals'));

        if (self::getConfig('ldapStartTls', true)) {
            if (!@ldap_start_tls($connection)) {
                throw self::ldapException($connection, "Unable to use STARTTLS");
            }
        }

        // Bind reader user
        $ldapBindUsername = self::getConfig('ldapReaderUser');
        $ldapBindPassword = self::getConfig('ldapReaderPassword');

        if (!@ldap_bind($connection, $ldapBindUsername, $ldapBindPassword)) {
            throw self::ldapException($connection, "Unable to bind to server as user '$ldapBindUsername'");
        }

        return $connection;
    }

    /**
     * @param resource $connection
     * @param string $baseDn
     * @param string $filter
     * @return array|bool
     * @throws Exception
     */
    private static function ldapGetFirstUser($connection, string $baseDn, string $filter)
    {
        $ldapAttributes = self::getConfig('ldapAttributes', array('mail', 'memberof'));
        if (!is_array($ldapAttributes)) {
            $ldapAttributes = array($ldapAttributes);
        }

        $result = @ldap_search($connection, $baseDn, $filter, $ldapAttributes);
        if (!$result) {
            throw self::ldapException($connection, "Error during LDAP search with query '$filter'");
        }

        $ldapUserData = @ldap_get_entries($connection, $result);
        if (!$ldapUserData) {
            throw self::ldapException($connection, "Could not get entries from LDAP server");
        }

        if (!isset($ldapUserData[0])) {
            return false;
        }

        $ldapUserData = $ldapUserData[0];

        // find the email address in the query's result
        $ldapEmailField = self::getConfig('ldapEmailField', array('mail'));
        if (!is_array($ldapEmailField)) {
            $ldapEmailField = array($ldapEmailField);
        }
        $userEmail = self::getEmailAddress($ldapUserData, $ldapEmailField);
        if (!$userEmail) {
            throw new Exception("Email address not found in fields " . json_encode($ldapEmailField) . ".");
        }

        return array($userEmail, $ldapUserData);
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

        // Set roleid depending on group membership
        $roleId = $this->findRoleId($ldapUserData);
        if (!$roleId) {
            if ($user) {
                self::disableUser($user, 'No role assigned.');
            }
            CakeLog::notice("Could not authorize '$userEmail' (DN '{$ldapUserData['dn']}'): User exists, but no MISP role is assigned.");
            return false;
        }

        if (!$user) {
            $orgId = self::getConfig('ldapDefaultOrg');
            if ($orgId) {
                if (!$userModel->Organisation->findById($orgId)) {
                    throw new Exception("Default organisation ID for LDAP users is se to '$orgId', but organisation with this ID doesn't exists.");
                }

            } else { // If not in config, take default org
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

            // User doesn't exists in MISP, create new account
            $user = array('User' => array(
                'email' => $userEmail,
                'org_id' => $orgId,
                'role_id' => $roleId,
                'change_pw' => 0,
                'created' => time(),
                'ldap_dn' => $ldapUserData['dn'],
            ));
            if (!$userModel->save($user)) {
                throw new Exception("Could not create user '$userEmail' in database.");
            }

        } else {
            self::updateUser($user, $userEmail, $roleId, $ldapUserData['dn']);
        }

        return parent::_findUser(array('ldap_dn' => $ldapUserData['dn']));
    }

    /**
     * @param resource $ldapConnection
     * @param string $message
     * @return Exception
     */
    private static function ldapException($ldapConnection, string $message): Exception
    {
        $message .= ": " . ldap_error($ldapConnection);
        ldap_get_option($ldapConnection, LDAP_OPT_DIAGNOSTIC_MESSAGE, $extendedError);
        if ($extendedError) {
            $message .= " (diagnostic message: $extendedError)";
        }

        return new Exception($message, ldap_errno($ldapConnection));
    }

    /**
     * @param array $ldapUserData
     * @return int|null
     * @throws Exception
     */
    private static function findRoleId(array $ldapUserData)
    {
        $roleIds = self::getConfig('ldapDefaultRoleId');
        if (is_array($roleIds)) {
            // Get role ID depending on group membership
            $roleId = null;
            foreach ($roleIds as $group => $id) {
                if (self::isUserMemberOf($ldapUserData, $group)) {
                    $roleId = $id;
                    break;
                }
            }
            if ($roleId === null) {
                return null;
            }
        } else {
            $roleId = $roleIds;
        }

        $roleModel = ClassRegistry::init('Role');
        if (!$roleModel->findById($roleId)) {
            throw new Exception("Role for user is set to '$roleId', but role with this ID doesn't exists.");
        }

        return $roleId;
    }

    /**
     * @param array $ldapUserData
     * @param string $group Name (CN) of the group or the whole group DN
     * @return bool
     * @throws Exception
     */
    private static function isUserMemberOf(array $ldapUserData, string $group): bool
    {
        if (!isset($ldapUserData['memberof'])) {
            throw new Exception("Data from LDAP doesn't contain 'memberof' field. Maybe you need to tune 'ldapAttributes' config.");
        }

        unset($ldapUserData['memberof']['count']);
        foreach ($ldapUserData['memberof'] as $memberof) {
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
    private static function getEmailAddress(array $ldapUserData, array $ldapEmailField)
    {
        foreach ($ldapEmailField as $field) {
            if (isset($ldapUserData[$field][0])) {
                return $ldapUserData[$field][0];
            }
        }
        return null;
    }

    /**
     * @param string $name
     * @param mixed|null $default
     * @param bool $required
     * @return mixed
     * @throws Exception
     */
    private static function getConfig(string $name, $default = null, bool $required = false)
    {
        $value = Configure::read("LdapAuth." . $name);
        if ($value === null) {
            if ($required) {
                throw new Exception("Configuration value 'LdapAuth.$name' is required, but it is not provided.");
            } else {
                $value = $default;
            }
        }
        return $value;
    }

    /**
     * @param array $user
     * @param string $userEmail
     * @param int $roleId
     * @param null $ldapUserDn
     * @throws Exception
     */
    private static function updateUser(array $user, string $userEmail, int $roleId, $ldapUserDn = null)
    {
        $editedUser = array(
            'email' => $userEmail,
            'role_id' => $roleId,
            'disabled' => 0, // Reenable user in case it has been disabled
        );

        if ($ldapUserDn) {
            $editedUser['ldap_dn'] = $ldapUserDn;
        }

        $fieldsToEdit = array();
        foreach ($editedUser as $key => $newValue) {
            $oldValue = $user[$key] ?? null;
            if ($newValue != $oldValue) {
                $fieldsToEdit[$key] = array($oldValue, $newValue);
            }
        }

        if (!empty($fieldsToEdit)) {
            $userModel = ClassRegistry::init('User');
            $userModel->id = $user['id'];
            if (!$userModel->save($editedUser, false)) {
                throw new Exception("Could not update user '$userEmail' in database.");
            }

            $log = ClassRegistry::init('Log');
            $log->createLogEntry('SYSTEM', 'edit', 'User', $user['id'], 'User edited from LDAP', $fieldsToEdit);
        }
    }

    /**
     * @param array $user
     * @param string $reason
     * @throws Exception
     */
    private static function disableUser(array $user, string $reason)
    {
        $userModel = ClassRegistry::init('User');
        $userModel->id = $user['id'];
        if (!$userModel->save(array('disabled' => 1), false)) {
            throw new Exception("Could not disable user with ID {$user['id']}.");
        }

        $log = ClassRegistry::init('Log');
        $log->createLogEntry('SYSTEM', 'edit', 'User', $user['id'], 'User disabled from LDAP: ' . $reason);
    }
}
