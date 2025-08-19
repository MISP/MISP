<?php
App::uses('BaseAuthenticate', 'Controller/Component/Auth');

if (session_status() === PHP_SESSION_NONE) {
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
     * 'ApacheShibbAuth' =>
     *     array(
     *      'MailTag'               => 'EMAIL_TAG',
     *      'OrgTag'                => 'ORG_TAG',
     *      'DefaultOrg'            => 'MY_ORG',
     *      'GroupTag'              => 'GROUP_TAG',
     *      'GroupSeparator'        => ';',
     *      'GroupRoleMatching'     => array(
     *          'value_3' => 3,
     *          'value_2' => 2,
     *          'value_1' => 1,
     *       ),
     *      'DefaultRole'            => 3,
     *      'BlockRoleModifications' => false,
     *      'BlockOrgModifications'  => false,
     * ),
     * @param CakeRequest $request The request that contains login information.
     * @param CakeResponse $response Unused response object.
     * @return mixed False on login failure. An array of User data on success.
     * @throws Exception
     */
    public function authenticate(CakeRequest $request, CakeResponse $response)
    {
        return self::getUser($request);
    }

    /**
     * @param CakeRequest $request
     * @return array|bool
     * @throws Exception
     */
    public function getUser(CakeRequest $request)
    {
        // If the url contains sso=disable we return false so the main misp authentication form is used to log in
        if (array_key_exists('sso', $request->query) && $request->query['sso'] == 'disable' || (isset($_SESSION["sso_disable"]) && $_SESSION["sso_disable"] === true)) {
            $_SESSION["sso_disable"] = true;
            return false;
        }

        // Get Default parameters
        $roleId = -1;
        $blockOrgModifications = Configure::check('ApacheShibbAuth.BlockOrgModifications') ? Configure::read('ApacheShibbAuth.BlockOrgModifications') : false;
        $defaultOrg = Configure::read('ApacheShibbAuth.DefaultOrg');
        $defaulRole = Configure::read('ApacheShibbAuth.DefaultRole');
        // Get tags from SSO config
        $mailTag = Configure::read('ApacheShibbAuth.MailTag');
        $orgTag = Configure::read('ApacheShibbAuth.OrgTag');
        $groupTag = Configure::read('ApacheShibbAuth.GroupTag');
        $groupRoleMatching = Configure::read('ApacheShibbAuth.GroupRoleMatching');
        $blockRoleModifications = Configure::check('ApacheShibbAuth.BlockRoleModifications') ? Configure::read('ApacheShibbAuth.BlockRoleModifications') : false;
        $blockOrgModifications = Configure::check('ApacheShibbAuth.BlockOrgModifications') ? Configure::read('ApacheShibbAuth.BlockOrgModifications') : false;

        // Get user values
        if (!isset($_SERVER[$mailTag])) {
            CakeLog::error('Mail tag is not given by the SSO SP. Not processing login.');
            return false;
        }
        $mispUsername = $_SERVER[$mailTag];

        if (filter_var($mispUsername, FILTER_VALIDATE_EMAIL) === false) {
            CakeLog::error( "Mail tag `$mispUsername` given by the SSO SP, but it is not valid email address.");
            return false;
        }

        CakeLog::info("Trying login of user: `$mispUsername`.");

        // Change username column for email (username in shibboleth attributes corresponds to the email in MISPs DB)
        $this->settings['fields'] = array('username' => 'email');

        // Find user with real username (mail)
        $user = $this->_findUser($mispUsername);

        // get user organization dynamically
        if ($orgTag && isset($_SERVER[$orgTag])) {
            $org = $_SERVER[$orgTag];
        // Use default organization as fallback, if provided
        } else {
            if ($defaultOrg) {
                $org = $defaultOrg;
            } else {
                CakeLog::error('No organization given the SSO SP, and no default organization. Not processing login.');
                return false;
            }
        }

        // Check if the organization exits and create it if not
        $org = $this->checkOrganization($org, $user);
        if (!$org) {
            return false;
        }

        // Get user role dynamically
        if ($groupTag && $groupRoleMatching && isset($_SERVER[$groupTag])) {
            list($roleChanged, $roleId) = $this->getUserRoleFromGroup($groupTag, $groupRoleMatching, $roleId);
        }

        // Use default role as fallback, if provided
        if ($roleId < 0) {
            if ($defaultRole) {
                $roleId = $defaultRole;
            } else {
                CakeLog::error('No group given the SSO SP, or no matching role, and no default role. Not processing login.');
                return false;
            }
        }

        if ($roleChanged) {
            CakeLog::write('info', "User role $roleId assigned.");
        }
        /** @var User $userModel */
        $userModel = ClassRegistry::init($this->settings['userModel']);

        if ($user) { // User already exists
            CakeLog::info( "User `$mispUsername` found in database.");
            if (!$blockRoleModifications) {
                $user = $this->updateUserRole($roleChanged, $user, $roleId, $userModel);
            }
            if (!$blockOrgModifications) {
                $user = $this->updateUserOrg($org, $user, $userModel);
            }
            $userModel->extralog($user, 'login');
            return $user;
        }

        CakeLog::info("User `$mispUsername` not found in database.");
        // Insert user in database if not existent
        $userData = array('User' => array(
            'email' => $mispUsername,
            'org_id' => $org,
            'newsread' => time(),
            'role_id' => $roleId,
            'change_pw' => 0,
            'date_created' => time(),
        ));

        // save user
        $userModel->save($userData);
        CakeLog::info("User `$mispUsername` saved in database.");
        $user = $this->_findUser($mispUsername);
        $userModel->extralog($user, 'login');
        return $user;
    }

    /**
     * @param string $org
     * @param array $user
     * @return int
     * @throws Exception
     */
    private function checkOrganization($org, $user)
    {
        $orgIsUuid = Validation::uuid($org);

        /** @var Organisation $orgModel */
        $orgModel = ClassRegistry::init('Organisation');
        $orgAux = $orgModel->find('first', [
            'fields' => array('Organisation.id'),
            'conditions' => $orgIsUuid ? ['uuid' => strtolower($org)] : ['name' => $org],
        ]);
        if (empty($orgAux)) {
            if ($orgIsUuid) {
                CakeLog::error("Could not found organisation with UUID `$org`.");
                return false;
            }

            $orgUserId = 1; // By default created by the admin
            if ($user) {
                $orgUserId = $user['id'];
            }
            $orgId = $orgModel->createOrgFromName($org, $orgUserId, true);
            CakeLog::info("User organisation `$org` created with ID $orgId.");
        } else {
            $orgId = $orgAux['Organisation']['id'];
            CakeLog::info("User organisation `$org` found with ID $orgId.");
        }
        return $orgId;
    }

    /**
     * @param string $groupTag
     * @param array $groupRoleMatching
     * @param int $roleId
     * @return array
     */
    public function getUserRoleFromGroup($groupTag, $groupRoleMatching, $roleId)
    {
        // Check the role mapping to get the user's role level and update it if needed
        $roleChanged = false;
        if (isset($_SERVER[$groupTag])) {
            $groupSeparator = Configure::read('ApacheShibbAuth.GroupSeparator');
            $groupList = explode($groupSeparator, $_SERVER[$groupTag]);
            // Check user roles and egroup match and update if needed
            foreach ($groupList as $group) {
                // TODO: Can be optimized inverting the search group and using only array_key_exists
                if (array_key_exists($group, $groupRoleMatching)) { //In case there is an group not defined in the config.php file
                    CakeLog::write('info', "User group $group found.");
                    $roleVal = $groupRoleMatching[$group];
                    if ($roleVal <= $roleId || $roleId == -1) {
                        $roleId = $roleVal;
                        $roleChanged = true;
                    }
                }
            }
            return array($roleChanged, $roleId);
        }
        return array($roleChanged, $roleId);
    }

    /**
     * @param bool $roleChanged
     * @param array $user
     * @param int $roleId
     * @param User $userModel
     * @return array
     * @throws Exception
     */
    private function updateUserRole($roleChanged, array $user, $roleId, User $userModel)
    {
        if ($roleChanged && $user['role_id'] != $roleId) {
            $message = "User role changed from ${user['role_id']} to $roleId for user ${user['email']} (${user['id']}).";
            CakeLog::write('warning', $message);
            $userModel->updateField($user, 'role_id', $roleId);
        }
        return $user;
    }

    /**
     * @param int $orgId
     * @param array $user
     * @param User $userModel
     * @return array
     * @throws Exception
     */
    private function updateUserOrg($orgId, array $user, User $userModel)
    {
        if ($user['org_id'] != $orgId) {
            $message = "User organisation changed from ${user['org_id']} to $orgId for user ${user['email']} (${user['id']}).";
            CakeLog::write('warning', $message);
            $user['org_id'] = $orgId; // Different role either increase or decrease permissions
            $userModel->updateField($user, 'org_id', $orgId);
        }
        return $user;
    }
}
