<?php
class Oidc
{
    private $oidcClient;
    
    /** @var User */
    private $User;
    
    public function __construct(User $user)
    {
        $this->User = $user;
    }

    /**
     * @return array|false
     * @throws Exception
     */
    public function authenticate(array $settings)
    {
        $oidc = $this->prepareClient();

        $this->log(null, 'Authenticate');

        if (!$oidc->authenticate()) {
            throw new Exception("OIDC authentication was not successful.");
        }

        $claims = $oidc->getVerifiedClaims();

        $mispUsername = $claims->email ?? $oidc->requestUserInfo('email');
        if (empty($mispUsername)) {
            $sub = $claims->sub ?? 'UNKNOWN';
            throw new Exception("OIDC user $sub doesn't have email address, that is required by MISP.");
        }

        $this->log($mispUsername, "Trying login.");

        $sub = $claims->sub; // sub is required

        // Try to find user by `sub` field, that is unique
        $user = $this->_findUser($settings, ['User.sub' => $sub]);

        if (!$user) { // User by sub not found, try to find by email
            $user = $this->_findUser($settings, ['User.email' => $mispUsername]);
            if ($user && $user['sub'] !== null && $user['sub'] !== $sub) {
                $this->log($mispUsername, "User sub doesn't match ({$user['sub']} != $sub), could not login.", LOG_ERR);
                return false;
            }
        }

        $organisationProperty = $this->getConfig('organisation_property', 'organization');
        $organisationName = $claims->{$organisationProperty} ?? null;

        $organisationUuidProperty = $this->getConfig('organisation_uuid_property', 'organization_uuid');
        $organisationUuid = $claims->{$organisationUuidProperty} ?? null;

        $organisationId = $this->checkOrganization($organisationName, $organisationUuid, $mispUsername);
        if (!$organisationId) {
            $defaultOrganisationId = $this->defaultOrganisationId();
            if ($defaultOrganisationId) {
                $organisationId = $defaultOrganisationId;
            } else {
                if ($user) {
                    $this->block($user);
                }
                return false;
            }
        }

        $roleProperty = $this->getConfig('roles_property', 'roles');
        $roles = $claims->{$roleProperty} ?? $oidc->requestUserInfo($roleProperty);
        if ($roles === null) {
            $this->log($mispUsername, "Role property `$roleProperty` is missing in claims, access prohibited.", LOG_WARNING);
            return false;
        }

        $roleId = $this->getUserRole($roles, $mispUsername);
        if ($roleId === null) {
            $this->log($mispUsername, 'No role was assigned, access prohibited.', LOG_WARNING);
            if ($user) {
                $this->block($user);
            }
            return false;
        }

        $offlineAccessEnabled = $this->getConfig('offline_access', false);

        if ($user) {
            $this->log($mispUsername, "Found in database with ID {$user['id']}.");

            if ($user['sub'] === null) {
                $this->User->updateField($user, 'sub', $sub);
                $this->log($mispUsername, "User sub changed from NULL to $sub.");
                $user['sub'] = $sub;
            }

            if ($user['email'] !== $mispUsername) {
                $this->User->updateField($user, 'email', $mispUsername);
                $this->log($mispUsername, "User e-mail changed from {$user['email']} to $mispUsername.");
                $user['email'] = $mispUsername;
            }

            if ($user['org_id'] != $organisationId) {
                $this->User->updateField($user, 'org_id', $organisationId);
                $this->log($mispUsername, "User organisation changed from {$user['org_id']} to $organisationId.");
                $user['org_id'] = $organisationId;
            }

            if ($user['role_id'] != $roleId && $this->getConfig('update_user_role', true)) {
                $this->User->updateField($user, 'role_id', $roleId);
                $this->log($mispUsername, "User role changed from {$user['role_id']} to $roleId.");
                $user['role_id'] = $roleId;
            }

            if ($user['disabled'] && $this->getConfig('unblock', false)) {
                $this->User->updateField($user, 'disabled', false);
                $this->log($mispUsername, "Unblocking user.");
                $user['disabled'] = false;
            }

            $refreshToken = $offlineAccessEnabled ? $oidc->getRefreshToken() : null;
            if ($offlineAccessEnabled && $refreshToken === null) {
                $this->log($mispUsername, 'Refresh token requested, but not provided.', LOG_WARNING);
            }
            $this->storeMetadata($user['id'], $claims, $refreshToken);

            $this->log($mispUsername, 'Logged in.');
            return $user;
        }

        $this->log($mispUsername, 'User not found in database, creating new one.');

        $time = time();
        $userData = [
            'email' => $mispUsername,
            'org_id' => $organisationId,
            'newsread' => $time,
            'autoalert' => $this->User->defaultPublishAlert(),
            'role_id' => $roleId,
            'change_pw' => 0,
            'date_created' => $time,
            'sub' => $sub,
            'enable_password' => false, // do not generate default password for user
        ];

        if (!$this->User->save($userData)) {
            throw new RuntimeException("Could not create user `$mispUsername` in database.");
        }

        $refreshToken = $offlineAccessEnabled ? $oidc->getRefreshToken() : null;
        if ($offlineAccessEnabled && $refreshToken === null) {
            $this->log($mispUsername, 'Refresh token requested, but not provided.', LOG_WARNING);
        }
        $this->storeMetadata($this->User->id, $claims, $refreshToken);

        $this->log($mispUsername, "User created in database with ID {$this->User->id}");
        $this->log($mispUsername, 'Logged in.');
        $user = $this->_findUser($settings, ['User.id' => $this->User->id]);

        if ($user['sub'] !== $sub) { // just to be sure that we have the correct user
            throw new Exception("User {$user['email']} sub doesn't match ({$user['sub']} != $sub)");
        }
        return $user;
    }

    /**
     * @param array $user
     * @param bool $ignoreValidityTime Ignore `check_user_validity` setting and always check if user is valid
     * @param bool $update Update user role or organisation from OIDC
     * @return bool True if user is still valid, false if not
     * @throws Exception
     */
    public function isUserValid(array $user, $ignoreValidityTime = false, $update = false)
    {
        if (!$this->getConfig('offline_access', false)) {
            return true; // offline access is not enabled, so it is not possible to verify user
        }

        if (!$ignoreValidityTime) {
            $checkUserValidityEvery = $this->getConfig('check_user_validity', 0);
            if ($checkUserValidityEvery === 0) {
                return true; // validity checking is disabled
            }
        }

        if (empty($user['id'])) {
            throw new InvalidArgumentException("Invalid user model provided.");
        }

        if (empty($user['sub'])) {
            return true; // user is not OIDC managed user
        }

        $userInfo = $this->findUserInfo($user);
        if (!isset($userInfo['refresh_token'])) {
            $this->log($user['email'], "User don't have refresh token, considering user is not valid");
            return false;
        }

        if (!$ignoreValidityTime && $userInfo['validity_check_timestamp'] > time() - $checkUserValidityEvery) {
            return true; // user was checked in last `check_user_validity`, do not check again
        }

        $oidc = $this->prepareClient();

        try {
            $oidc->refreshToken($userInfo['refresh_token']);
        } catch (JakubOnderka\ErrorResponse $e) {
            if ($e->getError() === 'invalid_grant') {
                $this->log($user['email'], "Refreshing token is not possible because of `{$e->getMessage()}`, considering user is not valid");
                return false;
            } else {
                $this->log($user['email'], "Refreshing token is not possible because of `{$e->getMessage()}`, considering user is still valid");
                return true;
            }
        } catch (Exception $e) {
            $this->log($user['email'], "Refreshing token is not possible because of `{$e->getMessage()}`, considering user is still valid");
            return true;
        }

        $claims = $oidc->getVerifiedClaims();
        if ($user['sub'] !== $claims->sub) {
            throw new Exception("User {$user['email']} sub doesn't match ({$user['sub']} != $claims->sub)");
        }

        // Check user role
        $roleProperty = $this->getConfig('roles_property', 'roles');
        $roles = $claims->{$roleProperty} ?? $oidc->requestUserInfo($roleProperty);
        if ($roles === null) {
            $this->log($user['email'], "Role property `$roleProperty` is missing in claims.", LOG_ERR);
            return false;
        }

        $roleId = $this->getUserRole($roles, $user['email']);
        if ($roleId === null) {
            $this->log($user['email'], 'No role was assigned.', LOG_WARNING);
            return false;
        }

        if ($update && $user['role_id'] != $roleId && $this->getConfig('update_user_role', true)) {
            $this->User->updateField($user, 'role_id', $roleId);
            $this->log($user['email'], "User role changed from {$user['role_id']} to $roleId.");
        }

        // Check user org
        $organisationProperty = $this->getConfig('organisation_property', 'organization');
        $organisationName = $claims->{$organisationProperty} ?? null;

        $organisationUuidProperty = $this->getConfig('organisation_uuid_property', 'organization_uuid');
        $organisationUuid = $claims->{$organisationUuidProperty} ?? null;

        $organisationId = $this->checkOrganization($organisationName, $organisationUuid, $user['email']);
        if (!$organisationId) {
            $defaultOrganisationId = $this->defaultOrganisationId();
            if ($defaultOrganisationId) {
                $organisationId = $defaultOrganisationId;
            } else {
                $this->log($user['email'], 'No organisation was assigned.', LOG_WARNING);
                return false;
            }
        }

        if ($update && $user['org_id'] != $organisationId) {
            $this->User->updateField($user, 'org_id', $organisationId);
            $this->log($user['email'], "User organisation changed from {$user['org_id']} to $organisationId.");
        }

        // Update refresh token if new token provided
        if ($oidc->getRefreshToken()) {
            $this->storeMetadata($user['id'], $claims, $oidc->getRefreshToken());
        }

        return true;
    }

    /**
     * @param array $user
     * @param bool $ignoreValidityTime
     * @param bool $update Update user role or organisation
     * @return bool True if user was blocked, false if not
     * @throws Exception
     */
    public function blockInvalidUser(array $user, $ignoreValidityTime = false, $update = false)
    {
        $isValid = $this->isUserValid($user, $ignoreValidityTime, $update);
        if (!$isValid) {
            $this->block($user);
        }
        return $isValid;
    }
    
    /**
     * @return \JakubOnderka\OpenIDConnectClient
     * @throws Exception
     */
    private function prepareClient()
    {
        if ($this->oidcClient) {
            return $this->oidcClient;
        }

        $providerUrl = $this->getConfig('provider_url');
        $clientId = $this->getConfig('client_id');
        $clientSecret = $this->getConfig('client_secret');
        $issuer = $this->getConfig('issuer', null, false);

        if (class_exists("\JakubOnderka\OpenIDConnectClient")) {
            $oidc = new \JakubOnderka\OpenIDConnectClient($providerUrl, $clientId, $clientSecret, $issuer);
        } else if (class_exists("\Jumbojett\OpenIDConnectClient")) {
            throw new Exception("Jumbojett OIDC implementation is not supported anymore, please use JakubOnderka's client");
        } else {
            throw new Exception("OpenID Connect client is not installed.");
        }

        $authenticationMethod = $this->getConfig('authentication_method', false);
        if ($authenticationMethod !== false && $authenticationMethod !== null) {
            $oidc->setAuthenticationMethod($authenticationMethod);
        }

        $ccm = $this->getConfig('code_challenge_method', false);
        if ($ccm) {
            $oidc->setCodeChallengeMethod($ccm);
        }

        if ($this->getConfig('offline_access', false)) {
            $oidc->addScope('offline_access');
        }

        $scopes = $this->getConfig('scopes', [], false);
        if (!is_array($scopes)) {
            throw new RuntimeException("Config option `OidcAuth.scopes` must be array, " . gettype($scopes) . " given.");
        }
        $oidc->addScope($scopes);

        $oidc->setRedirectURL(Configure::read('MISP.baseurl') . '/users/login');
        $this->oidcClient = $oidc;
        return $oidc;
    }

    /**
     * Fetch organisation ID from database by provided name and UUID. If organisation is not found, it is created. If
     * organisation with given UUID has different name, then is renamed.
     * @param string $orgName Organisation name or UUID
     * @param string|null $orgUuid Organisation UUID
     * @param string $mispUsername
     * @return int
     * @throws Exception
     */
    private function checkOrganization($orgName, $orgUuid, $mispUsername)
    {
        if (empty($orgName)) {
            $this->log($mispUsername, "Organisation name not provided.");
            return false;
        }

        if ($orgUuid && !Validation::uuid($orgUuid)) {
            $this->log($mispUsername, "Organisation UUID `$orgUuid` is not valid UUID.");
            return false;
        }

        $orgNameIsUuid = Validation::uuid($orgName);
        if ($orgUuid) {
            $conditions = ['uuid' => strtolower($orgUuid)];
            $this->log($mispUsername, "Trying to find user org by UUID `$orgUuid`.");
        } else if ($orgNameIsUuid) {
            $conditions = ['uuid' => strtolower($orgName)];
            $this->log($mispUsername, "Trying to find user org by UUID `$orgName` provided in org name.");
        } else {
            $conditions = ['name' => $orgName];
            $this->log($mispUsername, "Trying to find user org by name `$orgName`.");
        }

        $orgAux = $this->User->Organisation->find('first', [
            'fields' => ['Organisation.id', 'Organisation.name'],
            'conditions' => $conditions,
        ]);
        if (empty($orgAux)) {
            // Org does not exists and we don't know org name, so it is not possible to crete a new one.
            if ($orgNameIsUuid) {
                $this->log($mispUsername, "Could not find organisation with UUID `$orgName`.");
                return false;
            }

            $orgId = $this->User->Organisation->createOrgFromName($orgName, 0, true, $orgUuid);
            $this->log($mispUsername, "User organisation `$orgName` created with ID $orgId.");
        } else {
            $orgId = $orgAux['Organisation']['id'];
            $this->log($mispUsername, "User organisation `$orgName` found with ID $orgId.");

            // If org name in database is different, update to new name from OIDC
            if ($orgUuid && $orgName != $orgAux['Organisation']['name']) {
                $this->changeOrgName($orgId, $orgName);
                $this->log($mispUsername, "Changed org name for #$orgId from `{$orgAux['Organisation']['name']}` to `$orgName`.");
            }
        }
        return $orgId;
    }

    /**
     * @return false|int Organisation ID or false if org not found
     */
    private function defaultOrganisationId()
    {
        $defaultOrgName = $this->getConfig('default_org');
        if (empty($defaultOrgName)) {
            return false;
        }

        if (is_numeric($defaultOrgName)) {
            $conditions = ['id' => $defaultOrgName];
        } else if (Validation::uuid($defaultOrgName)) {
            $conditions = ['uuid' => strtolower($defaultOrgName)];
        } else {
            $conditions = ['name' => $defaultOrgName];
        }
        $orgAux = $this->User->Organisation->find('first', [
            'fields' => ['Organisation.id'],
            'conditions' => $conditions,
        ]);
        if (empty($orgAux)) {
            if (is_numeric($defaultOrgName)) {
                $this->log(null, "Could not find default organisation with ID `$defaultOrgName`.", LOG_ERR);
            } else if (Validation::uuid($defaultOrgName)) {
                $this->log(null, "Could not find default organisation with UUID `$defaultOrgName`.", LOG_ERR);
            } else {
                $this->log(null, "Could not find default organisation with name `$defaultOrgName`.", LOG_ERR);
            }
            return false;
        }

        return $orgAux['Organisation']['id'];
    }

    /**
     * @param int $orgId
     * @param string $newName
     * @return void
     * @throws Exception
     */
    private function changeOrgName($orgId, $newName)
    {
        $result = $this->User->Organisation->save([
            'id' => $orgId,
            'name' => $newName,
        ], true, ['id', 'name']);
        if (!$result) {
            throw new Exception("Could not rename org with ID $orgId to `$newName`.");
        }
    }

    /**
     * @param array|string $roles Role list provided by OIDC
     * @param string $mispUsername
     * @return int|null Role ID or null if no role matches
     */
    private function getUserRole($roles, $mispUsername)
    {
        $roles = is_string($roles) ? explode($this->getConfig('roles_delimiter', ','), $roles) : $roles;
        $this->log($mispUsername, 'Provided roles: ' . implode(', ', $roles));
        $roleMapper = $this->getConfig('role_mapper');
        if (!is_array($roleMapper)) {
            throw new RuntimeException("Config option `OidcAuth.role_mapper` must be array.");
        }

        $roleNameToId = $this->User->Role->find('list', [
            'fields' => ['Role.name', 'Role.id'],
        ]);
        $roleNameToId = array_change_key_case($roleNameToId); // normalize role names to lowercase

        foreach ($roleMapper as $oidcRole => $mispRole) {
            if (in_array($oidcRole, $roles, true)) {
                if (!is_numeric($mispRole)) {
                    $mispRole = mb_strtolower($mispRole);
                    if (isset($roleNameToId[$mispRole])) {
                        $mispRole = $roleNameToId[$mispRole];
                    } else {
                        $this->log($mispUsername, "MISP Role with name `$mispRole` not found, skipping.");
                        continue;
                    }
                }
                return $mispRole; // first match wins
            }
        }

        return null;
    }

    /**
     * @param array $settings
     * @param array $conditions
     * @return array|null
     */
    private function _findUser(array $settings, array $conditions)
    {
        $result = $this->User->find('first', [
            'conditions' => $conditions,
            'recursive' => $settings['recursive'],
            'fields' => $settings['userFields'],
            'contain' => $settings['contain'],
        ]);
        if ($result) {
            $user = $result['User'];
            unset($result['User']);
            return array_merge($user, $result);
        }
        return null;
    }

    /**
     * @param string $config
     * @param mixed|null $default
     * @param bool $required When true and variable is not set, RuntimeException will be thrown
     * @return mixed
     * @throws RuntimeException when config option is not set
     */
    private function getConfig($config, $default = null, $required = true)
    {
        $value = Configure::read("OidcAuth.$config");
        if ($value === null) {
            if ($default === null && $required) {
                throw new RuntimeException("Config option `OidcAuth.$config` is not set.");
            }
            return $default;
        }
        return $value;
    }

    /**
     * @param array $user
     * @return array
     */
    private function findUserInfo(array $user)
    {
        if (isset($user['UserSetting'])) {
            foreach ($user['UserSetting'] as $userSetting) {
                if ($userSetting['setting'] === 'oidc') {
                    return $userSetting['value'];
                }
            }
        }
        return $this->User->UserSetting->getValueForUser($user['id'], 'oidc');
    }

    /**
     * @param int $userId
     * @param stdClass $verifiedClaims
     * @param string|null $refreshToken
     * @return array|bool|mixed|null
     * @throws Exception
     */
    private function storeMetadata($userId, \stdClass $verifiedClaims, $refreshToken = null)
    {
        // OIDC session ID
        if (isset($verifiedClaims->sid)) {
            CakeSession::write('oidc_sid', $verifiedClaims->sid);
        }

        $value = [];
        foreach (['preferred_username', 'given_name', 'family_name'] as $field) {
            if (property_exists($verifiedClaims, $field)) {
                $value[$field] = $verifiedClaims->{$field};
            }
        }
        if ($refreshToken) {
            $value['validity_check_timestamp'] = time();
            $value['refresh_token'] = $refreshToken;
        }

        return $this->User->UserSetting->setSettingInternal($userId, 'oidc', $value);
    }

    /**
     * @param array $user
     * @return void
     * @throws Exception
     */
    private function block(array $user)
    {
        $this->User->updateField($user, 'disabled', true);
        $this->log($user['email'], "User blocked by OIDC");
    }

    /**
     * @param string|null $username
     * @param string $message
     * @param int $type
     */
    private function log($username, $message, $type = LOG_INFO)
    {
        $log = $username ? "OIDC user `$username`" : "OIDC";

        if (PHP_SAPI !== 'cli') {
            $sessionId = substr(session_id(), 0, 6);
            $ip = $this->User->_remoteIp();
            $log .= " [$ip;$sessionId] - $message";
        } else {
            $log .= " - $message";
        }

        CakeLog::write($type, $log);
    }
}
