<?php
App::uses('BaseAuthenticate', 'Controller/Component/Auth');

/**
 * Config options:
 *  - OidcAuth.provider_url
 *  - OidcAuth.client_id
 *  - OidcAuth.client_secret
 *  - OidcAuth.authentication_method
 *  - OidcAuth.code_challenge_method
 *  - OidcAuth.role_mapper
 *  - OidcAuth.organisation_property (default: `organization`)
 *  - OidcAuth.roles_property (default: `roles`)
 *  - OidcAuth.default_org
 *  - OidcAuth.unblock (boolean, default: false)
 *  - OidcAuth.offline_access (boolean, default: false)
 *  - OidcAuth.check_user_validity (integer, default `0`)
 */
class OidcAuthenticate extends BaseAuthenticate
{
    /** @var User|null */
    private $userModel;

    /** @var \JakubOnderka\OpenIDConnectClient|\Jumbojett\OpenIDConnectClient */
    private $oidc;

    /**
     * @param CakeRequest $request
     * @param CakeResponse $response
     * @return mixed|void
     * @throws Exception
     */
    public function authenticate(CakeRequest $request, CakeResponse $response)
    {
        $oidc = $this->prepareClient();

        if (!$oidc->authenticate()) {
            throw new Exception("OIDC authentication was not successful.");
        }

        $claims = $oidc->getVerifiedClaims();

        $mispUsername = $claims->email ?? $oidc->requestUserInfo('email');
        $this->log($mispUsername, "Trying login.");

        $sub = $claims->sub; // sub is required
        $organisationProperty = $this->getConfig('organisation_property', 'organization');
        $organisationName = $claims->{$organisationProperty} ?? $this->getConfig('default_org');

        // Try to find user by `sub` field, that is unique
        $this->settings['fields'] = ['username' => 'sub'];
        $user = $this->_findUser($sub);

        if (!$user) { // User by sub not found, try to find by email
            $this->settings['fields'] = ['username' => 'email'];
            $user = $this->_findUser($mispUsername);
            if ($user && $user['sub'] !== null && $user['sub'] !== $sub) {
                $this->log($mispUsername, "User sub doesn't match ({$user['sub']} != $sub), could not login.");
                return false;
            }
        }

        $organisationId = $this->checkOrganization($organisationName, $user, $mispUsername);
        if (!$organisationId) {
            if ($user) {
                $this->block($user);
            }
            return false;
        }

        $roles = [];
        $roleProperty = $this->getConfig('roles_property', 'roles');
        if (property_exists($claims, $roleProperty)) {
            $roles = $claims->{$roleProperty};
        }
        if (empty($roles)) {
            $roles = $oidc->requestUserInfo($roleProperty);
        }

        $roleId = $this->getUserRole($roles, $mispUsername);
        if ($roleId === null) {
            $this->log($mispUsername, 'No role was assigned.');
            if ($user) {
                $this->block($user);
            }
            return false;
        }

        if ($user) {
            $this->log($mispUsername, "Found in database with ID {$user['id']}.");

            if ($user['sub'] === null) {
                $this->userModel()->updateField($user, 'sub', $sub);
                $this->log($mispUsername, "User sub changed from NULL to $sub.");
                $user['sub'] = $sub;
            }

            if ($user['email'] !== $mispUsername) {
                $this->userModel()->updateField($user, 'email', $mispUsername);
                $this->log($mispUsername, "User e-mail changed from {$user['email']} to $mispUsername.");
                $user['email'] = $mispUsername;
            }

            if ($user['org_id'] != $organisationId) {
                $this->userModel()->updateField($user, 'org_id', $organisationId);
                $this->log($mispUsername, "User organisation changed from {$user['org_id']} to $organisationId.");
                $user['org_id'] = $organisationId;
            }

            if ($user['role_id'] != $roleId) {
                $this->userModel()->updateField($user, 'role_id', $roleId);
                $this->log($mispUsername, "User role changed from {$user['role_id']} to $roleId.");
                $user['role_id'] = $roleId;
            }

            if ($user['disabled'] && $this->getConfig('unblock', false)) {
                $this->userModel()->updateField($user, 'disabled', false);
                $this->log($mispUsername, "Unblocking user.");
                $user['disabled'] = false;
            }

            $refreshToken = $this->getConfig('offline_access', false) ? $oidc->getRefreshToken() : null;
            $this->storeMetadata($user['id'], $claims, $refreshToken);

            $this->log($mispUsername, 'Logged in.');
            return $user;
        }

        $this->log($mispUsername, 'Not found in database.');

        $userData = [
            'email' => $mispUsername,
            'org_id' => $organisationId,
            'newsread' => time(),
            'role_id' => $roleId,
            'change_pw' => 0,
            'date_created' => time(),
            'sub' => $sub,
        ];

        if (!$this->userModel()->save($userData)) {
            throw new RuntimeException("Could not save user `$mispUsername` to database.");
        }

        $refreshToken = $this->getConfig('offline_access', false) ? $oidc->getRefreshToken() : null;
        $this->storeMetadata($this->userModel()->id, $claims, $refreshToken);

        $this->log($mispUsername, "Saved in database with ID {$this->userModel()->id}");
        $this->log($mispUsername, 'Logged in.');
        return $this->_findUser($mispUsername);
    }

    /**
     * @param array $user
     * @param bool $blockInvalid Block invalid user
     * @param bool $ignoreValidityTime Ignore `check_user_validity` setting and always check if user is valid
     * @param bool $update
     * @return bool
     * @throws Exception
     */
    public function isUserValid(array $user, $blockInvalid = false, $ignoreValidityTime = false, $update = false)
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

        if (empty($user['sub'])) {
            return true; // user is not OIDC managed user
        }

        $userInfo = $this->findUserInfo($user);
        if (!isset($userInfo['refresh_token'])) {
            if ($blockInvalid) {
                $this->block($user);
            }
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
                if ($blockInvalid) {
                    $this->block($user);
                }
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

        // Check user role
        $roles = [];
        $claims = $oidc->getVerifiedClaims();
        $roleProperty = $this->getConfig('roles_property', 'roles');
        if (property_exists($claims, $roleProperty)) {
            $roles = $claims->{$roleProperty};
        }
        if (empty($roles)) {
            $roles = $oidc->requestUserInfo($roleProperty);
        }

        $roleId = $this->getUserRole($roles, $user['email']);
        if ($roleId === null) {
            $this->log($user['email'], 'No role was assigned.');
            if ($blockInvalid) {
                $this->block($user);
            }
            return false;
        }

        if ($update && $user['role_id'] != $roleId) {
            $this->userModel()->updateField($user, 'role_id', $roleId);
            $this->log($user['email'], "User role changed from {$user['role_id']} to $roleId.");
        }

        // Update refresh token if new token provided
        if ($oidc->getRefreshToken()) {
            $userInfo['validity_check_timestamp'] = time();
            $userInfo['refresh_token'] = $oidc->getRefreshToken();
            $this->userModel()->UserSetting->setSettingInternal($user['id'], 'oidc', $userInfo);
        }

        return true;
    }

    /**
     * @return \JakubOnderka\OpenIDConnectClient|\Jumbojett\OpenIDConnectClient
     * @throws Exception
     */
    private function prepareClient()
    {
        if ($this->oidc) {
            return $this->oidc;
        }

        $providerUrl = $this->getConfig('provider_url');
        if (!filter_var($providerUrl, FILTER_VALIDATE_URL)) {
            throw new RuntimeException("Config option `OidcAuth.provider_url` must be valid URL.");
        }

        $clientId = $this->getConfig('client_id');
        $clientSecret = $this->getConfig('client_secret');
        $authenticationMethod = $this->getConfig('authentication_method', false);

        if (class_exists("\JakubOnderka\OpenIDConnectClient")) {
            $oidc = new \JakubOnderka\OpenIDConnectClient($providerUrl, $clientId, $clientSecret);
            if ($authenticationMethod !== false && $authenticationMethod !== null) {
                $oidc->setAuthenticationMethod($authenticationMethod);
            }
        } else if (class_exists("\Jumbojett\OpenIDConnectClient")) {
            // OpenIDConnectClient will append well-know path, so if well-know path is already part of the url, remove it
            // This is required just for Jumbojett, not for JakubOnderka
            $wellKnownPosition = strpos($providerUrl, '/.well-known/');
            if ($wellKnownPosition !== false) {
                $providerUrl = substr($providerUrl, 0, $wellKnownPosition);
            }

            $oidc = new \Jumbojett\OpenIDConnectClient($providerUrl, $clientId, $clientSecret);
            if ($authenticationMethod !== false && $authenticationMethod !== null) {
                throw new Exception("Jumbojett OIDC implementation do not support changing authentication method, please use JakubOnderka's client");
            }
        } else {
            throw new Exception("OpenID connect client is not installed.");
        }

        $ccm = $this->getConfig('code_challenge_method', false);
        if ($ccm) {
            $oidc->setCodeChallengeMethod($ccm);
        }

        if ($this->getConfig('offline_access', false)) {
            $oidc->addScope('offline_access');
        }

        $oidc->setRedirectURL(Configure::read('MISP.baseurl') . '/users/login');
        $this->oidc = $oidc;
        return $oidc;
    }

    /**
     * @param string $org
     * @param array|null $user
     * @param string $mispUsername
     * @return int
     * @throws Exception
     */
    private function checkOrganization($org, $user, $mispUsername)
    {
        if (empty($org)) {
            $this->log($mispUsername, "Organisation name not provided.");
            return false;
        }

        $orgIsUuid = Validation::uuid($org);

        $orgAux = $this->userModel()->Organisation->find('first', [
            'fields' => ['Organisation.id'],
            'conditions' => $orgIsUuid ? ['uuid' => mb_strtolower($org)] : ['name' => $org],
        ]);
        if (empty($orgAux)) {
            if ($orgIsUuid) {
                $this->log($mispUsername, "Could not found organisation with UUID `$org`.");
                return false;
            }

            $orgUserId = 1; // By default created by the admin
            if ($user) {
                $orgUserId = $user['id'];
            }
            $orgId = $this->userModel()->Organisation->createOrgFromName($org, $orgUserId, true);
            $this->log($mispUsername, "User organisation `$org` created with ID $orgId.");
        } else {
            $orgId = $orgAux['Organisation']['id'];
            $this->log($mispUsername, "User organisation `$org` found with ID $orgId.");
        }
        return $orgId;
    }

    /**
     * @param array $roles Role list provided by OIDC
     * @param string $mispUsername
     * @return int|null Role ID or null if no role matches
     */
    private function getUserRole(array $roles, $mispUsername)
    {
        $this->log($mispUsername, 'Provided roles: ' . implode(', ', $roles));
        $roleMapper = $this->getConfig('role_mapper');
        if (!is_array($roleMapper)) {
            throw new RuntimeException("Config option `OidcAuth.role_mapper` must be array.");
        }

        $roleNameToId = $this->userModel()->Role->find('list', [
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
     * @param string $config
     * @param mixed|null $default
     * @return mixed
     */
    private function getConfig($config, $default = null)
    {
        $value = Configure::read("OidcAuth.$config");
        if (empty($value)) {
            if ($default === null) {
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
        return $this->userModel()->UserSetting->getValueForUser($user['id'], 'oidc');
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

        return $this->userModel()->UserSetting->setSettingInternal($userId, 'oidc', $value);
    }

    /**
     * @param array $user
     * @return void
     * @throws Exception
     */
    private function block(array $user)
    {
        $this->userModel()->updateField($user, 'disabled', true);
        $this->log($user['email'], "User blocked by OIDC");
    }

    /**
     * @param string $username
     * @param string $message
     */
    private function log($username, $message)
    {
        CakeLog::info("OIDC: User `$username` – $message");
    }

    /**
     * @return User
     */
    private function userModel()
    {
        if (isset($this->userModel)) {
            return $this->userModel;
        }

        $this->userModel = ClassRegistry::init($this->settings['userModel']);
        return $this->userModel;
    }
}
