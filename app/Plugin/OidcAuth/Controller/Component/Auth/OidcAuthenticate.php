<?php
use Jumbojett\OpenIDConnectClient;
App::uses('BaseAuthenticate', 'Controller/Component/Auth');

/**
 * Config options:
 *  - OidcAuth.provider_url
 *  - OidcAuth.client_id
 *  - OidcAuth.client_secret
 *  - OidcAuth.role_mapper
 *  - OidcAuth.organisation_property (default: `organization`)
 *  - OidcAuth.roles_property (default: `roles`)
 *  - OidcAuth.default_org
 */
class OidcAuthenticate extends BaseAuthenticate
{
    /** @var User|null */
    private $userModel;

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

        $mispUsername = $oidc->requestUserInfo('email');
        $this->log($mispUsername, "Trying login");

        $verifiedClaims = $oidc->getVerifiedClaims();
        $organisationProperty = $this->getConfig('organisation_property', 'organization');
        if (property_exists($verifiedClaims, $organisationProperty)) {
            $organisationName = $verifiedClaims->{$organisationProperty};
        } else {
            $organisationName = $this->getConfig('default_org');
        }

        $roles = [];
        $roleProperty = $this->getConfig('roles_property', 'roles');
        if (property_exists($verifiedClaims, $roleProperty)) {
            $roles = $verifiedClaims->{$roleProperty};
        }

        $this->settings['fields'] = ['username' => 'email'];
        $user = $this->_findUser($mispUsername);

        $organisationId = $this->checkOrganization($organisationName, $user, $mispUsername);
        if (!$organisationId) {
            return false;
        }

        $roleId = $this->getUserRole($roles, $mispUsername);
        if ($roleId === null) {
            $this->log($mispUsername, 'No role was assigned.');
            return false;
        }

        if ($user) {
            $this->log($mispUsername, "Found in database with ID {$user['id']}.");

            if ($user['org_id'] != $organisationId) {
                $user['org_id'] = $organisationId;
                $this->userModel()->updateField($user, 'org_id', $organisationId);
                $this->log($mispUsername, "User organisation changed from {$user['org_id']} to $organisationId.");
            }

            if ($user['role_id'] != $roleId) {
                $user['role_id'] = $roleId;
                $this->userModel()->updateField($user, 'role_id', $roleId);
                $this->log($mispUsername, "User role changed from {$user['role_id']} to $roleId.");
            }

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
        ];

        if (!$this->userModel()->save($userData)) {
            throw new RuntimeException("Could not save user `$mispUsername` to database.");
        }

        $this->log($mispUsername, "Saved in database with ID {$this->userModel()->id}");
        $this->log($mispUsername, 'Logged in.');
        return $this->_findUser($mispUsername);
    }

    /**
     * @return OpenIDConnectClient
     */
    private function prepareClient()
    {
        $providerUrl = $this->getConfig('provider_url');
        if (!filter_var($providerUrl, FILTER_VALIDATE_URL)) {
            throw new RuntimeException("Config option `OidcAuth.provider_url` must be valid URL.");
        }

        // OpenIDConnectClient will append well-know path, so if well-know path is already part of the url, remove it
        $wellKnownPosition = strpos($providerUrl, '/.well-known/');
        if ($wellKnownPosition !== false) {
            $providerUrl = substr($providerUrl, 0, $wellKnownPosition);
        }

        $clientId = $this->getConfig('client_id');
        $clientSecret = $this->getConfig('client_secret');

        $oidc = new OpenIDConnectClient($providerUrl, $clientId, $clientSecret);
        $oidc->setRedirectURL(Configure::read('MISP.baseurl') . '/users/login');
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

        $userRole = null;
        foreach ($roles as $role) {
            if (isset($roleMapper[$role])) {
                $roleId = $roleMapper[$role];
                if (!is_numeric($roleId)) {
                    $roleId = mb_strtolower($roleId);
                    if (isset($roleNameToId[$roleId])) {
                        $roleId = $roleNameToId[$roleId];
                    } else {
                        $this->log($mispUsername, "MISP Role with name `$roleId` not found, skipping.");
                        continue;
                    }
                }
                return $roleId; // first match wins
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
