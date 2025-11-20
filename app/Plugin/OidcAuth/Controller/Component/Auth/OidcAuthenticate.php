<?php
App::uses('BaseAuthenticate', 'Controller/Component/Auth');
App::uses('Oidc', 'OidcAuth.Lib');

/**
 * Config options:
 *  - OidcAuth.provider_url
 *  - OidcAuth.client_id
 *  - OidcAuth.client_secret
 *  - OidcAuth.authentication_method
 *  - OidcAuth.code_challenge_method
 *  - OidcAuth.role_mapper
 *  - OidcAuth.scopes (array, default: []) - request additional scopes ex. 'scopes' => ['profile', 'email']
 *  - OidcAuth.organisation_property (default: `organization`)
 *  - OidcAuth.organisation_uuid_property (default: `organization_uuid`)
 *  - OidcAuth.roles_property (default: `roles`)
 *  - OidcAuth.default_org - organisation ID, UUID or name if organisation is not provided by OIDC
 *  - OidcAuth.unblock (boolean, default: false)
 *  - OidcAuth.offline_access (boolean, default: false)
 *  - OidcAuth.check_user_validity (integer, default `0`)
 *  - OidcAuth.update_user_role (boolean, default: true) - if disabled, manually modified role in MISP admin interface will be not changed from OIDC
 *  - OidcAuth.mixedAuth (boolean, default: false) - if enabled, MISP will not automatically redirect to SSO portal and allow other authentication methods
 */
class OidcAuthenticate extends BaseAuthenticate
{
    /**
     * @param CakeRequest $request
     * @param CakeResponse $response
     * @return mixed|void
     * @throws Exception
     */
    public function authenticate(CakeRequest $request, CakeResponse $response)
    {
        $userModel = ClassRegistry::init($this->settings['userModel']);
        $headers = $response->header();
        if($headers) {
            foreach($headers as $name=>$value) {
                if ($value === null) {
                    header($name);
                } else {
                    header("{$name}: {$value}");
                }
            }
        }

        $oidc = new Oidc($userModel);

        $mixedAuth = Configure::read("OidcAuth.mixedAuth", false);

        if (!$mixedAuth){
            return $oidc->authenticate($this->settings);
        }

        if (!$mixedAuth && empty($request->query['OidcAuth']) && empty($request->query['code'])) {
            return false;
        }

        if (($request->query['OidcAuth'] ?? null) === 'enable' || isset($request->query['code'])) {
            return $oidc->authenticate($this->settings);
        }

        return false;
    }
}
