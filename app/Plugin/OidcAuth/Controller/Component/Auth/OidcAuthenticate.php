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
 *  - OidcAuth.organisation_property (default: `organization`)
 *  - OidcAuth.roles_property (default: `roles`)
 *  - OidcAuth.default_org
 *  - OidcAuth.unblock (boolean, default: false)
 *  - OidcAuth.offline_access (boolean, default: false)
 *  - OidcAuth.check_user_validity (integer, default `0`)
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
        $oidc = new Oidc($userModel);
        return $oidc->authenticate($this->settings);
    }
}
