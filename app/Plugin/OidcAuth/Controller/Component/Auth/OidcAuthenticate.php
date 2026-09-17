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
 *  - OidcAuth.update_user_organization (boolean, default: true) - if disabled, manually modified organisation in MISP admin interface will be not changed from OIDC
 *  - OidcAuth.mixedAuth (boolean, default: false) - if enabled, MISP will not automatically redirect to SSO portal and allow other authentication methods
 *  - OidcAuth.disable_request_object (boolean, default: false) Disable the Request Object approach in authorization requests, allowing users to fallback to plain parameters when needed for compatibility with certain OpenID Connect providers.
 *  - OidcAuth.disable_pushed_authorization_request (boolean, default: false) Disable the use of Pushed Authorization Requests (PAR) and send authorization request parameters directly to the authorization endpoint instead. This can be used for compatibility with OpenID Connect providers where PAR should not be used.
 *  - OidcAuth.skipProxy (boolean, default: true) - if enabled, MISP will disable global proxy settings for OIDC requests
 *  - OidcAuth.allow_email_linking (boolean, default: false) - allow OIDC to link to an existing local user (sub IS NULL) by matching the `email` claim. Off by default; enable only when the IdP is trusted to assert ownership of the email claim, otherwise a token holder may take over any local account sharing the email.
 *  - OidcAuth.require_email_verified (boolean, default: true) - when linking is allowed, also require the token's `email_verified` claim to be true. Disable only on IdPs that do not issue the claim and where ownership of the email is enforced by other means.
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
