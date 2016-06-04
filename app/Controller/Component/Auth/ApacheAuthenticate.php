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
    public function authenticate(CakeRequest $request, CakeResponse $response) {

        // Get information user for MISP auth
        $envvar = $this->settings['fields']['envvar'];
        $mispUsername = $_SERVER[$envvar];

        // make LDAP request to get user email required for MISP auth
        $ldapdn = Configure::read('ApacheSecureAuth.ldapDN');
        $ldaprdn = Configure::read('ApacheSecureAuth.ldapReaderUser');     // DN ou RDN LDAP
        $ldappass = Configure::read('ApacheSecureAuth.ldapReaderPassword');

        // LDAP connection
        $ldapconn = ldap_connect(Configure::read('ApacheSecureAuth.ldapServer'))
                or die('LDAP server connection failed');

        // LDAP protocol configuration
        ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, Configure::read('ApacheSecureAuth.ldapProtocol'));

        if ($ldapconn) {
            // LDAP bind
            $ldapbind = ldap_bind($ldapconn, $ldaprdn, $ldappass);
            // authentication verification
            if (!$ldapbind) {
                die("LDAP bind failed");
            }
            // example: '(uuid=ApacheUser)'
            $filter = '('.Configure::read('ApacheSecureAuth.ldapSearchAttribut').'=' . $_SERVER[$envvar] . ')';
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
            return $user;
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

        // create user
        $userData = array('User' => array(
                'email' => $mispUsername,
                'org_id' => $org_id,
                'password' => '',
                'confirm_password' => '',
                'authkey' => $userModel->generateAuthKey(),
                'nids_sid' => 4000000,
                'newsread' => date('Y-m-d'),
                'role_id' => Configure::read('ApacheSecureAuth.ldapDefaultRoleId'),
                'change_pw' => 0
        ));
        // save user
        $userModel->save($userData, false);

        return $this->_findUser(
                        $mispUsername
        );
    }

}
