<?php

App::uses('BaseAuthenticate', 'Controller/Component/Auth');

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

class ApacheShibbAuthenticate extends BaseAuthenticate {


    /**
     * Authentication class
     *
     * Configuration in app/Config/Config.php is:
     *
     * 'ApacheShibbAuth' =>                      // Configuration for shibboleth authentication
     *     array(
     *      'apacheEnv' => 'REMOTE_USER',        // If proxy variable = HTTP_REMOTE_USER
     *      'ssoAuth' => 'AUTH_TYPE',            // NOT to modify
     *      'MailTag' => 'EMAIL_TAG',
     *      'OrgTag' => 'FEDERATION_TAG',
     *      'GroupTag' => 'GROUP_TAG',
     *      'GroupSeparator' => ';',
     *      'GroupRoleMatching' => array(                // 3:User, 1:admin. May be good to set "1" for the first user
     *          'group_three' => '3',
     *          'group_two' => 2,
     *          'group_one' => 1,
     *       ),
     *      'DefaultRoleId' => 3,
     *      'DefaultOrg' => 'MY_ORG',
     * ),
     * @param CakeRequest $request The request that contains login information.
     * @param CakeResponse $response Unused response object.
     * @return mixed False on login failure. An array of User data on success.
     */


    public function authenticate(CakeRequest $request, CakeResponse $response)
    {
        return self::$this->getUser($request);
    }

    /**
     * @return array|bool
     */
    public function getUser(CakeRequest $request)
    {
        // Get Default parameters
        $roleId = Configure::read('ApacheShibbAuth.DefaultRoleId');
        $org = Configure::read('ApacheShibbAuth.DefaultOrg');
        // Get tags from SSO config
        $mailTag = Configure::read('ApacheShibbAuth.MailTag');
        $orgTag = Configure::read('ApacheShibbAuth.OrgTag');
        $groupTag = Configure::read('ApacheShibbAuth.GroupTag');
        $groupRoleMatching = Configure::read('ApacheShibbAuth.GroupRoleMatching');

        // Get user values
        $mispUsername = $_SERVER[$mailTag];

        //Change username column for email (username in shibboleth attributes corresponds to the email in MISPs DB)
        $this->settings['fields'] = array('username' => 'email');

        // Find user with real username (mail)
        $user = $this->_findUser($mispUsername);

        //Obtain default org. If not, org keeps the default value
        if (isset($_SERVER[$orgTag])) {
            $org = $_SERVER[$orgTag];
        }

        //Check if the list
        $roleChanged = false;
        if (isset($_SERVER[$groupTag])) {
            $groupSeparator = Configure::read('ApacheShibbAuth.GroupSeparator');
            $groupList = explode($groupSeparator, $_SERVER[$groupTag]);
            //Check user roles and egroup match and update if needed
            foreach ($groupList as $group) {
                $roleVal = $groupRoleMatching[$group];
                if ($roleVal <= $roleId) {
                    $roleId = $roleVal;
                    $roleChanged = true;
                }
            }
        }
        // Database model object
        $userModel = ClassRegistry::init($this->settings['userModel']);

        if ($user) { // User already exists
            if ($roleChanged && $user['role_id'] != $roleId) {
                $user['role_id'] = $roleId; // Different role either increase or decrease permissions
                $userUpdatedData = array('User' => $user);
                $userModel->set(array(
                    'role_id' => $roleId,
                    'id' => $user['id'],
                )); // Update the user
                $userModel->save($userUpdatedData, false);
            }
            return $user;
        }
        // insert user in database if not existent
        //Generate random password
        $password = $this->randPasswordGen(40);
        // create user
        $userData = array('User' => array(
            'email' => $mispUsername,
            'org_id' => $org,
            'password' => $password, //Since it is done via shibboleth the password will be a random 40 character string
            'confirm_password' => $password,
            'authkey' => $userModel->generateAuthKey(),
            'nids_sid' => 4000000,
            'newsread' => date('Y-m-d'),
            'role_id' => $roleId,
            'change_pw' => 0
        ));

        // save user
        $userModel->save($userData, false);

        return $this->_findUser(
            $mispUsername
        );
    }

    private function randPasswordGen($len){
        $result = "";
        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\$_?!-0123456789";
        $charArray = str_split($chars);
        for($i = 0; $i < $len; $i++){
            $randItem = array_rand($charArray);
            $result .= "".$charArray[$randItem];
        }
        return $result;
    }
}