<?php

App::uses('AppModel', 'Model');

class UserLoginProfile extends AppModel
{
    public $actsAs = array(
        'AuditLog',
            'Containable',
            'SysLogLogable.SysLogLogable' => array(
                'userModel' => 'User',
                'userKey' => 'user_id',
                'change' => 'full'
            ),
            'Containable'
    );

    public $validate = [
        // 'ip' => [
        //     'rule' => ''
        // ],
        // 'user_agent' => [],
        // 'status' => [
        //     'boolean' => ['rule' => 'boolean']
        // ],
        // 'created_at' => []],  // when the status was saved
        // 'user_id' => [
        //     'rule' => 'userExists',
        //     'message' => 'User doesn\'t exists',
        // ],
    ];

    public $belongsTo = [
    'User' => [
        'className' => 'User',
        'foreignKey' => 'user_id',
        'conditions' => '',
        'fields' => '',
        'order' => ''
    ]];

    /**
     * slow function - don't call it too often 
     * @return array
     */
    public function _getUserProfile() {
        if (!$this->userProfile) {
            $browser = get_browser();   // FIXME browscap.ini needs to be installed and takes a lot of memory, maybe we want a more simple 
                                        // FIXME replace by https://github.com/browscap/browscap-php 
                                        // this needs to be integrated in the update mechanism, for updating the capabilities page 
            $this->userProfile = [
                'user_agent' => env('HTTP_USER_AGENT'),
                'ip' => $this->_remoteIp(),
                'accept_lang' => env('HTTP_ACCEPT_LANGUAGE'),
                'ja3' => '',   // see https://fingerprint.com/blog/what-is-tls-fingerprinting-transport-layer-security/
                'geoip' => '',  // FIXME do geoip
                'ua_pattern' => $browser->browser_name_pattern,
                'ua_platform' => $browser->platform,
                'ua_browser' => $browser->browser
            ];
        }
        return $this->userProfile;
    }

    public function _fromLog($logEntry) {
        $data = json_decode('{"user_agent": "", "ip": "", "accept_lang":"", "ja3":"", "geoip":"", "ua_pattern":"", "ua_platform":"", "ua_browser":""}', true);
        $data = array_merge($data, json_decode($logEntry['change'], true) ?? []);
        $data['ip'] = $logEntry['ip'];
        
        return $data;
    }

    public function _isSimilar($a, $b) {
        if (!$a || !$b) return false;  // if one is not initialized
        // coming from the same source IP, and the same browser
        if ($a['ip'] == $b['ip'] && $a['ua_browser'] == $b['ua_browser']) {
            return true;
        }
        if (!$a['ua_browser']) return false;
        // really similar session, from same region, but different IP
        if ($a['ua_browser'] == $b['ua_browser'] && 
            $a['ua_platform'] == $b['ua_platform'] &&
            $a['accept_lang'] == $b['accept_lang'] &&
            $a['geoip'] == $b['geoip']) {
            return true;
        }
        return false;
    }

    public function _getTrustStatus($userProfileToCheck) {
        // load Singleton
        if (!$this->knownUserProfiles) {
            $this->knownUserProfiles = $this->find('all', [
                // 'fields' => ['UserLoginProfile.status'],
                'conditions' => ['UserLoginProfile.user_id' => AuthComponent::user('id')], // FIXME set username
                'recursive' => 0],
            );
        }
        // perform check on all entries, and stop when check OK
        foreach ($this->knownUserProfiles as $knownUserProfile) {
            // same IP
            if ($userProfileToCheck['ip'] == $knownUserProfile['UserLoginProfile']['ip']) {
                return $knownUserProfile['UserLoginProfile']['status'];
            }
            // if it is similar, more complex ruleset
            if ($this->_isSimilar($knownUserProfile['UserLoginProfile'], $userProfileToCheck)) {
                return $knownUserProfile['UserLoginProfile']['status'];
            }
        }
        // bad news, iterated over all and no similar found
        return 'unknown';
    }

}
