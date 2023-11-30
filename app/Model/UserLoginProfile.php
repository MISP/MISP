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
        'status' => [
            'rule' => '/^(trusted|malicious)$/',
            'message' => 'Must be one of: trusted, malicious'
        ],
        
    ];

    public $order = array("UserLoginProfile.id" => "DESC");

    public $belongsTo = [
    'User' => [
        'className' => 'User',
        'foreignKey' => 'user_id',
        'conditions' => '',
        'fields' => '',
        'order' => ''
    ]];

    protected $browscapCacheDir = APP . DS . 'tmp' . DS . 'browscap';
    protected $browscapIniFile = APP . DS . 'files' . DS . 'browscap'. DS . 'browscap.ini';       // Browscap file managed by MISP - https://browscap.org/stream?q=Lite_PHP_BrowsCapINI
    protected $geoIpDbFile = APP . DS . 'files' . DS . 'geo-open' . DS . 'GeoOpen-Country.mmdb';  // GeoIP file managed by MISP - https://data.public.lu/en/datasets/geo-open-ip-address-geolocation-per-country-in-mmdb-format/

    private $knownUserProfiles = [];

    public function _buildBrowscapCache() {
        $this->log("Browscap - building new cache from browscap.ini file.", "info");
        $fileCache = new \Doctrine\Common\Cache\FilesystemCache($this->browscapCacheDir);
        $cache = new \Roave\DoctrineSimpleCache\SimpleCacheAdapter($fileCache);

        $logger = new \Monolog\Logger('name');
        $bc = new \BrowscapPHP\BrowscapUpdater($cache, $logger);
        $bc->convertFile($this->browscapIniFile);
    }

    public function beforeSave($options = [])
    {
        $this->data['UserLoginProfile']['hash'] = $this->hash($this->data['UserLoginProfile']);
        return true;
    }

    public function hash($data) {
        unset($data['hash']);
        unset($data['created_at']);
        return md5(serialize($data));
    }

    /**
     * slow function - don't call it too often 
     * @return array
     */
    public function _getUserProfile() {
        if (!$this->userProfile) {
            // below uses https://github.com/browscap/browscap-php 
            if (class_exists('\BrowscapPHP\Browscap')) {
                try {
                    $fileCache = new \Doctrine\Common\Cache\FilesystemCache($this->browscapCacheDir);
                    $cache = new \Roave\DoctrineSimpleCache\SimpleCacheAdapter($fileCache);
                    $logger = new \Monolog\Logger('name');
                    $bc = new \BrowscapPHP\Browscap($cache, $logger);
                    $browser = $bc->getBrowser();
                } catch (\BrowscapPHP\Exception $e) {
                    $this->_buildBrowscapCache();
                    return $this->_getUserProfile();
                }
            } else {
                // a primitive OS & browser extraction capability
                $ua = env('HTTP_USER_AGENT');
                $browser = new stdClass();
                $browser->browser_name_pattern = $ua;
                if (mb_strpos($ua, 'Linux') !== false)  $browser->platform = "Linux";
                else if (mb_strpos($ua, 'Windows') !== false)  $browser->platform = "Windows";
                else if (mb_strpos($ua, 'like Mac OS X') !== false)  $browser->platform = "ipadOS";
                else if (mb_strpos($ua, 'Mac OS X') !== false)  $browser->platform = "macOS";
                else if (mb_strpos($ua, 'Android') !== false) $browser->platform = 'Android';
                else $browser->platform = 'unknown';
                $browser->browser = "browser";
            }
            $ip = $this->_remoteIp();
            if (class_exists('GeoIp2\Database\Reader')) {
                $geoDbReader = new GeoIp2\Database\Reader($this->geoIpDbFile);
                $record = $geoDbReader->country($ip);
                $country = $record->country->isoCode;
            } else {
                $country = 'None';
            }
            $this->userProfile = [
                'user_agent' => env('HTTP_USER_AGENT'),
                'ip' => $ip,
                'accept_lang' => env('HTTP_ACCEPT_LANGUAGE'),
                'geoip' => $country,
                'ua_pattern' => $browser->browser_name_pattern,
                'ua_platform' => $browser->platform,
                'ua_browser' => $browser->browser
            ];
        }
        return $this->userProfile;
    }

    public function _fromLog($logEntry) {
        $data = json_decode('{"user_agent": "", "ip": "", "accept_lang":"", "geoip":"", "ua_pattern":"", "ua_platform":"", "ua_browser":""}', true);
        $data = array_merge($data, json_decode($logEntry['change'], true) ?? []);
        $data['ip'] = $logEntry['ip'];
        $data['timestamp'] = $logEntry['created'];
        if ($data['user_agent'] == "") return false;
        return $data;
    }

    public function _isSimilar($a, $b) {
        // if one is not initialized
        if (!$a || !$b) return false;
        // transition for old logs where UA was not known
        if (!$a['ua_browser']) 
            return false;
        // really similar session, from same browser, region, but different IP
        if ($a['ua_browser'] == $b['ua_browser'] && 
            $a['ua_platform'] == $b['ua_platform'] &&
            $a['accept_lang'] == $b['accept_lang'] &&
            $a['geoip'] == $b['geoip']) {
            return true;
        }
        // similar browser pattern, OS and region
        if ($a['ua_pattern'] == $b['ua_pattern'] && 
            $a['ua_platform'] == $b['ua_platform'] &&
            $a['accept_lang'] == $b['accept_lang'] &&
            $a['geoip'] == $b['geoip']) {
            return true;
        }
        return false;
    }

    public function _isIdentical($a, $b) {
        if ($a['ip'] == $b['ip'] &&
            $a['ua_browser'] == $b['ua_browser'] && 
            $a['ua_platform'] == $b['ua_platform'] &&
            $a['accept_lang'] == $b['accept_lang'] &&
            $a['geoip'] == $b['geoip']) {
            return true;
        }
        return false;
    }

    public function _getTrustStatus($userProfileToCheck, $user_id = null) {
        if (!$user_id) {
            $user_id = AuthComponent::user('id');
        }
        // load Singleton / caching
        if (!isset($this->knownUserProfiles[$user_id])) {
            $this->knownUserProfiles[$user_id] = $this->find('all', [
                'conditions' => ['UserLoginProfile.user_id' => $user_id],
                'recursive' => 0]
            );
        }
        // perform check on all entries, and stop when check OK
        foreach ($this->knownUserProfiles[$user_id] as $knownUserProfile) {
            // when it is the same
            if ($this->_isIdentical($knownUserProfile['UserLoginProfile'], $userProfileToCheck)) {
                return $knownUserProfile['UserLoginProfile']['status'];
            }
            // if it is similar, more complex ruleset
            if ($this->_isSimilar($knownUserProfile['UserLoginProfile'], $userProfileToCheck)) {
                return 'likely ' . $knownUserProfile['UserLoginProfile']['status'];
            }
        }
        // bad news, iterated over all and no similar found
        return 'unknown';
    }
    
    public function _isTrusted() {
        if (strpos($this->_getTrustStatus($this->_getUserProfile()), 'trusted') !== false) {
            return true;
        }
        return false;
    }

    public function _isSuspicious() {
        // previously marked loginuserprofile as malicious by the user
        if (strpos($this->_getTrustStatus($this->_getUserProfile()), 'malicious') !== false) {
            return _('A user reported a similar login profile as malicious.');
        }
        // same IP as previous malicious user
        $maliciousWithSameIP = $this->find('first', [
            'conditions' => [
                'UserLoginProfile.ip' => $this->_getUserProfile()['ip'],
                'UserLoginProfile.status' => 'malicious'
            ],
            'recursive' => 0,
            'fields' => array('UserLoginProfile.*')]
        );
        if ($maliciousWithSameIP) {
            return _('The source IP was reported as as malicious by a user.');
        }
        // LATER - use other data to identify suspicious logins, such as:
        // - what with use-case where a user marks something as legitimate, but is marked by someone else as suspicious?
        // - warning lists
        // - ...
        return false;
    }

    public function email_newlogin($user) {
        if (!Configure::read('MISP.disable_emailing')) {
            $date_time = date('c');

            $body = new SendEmailTemplate('userloginprofile_newlogin');
            $body->set('userLoginProfile', $this->User->UserLoginProfile->_getUserProfile());
            $body->set('baseurl', Configure::read('MISP.baseurl'));
            $body->set('misp_org', Configure::read('MISP.org'));
            $body->set('date_time', $date_time);
            // Fetch user that contains also PGP or S/MIME keys for e-mail encryption
            $result = $this->User->sendEmail($user, $body, false, "[" . Configure::read('MISP.org') . " MISP] New sign in.");
            if ($result) {
                // all is well, email sent to user
            } else {
                // email flow system already logs errors
            }
        }
    }

    public function email_report_malicious($user, $userLoginProfile) {
        // inform the org admin
        $date_time = $userLoginProfile['timestamp']; // LATER not ideal as timestamp is string without timezone info
        $body = new SendEmailTemplate('userloginprofile_report_malicious');
        $body->set('userLoginProfile', $userLoginProfile);
        $body->set('username', $user['User']['email']);
        $body->set('baseurl', Configure::read('MISP.baseurl'));
        $body->set('misp_org', Configure::read('MISP.org'));
        $body->set('date_time', $date_time);
        $org_admins = $this->User->getOrgAdminsForOrg($user['User']['org_id']);
        $admins = $this->User->getSiteAdmins();
        $all_admins = array_unique(array_merge($org_admins, $admins));
        foreach($all_admins as $admin_email) {
            $admin = $this->User->find('first', array(
                'recursive' => -1,
                'conditions' => ['User.email' => $admin_email]
            ));
            $result = $this->User->sendEmail($admin, $body, false, "[" . Configure::read('MISP.org') . " MISP] Suspicious login reported.");
            if ($result) {
                // all is well, email sent to user
            } else {
                // email flow system already logs errors
            }
        }
    }

    public function email_suspicious($user, $suspiciousness_reason) {
        if (!Configure::read('MISP.disable_emailing')) {
            $date_time = date('c');
            // inform the user
            $body = new SendEmailTemplate('userloginprofile_suspicious');
            $body->set('userLoginProfile', $this->_getUserProfile());
            $body->set('username', $user['User']['email']);
            $body->set('baseurl', Configure::read('MISP.baseurl'));
            $body->set('misp_org', Configure::read('MISP.org'));
            $body->set('date_time', $date_time);
            $body->set('suspiciousness_reason', $suspiciousness_reason);
            // inform the user
            $result = $this->User->sendEmail($user, $body, false, "[" . Configure::read('MISP.org') . " MISP] Suspicious login with your account.");
            if ($result) {
                // all is well, email sent to user
            } else {
                // email flow system already logs errors
            }
            // inform the org admin
            $body = new SendEmailTemplate('userloginprofile_suspicious_orgadmin');
            $body->set('userLoginProfile', $this->_getUserProfile());
            $body->set('username', $user['User']['email']);
            $body->set('baseurl', Configure::read('MISP.baseurl'));
            $body->set('misp_org', Configure::read('MISP.org'));
            $body->set('date_time', $date_time);
            $body->set('suspiciousness_reason', $suspiciousness_reason);
            $org_admins = $this->User->getOrgAdminsForOrg($user['User']['org_id']);
            foreach($org_admins as $org_admin_email) {
                $org_admin = $this->User->find('first', array(
                    'recursive' => -1,
                    'conditions' => ['User.email' => $org_admin_email]
                ));
                $result = $this->User->sendEmail($org_admin, $body, false, "[" . Configure::read('MISP.org') . " MISP] Suspicious login detected.");
                if ($result) {
                    // all is well, email sent to user
                } else {
                    // email flow system already logs errors
                }
            }            
        }
    }


}
