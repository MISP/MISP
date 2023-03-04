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

    protected $browscapCacheDir = APP . DS . 'tmp' . DS . 'browscap';
    protected $browscapIniFile = APP . DS . 'files' . DS . 'browscap'. DS . 'browscap.ini';       // Browscap file managed by MISP - https://browscap.org/stream?q=Lite_PHP_BrowsCapINI
    protected $geoIpDbFile = APP . DS . 'files' . DS . 'geo-open' . DS . 'GeoOpen-Country.mmdb';  // GeoIP file managed by MISP

    public function _buildBrowscapCache() {
        $this->log("Browscap - building new cache from browscap.ini file.", "info");
        $fileCache = new \League\Flysystem\Local\LocalFilesystemAdapter($this->browscapCacheDir);
        $filesystem = new \League\Flysystem\Filesystem($fileCache);
        $cache = new \MatthiasMullie\Scrapbook\Psr16\SimpleCache(
            new \MatthiasMullie\Scrapbook\Adapters\Flysystem($filesystem)
        );
        $logger = new \Monolog\Logger('name');
        $bc = new \BrowscapPHP\BrowscapUpdater($cache, $logger);
        $bc->convertFile($this->browscapIniFile);
    }

    /**
     * slow function - don't call it too often 
     * @return array
     */
    public function _getUserProfile() {
        if (!$this->userProfile) {
            // below uses https://github.com/browscap/browscap-php 
            try {
                $fileCache = new \League\Flysystem\Local\LocalFilesystemAdapter($this->browscapCacheDir);
                $filesystem = new \League\Flysystem\Filesystem($fileCache);
                $cache = new \MatthiasMullie\Scrapbook\Psr16\SimpleCache(
                    new \MatthiasMullie\Scrapbook\Adapters\Flysystem($filesystem)
                );
                $logger = new \Monolog\Logger('name');
                $bc = new \BrowscapPHP\Browscap($cache, $logger);
                $browser = $bc->getBrowser();
            } catch (\BrowscapPHP\Exception $e) {
                $this->_buildBrowscapCache();
                return $this->_getUserProfile();
            }
            $ip = $this->_remoteIp();
            $geoDbReader = new GeoIp2\Database\Reader($this->geoIpDbFile);
            $record = $geoDbReader->country($ip);
            $country = $record->country->isoCode;
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
        
        return $data;
    }

    public function _isSimilar($a, $b) {
        // if one is not initialized
        if (!$a || !$b) return false;
        // coming from the same source IP, and the same browser
        if ($a['ip'] == $b['ip'] && $a['ua_browser'] == $b['ua_browser']) return true;
        // transition for old logs where UA was not known
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

    public function _getTrustStatus($userProfileToCheck) {
        // load Singleton
        if (!$this->knownUserProfiles) {
            $this->knownUserProfiles = $this->find('all', [
                'conditions' => ['UserLoginProfile.user_id' => AuthComponent::user('id')],
                'recursive' => 0],
            );
        }
        // perform check on all entries, and stop when check OK
        foreach ($this->knownUserProfiles as $knownUserProfile) {
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
            return 'UserLoginProfile was marked as malicious';
        }
        // FIXME chri - use other data to identify suspicious logins, such as:
        // - other marked 'malicious' userloginprofiles
        // - warning lists
        // - ...
        return false;
    }


}
