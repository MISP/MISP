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
    protected $geoIpDbFile = APP . DS . 'files' . DS . 'geo-open' . DS . 'GeoOpen-Country.mmdb';  // GeoIP file managed by MISP - https://data.public.lu/en/datasets/geo-open-ip-address-geolocation-per-country-in-mmdb-format/

    private $knownUserProfiles = [];

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
            if (class_exists('\BrowscapPHP\Browscap')) {
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
        return $data;
    }

    public function _isSimilar($a, $b) {
        // if one is not initialized
        if (!$a || !$b) return false;
        // coming from the same source IP, and the same browser
        if ($a['ip'] == $b['ip'] && $a['ua_browser'] == $b['ua_browser'])
            return true;
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
                'recursive' => 0],
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
            return _('The UserLoginProfile was reported as malicious in the past.');
        }
        // same IP as previous malicious user
        $maliciousWithSameIP = $this->find('first', [
            'conditions' => [
                'UserLoginProfile.ip' => $this->_getUserProfile()['ip'],
                'UserLoginProfile.status' => 'malicious'
        ],
            'recursive' => 0,
            'fields' => array('UserLoginProfile.*')],
        );
        if ($maliciousWithSameIP) {
            return _('Source IP was reported as as malicious in the past.');
        }
        // LATER - use other data to identify suspicious logins, such as:
        // - warning lists
        // - ...
        return false;
    }


}
