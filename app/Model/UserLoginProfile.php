<?php
App::uses('AppModel', 'Model');
App::uses('RedisTool', 'Tools');

/**
 * @property User $User
 */
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
        ]
    ];

    const BROWSER_CACHE_DIR = APP . DS . 'tmp' . DS . 'browscap';
    const BROWSER_INI_FILE = APP . DS . 'files' . DS . 'browscap'. DS . 'browscap.ini.gz';       // Browscap file managed by MISP - https://browscap.org/stream?q=Lite_PHP_BrowsCapINI
    const GEOIP_DB_FILE = APP . DS . 'files' . DS . 'geo-open' . DS . 'GeoOpen-Country.mmdb';  // GeoIP file managed by MISP - https://data.public.lu/en/datasets/geo-open-ip-address-geolocation-per-country-in-mmdb-format/

    private $userProfile;

    private $knownUserProfiles = [];

    private function browscapGetBrowser()
    {
        $logger = new \Monolog\Logger('name');
        $streamHandler = new \Monolog\Handler\StreamHandler('php://stderr', \Monolog\Level::Info);
        $logger->pushHandler($streamHandler);
        try {
            $redis = RedisTool::init();
        } catch (Exception $e) {
            $redis = false;
        }
        if (function_exists('apcu_fetch')) {
            App::uses('ApcuCacheTool', 'Tools');
            $cache = new ApcuCacheTool('misp:browscap');
        } else if (class_exists('\MatthiasMullie\Scrapbook\Adapters\Redis') && $redis) {
            $redis_cache = new \MatthiasMullie\Scrapbook\Adapters\Redis($redis);
            $cache = new \MatthiasMullie\Scrapbook\Psr16\SimpleCache($redis_cache);
        } else if (class_exists('\League\Flysystem\Local\LocalFilesystemAdapter') && class_exists('\MatthiasMullie\Scrapbook\Adapters\Flysystem')) {
            $adapter = new \League\Flysystem\Local\LocalFilesystemAdapter(APP . '/tmp/cache/browscap', null, LOCK_EX);
            $filesystem = new \League\Flysystem\Filesystem($adapter);
            $scrapbookadapter = new \MatthiasMullie\Scrapbook\Adapters\Flysystem($filesystem);
            $cache = new \MatthiasMullie\Scrapbook\Psr16\SimpleCache($scrapbookadapter);
        } else {
            $fileCache = new \Doctrine\Common\Cache\FilesystemCache(UserLoginProfile::BROWSER_CACHE_DIR);
            $cache = new \Roave\DoctrineSimpleCache\SimpleCacheAdapter($fileCache);
        }
        try {
            $bc = new \BrowscapPHP\Browscap($cache, $logger);
            return $bc->getBrowser();
        } catch (\BrowscapPHP\Exception $e) {
            $this->log("Browscap - building new cache from browscap.ini file.", LOG_INFO);
            $bcUpdater = new \BrowscapPHP\BrowscapUpdater($cache, $logger);
            $bcUpdater->convertString(FileAccessTool::readCompressedFile(UserLoginProfile::BROWSER_INI_FILE));
        }

        $bc = new \BrowscapPHP\Browscap($cache, $logger);
        return $bc->getBrowser();
    }

    /**
     * @param string $ip
     * @return string|null
     */
    public function countryByIp($ip)
    {
        if (class_exists('GeoIp2\Database\Reader')) {
            $geoDbReader = new GeoIp2\Database\Reader(UserLoginProfile::GEOIP_DB_FILE);
            try {
                $record = $geoDbReader->country($ip);
                return $record->country->isoCode;
            } catch (InvalidArgumentException $e) {
                $this->logException("Could not get country code for IP address", $e, LOG_NOTICE);
                return null;
            }
        }
        return null;
    }

    public function beforeSave($options = [])
    {
        $this->data['UserLoginProfile']['hash'] = $this->hash($this->data['UserLoginProfile']);
        return true;
    }

    public function hash(array $data)
    {
        unset($data['hash']);
        unset($data['created_at']);
        return md5(serialize($data));
    }

    /**
     * slow function - don't call it too often 
     * @return array
     */
    public function _getUserProfile()
    {
        if (!$this->userProfile) {
            // below uses https://github.com/browscap/browscap-php 
            if (class_exists('\BrowscapPHP\Browscap')) {
                $browser = $this->browscapGetBrowser();
            } else {
                // a primitive OS & browser extraction capability
                $ua = $_SERVER['HTTP_USER_AGENT'] ?? null;
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
            $country = $this->countryByIp($ip) ?? 'None';
            $this->userProfile = [
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
                'ip' => $ip,
                'accept_lang' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? null,
                'geoip' => $country,
                'ua_pattern' => $browser->browser_name_pattern,
                'ua_platform' => $browser->platform,
                'ua_browser' => $browser->browser
            ];
        }
        return $this->userProfile;
    }

    /**
     * @param array $logEntry
     * @return array|false|string[]
     * @throws JsonException
     */
    public function _fromLog(array $logEntry)
    {
        if (!$logEntry['change']) {
            return false;
        }

        $data = ["user_agent" => "", "ip" => "", "accept_lang" => "", "geoip" => "", "ua_pattern" => "", "ua_platform" => "", "ua_browser" => ""];
        $data = array_merge($data, JsonTool::decode($logEntry['change']));
        if ($data['user_agent'] === "") {
            return false;
        }
        $data['ip'] = $logEntry['ip'];
        $data['timestamp'] = $logEntry['created'];
        return $data;
    }

    public function _isSimilar($a, $b)
    {
        // if one is not initialized
        if (!$a || !$b) return false;
        // transition for old logs where UA was not known
        if (!$a['ua_browser']) 
            return false;
        // really similar session, from same browser, region, but different IP
        if ($a['ua_browser'] === $b['ua_browser'] &&
            $a['ua_platform'] === $b['ua_platform'] &&
            $a['accept_lang'] === $b['accept_lang'] &&
            $a['geoip'] === $b['geoip']) {
            return true;
        }
        // similar browser pattern, OS and region
        if ($a['ua_pattern'] === $b['ua_pattern'] &&
            $a['ua_platform'] === $b['ua_platform'] &&
            $a['accept_lang'] === $b['accept_lang'] &&
            $a['geoip'] === $b['geoip']) {
            return true;
        }
        return false;
    }

    public function _isIdentical(array $a, array $b)
    {
        if ($a['ip'] === $b['ip'] &&
            $a['ua_browser'] === $b['ua_browser'] &&
            $a['ua_platform'] === $b['ua_platform'] &&
            $a['accept_lang'] === $b['accept_lang'] &&
            $a['geoip'] === $b['geoip']) {
            return true;
        }
        return false;
    }

    /**
     * @param array $userProfileToCheck
     * @param int $userId
     * @return mixed|string
     */
    public function _getTrustStatus(array $userProfileToCheck, $userId = null)
    {
        if (!$userId) {
            $userId = AuthComponent::user('id');
        }
        // load Singleton / caching
        if (!isset($this->knownUserProfiles[$userId])) {
            $this->knownUserProfiles[$userId] = $this->find('all', [
                'conditions' => ['UserLoginProfile.user_id' => $userId],
                'recursive' => -1,
            ]);
        }
        // perform check on all entries, and stop when check OK
        foreach ($this->knownUserProfiles[$userId] as $knownUserProfile) {
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
    
    public function _isTrusted()
    {
        if (strpos($this->_getTrustStatus($this->_getUserProfile()), 'trusted') !== false) {
            return true;
        }
        return false;
    }

    public function _isSuspicious()
    {
        // previously marked loginuserprofile as malicious by the user
        if (str_contains($this->_getTrustStatus($this->_getUserProfile()), 'malicious')) {
            return __('A user reported a similar login profile as malicious.');
        }

        // same IP as previous malicious user
        $maliciousWithSameIP = $this->hasAny([
            'UserLoginProfile.ip' => $this->_getUserProfile()['ip'],
            'UserLoginProfile.status' => 'malicious'
        ]);
        if ($maliciousWithSameIP) {
            return __('The source IP was reported as as malicious by a user.');
        }
        // LATER - use other data to identify suspicious logins, such as:
        // - what with use-case where a user marks something as legitimate, but is marked by someone else as suspicious?
        // - warning lists
        // - ...
        return false;
    }

    public function emailNewLogin(array $user)
    {
        if (!Configure::read('MISP.disable_emailing')) {
            $user = $this->User->getUserById($user['id']); // fetch in database format
            $datetime = date('c'); // ISO 8601 date
            $body = new SendEmailTemplate('userloginprofile_newlogin');
            $body->set('userLoginProfile', $this->User->UserLoginProfile->_getUserProfile());
            $body->set('baseurl', Configure::read('MISP.baseurl'));
            $body->set('misp_org', Configure::read('MISP.org'));
            $body->set('date_time', $datetime);
            // Fetch user that contains also PGP or S/MIME keys for e-mail encryption
            $this->User->sendEmail($user, $body, false, "[" . Configure::read('MISP.org') . " MISP] New sign in.");
        }
    }

    public function emailReportMalicious(array $user, array $userLoginProfile)
    {
        // inform the org admin
        $date_time = $userLoginProfile['timestamp']; // LATER not ideal as timestamp is string without timezone info
        $body = new SendEmailTemplate('userloginprofile_report_malicious');
        $body->set('userLoginProfile', $userLoginProfile);
        $body->set('username', $user['User']['email']);
        $body->set('baseurl', Configure::read('MISP.baseurl'));
        $body->set('misp_org', Configure::read('MISP.org'));
        $body->set('date_time', $date_time);

        $orgAdmins = array_keys($this->User->getOrgAdminsForOrg($user['User']['org_id']));
        $admins = array_keys($this->User->getSiteAdmins());
        $allAdmins = array_unique(array_merge($orgAdmins, $admins));

        $subject = __("[%s MISP] Suspicious login reported.", Configure::read('MISP.org'));
        foreach ($allAdmins as $adminUserId) {
            $admin = $this->User->find('first', array(
                'recursive' => -1,
                'conditions' => ['User.id' => $adminUserId]
            ));
            $this->User->sendEmail($admin, $body, false, $subject);
        }
    }

    public function email_suspicious(array $user, $suspiciousness_reason)
    {
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
            $this->User->sendEmail($user, $body, false, "[" . Configure::read('MISP.org') . " MISP] Suspicious login with your account.");

            // inform the org admin
            $body = new SendEmailTemplate('userloginprofile_suspicious_orgadmin');
            $body->set('userLoginProfile', $this->_getUserProfile());
            $body->set('username', $user['User']['email']);
            $body->set('baseurl', Configure::read('MISP.baseurl'));
            $body->set('misp_org', Configure::read('MISP.org'));
            $body->set('date_time', $date_time);
            $body->set('suspiciousness_reason', $suspiciousness_reason);

            $orgAdmins = array_keys($this->User->getOrgAdminsForOrg($user['User']['org_id']));
            foreach ($orgAdmins as $orgAdminID) {
                $org_admin = $this->User->find('first', array(
                    'recursive' => -1,
                    'conditions' => ['User.id' => $orgAdminID]
                ));
                $this->User->sendEmail($org_admin, $body, false, "[" . Configure::read('MISP.org') . " MISP] Suspicious login detected.");
            }            
        }
    }
}
