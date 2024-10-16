<?php
App::uses('SyncTool', 'Tools');
App::uses('ProcessTool', 'Tools');

class SecurityAudit
{
    const STRONG_PASSWORD_LENGTH = 17;

    /**
     * @param Server $server
     * @param bool $systemOnly Run only system checks
     * @return array
     */
    public function run(Server $server, $systemOnly = false)
    {
        $output = [];

        foreach (['config.php', 'config.php.bk', 'database.php', 'email.php'] as $configFile) {
            if (!file_exists(CONFIG . $configFile)) {
                continue;
            }

            $perms = fileperms(CONFIG . $configFile);
            if ($perms & 0x0004) {
                $output['File permissions'][] = ['error', __('%s config file is readable for any user.', $configFile)];
            }
        }

        $redisPassword = Configure::read('MISP.redis_password');
        if (empty($redisPassword)) {
            $output['Redis'][] = ['error', __('Redis password not set.')];
        } else if (strlen($redisPassword) < 32) { // for Redis, password should be stronger
            $output['Redis'][] = [
                'warning',
                __('Redis password is too short, should be at least 32 chars long.'),
                'https://redis.io/topics/security#authentication-feature',
            ];
        }

        $databasePassword = ConnectionManager::getDataSource('default')->config['password'];
        if (empty($databasePassword)) {
            $output['Database'][] = ['error', __('Database password not set.')];
        } else if (strlen($databasePassword) < self::STRONG_PASSWORD_LENGTH) {
            $output['Database'][] = ['warning', __('Database password is too short, should be at least %s chars long.', self::STRONG_PASSWORD_LENGTH)];
        }

        if (!Configure::read('Security.encryption_key')) {
            $output['Database'][] = ['warning', __('Sensitive information like keys to remote server are stored in database unencrypted. Set `Security.encryption_key` to encrypt these values.')];
        }

        $passwordPolicyLength = Configure::read('Security.password_policy_length') ?: $server->serverSettings['Security']['password_policy_length']['value'];
        if ($passwordPolicyLength < 8) {
            $output['Password'][] = ['error', __('Minimum password length is set to %s, it is highly advised to increase it.', $passwordPolicyLength)];
        } elseif ($passwordPolicyLength < 12) {
            $output['Password'][] = ['warning', __('Minimum password length is set to %s, consider raising to at least 12 characters.', $passwordPolicyLength)];
        }

        if (empty(Configure::read('Security.require_password_confirmation'))) {
            $output['Password'][] = [
                'warning',
                __('Password confirmation is not enabled. %s', $server->serverSettings['Security']['require_password_confirmation']['description']),
            ];
        }
        if (!empty(Configure::read('Security.auth')) && !Configure::read('Security.auth_enforced')) {
            $output['Login'][] = [
                'hint',
                __('External authentication is enabled, but local accounts will still work. You can disable the ability to log in via local accounts by setting `Security.auth_enforced` to `true`.'),
            ];
        }

        if (!Configure::read('Security.alert_on_suspicious_logins')) {
            $output['Login'][] = [
                'warning',
                __('Warning about suspicious logins is disabled. You can enable alert by setting `Security.alert_on_suspicious_logins` to `true`.'),
            ];
        }

        if (empty(Configure::read('Security.disable_browser_cache'))) {
            $output['Browser'][] = [
                'warning',
                __('Browser cache is enabled. An attacker could obtain sensitive data from the user cache. You can disable the cache by setting `Security.disable_browser_cache` to `true`.'),
            ];
        }
        if (empty(Configure::read('Security.check_sec_fetch_site_header'))) {
            $output['Browser'][] = [
                'warning',
                __('The MISP server is not checking `Sec-Fetch` HTTP headers. This is a protection mechanism against CSRF used by modern browsers. You can enable this check by setting `Security.check_sec_fetch_site_header` to `true`.'),
            ];
        }
        if (empty(Configure::read('Security.csp_enforce'))) {
            $output['Browser'][] = [
                'warning',
                __('Content security policies (CSP) are not enforced. Consider enabling them by setting `Security.csp_enforce` to `true`.'),
                'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
            ];
        }
        if (!env('HTTPS') && str_starts_with(Configure::read('MISP.baseurl'), 'https://')) {
            $output['Browser'][] = [
                'error',
                __('MISP base URL is set to https://, but MISP thinks that the connection is insecure. This usually happens when a server is running behind a reverse proxy. By setting `Security.force_https` to `true`, session cookies will be set as Secure and CSP headers will upgrade insecure requests.'),
            ];
        }
        $sessionConfig = Configure::read('Session');
        if (isset($sessionConfig['ini']['session.cookie_secure']) && !$sessionConfig['ini']['session.cookie_secure']) {
            $output['Browser'][] = ['error', __('Setting session cookies as not secure is never a good idea.')];
        }

        if (empty(Configure::read('Security.advanced_authkeys'))) {
            $output['Auth Key'][] = ['warning', __('Consider enabling Advanced Auth Keys, they provide increased security by only storing the API key hashes.')];
        }
        if (Configure::read('Security.allow_unsafe_apikey_named_param')) {
            $output['Auth Key'][] = ['error', __('It is possible to pass API keys via the URL, meaning that the keys can be logged by proxies.')];
        }
        if (empty(Configure::read('Security.do_not_log_authkeys'))) {
            $output['Auth Key'][] = ['warning', __('Auth Key logging is not disabled. Auth Keys in cleartext can be visible in the Audit log.')];
        }

        $salt = Configure::read('Security.salt');
        if (empty($salt)) {
            $output['Security salt'][] = ['error', __('Salt is not set.')];
        } else if (strlen($salt) < 32) {
            $output['Security salt'][] = ['warning', __('Salt is too short, should contain at least 32 characters.')];
        } else if ($salt === "Rooraenietu8Eeyo<Qu2eeNfterd-dd+") {
            $output['Security salt'][] = ['error', __('Salt is set to the default value.')];
        }

        if (empty(Configure::read('MISP.log_client_ip'))) {
            $output['Logging'][] = ['warning', __('Logging client IP in audit log is disabled. Logging IP address can help to solve potential security breaches.')];
        }
        if (empty(Configure::read('MISP.log_user_ips'))) {
            $output['Logging'][] = ['warning', __('Logging client IP in Redis is disabled. Logging IP addresses can help investigate potential security breaches.')];
        }
        if (Configure::read('MISP.log_user_ips') && Configure::read('Security.advanced_authkeys') && empty(Configure::read('MISP.log_user_ips_authkeys'))) {
            $output['Logging'][] = [
                'hint',
                __('You can enable the logging of advanced authkeys by setting `MISP.log_user_ips_authkeys` to `true`.'),
            ];
        }
        if (empty(Configure::read('Security.username_in_response_header'))) {
            $output['Logging'][] = [
                'hint',
                __('Passing user information to response headers is disabled. This can be useful for logging user info at the reverse proxy level. You can enable it by setting `Security.username_in_response_header` to `true`.'),
            ];
        }
        if (!Configure::read('MISP.log_new_audit')) {
            $output['Logging'][] = [
                'hint',
                __('New audit log stores more information, like used authkey ID or request ID that can help when analysing or correlating audit logs. Set `MISP.log_new_audit` to `true` to enable.'),
            ];
        }

        if (empty(Configure::read('MISP.attachment_scan_module'))) {
            $output['Attachment scanning'][] = ['hint', __('No module for scanning attachments for viruses is currently defined.')];
        }

        if (Configure::read('debug')) {
            $output['Debug'][] = ['error', __('Debug mode is enabled for all users.')];
        }

        if (Configure::read('Proxy.host')) {
            $proxyPassword = Configure::read('Proxy.password');
            if (empty($proxyPassword)) {
                $output['Proxy'][] = ['error', __('Proxy password is empty.')];
            } else if (strlen($proxyPassword) < self::STRONG_PASSWORD_LENGTH) {
                $output['Proxy'][] = ['warning', __('Proxy password is too short, should be at least %s chars long.', self::STRONG_PASSWORD_LENGTH)];
            }
        }

        if (Configure::read('Security.rest_client_enable_arbitrary_urls')) {
            $output['REST client'][] = [
                'hint',
                __('Users can use the REST client to query any remote URL. This is generally not a good idea if your instance is public.')
            ];
        }

        if (Configure::read('Plugins.ZeroMQ_enable')) {
            $zeroMqPassword = Configure::read('Plugins.ZeroMQ_password');
            if (empty($zeroMqPassword)) {
                $output['ZeroMQ'][] = ['error', __('ZeroMQ password is not set.')];
            } else if (strlen($zeroMqPassword) < self::STRONG_PASSWORD_LENGTH) {
                $output['ZeroMQ'][] = ['warning', __('ZeroMQ password is too short, should be at least %s chars long.', self::STRONG_PASSWORD_LENGTH)];
            }

            $redisPassword = Configure::read('Plugins.ZeroMQ_redis_password');
            if (empty($redisPassword)) {
                $output['ZeroMQ'][] = ['error', __('Redis password is not set.')];
            } else if (strlen($redisPassword) < 32) { // for Redis, password should be stronger
                $output['ZeroMQ'][] = [
                    'warning',
                    __('Redis password is too short, should be at least 32 chars long.'),
                    'https://redis.io/topics/security#authentication-feature',
                ];
            }
        }

        $this->email($output);

        /*
         * These settings are dangerous and break both the transparency and potential introduce sync issues
        if (!Configure::read('Security.hide_organisation_index_from_users')) {
            $output['MISP'][] = [
                'hint',
                __('Any user can see list of all organisations. You can disable that by setting `Security.hide_organisation_index_from_users` to `true`. %s', $server->serverSettings['Security']['hide_organisation_index_from_users']['description']),
            ];
        }
        if (!Configure::read('Security.hide_organisations_in_sharing_groups')) {
            $output['MISP'][] = [
                'hint',
                __('Any user can see list of all organisations in sharing group that user can see. You can disable that by setting `Security.hide_organisations_in_sharing_groups` to `true`. %s', $server->serverSettings['Security']['hide_organisations_in_sharing_groups']['description']),
            ];
        }
        */

        if (!$systemOnly) {
            $this->feeds($output);
            $this->remoteServers($output);
        }

        try {
            $cakeVersion = $this->getCakeVersion();
            if (version_compare($cakeVersion, '2.10.21', '<')) {
                $output['Dependencies'][] = ['warning', __('CakePHP version %s is outdated.', $cakeVersion)];
            }
        } catch (RuntimeException $e) {}

        if (version_compare(PHP_VERSION, '7.4.0', '<')) {
            $output['PHP'][] = [
                'warning',
                __('PHP version %s is not supported anymore. It can be still supported by your distribution.', PHP_VERSION),
                'https://www.php.net/supported-versions.php'
            ];
        }

        if (ini_get('expose_php')) {
            $output['PHP'][] = [
                'hint',
                __('PHP `expose_php` setting is enabled. That means that PHP version will be send in `X-Powered-By` header. This can help attackers.'),
            ];
        }

        if (extension_loaded('xdebug')) {
            $output['PHP'][] = [
                'error',
                __('The xdebug extension can reveal code and data to an attacker.'),
            ];
        }

        if (ini_get('session.use_strict_mode') != 1) {
            $output['PHP'][] = [
                'warning',
                __('Session strict mode is disabled.'),
                'https://www.php.net/manual/en/session.configuration.php#ini.session.use-strict-mode',
            ];
        }
        if (empty(ini_get('session.cookie_httponly'))) {
            $output['PHP'][] = ['error', __('Session cookie is not set as HTTP only. Session cookie can be accessed from JavaScript.')];
        }
        if (!in_array(strtolower(ini_get('session.cookie_samesite')), ['strict', 'lax'])) {
            $output['PHP'][] = [
                'error',
                __('Session cookie SameSite parameter is not defined or set to None.'),
                'https://developer.mozilla.org/en-us/docs/Web/HTTP/Headers/Set-Cookie/SameSite',
            ];
        }
        $sidLength = ini_get('session.sid_length');
        if ($sidLength !== false && $sidLength < 32) {
            $output['PHP'][] = [
                'warning',
                __('Session ID length is set to %s, at least 32 is recommended.', $sidLength),
                'https://www.php.net/manual/en/session.configuration.php#ini.session.sid-length',
            ];
        }
        $sidBits = ini_get('session.sid_bits_per_character');
        if ($sidBits !== false && $sidBits <= 4) {
            $output['PHP'][] = [
                'warning',
                __('Session ID bit per character is set to %s, at least 5 is recommended.', $sidBits),
                'https://www.php.net/manual/en/session.configuration.php#ini.session.sid-bits-per-character',
            ];
        }

        $this->system($output);

        return $output;
    }

    /**
     * @return array|string[][]
     * @throws Exception
     */
    public function tlsConnections()
    {
        $urls = [
            'TLSv1.0' => ['url' => 'https://tls-v1-0.badssl.com:1010/'],
            'TLSv1.1' => ['url' => 'https://tls-v1-1.badssl.com:1011/'],
            'TLSv1.2' => ['url' => 'https://tls-v1-2.badssl.com:1012/', 'expected' => true],
            'TLSv1.3' => [
                'url' => 'https://check-tls.akamai.io/v1/tlsinfo.json',
                'expected' => true,
                'process' => function (HttpSocketResponseExtended $response) {
                    return $response->json()['tls_version'] === 'tls1.3';
                }
            ],
            'DH480' => ['url' => 'https://dh480.badssl.com/', 'expected' => false],
            'DH512' => ['url' => 'https://dh512.badssl.com/', 'expected' => false],
            'DH1024' => ['url' => 'https://dh1024.badssl.com/', 'expected' => false],
            'DH2048' => ['url' => 'https://dh2048.badssl.com/'],
            'RC4-MD5' => ['url' => 'https://rc4-md5.badssl.com/', 'expected' => false],
            'RC4' => ['url' => 'https://rc4.badssl.com/', 'expected' => false],
            '3DES' => ['url' => 'https://3des.badssl.com/', 'expected' => false],
            'NULL' => ['url' => 'https://null.badssl.com/', 'expected' => false],
            'SHA1 2016' => ['url' => 'https://sha1-2016.badssl.com/', 'expected' => false],
            'SHA1 2017' => ['url' => 'https://sha1-2017.badssl.com/', 'expected' => false],
            'SHA1 intermediate' => ['url' => 'https://sha1-intermediate.badssl.com/', 'expected' => false],
            'Invalid expected sct' => ['url' => 'https://invalid-expected-sct.badssl.com/', 'expected' => false],
            'Expired' => ['url' => 'https://expired.badssl.com/', 'expected' => false],
            'Wrong host' => ['url' => 'https://wrong.host.badssl.com/', 'expect' => false],
            'Self-signed' => ['url' => 'https://self-signed.badssl.com/', 'expected' => false],
            'Untrusted-root' => ['url' => 'https://untrusted-root.badssl.com/', 'expected' => false],
            'Revoked' => ['url' => 'https://revoked.badssl.com/'],
            'Pinning test' => ['url' => 'https://pinning-test.badssl.com/'],
            'Bad DNSSEC' => ['url' => 'http://rhybar.cz', 'expected' => false],
        ];
        $syncTool = new SyncTool();
        foreach ($urls as &$details) {
            $httpSocket = $syncTool->createHttpSocket();
            try {
                $response = $httpSocket->get($details['url']);
                if (isset($details['process'])) {
                    $details['success'] = $details['process']($response);
                } else {
                    $details['success'] = true;
                }
            } catch (Exception $e) {
                $details['success'] = false;
                $details['exception'] = $e;
            }
        }
        return $urls;
    }

    private function feeds(array &$output)
    {
        /** @var Feed $feed */
        $feed = ClassRegistry::init('Feed');
        $enabledFeeds = $feed->find('list', [
            'conditions' => [
                'input_source' => 'network',
                'OR' => [
                    'enabled' => true,
                    'caching_enabled' => true,
                ]
            ],
            'fields' => ['name', 'url'],
        ]);
        foreach ($enabledFeeds as $feedName => $feedUrl) {
            if (str_starts_with($feedUrl, 'http://')) {
                $output['Feeds'][] = ['warning', __('Feed %s uses insecure (HTTP) connection.', $feedName)];
            }
        }
    }

    private function remoteServers(array &$output)
    {
        /** @var Server $server */
        $server = ClassRegistry::init('Server');
        $enabledServers = $server->find('all', [
            'conditions' => ['OR' => [
                'push' => true,
                'pull' => true,
                'push_sightings' => true,
                'caching_enabled' => true,
            ]],
            'fields' => ['id', 'name', 'url', 'self_signed', 'cert_file', 'client_cert_file'],
        ]);
        foreach ($enabledServers as $enabledServer) {
            if (str_starts_with($enabledServer['Server']['url'], 'http://')) {
                $output['Remote servers'][] = ['warning', __('Server %s uses insecure (HTTP) connection.', $enabledServer['Server']['name'])];
            } else if ($enabledServer['Server']['self_signed']) {
                $output['Remote servers'][] = ['warning', __('Server %s uses self signed certificate. This is considered insecure.', $enabledServer['Server']['name'])];
            }

            try {
                $parsed = SyncTool::getServerClientCertificateInfo($enabledServer);
                if (isset($parsed['public_key_size_ok']) && !$parsed['public_key_size_ok']) {
                    $algo = $parsed['public_key_type'] . " " . $parsed['public_key_size'];
                    $output['Remote servers'][] = ['warning', __('Server %s uses weak client certificate (%s).', $enabledServer['Server']['name'], $algo)];
                }
            } catch (Exception $e) {}

            try {
                $parsed = SyncTool::getServerCaCertificateInfo($enabledServer);
                if (isset($parsed['public_key_size_ok']) && !$parsed['public_key_size_ok']) {
                    $algo = $parsed['public_key_type'] . " " . $parsed['public_key_size'];
                    $output['Remote servers'][] = ['warning', __('Server %s uses weak CA certificate (%s).', $enabledServer['Server']['name'], $algo)];
                }
            } catch (Exception $e) {}
        }
    }

    private function email(array &$output)
    {
        $canSignPgp = Configure::read('GnuPG.sign');
        $canSignSmime = Configure::read('SMIME.enabled') &&
            !empty(Configure::read('SMIME.cert_public_sign')) &&
            !empty(Configure::read('SMIME.key_sign'));

        if (!$canSignPgp && !$canSignSmime) {
            $output['Email'][] = [
                'warning',
                __('Email signing (PGP or S/MIME) is not enabled.')
            ];
        }

        if ($canSignPgp) {
            $gpgKeyPassword = Configure::read('GnuPG.password');
            if (empty($gpgKeyPassword)) {
                $output['Email'][] = ['error', __('PGP private key password is empty.')];
            } else if (strlen($gpgKeyPassword) < self::STRONG_PASSWORD_LENGTH) {
                $output['Email'][] = ['warning', __('PGP private key password is too short, should be at least %s chars long.', self::STRONG_PASSWORD_LENGTH)];
            }
        }

        if (!Configure::read('GnuPG.bodyonlyencrypted')) {
            $output['Email'][] = [
                'hint',
                __('Full email body with all event information will be sent, even without encryption.')
            ];
        }

        if ($canSignPgp && !Configure::read('GnuPG.obscure_subject')) {
            $output['Email'][] = [
                'hint',
                __('Even for encrypted emails, the email subject will be sent unencrypted. You can change that behaviour by setting `GnuPG.obscure_subject` to `true`.'),
            ];
        }

        App::uses('CakeEmail', 'Network/Email');
        $email = new CakeEmail();
        $emailConfig = $email->config();
        if ($emailConfig['transport'] === 'Smtp' && $emailConfig['port'] == 25 && empty($emailConfig['tls'])) {
            $output['Email'][] = [
                'warning',
                __('STARTTLS is not enabled.'),
                'https://en.wikipedia.org/wiki/Opportunistic_TLS',
            ];
        }
    }

    private function system(array &$output)
    {
        $kernelBuildTime = $this->getKernelBuild();
        if ($kernelBuildTime) {
            $diff = (new DateTime())->diff($kernelBuildTime);
            $diffDays = $diff->format('a');
            if ($diffDays > 300) {
                $output['System'][] = [
                    'warning',
                    __('Kernel build time was %s days ago. This usually means that the system kernel is not updated.', $diffDays),
                ];
            }
        }

        $uptime = $this->getUptime();
        if ($uptime) {
            $uptimeInDays = intdiv((int)$uptime, 3600 * 24);
            if ($uptimeInDays > 100) {
                $output['System'][] = [
                    'warning',
                    __('Uptime of this server is %s days. This usually means that the system kernel is outdated.', $uptimeInDays),
                ];
            }
        }

        // Python version
        try {
            $pythonVersion = ProcessTool::execute([ProcessTool::pythonBin(), '-V']);
            $parts = explode(' ', $pythonVersion);
            if ($parts[0] !== 'Python') {
                throw new Exception("Invalid python version response: $pythonVersion");
            }

            if (version_compare($parts[1], '3.6', '<')) {
                $output['System'][] = [
                    'warning',
                    __('You are using Python %s. This version is not supported anymore, but it can be still supported by your distribution.', $parts[1]),
                    'https://endoflife.date/python',
                ];
            } else if (version_compare($parts[1], '3.7', '<')) {
                $output['System'][] = [
                    'hint',
                    __('You are using Python %s. This version will not be supported beyond 23 Dec 2021, but it can be that it is still supported by your distribution.', $parts[1]),
                    'https://endoflife.date/python',
                ];
            }
        } catch (Exception $e) {
        }

        $linuxVersion = $this->getLinuxVersion();
        if ($linuxVersion) {
            list($name, $version) = $linuxVersion;
            if ($name === 'Ubuntu') {
                if (in_array($version, ['14.04', '16.04', '19.10', '20.10', '21.04', '21.10', '22.10', '23.04', '23.10'], true)) {
                    $output['System'][] = [
                        'warning',
                        __('You are using Ubuntu %s. This version doesn\'t receive security support anymore.', $version),
                        'https://endoflife.date/ubuntu',
                    ];
                }
            } else if ($name === 'CentOS Linux' && $version == 8) {
                $output['System'][] = [
                    'warning',
                    __('You are using CentOS 8. This version doesn\'t receive security support anymore. Please migrate to CentOS 8 Stream.'),
                    'https://endoflife.date/centos',
                ];
            }
        }
    }

    /**
     * @return DateTime|false
     */
    private function getKernelBuild()
    {
        if (PHP_OS !== 'Linux') {
            return false;
        }
        $version = php_uname('v');
        if (!str_starts_with($version, '#1 SMP ')) {
            return false;
        }
        try {
            return new DateTime('@' . substr($version, 7));
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * @return array|false
     */
    private function getLinuxVersion()
    {
        if (PHP_OS !== 'Linux') {
            return false;
        }
        if (!is_readable('/etc/os-release')) {
            return false;
        }
        $content = file_get_contents('/etc/os-release');
        if ($content === false) {
            return false;
        }
        $parsed = parse_ini_string($content);
        if ($parsed === false) {
            return false;
        }
        if (!isset($parsed['NAME']) || !isset($parsed['VERSION_ID'])) {
            return false;
        }
        return [$parsed['NAME'], $parsed['VERSION_ID']];
    }

    /**
     * Returns how long the system has been on since its last restart
     * @return false|float
     */
    private function getUptime()
    {
        if (PHP_OS !== 'Linux') {
            return false;
        }
        if (!is_readable('/proc/uptime')) {
            return false;
        }
        $content = file_get_contents('/proc/uptime');
        if ($content === false) {
            return false;
        }
        return (float)explode(" ", $content)[0];
    }

    /**
     * @return string
     */
    private function getCakeVersion()
    {
        $filePath = CAKE_CORE_INCLUDE_PATH . '/Cake/VERSION.txt';
        $version = file_get_contents($filePath);
        if (!$version) {
            throw new RuntimeException("Could not open CakePHP version file '$filePath'.");
        }
        foreach (explode("\n", $version) as $line) {
            if ($line[0] === '/') {
                continue;
            }
            return trim($line);
        }
        throw new RuntimeException("CakePHP version not found in file '$filePath'.");
    }
}
