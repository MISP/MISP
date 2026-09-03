<?php
App::uses('AppModel', 'Model');
App::uses('CidrTool', 'Tools');
App::uses('BlowfishConstantPasswordHasher', 'Controller/Component/Auth');

/**
 * @property User $User
 */
class AuthKey extends AppModel
{
    public $recursive = -1;

    /** @var string|null|false Memoised HMAC key, false when not yet loaded */
    private $hmacKey = false;

    public $actsAs = array(
        'AuditLog',
        'SysLogLogable.SysLogLogable' => array(
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'full'
        ),
        'Containable',
    );

    public $belongsTo = array(
        'User'
    );

    public $validate = [
        'uuid' => [
            'rule' => 'uuid',
            'message' => 'Please provide a valid RFC 4122 UUID',
        ],
        'user_id' => [
            'rule' => 'userExists',
            'message' => 'User doesn\'t exists',
        ],
        'read_only' => [
            'rule' => 'boolean',
        ],
    ];

    public function beforeValidate($options = array())
    {
        if (empty($this->data['AuthKey']['id'])) {
            if (empty($this->data['AuthKey']['uuid'])) {
                $this->data['AuthKey']['uuid'] = CakeText::uuid();
            }
            if (empty($this->data['AuthKey']['authkey'])) {
                $authkey = RandomTool::random_str(true, 40);
            } else {
                $authkey = $this->data['AuthKey']['authkey'];
            }
            $this->data['AuthKey']['authkey'] = $this->getHasher()->hash($authkey);
            $this->data['AuthKey']['authkey_start'] = substr($authkey, 0, 4);
            $this->data['AuthKey']['authkey_end'] = substr($authkey, -4);
            if ($this->hasField('authkey_hmac')) {
                $this->data['AuthKey']['authkey_hmac'] = $this->hmacAuthKey($authkey);
            }
            $this->data['AuthKey']['authkey_raw'] = $authkey;
        }

        $validAllowedIpFound = false;
        if (!empty($this->data['AuthKey']['allowed_ips'])) {
            $allowedIps = &$this->data['AuthKey']['allowed_ips'];
            if (is_string($allowedIps)) {
                $allowedIps = trim($allowedIps);
                if (empty($allowedIps)) {
                    $allowedIps = [];
                } else {
                    // Split by new line char or by comma
                    $allowedIps = preg_split('/([\n,])/', $allowedIps);
                    $allowedIps = array_map('trim', $allowedIps);
                }
            }
            if (!is_array($allowedIps)) {
                $this->invalidate('allowed_ips', 'Allowed IPs must be array');
            }

            foreach ($allowedIps as $cidr) {
                if (!CidrTool::validate($cidr)) {
                    $this->invalidate('allowed_ips', "$cidr is not valid IP range");
                } else {
                    $validAllowedIpFound = true;
                }
            }
        }
        if (!empty(Configure::read('Security.mandate_ip_allowlist_advanced_authkeys')) && $validAllowedIpFound === false){
            $this->invalidate('allowed_ips', "Setting an ip allowlist is mandatory on this instance.");
        }

        $creationTime = isset($this->data['AuthKey']['created']) ? $this->data['AuthKey']['created'] : time();
        $validity = Configure::read('Security.advanced_authkeys_validity');
        if (empty($this->data['AuthKey']['expiration'])) {
            $this->data['AuthKey']['expiration'] = $validity ? strtotime("+$validity days", $creationTime) : 0;
        } else {
            $expiration = is_numeric($this->data['AuthKey']['expiration']) ?
                (int)$this->data['AuthKey']['expiration'] :
                strtotime($this->data['AuthKey']['expiration']);

            if ($expiration === false) {
                $this->invalidate('expiration', __('Expiration must be in YYYY-MM-DD format.'));
            }
            if ($validity && $expiration > strtotime("+$validity days", $creationTime)) {
                $this->invalidate('expiration', __('Maximal key validity is %s days.', $validity));
            }
            $this->data['AuthKey']['expiration'] = $expiration;
        }

        return true;
    }

    public function afterFind($results, $primary = false)
    {
        foreach ($results as $key => $val) {
            if (isset($val['AuthKey']['allowed_ips'])) {
                try {
                    $results[$key]['AuthKey']['allowed_ips'] = JsonTool::decode($val['AuthKey']['allowed_ips']);
                } catch (JsonException $e) {
                    $results[$key]['AuthKey']['allowed_ips'] = array_map('trim', explode(',', $val['AuthKey']['allowed_ips']));
                }
            }
            if (isset($val['AuthKey']['unique_ips'])) {
                try {
                    $results[$key]['AuthKey']['unique_ips'] = JsonTool::decode($val['AuthKey']['unique_ips']);
                } catch (JsonException $e) {
                    $results[$key]['AuthKey']['unique_ips'] = array_map('trim', explode(',', $val['AuthKey']['unique_ips']));
                }
            } else {
                $results[$key]['AuthKey']['unique_ips'] = [];
            }

        }
        return $results;
    }

    public function beforeSave($options = array())
    {
        if (isset($this->data['AuthKey']['allowed_ips'])) {
            if (empty($this->data['AuthKey']['allowed_ips'])) {
                $this->data['AuthKey']['allowed_ips'] = null;
            } else {
                $this->data['AuthKey']['allowed_ips'] = JsonTool::encode($this->data['AuthKey']['allowed_ips']);
            }
        }
        if (isset($this->data['AuthKey']['unique_ips'])) {
            if (empty($this->data['AuthKey']['unique_ips'])) {
                $this->data['AuthKey']['unique_ips'] = null;
            } else {
                $this->data['AuthKey']['unique_ips'] = JsonTool::encode($this->data['AuthKey']['unique_ips']);
            }
        }
        return true;
    }

    /**
     * @param array $user
     * @param int $authKeyId
     * @return array
     */
    public function updateUserData(array $user, $authKeyId)
    {
        $authKey = $this->find('first', [
            'conditions' => ['id' => $authKeyId, 'user_id' => $user['id']],
            'fields' => ['id', 'expiration', 'allowed_ips', 'read_only'],
            'recursive' => -1,
        ]);
        if (empty($authKey)) {
            throw new RuntimeException("Auth key with ID $authKeyId doesn't exist anymore.");
        }
        return $this->setUserData($user, $authKey);
    }

    /**
     * @param string $authkey
     * @param bool $includeExpired
     * @return array|false
     * @throws Exception
     */
    public function getAuthUserByAuthKey($authkey, $includeExpired = false)
    {
        $expirationConditions = [];
        if (!$includeExpired) {
            $expirationConditions['OR'] = [
                'expiration >' => time(),
                'expiration' => 0
            ];
        }
        $fields = ['id', 'authkey', 'user_id', 'expiration', 'allowed_ips', 'read_only', 'unique_ips'];

        // Fast path: single indexed lookup on the keyed hash of the authkey. Rows created before this
        // column existed have it empty and fall through to the bcrypt path below, which fills it in.
        // hasField guards the window between deploying this code and running the db_version 160
        // migration - without it the lookup would reference a column that does not exist yet.
        $hmac = $this->hasField('authkey_hmac') ? $this->hmacAuthKey($authkey) : null;
        if ($hmac !== null) {
            $matchedAuthkey = $this->find('first', [
                'recursive' => -1,
                'fields' => $fields,
                'conditions' => array_merge(['authkey_hmac' => $hmac], $expirationConditions),
            ]);
            if (!empty($matchedAuthkey)) {
                return $this->authUserForAuthKey($matchedAuthkey);
            }
        }

        $conditions = array_merge([
            'authkey_start' => substr($authkey, 0, 4),
            'authkey_end' => substr($authkey, -4),
        ], $expirationConditions);

        $possibleAuthkeys = $this->find('all', [
            'recursive' => -1,
            'fields' => $fields,
            'conditions' => $conditions,
        ]);
        $passwordHasher = $this->getHasher();
        foreach ($possibleAuthkeys as $possibleAuthkey) {
            if ($passwordHasher->check($authkey, $possibleAuthkey['AuthKey']['authkey'])) {
                if ($hmac !== null) {
                    // Lazy migration - the plaintext key is in hand exactly here. updateAll to avoid
                    // firing the audit log behaviours for what is a pure lookup-index backfill.
                    $this->updateAll(
                        ['AuthKey.authkey_hmac' => $this->getDataSource()->value($hmac, 'string')],
                        ['AuthKey.id' => $possibleAuthkey['AuthKey']['id']]
                    );
                }
                return $this->authUserForAuthKey($possibleAuthkey);
            }
        }
        return false;
    }

    /**
     * Keyed hash of an authkey, used as an indexed lookup value. Uses the same secret as the
     * `Security.api_key_quick_lookup` cache in AppController.
     * @param string $authkey
     * @return string|null Null when no HMAC key is available, in which case the caller must fall back.
     */
    private function hmacAuthKey($authkey)
    {
        $hmacKey = $this->getHmacKey();
        if ($hmacKey === null) {
            return null;
        }
        return hash_hmac('sha512', $authkey, $hmacKey);
    }

    /**
     * @return string|null
     */
    private function getHmacKey()
    {
        if ($this->hmacKey !== false) {
            return $this->hmacKey;
        }
        $this->hmacKey = null;
        $hmacKeyFile = APP . 'Config/hmac_key.php';
        if (file_exists($hmacKeyFile)) {
            include $hmacKeyFile;
        } elseif (is_writable(APP . 'Config')) {
            App::uses('RandomTool', 'Tools');
            $hmac_key = RandomTool::random_str(true, 40);
            file_put_contents($hmacKeyFile, sprintf('<?php%s$hmac_key = \'%s\';', PHP_EOL, $hmac_key));
        }
        if (!empty($hmac_key) && is_string($hmac_key)) {
            $this->hmacKey = $hmac_key;
        }
        return $this->hmacKey;
    }

    /**
     * @param array $authkey Row as fetched by getAuthUserByAuthKey
     * @return array|false
     * @throws Exception
     */
    private function authUserForAuthKey(array $authkey)
    {
        $this->updateUniqueIp($authkey);
        $user = $this->User->getAuthUser($authkey['AuthKey']['user_id']);
        if ($user) {
            $user = $this->setUserData($user, $authkey);
        }
        return $user;
    }

    /**
     * @param array $authkey
     * @return void
     * @throws Exception
     */
    private function updateUniqueIp(array $authkey)
    {
        if (PHP_SAPI === 'cli' || Configure::read("MISP.disable_seen_ips_authkeys")) {
            return;
        }

        $remoteIp = $this->_remoteIp();
        if ($remoteIp === null || in_array($remoteIp, $authkey['AuthKey']['unique_ips'], true)) {
            return;
        }

        $authkey['AuthKey']['unique_ips'][] = $remoteIp;
        $this->save($authkey, ['fieldList' => ['unique_ips']]);
    }

    /**
     * @param array $user
     * @param array $authkey
     * @return array
     */
    private function setUserData(array $user, array $authkey)
    {
        $user['authkey_id'] = $authkey['AuthKey']['id'];
        $user['authkey_expiration'] = $authkey['AuthKey']['expiration'];
        $user['allowed_ips'] = $authkey['AuthKey']['allowed_ips'];
        $user['authkey_read_only'] = (bool)$authkey['AuthKey']['read_only'];

        if ($authkey['AuthKey']['read_only']) {
            // Disable all permissions, keep just `perm_auth` and `perm_audit` unchanged
            foreach ($user['Role'] as $key => &$value) {
                if (str_starts_with($key, 'perm_') && $key !== 'perm_auth' && $key !== 'perm_audit') {
                    $value = 0;
                }
            }
        }
        return $user;
    }


    /**
     * @param int $userId
     * @param int|null $keyId
     * @param string|null $authKey
     * @return false|string
     * @throws Exception
     */
    public function resetAuthKey($userId, $keyId = null, $authKey = null)
    {
        $time = time();

        if ($keyId) {
            $currentAuthkey = $this->find('first', [
                'recursive' => -1,
                'conditions' => [
                    'id' => $keyId,
                    'user_id' => $userId,
                ],
            ]);
            if (empty($currentAuthkey)) {
                throw new RuntimeException("Key with ID $keyId for user with ID $userId not found.");
            }
            $currentAuthkey['AuthKey']['expiration'] = $time;
            if (!$this->save($currentAuthkey)) {
                throw new RuntimeException("Key with ID $keyId could not be saved.");
            }
            $comment = __("Created by resetting auth key %s\n%s", $keyId, $currentAuthkey['AuthKey']['comment']);
            $allowedIps = isset($currentAuthkey['AuthKey']['allowed_ips']) ? $currentAuthkey['AuthKey']['allowed_ips'] : [];
            return $this->createnewkey($userId, $authKey, $comment, $allowedIps);
        } else {
            $existingAuthkeys = $this->find('all', [
                'recursive' => -1,
                'conditions' => [
                    'OR' => [
                        'expiration >' => $time,
                        'expiration' => 0
                    ],
                    'user_id' => $userId
                ]
            ]);
            foreach ($existingAuthkeys as $key) {
                $key['AuthKey']['expiration'] = $time;
                $this->save($key);
            }
            return $this->createnewkey($userId, $authKey);
        }
    }

    /**
     * @param int $userId
     * @param string|null $authKey
     * @param string $comment
     * @param array $allowedIps
     * @return false|string
     * @throws Exception
     */
    public function createnewkey($userId, $authKey = null, $comment = '', array $allowedIps = [])
    {
        if(empty($authKey)) {
            $authKey = RandomTool::random_str(true, 40);
        }
        $newKey = [
            'authkey' => $authKey,
            'user_id' => $userId,
            'comment' => $comment,
            'allowed_ips' => empty($allowedIps) ? null : $allowedIps,
        ];
        $this->create();
        if ($this->save($newKey)) {
            return $newKey['authkey'];
        } else {
            return false;
        }
    }

    /**
     * @param int $id
     * @return array
     * @throws Exception
     */
    public function getKeyUsage($id)
    {
        $redis = RedisTool::init();
        $data = $redis->hGetAll("misp:authkey_usage:$id");

        $output = [];
        $uniqueIps = [];
        foreach ($data as $key => $count) {
            list($date, $ip) = explode(':', $key);
            $uniqueIps[$ip] = true;
            if (isset($output[$date])) {
                $output[$date] += $count;
            } else {
                $output[$date] = $count;
            }
        }
        // Data from redis are not sorted
        ksort($output);

        $lastUsage = $redis->get("misp:authkey_last_usage:$id");
        $lastUsage = $lastUsage === false ? null : (int)$lastUsage;

        return [$output, $lastUsage, count($uniqueIps)];
    }

    /**
     * @param array $ids
     * @return array<DateTime|null>
     * @throws Exception
     */
    public function getLastUsageForKeys(array $ids)
    {
        $redis = RedisTool::init();
        $keys = array_map(function($id) {
            return "misp:authkey_last_usage:$id";
        }, $ids);
        $lastUsages = $redis->mget($keys);
        $output = [];
        foreach (array_values($ids) as $i => $id) {
            $output[$id] = $lastUsages[$i] === false ? null : (int)$lastUsages[$i];
        }
        return $output;
    }

    /**
     * When key is modified, update `date_modified` for user that was assigned to that key, so session data
     * will be reloaded.
     * @see AppController::_refreshAuth
     */
    public function afterSave($created, $options = array())
    {
        parent::afterSave($created, $options);
        $userId = $this->data['AuthKey']['user_id'];
        $this->User->updateAll(['date_modified' => time()], ['User.id' => $userId]);
    }

    /**
     * When key is deleted, update after `date_modified` for user that was assigned to that key, so session data
     * will be reloaded and canceled.
     * @see AppController::_refreshAuth
     */
    public function afterDelete()
    {
        parent::afterDelete();
        $userId = $this->data['AuthKey']['user_id'];
        $this->User->updateAll(['date_modified' => time()], ['User.id' => $userId]);
    }

    /**
     * Validation
     * @param array $check
     * @return bool
     */
    public function userExists(array $check)
    {
        return $this->User->hasAny(['id' => $check['user_id']]);
    }

    /**
     * Check if given user has valid advanced auth key.
     * @param int $userId
     * @return bool
     */
    public function userHasAuthKey($userId)
    {
        return $this->hasAny([
            'user_id' => $userId,
            'OR' => [
                'expiration >' => time(),
                'expiration' => 0
            ],
        ]);
    }

    /**
     * @return AbstractPasswordHasher
     */
    private function getHasher()
    {
        return new BlowfishConstantPasswordHasher();
    }

    public function canCreateAuthKeyForUser($currentUser, $user_id)
    {
        if (!empty($currentUser['Role']['perm_site_admin'])) {
            return true;
        }
        if (!empty($currentUser['Role']['perm_admin'])) {
            // org admin only for non-admin users and themselves
            $user = $this->User->find('first', [
                'recursive' => -1,
                'conditions' => [
                    'User.id' => $user_id,
                    'User.disabled' => false,
                    'User.org_id' => $currentUser['org_id']
                ],
                'fields' => ['User.id', 'User.org_id', 'User.disabled'],
                'contain' => [
                    'Role' => [
                        'fields' => [
                            'Role.perm_site_admin', 'Role.perm_admin', 'Role.perm_auth'
                        ]
                    ]
                ]
            ]);
            // Make sure that we can't create keys for disabled users
            if (empty($user)) {
                return false;
            }
            if ($user['Role']['perm_site_admin'] || 
                ($user['Role']['perm_admin'] && $user['User']['id'] !== $currentUser['id']) ||
                !$user['Role']['perm_auth']) {
                // no create/edit for site_admin or other org admin
                return false;
            } else {
                // ok for themselves or users
                return true;
            }
        } else {
            // user for themselves
            return (int)$user_id === (int)$currentUser['id'];
        }
    }

    public function canEditAuthKey($currentUser, $key_id)
    {
        $user_id = $this->find('column', [
            'fields' => ['AuthKey.user_id'],
            'conditions' => [
                'AuthKey.id' => $key_id
            ]]);
        if (!empty($user_id)) {
            $user_id = $user_id[0];
        }
        return $this->canCreateAuthKeyForUser($currentUser, $user_id);
    }
}
