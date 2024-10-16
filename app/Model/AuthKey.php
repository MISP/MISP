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
                $results[$key]['AuthKey']['allowed_ips'] = JsonTool::decode($val['AuthKey']['allowed_ips']);
            }
            if (isset($val['AuthKey']['unique_ips'])) {
                $results[$key]['AuthKey']['unique_ips'] = JsonTool::decode($val['AuthKey']['unique_ips']);
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
        $start = substr($authkey, 0, 4);
        $end = substr($authkey, -4);

        $conditions = [
            'authkey_start' => $start,
            'authkey_end' => $end,
        ];

        if (!$includeExpired) {
            $conditions['OR'] = [
                'expiration >' => time(),
                'expiration' => 0
            ];
        }

        $possibleAuthkeys = $this->find('all', [
            'recursive' => -1,
            'fields' => ['id', 'authkey', 'user_id', 'expiration', 'allowed_ips', 'read_only', 'unique_ips'],
            'conditions' => $conditions,
        ]);
        $passwordHasher = $this->getHasher();
        foreach ($possibleAuthkeys as $possibleAuthkey) {
            if ($passwordHasher->check($authkey, $possibleAuthkey['AuthKey']['authkey'])) {
                $this->updateUniqueIp($possibleAuthkey);
                $user = $this->User->getAuthUser($possibleAuthkey['AuthKey']['user_id']);
                if ($user) {
                    $user = $this->setUserData($user, $possibleAuthkey);
                }
                return $user;
            }
        }
        return false;
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
     * will be realoaded and canceled.
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
}
