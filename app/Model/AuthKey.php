<?php
App::uses('AppModel', 'Model');
App::uses('RandomTool', 'Tools');
App::uses('CidrTool', 'Tools');

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
                'change' => 'full'),
        'Containable',
    );

    public $belongsTo = array(
        'User'
    );

    public $authkey_raw = false;

    // massage the data before we send it off for validation before saving anything
    public function beforeValidate($options = array())
    {
        if (empty($this->data['AuthKey']['id'])) {
            if (empty($this->data['AuthKey']['uuid'])) {
                $this->data['AuthKey']['uuid'] = CakeText::uuid();
            }
            if (empty($this->data['AuthKey']['authkey'])) {
                $authkey = (new RandomTool())->random_str(true, 40);
            } else {
                $authkey = $this->data['AuthKey']['authkey'];
            }
            $passwordHasher = $this->getHasher();
            $this->data['AuthKey']['authkey'] = $passwordHasher->hash($authkey);
            $this->data['AuthKey']['authkey_start'] = substr($authkey, 0, 4);
            $this->data['AuthKey']['authkey_end'] = substr($authkey, -4);
            $this->data['AuthKey']['authkey_raw'] = $authkey;
            $this->authkey_raw = $authkey;
        }

        if (!empty($this->data['AuthKey']['allowed_ips'])) {
            if (is_string($this->data['AuthKey']['allowed_ips'])) {
                $this->data['AuthKey']['allowed_ips'] = trim($this->data['AuthKey']['allowed_ips']);
                if (empty($this->data['AuthKey']['allowed_ips'])) {
                    $this->data['AuthKey']['allowed_ips'] = [];
                } else {
                    $this->data['AuthKey']['allowed_ips'] = explode("\n", $this->data['AuthKey']['allowed_ips']);
                    $this->data['AuthKey']['allowed_ips'] = array_map('trim', $this->data['AuthKey']['allowed_ips']);
                }
            }
            if (!is_array($this->data['AuthKey']['allowed_ips'])) {
                $this->invalidate('allowed_ips', 'Allowed IPs must be array');
            }
            foreach ($this->data['AuthKey']['allowed_ips'] as $cidr) {
                if (!CidrTool::validate($cidr)) {
                    $this->invalidate('allowed_ips', "$cidr is not valid IP range");
                }
            }
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
                $results[$key]['AuthKey']['allowed_ips'] = $this->jsonDecode($val['AuthKey']['allowed_ips']);
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
                $this->data['AuthKey']['allowed_ips'] = json_encode($this->data['AuthKey']['allowed_ips']);
            }
        }
        return true;
    }

    /**
     * @param string $authkey
     * @return array|false
     */
    public function getAuthUserByAuthKey($authkey)
    {
        $start = substr($authkey, 0, 4);
        $end = substr($authkey, -4);
        $possibleAuthkeys = $this->find('all', [
            'recursive' => -1,
            'fields' => ['id', 'authkey', 'user_id', 'expiration', 'allowed_ips'],
            'conditions' => [
                'OR' => [
                    'expiration >' => time(),
                    'expiration' => 0
                ],
                'authkey_start' => $start,
                'authkey_end' => $end,
            ]
        ]);
        $passwordHasher = $this->getHasher();
        foreach ($possibleAuthkeys as $possibleAuthkey) {
            if ($passwordHasher->check($authkey, $possibleAuthkey['AuthKey']['authkey'])) {
                $user = $this->User->getAuthUser($possibleAuthkey['AuthKey']['user_id']);
                if ($user) {
                    $user['authkey_id'] = $possibleAuthkey['AuthKey']['id'];
                    $user['authkey_expiration'] = $possibleAuthkey['AuthKey']['expiration'];
                    $user['allowed_ips'] = $possibleAuthkey['AuthKey']['allowed_ips'];
                }
                return $user;
            }
        }
        return false;
    }

    /**
     * @param int $userId
     * @param int|null $keyId
     * @return false|string
     * @throws Exception
     */
    public function resetAuthKey($userId, $keyId = null)
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
            return $this->createnewkey($userId, $comment, $allowedIps);
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
            return $this->createnewkey($userId);
        }
    }

    /**
     * @param int $userId
     * @param string $comment
     * @param array $allowedIps
     * @return false|string
     * @throws Exception
     */
    public function createnewkey($userId, $comment = '', array $allowedIps = [])
    {
        $newKey = [
            'authkey' => (new RandomTool())->random_str(true, 40),
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
        $redis = $this->setupRedisWithException();
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
        $redis = $this->setupRedisWithException();
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
     * will be realoaded.
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
     * @return AbstractPasswordHasher
     */
    private function getHasher()
    {
        return new BlowfishPasswordHasher();
    }
}
