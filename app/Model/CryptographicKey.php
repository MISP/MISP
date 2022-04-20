<?php
App::uses('AppModel', 'Model');
App::uses('EncryptedValue', 'Tools');
App::uses('GpgTool', 'Tools');

class CryptographicKey extends AppModel
{
    public $actsAs = [
        'AuditLog',
        'SysLogLogable.SysLogLogable' => [
            'roleModel' => 'Role',
            'roleKey' => 'role_id',
            'change' => 'full'
        ],
        'Containable'
    ];

    public $belongsTo = array(
        'Event' => [
            'foreignKey' => 'parent_id',
            'conditions' => ['parent_type' => 'Event', 'type' => 'pgp']
        ]
    );

    const ERROR_MALFORMED_SIGNATURE = 'Malformed signature',
        ERROR_INVALID_SIGNATURE = 'Invalid signature',
        ERROR_WRONG_KEY = 'Wrong key',
        ERROR_INVALID_KEY = 'Invalid key';

    public $validTypes = [
        'pgp'
    ];

    public $error = false;

    public $validate = [];

    /** @var CryptGpgExtended|null */
    private $gpg;

    public function __construct($id = false, $table = null, $ds = null)
    {
        parent::__construct($id, $table, $ds);
        try {
            $this->gpg = GpgTool::initializeGpg();
        } catch (Exception $e) {
            $this->gpg = null;
        }
        $this->validate = [
            'uuid' => [
                'uuid' => [
                    'rule' => 'uuid',
                    'message' => 'Please provide a valid RFC 4122 UUID',
                ],
            ],
            'type' => [
                'rule' => ['inList', $this->validTypes],
                'message' => __('Invalid key type'),
                'required' => 'create'
            ],
            'key_data' => [
                'notBlankKey' => [
                    'rule' => 'notBlank',
                    'message' => __('No key data received.'),
                    'required' => 'create'
                ],
                'validKey' => [
                    'rule' => 'validateKey',
                    'message' => __('Invalid key.'),
                    'required' => 'create'
                ],
                'uniqueKeyForElement' => [
                    'rule' => 'uniqueKeyForElement',
                    'message' => __('This key is already assigned to the target.'),
                    'required' => 'create'
                ]
            ]
        ];
    }

    public function beforeSave($options = array())
    {
        $this->data['CryptographicKey']['timestamp'] = time();
        if (!isset($this->data['CryptographicKey']['id'])) {
            $this->data['CryptographicKey']['uuid'] = CakeText::uuid();
            $this->data['CryptographicKey']['fingerprint'] = $this->extractKeyData($this->data['CryptographicKey']['type'], $this->data['CryptographicKey']['key_data']);
        }
        return true;
    }

    /**
     * @return string Instance key fingerprint
     * @throws Crypt_GPG_BadPassphraseException
     * @throws Crypt_GPG_Exception
     */
    public function ingestInstanceKey()
    {
        // If instance just key stored just in GPG homedir, use that key.
        if (Configure::read('MISP.download_gpg_from_homedir')) {
            if (!$this->gpg) {
                throw new Exception("Could not initiate GPG");
            }
            /** @var Crypt_GPG_Key[] $keys */
            $keys = $this->gpg->getKeys(Configure::read('GnuPG.email'));
            if (empty($keys)) {
                return false;
            }
            $this->gpg->addSignKey($keys[0], Configure::read('GnuPG.password'));
            return $keys[0]->getPrimaryKey()->getFingerprint();
        }

        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            $redis = false;
        }
        if ($redis) {
            $redisKey = "misp:instance_fingerprint";
            $fingerprint = $redis->get($redisKey);
        }
        if (!file_exists(APP . '/webroot/gpg.asc')) {
            return false;
        }
        if (empty($fingerprint)) {
            $file = new File(APP . '/webroot/gpg.asc');
            $instanceKey = $file->read();
            if (!$this->gpg) {
                throw new MethodNotAllowedException("Could not initiate GPG");
            }
            try {
                $this->gpg->importKey($instanceKey);
            } catch (Crypt_GPG_NoDataException $e) {
                throw new MethodNotAllowedException("Could not import the instance key..");
            }
            $fingerprint = $this->gpg->getFingerprint(Configure::read('GnuPG.email'));
            if ($redis) {
                $redis->setEx($redisKey, 300, $fingerprint);
            }
        }
        if (!$this->gpg) {
            throw new MethodNotAllowedException("Could not initiate GPG");
        }
        try {
            $this->gpg->addSignKey(Configure::read('GnuPG.email'), Configure::read('GnuPG.password'));
        } catch (Exception $e) {
            throw new NotFoundException('Could not add signing key.');
        }
        return $fingerprint;
    }

    /**
     * @param string $data
     * @return false|string
     * @throws Crypt_GPG_BadPassphraseException
     * @throws Crypt_GPG_Exception
     * @throws Crypt_GPG_KeyNotFoundException
     */
    public function signWithInstanceKey($data)
    {
        if (!$this->ingestInstanceKey()) {
            return false;
        }
        $data = preg_replace("/\s+/", "", $data);
        $signature = $this->gpg->sign($data, Crypt_GPG::SIGN_MODE_DETACHED, Crypt_GPG::ARMOR_BINARY);
        return $signature;
    }

    /**
     * @param string $data
     * @param string $signature
     * @param string $key
     * @return bool
     */
    public function verifySignature($data, $signature, $key)
    {
        $this->error = false;
        $fingerprint = $this->__extractPGPKeyData($key);
        if ($fingerprint === false) {
            $this->error = self::ERROR_INVALID_KEY;
            return false;
        }
        $data = preg_replace("/\s+/", "", $data);
        try {
            $verifiedSignature = $this->gpg->verify($data, $signature);
        } catch (Exception $e) {
            $this->error = self::ERROR_WRONG_KEY;
            return false;
        }
        if (empty($verifiedSignature)) {
            $this->error = self::ERROR_MALFORMED_SIGNATURE;
            return false;
        }
        if (!$verifiedSignature[0]->isValid()) {
            $this->error = self::ERROR_INVALID_SIGNATURE;
            return false;
        }
        if ($verifiedSignature[0]->getKeyFingerprint() === $fingerprint) {
            return true;
        } else {
            $this->error = self::ERROR_WRONG_KEY;
            return false;
        }
    }

    public function extractKeyData($type, $data)
    {
        $fingerprint = '';
        if ($type === 'pgp') {
            $fingerprint = $this->__extractPGPKeyData($data);
        }
        return $fingerprint;

    }

    /**
     * @param string $data
     * @return string|false Primary key fingerprint or false of key is invalid
     */
    private function __extractPGPKeyData($data)
    {
        try {
            $gpgTool = new GpgTool($this->gpg);
        } catch (Exception $e) {
            $this->logException("GPG couldn't be initialized, GPG encryption and signing will be not available.", $e, LOG_NOTICE);
            return false;
        }
        try {
            return $gpgTool->validateGpgKey($data);
        } catch (Exception $e) {
            return false;
        }
    }

    public function validateKey($check)
    {
        if ($this->data['CryptographicKey']['type'] === 'pgp') {
            return $this->validateGpgKey($check);
        }
        return true;
    }

    public function validateGpgKey($data)
    {
        return !empty($this->__extractPGPKeyData($data['key_data']));
    }

    public function uniqueKeyForElement($data)
    {
        return !$this->hasAny([
            'parent_type' => $this->data['CryptographicKey']['parent_type'],
            'parent_id' => $this->data['CryptographicKey']['parent_id'],
            'key_data' => $this->data['CryptographicKey']['key_data'],
            'type' => $this->data['CryptographicKey']['type'],
        ]);
    }

    public function validateProtectedEvent($raw_data, array $user, $pgp_signature, array $event)
    {
        $eventCryptoGraphicKey = [];
        if (!empty($event['Event']['CryptographicKey'])) { // Depending if $event comes from fetchEvent or from pushed data
            $eventCryptoGraphicKey = $event['Event']['CryptographicKey'];
        } else if (!empty($event['CryptographicKey'])) {
            $eventCryptoGraphicKey = $event['CryptographicKey'];
        }
        if (empty($eventCryptoGraphicKey)) {
            $message = __('No valid signatures found for validating the signature.');
            $this->loadLog()->createLogEntry($user, 'validateSig', 'Event', $event['Event']['id'], $message);
            return false;
        }
        foreach ($eventCryptoGraphicKey as $supplied_key) {
            if ($this->verifySignature($raw_data, base64_decode($pgp_signature), $supplied_key['key_data'])) {
                return true;
            }
        }
        $message = __('Could not validate the signature.');
        $this->loadLog()->createLogEntry($user, 'validateSig', 'Event', $event['Event']['id'], $message);
        return false;
    }

    /**
     * @param array $user
     * @param array $cryptographicKeys
     * @param int $parent_id
     * @param string $type
     * @return void
     * @throws Exception
     */
    public function captureCryptographicKeyUpdate(array $user, array $cryptographicKeys, $parent_id, $type)
    {
        $existingKeys = $this->find('first', [
            'recursive' => -1,
            'conditions' => [
                'parent_type' => $type,
                'parent_id' => $parent_id,
            ],
            'fields' => [
                'id',
                'type',
                'parent_type',
                'parent_id',
                'revoked',
                'fingerprint',
            ]
        ]);
        $toRemove = [];
        $results = ['add' => [], 'remove' => []];
        foreach ($existingKeys as $existingKey) {
            foreach ($cryptographicKeys as $k2 => $cryptographicKey) {
                if ($existingKey['fingerprint'] === $cryptographicKey['fingerprint']) {
                    if ($cryptographicKey['revoked'] && !$existingKey['CryptographicKey']['revoked']) {
                        $existingKey['CryptographicKey']['revoked'] = 1;
                        $this->save($existingKey['CryptographicKey']);
                    }
                    unset($cryptographicKeys[$k2]);
                    continue 2;
                }
            }
            $toRemove[] = $existingKey['CryptographicKey']['id'];
            $results['remove'][$existingKey['CryptographicKey']['id']] = $existingKey['CryptographicKey']['fingerprint'];
        }
        foreach ($cryptographicKeys as $cryptographicKey) {
            $this->create();
            $this->save(
                [
                    'uuid' => $cryptographicKey['uuid'],
                    'key_data' => $cryptographicKey['key_data'],
                    'fingerprint' => $cryptographicKey['fingerprint'],
                    'revoked' => $cryptographicKey['revoked'],
                    'parent_type' => $cryptographicKey['parent_type'],
                    'parent_id' => $parent_id,
                    'type' => $cryptographicKey['type']
                ]
            );
            $results['add'][$cryptographicKey['id']] = $cryptographicKey['fingerprint'];
        }
        $message = __(
            'Added %s (%s) and removed %s (%s) keys for %s #%s.',
            count($results['add']),
            implode (',', $results['add']),
            count($results['remove']),
            implode (',', $results['remove']),
            $cryptographicKey['parent_type'],
            $parent_id
        );
        $this->deleteAll(['CryptographicKey.id' => $toRemove]);
        $this->loadLog()->createLogEntry($user, 'updateCryptoKeys', $cryptographicKey['parent_type'], $cryptographicKey['parent_id'], $message);
    }
}
