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
        ERROR_WRONG_KEY = 'Wrong key';

    public $validTypes = [
        'pgp'
    ];

    public $error = false;

    public $validate = [];

    public function __construct($id = false, $table = null, $ds = null)
    {
        parent::__construct($id, $table, $ds);

        $this->validate = [
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
        $existingKeyForObject = $this->find('first', [
            'recursive'
        ]);
        return true;
    }

    public function signWithInstanceKey($data)
    {
        $file = new File(APP . '/webroot/gpg.asc');
        $instanceKey = $file->read();
        try {
            $this->gpg = GpgTool::initializeGpg();
            $this->gpg->importKey($instanceKey);
        } catch (Crypt_GPG_NoDataException $e) {
            throw new MethodNotAllowedException("Could not import the instance key..");
        }
        $this->gpg->addSignKey(Configure::read('GnuPG.email'), Configure::read('GnuPG.password'));
        $signature = $this->gpg->sign($data, Crypt_GPG::SIGN_MODE_DETACHED);
        return $signature;
    }

    public function verifySignature($data, $signature, $key)
    {
        $this->error = false;
        $fingerprint = $this->__extractPGPKeyData($key);
        $verifiedSignature = $this->gpg->verify($data, $signature);
        if (empty($verifiedSignature)) {
            $this->error = ERROR_MALFORMED_SIGNATURE;
            return false;
        }
        if (!$verifiedSignature[0]->isValid()) {
            $this->error = ERROR_INVALID_SIGNATURE;
            return false;
        }
        if ($verifiedSignature[0]->getKeyFingerprint() === $fingerprint) {
            return true;
        } else {
            $this->error = ERROR_WRONG_KEY;
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

    private function __extractPGPKeyData($data)
    {
        try {
            $gpgTool = new GpgTool(GpgTool::initializeGpg());
        } catch (Exception $e) {
            $this->logException("GPG couldn't be initialized, GPG encryption and signing will be not available.", $e, LOG_NOTICE);
            return '';
        }
        try {
            return $gpgTool->validateGpgKey($data);
        } catch (Exception $e) {
            $this->logException("Could not validate PGP key.", $e, LOG_NOTICE);
            return '';
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
        $existingKey = $this->find('first', [
            'recursive' => -1,
            'conditions' => [
                'parent_type' => $this->data['CryptographicKey']['parent_type'],
                'parent_id' => $this->data['CryptographicKey']['parent_id'],
                'key_data' => $this->data['CryptographicKey']['key_data'],
                'type' => $this->data['CryptographicKey']['type']
            ],
            'fields' => ['id']
        ]);
        return empty($existingKey);
    }

    public function validateProtectedEvent($raw_data, $user, $pgp_signature, $event)
    {
        if (empty($event['Event']['CryptographicKey'])) {
            $this->Log = ClassRegistry::init('Log');
            $this->Log->createLogEntry($user['email'], 'add', 'Event', $server['Server']['id'], $message);
            return false;
        }
        foreach ($event['Event']['CryptographicKey'] as $supplied_key) {
            if ($this->verifySignature($raw_data, $pgp_signature, $supplied_key)) {
                return true;
            }
        }
        $this->Log = ClassRegistry::init('Log');
        $this->Log->createLogEntry($user['email'], 'add', 'Event', $server['Server']['id'], $message);
        return false;
    }

    public function captureCryptographicKeyUpdate($cryptographicKeys, $parent_id, $type)
    {
        $existingKeys = $this->find('first', [
            'recursive' => -1,
            'fields' => 1,
            'conditions' => [
                'parent_type' => $cryptographicKey['type'],
                'parent_id' => $cryptographicKey['parent_id']
            ],
            'fields' => [
                'id',
                'type',
                'parent_type',
                'parent_id',
                'revoked',
                'fingerprint'
            ]
        ]);
        $toRemove = [];
        $results = ['add' => [], 'remove' => []];
        foreach ($existingKeys as $k => $existingKey) {
            foreach ($cryptographicKeys as $k2 => $cryptographicKey) {
                if ($existingKey['CryptographicKey']['fingerprint'] === $cryptographicKey['fingerprint']) {
                    $found = true;
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
                    'uuid' => $cryptoGraphicKey['uuid'],
                    'key_data' => $cryptoGraphicKey['key_data'],
                    'fingerprint' => $cryptoGraphicKey['fingerprint'],
                    'revoked' => $cryptoGraphicKey['revoked'],
                    'parent_type' => $cryptoGraphicKey['parent_type'],
                    'parent_id' => $cryptoGraphicKey['parent_id'],
                    'type' => $cryptoGraphicKey['type']
                ]
            );
            $results['add'][$cryptoGraphicKey['id']] = $cryptoGraphicKey['fingerprint'];
        }
        $message = __(
            'Added %s (%s) and removed %s (%s) keys for %s #%s.',
            count($results['add']),
            implode (',', $results['add']),
            count($results['remove']),
            implode (',', $results['remove']),
            $cryptographicKey['parent_type'],
            $cryptographicKey['parent_id']
        );
        $this->deleteaAll(['CryptoGraphicKey.id' => $toRemove]);
        $this->Log = ClassRegistry::init('Log');
        $this->Log->createLogEntry($user['email'], 'updateCryptoKeys', $cryptoGraphicKey['parent_type'], $cryptoGraphicKey['parent_id'], $message);
    }
}
