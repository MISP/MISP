<?php


namespace App\Model\Table;

use App\Lib\Tools\GpgTool;
use App\Lib\Tools\RedisTool;
use App\Model\Table\AppTable;
use ArrayObject;
use Cake\Core\Configure;
use Cake\Event\EventInterface;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\NotFoundException;
use Cake\Log\Log;
use Cake\Utility\Text;
use Cake\Validation\Validator;
use Exception;

class CryptographicKeysTable extends AppTable
{
    public const ERROR_MALFORMED_SIGNATURE = 'Malformed signature',
        ERROR_INVALID_SIGNATURE = 'Invalid signature',
        ERROR_WRONG_KEY = 'Wrong key',
        ERROR_INVALID_KEY = 'Invalid key';

    public const VALID_TYPES = [
        'pgp'
    ];

    public $error = false;

    /** @var CryptGpgExtended|null */
    private $gpg;

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');

        $this->belongsTo(
            'Event',
            [
                'dependent' => false,
                'cascadeCallbacks' => false
            ]
        )
            ->setForeignKey('parent_id')
            ->setConditions(['parent_type' => 'Event', 'type' => 'pgp']);
    }

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->requirePresence(['type', 'key_data'], 'create')
            ->add(
                'uuid',
                'uuid',
                [
                    'rule' => 'uuid',
                    'message' => 'Please provide a valid RFC 4122 UUID'
                ]
            )
            ->add(
                'type',
                'inList',
                [
                    'rule' => ['inList', self::VALID_TYPES],
                    'message' => 'Invalid key type'
                ]
            )
            ->add(
                'key_data',
                'notBlankKey',
                [
                    'rule' => 'notBlank',
                    'message' => 'No key data received.'
                ]
            )
            ->add(
                'key_data',
                'validKey',
                [
                    'rule' => function ($value, $context) {
                        return $this->validateKey($context['data']['type'], $value);
                    },
                    'message' => 'Invalid key.'
                ]
            )
            ->add(
                'key_data',
                'uniqueKeyForElement',
                [
                    'rule' => function ($value, $context) {
                        return $this->uniqueKeyForElement($value, $context);
                    },
                    'message' => 'This key is already assigned to the target.'
                ]
            );

        return $validator;
    }

    public function beforeMarshal(EventInterface $event, ArrayObject $data, ArrayObject $options)
    {
        $data['timestamp'] = time();
        if (!isset($data['id'])) {
            $data['uuid'] = Text::uuid();
            $data['fingerprint'] = $this->extractKeyData($data['type'], $data['key_data']);
        }
        return true;
    }

    /**
     * @return string|false Instance key fingerprint or false is no key is set
     * @throws Crypt_GPG_BadPassphraseException
     * @throws Crypt_GPG_Exception
     */
    public function ingestInstanceKey()
    {
        // If instance key is stored just in GPG homedir, use that key.
        if (Configure::read('MISP.download_gpg_from_homedir')) {
            /** @var Crypt_GPG_Key[] $keys */
            $keys = $this->getGpg()->getKeys(Configure::read('GnuPG.email'));
            if (empty($keys)) {
                return false;
            }
            $this->getGpg()->addSignKey($keys[0], Configure::read('GnuPG.password'));
            return $keys[0]->getPrimaryKey()->getFingerprint();
        }

        try {
            $redis = RedisTool::init();
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
            $file = new \SplFileObject(APP . '/webroot/gpg.asc', 'r');
            $instanceKey = $file->fread($file->getSize());
            try {
                $this->getGpg()->importKey($instanceKey);
            } catch (\Crypt_GPG_NoDataException $e) {
                throw new MethodNotAllowedException("Could not import the instance key.");
            }
            $fingerprint = $this->getGpg()->getFingerprint(Configure::read('GnuPG.email'));
            if ($redis) {
                $redis->setEx($redisKey, 300, $fingerprint);
            }
        }
        try {
            $this->getGpg()->addSignKey(Configure::read('GnuPG.email'), Configure::read('GnuPG.password'));
        } catch (Exception $e) {
            throw new NotFoundException('Could not add signing key.');
        }
        return $fingerprint;
    }

    /**
     * Check if given events are protected by instance key, returns array of Event IDs
     * @param array $events
     * @return array Event ID that is protected in key
     */
    public function protectedEventsByInstanceKey(array $events)
    {
        $eventIds = [];
        foreach ($events as $event) {
            if ($event['protected']) {
                $eventIds[] = $event['id'];
            }
        }

        if (empty($eventIds)) {
            return [];
        }

        try {
            $instanceKey = $this->ingestInstanceKey();
        } catch (Exception $e) {
            // could not fetch instance key
            return [];
        }

        return $this->find(
            'column',
            [
                'conditions' => [
                    'CryptographicKeys.parent_type' => 'Event',
                    'CryptographicKeys.parent_id' => $eventIds,
                    'CryptographicKeys.fingerprint' => $instanceKey,
                ],
                'fields' => ['CryptographicKeys.parent_id'],
                'recursive' => -1,
            ]
        );
    }

    /**
     * @param string $data
     * @return false|string Signature
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
        $signature = $this->getGpg()->sign($data, \Crypt_GPG::SIGN_MODE_DETACHED, \Crypt_GPG::ARMOR_BINARY);
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
            $verifiedSignature = $this->getGpg()->verify($data, $signature);
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
            $gpgTool = new GpgTool($this->getGpg());
        } catch (Exception $e) {
            Log::notice("GPG couldn't be initialized, GPG encryption and signing will be not available.", ['exception' => $e]);
            return false;
        }
        try {
            return $gpgTool->validateGpgKey($data);
        } catch (Exception $e) {
            return false;
        }
    }

    public function validateKey($type, $value)
    {
        if ($type === 'pgp') {
            return $this->validateGpgKey($value);
        }
        return true;
    }

    public function validateGpgKey($data)
    {
        return !empty($this->__extractPGPKeyData($data));
    }

    public function uniqueKeyForElement($value, $context)
    {
        return $this->find()->where(
            [
                'parent_type' => $context['data']['parent_type'],
                'parent_id' => $context['data']['parent_id'],
                'key_data' => $value,
                'type' => $context['data']['type'],
            ]
        )->all()->isEmpty();
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
        $existingKeys = $this->find(
            'all',
            [
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
            ]
        )->first();
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
            $cryptoKeyEntity = $this->newEntity(
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

            $this->save($cryptoKeyEntity);
            $results['add'][$cryptographicKey['id']] = $cryptographicKey['fingerprint'];
        }
        $message = __(
            'Added %s (%s) and removed %s (%s) keys for %s #%s.',
            count($results['add']),
            implode(',', $results['add']),
            count($results['remove']),
            implode(',', $results['remove']),
            $cryptographicKey['parent_type'],
            $parent_id
        );
        $this->deleteAll(['CryptographicKeys.id' => $toRemove]);
        $this->loadLog()->createLogEntry($user, 'updateCryptoKeys', $cryptographicKey['parent_type'], $cryptographicKey['parent_id'], $message);
    }

    /**
     * Lazy load GPG
     * @return CryptGpgExtended|null
     * @throws Exception
     */
    private function getGpg()
    {
        if ($this->gpg) {
            return $this->gpg;
        }

        $this->gpg = GpgTool::initializeGpg();
        return $this->gpg;
    }
}
