<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use ArrayObject;
use Cake\Auth\DefaultPasswordHasher;
use Cake\Datasource\EntityInterface;
use Cake\Event\Event;
use Cake\Event\EventInterface;
use Cake\Utility\Security;
use Cake\Validation\Validator;

class AuthKeysTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('UUID');
        $this->addBehavior('AuditLog');
        $this->belongsTo(
            'Users',
            [
                'dependent' => false,
                'cascadeCallbacks' => false,
                'propertyName' => 'User'
            ]
        );
        $this->addBehavior(
            'JsonFields',
            [
                'fields' => ['allowed_ips' => []],
            ]
        );
        $this->setDisplayField('comment');
    }

    public function beforeMarshal(EventInterface $event, ArrayObject $data, ArrayObject $options)
    {
        $data['created'] = time();
        if (empty($data['expiration'])) {
            $data['expiration'] = 0;
        } else {
            $data['expiration'] = strtotime($data['expiration']);
        }
    }

    public function beforeSave(Event $event, EntityInterface $entity, ArrayObject $options)
    {
        if (empty($entity->authkey)) {
            $authkey = $this->generateAuthKey();
            $entity->authkey_start = substr($authkey, 0, 4);
            $entity->authkey_end = substr($authkey, -4);
            $entity->authkey = (new DefaultPasswordHasher())->hash($authkey);
            $entity->authkey_raw = $authkey;
        }
    }

    public function generateAuthKey()
    {
        return Security::randomString(40);
    }

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->notEmptyString('user_id')
            ->requirePresence(['user_id'], 'create');
        return $validator;
    }

    public function checkKey($authkey)
    {
        if (strlen($authkey) != 40) {
            return [];
        }
        $start = substr($authkey, 0, 4);
        $end = substr($authkey, -4);
        $candidates = $this->find()->where(
            [
                'authkey_start' => $start,
                'authkey_end' => $end,
                'OR' => [
                    'expiration' => 0,
                    'expiration >' => time()
                ]
            ]
        );
        if (!empty($candidates)) {
            foreach ($candidates as $candidate) {
                if ((new DefaultPasswordHasher())->check($authkey, $candidate['authkey'])) {
                    return $candidate;
                }
            }
        }
        return [];
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

        $possibleAuthkeys = $this->find(
            'all',
            [
                'recursive' => -1,
                'fields' => ['id', 'authkey', 'user_id', 'expiration', 'allowed_ips', 'read_only', 'unique_ips'],
                'conditions' => $conditions,
            ]
        );
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
}
