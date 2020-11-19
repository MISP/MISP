<?php
App::uses('AppModel', 'Model');
App::uses('RandomTool', 'Tools');

/**
 * @property User $User
 */
class AuthKey extends AppModel
{
    public $recursive = -1;

    public $actsAs = array(
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
        //parent::beforeValidate();
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
            if (empty($this->data['AuthKey']['expiration'])) {
                $this->data['AuthKey']['expiration'] = 0;
            } else {
                $this->data['AuthKey']['expiration'] = strtotime($this->data['AuthKey']['expiration']);
            }
        }
        return true;
    }

    public function getAuthUserByAuthKey($authkey)
    {
        $start = substr($authkey, 0, 4);
        $end = substr($authkey, -4);
        $existing_authkeys = $this->find('all', [
            'recursive' => -1,
            'fields' => ['authkey', 'user_id'],
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
        foreach ($existing_authkeys as $existing_authkey) {
            if ($passwordHasher->check($authkey, $existing_authkey['AuthKey']['authkey'])) {
                return $this->User->getAuthUser($existing_authkey['AuthKey']['user_id']);
            }
        }
        return false;
    }

    public function resetauthkey($id)
    {
        $existing_authkeys = $this->find('all', [
            'recursive' => -1,
            'conditions' => [
                'user_id' => $id
            ]
        ]);
        foreach ($existing_authkeys as $key) {
            $key['AuthKey']['expiration'] = time();
            $this->save($key);
        }
        return $this->createnewkey($id);
    }

    public function createnewkey($id)
    {
        $newKey = [
            'authkey' => (new RandomTool())->random_str(true, 40),
            'user_id' => $id
        ];
        $this->create();
        if ($this->save($newKey)) {
            return $newKey['authkey'];
        } else {
            return false;
        }
    }

    /**
     * @return AbstractPasswordHasher
     */
    private function getHasher()
    {
        return new BlowfishPasswordHasher();
    }
}
