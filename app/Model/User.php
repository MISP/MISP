<?php
App::uses('AppModel', 'Model');
App::uses('AuthComponent', 'Controller/Component');
App::uses('RandomTool', 'Tools');

class User extends AppModel
{
    public $displayField = 'email';

    public $orgField = array('Organisation', 'name');

    public $validate = array(
        'role_id' => array(
            'numeric' => array(
                'rule' => array('numeric'),
                //'message' => 'Your custom message here',
                //'allowEmpty' => false,
                //'required' => false,
                //'last' => false, // Stop validation after this rule
                //'on' => 'create', // Limit validation to 'create' or 'update' operations
            ),
        ),
        'password' => array(
            'minlength' => array(
                'rule' => array('passwordLength'),
                'message' => 'Password length requirement not met.',
                //'allowEmpty' => false,
                'required' => true,
                //'last' => false, // Stop validation after this rule
                //'on' => 'create', // Limit validation to 'create' or 'update' operations
            ),
            'complexity' => array(
                'rule' => array('complexPassword'),
                'message' => 'Password complexity requirement not met.',
                //'allowEmpty' => false,
                //'required' => true,
                //'last' => false, // Stop validation after this rule
                //'on' => 'create', // Limit validation to 'create' or 'update' operations
            ),
            'identical' => array(
                'rule' => array('identicalFieldValues', 'confirm_password'),
                'message' => 'Please re-enter your password twice so that the values match.',
                //'allowEmpty' => false,
                //'required' => true,
                //'last' => false, // Stop validation after this rule
                //'on' => 'create', // Limit validation to 'create' or 'update' operations
            ),
        ),

        'org_id' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
            'numeric' => array(
                    'rule' => array('numeric'),
                    'message' => 'The organisation ID has to be a numeric value.',
            ),
        ),
        'email' => array(
            'email' => array(
                'rule' => array('email'),
                'message' => 'Please enter a valid email address.',
                //'allowEmpty' => false,
                'required' => true,
                //'last' => false, // Stop validation after this rule
                //'on' => 'create', // Limit validation to 'create' or 'update' operations
            ),
            'unique' => array(
                'rule' => 'isUnique',
                'message' => 'An account with this email address already exists.'
            ),
        ),
        'autoalert' => array(
            'boolean' => array(
                'rule' => array('boolean'),
                //'message' => 'Your custom message here',
                //'allowEmpty' => false,
                'required' => false,
                //'last' => false, // Stop validation after this rule
                //'on' => 'create', // Limit validation to 'create' or 'update' operations
            ),
        ),
        'contactalert' => array(
                'boolean' => array(
                        'rule' => array('boolean'),
                        //'message' => 'Your custom message here',
                        //'allowEmpty' => false,
                        'required' => false,
                        //'last' => false, // Stop validation after this rule
                        //'on' => 'create', // Limit validation to 'create' or 'update' operations
                ),
        ),
        'authkey' => array(
            'minlength' => array(
                'rule' => array('minlength', 40),
                'message' => 'A authkey of a minimum length of 40 is required.',
                'required' => true,
            ),
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
        ),
        'invited_by' => array(
            'numeric' => array(
                'rule' => array('numeric'),
                //'message' => 'Your custom message here',
                //'allowEmpty' => false,
                //'required' => false,
                //'last' => false, // Stop validation after this rule
                //'on' => 'create', // Limit validation to 'create' or 'update' operations
            ),
        ),
        'change_pw' => array(
            'boolean' => array(
                'rule' => array('boolean'),
                //'message' => 'Your custom message here',
                'allowEmpty' => true,
                'required' => false,
                //'last' => false, // Stop validation after this rule
                //'on' => 'create', // Limit validation to 'create' or 'update' operations
            ),
        ),
        'gpgkey' => array(
            'gpgvalidation' => array(
                'rule' => array('validateGpgkey'),
                'message' => 'GnuPG key not valid, please enter a valid key.',
            ),
        ),
        'certif_public' => array(
            'notempty' => array(
                'rule' => array('validateCertificate'),
                'message' => 'Certificate not valid, please enter a valid certificate (x509).',
                //'allowEmpty' => false,
                //'required' => false,
                //'last' => false, // Stop validation after this rule
                //'on' => 'create', // Limit validation to 'create' or 'update' operations
            ),
        ),
        'nids_sid' => array(
            'numeric' => array(
                'rule' => array('numeric'),
                'message' => 'A SID should be an integer.',
                'allowEmpty' => false,
                'required' => true,
                //'last' => false, // Stop validation after this rule
                //'on' => 'create', // Limit validation to 'create' or 'update' operations
            ),
        ),
        'termsaccepted' => array(
            'boolean' => array(
                'rule' => array('boolean'),
                //'message' => 'Your custom message here',
                //'allowEmpty' => false,
                //'required' => false,
                //'last' => false, // Stop validation after this rule
                //'on' => 'create', // Limit validation to 'create' or 'update' operations
            ),
        ),
        'newsread' => array(
            'numeric' => array(
                'rule' => array('numeric')
            ),
        ),
    );

    // The Associations below have been created with all possible keys, those that are not needed can be removed
    public $belongsTo = array(
        'Role' => array(
            'className' => 'Role',
            'foreignKey' => 'role_id',
            'conditions' => '',
            'fields' => '',
            'order' => ''
        ),
        'Organisation' => array(
            'className' => 'Organisation',
            'foreignKey' => 'org_id',
            'conditions' => '',
            'fields' => '',
            'order' => ''
        ),
        'Server' => array(
            'className' => 'Server',
            'foreignKey' => 'server_id',
            'conditions' => '',
            'fields' => array('Server.id', 'Server.url', 'Server.push_rules'),
            'order' => ''
        )
    );

    public $hasMany = array(
        'Event' => array(
            'className' => 'Event',
            'foreignKey' => 'user_id',
            'dependent' => false,
            'conditions' => '',
            'fields' => '',
            'order' => '',
            'limit' => '',
            'offset' => '',
            'exclusive' => '',
            'finderQuery' => '',
            'counterQuery' => ''
        ),
        'Post',
        'UserSetting'
    );

    public $actsAs = array(
        'SysLogLogable.SysLogLogable' => array(
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'full',
            'ignore' => array('password')
        ),
        'Trim',
        'Containable'
    );

    public function beforeValidate($options = array())
    {
        if (!isset($this->data['User']['id'])) {
            if ((isset($this->data['User']['enable_password']) && (!$this->data['User']['enable_password'])) || (empty($this->data['User']['password']) && empty($this->data['User']['confirm_password']))) {
                $this->data['User']['password'] = $this->generateRandomPassword();
                $this->data['User']['confirm_password'] = $this->data['User']['password'];
            }
        }
        if (!isset($this->data['User']['certif_public']) || empty($this->data['User']['certif_public'])) {
            $this->data['User']['certif_public'] = '';
        }
        if (!isset($this->data['User']['authkey']) || empty($this->data['User']['authkey'])) {
            $this->data['User']['authkey'] = $this->generateAuthKey();
        }
        if (!isset($this->data['User']['nids_sid']) || empty($this->data['User']['nids_sid'])) {
            $this->data['User']['nids_sid'] = mt_rand(1000000, 9999999);
        }
        if (isset($this->data['User']['newsread']) && $this->data['User']['newsread'] === null) {
            $this->data['User']['newsread'] = 0;
        }
        return true;
    }

    public function beforeSave($options = array())
    {
        $this->data[$this->alias]['date_modified'] = time();
        if (isset($this->data[$this->alias]['password'])) {
            $passwordHasher = new BlowfishPasswordHasher();
            $this->data[$this->alias]['password'] = $passwordHasher->hash($this->data[$this->alias]['password']);
        }
        return true;
    }

    public function afterSave($created, $options = array())
    {
        $pubToZmq = Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_user_notifications_enable');
        $kafkaTopic = Configure::read('Plugin.Kafka_user_notifications_topic');
        $pubToKafka = Configure::read('Plugin.Kafka_enable') && Configure::read('Plugin.Kafka_user_notifications_enable') && !empty($kafkaTopic);
        if ($pubToZmq || $pubToKafka) {
            if (!empty($this->data)) {
                $user = $this->data;
                if (!isset($user['User'])) {
                    $user['User'] = $user;
                }
                $action = $created ? 'edit' : 'add';
                if (isset($user['User']['action'])) {
                    $action = $user['User']['action'];
                }
                if (isset($user['User']['id'])) {
                    $user = $this->find('first', array(
                        'recursive' => -1,
                        'conditions' => array('User.id' => $user['User']['id']),
                        'fields' => array('id', 'email', 'last_login', 'org_id', 'termsaccepted', 'autoalert', 'newsread', 'disabled'),
                        'contain' => array(
                            'Organisation' => array(
                                'fields' => array('Organisation.id', 'Organisation.name', 'Organisation.description', 'Organisation.uuid', 'Organisation.nationality', 'Organisation.sector', 'Organisation.type', 'Organisation.local')
                            )
                        )
                    ));
                }
                if (isset($user['User']['password'])) {
                    unset($user['User']['password']);
                    unset($user['User']['confirm_password']);
                }
                if ($pubToZmq) {
                    $pubSubTool = $this->getPubSubTool();
                    $pubSubTool->modified($user, 'user', $action);
                }
                if ($pubToKafka) {
                    $kafkaPubTool = $this->getKafkaPubTool();
                    $kafkaPubTool->publishJson($kafkaTopic, $user, $action);
                }
            }
        }
        return true;
    }

    // Checks if the GnuPG key is a valid key, but also import it in the keychain.
    // this will NOT fail on keys that can only be used for signing but not encryption!
    // the method in verifyUsers will fail in that case.
    public function validateGpgkey($check)
    {
        // LATER first remove the old gpgkey from the keychain
        // empty value
        if (empty($check['gpgkey'])) {
            return true;
        }

        // we have a clean, hopefully public, key here
        try {
            $gpg = $this->initializeGpg();
            try {
                $keyImportOutput = $gpg->importKey($check['gpgkey']);
                if (!empty($keyImportOutput['fingerprint'])) {
                    return true;
                }
            } catch (Exception $e) {
                $this->log($e->getMessage());
                return false;
            }
        } catch (Exception $e) {
            $this->log($e->getMessage());
            return true;
        }
    }

    // Checks if the certificate is a valid x509 certificate, but also import it in the keychain.
    // this will NOT fail on keys that can only be used for signing but not encryption!
    // the method in verifyUsers will fail in that case.
    public function validateCertificate($check)
    {
        // LATER first remove the old certif_public from the keychain

        // empty value
        if (empty($check['certif_public'])) {
            return true;
        }

        // certif_public is entered

        // Check if $check is a x509 certificate
        if (openssl_x509_read($check['certif_public'])) {
            return $this->testSmimeCertificate($check['certif_public']);
        } else {
            return false;
        }
    }

    public function passwordLength($check)
    {
        $length = Configure::read('Security.password_policy_length');
        if (empty($length) || $length < 0) {
            $length = 12;
        }
        $value = array_values($check);
        $value = $value[0];
        if (strlen($value) < $length) {
            return false;
        }
        return true;
    }

    /*
     default password:
     6 characters minimum
     1 or more upper-case letters
     1 or more lower-case letters
     1 or more digits or special characters
     example: "EasyPeasy34"
     If Security.password_policy_complexity is set and valid, use the regex provided.
     */
    public function complexPassword($check)
    {
        $regex = Configure::read('Security.password_policy_complexity');
        if (empty($regex) || @preg_match($regex, 'test') === false) {
            $regex = '/^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/';
        }
        $value = array_values($check);
        $value = $value[0];
        return preg_match($regex, $value);
    }

    public function identicalFieldValues($field = array(), $compareField = null)
    {
        foreach ($field as $key => $value) {
            $v1 = $value;
            $v2 = $this->data[$this->name][$compareField];
            if ($v1 !== $v2) {
                return false;
            } else {
                continue;
            }
        }
        return true;
    }

    public function generateAuthKey()
    {
        return (new RandomTool())->random_str(true, 40);
    }

    /**
     * Generates a cryptographically secure password
     *
     * @param int $passwordLength
     * @return string
     */
    public function generateRandomPassword($passwordLength = 40)
    {
        // makes sure, the password policy isn't undermined by setting a manual passwordLength
        $policyPasswordLength = Configure::read('Security.password_policy_length') ? Configure::read('Security.password_policy_length') : false;
        if (is_int($policyPasswordLength) && $policyPasswordLength > $passwordLength) {
            $passwordLength = $policyPasswordLength;
        }
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-+=!@#$%^&*()<>/?';
        return (new RandomTool())->random_str(true, $passwordLength, $characters);
    }


    public function checkAndCorrectPgps()
    {
        $fails = array();
        $users = $this->find('all', array('recursive' => 0));

        foreach ($users as $user) {
            if (strlen($user['User']['gpgkey']) && strpos($user['User']['gpgkey'], "\n")) {
                $fails[] = $user['User']['id'] . ':' . $user['User']['id'];
            }
        }
        return $fails;
    }

    public function getOrgs()
    {
        $orgs = $this->Organisation->find('list', array(
            'recursive' => -1,
            'fields' => array('name'),
        ));
        return $orgs;
    }

    public function getOrgMemberCount($org)
    {
        return $this->find('count', array(
                'conditions' => array(
                        'org =' => $org,
                )));
    }

    public function verifySingleGPG($user, $gpg = false)
    {
        if (!$gpg) {
            try {
                $gpg = $this->initializeGpg();
            } catch (Exception $e) {
                $result[2] = 'GnuPG is not configured on this system.';
                $result[0] = true;
                return $result;
            }
        }
        $result = array();
        try {
            $currentTimestamp = time();
            $temp = $gpg->importKey($user['User']['gpgkey']);
            $key = $gpg->getKeys($temp['fingerprint']);
            $result[5] = $temp['fingerprint'];
            $subKeys = $key[0]->getSubKeys();
            $sortedKeys = array('valid' => 0, 'expired' => 0, 'noEncrypt' => 0);
            foreach ($subKeys as $subKey) {
                $expiration = $subKey->getExpirationDate();
                if ($expiration != 0 && $currentTimestamp > $expiration) {
                    $sortedKeys['expired']++;
                    continue;
                }
                if (!$subKey->canEncrypt()) {
                    $sortedKeys['noEncrypt']++;
                    continue;
                }
                $sortedKeys['valid']++;
            }
            if (!$sortedKeys['valid']) {
                $result[2] = 'The user\'s GnuPG key does not include a valid subkey that could be used for encryption.';
                if ($sortedKeys['expired']) {
                    $result[2] .= ' Found ' . $sortedKeys['expired'] . ' subkey(s) that have expired.';
                }
                if ($sortedKeys['noEncrypt']) {
                    $result[2] .= ' Found ' . $sortedKeys['noEncrypt'] . ' subkey(s) that are sign only.';
                }
                $result[0] = true;
            }
        } catch (Exception $e) {
            $result[2] = $e->getMessage();
            $result[0] = true;
        }
        $result[1] = $user['User']['email'];
        $result[4] = $temp['fingerprint'];
        return $result;
    }

    public function verifyGPG($id = false)
    {
        $this->Behaviors->detach('Trim');
        $results = array();
        $conditions = array('not' => array('gpgkey' => ''));
        if ($id !== false) {
            $conditions['User.id'] = $id;
        }
        $users = $this->find('all', array(
            'conditions' => $conditions,
            'recursive' => -1,
        ));
        if (empty($users)) {
            return $results;
        }
        $gpg = $this->initializeGpg();
        foreach ($users as $k => $user) {
            $results[$user['User']['id']] = $this->verifySingleGPG($user, $gpg);
        }
        return $results;
    }

    private function testSmimeCertificate($certif_public)
    {
        $result = array();
        try {
            App::uses('Folder', 'Utility');
            App::uses('FileAccessTool', 'Tools');
            $fileAccessTool = new FileAccessTool();
            $dir = APP . 'tmp' . DS . 'SMIME';
            if (!file_exists($dir)) {
                if (!mkdir($dir, 0750, true)) {
                    throw new MethodNotAllowedException('The SMIME temp directory is not writeable (app/tmp/SMIME).');
                }
            }
            $tempFile = $fileAccessTool->createTempFile($dir, 'SMIME');
            $msg_test = $fileAccessTool->writeToFile($tempFile, 'test');
            $msg_test_encrypted = $fileAccessTool->createTempFile($dir, 'SMIME');
            // encrypt it
            if (openssl_pkcs7_encrypt($msg_test, $msg_test_encrypted, $certif_public, null, 0, OPENSSL_CIPHER_AES_256_CBC)) {
                $parse = openssl_x509_parse($certif_public);
                // Valid certificate ?
                $now = new DateTime("now");
                $validTo_time_t_epoch = $parse['validTo_time_t'];
                $validTo_time_t = new DateTime("@$validTo_time_t_epoch");
                if ($validTo_time_t > $now) {
                    // purposes smimeencrypt ?
                    if (($parse['purposes'][5][0] == 1) && ($parse['purposes'][5][2] == 'smimeencrypt')) {
                        $result = true;
                    } else {
                        // openssl_pkcs7_encrypt good -- Model/User purposes is NOT GOOD'
                        $result = 'This certificate cannot be used to encrypt email';
                    }
                } else {
                    // openssl_pkcs7_encrypt good -- Model/User expired;
                    $result = 'This certificate is expired';
                }
            } else {
                // openssl_pkcs7_encrypt NOT good -- Model/User
                $result = 'This certificate cannot be used to encrypt email';
            }
        } catch (Exception $e) {
            $this->log($e->getMessage());
        }
        unlink($msg_test);
        unlink($msg_test_encrypted);
        return $result;
    }

    public function verifyCertificate()
    {
        $this->Behaviors->detach('Trim');
        $results = array();
        $users = $this->find('all', array(
            'conditions' => array('not' => array('certif_public' => '')),
            'recursive' => -1,
        ));
        foreach ($users as $k => $user) {
            $result = $this->testSmimeCertificate($user['User']['certif_public']);
            if ($result !== true) {
                $results[$user['User']['id']] = array(0 => true, 1 => $user['User']['email']);
            }
        }
        return $results;
    }

    public function getPGP($id)
    {
        $result = $this->find('first', array(
            'recursive' => -1,
            'fields' => array('id', 'gpgkey'),
            'conditions' => array('id' => $id),
        ));
        return $result['User']['gpgkey'];
    }

    public function getCertificate($id)
    {
        $result = $this->find('first', array(
            'recursive' => -1,
            'fields' => array('id', 'certif_public'),
            'conditions' => array('id' => $id),
        ));
        return $result['User']['certif_public'];
    }

    // get the current user and rearrange it to be in the same format as in the auth component
    public function getAuthUser($id)
    {
        if (empty($id)) {
            throw new NotFoundException('Invalid user ID.');
        }
        $conditions = array('User.id' => $id);
        $user = $this->find(
            'first',
            array(
                'conditions' => $conditions,
                'recursive' => -1,
                'contain' => array(
                    'Organisation',
                    'Role',
                    'Server',
                    'UserSetting'
                )
            )
        );
        if (empty($user)) {
            return $user;
        }
        // Rearrange it a bit to match the Auth object created during the login
        $user['User']['Role'] = $user['Role'];
        $user['User']['Organisation'] = $user['Organisation'];
        $user['User']['Server'] = $user['Server'];
        $user['User']['UserSetting'] = $user['UserSetting'];
        unset($user['Organisation'], $user['Role'], $user['Server']);
        return $user['User'];
    }

    // get the current user and rearrange it to be in the same format as in the auth component
    public function getAuthUserByAuthkey($id)
    {
        $conditions = array('User.authkey' => $id);
        $user = $this->find('first', array('conditions' => $conditions, 'recursive' => -1,'contain' => array('Organisation', 'Role', 'Server')));
        if (empty($user)) {
            return $user;
        }
        // Rearrange it a bit to match the Auth object created during the login
        $user['User']['Role'] = $user['Role'];
        $user['User']['Organisation'] = $user['Organisation'];
        $user['User']['Server'] = $user['Server'];
        return $user['User'];
    }

    public function getAuthUserByExternalAuth($auth_key)
    {
        $conditions = array(
            'User.external_auth_key' => $auth_key,
            'User.external_auth_required' => true
        );
        $user = $this->find('first', array(
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array(
                'Organisation',
                'Role',
                'Server'
            )
        ));
        if (empty($user)) {
            return $user;
        }
        // Rearrange it a bit to match the Auth object created during the login
        $user['User']['Role'] = $user['Role'];
        $user['User']['Organisation'] = $user['Organisation'];
        $user['User']['Server'] = $user['Server'];
        unset($user['Organisation'], $user['Role'], $user['Server']);
        return $user['User'];
    }

    // Fetch all users that have access to an event / discussion for e-mailing (or maybe something else in the future.
    // parameters are an array of org IDs that are owners (for an event this would be orgc and org)
    public function getUsersWithAccess($owners = array(), $distribution, $sharing_group_id = 0, $userConditions = array())
    {
        $sgModel = ClassRegistry::init('SharingGroup');
        $conditions = array();
        $validOrgs = array();
        $all = true;

        // add owners to the conditions
        if ($distribution == 0 || $distribution == 4) {
            $all = false;
            $validOrgs = $owners;
        }

        // add all orgs to the conditions that can see the SG
        if ($distribution == 4) {
            $sgOrgs = $sgModel->getOrgsWithAccess($sharing_group_id);
            if ($sgOrgs === true) {
                $all = true;
            } else {
                $validOrgs = array_merge($validOrgs, $sgOrgs);
            }
        }
        $validOrgs = array_unique($validOrgs);
        $conditions['AND'][] = array('disabled' => 0);
        if (!$all) {
            $conditions['AND']['OR'][] = array('org_id' => $validOrgs);

            // Add the site-admins to the list
            $roles = $this->Role->find('all', array(
                    'conditions' => array('perm_site_admin' => 1),
                    'fields' => array('id')
            ));
            $roleIDs = array();
            foreach ($roles as $role) {
                $roleIDs[] = $role['Role']['id'];
            }
            $conditions['AND']['OR'][] = array('role_id' => $roleIDs);
        }
        $conditions['AND'][] = $userConditions;
        $users = $this->find('all', array(
            'conditions' => $conditions,
            'recursive' => -1,
            'fields' => array('id', 'email', 'gpgkey', 'certif_public', 'org_id'),
            'contain' => array('Role' => array('fields' => array('perm_site_admin'))),
        ));
        foreach ($users as $k => $user) {
            $user = $user['User'];
            unset($users[$k]['User']);
            $users[$k] = array_merge($user, $users[$k]);
        }
        return $users;
    }

    public function sendEmailExternal($user, $params)
    {
        $this->Log = ClassRegistry::init('Log');
        $params['body'] = str_replace('\n', PHP_EOL, $params['body']);
        $Email = new CakeEmail();
        $recipient = array('User' => array('email' => $params['to']));
        $failed = false;
        $mock = false;
        if (!empty($params['gpgkey'])) {
            $recipient['User']['gpgkey'] = $params['gpgkey'];
            $encryptionResult = $this->__encryptUsingGPG($Email, $params['body'], $params['subject'], $recipient);
            if (isset($encryptionResult['failed'])) {
                $mock = true;
            }
            if (isset($encryptionResult['failureReason'])) {
                $failureReason = $encryptionResult['failureReason'];
            }
        }
        if (!$failed) {
            $replyToLog = '';
            $user = array('User' => $user);
            $attachments = array();
            $Email->replyTo($params['reply-to']);
            if (!empty($params['requestor_gpgkey'])) {
                $attachments['gpgkey.asc'] = array(
                    'data' => $params['requestor_gpgkey']
                );
            }
            $Email->from(Configure::read('MISP.email'));
            $Email->returnPath(Configure::read('MISP.email'));
            $Email->to($params['to']);
            $Email->subject($params['subject']);
            $Email->emailFormat('text');
            if (!empty($params['attachments'])) {
                foreach ($params['attachments'] as $key => $value) {
                    $attachments[$k] = array('data' => $value);
                }
            }
            $Email->attachments($attachments);
            if (!empty(Configure::read('MISP.disable_emailing')) || !empty($params['mock'])) {
                $Email->transport('Debug');
                $mock = true;
            }
            $result = $Email->send($params['body']);
            $Email->reset();
            if ($result && !$mock) {
                return true;
            }
            return $result;
        }
        return false;
    }

    // all e-mail sending is now handled by this method
    // Just pass the user ID in an array that is the target of the e-mail along with the message body and the alternate message body if the message cannot be encrypted
    // the remaining two parameters are the e-mail subject and a secondary user object which will be used as the replyto address if set. If it is set and an encryption key for the replyTo user exists, then his/her public key will also be attached
    public function sendEmail($user, $body, $bodyNoEnc = false, $subject, $replyToUser = false)
    {
        $this->Log = ClassRegistry::init('Log');
        if (Configure::read('MISP.disable_emailing')) {
            $this->Log->create();
            $this->Log->save(array(
                    'org' => 'SYSTEM',
                    'model' => 'User',
                    'model_id' => $user['User']['id'],
                    'email' => $user['User']['email'],
                    'action' => 'email',
                    'title' => 'Email to ' . $user['User']['email'] . ', titled "' . $subject . '" failed. Reason: Emailing is currently disabled on this instance.',
                    'change' => null,
            ));
            return true;
        }
        if (!empty($user['User']['disabled'])) {
            return true;
        }
        $failed = false;
        $failureReason = "";
        // check if the e-mail can be encrypted
        $canEncryptGPG = isset($user['User']['gpgkey']) && !empty($user['User']['gpgkey']);
        $canEncryptSMIME = isset($user['User']['certif_public']) && !empty($user['User']['certif_public']) && Configure::read('SMIME.enabled');

        // If bodyonlyencrypted is enabled and the user has no encryption key, use the alternate body (if it exists)
        if (Configure::read('GnuPG.bodyonlyencrypted') && !$canEncryptSMIME && !$canEncryptGPG && $bodyNoEnc) {
            $body = $bodyNoEnc;
        }
        $body = str_replace('\n', PHP_EOL, $body);

        $Email = new CakeEmail();
        // If we cannot encrypt the mail and the server settings restricts sending unencrypted messages, return false
        if (!$failed && Configure::read('GnuPG.onlyencrypted') && !$canEncryptGPG && !$canEncryptSMIME) {
            $failed = true;
            $failureReason = " encrypted messages are enforced and the message could not be encrypted for this user as no valid encryption key was found.";
        }
        // Let's encrypt the message if we can
        if (!$failed && $canEncryptGPG) {
            $encryptionResult = $this->__encryptUsingGPG($Email, $body, $subject, $user);
            if (isset($encryptionResult['failed'])) {
                $failed = true;
            }
            if (isset($encryptionResult['failureReason'])) {
                $failureReason = $encryptionResult['failureReason'];
            }
        }
        // SMIME if not GPG key
        if (!$failed && !$canEncryptGPG && $canEncryptSMIME) {
            $encryptionResult = $this->__encryptUsingSmime($Email, $body, $subject, $user);
            if (isset($encryptionResult['failed'])) {
                $failed = true;
            }
            if (isset($encryptionResult['failureReason'])) {
                $failureReason = $encryptionResult['failureReason'];
            }
        }
        $replyToLog = '';
        if (!$failed) {
            $result = $this->__finaliseAndSendEmail($replyToUser, $Email, $replyToLog, $user, $subject, $body);
        }
        $this->Log = ClassRegistry::init('Log');
        $this->Log->create();
        if (!$failed && $result) {
            $this->Log->save(array(
                    'org' => 'SYSTEM',
                    'model' => 'User',
                    'model_id' => $user['User']['id'],
                    'email' => $user['User']['email'],
                    'action' => 'email',
                    'title' => 'Email ' . $replyToLog  . ' to ' . $user['User']['email'] . ' sent, titled "' . $subject . '".',
                    'change' => null,
            ));
            return true;
        } else {
            if (empty($failureReason)) {
                $failureReason = " there was an error sending the e-mail.";
            }
            $this->Log->save(array(
                    'org' => 'SYSTEM',
                    'model' => 'User',
                    'model_id' => $user['User']['id'],
                    'email' => $user['User']['email'],
                    'action' => 'email',
                    'title' => 'Email ' . $replyToLog  . ' to ' . $user['User']['email'] . ', titled "' . $subject . '" failed. Reason: ' . $failureReason,
                    'change' => null,
            ));
        }
        return false;
    }

    private function __finaliseAndSendEmail($replyToUser, &$Email, &$replyToLog, $user, $subject, $body, $additionalAttachments = false)
    {
        // If the e-mail is sent on behalf of a user, then we want the target user to be able to respond to the sender
        // For this reason we should also attach the public key of the sender along with the message (if applicable)
        $attachments = array();
        if ($replyToUser != false) {
            $Email->replyTo($replyToUser['User']['email']);
            if (!empty($replyToUser['User']['gpgkey'])) {
                $attachments['gpgkey.asc'] = array(
                    'data' => $replyToUser['User']['gpgkey']
                );
            } elseif (!empty($replyToUser['User']['certif_public'])) {
                $attachments[$replyToUser['User']['email'] . '.pem'] = array(
                    'data' => $replyToUser['User']['certif_public']
                );
            }
            $replyToLog = 'from ' . $replyToUser['User']['email'];
        }
        $Email->from(Configure::read('MISP.email'));
        $Email->returnPath(Configure::read('MISP.email'));
        $Email->to($user['User']['email']);
        $Email->subject($subject);
        $Email->emailFormat('text');
        if (!empty($additionalAttachments)) {
            foreach ($additionalAttachments as $key => $value) {
                $attachments[$k] = array('data' => $value);
            }
        }
        $Email->attachments($attachments);
        $result = $Email->send($body);
        $Email->reset();
        return $result;
    }

    private function __encryptUsingGPG(&$Email, &$body, $subject, $user)
    {
        $failed = false;
        // Sign the body
        require_once 'Crypt/GPG.php';
        try {
            $gpg = new Crypt_GPG(array('homedir' => Configure::read('GnuPG.homedir'), 'gpgconf' => Configure::read('GnuPG.gpgconf'), 'binary' => (Configure::read('GnuPG.binary') ? Configure::read('GnuPG.binary') : '/usr/bin/gpg'), 'debug'));   // , 'debug' => true
            if (Configure::read('GnuPG.sign')) {
                $gpg->addSignKey(Configure::read('GnuPG.email'), Configure::read('GnuPG.password'));
                $body = $gpg->sign($body, Crypt_GPG::SIGN_MODE_CLEAR);
            }
        } catch (Exception $e) {
            $failureReason = " the message could not be signed. The following error message was returned by gpg: " . $e->getMessage();
            $this->log($e->getMessage());
            $failed = true;
        }
        if (!$failed) {
            $keyImportOutput = $gpg->importKey($user['User']['gpgkey']);
            try {
                $key = $gpg->getKeys($keyImportOutput['fingerprint']);
                $subKeys = $key[0]->getSubKeys();
                $canEncryptGPG = false;
                $currentTimestamp = time();
                foreach ($subKeys as $subKey) {
                    $expiration = $subKey->getExpirationDate();
                    if (($expiration == 0 || $currentTimestamp < $expiration) && $subKey->canEncrypt()) {
                        $canEncryptGPG = true;
                    }
                }
                if ($canEncryptGPG) {
                    $gpg->addEncryptKey($keyImportOutput['fingerprint']); // use the key that was given in the import
                    $body = $gpg->encrypt($body, true);
                } else {
                    $failed = true;
                    $failureReason = " the message could not be encrypted because the provided key is either expired or cannot be used for encryption.";
                }
            } catch (Exception $e) {
                // despite the user having a GnuPG key and the signing already succeeding earlier, we get an exception. This must mean that there is an issue with the user's key.
                $failureReason = " the message could not be encrypted because there was an issue with the user's GnuPG key. The following error message was returned by gpg: " . $e->getMessage();
                $this->log($e->getMessage());
                $failed = true;
            }
        }
        if (!empty($failed)) {
            return array('failed' => $failed, 'failureReason' => $failureReason);
        }
        return true;
    }

    private function __encryptUsingSmime(&$Email, &$body, $subject, $user)
    {
        try {
            $prependedBody = 'Content-Transfer-Encoding: 7bit' . PHP_EOL . 'Content-Type: text/plain;' . PHP_EOL . '    charset=us-ascii' . PHP_EOL . PHP_EOL . $body;
            App::uses('Folder', 'Utility');
            App::uses('FileAccessTool', 'Tools');
            $fileAccessTool = new FileAccessTool();
            $dir = APP . 'tmp' . DS . 'SMIME';
            if (!file_exists($dir)) {
                if (!mkdir($dir, 0750, true)) {
                    throw new MethodNotAllowedException('The SMIME temp directory is not writeable (app/tmp/SMIME).');
                }
            }
            // save message to file
            $tempFile = $fileAccessTool->createTempFile($dir, 'SMIME');
            $msg = $fileAccessTool->writeToFile($tempFile, $prependedBody);
            $headers_smime = array("To" => $user['User']['email'], "From" => Configure::read('MISP.email'), "Subject" => $subject);
            $canSign = true;
            if (
                !empty(Configure::read('SMIME.cert_public_sign')) &&
                is_readable(Configure::read('SMIME.cert_public_sign')) &&
                !empty(Configure::read('SMIME.key_sign')) &&
                is_readable(Configure::read('SMIME.key_sign'))
            ) {
                $signed = $fileAccessTool->createTempFile($dir, 'SMIME');
                if (openssl_pkcs7_sign($msg, $signed, 'file://'.Configure::read('SMIME.cert_public_sign'), array('file://'.Configure::read('SMIME.key_sign'), Configure::read('SMIME.password')), array(), PKCS7_TEXT)) {
                    $bodySigned = $fileAccessTool->readFromFile($signed);
                    unlink($msg);
                    unlink($signed);
                } else {
                    unlink($msg);
                    unlink($signed);
                    throw new Exception('Failed while attempting to sign the SMIME message.');
                }
                // save message to file
                $tempFile = $fileAccessTool->createTempFile($dir, 'SMIME');
                $msg_signed = $fileAccessTool->writeToFile($tempFile, $bodySigned);
            } else {
                $msg_signed = $msg;
            }
            $msg_signed_encrypted = $fileAccessTool->createTempFile($dir, 'SMIME');
            // encrypt it
            if (openssl_pkcs7_encrypt($msg_signed, $msg_signed_encrypted, $user['User']['certif_public'], $headers_smime, 0, OPENSSL_CIPHER_AES_256_CBC)) {
                $bodyEncSig = $fileAccessTool->readFromFile($msg_signed_encrypted);
                unlink($msg_signed);
                unlink($msg_signed_encrypted);
                $parts = explode("\n\n", $bodyEncSig);
                $bodyEncSig = $parts[1];
                // SMIME transport (hardcoded headers
                $Email = $Email->transport('Smime');
                $body = $bodyEncSig;
            } else {
                unlink($msg_signed);
                unlink($msg_signed_encrypted);
                throw new Exception('Could not encrypt the SMIME message.');
            }
        } catch (Exception $e) {
            // despite the user having a certificate. This must mean that there is an issue with the user's certificate.
            $result['failureReason'] = " the message could not be encrypted because there was an issue with the user's public certificate. The following error message was returned by openssl: " . $e->getMessage();
            $this->log($e->getMessage());
            $result['failed'] = true;
        }
        return $result;
    }

    public function adminMessageResolve($message)
    {
        $resolveVars = array('$contact' => 'MISP.contact', '$org' => 'MISP.org', '$misp' => 'MISP.baseurl');
        foreach ($resolveVars as $k => $v) {
            $v = Configure::read($v);
            $message = str_replace($k, $v, $message);
        }
        return $message;
    }

    public function fetchPGPKey($email)
    {
        App::uses('SyncTool', 'Tools');
        $syncTool = new SyncTool();
        $HttpSocket = $syncTool->setupHttpSocket();
        $response = $HttpSocket->get('https://pgp.circl.lu/pks/lookup?search=' . urlencode($email) . '&op=index&fingerprint=on&options=mr');
        if ($response->code != 200) {
            return $response->code;
        }
        return $this->__extractPGPInfo($response->body);
    }

    private function __extractPGPInfo($body)
    {
        $final = array();
        $lines = explode("\n", $body);
        foreach ($lines as $line) {
            $parts = explode(":", $line);

            if ($parts[0] === 'pub') {
                if (!empty($temp)) {
                    $final[] = $temp;
                    $temp = array();
                }

                if (strpos($parts[6], 'r') !== false || strpos($parts[6], 'd') !== false || strpos($parts[6], 'e') !== false) {
                    continue; // skip if key is expired, revoked or disabled
                }

                $temp = array(
                    'fingerprint' => chunk_split($parts[1], 4, ' '),
                    'key_id' => substr($parts[1], -8),
                    'date' => date('Y-m-d', $parts[4]),
                    'uri' => '/pks/lookup?op=get&search=0x' . $parts[1],
                );

            } else if ($parts[0] === 'uid' && !empty($temp)) {
                $temp['address'] = urldecode($parts[1]);
            }
        }

        if (!empty($temp)) {
            $final[] = $temp;
        }

        return $final;
    }

    public function describeAuthFields()
    {
        $fields = array();
        $fields = array_merge($fields, array_keys($this->getColumnTypes()));
        foreach ($fields as $k => $field) {
            if (in_array($field, array('gpgkey', 'certif_public'))) {
                unset($fields[$k]);
            }
        }
        $fields = array_values($fields);
        $relatedModels = array_keys($this->belongsTo);
        foreach ($relatedModels as $relatedModel) {
            $fields[] = $relatedModel . '.*';
        }
        return $fields;
    }

    public function getMembersCount($org_id = false)
    {
        // for Organizations List
        $conditions = array();
        $findType = 'all';
        if ($org_id !== false) {
            $findType = 'first';
            $conditions = array('User.org_id' => $org_id);
        }
        $fields = array('org_id', 'COUNT(User.id) AS num_members');
        $params = array(
                'fields' => $fields,
                'recursive' => -1,
                'group' => array('org_id'),
                'order' => array('org_id'),
                'conditions' => $conditions
        );
        $orgs = $this->find($findType, $params);
        if (empty($orgs)) {
            return 0;
        }
        if ($org_id !== false) {
            return $orgs[0]['num_members'];
        } else {
            $usersPerOrg = [];
            foreach ($orgs as $key => $value) {
                $usersPerOrg[$value['User']['org_id']] = $value[0]['num_members'];
            }
            return $usersPerOrg;
        }
    }

    public function findAdminsResponsibleForUser($user)
    {
        $admin = $this->find('first', array(
            'recursive' => -1,
            'conditions' => array(
                'Role.perm_admin' => 1,
                'User.disabled' => 0,
                'User.org_id' => $user['org_id']
            ),
            'contain' => array(
                'Role' => array('fields' => array('perm_admin'))
            ),
            'fields' => array('User.id', 'User.email', 'User.org_id')
        ));
        if (count($admin) == 0) {
            $admin = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array(
                    'Role.perm_site_admin' => 1,
                    'User.disabled' => 0,
                ),
                'contain' => array(
                    'Role' => array('fields' => array('perm_site_admin'))
                ),
                'fields' => array('User.id', 'User.email', 'User.org_id')
            ));
        }

        return $admin['User'];
    }

    public function initiatePasswordReset($user, $firstTime = false, $simpleReturn = false, $fixedPassword = false)
    {
        $org = Configure::read('MISP.org');
        $options = array('passwordResetText', 'newUserText');
        $subjects = array('[' . $org . ' MISP] New user registration', '[' . $org .  ' MISP] Password reset');
        $textToFetch = $options[($firstTime ? 0 : 1)];
        $subject = $subjects[($firstTime ? 0 : 1)];
        $this->Server = ClassRegistry::init('Server');
        $body = Configure::read('MISP.' . $textToFetch);
        if (!$body) {
            $body = $this->Server->serverSettings['MISP'][$textToFetch]['value'];
        }
        $body = $this->adminMessageResolve($body);
        if ($fixedPassword) {
            $password = $fixedPassword;
        } else {
            $password = $this->generateRandomPassword();
        }
        $body = str_replace('$password', $password, $body);
        $body = str_replace('$username', $user['User']['email'], $body);
        $result = $this->sendEmail($user, $body, false, $subject);
        if ($result) {
            $this->id = $user['User']['id'];
            $this->saveField('password', $password);
            $this->saveField('change_pw', '1');
            if ($simpleReturn) {
                return true;
            } else {
                return array('body'=> json_encode(array('saved' => true, 'success' => 'New credentials sent.')),'status'=>200);
            }
        }
        if ($simpleReturn) {
            return false;
        } else {
            return array('body'=> json_encode(array('saved' => false, 'errors' => 'There was an error notifying the user. His/her credentials were not altered.')),'status'=>200);
        }
    }

    public function getOrgAdminsForOrg($org_id, $excludeUserId = false)
    {
        $adminRoles = $this->Role->find('list', array(
            'recursive' => -1,
            'conditions' => array('perm_admin' => 1),
            'fields' => array('Role.id', 'Role.id')
        ));
        $conditions = array(
            'User.org_id' => $org_id,
            'User.disabled' => 0,
            'User.role_id' => $adminRoles
        );
        if ($excludeUserId) {
            $conditions['User.id !='] = $excludeUserId;
        }
        return $this->find('list', array(
            'recursive' => -1,
            'conditions' => $conditions,
            'fields' => array(
                'User.id', 'User.email'
            )
        ));
    }

    public function verifyPassword($user_id, $password)
    {
        $currentUser = $this->find('first', array(
            'conditions' => array('User.id' => $user_id),
            'recursive' => -1,
            'fields' => array('User.password')
        ));
        if (empty($currentUser)) {
            return false;
        }
        if (strlen($currentUser['User']['password']) == 40) {
            App::uses('SimplePasswordHasher', 'Controller/Component/Auth');
            $passwordHasher = new SimplePasswordHasher();
        } else {
            $passwordHasher = new BlowfishPasswordHasher();
        }
        $hashed = $passwordHasher->check($password, $currentUser['User']['password']);
        return $hashed;
    }

    public function createInitialUser($org_id)
    {
        $authKey = $this->generateAuthKey();
        $admin = array('User' => array(
            'id' => 1,
            'email' => 'admin@admin.test',
            'org_id' => $org_id,
            'password' => 'admin',
            'confirm_password' => 'admin',
            'authkey' => $authKey,
            'nids_sid' => 4000000,
            'newsread' => 0,
            'role_id' => 1,
            'change_pw' => 1
        ));
        $this->validator()->remove('password'); // password is too simple, remove validation
        $this->save($admin);
        return $authKey;
    }

    public function resetAllSyncAuthKeysRouter($user, $jobId = false)
    {
        if (Configure::read('MISP.background_jobs')) {
            $job = ClassRegistry::init('Job');
            $job->create();
            $eventModel = ClassRegistry::init('Event');
            $data = array(
                    'worker' => $eventModel->__getPrioWorkerIfPossible(),
                    'job_type' => __('reset_all_sync_api_keys'),
                    'job_input' => __('Reseting all API keys'),
                    'status' => 0,
                    'retries' => 0,
                    'org_id' => $user['org_id'],
                    'org' => $user['Organisation']['name'],
                    'message' => 'Issuing new API keys to all sync users.',
            );
            $job->save($data);
            $jobId = $job->id;
            $process_id = CakeResque::enqueue(
                    'prio',
                    'AdminShell',
                    array('resetSyncAuthkeys', $user['id'], $jobId),
                    true
            );
            $job->saveField('process_id', $process_id);
            return true;
        } else {
            return $this->resetAllSyncAuthKeys($user);
        }
    }

    public function resetAllSyncAuthKeys($user, $jobId = false)
    {
        $affected_users = $this->find('all', array(
            'recursive' => -1,
            'contain' => array('Role'),
            'conditions' => array(
                'OR' => array(
                    'Role.perm_sync' => 1,
                    'Role.perm_admin' => 1
                ),
                'Role.perm_site_admin' => 0
            )
        ));
        $results = array('success' => 0, 'fails' => 0);
        $user_count = count($affected_users);
        if ($jobId) {
            $job = ClassRegistry::init('Job');
            $existingJob = $job->find('first', array(
                'conditions' => array('Job.id' => $jobId),
                'recursive' => -1
            ));
            if (empty($existingJob)) {
                $jobId = false;
            }
        }
        foreach ($affected_users as $k => $affected_user) {
            try {
                $reset_result = $this->resetauthkey($user, $affected_user['User']['id'], true);
                if ($reset_result) {
                    $results['success'] += 1;
                } else {
                    $results['fails'] += 1;
                }
            } catch (Exception $e) {
                $results['fails'] += 1;
            }
            if ($jobId) {
                if ($k % 100 == 0) {
                    $job->id =  $jobId;
                    $job->saveField('progress', 100 * (($k + 1) / $user_count));
                    $job->saveField('message', __('Reset in progress - %s/%s.', $k, $user_count));
                }
            }
        }
        if ($jobId) {
            $message = __('%s authkeys reset, %s could not be reset', $results['success'], $results['fails']);
            $job->saveField('progress', 100);
            $job->saveField('message', $message);
            $job->saveField('status', 4);
        }
        return $results;
    }

    public function resetauthkey($user, $id, $alert = false)
    {
        $this->id = $id;
        if (!$id || !$this->exists($id)) {
            return false;
        }
        $updatedUser = $this->read();
        $oldKey = $this->data['User']['authkey'];
        if (empty($user['Role']['perm_site_admin']) && !($user['Role']['perm_admin'] && $user['org_id'] == $updatedUser['User']['org_id']) && ($user['id'] != $id)) {
            return false;
        }
        $newkey = $this->generateAuthKey();
        $this->saveField('authkey', $newkey);
        $this->extralog(
                $user,
                'reset_auth_key',
                sprintf(
                    __('Authentication key for user %s (%s) updated.'),
                    $updatedUser['User']['id'],
                    $updatedUser['User']['email']
                ),
                $fieldsResult = 'authkey(' . $oldKey . ') => (' . $newkey . ')',
                $updatedUser
        );
        if ($alert) {
            $baseurl = Configure::read('MISP.external_baseurl');
            if (empty($baseurl)) {
                $baseurl = Configure::read('MISP.baseurl');
            }
            $body = __(
                "Dear user,\n\nan API key reset has been triggered by an administrator for your user account on %s.\n\nYour new API key is: %s\n\nPlease update your server's sync setup to reflect this change.\n\nWe apologise for the inconvenience.",
                $baseurl,
                $newkey
            );
            $bodyNoEnc = __(
                "Dear user,\n\nan API key reset has been triggered by an administrator for your user account on %s.\n\nYour new API key can be retrieved by logging in using this sync user's account.\n\nPlease update your server's sync setup to reflect this change.\n\nWe apologise for the inconvenience.",
                $baseurl,
                $newkey
            );
            $this->sendEmail(
                $updatedUser,
                $body,
                $bodyNoEnc,
                __('API key reset by administrator')
            );
        }
        return $newkey;
    }

    public function extralog($user, $action = null, $description = null, $fieldsResult = null, $modifiedUser = null)
    {
        // new data
        $model = 'User';
        $modelId = $user['id'];
        if (!empty($modifiedUser)) {
            $modelId = $modifiedUser['User']['id'];
        }
        if ($action == 'login') {
            $description = "User (" . $user['id'] . "): " . $user['email'];
        } elseif ($action == 'logout') {
            $description = "User (" . $user['id'] . "): " . $user['email'];
        } elseif ($action == 'edit') {
            $description = "User (" . $modifiedUser['User']['id'] . "): " . $modifiedUser['User']['email'];
        } elseif ($action == 'change_pw') {
            $description = "User (" . $modifiedUser['User']['id'] . "): " . $modifiedUser['User']['email'];
            $fieldsResult = "Password changed.";
        }

        // query
        $this->Log = ClassRegistry::init('Log');
        $this->Log->create();
        $this->Log->save(array(
            'org' => $user['Organisation']['name'],
            'model' => $model,
            'model_id' => $modelId,
            'email' => $user['email'],
            'action' => $action,
            'title' => $description,
            'change' => isset($fieldsResult) ? $fieldsResult : ''));

        // write to syslogd as well
        App::import('Lib', 'SysLog.SysLog');
        $syslog = new SysLog();
        $syslog->write('notice', $description . ' -- ' . $action . (empty($fieldResult) ? '' : '-- ' . $fieldResult));
    }

    /**
     * @return Crypt_GPG
     * @throws Exception
     */
    private function initializeGpg()
    {
        if (!class_exists('Crypt_GPG')) {
            if (!stream_resolve_include_path('Crypt/GPG.php')) {
                throw new Exception("Crypt_GPG is not installed.");
            }
            require_once 'Crypt/GPG.php';
        }

        $homedir = Configure::read('GnuPG.homedir');
        if ($homedir === null) {
            throw new Exception("Configuration option 'GnuPG.homedir' is not set, Crypt_GPG cannot be initialized.");
        }

        $options = array(
            'homedir' => $homedir,
            'gpgconf' => Configure::read('GnuPG.gpgconf'),
            'binary' => Configure::read('GnuPG.binary') ?: '/usr/bin/gpg',
        );

        return new Crypt_GPG($options);
    }
}
