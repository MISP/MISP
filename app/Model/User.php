<?php
App::uses('AppModel', 'Model');
App::uses('AuthComponent', 'Controller/Component');
App::uses('RandomTool', 'Tools');
App::uses('GpgTool', 'Tools');
App::uses('SendEmail', 'Tools');

/**
 * @property Log $Log
 * @property Organisation $Organisation
 * @property Role $Role
 * @property UserSetting $UserSetting
 */
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
        'UserSetting',
        // 'AuthKey' - readd once the initial update storm is over
    );

    public $actsAs = array(
        'AuditLog',
        'SysLogLogable.SysLogLogable' => array(
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'full',
            'ignore' => array('password')
        ),
        'Trim',
        'Containable'
    );

    public function __construct($id = false, $table = null, $ds = null) {
        parent::__construct();
        $this->AdminSetting = ClassRegistry::init('AdminSetting');
        $db_version = $this->AdminSetting->find('first', [
            'recursive' => -1,
            'conditions' => ['setting' => 'db_version'],
            'fields' => ['value']
        ]);
        if ($db_version['AdminSetting']['value'] >= 62) {
            $this->bindModel([
                'hasMany' => ['AuthKey']
            ], false);
        }
    }

    /** @var CryptGpgExtended|null|false */
    private $gpg;

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

    /**
     * Checks if the GnuPG key is a valid key.
     * @param array $check
     * @return bool
     */
    public function validateGpgkey($check)
    {
        // LATER first remove the old gpgkey from the keychain
        // empty value
        if (empty($check['gpgkey'])) {
            return true;
        }

        // we have a clean, hopefully public, key here
        $gpg = $this->initializeGpg();
        if (!$gpg) {
            return true;
        }
        try {
            $gpgTool = new GpgTool($gpg);
            $gpgTool->validateGpgKey($check['gpgkey']);
            return true;
        } catch (Exception $e) {
            $this->logException("Exception during validating GPG key", $e, LOG_NOTICE);
            return false;
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

    /**
     * 0 - true if key is valid
     * 1 - User e-mail
     * 2 - Error message
     * 3 - Not used
     * 4 - Key fingerprint
     * 5 - Key fingerprint
     * @param array $user
     * @return array
     */
    public function verifySingleGPG(array $user)
    {
        $result = [0 => false, 1 => $user['User']['email']];

        $gpg = $this->initializeGpg();
        if (!$gpg) {
            $result[2] = 'GnuPG is not configured on this system.';
            return $result;
        }

        try {
            $currentTimestamp = time();
            $keys = $gpg->keyInfo($user['User']['gpgkey']);
            if (count($keys) !== 1) {
                $result[2] = 'Multiple or no key found';
                return $result;
            }

            $key = $keys[0];
            $result[4] = $key->getPrimaryKey()->getFingerprint();
            $result[5] = $result[4];

            $sortedKeys = ['valid' => 0, 'expired' => 0, 'noEncrypt' => 0];
            foreach ($key->getSubKeys() as $subKey) {
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
            } else {
                $result[0] = true;
            }
        } catch (Exception $e) {
            $result[2] = $e->getMessage();
        }
        return $result;
    }

    public function verifyGPG($id = false)
    {
        $this->Behaviors->detach('Trim');
        $conditions = array('not' => array('gpgkey' => ''));
        if ($id !== false) {
            $conditions['User.id'] = $id;
        }
        $users = $this->find('all', array(
            'conditions' => $conditions,
            'recursive' => -1,
        ));
        if (empty($users)) {
            return [];
        }
        $gpg = $this->initializeGpg();
        if (!$gpg) {
            return [];
        }
        $results = [];
        foreach ($users as $k => $user) {
            $results[$user['User']['id']] = $this->verifySingleGPG($user);
        }
        return $results;
    }

    private function testSmimeCertificate($certif_public)
    {
        $sendEmail = new SendEmail();
        try {
            $sendEmail->testSmimeCertificate($certif_public);
            return true;
        } catch (Exception $e) {
            if ($e->getPrevious()) {
                return $e->getMessage() . ": " . $e->getPrevious()->getMessage();
            }

            return $e->getMessage();
        }
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

    /**
     * If you want to check if user has GPG or X.509 or send encrypted emails to that user, you need user keys. But by
     * default, keys are part of default user model. This method add that keys to user model.
     *
     * @param array $user
     * @return array
     * @throws Exception
     */
    public function fillKeysToUser(array $user)
    {
        if (empty($user['id'])) {
            throw new InvalidArgumentException("Invalid user model provided, not ID found.");
        }
        $result = $this->find('first', array(
            'recursive' => -1,
            'fields' => array('certif_public', 'gpgkey'),
            'conditions' => array('id' => $user['id']),
        ));
        if (!$result) {
            throw new Exception("User with ID {$user['id']} not found.");
        }
        $user['gpgkey'] = $result['User']['gpgkey'];
        $user['certif_public'] = $result['User']['certif_public'];
        return $user;
    }

    /**
     * @param int $id
     * @return array|null
     */
    public function getUserById($id)
    {
        if (empty($id)) {
            throw new NotFoundException('Invalid user ID.');
        }
        return $this->find(
            'first',
            array(
                'conditions' => array('User.id' => $id),
                'recursive' => -1,
                'contain' => array(
                    'Organisation',
                    'Role',
                    'Server',
                    'UserSetting',
                )
            )
        );
    }

    // get the current user and rearrange it to be in the same format as in the auth component
    public function getAuthUser($id)
    {
        if (empty($id)) {
            throw new InvalidArgumentException('Invalid user ID.');
        }
        $conditions = ['User.id' => $id];
        return $this->getAuthUserByConditions($conditions);
    }

    // get the current user and rearrange it to be in the same format as in the auth component
    public function getAuthUserByAuthkey($authkey)
    {
        if (empty($authkey)) {
            throw new InvalidArgumentException('Invalid user auth key.');
        }
        $conditions = array('User.authkey' => $authkey);
        return $this->getAuthUserByConditions($conditions);
    }

    public function getAuthUserByExternalAuth($auth_key)
    {
        if (empty($auth_key)) {
            throw new InvalidArgumentException('Invalid user external auth key.');
        }
        $conditions = array(
            'User.external_auth_key' => $auth_key,
            'User.external_auth_required' => true
        );
        return $this->getAuthUserByConditions($conditions);
    }

    /**
     * @param array $conditions
     * @return array|null
     */
    private function getAuthUserByConditions(array $conditions)
    {
        $user = $this->find('first', [
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => [
                'Organisation',
                'Role',
                'Server',
            ],
        ]);
        if (empty($user)) {
            return $user;
        }
        return $this->rearrangeToAuthForm($user);
    }

    /**
     * User model is a mess. Sometimes it is necessary to convert User model to form that is created during the login
     * process. This method do that work for you.
     *
     * @param array $user
     * @return array
     */
    public function rearrangeToAuthForm(array $user)
    {
        if (!isset($user['User'])) {
            throw new InvalidArgumentException('Invalid user model provided.');
        }

        $user['User']['Role'] = $user['Role'];
        $user['User']['Organisation'] = $user['Organisation'];
        $user['User']['Server'] = $user['Server'];
        return $user['User'];
    }

    // Fetch all users that have access to an event / discussion for e-mailing (or maybe something else in the future.
    // parameters are an array of org IDs that are owners (for an event this would be orgc and org)
    public function getUsersWithAccess($owners = array(), $distribution, $sharing_group_id = 0, $userConditions = array())
    {
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
            $sgModel = ClassRegistry::init('SharingGroup');
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
            'fields' => array('id', 'email', 'gpgkey', 'certif_public', 'org_id', 'disabled'),
            'contain' => ['Role' => ['fields' => ['perm_site_admin', 'perm_audit']], 'Organisation' => ['fields' => ['id', 'name']]],
        ));
        foreach ($users as $k => $user) {
            $user = $user['User'];
            unset($users[$k]['User']);
            $users[$k] = array_merge($user, $users[$k]);
        }
        return $users;
    }

    /**
     * @param $user - deprecated
     * @param array $params
     * @throws Crypt_GPG_Exception
     * @throws SendEmailException
     */
    public function sendEmailExternal($user, array $params)
    {
        $gpg = $this->initializeGpg();
        $sendEmail = new SendEmail($gpg);
        $sendEmail->sendExternal($params);
    }

    /**
     * All e-mail sending is now handled by this method
     * Just pass the user array that is the target of the e-mail along with the message body and the alternate message body if the message cannot be encrypted
     * the remaining two parameters are the e-mail subject and a secondary user object which will be used as the replyto address if set. If it is set and an encryption key for the replyTo user exists, then his/her public key will also be attached
     *
     * @param array $user
     * @param SendEmailTemplate|string $body
     * @param string|false $bodyNoEnc
     * @param string $subject
     * @param array|false $replyToUser
     * @return bool
     * @throws Crypt_GPG_BadPassphraseException
     * @throws Crypt_GPG_Exception
     */
    public function sendEmail(array $user, $body, $bodyNoEnc = false, $subject, $replyToUser = false)
    {
        if ($user['User']['disabled']) {
            return true;
        }

        $this->loadLog();
        $replyToLog = $replyToUser ? ' from ' . $replyToUser['User']['email'] : '';

        $gpg = $this->initializeGpg();
        $sendEmail = new SendEmail($gpg);
        try {
            $result = $sendEmail->sendToUser($user, $subject, $body, $bodyNoEnc,$replyToUser ?: []);

        } catch (SendEmailException $e) {
            $this->logException("Exception during sending e-mail", $e);
            $this->Log->create();
            $this->Log->save(array(
                'org' => 'SYSTEM',
                'model' => 'User',
                'model_id' => $user['User']['id'],
                'email' => $user['User']['email'],
                'action' => 'email',
                'title' => 'Email' . $replyToLog . ' to ' . $user['User']['email'] . ', titled "' . $subject . '" failed. Reason: ' . $e->getMessage(),
                'change' => null,
            ));
            return false;
        }

        $logTitle = $result['encrypted'] ? 'Encrypted email' : 'Email';
        // Intentional two spaces to pass test :)
        $logTitle .= $replyToLog  . '  to ' . $user['User']['email'] . ' sent, titled "' . $result['subject'] . '".';

        $this->Log->create();
        $this->Log->save(array(
            'org' => 'SYSTEM',
            'model' => 'User',
            'model_id' => $user['User']['id'],
            'email' => $user['User']['email'],
            'action' => 'email',
            'title' => $logTitle,
            'change' => null,
        ));
        return true;
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

    /**
     * @param string $email
     * @return array
     * @throws Exception
     */
    public function searchGpgKey($email)
    {
        $gpgTool = new GpgTool(null);
        return $gpgTool->searchGpgKey($email);
    }

    /**
     * @param string $fingerprint
     * @return string|null
     * @throws Exception
     */
    public function fetchGpgKey($fingerprint)
    {
        $gpgTool = new GpgTool($this->initializeGpg());
        return $gpgTool->fetchGpgKey($fingerprint);
    }

    /**
     * Returns fields that should be fetched from database.
     * @return array
     */
    public function describeAuthFields()
    {
        $fields = $this->schema();
        // Do not include keys, because they are big and usually not necessary
        unset($fields['gpgkey']);
        unset($fields['certif_public']);
        $fields = array_keys($fields);

        foreach ($this->belongsTo as $relatedModel => $foo) {
            $fields[] = $relatedModel . '.*';
        }
        return $fields;
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
        $options = array('newUserText', 'passwordResetText');
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
        $body = str_replace('\n', PHP_EOL, $body);
        $result = $this->sendEmail($user, $body, false, $subject);
        if ($result) {
            $this->id = $user['User']['id'];
            $this->saveField('password', $password);
            $this->updateField($user['User'], 'change_pw', 1);
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
        $adminRoles = $this->Role->find('column', array(
            'conditions' => array('perm_admin' => 1),
            'fields' => array('Role.id')
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
            $data = array(
                'worker' => 'prio',
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

    public function resetauthkey($user, $id, $alert = false, $keyId = null)
    {
        $this->id = $id;
        if (!$id || !$this->exists($id)) {
            return false;
        }
        $updatedUser = $this->read();
        if (empty($user['Role']['perm_site_admin']) && !($user['Role']['perm_admin'] && $user['org_id'] == $updatedUser['User']['org_id']) && ($user['id'] != $id)) {
            return false;
        }
        if (empty(Configure::read('Security.advanced_authkeys'))) {
            $oldKey = $this->data['User']['authkey'];
            $newkey = $this->generateAuthKey();
            $this->updateField($updatedUser['User'], 'authkey', $newkey);
            $this->extralog(
                    $user,
                    'reset_auth_key',
                    __('Authentication key for user %s (%s) updated.',
                        $updatedUser['User']['id'],
                        $updatedUser['User']['email']
                    ),
                    $fieldsResult = ['authkey' =>  [$oldKey, $newkey]],
                    $updatedUser
            );
        } else {
            $this->AuthKey = ClassRegistry::init('AuthKey');
            $newkey = $this->AuthKey->resetAuthKey($id, $keyId);
        }
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
        $result = $this->Log->createLogEntry($user, $action, $model, $modelId, $description, $fieldsResult);

        // write to syslogd as well
        App::import('Lib', 'SysLog.SysLog');
        $syslog = new SysLog();
        $syslog->write('notice', "$description -- $action" . (empty($fieldResult) ? '' : ' -- ' . $result['Log']['change']));
    }

    /**
     * @return array|null
     * @throws Exception
     */
    public function getGpgPublicKey()
    {
        $email = Configure::read('GnuPG.email');
        if (!$email) {
            throw new Exception("Configuration option 'GnuPG.email' is not set, public key cannot be exported.");
        }

        $cryptGpg = $this->initializeGpg();
        $fingerprint = $cryptGpg->getFingerprint($email);
        if (!$fingerprint) {
            return null;
        }

        $publicKey = $cryptGpg->exportPublicKey($fingerprint);
        return array($fingerprint, $publicKey);
    }

    public function getOrgActivity($orgId, $params=array())
    {
        $conditions = array();
        $options = array();
        foreach($params as $paramName => $value) {
            $options['filter'] = $paramName;
            $filterParam[$paramName] = $value;
            $conditions = $this->Event->set_filter_timestamp($filterParam, $conditions, $options);
        }
        $conditions['Event.orgc_id'] = $orgId;
        $events = $this->Event->find('all', array(
            'recursive' => -1,
            'fields' => array('Event.orgc_id', 'Event.timestamp', 'Event.attribute_count'),
            'conditions' => $conditions,
            'order' => 'Event.timestamp'
        ));
        $sparklineData = array();
        foreach ($events as $event) {
            $date = date("Y-m-d", $event['Event']['timestamp']);
            if (!isset($sparklineData[$event['Event']['attribute_count']][$date])) {
                $sparklineData[$date] = $event['Event']['attribute_count'];
            } else {
                $sparklineData[$date] += $event['Event']['attribute_count'];
            }
        }

        // get first and last timestamp
        if (isset($params['from'])) {
            $startDate = $params['from'];
        } else {
            $startDate = $this->resolveTimeDelta($params['event_timestamp']);
        }
        if (isset($params['to'])) {
            $endDate = $params['to'];
        } else {
            $endDate = time();
        }
        $dates = array();
        for ($d=$startDate; $d < $endDate; $d=$d+3600*24) {
            $dates[] = date('Y-m-d', $d);
        }
        $csv = 'Date,Close\n';
        foreach ($dates as $date) {
            $csv .= sprintf('%s,%s\n', $date, isset($sparklineData[$date]) ? $sparklineData[$date] : 0);
        }
        $data = array(
            'csv' => $csv,
            'data' => $sparklineData,
            'orgId' => $orgId
        );
        return $data;
    }

    public function registerUser($added_by, $registration, $org_id, $role_id) {
        $user = array(
                'email' => $registration['data']['email'],
                'gpgkey' => empty($registration['data']['pgp']) ? '' : $registration['data']['pgp'],
                'disabled' => 0,
                'newsread' => 0,
                'change_pw' => 1,
                'authkey' => $this->generateAuthKey(),
                'termsaccepted' => 0,
                'org_id' => $org_id,
                'role_id' => $role_id,
                'invited_by' => $added_by['id'],
                'contactalert' => 1,
                'autoalert' => Configure::check('MISP.default_publish_alert') ? Configure::read('MISP.default_publish_alert') : 1
        );
        $this->create();
        $this->Log = ClassRegistry::init('Log');
        $result = $this->save(array('User' => $user));
        $currentOrg = $this->Organisation->find('first', array(
            'recursive' => -1,
            'conditions' => array('Organisation.id' => $org_id)
        ));
        if (!empty($currentOrg) && empty($currentOrg['Organisation']['local'])) {
            $currentOrg['Organisation']['local'] = 1;
            $this->Organisation->save($currentOrg);
        }
        if (empty($result)) {
            $error = array();
            foreach ($this->validationErrors as $key => $errors) {
                $error[$key] = $key . ': ' . implode(', ', $errors);
            }
            $error = implode(PHP_EOL, $error);
            $this->Log->save(array(
                    'org' => 'SYSTEM',
                    'model' => 'User',
                    'model_id' => $added_by['id'],
                    'email' => $added_by['email'],
                    'action' => 'registration_error',
                    'title' => 'User registration failed for ' . $user['email'] . '. Reason(s): ' . $error,
                    'change' => null,
            ));
            return false;
        } else {
            $user = $this->find('first', array(
                'recursive' => -1,
                'conditions' => array('id' => $this->id)
            ));
            $this->Log->save(array(
                'org' => 'SYSTEM',
                'model' => 'User',
                'model_id' => $added_by['id'],
                'email' => $added_by['email'],
                'action' => 'registration',
                'title' => sprintf('User registration success for %s (id=%s)', $user['User']['email'], $user['User']['id']),
                'change' => null,
            ));
            $this->initiatePasswordReset($user, true, true, false);
            $this->Inbox = ClassRegistry::init('Inbox');
            $this->Inbox->delete($registration['id']);
            return true;
        }
    }

    /**
     * Updates `current_login` and `last_login` time in database.
     *
     * @param array $user
     * @return array|bool
     * @throws Exception
     */
    public function updateLoginTimes(array $user)
    {
        if (!isset($user['id'])) {
            throw new InvalidArgumentException("Invalid user object provided.");
        }
        $user['action'] = 'login'; // for afterSave callbacks
        $user['last_login'] = $user['current_login'];
        $user['current_login'] = time();
        return $this->save($user, true, array('id', 'last_login', 'current_login'));
    }

    /**
     * Update field in user model and also set `date_modified`
     *
     * @param array $user
     * @param string $name
     * @param mixed $value
     * @throws Exception
     */
    public function updateField(array $user, $name, $value)
    {
        if (!isset($user['id'])) {
            throw new InvalidArgumentException("Invalid user object provided.");
        }
        $success = $this->save([
            'id' => $user['id'],
            $name => $value,
        ], true, ['id', $name, 'date_modified']);
        if (!$success) {
            throw new RuntimeException("Could not save setting $name for user {$user['id']}.");
        }
    }

    /**
     * Initialize GPG. Returns `null` if initialization failed.
     *
     * @return null|CryptGpgExtended
     */
    private function initializeGpg()
    {
        if ($this->gpg !== null) {
            if ($this->gpg === false) { // initialization failed
                return null;
            }

            return $this->gpg;
        }

        try {
            $this->gpg = GpgTool::initializeGpg();
            return $this->gpg;
        } catch (Exception $e) {
            $this->logException("GPG couldn't be initialized, GPG encryption and signing will be not available.", $e, LOG_NOTICE);
            $this->gpg = false;
            return null;
        }
    }
}
