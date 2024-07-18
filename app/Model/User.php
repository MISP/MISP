<?php
App::uses('AppModel', 'Model');
App::uses('AuthComponent', 'Controller/Component');
App::uses('RandomTool', 'Tools');
App::uses('GpgTool', 'Tools');
App::uses('SendEmail', 'Tools');
App::uses('SendEmailTemplate', 'Tools');
App::uses('BlowfishConstantPasswordHasher', 'Controller/Component/Auth');

/**
 * @property Log $Log
 * @property Organisation $Organisation
 * @property Role $Role
 * @property UserSetting $UserSetting
 * @property UserLoginProfile $UserLoginProfile
 * @property Event $Event
 * @property AuthKey $AuthKey
 * @property Server $Server
 */
class User extends AppModel
{
    private const PERIODIC_USER_SETTING_KEY = 'periodic_notification_filters';
    public const PERIODIC_NOTIFICATIONS = ['notification_daily', 'notification_weekly', 'notification_monthly'];

    public $displayField = 'email';

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
            'emailValidation' => array(
                'rule' => array('validateEmail'),
                'message' => 'Please enter a valid email address.',
                'required' => true,
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
        'UserLoginProfile'
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

    public const HEARTBEAT_MESSAGES = [
        'You must construct additional pylons.',
        'You\'ve not enough minerals.',
        'You require more vespene gas.',
        'Additional supply depots required.',
        'Not enough minerals.',
        'Insufficient vespene gas.',
        'Spawn more overlords.',
        'We require more minerals.',
        'We require more vespene gas.'
    ];

    /** @var CryptGpgExtended|null|false */
    private $gpg;

    public function __construct($id = false, $table = null, $ds = null)
    {
        parent::__construct($id, $table, $ds);

        // bind AuthKey just when authkey table already exists. This is important for updating from old versions
        if (in_array('auth_keys', $this->getDataSource()->listSources(), true)) {
            $this->bindModel([
                'hasMany' => ['AuthKey']
            ], false);
        }
    }

    public function beforeValidate($options = array())
    {
        $user = &$this->data['User'];
        if (!isset($user['id'])) {
            if ((isset($user['enable_password']) && !$user['enable_password']) || (empty($user['password']) && empty($user['confirm_password']))) {
                $user['password'] = $this->generateRandomPassword();
                $user['confirm_password'] = $user['password'];
            }
        }
        if (empty($user['certif_public'])) {
            $user['certif_public'] = '';
        }
        if (empty($user['authkey'])) {
            $user['authkey'] = $this->generateAuthKey();
        }
        if (empty($user['nids_sid'])) {
            $user['nids_sid'] = mt_rand(1000000, 9999999);
        }
        if (!empty(Configure::read('Security.limit_site_admins_to_host_org'))){
            if (!empty($user['role_id']) and !empty($user['org_id'] and $user['org_id'] != Configure::read('MISP.host_org_id'))){
                $role = $this->Role->find('first', array(
                    'conditions' => array('Role.id' => $user['role_id'])
                ));
                if (!empty($role) and $role['Role']['perm_site_admin'] === true){
                    $this->invalidate('role_id', "Site admin roles can only be assigned to users of the host org on this instance.");
                }
            }
        }
        return true;
    }

    public function beforeSave($options = [])
    {
        $user = &$this->data[$this->alias];
        $user['date_modified'] = time();

        if (isset($user['password'])) {
            $passwordHasher = new BlowfishConstantPasswordHasher();
            $user['password'] = $passwordHasher->hash($user['password']);
        }

        if (
            empty($user['action']) ||
            (
                $user['action'] !== 'logout' &&
                $user['action'] !== 'login'
            )
        ) {
            $action = empty($this->id) ? 'add' : 'edit';
            $user_id = $action === 'add' ? 0 : $user['id'];
            $trigger_id = 'user-before-save';
            $workflowErrors = [];
            $logging = [
                'model' => 'User',
                'action' => $action,
                'id' => $user_id,
                'message' => __('The workflow `%s` prevented the saving of user %s', $trigger_id, $user_id),
            ];
            return $this->executeTrigger($trigger_id, $user, $workflowErrors, $logging);
        }
        return true;
    }

    public function afterSave($created, $options = array())
    {
        $pubToZmq = $this->pubToZmq('user');
        $kafkaTopic = $this->kafkaTopic('user');
        $action = empty($created) ? 'edit' : 'add';
        $user = $this->data;
        if (
            empty($user['User']['action']) ||
            (
                $user['User']['action'] != 'logout' &&
                $user['User']['action'] != 'login'
            )
        ) {
            $workflowErrors = [];
            $logging = [
                'model' => 'User',
                'action' => $action,
                'id' => $user['User']['id'],
            ];
            $this->executeTrigger('user-after-save', $user['User'], $workflowErrors, $logging);
        }
        if ($pubToZmq || $kafkaTopic) {
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
                if ($kafkaTopic) {
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

    public function validateEmail($check)
    {
        $localPartReg = '[\p{L}0-9!#$%&\'*+\/=?^_`{|}~-]+(?:\.[\p{L}0-9!#$%&\'*+\/=?^_`{|}~-]+)*@';
        $domainReg = '[a-z0-9_\-\.]+';
        $fullReg = sprintf('/^%s%s$/ui', $localPartReg, $domainReg);
        $check = array_values($check);
        $check = $check[0];
        return preg_match($fullReg, $check, $matches) ? true : false;
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
        $v1 = array_values($field)[0];
        $v2 = $this->data[$this->name][$compareField];
        return $v1 === $v2;
    }

    public function generateAuthKey()
    {
        return RandomTool::random_str(true, 40);
    }

    /**
     * Generates a cryptographically secure password
     *
     * @param int $passwordLength
     * @return string
     * @throws Exception
     */
    public function generateRandomPassword($passwordLength = 40)
    {
        // makes sure, the password policy isn't undermined by setting a manual passwordLength
        $policyPasswordLength = Configure::read('Security.password_policy_length') ?: false;
        if (is_int($policyPasswordLength) && $policyPasswordLength > $passwordLength) {
            $passwordLength = $policyPasswordLength;
        }
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-+=!@#$%^&*()<>/?';
        return RandomTool::random_str(true, $passwordLength, $characters);
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
                $result[2] = 'The user\'s PGP key does not include a valid subkey that could be used for encryption.';
                if ($sortedKeys['expired']) {
                    $result[2] .= ' ' . __n('Found %s subkey that have expired.', 'Found %s subkeys that have expired.', $sortedKeys['expired'], $sortedKeys['expired']);
                }
                if ($sortedKeys['noEncrypt']) {
                    $result[2] .= ' ' . __n('Found %s subkey that is sign only.', 'Found %s subkeys that are sign only.', $sortedKeys['noEncrypt'], $sortedKeys['noEncrypt']);
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
            'fields' => ['id', 'email', 'gpgkey'],
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
        foreach ($users as $user) {
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
            throw new InvalidArgumentException('Invalid user ID.');
        }
        return $this->find('first', [
            'conditions' => ['User.id' => $id],
            'recursive' => -1,
            'contain' => [
                'Organisation',
                'Role',
                'Server',
                'UserSetting',
            ]
        ]);
    }

    /**
     * Get the current user and rearrange it to be in the same format as in the auth component.
     * @param int $id
     * @param bool $full
     * @return array|null
     */
    public function getAuthUser($id, $full = false)
    {
        if (empty($id)) {
            throw new InvalidArgumentException('Invalid user ID.');
        }
        $conditions = ['User.id' => $id];
        return $this->getAuthUserByConditions($conditions, $full);
    }

    /**
     * Get the current user and rearrange it to be in the same format as in the auth component.
     * @param string $authkey
     * @return array|null
     */
    public function getAuthUserByAuthkey($authkey)
    {
        if (empty($authkey)) {
            throw new InvalidArgumentException('Invalid user auth key.');
        }
        $conditions = array('User.authkey' => $authkey);
        return $this->getAuthUserByConditions($conditions);
    }

    /**
     * @param string $auth_key
     * @return array|null
     */
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
     * Get user model with Role, Organisation and Server, but without PGP and S/MIME keys
     * @param array $conditions
     * @param bool $full When true, fetch all user fields.
     * @return array|null
     */
    private function getAuthUserByConditions(array $conditions, $full = false)
    {
        $user = $this->find('first', [
            'conditions' => $conditions,
            'fields' => $full ? [] : $this->describeAuthFields(),
            'recursive' => -1,
            'contain' => [
                'Organisation',
                'Role',
                'Server',
            ],
        ]);
        if (empty($user)) {
            return null;
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
        if (isset($user['Server'])) {
            $user['User']['Server'] = $user['Server'];
        }
        if (isset($user['UserSetting'])) {
            $user['User']['UserSetting'] = $user['UserSetting'];
        }
        return $user['User'];
    }

    /**
     * Fetch all users that have access to an event / discussion for e-mailing (or maybe something else in the future.
     * parameters are an array of org IDs that are owners (for an event this would be orgc and org)
     * @param array $owners Event owners
     * @param int $distribution
     * @param int $sharing_group_id
     * @param array $userConditions
     * @return array|int
     */
    public function getUsersWithAccess(array $owners, $distribution, $sharing_group_id = 0, array $userConditions = [])
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
            $siteAdminRoleIds = $this->Role->find('column', [
                'conditions' => array('perm_site_admin' => 1),
                'fields' => array('id'),
            ]);
            $conditions['AND']['OR'][] = array('role_id' => $siteAdminRoleIds);
        }
        $conditions['AND'][] = $userConditions;
        $users = $this->find('all', array(
            'conditions' => $conditions,
            'recursive' => -1,
            'fields' => array('id', 'email', 'gpgkey', 'certif_public', 'org_id', 'disabled'),
            'contain' => [
                'Role' => ['fields' => ['perm_site_admin', 'perm_audit']],
                'Organisation' => ['fields' => ['id', 'name']]
            ],
        ));
        foreach ($users as $k => $user) {
            $users[$k] = $this->rearrangeToAuthForm($user);
        }
        return $users;
    }

    /**
     * @param array $params
     * @return array|bool
     * @throws Crypt_GPG_Exception
     * @throws SendEmailException
     */
    public function sendEmailExternal(array $params)
    {
        $gpg = $this->initializeGpg();
        $sendEmail = new SendEmail($gpg);
        return $sendEmail->sendExternal($params);
    }

    /**
     * All e-mail sending is now handled by this method
     * Just pass the user array that is the target of the e-mail along with the message body and the alternate message body if the message cannot be encrypted
     * the remaining two parameters are the e-mail subject and a secondary user object which will be used as the replyto address if set. If it is set and an encryption key for the replyTo user exists, then his/her public key will also be attached
     *
     * @param array $user
     * @param SendEmailTemplate|string $body
     * @param string|false $bodyNoEnc
     * @param string|null $subject
     * @param array|false $replyToUser
     * @return bool
     * @throws Crypt_GPG_BadPassphraseException
     * @throws Crypt_GPG_Exception
     */
    public function sendEmail(array $user, $body, $bodyNoEnc = false, $subject, $replyToUser = false)
    {
        if (Configure::read('MISP.disable_emailing')) {
            return true;
        }

        if (!isset($user['User'])) {
            throw new InvalidArgumentException("Invalid user model provided.");
        }

        if ($user['User']['disabled'] || !$this->checkIfUserIsValid($user['User'])) {
            return true;
        }

        $log = $this->loadLog();
        $replyToLog = $replyToUser ? ' from ' . $replyToUser['User']['email'] : '';

        $gpg = $this->initializeGpg();
        $sendEmail = new SendEmail($gpg);
        try {
            $result = $sendEmail->sendToUser($user, $subject, $body, $bodyNoEnc,$replyToUser ?: []);

        } catch (SendEmailException $e) {
            $this->logException("Exception during sending e-mail", $e);
            $log->create();
            $log->saveOrFailSilently(array(
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
        $logTitle .= $replyToLog  . '  to ' . $result['to'] . ' sent, titled "' . $result['subject'] . '".';

        if (Configure::read('Security.ecs_log')) {
            EcsLog::writeEmailLog($logTitle, $result, $replyToUser ? $replyToUser['User']['email'] : null);
        }

        $log->create();
        $log->saveOrFailSilently(array(
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
        static $fields; // generate array just once
        if ($fields) {
            return $fields;
        }

        $fields = $this->schema();
        // Do not include keys, because they are big and usually not necessary
        unset($fields['gpgkey']);
        unset($fields['certif_public']);
        // Do not fetch password from db, it is automatically fetched by BaseAuthenticate::_findUser
        unset($fields['password']);
        // Do not fetch authkey from db, it is sensitive and not need
        unset($fields['authkey']);
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
        $subjects = array('[' . $org . ' MISP] New user registration', '[' . $org .  ' MISP] Password reset');
        $subject = $subjects[($firstTime ? 0 : 1)];
        $this->Server = ClassRegistry::init('Server');
        if ($fixedPassword) {
            $password = $fixedPassword;
        } else {
            $password = $this->generateRandomPassword();
        }
        $body = $this->preparePasswordResetEmail($user, $password, $firstTime, $subject);
        $result = $this->sendEmail($user, $body, false, $subject);
        if ($result) {
            $this->id = $user['User']['id'];
            $this->saveField('password', $password);
            $this->saveField('last_pw_change', time());
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

    private function preparePasswordResetEmail($user, $password, $firstTime, $subject)
    {
        $textToFetch = $firstTime ? 'newUserText': 'passwordResetText';
        $this->Server = ClassRegistry::init('Server');
        $bodyTemplate = Configure::read('MISP.' . $textToFetch);
        if (!$bodyTemplate) {
            $bodyTemplate = $this->Server->serverSettings['MISP'][$textToFetch]['value'];
        }
        $template = new SendEmailTemplate('password_reset');
        $template->set('body', $bodyTemplate);
        $template->set('user', $user);
        $template->set('password', $password);
        $template->subject($subject);
        return $template;
    }

    /**
     * @param int $orgId
     * @param int|false $excludeUserId
     * @return array User ID => Email
     */
    public function getOrgAdminsForOrg($orgId, $excludeUserId = false)
    {
        $adminRoles = $this->Role->find('column', array(
            'conditions' => array('perm_admin' => 1),
            'fields' => array('Role.id')
        ));
        $conditions = array(
            'User.org_id' => $orgId,
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

    /**
     * @param int|false $excludeUserId
     * @return array User ID => Email
     */
    public function getSiteAdmins($excludeUserId = false)
    {
        $adminRoles = $this->Role->find('column', array(
            'conditions' => array('perm_site_admin' => 1),
            'fields' => array('Role.id')
        ));
        $conditions = array(
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
            $passwordHasher = new BlowfishConstantPasswordHasher();
        }
        $hashed = $passwordHasher->check($password, $currentUser['User']['password']);
        return $hashed;
    }

    /**
     * @param int $orgId
     * @return string User auth key
     * @throws Exception
     */
    public function createInitialUser($orgId)
    {
        $authKey = $this->generateAuthKey();
        $admin = array('User' => array(
            'id' => 1,
            'email' => 'admin@admin.test',
            'org_id' => $orgId,
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
        if (!empty(Configure::read("Security.advanced_authkeys"))) {
            $newKey = [
                'authkey' => $authKey,
                'user_id' => 1,
                'comment' => 'Initial auto-generated key',
                'allowed_ips' => null,
            ];
            $this->AuthKey->create();
            $this->AuthKey->save($newKey);
        }
        return $authKey;
    }

    public function resetAllSyncAuthKeysRouter($user, $jobId = false)
    {
        if (Configure::read('MISP.background_jobs')) {

            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob(
                $user,
                Job::WORKER_PRIO,
                'reset_all_sync_api_keys',
                __('Reseting all API keys'),
                'Issuing new API keys to all sync users.'
            );

            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::PRIO_QUEUE,
                BackgroundJobsTool::CMD_ADMIN,
                [
                    'resetSyncAuthkeys',
                    $user['id'],
                    $jobId
                ],
                true,
                $jobId
            );

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

    /**
     * @param string|array $user
     * @param string $action
     * @param string $description
     * @param string $fieldsResult
     * @param array|null $modifiedUser
     * @return void
     * @throws JsonException
     */
    public function extralog($user, $action, $description = null, $fieldsResult = null, $modifiedUser = null)
    {
        if ($user === 'SYSTEM') {
            $user = [
                'id' => 0,
                'email' => 'SYSTEM',
                'Organisation' => [
                    'name' => 'SYSTEM'
                ],
            ];
        }
        // new data
        $modelId = $user['id'];
        if (!empty($modifiedUser)) {
            $modelId = $modifiedUser['User']['id'];
        }
        if ($action === 'login') {
            $description = "User (" . $user['id'] . "): " . $user['email'];
            $fieldsResult = JsonTool::encode($this->UserLoginProfile->_getUserProfile());
        } else if ($action === 'logout') {
            $description = "User (" . $user['id'] . "): " . $user['email'];
        } else if ($action === 'edit') {
            $description = "User (" . $modifiedUser['User']['id'] . "): " . $modifiedUser['User']['email'];
        } else if ($action === 'change_pw') {
            $description = "User (" . $modifiedUser['User']['id'] . "): " . $modifiedUser['User']['email'];
            $fieldsResult = "Password changed.";
        }

        $result = $this->loadLog()->createLogEntry($user, $action, 'User', $modelId, $description, $fieldsResult);
        // write to syslogd as well
        if ($result) {
            App::import('Lib', 'SysLog.SysLog');
            $syslog = new SysLog();
            $syslog->write(LOG_NOTICE, "$description -- $action" . (empty($fieldsResult) ? '' : ' -- ' . $result['Log']['change']));
        }
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

    public function registerUser($added_by, $registration, $org_id, $role_id)
    {
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
            'autoalert' => $this->defaultPublishAlert(),
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
            $this->Log->saveOrFailSilently(array(
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
            $this->Log->saveOrFailSilently(array(
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
     * Updates `last_api_access` time in database.
     * Always update when MISP.store_api_access_time is set.
     * Only update every hour when it isn't set
     *
     * @param array $user
     * @return array|bool
     * @throws Exception
     */
    public function updateAPIAccessTime(array $user)
    {
        if (!isset($user['id'])) {
            throw new InvalidArgumentException("Invalid user object provided.");
        }
        $storeAPITime = Configure::read('MISP.store_api_access_time');
        if ((!empty($storeAPITime) && $storeAPITime) || $user['last_api_access'] < time() - 60*60) {
            $user['last_api_access'] = time();
            return $this->save($user, true, array('id', 'last_api_access'));
        }
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
     * Check if user still valid at identity provider.
     * @param array $user
     * @return bool
     * @throws Exception
     */
    public function checkIfUserIsValid(array $user)
    {
        static $oidc;

        if ($oidc === null) {
            $auth = Configure::read('Security.auth');
            if (!$auth) {
                return true;
            }
            if (!is_array($auth)) {
                throw new Exception("`Security.auth` config value must be array.");
            }
            if (!in_array('OidcAuth.Oidc', $auth, true)) {
                return true; // this method currently makes sense just for OIDC auth provider
            }
            App::uses('Oidc', 'OidcAuth.Lib');
            $oidc = new Oidc($this);
        }

        return $oidc->isUserValid($user);
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

    public function updateToAdvancedAuthKeys()
    {
        $users = $this->find('all', [
            'recursive' => -1,
            'contain' => ['AuthKey'],
            'fields' => ['id', 'authkey']
        ]);
        $updated = 0;
        foreach ($users as $user) {
            if (!empty($user['AuthKey'])) {
                $currentKeyStart = substr($user['User']['authkey'], 0, 4);
                $currentKeyEnd = substr($user['User']['authkey'], -4);
                foreach ($user['AuthKey'] as $authkey) {
                    if ($authkey['authkey_start'] === $currentKeyStart && $authkey['authkey_end'] === $currentKeyEnd) {
                        continue 2;
                    }
                }
            }
            $this->AuthKey->create();
            $this->AuthKey->save([
                'authkey' => $user['User']['authkey'],
                'expiration' => 0,
                'user_id' => $user['User']['id']
            ]);
            $updated += 1;
        }
        return $updated;
    }

    public function checkNotificationBanStatus(array $user)
    {
        $banStatus = [
            'error' => false,
            'active' => false,
            'message' => __('User is not banned to sent email notification')
        ];
        if (!empty($user['Role']['perm_site_admin'])) {
            return $banStatus;
        }
        if (Configure::read('MISP.user_email_notification_ban')) {
            $banThresholdAmount = intval(Configure::read('MISP.user_email_notification_ban_amount_threshold'));
            $banThresholdMinutes = intval(Configure::read('MISP.user_email_notification_ban_time_threshold'));
            $banThresholdSeconds = 60 * $banThresholdMinutes;
            $redis = $this->setupRedis();
            if ($redis === false) {
                $banStatus['error'] = true;
                $banStatus['active'] = true;
                $banStatus['message'] =  __('Reason: Could not reach redis to check user email notification ban status.');
                return $banStatus;
            }

            $redisKeyAmountThreshold = "misp:user_email_notification_ban_amount:{$user['id']}";
            $notificationAmount = $redis->get($redisKeyAmountThreshold);
            if (!empty($notificationAmount)) {
                $remainingAttempt = $banThresholdAmount - intval($notificationAmount);
                if ($remainingAttempt <= 0) {
                    $ttl = $redis->ttl($redisKeyAmountThreshold);
                    $remainingMinutes = intval($ttl) / 60;
                    $banStatus['active'] = true;
                    $banStatus['message'] = __('Reason: User is banned from sending out emails (%s notification tried to be sent). Ban will be lifted in %smin %ssec.', $notificationAmount, floor($remainingMinutes), intval($ttl) % 60);
                }
            }
            $pipe = $redis->multi(Redis::PIPELINE)
                ->incr($redisKeyAmountThreshold);
            if (!$banStatus['active']) { // no need to refresh the ttl if the ban is active
                $pipe->expire($redisKeyAmountThreshold, $banThresholdSeconds);
            }
            $pipe->exec();
            return $banStatus;
        }
        $banStatus['message'] = __('User email notification ban setting is not enabled');
        return $banStatus;
    }

    /**
     * @return bool
     */
    public function defaultPublishAlert()
    {
        return (bool)Configure::read('MISP.default_publish_alert');
    }

    /**
     * @param array $user
     * @return bool
     */
    public function hasNotifications(array $user)
    {
        $hasProposal = $this->Event->ShadowAttribute->hasAny([
            'ShadowAttribute.event_org_id' => $user['org_id'],
            'ShadowAttribute.deleted' => 0,
        ]);
        if ($hasProposal) {
            return true;
        }

        if (Configure::read('MISP.delegation') && $this->_getDelegationCount($user)) {
            return true;
        }
        return false;
    }

    /**
     * @param array $user
     * @return array
     */
    public function populateNotifications(array $user)
    {
        $notifications = array();
        list($notifications['proposalCount'], $notifications['proposalEventCount']) = $this->_getProposalCount($user);
        $notifications['total'] = $notifications['proposalCount'];
        if (Configure::read('MISP.delegation')) {
            $notifications['delegationCount'] = $this->_getDelegationCount($user);
            $notifications['total'] += $notifications['delegationCount'];
        }
        return $notifications;
    }

    // if not using $mode === 'full', simply check if an entry exists. We really don't care about the real count for the top menu.
    private function _getProposalCount($user, $mode = 'full')
    {
        $results[0] = $this->Event->ShadowAttribute->find('count', [
            'conditions' => array(
                'ShadowAttribute.event_org_id' => $user['org_id'],
                'ShadowAttribute.deleted' => 0,
            )
        ]);
        $results[1] = $this->Event->ShadowAttribute->find('count', [
            'conditions' => array(
                'ShadowAttribute.event_org_id' => $user['org_id'],
                'ShadowAttribute.deleted' => 0,
            ),
            'fields' => 'distinct event_id'
        ]);
        return $results;
    }

    private function _getDelegationCount($user)
    {
        $this->EventDelegation = ClassRegistry::init('EventDelegation');
        return $this->EventDelegation->find('count', array(
            'recursive' => -1,
            'conditions' => array('EventDelegation.org_id' => $user['org_id'])
        ));
    }

    /**
     * Generate code that is used in event alert unsubscribe link.
     * @return string
     */
    public function unsubscribeCode(array $user)
    {
        $salt = Configure::read('Security.salt');
        return substr(hash('sha256', "{$user['id']}|$salt"), 0, 8);
    }

    /**
     * @param int $userId
     * @param bool $decode
     * @return array
     * @throws JsonException
     */
    public function fetchPeriodicSettingForUser($userId, $decode = false): array
    {
        $filterNames = ['orgc_id', 'distribution', 'sharing_group_id', 'event_info', 'tags', 'trending_for_tags', 'include_correlations', 'trending_period_amount'];
        $filterToDecode = ['tags', 'trending_for_tags'];
        $defaultPeriodicSettings = [
            'orgc_id' => '',
            'distribution' => -1,
            'sharing_group_id' => '',
            'event_info' => '',
            'tags' => '[]',
            'trending_for_tags' => '[]',
            'include_correlations' => '',
            'trending_period_amount' => 2,
        ];

        $periodicSettings = $this->UserSetting->getValueForUser($userId, self::PERIODIC_USER_SETTING_KEY);
        $periodicSettings = $periodicSettings ?: $defaultPeriodicSettings;

        $periodicSettingsIndexed = [];
        foreach ($filterNames as $filterName) {
            $periodicSettingsIndexed[$filterName] = $periodicSettings[$filterName] ?? $defaultPeriodicSettings[$filterName];
        }
        if ($decode) {
            foreach ($filterToDecode as $filter) {
                if (!empty($periodicSettingsIndexed[$filter])) {
                    $periodicSettingsIndexed[$filter] = JsonTool::decode($periodicSettingsIndexed[$filter]);
                }
            }
        }
        return $periodicSettingsIndexed;
    }

    /**
     * @param array $period_filters
     * @param string $period
     * @return array
     */
    private function getUsablePeriodicSettingForUser(array $period_filters, $period='daily', $lastdays=7): array
    {
        $filters = [
            'last' => $this->__genTimerangeFilter($period, $lastdays),
            'published' => true,
        ];
        if (!empty($period_filters['orgc_id'])) {
            $filters['orgc_id'] = $period_filters['orgc_id'];
        }
        if (isset($period_filters['distribution']) && $period_filters['distribution'] >= 0) {
            $filters['distribution'] = intval($period_filters['distribution']);
        }
        if (!empty($period_filters['sharing_group_id'])) {
            $filters['sharing_group_id'] = $period_filters['sharing_group_id'];
        }
        if (!empty($period_filters['event_info'])) {
            $filters['event_info'] = $period_filters['event_info'];
        }
        if (!empty($period_filters['tags'])) {
            $filters['tags'] = $period_filters['tags'];
        }
        return $filters;
    }

    public function saveNotificationSettings(int $userId, array $data): bool
    {
        $existingUser = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['User.id' => $userId],
        ]);
        if (empty($existingUser)) {
            return false;
        }
        foreach (self::PERIODIC_NOTIFICATIONS as $notification_period) {
            $existingUser['User'][$notification_period] = $data['User'][$notification_period];
        }
        $success = $this->save($existingUser, [
            'fieldList' => array_merge(self::PERIODIC_NOTIFICATIONS, ['date_modified']),
        ]);
        if ($success) {
            $periodic_settings = $data['periodic_settings'];
            $param_to_decode = ['tags', 'trending_for_tags'];
            foreach ($param_to_decode as $param) {
                if (empty($periodic_settings[$param])) {
                    $periodic_settings[$param] = '[]';
                } else {
                    $decodedTags = json_decode($periodic_settings[$param], true);
                    if ($decodedTags === null) {
                        return false;
                    }
                }
            }
            $notification_filters = [
                'orgc_id' => $periodic_settings['orgc_id'] ?? [],
                'distribution' => $periodic_settings['distribution'] ?? '',
                'sharing_group_id' => $periodic_settings['distribution'] != 4 ? '' : ($periodic_settings['sharing_group_id'] ?? []),
                'event_info' => $periodic_settings['event_info'] ?? '',
                'tags' => $periodic_settings['tags'] ?? '[]',
                'trending_for_tags' => $periodic_settings['trending_for_tags'] ?? '[]',
                'include_correlations' => $periodic_settings['include_correlations'] ?? '',
                'trending_period_amount' => $periodic_settings['trending_period_amount'] ?? 2,
            ];
            $new_user_setting = [
                'UserSetting' => [
                    'user_id' => $existingUser['User']['id'],
                    'setting' => self::PERIODIC_USER_SETTING_KEY,
                    'value' => $notification_filters
                ]
            ];
            $success = $this->UserSetting->setSetting($existingUser['User'], $new_user_setting);
        }
        return !empty($success);
    }

    public function getSubscribedUsersForPeriod(string $period): array
    {
        return $this->find('all', [
            'recursive' => -1,
            'conditions' => [
                "notification_$period" => true,
                'disabled' => false,
            ],
        ]);
    }

    /**
     * generatePeriodicSummary
     *
     * @param int $userId
     * @param string $period Can be 'daily', 'weekly' or 'monthly'
     * @param bool $rendered When false, instance of SendEmailTemplate will returned
     * @return string|SendEmailTemplate|null
     * @throws NotFoundException
     * @throws InvalidArgumentException
     * @throws JsonException
     */
    public function generatePeriodicSummary(int $userId, string $period, $rendered = true, $lastdays=7)
    {
        $allowedPeriods = array_map(function($period) {
            return substr($period, strlen('notification_'));
        }, self::PERIODIC_NOTIFICATIONS);
        $allowedPeriods[] = 'custom';
        if (!in_array($period, $allowedPeriods, true)) {
            throw new InvalidArgumentException(__('Invalid period. Must be one of %s', JsonTool::encode(self::PERIODIC_NOTIFICATIONS)));
        }

        $user = $this->getAuthUser($userId);
        App::import('Tools', 'SendEmail');
        $periodicSettings = $this->fetchPeriodicSettingForUser($userId, true);
        $filters = $this->getUsablePeriodicSettingForUser($periodicSettings, $period, $lastdays);
        $filtersForRestSearch = $filters; // filters for restSearch are slightly different than fetchEvent
        $filters['last'] = $this->resolveTimeDelta($filters['last']);
        $filters['sgReferenceOnly'] = true;
        $filters['includeEventCorrelations'] = !empty($periodicSettings['include_correlations']);
        $filters['includeGranularCorrelations'] = !empty($periodicSettings['include_correlations']);
        $filters['noSightings'] = true;
        $filters['fetchFullClusters'] = true;
        $filters['fetchFullClusterRelationship'] = true;
        $filters['includeScoresOnEvent'] = true;
        $events = $this->Event->fetchEvent($user, $filters);

        if (empty($events)) {
            return null;
        }

        $elementCounter = 0;
        $renderView = false;
        $filtersForRestSearch['publish_timestamp'] = $filtersForRestSearch['last'];
        $filtersForRestSearch['returnFormat'] = 'context';
        $filtersForRestSearch['staticHtml'] = true;
        unset($filtersForRestSearch['last']);
        if (!empty($filtersForRestSearch['tags'])) {
            $filtersForRestSearch['event_tags'] = $filtersForRestSearch['tags'];
            unset($filtersForRestSearch['tags']);
        }
        $finalContext = $this->Event->restSearch($user, 'context', $filtersForRestSearch, false, false, $elementCounter, $renderView);
        $finalContext = JsonTool::decode($finalContext->intoString());
        $aggregated_context = $this->__renderAggregatedContext($finalContext);
        $rollingWindows = $periodicSettings['trending_period_amount'] ?: 2;
        $trendAnalysis = $this->Event->getTrendsForTagsFromEvents($events, $this->periodToDays($period, $lastdays), $rollingWindows, $periodicSettings['trending_for_tags']);
        $tagFilterPrefixes = $periodicSettings['trending_for_tags'] ?: array_keys($trendAnalysis['all_tags']);
        $trendData = [
            'trendAnalysis' => $trendAnalysis,
            'tagFilterPrefixes' => $tagFilterPrefixes,
        ];
        $trending_summary = $this->__renderTrendingSummary($trendData);
        $securityRecommendationsData = [
            'course_of_action' => $this->Event->extractRelatedCourseOfActions($events),
        ];
        $security_recommendations = $this->__renderSecurityRecommendations($securityRecommendationsData);

        $templateName = $period == 'custom' ? 'daily' : $period;
        $emailTemplate = $this->prepareEmailTemplate($templateName);
        $emailTemplate->set('baseurl', $this->Event->__getAnnounceBaseurl());
        $emailTemplate->set('events', $events);
        $emailTemplate->set('filters', $filters);
        $emailTemplate->set('periodicSettings', $periodicSettings);
        $emailTemplate->set('period_days', $this->periodToDays($period, $lastdays));
        $emailTemplate->set('period', $period);
        $emailTemplate->set('aggregated_context', $aggregated_context);
        $emailTemplate->set('trending_summary', $trending_summary);
        $emailTemplate->set('security_recommendations', $security_recommendations);
        $emailTemplate->set('analysisLevels', $this->Event->analysisLevels);
        $emailTemplate->set('distributionLevels', $this->Event->distributionLevels);
        if ($rendered) {
            $summary = $emailTemplate->render();
            return $summary->format() === 'text' ? $summary->text : $summary->html;
        }
        return $emailTemplate;
    }

    private function __renderAggregatedContext(array $restSearchOutput): string
    {
        return $this->__renderGeneric('Events' . DS . 'module_views', 'context_view', $restSearchOutput);
    }

    private function __renderTrendingSummary(array $trendData): string
    {
        return $this->__renderGeneric('Elements' . DS . 'Events', 'trendingSummary', $trendData);
    }

    private function __renderSecurityRecommendations(array $data): string
    {
        return $this->__renderGeneric('Elements' . DS . 'Events', 'securityRecommendations', $data);
    }

    private function __renderGeneric(string $viewPath, string $viewFile, array $viewVars): string
    {
        $view = new View();
        $view->autoLayout = false;
        $view->helpers = ['TextColour'];
        $view->loadHelpers();

        $view->set($viewVars);
        $view->set('baseurl', $this->Event->__getAnnounceBaseurl());
        $view->viewPath = $viewPath;
        return $view->render($viewFile, false);
    }

    private function __getUsableFilters(array $period_filters, string $period='daily'): array
    {
        $filters = [
            'last' => $this->__genTimerangeFilter($period),
            'published' => true,
            'includeScoresOnEvent' => true,
        ];
        if (!empty($period_filters['orgc_id'])) {
            $filters['orgc_id'] = $period_filters['orgc_id'];
        }
        if (isset($period_filters['distribution']) && $period_filters['distribution'] >= 0) {
            $filters['distribution'] = intval($period_filters['distribution']);
        }
        if (!empty($period_filters['sharing_group_id'])) {
            $filters['sharing_group_id'] = $period_filters['sharing_group_id'];
        }
        if (!empty($period_filters['event_info'])) {
            $filters['event_info'] = $period_filters['event_info'];
        }
        if (!empty($period_filters['tags'])) {
            $filters['tags'] = $period_filters['tags'];
        }
        return $filters;
    }
    private function __genTimerangeFilter(string $period='daily', $lastdays = 7): string
    {
        if ($period == 'custom') {
            return strval($lastdays) . 'd';
        }
        return $this->periodToDays($period) . 'd';
    }

    private function periodToDays(string $period='daily', $lastdays = false): int
    {
        if ($lastdays !== false) {
            return $lastdays;
        }
        if ($period === 'daily') {
            return 1;
        } else if ($period === 'weekly') {
            return 7;
        } else {
            return 31;
        }
    }

    private function prepareEmailTemplate(string $period = 'daily'): SendEmailTemplate
    {
        $subject = sprintf('[%s MISP] %s %s', Configure::read('MISP.org'), Inflector::humanize($period), __('Notification - %s', (new DateTime())->format('Y-m-d')));
        $template = new SendEmailTemplate("notification_$period");
        $template->subject($subject);
        return $template;
    }

    /**
     * @return bool
     */
    public function advancedAuthkeysEnabled()
    {
        return !empty(Configure::read("Security.advanced_authkeys"));
    }

    /**
     * @param array $users
     * @return array
     * @throws RedisException
     */
    public function attachIsUserMonitored(array $users)
    {
        if (!empty(Configure::read('Security.user_monitoring_enabled'))) {
            $redis = RedisTool::init();
            $redis->pipeline();
            foreach ($users as $user) {
                $redis->sismember('misp:monitored_users', $user['User']['id']);
            }
            $output = $redis->exec();

            foreach ($users as $key => $user) {
                $users[$key]['User']['monitored'] = $output[$key];
            }
        }
        return $users;
    }

    /**
     * @param int $id
     * @param int $sessionCreationTimestamp
     * @return bool
     * @throws RedisException
     */
    public function checkForSessionDestruction($id, $sessionCreationTimestamp)
    {
        try {
            $redis = RedisTool::init();
        } catch (Exception $e) {
            return false;
        }

        list($cutoff, $allcutoff) = $redis->mGet(['misp:session_destroy:' . $id, 'misp:session_destroy:all']);
        if (
            empty($cutoff) ||
            (
                !empty($allcutoff) &&
                $allcutoff < $cutoff
            )
        ) {
            $cutoff = $allcutoff;
        }
        if ($cutoff && $sessionCreationTimestamp < $cutoff) {
            return true;
        }

        return false;
    }

    public function forgotRouter($email, $ip)
    {
        if (Configure::read('MISP.background_jobs')) {
            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $dummyUser = [
                'email' => 'SYSTEM',
                'org_id' => 0,
                'role_id' => 0
            ];
            $jobId = $job->createJob($dummyUser, Job::WORKER_EMAIL, 'forgot_password', $email, 'Sending...');

            $args = [
                'jobForgot',
                $email,
                $ip,
                $jobId,
            ];

            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::EMAIL_QUEUE,
                BackgroundJobsTool::CMD_ADMIN,
                $args,
                true,
                $jobId
            );

            return true;
        } else {
            return $this->forgot($email, $ip);
        }
    }

    public function forgot($email, $ip)
    {
        $user = $this->find('first', [
            'recursive' => -1,
            'conditions' => [
                'User.email' => $email,
                'User.disabled' => 0
            ]
        ]);
        if (empty($user)) {
            return false;
        }
        $token = RandomTool::random_str(true, 40, '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ');
        RedisTool::init()->set('misp:forgot:' . $token, $user['User']['id'], ['nx', 'ex' => 600]);
        $baseurl = Configure::check('MISP.external_baseurl') ? Configure::read('MISP.external_baseurl') : Configure::read('MISP.baseurl');
        $body = __(
            "Dear MISP user,\n\nyou have requested a password reset on the MISP instance at %s. Click the link below to change your password.\n\n%s\n\nThe link above is only valid for 10 minutes, feel free to request a new one if it has expired.\n\nIf you haven't requested a password reset, reach out to your admin team and let them know that someone has attempted it in your stead.\n\nMake sure you keep the contents of this e-mail confidential, do NOT ever forward it as it contains a reset token that is equivalent of a password if acted upon. The IP used to trigger the request was: %s\n\nBest regards,\nYour MISP admin team",
            $baseurl,
            $baseurl . '/users/password_reset/' . $token,
            $ip
        );
        $bodyNoEnc = __(
            "Dear MISP user,\n\nyou have requested a password reset on the MISP instance at %s, however, no valid encryption key was found for your user and thus we cannot deliver your reset token. Please get in touch with your org admin / with an instance site admin to ask for a reset.\n\nThe IP used to trigger the request was: %s\n\nBest regards,\nYour MISP admin team",
            $baseurl,
            $ip
        );
        $this->sendEmail($user, $body, $bodyNoEnc, __('MISP password reset'));
        return true;
    }

    public function fetchForgottenPasswordUser($token)
    {
        if (!ctype_alnum($token)) {
            return false;
        }
        $redis = RedisTool::init();
        $userId = $redis->get('misp:forgot:' . $token);
        if (empty($userId)) {
            return false;
        }
        $user = $this->getAuthUser($userId, true);
        return $user;
    }

    public function purgeForgetToken($token)
    {
        $redis = RedisTool::init();
        $redis->del('misp:forgot:' . $token);
        return true;
    }

    /**
     * Create default Role, Organisation and User
     * @return string|null Created user auth key
     * @throws Exception
     */
    public function init()
    {
        if (!$this->Role->hasAny()) {
            $siteAdmin = ['Role' => [
                'id' => 1,
                'name' => 'Site Admin',
                'permission' => 3,
                'perm_add' => 1,
                'perm_modify' => 1,
                'perm_modify_org' => 1,
                'perm_publish' => 1,
                'perm_sync' => 1,
                'perm_admin' => 1,
                'perm_audit' => 1,
                'perm_auth' => 1,
                'perm_site_admin' => 1,
                'perm_regexp_access' => 1,
                'perm_sharing_group' => 1,
                'perm_template' => 1,
                'perm_tagger' => 1,
            ]];
            $this->Role->save($siteAdmin);
            // PostgreSQL: update value of auto incremented serial primary key after setting the column by force
            if (!$this->isMysql()) {
                $sql = "SELECT setval('roles_id_seq', (SELECT MAX(id) FROM roles));";
                $this->Role->query($sql);
            }
        }

        if (!$this->Organisation->hasAny(['Organisation.local' => true])) {
            $this->runUpdates();
            $org = ['Organisation' => [
                'id' => 1,
                'name' => !empty(Configure::read('MISP.org')) ? Configure::read('MISP.org') : 'ADMIN',
                'description' => 'Automatically generated admin organisation',
                'type' => 'ADMIN',
                'date_created' => date('Y-m-d H:i:s'),
                'local' => 1,
            ]];
            $this->Organisation->save($org);
            // PostgreSQL: update value of auto incremented serial primary key after setting the column by force
            if (!$this->isMysql()) {
                $sql = "SELECT setval('organisations_id_seq', (SELECT MAX(id) FROM organisations));";
                $this->Organisation->query($sql);
            }
            $orgId = $this->Organisation->id;
        }

        if (!$this->hasAny()) {
            if (!isset($orgId)) {
                $hostOrg = $this->Organisation->find('first', array('conditions' => array('Organisation.name' => Configure::read('MISP.org'), 'Organisation.local' => true), 'recursive' => -1));
                if (!empty($hostOrg)) {
                    $orgId = $hostOrg['Organisation']['id'];
                } else {
                    $firstOrg = $this->Organisation->find('first', array('conditions' => array('Organisation.local' => true), 'order' => 'Organisation.id ASC'));
                    $orgId = $firstOrg['Organisation']['id'];
                }
            }
            $this->runUpdates();
            return $this->createInitialUser($orgId);
        }

        return null;
    }
}
