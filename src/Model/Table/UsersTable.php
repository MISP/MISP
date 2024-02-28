<?php

namespace App\Model\Table;

use App\Lib\Tools\GpgTool;
use App\Lib\Tools\LogExtendedTrait;
use App\Lib\Tools\SendEmail;
use App\Lib\Tools\SendEmailException;
use App\Model\Table\AppTable;
use ArrayObject;
use Cake\Core\Configure;
use Cake\Datasource\EntityInterface;
use Cake\Event\EventInterface;
use Cake\Http\Exception\BadRequestException;
use Cake\Http\Exception\NotFoundException;
use Cake\ORM\RulesChecker;
use Cake\Validation\Validator;
use Exception;
use InvalidArgumentException;


class UsersTable extends AppTable
{
    use LogExtendedTrait;

    private const PERIODIC_USER_SETTING_KEY = 'periodic_notification_filters';
    public const PERIODIC_NOTIFICATIONS = ['notification_daily', 'notification_weekly', 'notification_monthly'];

    private $PermissionLimitations;

    /** @var GpgTool */
    private $gpg;

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('Timestamp');
        $this->addBehavior('UUID');
        //$this->addBehavior('MetaFields');
        $this->addBehavior('AuditLog');
        /*$this->addBehavior('NotifyAdmins', [
            'fields' => ['role_id', 'individual_id', 'organisation_id', 'disabled', 'modified', 'meta_fields'],
        ]);*/
        $this->initAuthBehaviors();
        /*
        $this->belongsTo(
            'Individuals',
            [
                'dependent' => false,
                'cascadeCallbacks' => false
            ]
        );
        */
        $this->belongsTo(
            'Roles',
            [
                'dependent' => false,
                'cascadeCallbacks' => false,
                'propertyName' => 'Role'
            ]
        );
        $this->belongsTo(
            'Organisations',
            [
                'dependent' => false,
                'cascadeCallbacks' => false,
                'foreignKey' => 'org_id',
                'propertyName' => 'Organisation'
            ]
        );
        $this->hasMany(
            'UserSettings',
            [
                'dependent' => true,
                'cascadeCallbacks' => true,
                'propertyName' => 'UserSetting'
            ]
        );
        $this->belongsTo(
            'Servers',
            [
                'dependent' => false,
                'cascadeCallbacks' => false,
                'foreignKey' => 'server_id',
                'propertyName' => 'Server'
            ]
        );
        $this->setDisplayField('email');
    }

    public function beforeMarshal(EventInterface $event, ArrayObject $data, ArrayObject $options)
    {
        if (isset($data['username'])) {
            $data['username'] = trim(mb_strtolower($data['username']));
        }
    }

    public function beforeSave(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        $success = true;
        if (!$entity->isNew()) {
            $success = $this->handleUserUpdateRouter($entity);
        }
        $permissionRestrictionCheck = $this->checkPermissionRestrictions($entity);
        if ($permissionRestrictionCheck !== true) {
            $entity->setErrors($permissionRestrictionCheck);
            $event->stopPropagation();
            $event->setResult(false);
            return false;
        }
        return $success;
    }

    private function checkPermissionRestrictions(EntityInterface $entity)
    {
        if (!isset($this->PermissionLimitations)) {
            $this->PermissionLimitations = $this->fetchTable('PermissionLimitations');
        }
        $permissions = $this->PermissionLimitations->getListOfLimitations($entity);
        foreach ($permissions as $permission_name => $permission) {
            foreach ($permission as $scope => $permission_data) {
                $valueToCompareTo = $permission_data['current'];

                $enabled = false;
                if (!empty($entity->meta_fields)) {
                    foreach ($entity['meta_fields'] as $metaField) {
                        if ($metaField['field'] === $permission_name) {
                            $enabled = true;
                            if ($metaField->isNew()) {
                                $valueToCompareTo += !empty($metaField->value) ? 1 : 0;
                            } else {
                                $valueToCompareTo += !empty($metaField->value) ? 0 : -1;
                            }
                        }
                    }
                }

                if (!$enabled && !empty($entity->_metafields_to_delete)) {
                    foreach ($entity->_metafields_to_delete as $metaFieldToDelete) {
                        if ($metaFieldToDelete['field'] === $permission_name) {
                            $valueToCompareTo += !empty($metaFieldToDelete->value) ? -1 : 0;
                        }
                    }
                }

                if ($valueToCompareTo > $permission_data['limit']) {
                    return [
                        $permission_name =>
                        __(
                            '{0} limit exceeded.',
                            $scope
                        )
                    ];
                }
            }
        }
        return true;
    }

    private function initAuthBehaviors()
    {
        if (!empty(Configure::read('keycloak'))) {
            $this->addBehavior('AuthKeycloak');
        }
    }

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->setStopOnFailure()
            ->requirePresence(['password'], 'create')
            ->add(
                'password',
                [
                    'password_complexity' => [
                        'rule' => function ($value, $context) {
                            if (!preg_match('/^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/s', $value) || strlen($value) < 12) {
                                return false;
                            }
                            return true;
                        },
                        'message' => __('Invalid password. Passwords have to be either 16 character long or 12 character long with 3/4 special groups.')
                    ],
                    'password_confirmation' => [
                        'rule' => function ($value, $context) {
                            if (isset($context['data']['confirm_password'])) {
                                if ($context['data']['confirm_password'] !== $value) {
                                    return false;
                                }
                            }
                            return true;
                        },
                        'message' => __('Password confirmation missing or not matching the password.')
                    ]
                ]
            )
            ->add(
                'username',
                [
                    'username_policy' => [
                        'rule' => function ($value, $context) {
                            if (mb_strlen(trim($value)) < 5 || mb_strlen(trim($value)) > 50) {
                                return __('Invalid username length. Make sure that you provide a username of at least 5 and up to 50 characters in length.');
                            }
                            return true;
                        }
                    ]
                ]
            )
            ->requirePresence(['username'], 'create')
            ->notEmptyString('username', __('Please fill this field'), 'create');
        if (Configure::read('user.username-must-be-email')) {
            $validator->add(
                'username',
                'valid_email',
                [
                    'rule' => 'email',
                    'message' => 'Username has to be a valid e-mail address.'
                ]
            );
        }
        return $validator;
    }

    public function buildRules(RulesChecker $rules): RulesChecker
    {
        $rules->add($rules->isUnique(['username']));
        $allowDuplicateIndividuals = false;
        if (empty(Configure::read('user.multiple-users-per-individual')) || !empty(Configure::read('keycloak.enabled'))) {
            $rules->add($rules->isUnique(['individual_id']));
        }
        return $rules;
    }


    public function captureOrganisation($user): int
    {
        $organisation = $this->Organisations->find()->where(['uuid' => $user['organisation']['uuid']])->first();
        if (empty($organisation)) {
            $user['organisation']['name'] = $user['organisation']['uuid'];
            $organisation = $this->Organisations->newEntity($user['organisation']);
            if (!$this->Organisations->save($organisation)) {
                throw new BadRequestException(__('Could not save the associated organisation'));
            }
        }
        return $organisation->id;
    }

    public function captureRole($user): int
    {
        $role = $this->Roles->find()->where(['name' => $user['role']['name']])->first();
        if (empty($role)) {
            if (empty($role)) {
                throw new NotFoundException(__('Invalid role'));
            }
        }
        return $role->id;
    }

    public function enrollUserRouter($data): void
    {
        if (!empty(Configure::read('keycloak'))) {
            $this->enrollUser($data);
        }
    }

    public function handleUserUpdateRouter(\App\Model\Entity\User $user): bool
    {
        if (!empty(Configure::read('keycloak.enabled'))) {
            $success = $this->handleUserUpdate($user);
            // return $success;
        }
        return true;
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
        $conditions = ['Users.id' => $id];
        return $this->getAuthUserByConditions($conditions, $full);
    }

    /**
     * Get user model with Role, Organisation and Server, but without PGP and S/MIME keys
     * @param array $conditions
     * @param bool $full When true, fetch all user fields.
     * @return array|null
     */
    private function getAuthUserByConditions(array $conditions, $full = false)
    {
        $user = $this->find(
            'all',
            [
                'conditions' => $conditions,
                'fields' => $full ? [] : $this->describeAuthFields(),
                'recursive' => -1,
                'contain' => [
                    'Organisations',
                    'Roles',
                    'Servers',
                ],
            ]
        )->first();
        if (empty($user)) {
            return $user;
        }

        // return $this->rearrangeToAuthForm($user); // TODO: [3.x-MIGRATION] - is this still needed?
        return $user;
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
            // TODO: [3.x-MIGRATION] - Oidc
            // if (!in_array('OidcAuth.Oidc', $auth, true)) {
            //     return true; // this method currently makes sense just for OIDC auth provider
            // }
            // $oidc = new Oidc($this);
        }

        // TODO: [3.x-MIGRATION] - Oidc
        // return $oidc->isUserValid($user);
        return false;
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
    public function sendEmail(array $user, $body, $bodyNoEnc, $subject, $replyToUser = false)
    {
        if ($bodyNoEnc === null) {
            $bodyNoEnc = false;
        }

        if (Configure::read('MISP.disable_emailing')) {
            return true;
        }

        if ($user['disabled'] || !$this->checkIfUserIsValid($user)) {
            return true;
        }

        $LogsTable = $this->fetchTable('Logs');
        $replyToLog = $replyToUser ? ' from ' . $replyToUser['email'] : '';

        $gpg = $this->initializeGpg();
        $sendEmail = new SendEmail($gpg);
        try {
            $result = $sendEmail->sendToUser($user, $subject, $body, $bodyNoEnc, $replyToUser ?: []);
        } catch (SendEmailException $e) {
            $this->logException("Exception during sending e-mail", $e);
            $log = $LogsTable->newEntity(
                [
                    'org' => 'SYSTEM',
                    'model' => 'User',
                    'model_id' => $user['id'],
                    'email' => $user['email'],
                    'action' => 'email',
                    'title' => 'Email' . $replyToLog . ' to ' . $user['email'] . ', titled "' . $subject . '" failed. Reason: ' . $e->getMessage(),
                    'change' => null,
                ]
            );
            $LogsTable->save($log);
            return false;
        }

        $logTitle = $result['encrypted'] ? 'Encrypted email' : 'Email';
        // Intentional two spaces to pass test :)
        $logTitle .= $replyToLog  . '  to ' . $user['email'] . ' sent, titled "' . $result['subject'] . '".';

        $log = $LogsTable->newEntity(
            [
                'org' => 'SYSTEM',
                'model' => 'User',
                'model_id' => $user['id'],
                'email' => $user['email'],
                'action' => 'email',
                'title' => $logTitle,
                'change' => null,
            ]
        );
        $LogsTable->save($log);

        return true;
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
        // TODO: [3.x-MIGRATION] - is this still needed?
        // $fields = $this->schema();
        // // Do not include keys, because they are big and usually not necessary
        // unset($fields['gpgkey']);
        // unset($fields['certif_public']);
        // // Do not fetch password from db, it is automatically fetched by BaseAuthenticate::_findUser
        // unset($fields['password']);
        // // Do not fetch authkey from db, it is sensitive and not need
        // unset($fields['authkey']);
        // $fields = array_keys($fields);

        // foreach ($this->belongsTo as $relatedModel => $foo) {
        //     $fields[] = $relatedModel . '.*';
        // }
        // return $fields;

        return [
            "id",
            "org_id",
            "server_id",
            "email",
            "autoalert",
            "invited_by",
            "nids_sid",
            "termsaccepted",
            "newsread",
            "role_id",
            "change_pw",
            "contactalert",
            "disabled",
            "expiration",
            "current_login",
            "last_login",
            "force_logout",
            "date_created",
            "date_modified",
            "sub",
            "external_auth_required",
            "external_auth_key",
            "last_api_access",
            "notification_daily",
            "notification_weekly",
            "notification_monthly",
            // "totp", // TODO: [3.x-MIGRATION]
            // "hotp_counter", // TODO: [3.x-MIGRATION]
            // "last_pw_change", // TODO: [3.x-MIGRATION]
            // "Roles.*", // TODO: [3.x-MIGRATION]
            // "Organisations.*", v
            // "Servers.*" // TODO: [3.x-MIGRATION]
        ];
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
        $conditions = ['Users.authkey' => $authkey];
        return $this->getAuthUserByConditions($conditions);
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
            $pipe = $redis->multi(\Redis::PIPELINE)
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
        $conditions = [];
        $validOrgs = [];
        $all = true;

        // add owners to the conditions
        if ($distribution == 0 || $distribution == 4) {
            $all = false;
            $validOrgs = $owners;
        }

        // add all orgs to the conditions that can see the SG
        if ($distribution == 4) {
            $SharingGroupsTable = $this->fetchTable('SharingGroups');
            $sgOrgs = $SharingGroupsTable->getOrgsWithAccess($sharing_group_id);
            if ($sgOrgs === true) {
                $all = true;
            } else {
                $validOrgs = array_merge($validOrgs, $sgOrgs);
            }
        }
        $validOrgs = array_unique($validOrgs);
        $conditions['AND'][] = ['disabled' => 0];
        if (!$all) {
            $conditions['AND']['OR'][] = ['org_id IN' => $validOrgs];

            // Add the site-admins to the list
            $siteAdminRoleIds = $this->Roles->find(
                'column',
                [
                    'conditions' => ['perm_site_admin' => 1],
                    'fields' => ['id'],
                ]
            );
            $conditions['AND']['OR'][] = ['role_id' => $siteAdminRoleIds];
        }
        $conditions['AND'][] = $userConditions;
        $users = $this->find(
            'all',
            [
                'conditions' => $conditions,
                'recursive' => -1,
                'fields' => ['id', 'email', 'gpgkey', 'certif_public', 'org_id', 'disabled'],
                'contain' => [
                    'Roles' => ['fields' => ['perm_site_admin', 'perm_audit']],
                    'Organisations' => ['fields' => ['id', 'name']]
                ],
            ]
        )->toArray();
        foreach ($users as $k => $user) {
            $users[$k] = $this->rearrangeToAuthForm($user);
        }
        return $users;
    }
}
