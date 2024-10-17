<?php

/**
 * @property User $User
 * @property Log $Log
 * @property UserLoginProfile $UserLoginProfile
 */
class UserShell extends AppShell
{
    public $uses = ['User', 'Log', 'UserLoginProfile'];

    public function getOptionParser()
    {
        $parser = parent::getOptionParser();
        $parser->addSubcommand('list', [
            'help' => __('Get list of user accounts.'),
            'parser' => [
                'arguments' => [
                    'userId' => ['help' => __('User ID or e-mail address to filter.'), 'required' => false],
                ],
                'options' => [
                    'json' => ['help' => __('Output as JSON.'), 'boolean' => true],
                ],
            ]
        ]);
        $parser->addSubcommand('create', [
            'help' => __('Create a new user account.'),
            'parser' => [
                'arguments' => [
                    'email' => ['help' => __('E-mail address (also used as the username.'), 'required' => true],
                    'role_id' => ['help' => __('Role ID of the user. For a list of available roles, use `cake Roles list`.'), 'required' => true],
                    'org_id' => ['help' => __('Organisation under which the user should be created'), 'required' => true],
                    'password' => ['help' => __('Enter a password to assign to the user (optional) - if none is set, the user will receive a temporary password.')]
                ],
                'options' => [
                    'json' => ['help' => __('Output as JSON.'), 'boolean' => true],
                ],
            ]
        ]);
        $parser->addSubcommand('init', [
            'help' => __('Create default role, organisation and user when not exists.'),
        ]);
        $parser->addSubcommand('authkey', [
            'help' => __('Get information about given authkey.'),
            'parser' => [
                'arguments' => [
                    'authkey' => ['help' => __('Authentication key. If not provided, it will be read from STDIN.')],
                ],
            ]
        ]);
        $parser->addSubcommand('authkey_valid', [
            'help' => __('Check if given authkey by STDIN is valid.'),
            'parser' => [
                'options' => [
                    'disableStdLog' => ['help' => __('Do not show logs in STDOUT or STDERR.'), 'boolean' => true],
                ],
            ],
        ]);
        $parser->addSubcommand('block', [
            'help' => __('Immediately block user.'),
            'parser' => [
                'arguments' => [
                    'userId' => ['help' => __('User ID or e-mail address.'), 'required' => true],
                ],
            ],
        ]);
        $parser->addSubcommand('unblock', [
            'help' => __('Unblock blocked user.'),
            'parser' => [
                'arguments' => [
                    'userId' => ['help' => __('User ID or e-mail address.'), 'required' => true],
                ],
            ],
        ]);
        $parser->addSubcommand('check_validity', [
            'help' => __('Check users validity from external identity provider and block not valid user.'),
            'parser' => [
                'arguments' => [
                    'userId' => ['help' => __('User ID or e-mail address. If not provided, all users will be checked.'), 'required' => false],
                ],
                'options' => [
                    'block_invalid' => ['help' => __('Block user that are considered invalid.'), 'boolean' => true],
                    'update' => ['help' => __('Update user role or organisation.'), 'boolean' => true],
                ],
            ]
        ]);
        $parser->addSubcommand('change_pw', [
            'help' => __('Change user password.'),
            'parser' => [
                'arguments' => [
                    'userId' => ['help' => __('User ID or e-mail address.'), 'required' => true],
                    'password' => ['help' => __('New user password.'), 'required' => true],
                ],
                'options' => [
                    'no_password_change' => ['help' => __('Do not require password change.'), 'boolean' => true],
                ],
            ],
        ]);
        $parser->addSubcommand('change_role', [
            'help' => __('Change user role.'),
            'parser' => [
                'arguments' => [
                    'userId' => ['help' => __('User ID or e-mail address.'), 'required' => true],
                    'new_role' => ['help' => __('Role ID or Role name.'), 'required' => true],
                ]
            ],
        ]);
        $parser->addSubcommand('change_authkey', [
            'help' => __('Change authkey. When advanced authkeys are enabled, old authkeys will be disabled.'),
            'parser' => [
                'arguments' => [
                    'userId' => ['help' => __('User ID or e-mail address.'), 'required' => true],
                    'authKey' => ['help' => __('Optional new authentication key.'), 'required' => false],
                ],
            ],
        ]);
        $parser->addSubcommand('user_ips', [
            'help' => __('Show IP addresses that user uses to access MISP.'),
            'parser' => [
                'arguments' => [
                    'userId' => ['help' => __('User ID or e-mail address.'), 'required' => true],
                ],
                'options' => [
                    'json' => ['help' => __('Output as JSON.'), 'boolean' => true],
                ],
            ],
        ]);
        $parser->addSubcommand('ip_user', [
            'help' => __('Get user ID for user IP. If multiple users use the same IP, only last user ID will be returned.'),
            'parser' => [
                'arguments' => [
                    'ip' => ['help' => __('IPv4 or IPv6 address.'), 'required' => true],
                ],
                'options' => [
                    'json' => ['help' => __('Output as JSON.'), 'boolean' => true],
                ],
            ],
        ]);
        $parser->addSubcommand('ip_country', [
            'help' => __('Get country for given IP address'),
            'parser' => [
                'arguments' => [
                    'ip' => ['help' => __('IPv4 or IPv6 address.'), 'required' => true],
                ]
            ],
        ]);
        $parser->addSubcommand('require_password_change_for_old_passwords', [
            'help' => __('Trigger forced password change on next login for users with an old (older than x days) password.'),
            'parser' => [
                'arguments' => [
                    'days' => ['help' => __('Amount of days after which a password is considered "old" and needs to be changed.'), 'required' => true]
                ],
            ]
        ]);

        $parser->addSubcommand('expire_authkeys_without_ip_allowlist', [
            'help' => __('Expire all active authkeys that do not have an IP allowlist set.'),
        ]);
        return $parser;
    }

    public function list()
    {
        $userId = $this->args[0] ?? null;
        if ($userId) {
            $conditions = ['OR' => [
                'User.id' => $userId,
                'User.email LIKE' => "%$userId%",
                'User.sub LIKE' => "%$userId%",
            ]];
        } else {
            $conditions = [];
        }

        if ($this->params['json']) {
            // do not fetch sensitive or big values
            $schema = $this->User->schema();
            unset($schema['authkey']);
            unset($schema['password']);
            unset($schema['gpgkey']);
            unset($schema['certif_public']);

            $fields = array_keys($schema);
            $fields[] = 'Role.*';
            $fields[] = 'Organisation.*';

            $users = $this->User->find('all', [
                'recursive' => -1,
                'fields' => $fields,
                'conditions' => $conditions,
                'contain' => ['Organisation', 'Role', 'UserSetting'],
            ]);

            $this->out($this->json($users));
        } else {
            $users = $this->User->find('column', [
                'fields' => ['email'],
                'conditions' => $conditions,
            ]);
            foreach ($users as $user) {
                $this->out($user);
            }
        }
    }

    public function create()
    {
        if (empty($this->args[0]) || empty($this->args[1]) || empty($this->args[2])) {
            $this->err('Invalid input. Usage: `User create [email] [role_id] [org_id] [password:optional]`');
        }
        $user = [
            'email' => $this->args[0],
            'role_id' => $this->args[1],
            'org_id' => $this->args[2],
            'change_pw' => true
        ];
        if (!empty($this->args[3])) {
            $user['password'] = $this->args[3];
            $user['confirm_password'] = $this->args[3];
            $user['change_pw'] = true;
        }
        $this->User->create();
        $result = $this->User->save($user);
        // do not fetch sensitive or big values
        $schema = $this->User->schema();
        unset($schema['authkey']);
        unset($schema['password']);
        unset($schema['gpgkey']);
        unset($schema['certif_public']);

        $fields = array_keys($schema);
        $fields[] = 'Role.*';
        $fields[] = 'Organisation.*';

        $user = $this->User->find('first', [
            'recursive' => -1,
            'fields' => $fields,
            'conditions' => ['User.id' => $this->User->id],
            'contain' => ['Organisation', 'Role', 'UserSetting'],
        ]);
        if ($this->params['json']) {
            $this->out($this->json($user));
        } else {
            $this->out('User created.');
        }
    }

    public function init()
    {
        if (!Configure::read('Security.salt')) {
            $this->loadModel('Server');
            $this->Server->serverSettingsSaveValue('Security.salt', $this->User->generateRandomPassword(32));
        }

        $authKey = $this->User->init();
        if ($authKey === null) {
            $this->err('Script aborted: MISP instance already initialised.');
        } else {
            $this->out($authKey);
        }
    }

    public function authkey()
    {
        $authkey = $this->args[0] ?? fgets(STDIN);
        $authkey = trim($authkey);
        if (strlen($authkey) !== 40) {
            $this->error('Authkey has not valid format.');
        }
        if (Configure::read('Security.advanced_authkeys')) {
            $user = $this->User->AuthKey->getAuthUserByAuthKey($authkey, true);
            if (empty($user)) {
                $this->error("Given authkey doesn't belong to any user.");
            }

            $isExpired = $user['authkey_expiration'] && $user['authkey_expiration'] < time();

            $this->out($this->json([
                'user_id' => $user['id'],
                'email' => $user['email'],
                'org_id' => $user['org_id'],
                'authkey_id' => $user['authkey_id'],
                'authkey_expiration' => $user['authkey_expiration'],
                'authkey_expired' => $isExpired,
                'allowed_ips' => $user['allowed_ips'],
                'authkey_read_only' => $user['authkey_read_only'],
            ]));

            $this->_stop($isExpired ? 2 : 0);
        } else {
            $user = $this->User->getAuthUserByAuthkey($authkey);
            if (empty($user)) {
                $this->error("Given authkey doesn't belong to any user.");
            }
            $this->out($this->json([
                'user_id' => $user['id'],
                'email' => $user['email'],
                'org_id' => $user['org_id'],
            ]));
        }
    }

    /**
     * Reads line from stdin and checks if authkey is valid. Returns '1' to stdout if key is valid and '0' if not.
     */
    public function authkey_valid()
    {
        if ($this->params['disableStdLog']) {
            $this->_useLogger(false);
        }

        $cache = [];
        $randomKey = random_bytes(16);
        $advancedAuthKeysEnabled = (bool)Configure::read('Security.advanced_authkeys');

        while (true) {
            $authkey = fgets(STDIN); // read line from STDIN
            $authkey = trim($authkey);
            if (strlen($authkey) !== 40) {
                echo "0\n";  // authkey is not in valid format
                $this->log("Authkey in incorrect format provided, expected 40 chars long string, $authkey provided.", LOG_WARNING);
                continue;
            }

            // Generate hash from authkey to not store raw authkey in memory
            $keyHash = sha1($authkey . $randomKey, true);

            // If authkey is in cache and is fresh, use info from cache
            $time = time();
            if (isset($cache[$keyHash]) && $cache[$keyHash][1] > $time) {
                echo $cache[$keyHash][0] ? "1\n" : "0\n";
                continue;
            }

            $user = false;
            for ($i = 0; $i < 5; $i++) {
                try {
                    if ($advancedAuthKeysEnabled) {
                        $user = $this->User->AuthKey->getAuthUserByAuthKey($authkey);
                    } else {
                        $user = $this->User->getAuthUserByAuthkey($authkey);
                    }
                    break;
                } catch (PDOException $e) {
                    $this->log($e->getMessage());
                    // Reconnect in case of failure and try again
                    try {
                        $this->User->getDataSource()->connect();
                    } catch (MissingConnectionException $e) {
                        sleep(1);
                        $this->log($e->getMessage());
                    }
                }
            }

            if (!$user) {
                $valid = null;
            } else if ($user['disabled']) {
                $valid = false;
            } else {
                $valid = true;
            }

            echo $valid ? "1\n" : "0\n";

            if ($valid) {
                // Cache results for 60 seconds if key is valid
                $cache[$keyHash] = [true, $time + 60];
            } else {
                // Cache results for 5 seconds if key is invalid
                $cache[$keyHash] = [false, $time + 5];

                $start = substr($authkey, 0, 4);
                $end = substr($authkey, -4);
                $authKeyForLog = $start . str_repeat('*', 32) . $end;

                if ($valid === false) {
                    $this->log("Authkey $authKeyForLog belongs to user {$user['id']} that is disabled.", LOG_WARNING);
                } else {
                    $this->log("Authkey $authKeyForLog is invalid or expired.", LOG_WARNING);
                }
            }
        }
    }

    public function block()
    {
        list($userId) = $this->args;
        $user = $this->getUser($userId);
        if ($user['disabled']) {
            $this->error("User $userId is already blocked.");
        }
        $this->User->updateField($user, 'disabled', true);
        $this->out("User $userId blocked.");
    }

    public function unblock()
    {
        list($userId) = $this->args;
        $user = $this->getUser($userId);
        if (!$user['disabled']) {
            $this->error("User $userId is not blocked.");
        }
        $this->User->updateField($user, 'disabled', false);
        $this->out("User $userId unblocked.");
    }

    public function check_validity()
    {
        $auth = Configure::read('Security.auth');
        if (!$auth) {
            $this->error('External authentication is not enabled');
        }
        if (!is_array($auth)) {
            throw new Exception("`Security.auth` config value must be array.");
        }
        if (!in_array('OidcAuth.Oidc', $auth, true)) {
            $this->error('This method is currently supported just by OIDC auth provider');
        }

        App::uses('Oidc', 'OidcAuth.Lib');
        $oidc = new Oidc($this->User);

        $conditions = ['User.disabled' => false]; // fetch just not disabled users

        $userId = $this->args[0] ?? null;
        if ($userId) {
            $conditions['OR'] = [
                'User.id' => $userId,
                'User.email LIKE' => "%$userId%",
                'User.sub LIKE' => "%$userId%",
            ];
        }

        $users = $this->User->find('all', [
            'recursive' => -1,
            'contain' => ['UserSetting'],
            'conditions' => $conditions,
        ]);
        $blockInvalid = $this->params['block_invalid'];
        $update = $this->params['update'];

        foreach ($users as $user) {
            $user['User']['UserSetting'] = $user['UserSetting'];
            $user = $user['User'];

            if ($blockInvalid) {
                $result = $oidc->blockInvalidUser($user, true, $update);
            } else {
                $result = $oidc->isUserValid($user, true, $update);
            }

            $this->out("{$user['email']}: " . ($result ? '<success>valid</success>' : '<error>invalid</error>'));
        }
    }

    public function change_pw()
    {
        list($userId, $newPassword) = $this->args;
        $user = $this->getUser($userId);

        $user['password'] = $newPassword;
        $user['confirm_password'] = $newPassword;
        $user['change_pw'] = !$this->params['no_password_change'];

        if (!$this->User->save($user)) {
            $this->out("Could not update password for user $userId.");
            $this->out($this->json($this->User->validationErrors));
            $this->_stop(self::CODE_ERROR);
        }

        $this->out("Password for $userId changed.");
    }

    public function change_authkey()
    {
        $newkey = null;
        if (isset($this->args[1])) {
            list($userId, $newkey) = $this->args;
        } else {
            list($userId) = $this->args;
        }
        $user = $this->getUser($userId);

        // validate new authentication key if provided
        if (!empty($newkey) && (strlen($newkey) != 40 || !ctype_alnum($newkey))) {
            $this->error('The new auth key needs to be 40 characters long and only alphanumeric.');
        }

        if (empty(Configure::read('Security.advanced_authkeys'))) {
            $oldKey = $user['authkey'];
            if (empty($newkey)) {
                $newkey = $this->User->generateAuthKey();
            }
            $this->User->updateField($user, 'authkey', $newkey);
            $this->Log->createLogEntry('SYSTEM', 'reset_auth_key', 'User', $user['id'],
                __('Authentication key for user %s (%s) updated.', $user['id'], $user['email']),
                ['authkey' =>  [$oldKey, $newkey]]
            );
            $this->out("Authentication key changed to: $newkey");
        } else {
            $newkey = $this->User->AuthKey->resetAuthKey($user['id'], null, $newkey);
            if ($newkey) {
                $this->out("Old authentication keys disabled and new key created: $newkey");
            } else {
                $this->error('There is problem with changing auth key.');
            }
        }
    }

    public function change_role()
    {
        list($userId, $newRole) = $this->args;
        $user = $this->getUser($userId);

        if (is_numeric($newRole)) {
            $conditions = ['Role.id' => $newRole];
        } else {
            $conditions = ['Role.name' => $newRole];
        }

        $newRoleFromDb = $this->User->Role->find('first', [
            'conditions' => $conditions,
            'fields' => ['Role.id'],
        ]);

        if (empty($newRoleFromDb)) {
            $this->error("Role `$newRole` not found.");
        }

        if ($newRoleFromDb['Role']['id'] == $user['role_id']) {
            $this->error("Role `$newRole` is already assigned to {$user['email']}.");
        }

        $this->User->updateField($user, 'role_id', $newRoleFromDb['Role']['id']);

        $this->out("Role changed from `{$user['role_id']}` to `{$newRoleFromDb['Role']['id']}`.");
    }

    public function user_ips()
    {
        list($userId) = $this->args;
        $user = $this->getUser($userId);

        if (empty(Configure::read('MISP.log_user_ips'))) {
            $this->out('<warning>Storing user IP addresses is disabled.</warning>');
        }

        $ips = RedisTool::init()->smembers('misp:user_ip:' . $user['id']);

        if ($this->params['json']) {
            $this->out($this->json($ips));
        } else {
            $this->hr();
            $this->out("User #{$user['id']}: {$user['email']}");
            $this->hr();
            $this->out(implode(PHP_EOL, $ips));
        }
    }

    public function ip_user()
    {
        list($ip) = $this->args;
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->error("IP `$ip` is not valid IPv4 or IPv6 address");
        }

        if (empty(Configure::read('MISP.log_user_ips'))) {
            $this->out('<warning>Storing user IP addresses is disabled.</warning>');
        }

        $userId = RedisTool::init()->get('misp:ip_user:' . $ip);
        if (empty($userId)) {
            $this->out('No hits.');
            $this->_stop();
        }

        $user = $this->User->find('first', [
            'recursive' => -1,
            'conditions' => ['User.id' => $userId],
            'fields' => ['id', 'email'],
        ]);

        if (empty($user)) {
            $this->error("User with ID $userId doesn't exists anymore.");
        }

        $ipCountry = $this->UserLoginProfile->countryByIp($ip);

        if ($this->params['json']) {
            $this->out($this->json([
                'ip' => $ip,
                'id' => $user['User']['id'],
                'email' => $user['User']['email'],
                'country' => $ipCountry,
            ]));
        } else {
            $this->hr();
            $this->out("IP: $ip (country $ipCountry)");
            $this->hr();
            $this->out("User #{$user['User']['id']}: {$user['User']['email']}");
            $this->hr();
        }
    }

    public function ip_country()
    {
        list($ip) = $this->args;
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->error("IP `$ip` is not valid IPv4 or IPv6 address");
        }

        $this->out($this->UserLoginProfile->countryByIp($ip));
    }

    public function require_password_change_for_old_passwords()
    {
        list($days) = $this->args;
        if(!is_numeric($days)){
            $this->error("The amount of days after which a password change is required (the argument) should be numeric.");
        }
        $interval  = 'P' . $days . 'D';

        $current_time = new DateTime();
        $time_before_change_required = $current_time->sub(new DateInterval($interval))->getTimestamp();
        $users = $this->User->find('all', [
            'conditions' => [
                'OR' => [
                    'last_pw_change <' => $time_before_change_required
                ]
            ],
            'fields' => ['id'],
            'recursive' => 0
        ]);
        foreach ($users as $user) {
            $user['User']['change_pw'] = true;
            $userId = $user['User']['id'];
            if (!$this->User->save($user['User'], true, ["change_pw"])) {
                $this->out("Could not update user $userId.");
                $this->out($this->json($this->User->validationErrors));
                $this->_stop(self::CODE_ERROR);
            }
        }
    }

    public function expire_authkeys_without_ip_allowlist()
    {
        $time = time();
        $authkeys = $this->User->AuthKey->find('all', [
            'conditions' => [
                'OR' => [
                    'AuthKey.expiration >' => $time,
                    'AuthKey.expiration' => 0
                ],
                'allowed_ips' => NULL
            ],
            'fields' => ['id', 'user_id'],
            'recursive' => 0
        ]);
        foreach ($authkeys as $authkey) {
            $authkey['AuthKey']['expiration'] = $time;
            $authkeyId = $authkey['AuthKey']['id'];
            if (!$this->User->AuthKey->save($authkey['AuthKey'])) {
                $this->out("Could not update authkey $authkeyId.");
                $this->out($this->json($this->User->AuthKey->validationErrors));
                $this->_stop(self::CODE_ERROR);
            }
        }
    }

    /**
     * @param string|int $userId User ID or User e-mail
     * @return array
     */
    private function getUser($userId)
    {
        // Do not fetch password from database
        $schema = $this->User->schema();
        unset($schema['password']);

        $conditions = is_numeric($userId) ? ['User.id' => $userId] : ['User.email' => $userId];
        $user = $this->User->find('first', [
            'conditions' => $conditions,
            'recursive' => -1,
            'fields' => array_keys($schema),
        ]);
        if (empty($user)) {
            $this->error("User `$userId` not found.");
        }
        return $user['User'];
    }
}
