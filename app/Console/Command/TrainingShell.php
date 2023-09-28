<?php
/*
 * Reset a password
 *
 * arg0 = email
 * arg1 = new password
 */

App::uses('File', 'Utility');


class TrainingShell extends AppShell {

    public $uses = array('User', 'Organisation', 'Server', 'AuthKey');

    private $__currentUrl = false;
    private $__currentAuthKey = false;
    private $__simulate = false;
    private $__config = false;
    private $__report = array();
    private $__verbose = false;
    private $__interactive = false;

    public function simulate()
    {
        $this->__simulate = true;
        $this->setup();
    }

    public function changePasswords()
    {
        $this->__verbose = !empty($this->params['verbose']);
        $this->__interactive = !empty($this->params['interactive']);
        $this->__config = file_get_contents(APP . 'Console/Command/training.json');
        $this->__config = json_decode($this->__config, true);
        $this->__report = array();
        for ($i = $this->__config['ID_start']; $i < ($this->__config['ID_start'] + $this->__config['number_of_misps_to_configure']); $i++) {
            $id = $i;
            if ($this->__config['ID_zero_out']) {
                if ($id < 10) {
                    $id = '0' . $id;
                }
            }
            $this->__currentUrl = str_replace('$ID', $id, $this->__config['server_blueprint']);
            if ($this->__interactive) {
                $question = sprintf('Configure instance at %s?', $this->__currentUrl);
                $input = $this->__user_input($question, array('y', 'n'));
                if ($input === 'n') {
                    $this->__printReport('Stopping execution. Data created so far:' . PHP_EOL . PHP_EOL);
                    die();
                }
            }
            if ($this->__verbose) {
                echo 'INFO - Instance to configure' . $this->__currentUrl . PHP_EOL;
            }
            $org = str_replace('$ID', $id, $this->__config['org_blueprint']);
            $this->__report['servers'][$this->__currentUrl]['users'] = $this->__resetPasswords($org, $id);
        }
        $this->__printReport('Password change complete. Please find the modifications below:' . PHP_EOL . PHP_EOL);
    }

    public function setup()
    {
        $this->__verbose = !empty($this->params['verbose']);
        $this->__interactive = !empty($this->params['interactive']);
        $this->__config = file_get_contents(APP . 'Console/Command/training.json');
        if (empty($this->__config)) {
            echo 'No config file found. Make sure that training.json exists and is configured.';
            die();
        }
        $this->__config = json_decode($this->__config, true);
        $this->__report = array();
        for ($i = $this->__config['ID_start']; $i < ($this->__config['ID_start'] + $this->__config['number_of_misps_to_configure']); $i++) {
            $id = $i;
            if ($this->__config['ID_zero_out']) {
                if ($id < 10) {
                    $id = '0' . $id;
                }
            }
            $this->__currentUrl = str_replace('$ID', $id, $this->__config['server_blueprint']);
            if ($this->__interactive) {
                $question = sprintf('Configure instance at %s?', $this->__currentUrl);
                $input = $this->__user_input($question, array('y', 'n'));
                if ($input === 'n') {
                    $this->__printReport('Stopping execution. Data created so far:' . PHP_EOL . PHP_EOL);
                    die();
                }
            }
            if ($this->__verbose) {
                echo 'INFO - Instance to configure' . $this->__currentUrl . PHP_EOL;
            }
            $org = $this->__createOrgFromBlueprint($id);
            $this->__setSetting('MISP.host_org_id', $org['Organisation']['remote_org_id'], $id, $org['Organisation']['name']);
            $this->__report['servers'][$this->__currentUrl]['host_org_id'] = $org['Organisation']['remote_org_id'];
            $this->__report['remote_orgs'][] = array('id' => $org['Organisation']['remote_org_id'], 'name' => $org['Organisation']['name']);
            $role_id = $this->__createRole($this->__config['role_blueprint']);
            $this->__report['servers'][$this->__currentUrl]['training_role_id'] = $role_id;
            $sync_user = $this->__createSyncUserLocally($org['Organisation']['remote_org_id'], $org['Organisation']['name'], $org['Organisation']['id']);
            $this->__report['users'][] = $sync_user;
            $local_host_org = $this->__getLocalHostOrgId();
            $hub_org_id_on_remote = $this->__createOrg($local_host_org);
            $external_baseurl = empty(Configure::read('MISP.external_baseurl')) ? Configure::read('MISP.baseurl') : Configure::read('MISP.external_baseurl');
            $this->__report['servers'][$this->__currentUrl]['sync_connections'][] = $this->__addSyncConnection($external_baseurl, 'Exercise hub', $local_host_org, $hub_org_id_on_remote, $sync_user);
            $this->__report['servers'][$this->__currentUrl]['users'] = $this->__createUsers($org['Organisation']['remote_org_id'], $role_id, $org['Organisation']['name'], $id);
            if (!empty($this->__config['create_sync_both_ways'])) {
                $this->__createReverseSyncConnection($org['Organisation']['id'], $org['Organisation']['name'], $local_host_org);
            }
            if (!empty($this->__config['create_admin_user'])) {
                $this->__report['servers'][$this->__currentUrl['users']][] = $this->__addAdminUserRemotely($i, $org['Organisation']['name'], $org['Organisation']['remote_org_id']);
            }
            if (!empty($this->__config['settings'])) {
                foreach ($this->__config['settings'] as $key => $value)
                $this->__setSetting($key, $value, $id, $org['Organisation']['name']);
            }
            if ($this->__config['reset_admin_credentials']) {
                $this->__report['servers'][$this->__currentUrl]['management_account'] = $this->__reset_admin_credentials($this->__report);
            }
        }
        $this->__printReport('Setup complete. Please find the modifications below:' . PHP_EOL . PHP_EOL);
    }

    public function createOrganisationsFromConfig()
    {
        $rawConfig = file_get_contents(APP . 'Console/Command/config_orgs.json');
        $config = json_decode($rawConfig, true);
        $createdOrgs = [];
        foreach ($config as $org) {
            $filepath = APP . 'Console/Command/' . $org['Organisation']['logo_path'];
            $file = new File($filepath, false);
            if ($file->exists()) {
                $org['Organisation']['logo'] = [
                    'name' => $file->name(),
                    'type' => $file->mime(),
                    'tmp_name' => $filepath,
                    'error' => 0,
                    'size' => $file->size(),
                ];
            }
            $file->close();
            $date = date('Y-m-d H:i:s');
            $org['Organisation']['date_created'] = $date;
            $org['Organisation']['date_modified'] = $date;
            $this->Organisation->create();
            $this->Organisation->save($org);
            $filename = $this->Organisation->id . '.' . ($file->ext() === 'svg' ? 'svg' : 'png');
            $file->copy(APP . 'webroot/img/orgs/' . $filename);
            $createdOrg = $this->Organisation->find('first', ['conditions' => ['id' => $this->Organisation->id]]);
            $createdOrgs[$createdOrg['Organisation']['uuid']] = $createdOrg['Organisation'];
        }
        return $createdOrgs;
    }

    public function createUsersFromConfig($createdOrgs)
    {
        $rawConfig = file_get_contents(APP . 'Console/Command/config_users.json');
        $config = json_decode($rawConfig, true);
        $createdUsers = [];
        foreach ($config as $user) {
            if (!empty($user['org_uuid'])) {
                $user['org_id'] = $createdOrgs[$user['org_uuid']]['id'];
            }
            $existingUser = $this->User->find('first', [
                'recursive' => -1,
                'conditions' => ['User.email' => $user['email']],
            ]);
            if (empty($existingUser)) {
                $this->User->create();
            } else {
                $user['id'] = $existingUser['User']['id'];
            }
            $this->User->save($user);
            $createdUser = $this->User->find('first', ['id' => $this->User->id]);
            $createdUsers[] = $createdUser;
        }
        return $createdUsers;
    }

    public function setSettingsFromConfig($createdOrgs)
    {
        $rawConfig = file_get_contents(APP . 'Console/Command/config_settings.json');
        $config = json_decode($rawConfig, true);
        $cli_user = ['id' => 0, 'email' => 'SYSTEM', 'Organisation' => ['name' => 'SYSTEM']];
        foreach ($config as $setting_name => $value) {
            if ($setting_name == 'MISP.host_org_id') {
                $value = $createdOrgs[$value]['id'];
            }
            $setting = $this->Server->getSettingData($setting_name);
            if (empty($setting)) {
                $this->error(__('Setting change rejected.'));
            }
            $result = $this->Server->serverSettingsEditValue($cli_user, $setting, $value, true);
            if (empty($result)) {
                $this->error(__('Setting change rejected.'));
            }
        }
    }

    public function createRemoteServersFromConfig($createdOrgs, $createdUsers)
    {
        $rawConfig = file_get_contents(APP . 'Console/Command/config_syncs.json');
        $config = json_decode($rawConfig, true);
        $createdServers = [];
        foreach ($config as $sync) {
            $sync['org_id'] = $createdOrgs[$sync['org_uuid']]['id'];
            $sync['remote_org_id'] = $createdOrgs[$sync['remote_org_uuid']]['id'];
            $this->Server->create();
            $this->Server->save($sync);
            $createdServer = $this->User->find('first', ['id' => $this->User->id]);
            $createdServers[] = $createdServer;
        }
        return $createdServers;
    }

    public function createAllFromConfig()
    {
        $createdOrgs = $this->createOrganisationsFromConfig();
        $createdUsers = $this->createUsersFromConfig($createdOrgs);
        $this->setSettingsFromConfig($createdOrgs);
        $this->createRemoteServersFromConfig($createdOrgs, $createdUsers);
    }

    public function WipeAllSyncs()
    {
        $this->Server->deleteAll(['Server.id !=' => 0]);
    }

    public function WipeAllUsers()
    {
        $this->User->deleteAll(['User.email !=' => 'admin@admin.test']);
    }

    public function WipeAllOrgs()
    {
        $this->Organisation->deleteAll(['Organisation.name !=' => 'ORGNAME']);
    }

    public function WipeAllAuthkeys()
    {
        $this->AuthKey->deleteAll(['AuthKey.id !=' => 0]);
    }

    private function __createOrgFromBlueprint($id)
    {
        $org = str_replace('$ID', $id, $this->__config['org_blueprint']);
        $org_id = $this->Organisation->createOrgFromName($org, 1, true);
        if (empty($org_id)) {
            sprintf("Something went wrong. Could not create organisation with the following input: \n\n", $org);
        }
        $org_data = $this->Organisation->find('first', array(
            'recursive' => -1,
            'fields' => array('name', 'uuid', 'local', 'id'),
            'conditions' => array('Organisation.id' => $org_id)
        ));
        $org_data['Organisation']['remote_org_id'] = $this->__createOrg($org_data);
        return $org_data;
    }

    private function __getLocalHostOrgId()
    {
        $org = $this->Organisation->find('first', array(
            'recursive' => -1,
            'conditions' => array(
                'Organisation.id' => empty(Configure::read('MISP.host_org_id')) ? -1 : Configure::read('MISP.host_org_id')
            ),
            'fields' => array(
                'name', 'id', 'uuid'
            )
        ));
        if (empty($org)) {
            $this->__printReport('Stopping execution, no host_org_id set on the current instance, or the setting points to a non-existing org. Data created so far:' . PHP_EOL . PHP_EOL);
            die();
        }
        return $org;
    }

    private function __createReverseSyncConnection($remote_org_id_on_local, $org_name, $host_org_id_on_local)
    {
        $sync_user = $this->__addSyncUserRemotely();
        $this->__report['servers'][$this->__currentUrl]['users'][] = $sync_user;
        $sync_server = $this->__addSyncConnectionLocally($this->__currentUrl, $org_name . '_misp', $remote_org_id_on_local, $sync_user, $host_org_id_on_local);
        if ($sync_server) {
            $this->__report['sync'][] = $sync_server;
        }
    }

    private function __printReport($message)
    {
        echo json_encode($this->__report, JSON_PRETTY_PRINT);
        $this->__report = '';
        return true;
    }

    private function __findRemoteRoleId($role_name)
    {
        $options = array(
            'url' => $this->__currentUrl . '/roles/index',
            'method' => 'GET'
        );
        $response = $this->__queryRemoteMISP($options, true);
        if ($response->code == 200) {
            $roles = json_decode($response->body, true);
            foreach ($roles as $role) {
                if ($role['Role']['name'] == $role_name) {
                    return $role['Role']['id'];
                }
            }
        } else {
            $this->__responseError($response, $options);
        }
        return false;
    }

    private function __getRemoteAdminUser()
    {
        $options = array(
            'url' => $this->__currentUrl . '/users/view/me',
            'method' => 'GET'
        );
        $response = $this->__queryRemoteMISP($options, true);
        if ($response->code == 200) {
            return json_decode($response->body, true);
        } else {
            $this->__responseError($response, $options);
        }
        return false;
    }

    private function __addAdminUserRemotely($i, $org, $remote_org_id)
    {
        $email = $this->__config['user_blueprint'];
        $email = str_replace('$ORGNAME', $org, $email);
        $email = str_replace('$ID', $i, $email);
        $email = 'admin' . substr($email, strpos($email, '@'));
        $admin_role_id = $this->__findRemoteRoleId('Admin');
        if (!$admin_role_id) {
            echo 'Remote instance lacks the required role (Admin).' . PHP_EOL ;
            die();
        }
        $options = array(
            'url' => $this->__currentUrl . '/admin/users/index/searchall:' . $email,
            'method' => 'GET'
        );
        $response = $this->__queryRemoteMISP($options, true);
        if ($response->code != 200) {
            $this->__responseError($response, $options);
        }
        $newKey = $this->User->generateRandomPassword(32);
        if (empty(json_decode($response->body, true))) {
            $user = array(
                'email' => $email,
                'password' => $newKey,
                'role_id' => $admin_role_id,
                'org_id' => $remote_org_id
            );
            $options = array(
                'url' => $this->__currentUrl . '/admin/users/add',
                'method' => 'POST',
                'body' => $user
            );
            $response = $this->__queryRemoteMISP($options, true);
            if ($response->code != 200) {
                $this->__responseError($response, $options);
            } else {
                $response_data = json_decode($response->body, true);
                if (!$this->__simulate) {
                    $user['authkey'] = $response_data['User']['authkey'];
                }
            }
        } else {
            $user = json_decode($response->body, true)[0]['User'];
        }
        return $user;
    }

    private function __addSyncUserRemotely()
    {
        $sync_user_role_id = $this->__findRemoteRoleId('Sync user');
        if (!$sync_user_role_id) {
            echo 'Remote instance lacks the required role (Sync user).' . PHP_EOL ;
            die();
        }
        $remote_admin = $this->__getRemoteAdminUser();
        if (!$remote_admin) {
            echo 'Remote instance did not return the admin user\'s information.' . PHP_EOL ;
            die();
        }
        $email = $remote_admin['User']['email'];
        $email = 'sync' . substr($email, strpos($email, '@'));
        $options = array(
            'url' => $this->__currentUrl . '/admin/users/index/searchall:' . $email,
            'method' => 'GET'
        );
        $response = $this->__queryRemoteMISP($options, true);
        if ($response->code != 200) {
            $this->__responseError($response, $options);
        }
        $newKey = $this->User->generateRandomPassword(32);
        if (empty(json_decode($response->body, true))) {
            $user = array(
                'email' => $email,
                'password' => $newKey,
                'role_id' => $sync_user_role_id,
                'org_id' => $remote_admin['User']['role_id']
            );
            $options = array(
                'url' => $this->__currentUrl . '/admin/users/add',
                'method' => 'POST',
                'body' => $user
            );
            $response = $this->__queryRemoteMISP($options, true);
            if ($response->code != 200) {
                $this->__responseError($response, $options);
            } else {
                $response_data = json_decode($response->body, true);
                if (!$this->__simulate) {
                    $user['authkey'] = $response_data['User']['authkey'];
                }
            }
        } else {
            $user = json_decode($response->body, true)[0]['User'];
        }
        return $user;
    }

    private function __addSyncConnectionLocally($baseurl, $org_name, $remote_org_id_on_local, $sync_user, $host_org_id_on_local)
    {
        $this->Server->create();
        $server = array(
            "name" => $org_name,
            "url" => $baseurl,
            "authkey" => $sync_user['authkey'],
            "push" => 1,
            "pull" => 1,
            "remote_org_id" => $sync_user['org_id'],
            "self_signed" => 1,
            "org_id" => Configure::read('MISP.host_org_id')
        );
        $result = $this->Server->save($server);
        if (!$result) {
            echo sprintf(
                'Could not add connection to %s. Reason: %s.' . PHP_EOL,
                $baseurl,
                json_encode($this->Server->validationErrors)
            );
            return false;
        }
        return $server;
    }

    private function __addSyncConnection($baseurl, $name, $local_host_org, $hub_org_id_on_remote, $sync_user)
    {
        $server = array(
            'name' => $name,
            'url' => $baseurl,
            'authkey' => $sync_user['User']['authkey'],
            'remote_org_id' => $hub_org_id_on_remote,
            'push' => 1,
            'pull' => 1,
            'self_signed' => 1
        );
        $options = array(
            'url' => $this->__currentUrl . '/servers/add',
            'method' => 'POST',
            'body' => $server
        );
        $response = $this->__queryRemoteMISP($options, true);
        if ($response->code != 200) {
            $this->__responseError($response, $options);
        } else {
            $response_data = json_decode($response->body, true);
            return array(
                'url' => $response_data['Server']['url'],
                'authkey' => $response_data['Server']['authkey']
            );
        }
    }

    private function __createSyncUserLocally($remote_org_id, $org, $local_org_id)
    {
        $sync_role = $this->User->Role->find('first', array('recursive' => -1, 'conditions' => array('Role.name' => 'Sync user')));
        $sync_role = $sync_role['Role']['id'];
        $this->User->create();
        $user = array(
                'external_auth_required' => 0,
                'external_auth_key' => '',
                'server_id' => 0,
                'gpgkey' => '',
                'certif_public' => '',
                'autoalert' => 0,
                'contactalert' => 0,
                'disabled' => 0,
                'newsread' => 0,
                'change_pw' => 1,
                'authkey' => $this->User->generateAuthKey(),
                'termsaccepted' => 0,
                'org_id' => $local_org_id,
                'role_id' => $sync_role,
                'email' => 'sync_user@' . $org . '.test'
        );
        $result = $this->User->save($user);
        if (!$result) {
            echo 'Could not add sync user due to validation error. Error: ' . json_encode($this->User->validationErrors) . PHP_EOL . PHP_EOL;
            echo 'Input was: ' . json_encode($user, true) . PHP_EOL . PHP_EOL;
        }
        $user = $this->User->find('first', array('recursive' => -1, 'conditions' => array('User.email' => 'sync_user@' . $org . '.test')));
        return $user;
    }

    private function __responseError($response, $options)
    {
        echo sprintf(
            "Received a non-200 response (%s). Aborting.\nQueried URL: %s\n Query type: %s\n Request payload: %s\n\n",
            $response->code,
            $options['url'],
            $options['method'],
            empty($options['body']) ? '' : json_encode($options['body'], JSON_PRETTY_PRINT)
        );
        if ($this->__interactive) {
            $question = 'The above error can cause the issues to compound if you continue. For example, not creating an organisation that subsequently created users should belong to will fail. Would you like to continue?';
            $input = $this->__user_input($question, array('y', 'n'));
            if ($input === 'y') {
                return true;
            }
        }
        $this->__printReport('Setup failed. Output of what has been created:' . PHP_EOL . PHP_EOL);
        die();
    }

    private function __resetPasswords($org, $i)
    {
        $summary = array();
        for ($j = 1; $j < (1 + $this->__config['user_count']); $j++) {
            $email = $this->__config['user_blueprint'];
            $email = str_replace('$ID', $i, $email);
            $email = str_replace('$ORGNAME', $org, $email);
            $email = str_replace('$USER_ITERATOR', $j, $email);
            $options = array(
                'url' => $this->__currentUrl . '/admin/users/index/searchall:' . $email,
                'method' => 'GET'
            );
            $response = $this->__queryRemoteMISP($options, true);
            if ($response->code != 200) {
                $this->__responseError($response, $options);
            }
            $newKey = $this->User->generateRandomPassword(32);
            $user = json_decode($response->body, true);
            if (!empty($user)) {
                $user = $user[0];
                $user['User']['password'] = $newKey;
                $user['User']['confirm_password'] = $newKey;
                $options = array(
                    'url' => $this->__currentUrl . '/admin/users/edit/' . $user['User']['id'],
                    'method' => 'POST',
                    'body' => $user
                );
                $response = $this->__queryRemoteMISP($options, true);
                if ($response->code != 200) {
                    $this->__responseError($response, $options);
                } else {
                    $response_data = json_decode($response->body, true);
                    if ($this->__simulate) {
                        $summary[] = array(
                            'id' => $user['User']['id'],
                            'email' => $user['User']['email'],
                            'password' => $newKey,
                        );
                    } else {
                        $user['User']['authkey'] = $response_data['User']['authkey'];
                        $summary[] = array(
                            'id' => $user['User']['id'],
                            'email' => $user['User']['email'],
                            'password' => $newKey,
                            'authkey' => $user['User']['authkey']
                        );
                    }
                }
            }
        }
        return $summary;
    }

    private function __createUsers($remote_org_id, $role_id, $org, $i)
    {
        $summary = array();
        for ($j = 1; $j < (1 + $this->__config['user_count']); $j++) {
            $email = $this->__config['user_blueprint'];
            $email = str_replace('$ID', $i, $email);
            $email = str_replace('$ORGNAME', $org, $email);
            $email = str_replace('$USER_ITERATOR', $j, $email);
            $options = array(
                'url' => $this->__currentUrl . '/admin/users/index/searchall:' . $email,
                'method' => 'GET'
            );
            $response = $this->__queryRemoteMISP($options, true);
            if ($response->code != 200) {
                $this->__responseError($response, $options);
            }
            $newKey = $this->User->generateRandomPassword(32);
            if (empty(json_decode($response->body, true))) {
                $user = array(
                    'email' => $email,
                    'password' => $newKey,
                    'role_id' => $role_id,
                    'org_id' => $remote_org_id
                );
                $options = array(
                    'url' => $this->__currentUrl . '/admin/users/add',
                    'method' => 'POST',
                    'body' => $user
                );
                $response = $this->__queryRemoteMISP($options, true);
                if ($response->code != 200) {
                    $this->__responseError($response, $options);
                } else {
                    $response_data = json_decode($response->body, true);
                    if ($this->__simulate) {
                        $summary[] = $user;
                    } else {
                        $user['authkey'] = $response_data['User']['authkey'];
                        $summary[] = $user;
                    }
                }
            }
        }
        return $summary;
    }

    private function __createRole($blueprint)
    {
        $blueprint = array('Role' => $blueprint);
        $options = array(
            'url' => $this->__currentUrl . '/roles/index',
            'method' => 'GET'
        );
        $response = $this->__queryRemoteMISP($options, true);
        if ($response->code == 200) {
            $roles = json_decode($response->body, true);
            $found = false;
            foreach ($roles as $role) {
                if ($role['Role']['name'] == $blueprint['Role']['name']) {
                    return $role['Role']['id'];
                }
            }
            $options = array(
                'url' => $this->__currentUrl . '/admin/roles/add',
                'method' => 'POST',
                'body' => $blueprint
            );
            $response = $this->__queryRemoteMISP($options, true);
            if ($response->code != 200) {
                $this->__responseError($response, $options);
            } else {
                $response_data = json_decode($response->body, true);
                return $response_data['Role']['id'];
            }
        } else {
            $this->__responseError($response, $options);
        }
    }

    private function __reset_admin_credentials()
    {
        $credentials = array(
            'authkey' => $this->User->generateAuthKey(),
            'password' => $this->User->generateRandomPassword(32)
        );
        $this->__queryRemoteMISP(array(
            'url' => $this->__currentUrl . '/admin/users/edit/1',
            'body' => array('User' => array(
                'password' => $credentials['password'],
                'authkey' => $credentials['authkey']
            )),
            'method' => 'POST'
        ));
        return $credentials;
    }

    private function __createOrg($org_data)
    {
        $options = array(
            'url' => $this->__currentUrl . '/organisations/index.json',
            'method' => 'GET'
        );
        $response = $this->__queryRemoteMISP($options, true);
        if ($response->code != 200) {
            $this->__responseError($response, $options);
        } else {
            $response_data = json_decode($response->body, true);
            $found = false;
            foreach ($response_data as $existingOrg) {
                if ($existingOrg['Organisation']['name'] == $org_data['Organisation']['name']) {
                    return $existingOrg['Organisation']['id'];
                }
            }
            if (isset($org_data['Organisation'])) {
                $org_data = $org_data['Organisation'];
            }
            unset($org_data['id']);
            $options = array(
                'body' => $org_data,
                'url' => $this->__currentUrl . '/admin/organisations/add',
                'method' => 'POST'
            );
            $response = $this->__queryRemoteMISP($options, true);
            if ($response->code != 200) {
                $this->__responseError($response, $options);
            }
            $options = array(
                'url' => $this->__currentUrl . '/organisations/view/' . $org_data['uuid'],
                'method' => 'GET'
            );
            $response = $this->__queryRemoteMISP($options, true);
            if ($response->code != 200) {
                $this->__responseError($response, $options);
            }
            $response_data = json_decode($response->body, true);
            return $response_data['Organisation']['id'];
        }
    }

    private function __user_input($question, $valid_input_options)
    {
        $valid_input = false;
        while (!$valid_input) {
            echo sprintf(
                '%s (%s)' . PHP_EOL,
                $question,
                implode('/', $valid_input_options)
            );
            $handle = fopen ("php://stdin","r");
            $input = trim(strtolower(fgets($handle)));
            if (in_array($input, $valid_input_options)) {
                $valid_input = true;
            }
        }
        return $input;
    }


    private function __setSetting($key, $value, $i, $org)
    {
        $value = str_replace('$ID', $i, $value);
        $value = str_replace('$ORGNAME', $org, $value);
        $options = array(
            'url' => $this->__currentUrl . '/servers/serverSettingsEdit/' . $key,
            'method' => 'POST',
            'body' => array('value' => $value)
        );
        $response = $this->__queryRemoteMISP($options, true);
        if ($response->code != 200) {
            $this->__responseError($response, $options);
        } else {
            return true;
        }
    }


    private function __queryRemoteMISP($options, $returnFullResponse = false)
    {
        $params = array();
        App::uses('HttpSocket', 'Network/Http');
        $params['ssl_allow_self_signed'] = true;
        $params['ssl_verify_peer_name'] = false;
        $params['ssl_verify_peer'] = false;
        $HttpSocket = new HttpSocket($params);
        $request = array(
            'header' => array(
                    'Authorization' => $this->__config['authkey'],
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json'
            )
        );
        if ($this->__simulate) {
            if ($this->__verbose) {
                echo 'SIMULATION - query to be executed:' . PHP_EOL . json_encode($options) . PHP_EOL . ' using request object:' . PHP_EOL . json_encode($request) . PHP_EOL . PHP_EOL;
            }
            $response = new class{};
            $response->code = 200;
            $response->body = '{"id": 666, "Organisation": {"id": 666}, "User": {"id": 666, "email": "foo"}, "Role": {"id": 666}, "Server": {"url": "https://foo.bar", "authkey": "bla"}}';
            return $response;
        } else {
            if ($this->__verbose) {
                echo 'EXEC - query to be executed:' . PHP_EOL . json_encode($options) . PHP_EOL . ' using request object:' . PHP_EOL . json_encode($request) . PHP_EOL . PHP_EOL;
            }
            if ($options['method'] === 'POST') {
                $response = $HttpSocket->post($options['url'], json_encode($options['body']), $request);
            } else {
                $response = $HttpSocket->get($options['url'], '', $request);
            }
            if ($returnFullResponse) {
                return $response;
            }
            if ($response->code != 200) {
                $this->__responseError($response, $options);
            } else {
                return json_decode($response->body, true);
            }
        }
    }

    public function getOptionParser()
    {
        $parser = parent::getOptionParser();
        $parser->addOption('verbose', array(
            'short' => 'v',
            'help' => __('verbose mode'),
            'boolean' => 1
        ))->addOption('interactive', array(
            'short' => 'i',
            'help' => __('interactive mode'),
            'boolean' => 1
        ));
        return $parser;
    }
}
