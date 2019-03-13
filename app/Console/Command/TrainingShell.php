<?php
/*
 * Reset a password
 *
 * arg0 = email
 * arg1 = new password
 */
class TrainingShell extends AppShell {

    public $uses = array('User', 'Organisation');

    private $__currentUrl = false;
    private $__currentAuthKey = false;

    private $__simulate = false;
    private $__config = false;
    private $__report = array();
    private $__verbose = false;

    public function simulate()
    {
        $this->__verbose = $this->params['verbose'];
        $this->__simulate = true;
        $this->setup();
    }

    public function setup()
    {
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
            if ($this->__verbose) {
                echo 'INFO - Instance to configure' . $this->__currentUrl . PHP_EOL;
            }
            $org = str_replace('$ID', $id, $this->__config['org_blueprint']);
            $org_id = $this->Organisation->createOrgFromName($org, 1, true);
            $org_data = $this->Organisation->find('first', array(
                'recursive' => -1,
                'fields' => array('name', 'uuid', 'local'),
                'conditions' => array('Organisation.id' => $org_id)
            ));
            $remote_org_id = $this->__createOrg($org_data);
            $this->__setSetting('MISP.host_org_id', $remote_org_id, $id, $org);
            $this->__report['servers'][$this->__currentUrl]['host_org_id'] = $remote_org_id;
            $this->__report['remote_orgs'][] = array('id' => $remote_org_id, 'name' => $org);
            $role_id = $this->__createRole($this->__config['role_blueprint']);
            $this->__report['servers'][$this->__currentUrl]['training_role_id'] = $role_id;
            $sync_user = $this->__createSyncUserLocally($remote_org_id, $org);
            $local_host_org = $this->Organisation->find('first', array(
                'recursive' => -1,
                'conditions' => array(
                    'Organisation.id' => Configure::read('MISP.host_org_id')
                ),
                'fields' => array(
                    'name', 'id', 'uuid'
                )
            ));
            $hub_org_id_on_remote = $this->__createOrg($local_host_org);
            $external_baseurl = empty(Configure::read('MISP.external_baseurl')) ? Configure::read('MISP.baseurl') : Configure::read('MISP.external_baseurl');
            $this->__report['servers'][$this->__currentUrl]['sync_connections'][] = $this->__addSyncConnection($external_baseurl, 'Exercise hub', $local_host_org, $hub_org_id_on_remote, $sync_user);
            $this->__report['servers'][$this->__currentUrl]['users'] = $this->__createUsers($remote_org_id, $role_id, $org, $id);
            if (!empty($this->__config['settings'])) {
                foreach ($this->__config['settings'] as $key => $value)
                $this->__setSetting($key, $value, $id, $org);
            }
            if ($this->__config['reset_admin_credentials']) {
                $this->__report['servers'][$this->__currentUrl]['management_account'] = $this->__reset_admin_credentials($this->__report);
            }
        }
        echo 'Setup complete. Please find the modifications below:' . PHP_EOL . PHP_EOL;
        echo json_encode($this->__report, JSON_PRETTY_PRINT);
    }

    private function __addSyncConnection($baseurl, $name, $local_host_org, $hub_org_id_on_remote, $sync_user)
    {
        $server = array(
            'name' => $name,
            'url' => $baseurl,
            'authkey' => $sync_user['User']['authkey'],
            'remote_org_id' => $hub_org_id_on_remote,
            'push' => 1,
            'pull' => 1
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

    private function __createSyncUserLocally($remote_org_id, $org)
    {
        $sync_role = $this->User->Role->find('first', array('recursive' => -1, 'conditions' => array('Role.name' => 'Sync user')));
        $sync_role = $sync_role['Role']['id'];
        $this->User->create();
        $this->User->save(array(
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
                'org_id' => $remote_org_id,
                'role_id' => $sync_role,
                'email' => 'sync_user@' . $org . '.test'
        ));
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
        die();
    }

    private function __createUsers($remote_org_id, $role_id, $org, $i)
    {
        $summary = array();
        for ($j = 1; $j < (1+$this->__config['user_count']); $j++) {
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
            if (!empty($response->body)) {
                $user = array(
                    'email' => $email,
                    'password' => $newKey = $this->User->generateRandomPassword(32),
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
                        $summary[] = $response_data['User'];
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
            'url' => $this->__currentUrl . '/organisations/' . $org_data['Organisation']['uuid'],
            'method' => 'GET'
        );
        $response = $this->__queryRemoteMISP($options, true);
        if ($response->code == 404){
            $options = array(
                'body' => $org_data,
                'url' => $this->__currentUrl . '/admin/organisations/add',
                'method' => 'POST'
            );
            $response = $this->__queryRemoteMISP($options, true);
        }

        if ($response->code != 200) {
            $this->__responseError($response, $options);
        } else {
            $response_data = json_decode($response->body, true);
            return $response_data['Organisation']['id'];
        }
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
        ))->description(__('Lookup doc block comments for classes in CakePHP'));
        return $parser;
    }
}
