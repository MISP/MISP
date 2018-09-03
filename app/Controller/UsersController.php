<?php
App::uses('AppController', 'Controller');

class UsersController extends AppController
{
    public $newkey;

    public $components = array(
            'Security',
            'Email',
            'RequestHandler'
    );

    public $paginate = array(
            'limit' => 60,
            'recursive' => -1,
            'order' => array(
                    'Organisation.name' => 'ASC'
            ),
            'contain' => array(
                'Organisation' => array('id', 'name'),
                'Role' => array('id', 'name', 'perm_auth')
            )
    );

    public $helpers = array('Js' => array('Jquery'));

    public function beforeFilter()
    {
        parent::beforeFilter();

        // what pages are allowed for non-logged-in users
        $this->Auth->allow('login', 'logout');
    }

    public function view($id = null)
    {
        if ("me" == $id) {
            $id = $this->Auth->user('id');
        }
        if (!$this->_isSiteAdmin() && $this->Auth->user('id') != $id) {
            throw new NotFoundException(__('Invalid user or not authorised.'));
        }
        if (!is_numeric($id) && !empty($id)) {
            $userId = $this->User->find('first', array(
                    'conditions' => array('email' => $id),
                    'fields' => array('id')
            ));
            $id = $userid['User']['id'];
        }
        $this->User->id = $id;
        $this->User->recursive = 0;
        if (!$this->User->exists()) {
            throw new NotFoundException(__('Invalid user'));
        }
        $user = $this->User->read(null, $id);
        if (!empty($user['User']['gpgkey'])) {
            $pgpDetails = $this->User->verifySingleGPG($user);
            $user['User']['pgp_status'] = isset($pgpDetails[2]) ? $pgpDetails[2] : 'OK';
            $user['User']['fingerprint'] = !empty($pgpDetails[4]) ? $pgpDetails[4] : 'N/A';
        }
        if ($this->_isRest()) {
            unset($user['User']['server_id']);
            $user['User']['password'] = '*****';
            return $this->RestResponse->viewData(array('User' => $user['User']), $this->response->type());
        } else {
            $this->set('user', $user);
        }
    }

    public function request_API()
    {
        if (Configure::read('MISP.disable_emailing')) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'API access request failed. E-mailing is currently disabled on this instance.')), 'status'=>200, 'type' => 'json'));
        }
        $responsibleAdmin = $this->User->findAdminsResponsibleForUser($this->Auth->user());
        if (isset($responsibleAdmin['email']) && !empty($responsibleAdmin['email'])) {
            $subject = "[MISP " . Configure::read('MISP.org') . "] User requesting API access";
            $body = "A user (" . $this->Auth->user('email') . ") has sent you a request to enable his/her API key access." . PHP_EOL;
            $body .= "You can edit the user's profile at " . Configure::read('MISP.baseurl') . '/admin/users/edit/' . $this->Auth->user('id');
            $user = $this->User->find('first', array('conditions' => array('User.id' => $responsibleAdmin['id'])));
            $result = $this->User->sendEmail($user, $body, false, $subject);
            if ($result) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'API access requested.')), 'status'=>200, 'type' => 'json'));
            }
        }
        return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Something went wrong, please try again later.')), 'status'=>200, 'type' => 'json'));
    }

    public function edit()
    {
        if (!$this->_isAdmin() && Configure::read('MISP.disableUserSelfManagement')) {
            throw new MethodNotAllowedException('User self-management has been disabled on this instance.');
        }
        $id = $this->Auth->user('id');
        $this->User->read(null, $id);
        if (!$this->User->exists()) {
            throw new NotFoundException('Something went wrong. Your user account could not be accessed.');
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            $abortPost = false;
            if (!$this->_isSiteAdmin() && !empty($this->request->data['User']['email'])) {
                $organisation = $this->User->Organisation->find('first', array(
                    'conditions' => array('Organisation.id' => $this->Auth->user('org_id')),
                    'recursive' => -1
                ));
                if (!empty($organisation['Organisation']['restricted_to_domain'])) {
                    $abortPost = true;
                    foreach ($organisation['Organisation']['restricted_to_domain'] as $restriction) {
                        if (
                            strlen($this->request->data['User']['email']) > strlen($restriction) &&
                            substr($this->request->data['User']['email'], (-1 * strlen($restriction))) === $restriction &&
                            in_array($this->request->data['User']['email'][strlen($this->request->data['User']['email']) - strlen($restriction) -1], array('@', '.'))
                        ) {
                            $abortPost = false;
                        }
                    }
                    if ($abortPost) {
                        $this->Flash->error(__('Invalid e-mail domain. Your user is restricted to creating users for the following domain(s): ') . implode(', ', $organisation['Organisation']['restricted_to_domain']));
                    }
                }
            }
            if (!$abortPost && !$this->_isRest()) {
                if (Configure::read('Security.require_password_confirmation')) {
                    if (!empty($this->request->data['User']['current_password'])) {
                        $hashed = $this->User->verifyPassword($this->Auth->user('id'), $this->request->data['User']['current_password']);
                        if (!$hashed) {
                            $abortPost = true;
                            $this->Flash->error('Invalid password. Please enter your current password to continue.');
                        }
                        unset($this->request->data['User']['current_password']);
                    } else {
                        $abortPost = true;
                        $this->Flash->info('Please enter your current password to continue.');
                    }
                }
            }
            if (!$abortPost) {
                // What fields should be saved (allowed to be saved)
                $fieldList = array('email', 'autoalert', 'gpgkey', 'certif_public', 'nids_sid', 'contactalert', 'disabled');
                if ("" != $this->request->data['User']['password']) {
                    $fieldList[] = 'password';
                }
                // Save the data
                if ($this->User->save($this->request->data, true, $fieldList)) {
                    $this->Flash->success(__('The profile has been updated'));
                    $this->_refreshAuth();
                    $this->redirect(array('action' => 'view', $id));
                } else {
                    $this->Flash->error(__('The profile could not be updated. Please, try again.'));
                }
            }
        } else {
            $this->User->set('password', '');
            $this->request->data = $this->User->data;
        }
        $this->loadModel('Server');
        $this->set('complexity', !empty(Configure::read('Security.password_policy_complexity')) ? Configure::read('Security.password_policy_complexity') : $this->Server->serverSettings['Security']['password_policy_complexity']['value']);
        $this->set('length', !empty(Configure::read('Security.password_policy_length')) ? Configure::read('Security.password_policy_length') : $this->Server->serverSettings['Security']['password_policy_length']['value']);
        $roles = $this->User->Role->find('list');
        $this->set(compact('roles'));
        $this->set('id', $id);
    }

    public function change_pw()
    {
        if (!$this->_isAdmin() && Configure::read('MISP.disableUserSelfManagement')) {
            throw new MethodNotAllowedException('User self-management has been disabled on this instance.');
        }
        $id = $this->Auth->user('id');
        $user = $this->User->find('first', array(
            'conditions' => array('User.id' => $id),
            'recursive' => -1
        ));
        if ($this->request->is('post') || $this->request->is('put')) {
            $abortPost = false;
            if (Configure::read('Security.require_password_confirmation')) {
                if (!empty($this->request->data['User']['current_password'])) {
                    $hashed = $this->User->verifyPassword($this->Auth->user('id'), $this->request->data['User']['current_password']);
                    if (!$hashed) {
                        $abortPost = true;
                        $this->Flash->error('Invalid password. Please enter your current password to continue.');
                    }
                    unset($this->request->data['User']['current_password']);
                } else {
                    $abortPost = true;
                    $this->Flash->info('Please enter your current password to continue.');
                }
            }
            if (!$abortPost) {
                // What fields should be saved (allowed to be saved)
                $user['User']['change_pw'] = 0;
                $user['User']['password'] = $this->request->data['User']['password'];
                $user['User']['confirm_password'] = $this->request->data['User']['confirm_password'];
                $temp = $user['User']['password'];
                // Save the data
                if ($this->User->save($user)) {
                    $this->Flash->success(__('Password Changed.'));
                    $this->_refreshAuth();
                    $this->__extralog("change_pw");
                    $this->redirect(array('action' => 'view', $id));
                } else {
                    $this->Flash->error(__('The password could not be updated. Make sure you meet the minimum password length / complexity requirements.'));
                }
            }
        }
        $this->loadModel('Server');
        $this->set('complexity', !empty(Configure::read('Security.password_policy_complexity')) ? Configure::read('Security.password_policy_complexity') : $this->Server->serverSettings['Security']['password_policy_complexity']['value']);
        $this->set('length', !empty(Configure::read('Security.password_policy_length')) ? Configure::read('Security.password_policy_length') : $this->Server->serverSettings['Security']['password_policy_length']['value']);
        $this->User->recursive = 0;
        $this->User->read(null, $id);
        $this->User->set('password', '');
        $this->request->data = $this->User->data;
        $roles = $this->User->Role->find('list');
        $this->set(compact('roles'));
    }

    public function admin_index()
    {
        if (!$this->_isAdmin()) {
            throw new NotFoundException(__('Invalid user or not authorised.'));
        }
        $this->User->virtualFields['org_ci'] = 'UPPER(Organisation.name)';
        $urlParams = "";
        $passedArgsArray = array();
        $booleanFields = array('autoalert', 'contactalert', 'termsaccepted');
        $textFields = array('role', 'email', 'all', 'authkey');
        // org admins can't see users of other orgs
        if ($this->_isSiteAdmin()) {
            $textFields[] = 'org';
        }
        $this->set('passedArgs', json_encode($this->passedArgs));
        // check each of the passed arguments whether they're a filter (could also be a sort for example) and if yes, add it to the pagination conditions
        foreach ($this->passedArgs as $k => $v) {
            if (substr($k, 0, 6) === 'search') {
                if ($v != "") {
                    if ($urlParams != "") {
                        $urlParams .= "/";
                    }
                    $urlParams .= $k . ":" . $v;
                }
                $searchTerm = substr($k, 6);
                if (in_array($searchTerm, $booleanFields)) {
                    if ($v != "") {
                        $this->paginate['conditions'][] = array('User.' . $searchTerm => $v);
                    }
                } elseif (in_array($searchTerm, $textFields)) {
                    if ($v != "") {
                        if ($searchTerm == "role") {
                            $searchTerm = "role_id";
                        }
                        $pieces = explode('|', $v);
                        $test = array();
                        foreach ($pieces as $piece) {
                            if ($piece[0] == '!') {
                                if ($searchTerm == 'email') {
                                    $this->paginate['conditions']['AND'][] = array('LOWER(User.' . $searchTerm . ') NOT LIKE' => '%' . strtolower(substr($piece, 1)) . '%');
                                } elseif ($searchTerm == 'org') {
                                    $this->paginate['conditions']['AND'][] = array('User.org_id !=' => substr($piece, 1));
                                } else {
                                    $this->paginate['conditions']['AND'][] = array('User.' . $searchTerm => substr($piece, 1));
                                }
                            } else {
                                if ($searchTerm == 'email') {
                                    $test['OR'][] = array('LOWER(User.' . $searchTerm . ') LIKE' => '%' . strtolower($piece) . '%');
                                } elseif ($searchTerm == 'org') {
                                    $this->paginate['conditions']['OR'][] = array('User.org_id' => $piece);
                                } elseif ($searchTerm == 'all') {
                                    $this->paginate['conditions']['AND'][] = array(
                                            'OR' => array(
                                                    'UPPER(User.email) LIKE' => '%' . strtoupper($piece) . '%',
                                                    'UPPER(Organisation.name) LIKE' => '%' . strtoupper($piece) . '%',
                                                    'UPPER(Role.name) LIKE' => '%' . strtoupper($piece) . '%',
                                                    'UPPER(User.authkey) LIKE' => '%' . strtoupper($piece) . '%'
                                            ),
                                    );
                                } else {
                                    $test['OR'][] = array('User.' . $searchTerm => $piece);
                                }
                            }
                        }
                        if (!empty($test)) {
                            $this->paginate['conditions']['AND'][] = $test;
                        }
                    }
                }
                $passedArgsArray[$searchTerm] = $v;
            }
        }
        if ($this->_isRest()) {
            $conditions = array();
            if (isset($this->paginate['conditions'])) {
                $conditions = $this->paginate['conditions'];
            }
            if (!$this->_isSiteAdmin()) {
                $conditions['User.org_id'] = $this->Auth->user('org_id');
            }
            $users = $this->User->find('all', array(
                    'conditions' => $conditions,
                    'recursive' => -1,
                    'fields' => array(
                        'id',
            'org_id',
            'server_id',
            'email',
            'autoalert',
            'authkey',
            'invited_by',
            'gpgkey',
            'certif_public',
            'nids_sid',
            'termsaccepted',
            'newsread',
            'role_id',
            'change_pw',
            'contactalert',
            'disabled',
            'expiration',
            'current_login',
            'last_login',
            'force_logout',
            'date_created',
            'date_modified'
                    ),
                    'contain' => array(
                            'Organisation' => array('id', 'name'),
                            'Role' => array('id', 'name', 'perm_auth')
                    )
            ));
            foreach ($users as $key => $value) {
                unset($users['User']['password']);
            }
            return $this->RestResponse->viewData($users, $this->response->type());
        } else {
            $this->set('urlparams', $urlParams);
            $this->set('passedArgsArray', $passedArgsArray);
            $conditions = array();
            if ($this->_isSiteAdmin()) {
                $this->set('users', $this->paginate());
            } else {
                $conditions['User.org_id'] = $this->Auth->user('org_id');
                $this->paginate['conditions']['AND'][] = $conditions;
                $this->set('users', $this->paginate());
            }
            if ($this->request->is('ajax')) {
                $this->autoRender = false;
                $this->layout = false;
                $this->render('ajax/admin_index');
            }
        }
    }

    public function admin_filterUserIndex()
    {
        if (!$this->_isAdmin() && !$this->_isSiteAdmin()) {
            throw new MethodNotAllowedException();
        }
        $passedArgsArray = array();
        $booleanFields = array('autoalert', 'contactalert', 'termsaccepted');
        $textFields = array('role', 'email', 'authkey');
        $showOrg = 0;
        // org admins can't see users of other orgs
        if ($this->_isSiteAdmin()) {
            $textFields[] = 'org';
            $showOrg = 1;
        }
        $this->set('differentFilters', $booleanFields);
        $this->set('simpleFilters', $textFields);
        $rules = array_merge($booleanFields, $textFields);
        $this->set('showorg', $showOrg);

        $filtering = array();
        foreach ($booleanFields as $b) {
            $filtering[$b] = '';
        }
        foreach ($textFields as $t) {
            $filtering[$t] = array('OR' => array(), 'NOT' => array());
        }

        foreach ($this->passedArgs as $k => $v) {
            if (substr($k, 0, 6) === 'search') {
                $searchTerm = substr($k, 6);
                if (in_array($searchTerm, $booleanFields)) {
                    $filtering[$searchTerm] = $v;
                } elseif (in_array($searchTerm, $textFields)) {
                    $pieces = explode('|', $v);
                    foreach ($pieces as $piece) {
                        if ($piece[0] == '!') {
                            $filtering[$searchTerm]['NOT'][] = substr($piece, 1);
                        } else {
                            $filtering[$searchTerm]['OR'][] = $piece;
                        }
                    }
                }
                $passedArgsArray[$searchTerm] = $v;
            }
        }
        $this->set('filtering', json_encode($filtering));

        $roles = $this->User->Role->find('all', array('recursive' => -1));
        $roleNames = array();
        $roleJSON = array();
        foreach ($roles as $k => $v) {
            $roleNames[$v['Role']['id']] = $v['Role']['name'];
            $roleJSON[] = array('id' => $v['Role']['id'], 'value' => $v['Role']['name']);
        }
        $temp = $this->User->Organisation->find('all', array(
            'conditions' => array('local' => 1),
            'recursive' => -1,
            'fields' => array('id', 'name'),
            'order' => array('LOWER(name) ASC')
        ));
        $orgs = array();
        foreach ($temp as $org) {
            $orgs[$org['Organisation']['id']] = $org['Organisation']['name'];
        }
        $this->set('orgs', $orgs);
        $this->set('roles', $roleNames);
        $this->set('roleJSON', json_encode($roleJSON));
        $rules = $this->_arrayToValuesIndexArray($rules);
        $this->set('rules', $rules);
        $this->set('baseurl', Configure::read('MISP.baseurl'));
        $this->layout = 'ajax';
    }

    public function admin_view($id = null)
    {
        $this->User->id = $id;
        if (!$this->User->exists()) {
            throw new NotFoundException(__('Invalid user'));
        }
        $user = $this->User->read(null, $id);
        if (!empty($user['User']['gpgkey'])) {
            $pgpDetails = $this->User->verifySingleGPG($user);
            $user['User']['pgp_status'] = isset($pgpDetails[2]) ? $pgpDetails[2] : 'OK';
            $user['User']['fingerprint'] = !empty($pgpDetails[4]) ? $pgpDetails[4] : 'N/A';
        }
        $user['User']['orgAdmins'] = $this->User->getOrgAdminsForOrg($user['User']['org_id'], $user['User']['id']);
        $this->set('user', $user);
        if (!$this->_isSiteAdmin() && !($this->_isAdmin() && $this->Auth->user('org_id') == $user['User']['org_id'])) {
            throw new MethodNotAllowedException();
        }
        if ($this->_isRest()) {
            $user['User']['password'] = '*****';
            return $this->RestResponse->viewData(array('User' => $user['User']), $this->response->type());
        } else {
            $temp = $this->User->data['User']['invited_by'];
            $this->set('id', $id);
            $this->set('user2', $this->User->read(null, $temp));
        }
    }

    public function admin_add()
    {
        if (!$this->_isAdmin()) {
            throw new Exception('Administrators only.');
        }
        $params = null;
        if (!$this->_isSiteAdmin()) {
            $params = array('conditions' => array('perm_site_admin !=' => 1, 'perm_sync !=' => 1, 'perm_regexp_access !=' => 1));
        }
        $this->loadModel('AdminSetting');
        $default_role_id = $this->AdminSetting->getSetting('default_role');
        $roles = $this->User->Role->find('list', $params);
        $syncRoles = $this->User->Role->find('list', array('conditions' => array('perm_sync' => 1), 'recursive' => -1));
        if ($this->request->is('post')) {
            // In case we don't get the data encapsulated in a User object
            if ($this->_isRest()) {
                if (!isset($this->request->data['User'])) {
                    $this->request->data = array('User' => $this->request->data);
                }
                if (isset($this->request->data['User']['id'])) {
                    unset($this->request->data['User']['id']);
                }
                $required_fields = array('role_id', 'email');
                foreach ($required_fields as $field) {
                    if (empty($this->request->data['User'][$field])) {
                        return $this->RestResponse->saveFailResponse('Users', 'admin_add', false, array($field => 'Mandatory field not set.'), $this->response->type());
                    }
                }
                if (isset($this->request->data['User']['password'])) {
                    $this->request->data['User']['confirm_password'] = $this->request->data['User']['password'];
                }
                $defaults = array(
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
                        'org_id' => $this->Auth->user('org_id')
                );
                foreach ($defaults as $key => $value) {
                    if (!isset($this->request->data['User'][$key])) {
                        $this->request->data['User'][$key] = $value;
                    }
                }
            }
            $this->request->data['User']['date_created'] = time();
            $this->request->data['User']['date_modified'] = time();
            if (!array_key_exists($this->request->data['User']['role_id'], $syncRoles)) {
                $this->request->data['User']['server_id'] = 0;
            }
            $this->User->create();
            // set invited by
            $this->loadModel('Role');
            $this->Role->recursive = -1;
            $chosenRole = $this->Role->findById($this->request->data['User']['role_id']);
            if (empty($chosenRole)) {
                throw new MethodNotAllowedException('Invalid role');
            }
            $this->request->data['User']['invited_by'] = $this->Auth->user('id');
            if (!$this->_isRest()) {
                if ($chosenRole['Role']['perm_sync']) {
                    $this->request->data['User']['change_pw'] = 0;
                    $this->request->data['User']['termsaccepted'] = 1;
                } else {
                    $this->request->data['User']['change_pw'] = 1;
                    $this->request->data['User']['termsaccepted'] = 0;
                }
            }
            if (!isset($this->request->data['User']['disabled'])) {
                $this->request->data['User']['disabled'] = false;
            }
            $this->request->data['User']['newsread'] = 0;
            if (!$this->_isSiteAdmin()) {
                $this->request->data['User']['org_id'] = $this->Auth->user('org_id');
                $this->loadModel('Role');
                $this->Role->recursive = -1;
                $chosenRole = $this->Role->findById($this->request->data['User']['role_id']);
                if (
                    $chosenRole['Role']['perm_site_admin'] == 1 ||
                    $chosenRole['Role']['perm_regexp_access'] == 1 ||
                    $chosenRole['Role']['perm_sync'] == 1 ||
                    $chosenRole['Role']['restricted_to_site_admin'] == 1
                ) {
                    throw new Exception('You are not authorised to assign that role to a user.');
                }
            }
            $organisation = $this->User->Organisation->find('first', array(
                'conditions' => array('Organisation.id' => $this->request->data['User']['org_id']),
                'recursive' => -1
            ));
            $fail = false;
            if (!$this->_isSiteAdmin()) {
                if (!empty($organisation['Organisation']['restricted_to_domain'])) {
                    $fail = true;
                    foreach ($organisation['Organisation']['restricted_to_domain'] as $restriction) {
                        if (
                            strlen($this->request->data['User']['email']) > strlen($restriction) &&
                            substr($this->request->data['User']['email'], (-1 * strlen($restriction))) === $restriction &&
                            in_array($this->request->data['User']['email'][strlen($this->request->data['User']['email']) - strlen($restriction) -1], array('@', '.'))
                        ) {
                            $fail = false;
                        }
                    }
                    if ($abortPost) {
                        $this->Flash->error(__('Invalid e-mail domain. Your user is restricted to creating users for the following domain(s): ') . implode(', ', $organisation['Organisation']['restricted_to_domain']));
                    }
                }
            }
            if (!$fail) {
                if (empty($organisation)) {
                    if ($this->_isRest()) {
                        return $this->RestResponse->saveFailResponse('Users', 'admin_add', false, array('Invalid organisation'), $this->response->type());
                    } else {
                        // reset auth key for a new user
                        $this->set('authkey', $this->newkey);
                        $this->Flash->error(__('The user could not be saved. Invalid organisation.'));
                    }
                } else {
                    $fieldList = array('password', 'email', 'external_auth_required', 'external_auth_key', 'enable_password', 'confirm_password', 'org_id', 'role_id', 'authkey', 'nids_sid', 'server_id', 'gpgkey', 'certif_public', 'autoalert', 'contactalert', 'disabled', 'invited_by', 'change_pw', 'termsaccepted', 'newsread', 'date_created', 'date_modified');
                    if ($this->User->save($this->request->data, true, $fieldList)) {
                        $notification_message = '';
                        if (!empty($this->request->data['User']['notify'])) {
                            $user = $this->User->find('first', array('conditions' => array('User.id' => $this->User->id), 'recursive' => -1));
                            $password = isset($this->request->data['User']['password']) ? $this->request->data['User']['password'] : false;
                            $result = $this->User->initiatePasswordReset($user, true, true, $password);
                            if ($result) {
                                $notification_message .= ' User notified of new credentials.';
                            }
                        }
                        if ($this->_isRest()) {
                            $user = $this->User->find('first', array(
                                    'conditions' => array('User.id' => $this->User->id),
                                    'recursive' => -1
                            ));
                            $user['User']['password'] = '******';
                            return $this->RestResponse->viewData($user, $this->response->type());
                        } else {
                            $this->Flash->success(__('The user has been saved.' . $notification_message));
                            $this->redirect(array('action' => 'index'));
                        }
                    } else {
                        if ($this->_isRest()) {
                            return $this->RestResponse->saveFailResponse('Users', 'admin_add', false, $this->User->validationErrors, $this->response->type());
                        } else {
                            // reset auth key for a new user
                            $this->set('authkey', $this->newkey);
                            $this->Flash->error(__('The user could not be saved. Please, try again.'));
                        }
                    }
                }
            }
        }
        if (!$this->_isRest()) {
            $this->newkey = $this->User->generateAuthKey();
            $this->set('authkey', $this->newkey);
        }
        if ($this->_isRest()) {
            return $this->RestResponse->describe('Users', 'admin_add', false, $this->response->type());
        } else {
            $orgs = $this->User->Organisation->find('list', array(
                    'conditions' => array('local' => 1),
                    'order' => array('lower(name) asc')
            ));
            $this->set('orgs', $orgs);
            // generate auth key for a new user
            $this->loadModel('Server');
            $this->set('complexity', !empty(Configure::read('Security.password_policy_complexity')) ? Configure::read('Security.password_policy_complexity') : $this->Server->serverSettings['Security']['password_policy_complexity']['value']);
            $this->set('length', !empty(Configure::read('Security.password_policy_length')) ? Configure::read('Security.password_policy_length') : $this->Server->serverSettings['Security']['password_policy_length']['value']);
            $conditions = array();
            if (!$this->_isSiteAdmin()) {
                $conditions['Server.org_id LIKE'] = $this->Auth->user('org_id');
            }
            $temp = $this->Server->find('all', array('conditions' => $conditions, 'recursive' => -1, 'fields' => array('id', 'name', 'url')));
            $servers = array(0 => 'Not bound to a server');
            if (!empty($temp)) {
                foreach ($temp as $t) {
                    if (!empty($t['Server']['name'])) {
                        $servers[$t['Server']['id']] = $t['Server']['name'];
                    } else {
                        $servers[$t['Server']['id']] = $t['Server']['url'];
                    }
                }
            }
            $this->set('currentOrg', $this->Auth->user('org_id'));
            $this->set('isSiteAdmin', $this->_isSiteAdmin());
            $this->set('default_role_id', $default_role_id);
            $this->set('servers', $servers);
            $this->set(compact('roles'));
            $this->set(compact('syncRoles'));
        }
    }

    public function admin_edit($id = null)
    {
        $this->set('currentOrg', $this->Auth->user('org_id'));
        $this->User->id = $id;
        if (!$this->User->exists()) {
            throw new NotFoundException(__('Invalid user'));
        }
        $params = array();
        $allowedRole = '';
        $userToEdit = $this->User->find('first', array(
                'conditions' => array('id' => $id),
                'recursive' => -1,
                'fields' => array('id', 'role_id', 'email', 'org_id'),
        ));
        if (!$this->_isSiteAdmin()) {
            // Org admins should be able to select the role that is already assigned to an org user when editing them.
            // What happened previously:
            // Org admin edits another org admin of the same org
            // Org admin is not allowed to set privileged access roles (site_admin/sync/regex)
            // MISP automatically chooses the first available option for the user as the selected setting (usually user)
            // Org admin is downgraded to a user
            // Now we make an exception for the already assigned role, both in the form and the actual edit.
            if ($userToEdit['User']['org_id'] != $this->Auth->user('org_id')) {
                throw new Exception('Invalid user');
            }
            $allowedRole = $userToEdit['User']['role_id'];
            $params = array('conditions' => array(
                    'OR' => array(
                            'AND' => array(
                                'perm_site_admin' => 0, 'perm_sync' => 0, 'perm_regexp_access' => 0, 'restricted_to_site_admin' => 0
                            ),
                            'id' => $allowedRole,
                    )
            ));
        }
        $roles = $this->User->Role->find('list', $params);
        $syncRoles = $this->User->Role->find('list', array('conditions' => array('perm_sync' => 1), 'recursive' => -1));
        $this->set('currentId', $id);
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!isset($this->request->data['User'])) {
                $this->request->data['User'] = $this->request->data;
            }
            $abortPost = false;
            if (!$this->_isRest()) {
                if (Configure::read('Security.require_password_confirmation')) {
                    if (!empty($this->request->data['User']['current_password'])) {
                        $hashed = $this->User->verifyPassword($this->Auth->user('id'), $this->request->data['User']['current_password']);
                        if (!$hashed) {
                            $abortPost = true;
                            $this->Flash->error('Invalid password. Please enter your current password to continue.');
                        }
                        unset($this->request->data['User']['current_password']);
                    } else {
                        $abortPost = true;
                        $this->Flash->info('Please enter your current password to continue.');
                    }
                }
            }
            $fail = false;
            if ($this->_isSiteAdmin() && !$abortPost && !empty($this->request->data['User']['email'])) {
                $organisation = $this->User->Organisation->find('first', array(
                    'conditions' => array('Organisation.id' => $userToEdit['User']['org_id']),
                    'recursive' => -1
                ));
                if (!empty($organisation['Organisation']['restricted_to_domain'])) {
                    $abortPost = true;
                    foreach ($organisation['Organisation']['restricted_to_domain'] as $restriction) {
                        if (
                            strlen($this->request->data['User']['email']) > strlen($restriction) &&
                            substr($this->request->data['User']['email'], (-1 * strlen($restriction))) === $restriction &&
                            in_array($this->request->data['User']['email'][strlen($this->request->data['User']['email']) - strlen($restriction) -1], array('@', '.'))
                        ) {
                            $abortPost = false;
                        }
                    }
                    if ($abortPost) {
                        $this->Flash->error(__('Invalid e-mail domain. Your user is restricted to creating users for the following domain(s): ') . implode(', ', $organisation['Organisation']['restricted_to_domain']));
                    }
                }
            }
            if (!$abortPost) {
                $this->request->data['User']['id'] = $id;
                if (!isset($this->request->data['User']['email'])) {
                    $this->request->data['User']['email'] = $userToEdit['User']['email'];
                }
                if (isset($this->request->data['User']['role_id']) && !array_key_exists($this->request->data['User']['role_id'], $syncRoles)) {
                    $this->request->data['User']['server_id'] = 0;
                }
                $fields = array();
                $blockedFields = array('id', 'invited_by');
                if (!$this->_isSiteAdmin()) {
                    $blockedFields[] = 'org_id';
                }
                foreach (array_keys($this->request->data['User']) as $field) {
                    if (in_array($field, $blockedFields)) {
                        continue;
                    }
                    if ($field != 'password') {
                        array_push($fields, $field);
                    }
                }
                $fieldsOldValues = array();
                foreach ($fields as $field) {
                    if ($field == 'enable_password') {
                        continue;
                    }
                    if ($field != 'confirm_password') {
                        array_push($fieldsOldValues, $this->User->field($field));
                    } else {
                        array_push($fieldsOldValues, $this->User->field('password'));
                    }
                }
                if (
                    isset($this->request->data['User']['enable_password']) && $this->request->data['User']['enable_password'] != '0' &&
                    isset($this->request->data['User']['password']) && "" != $this->request->data['User']['password']
                ) {
                    $fields[] = 'password';
                    if ($this->_isRest() && !isset($this->request->data['User']['confirm_password'])) {
                        $this->request->data['User']['confirm_password'] = $this->request->data['User']['password'];
                        $fields[] = 'confirm_password';
                    }
                }
                if (!$this->_isRest()) {
                    $fields[] = 'role_id';
                }
                if (!$this->_isSiteAdmin()) {
                    $this->loadModel('Role');
                    $this->Role->recursive = -1;
                    $chosenRole = $this->Role->findById($this->request->data['User']['role_id']);
                    if (empty($chosenRole) || (($chosenRole['Role']['id'] != $allowedRole) && ($chosenRole['Role']['perm_site_admin'] == 1 || $chosenRole['Role']['perm_regexp_access'] == 1 || $chosenRole['Role']['perm_sync'] == 1))) {
                        throw new Exception('You are not authorised to assign that role to a user.');
                    }
                }
                if ($this->User->save($this->request->data, true, $fields)) {
                    // newValues to array
                    $fieldsNewValues = array();
                    foreach ($fields as $field) {
                        if ($field != 'confirm_password') {
                            $newValue = $this->data['User'][$field];
                            if (gettype($newValue) == 'array') {
                                $newValueStr = '';
                                $cP = 0;
                                foreach ($newValue as $newValuePart) {
                                    if ($cP < 2) {
                                        $newValueStr .= '-' . $newValuePart;
                                    } else {
                                        $newValueStr = $newValuePart . $newValueStr;
                                    }
                                    $cP++;
                                }
                                array_push($fieldsNewValues, $newValueStr);
                            } else {
                                array_push($fieldsNewValues, $newValue);
                            }
                        } else {
                            array_push($fieldsNewValues, $this->data['User']['password']);
                        }
                    }
                    // compare
                    $fieldsResultStr = '';
                    $c = 0;
                    foreach ($fields as $field) {
                        if (isset($fieldsOldValues[$c]) && $fieldsOldValues[$c] != $fieldsNewValues[$c]) {
                            if ($field != 'confirm_password' && $field != 'enable_password') {
                                $fieldsResultStr = $fieldsResultStr . ', ' . $field . ' (' . $fieldsOldValues[$c] . ') => (' . $fieldsNewValues[$c] . ')';
                            }
                        }
                        $c++;
                    }
                    $fieldsResultStr = substr($fieldsResultStr, 2);
                    $this->__extralog("edit", "user", $fieldsResultStr);
                    if ($this->_isRest()) {
                        $user = $this->User->find('first', array(
                                'conditions' => array('User.id' => $this->User->id),
                                'recursive' => -1
                        ));
                        $user['User']['password'] = '******';
                        return $this->RestResponse->viewData($user, $this->response->type());
                    } else {
                        $this->Flash->success(__('The user has been saved'));
                        $this->_refreshAuth(); // in case we modify ourselves
                        $this->redirect(array('action' => 'index'));
                    }
                } else {
                    if ($this->_isRest()) {
                        return $this->RestResponse->saveFailResponse('Users', 'admin_edit', $id, $this->User->validationErrors, $this->response->type());
                    } else {
                        $this->Flash->error(__('The user could not be saved. Please, try again.'));
                    }
                }
            }
        } else {
            if ($this->_isRest()) {
                return $this->RestResponse->describe('Users', 'admin_edit', $id, $this->response->type());
            }
            $this->User->read(null, $id);
            if (!$this->_isSiteAdmin() && $this->Auth->user('org_id') != $this->User->data['User']['org_id']) {
                $this->redirect(array('controller' => 'users', 'action' => 'index', 'admin' => true));
            }
            $this->User->set('password', '');
            $this->request->data = $this->User->data;
        }
        if ($this->_isSiteAdmin()) {
            $orgs = $this->User->Organisation->find('list', array(
                    'conditions' => array('local' => 1),
                    'order' => array('lower(name) asc')
            ));
        } else {
            $orgs = array();
        }
        $this->loadModel('Server');
        $this->set('complexity', !empty(Configure::read('Security.password_policy_complexity')) ? Configure::read('Security.password_policy_complexity') : $this->Server->serverSettings['Security']['password_policy_complexity']['value']);
        $this->set('length', !empty(Configure::read('Security.password_policy_length')) ? Configure::read('Security.password_policy_length') : $this->Server->serverSettings['Security']['password_policy_length']['value']);
        $conditions = array();
        if (!$this->_isSiteAdmin()) {
            $conditions['Server.org_id LIKE'] = $this->Auth->user('org_id');
        }
        $temp = $this->Server->find('all', array('conditions' => $conditions, 'recursive' => -1, 'fields' => array('id', 'name', 'url')));
        $servers = array(0 => 'Not bound to a server');
        foreach ($temp as $t) {
            if (!empty($t['Server']['name'])) {
                $servers[$t['Server']['id']] = $t['Server']['name'];
            } else {
                $servers[$t['Server']['id']] = $t['Server']['url'];
            }
        }
        $this->set('servers', $servers);
        $this->set('orgs', $orgs);
        $this->set('id', $id);
        $this->set(compact('roles'));
        $this->set(compact('syncRoles'));
    }

    public function admin_delete($id = null)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }
        if (!$this->_isAdmin()) {
            throw new Exception('Administrators only.');
        }
        $this->User->id = $id;
        $conditions = array('User.id' => $id);
        if (!$this->_isSiteAdmin()) {
            $conditions['org_id'] = $this->Auth->user('org_id');
        }
        $user = $this->User->find('first', array(
                'conditions' => $conditions,
                'recursive' => -1
        ));
        if (empty($user)) {
            throw new NotFoundException(__('Invalid user'));
        }
        $fieldsDescrStr = 'User (' . $id . '): ' . $user['User']['email'];
        if ($this->User->delete($id)) {
            $this->__extralog("delete", $fieldsDescrStr, '');
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('User', 'admin_delete', $id, $this->response->type(), 'User deleted.');
            } else {
                $this->Flash->success(__('User deleted'));
                $this->redirect(array('action' => 'index'));
            }
        }
        $this->Flash->error(__('User was not deleted'));
        $this->redirect(array('action' => 'index'));
    }

    public function updateLoginTime()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('This feature is only accessible via POST requests');
        }
        $user = $this->User->find('first', array(
            'recursive' => -1,
            'conditions' => array('User.id' => $this->Auth->user('id'))
        ));
        $this->User->id = $this->Auth->user('id');
        $this->User->saveField('last_login', time());
        $this->User->saveField('current_login', time());
        $user = $this->User->getAuthUser($user['User']['id']);
        $this->Auth->login($user);
        $this->redirect(array('Controller' => 'User', 'action' => 'dashboard'));
    }

    public function login()
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            $this->Bruteforce = ClassRegistry::init('Bruteforce');
            if (!empty($this->request->data['User']['email'])) {
                if ($this->Bruteforce->isBlacklisted($_SERVER['REMOTE_ADDR'], $this->request->data['User']['email'])) {
                    throw new ForbiddenException('You have reached the maximum number of login attempts. Please wait ' . Configure::read('SecureAuth.expire') . ' seconds and try again.');
                }
            }
            // Check the length of the user's authkey
            $userPass = $this->User->find('first', array(
                'conditions' => array('User.email' => $this->request->data['User']['email']),
                'fields' => array('User.password'),
                'recursive' => -1
            ));
            if (!empty($userPass) && strlen($userPass['User']['password']) == 40) {
                $this->AdminSetting = ClassRegistry::init('AdminSetting');
                $db_version = $this->AdminSetting->find('all', array('conditions' => array('setting' => 'db_version')));
                $versionRequirementMet = $this->User->checkVersionRequirements($db_version[0]['AdminSetting']['value'], '2.4.77');
                if ($versionRequirementMet) {
                    $passwordToSave = $this->request->data['User']['password'];
                }
                unset($this->Auth->authenticate['Form']['passwordHasher']);
                $this->Auth->constructAuthenticate();
            }
        }
        if ($this->Auth->login()) {
            $this->__extralog("login");
            $this->User->Behaviors->disable('SysLogLogable.SysLogLogable');
            $this->User->id = $this->Auth->user('id');
            $user = $this->User->find('first', array(
                'conditions' => array(
                    'User.id' => $this->Auth->user('id')
                ),
                'recursive' => -1
            ));
            unset($user['User']['password']);
            $user['User']['action'] = 'login';
            $user['User']['last_login'] = $this->Auth->user('current_login');
            $user['User']['current_login'] = time();
            $this->User->save($user['User'], true, array('id', 'last_login', 'current_login'));
            if (empty($this->Auth->authenticate['Form']['passwordHasher']) && !empty($passwordToSave)) {
                $this->User->saveField('password', $passwordToSave);
            }
            $this->User->Behaviors->enable('SysLogLogable.SysLogLogable');
            // no state changes are ever done via GET requests, so it is safe to return to the original page:
            $this->redirect($this->Auth->redirectUrl());
        // $this->redirect(array('controller' => 'events', 'action' => 'index'));
        } else {
            $dataSourceConfig = ConnectionManager::getDataSource('default')->config;
            $dataSource = $dataSourceConfig['datasource'];
            // don't display authError before first login attempt
            if (str_replace("//", "/", $this->webroot . $this->Session->read('Auth.redirect')) == $this->webroot && $this->Session->read('Message.auth.message') == $this->Auth->authError) {
                $this->Session->delete('Message.auth');
            }
            // don't display "invalid user" before first login attempt
            if ($this->request->is('post')) {
                $this->Flash->error(__('Invalid username or password, try again'));
                if (isset($this->request->data['User']['email'])) {
                    $this->Bruteforce->insert($_SERVER['REMOTE_ADDR'], $this->request->data['User']['email']);
                }
            }
            // populate the DB with the first role (site admin) if it's empty
            $this->loadModel('Role');
            if ($this->Role->find('count') == 0) {
                $siteAdmin = array('Role' => array(
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
                ));
                $this->Role->save($siteAdmin);
                // PostgreSQL: update value of auto incremented serial primary key after setting the column by force
                if ($dataSource == 'Database/Postgres') {
                    $sql = "SELECT setval('roles_id_seq', (SELECT MAX(id) FROM roles));";
                    $this->Role->query($sql);
                }
            }
            if ($this->User->Organisation->find('count', array('conditions' => array('Organisation.local' => true))) == 0) {
                $this->User->runUpdates();
                $date = date('Y-m-d H:i:s');
                $org = array('Organisation' => array(
                        'id' => 1,
                        'name' => !empty(Configure::read('MISP.org')) ? Configure::read('MISP.org') : 'ADMIN',
                        'description' => 'Automatically generated admin organisation',
                        'type' => 'ADMIN',
                        'uuid' => CakeText::uuid(),
                        'local' => 1,
                        'date_created' => $date,
                        'sector' => '',
                        'nationality' => ''
                ));
                $this->User->Organisation->save($org);
                // PostgreSQL: update value of auto incremented serial primary key after setting the column by force
                if ($dataSource == 'Database/Postgres') {
                    $sql = "SELECT setval('organisations_id_seq', (SELECT MAX(id) FROM organisations));";
                    $this->User->Organisation->query($sql);
                }
                $org_id = $this->User->Organisation->id;
            } else {
                $hostOrg = $this->User->Organisation->find('first', array('conditions' => array('Organisation.name' => Configure::read('MISP.org'), 'Organisation.local' => true), 'recursive' => -1));
                if (!empty($hostOrg)) {
                    $org_id = $hostOrg['Organisation']['id'];
                } else {
                    $firstOrg = $this->User->Organisation->find('first', array('conditions' => array('Organisation.local' => true), 'order' => 'Organisation.id ASC'));
                    $org_id = $firstOrg['Organisation']['id'];
                }
            }

            // populate the DB with the first user if it's empty
            if ($this->User->find('count') == 0) {
                $this->User->runUpdates();
                $this->User->createInitialUser($org_id);
            }
        }
    }

    public function routeafterlogin()
    {
        // Events list
        $this->redirect(array('controller' => 'events', 'action' => 'index'));
    }

    public function logout()
    {
        if ($this->Session->check('Auth.User')) {
            $this->__extralog("logout");
        }
        $this->Flash->info(__('Good-Bye'));
        $user = $this->User->find('first', array(
            'conditions' => array(
                'User.id' => $this->Auth->user('id')
            ),
            'recursive' => -1
        ));
        unset($user['User']['password']);
        $user['User']['action'] = 'logout';
        $this->User->save($user['User'], true, array('id'));
        $this->redirect($this->Auth->logout());
    }

    public function resetauthkey($id = null)
    {
        if (!$this->_isAdmin() && Configure::read('MISP.disableUserSelfManagement')) {
            throw new MethodNotAllowedException('User self-management has been disabled on this instance.');
        }
        if ($id == 'me') {
            $id = $this->Auth->user('id');
        }
        if (!$this->userRole['perm_auth']) {
            throw new MethodNotAllowedException('Invalid action.');
        }
        $this->User->id = $id;
        if (!$id || !$this->User->exists($id)) {
            throw new MethodNotAllowedException('Invalid user.');
        }
        $user = $this->User->read();
        $oldKey = $this->User->data['User']['authkey'];
        if (!$this->_isSiteAdmin() && !($this->_isAdmin() && $this->Auth->user('org_id') == $this->User->data['User']['org_id']) && ($this->Auth->user('id') != $id)) {
            throw new MethodNotAllowedException('Invalid user.');
        }
        $newkey = $this->User->generateAuthKey();
        $this->User->saveField('authkey', $newkey);
        $this->__extralog(
                'reset_auth_key',
                'Authentication key for user ' . $user['User']['id'] . ' (' . $user['User']['email'] . ')',
                $fieldsResult = 'authkey(' . $oldKey . ') => (' . $newkey . ')'
        );
        if (!$this->_isRest()) {
            $this->Flash->success(__('New authkey generated.', true));
            $this->_refreshAuth();
            $this->redirect($this->referer());
        } else {
            return $this->RestResponse->saveSuccessResponse('User', 'resetauthkey', $id, $this->response->type(), 'User\'s authkey has been reset.');
        }
    }

    public function histogram($selected = null)
    {
        //if (!$this->request->is('ajax') && !$this->_isRest()) throw new MethodNotAllowedException('This function can only be accessed via AJAX or the API.');
        if ($selected == '[]') {
            $selected = null;
        }
        $selectedTypes = array();
        if ($selected) {
            $selectedTypes = json_decode($selected);
        }
        if (!$this->_isSiteAdmin() && !empty(Configure::read('Security.hide_organisation_index_from_users'))) {
            $org_ids = array($this->Auth->user('org_id'));
        } else {
            $org_ids = $this->User->Event->find('list', array(
                'fields' => array('Event.orgc_id', 'Event.orgc_id'),
                'group' => array('Event.orgc_id')
            ));
        }
        $orgs_temp = $this->User->Organisation->find('list', array(
            'fields' => array('Organisation.id', 'Organisation.name'),
            'conditions' => array('Organisation.id' => $org_ids)
        ));
        $orgs = array(0 => 'All organisations');
        foreach ($org_ids as $v) {
            $orgs[$v] = $orgs_temp[$v];
        }
        $data = array();
        $max = 1;
        foreach ($orgs as $org_id => $org_name) {
            $conditions = array('Attribute.deleted' => 0);
            if ($selected) {
                $conditions['Attribute.type'] = $selectedTypes;
            }
            if ($org_id != 0) {
                $conditions['Event.orgc_id'] = $org_id;
            }
            $params = array(
                'recursive' => -1,
                'fields' => array('Attribute.type', 'COUNT(*) as num_types'),
                'group' => array('Attribute.type'),
                'joins' => array(
                    array(
                        'table' => 'events',
                        'alias' => 'Event',
                        'type' => 'LEFT',
                        'conditions' => array(
                            'Attribute.event_id = Event.id'
                        )
                    )
                ),
                //'order' => array('num_types DESC'),
                'conditions' => $conditions,
                'order' => false
            );
            if ($org_id == 0) {
                unset($params['joins']);
            }
            $temp = $this->User->Event->Attribute->find('all', $params);
            $temp = Hash::combine($temp, '{n}.Attribute.type', '{n}.0.num_types');
            $total = 0;
            foreach ($temp as $k => $v) {
                if (intval($v) > $max) {
                    $max = intval($v);
                }
                $total += intval($v);
            }
            $data[$org_id]['data'] = $temp;
            $data[$org_id]['org_name'] = $org_name;
            $data[$org_id]['total'] = $total;
        }
        uasort($data, function ($a, $b) {
            return $b['total'] - $a['total'];
        });
        $this->set('data', $data);
        $this->set('max', $max);
        $this->set('selectedTypes', $selectedTypes);

        // Nice graphical histogram
        $sigTypes = array_keys($this->User->Event->Attribute->typeDefinitions);
        App::uses('ColourPaletteTool', 'Tools');
        $paletteTool = new ColourPaletteTool();
        $colours = $paletteTool->createColourPalette(count($sigTypes));
        $typeDb = array();
        foreach ($sigTypes as $k => $type) {
            $typeDb[$type] = $colours[$k];
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($data, $this->response->type());
        } else {
            $this->set('typeDb', $typeDb);
            $this->set('sigTypes', $sigTypes);
            $this->layout = 'ajax';
        }
    }

    public function terms()
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            $this->User->id = $this->Auth->user('id');
            $this->User->saveField('termsaccepted', true);
            $this->_refreshAuth(); // refresh auth info
            $this->Flash->success(__('You accepted the Terms and Conditions.'));
            $this->redirect(array('action' => 'routeafterlogin'));
        }
        $this->set('termsaccepted', $this->Auth->user('termsaccepted'));
    }

    public function downloadTerms()
    {
        if (!Configure::read('MISP.terms_file')) {
            $termsFile = APP ."View/Users/terms";
        } else {
            $termsFile = APP . 'files' . DS . 'terms' . DS .  Configure::read('MISP.terms_file');
        }
        $this->response->file($termsFile, array('download' => true, 'name' => Configure::read('MISP.terms_file')));
        return $this->response;
    }

    private function __extralog($action = null, $description = null, $fieldsResult = null)
    {
        // new data
        $model = 'User';
        $modelId = $this->Auth->user('id');
        if ($action == 'login') {
            $description = "User (" . $this->Auth->user('id') . "): " . $this->data['User']['email'];
        } elseif ($action == 'logout') {
            $description = "User (" . $this->Auth->user('id') . "): " . $this->Auth->user('email');
        } elseif ($action == 'edit') {
            $description = "User (" . $this->User->id . "): " . $this->data['User']['email'];
        } elseif ($action == 'change_pw') {
            $description = "User (" . $this->User->id . "): " . $this->data['User']['email'];
            $fieldsResult = "Password changed.";
        }

        // query
        $this->Log = ClassRegistry::init('Log');
        $this->Log->create();
        $this->Log->save(array(
            'org' => $this->Auth->user('Organisation')['name'],
            'model' => $model,
            'model_id' => $modelId,
            'email' => $this->Auth->user('email'),
            'action' => $action,
            'title' => $description,
            'change' => isset($fieldsResult) ? $fieldsResult : ''));

        // write to syslogd as well
        App::import('Lib', 'SysLog.SysLog');
        $syslog = new SysLog();
        if (isset($fieldsResult) && $fieldsResult) {
            $syslog->write('notice', $description . ' -- ' . $action . ' -- ' . $fieldsResult);
        } else {
            $syslog->write('notice', $description . ' -- ' . $action);
        }
    }

    // Used for fields_before and fields for audit
    public function arrayCopy(array $array)
    {
        $result = array();
        foreach ($array as $key => $val) {
            if (is_array($val)) {
                $result[$key] = arrayCopy($val);
            } elseif (is_object($val)) {
                $result[$key] = clone $val;
            } else {
                $result[$key] = $val;
            }
        }
        return $result;
    }

    public function checkAndCorrectPgps()
    {
        if (!self::_isAdmin()) {
            throw new NotFoundException();
        }
        $this->set('fails', $this->User->checkAndCorrectPgps());
    }

    public function admin_quickEmail($user_id)
    {
        if (!$this->_isAdmin()) {
            throw new MethodNotAllowedException();
        }
        $conditions = array('User.id' => $user_id);
        if (!$this->_isSiteAdmin()) {
            $conditions['User.org_id'] = $this->Auth->user('org_id');
        }
        $user = $this->User->find('first', array(
            'conditions' => $conditions,
            'recursive' => -1
        ));
        $error = false;
        if (empty($user)) {
            $error = 'Invalid user.';
        }
        if (!$error && $user['User']['disabled']) {
            $error = 'Cannot send an e-mail to this user as the account is disabled.';
        }
        $encryption = false;
        if (!$error && !empty($user['User']['gpgkey'])) {
            $encryption = 'PGP';
        } elseif (!$error && !empty($user['User']['certif_public'])) {
            $encryption = 'SMIME';
        }
        $this->set('encryption', $encryption);
        if (!$error && !$encryption && (Configure::read('GnuPG.onlyencrypted') || Configure::read('GnuPG.bodyonlyencrypted'))) {
            $error = 'No encryption key found for the user and the instance posture blocks non encrypted e-mails from being sent.';
        }
        if ($error) {
            if ($this->_isRest()) {
                return $this->RestResponse->saveFailResponse('Users', 'admin_quickEmail', false, $error, $this->response->type());
            } else {
                $this->Flash->error('Cannot send an e-mail to this user as the account is disabled.');
                $this->redirect('/admin/users/view/' . $user_id);
            }
        }
        if ($this->request->is('post')) {
            if (!isset($this->request->data['User'])) {
                $this->request->data['User'] = $this->request->data;
            }
            if (empty($this->request->data['User']['subject']) || empty($this->request->data['User']['body'])) {
                $message = 'Both the subject and the body have to be set.';
                if ($this->_isRest()) {
                    throw new MethodNotAllowedException($message);
                } else {
                    $this->Flash->error($message);
                    $this->redirect('/admin/users/quickEmail/' . $user_id);
                }
            }
            $result = $this->User->sendEmail($user, $this->request->data['User']['body'], false, $this->request->data['User']['subject']);
            if ($this->_isRest()) {
                if ($result) {
                    return $this->RestResponse->saveSuccessResponse('User', 'admin_quickEmail', $id, $this->response->type(), 'User deleted.');
                } else {
                    return $this->RestResponse->saveFailResponse('Users', 'admin_quickEmail', false, $this->User->validationErrors, $this->response->type());
                }
            } else {
                if ($result) {
                    $this->Flash->success('Email sent.');
                } else {
                    $this->Flash->error('Could not send e-mail.');
                }
                $this->redirect('/admin/users/view/' . $user_id);
            }
        } elseif ($this->_isRest()) {
            return $this->RestResponse->describe('Users', 'admin_quickEmail', false, $this->response->type());
        }
        $this->set('encryption', $encryption);
        $this->set('user', $user);
    }

    public function admin_email()
    {
        if (!$this->_isAdmin()) {
            throw new MethodNotAllowedException();
        }
        // User has filled in his contact form, send out the email.
        if ($this->request->is('post') || $this->request->is('put')) {
            $conditions = array();
            if (!$this->_isSiteAdmin()) {
                $conditions = array('org_id' => $this->Auth->user('org_id'));
            }
            if ($this->request->data['User']['recipient'] != 1) {
                $conditions['id'] = $this->request->data['User']['recipientEmailList'];
            }
            $conditions['AND'][] = array('User.disabled' => 0);
            $users = $this->User->find('all', array('recursive' => -1, 'order' => array('email ASC'), 'conditions' => $conditions));
            $this->request->data['User']['message'] = $this->User->adminMessageResolve($this->request->data['User']['message']);
            $failures = '';
            foreach ($users as $user) {
                $password = $this->User->generateRandomPassword();
                $body = str_replace('$password', $password, $this->request->data['User']['message']);
                $body = str_replace('$username', $user['User']['email'], $body);
                $result = $this->User->sendEmail($user, $body, false, $this->request->data['User']['subject']);
                // if sending successful and action was a password change, update the user's password.
                if ($result && $this->request->data['User']['action'] != '0') {
                    $this->User->id = $user['User']['id'];
                    $this->User->saveField('password', $password);
                    $this->User->saveField('change_pw', '1');
                }
                if (!$result) {
                    if ($failures != '') {
                        $failures .= ', ';
                    }
                    $failures .= $user['User']['email'];
                }
            }
            if ($failures != '') {
                $this->Flash->success(__('E-mails sent, but failed to deliver the messages to the following recipients: ' . $failures));
            } else {
                $this->Flash->success(__('E-mails sent.'));
            }
        }
        $conditions = array();
        if (!$this->_isSiteAdmin()) {
            $conditions = array('org_id' => $this->Auth->user('org_id'));
        }
        $conditions['User.disabled'] = 0;
        $temp = $this->User->find('all', array('recursive' => -1, 'fields' => array('id', 'email'), 'order' => array('email ASC'), 'conditions' => $conditions));
        $emails = array();
        // save all the emails of the users and set it for the dropdown list in the form
        foreach ($temp as $user) {
            $emails[$user['User']['id']] = $user['User']['email'];
        }
        $this->set('users', $temp);
        $this->set('recipientEmail', $emails);
        $this->set('org', Configure::read('MISP.org'));
        $textsToFetch = array('newUserText', 'passwordResetText');
        $this->loadModel('Server');
        foreach ($textsToFetch as $text) {
            ${$text} = Configure::read('MISP.' . $text);
            if (!${$text}) {
                ${$text} = $this->Server->serverSettings['MISP'][$text]['value'];
            }
            $this->set($text, ${$text});
        }
    }

    public function initiatePasswordReset($id, $firstTime = false)
    {
        if (!$this->_isAdmin()) {
            throw new MethodNotAllowedException('You are not authorised to do that.');
        }
        $user = $this->User->find('first', array(
            'conditions' => array('id' => $id),
            'recursive' => -1
        ));
        if (!$this->_isSiteAdmin() && $this->Auth->user('org_id') != $user['User']['org_id']) {
            throw new MethodNotAllowedException('You are not authorised to do that.');
        }
        if ($this->request->is('post')) {
            if (isset($this->request->data['User']['firstTime'])) {
                $firstTime = $this->request->data['User']['firstTime'];
            }
            return new CakeResponse($this->User->initiatePasswordReset($user, $firstTime));
        } else {
            $error = false;
            $encryption = false;
            if (!empty($user['User']['gpgkey'])) {
                $encryption = 'PGP';
            } elseif (!$error && !empty($user['User']['certif_public'])) {
                $encryption = 'SMIME';
            }
            $this->set('encryption', $encryption);
            if (!$encryption && (Configure::read('GnuPG.onlyencrypted') || Configure::read('GnuPG.bodyonlyencrypted'))) {
                $error = 'No encryption key found for the user and the instance posture blocks non encrypted e-mails from being sent.';
            }
            $this->set('error', $error);
            $this->layout = 'ajax';
            $this->set('user', $user);
            $this->set('firstTime', $firstTime);
            $this->render('ajax/passwordResetConfirmationForm');
        }
    }

    // shows some statistics about the instance
    public function statistics($page = 'data')
    {
        $this->set('page', $page);
        $pages = array('data' => 'Usage data', 'orgs' => 'Organisations', 'users' => 'User and Organisation statistics', 'tags' => 'Tags', 'attributehistogram' => 'Attribute histogram', 'sightings' => 'Sightings toplists', 'attackMatrix' => 'ATT&CK Matrix');
        if (!$this->_isSiteAdmin() && !empty(Configure::read('Security.hide_organisation_index_from_users'))) {
            unset($pages['orgs']);
        }
        $this->set('pages', $pages);
        $result = array();
        if ($page == 'data') {
            $result = $this->__statisticsData($this->params['named']);
        } elseif ($page == 'orgs') {
            if (!$this->_isSiteAdmin() && !empty(Configure::read('Security.hide_organisation_index_from_users'))) {
                throw new MethodNotAllowedException('This feature is currently disabled.');
            }
            $result = $this->__statisticsOrgs($this->params['named']);
        } elseif ($page == 'users') {
            $result = $this->__statisticsUsers($this->params['named']);
        } elseif ($page == 'tags') {
            $result = $this->__statisticsTags($this->params['named']);
        } elseif ($page == 'attributehistogram') {
            if ($this->_isRest()) {
                return $this->histogram($selected = null);
            } else {
                $this->render('statistics_histogram');
            }
        } elseif ($page == 'sightings') {
            $result = $this->__statisticsSightings($this->params['named']);
        } elseif ($page == 'attackMatrix') {
            $result = $this->__statisticsAttackMatrix($this->params['named']);
        }
        if ($this->_isRest()) {
            return $result;
        }
    }

    private function __statisticsData($params = array())
    {
        // set all of the data up for the heatmaps
        $params = array(
            'fields' => array('name'),
            'recursive' => -1
        );
        if (!$this->_isSiteAdmin() && !empty(Configure::read('Security.hide_organisation_index_from_users'))) {
            $params['conditions'] = array('Organisation.id' => $this->Auth->user('org_id'));
        }
        $orgs = $this->User->Organisation->find('all', $params);
        $this->loadModel('Log');
        $year = date('Y');
        $month = date('n');
        $month = $month - 5;
        if ($month < 1) {
            $year--;
            $month = 12 + $month;
        }
        // Some additional statistics
        $this_month = strtotime('first day of this month');
        $stats['event_count'] = $this->User->Event->find('count', array('recursive' => -1));
        $stats['event_count_month'] = $this->User->Event->find('count', array('conditions' => array('Event.timestamp >' => $this_month), 'recursive' => -1));

        $stats['attribute_count'] = $this->User->Event->Attribute->find('count', array('conditions' => array('Attribute.deleted' => 0), 'recursive' => -1));
        $stats['attribute_count_month'] = $this->User->Event->Attribute->find('count', array('conditions' => array('Attribute.timestamp >' => $this_month, 'Attribute.deleted' => 0), 'recursive' => -1));
        $stats['attributes_per_event'] = round($stats['attribute_count'] / $stats['event_count']);

        $this->loadModel('Correlation');
        $this->Correlation->recursive = -1;
        $stats['correlation_count'] = $this->Correlation->find('count', array('recursive' => -1));
        $stats['correlation_count'] = $stats['correlation_count'] / 2;

        $stats['proposal_count'] = $this->User->Event->ShadowAttribute->find('count', array('recursive' => -1));

        $stats['user_count'] = $this->User->find('count', array('recursive' => -1));
        $stats['org_count'] = count($orgs);

        $this->loadModel('Thread');
        $stats['thread_count'] = $this->Thread->find('count', array('conditions' => array('Thread.post_count >' => 0), 'recursive' => -1));
        $stats['thread_count_month'] = $this->Thread->find('count', array('conditions' => array('Thread.date_created >' => date("Y-m-d H:i:s", $this_month), 'Thread.post_count >' => 0), 'recursive' => -1));

        $stats['post_count'] = $this->Thread->Post->find('count', array('recursive' => -1));
        $stats['post_count_month'] = $this->Thread->Post->find('count', array('conditions' => array('Post.date_created >' => date("Y-m-d H:i:s", $this_month)), 'recursive' => -1));


        if ($this->_isRest()) {
            $data = array(
                'stats' => $stats
            );
            return $this->RestResponse->viewData($data, $this->response->type());
        } else {
            $this->set('stats', $stats);
            $this->set('orgs', $orgs);
            $this->set('start', strtotime(date('Y-m-d H:i:s') . ' -5 months'));
            $this->set('end', strtotime(date('Y-m-d H:i:s')));
            $this->set('startDateCal', $year . ', ' . $month . ', 01');
            $range = '[5, 10, 50, 100]';
            $this->set('range', $range);
            $this->render('statistics_data');
        }
    }

    private function __statisticsSightings($params = array())
    {
        $this->loadModel('Sighting');
        $conditions = array('Sighting.org_id' => $this->Auth->user('org_id'));
        if (isset($params['timestamp'])) {
            $conditions['Sighting.date_sighting >'] = $params['timestamp'];
        }
        $sightings = $this->Sighting->find('all', array(
            'conditions' => $conditions,
            'fields' => array('Sighting.date_sighting', 'Sighting.type', 'Sighting.source', 'Sighting.event_id')
        ));
        $data = array();
        $toplist = array();
        $eventids = array();
        foreach ($sightings as $k => $v) {
            if ($v['Sighting']['source'] == '') {
                $v['Sighting']['source'] = 'Undefined';
            }
            $v['Sighting']['type'] = array('sighting', 'false-positive', 'expiration')[$v['Sighting']['type']];
            if (isset($data[$v['Sighting']['source']][$v['Sighting']['type']])) {
                $data[$v['Sighting']['source']][$v['Sighting']['type']]++;
            } else {
                $data[$v['Sighting']['source']][$v['Sighting']['type']] = 1;
            }
            if (!isset($toplist[$v['Sighting']['source']])) {
                $toplist[$v['Sighting']['source']] = 1;
            } else {
                $toplist[$v['Sighting']['source']]++;
            }
            if (!isset($eventids[$v['Sighting']['source']][$v['Sighting']['type']])) {
                $eventids[$v['Sighting']['source']][$v['Sighting']['type']] = array();
            }
            if (!in_array($v['Sighting']['event_id'], $eventids[$v['Sighting']['source']][$v['Sighting']['type']])) {
                $eventids[$v['Sighting']['source']][$v['Sighting']['type']][] = $v['Sighting']['event_id'];
            }
        }
        arsort($toplist);
        if ($this->_isRest()) {
            $data = array(
                'toplist' => $toplist,
                'eventids' => $eventids
            );
            return $this->RestResponse->viewData($data, $this->response->type());
        } else {
            $this->set('eventids', $eventids);
            $this->set('toplist', $toplist);
            $this->set('data', $data);
            $this->render('statistics_sightings');
        }
    }

    private function __statisticsOrgs($params = array())
    {
        $this->loadModel('Organisation');
        $conditions = array();
        if (!isset($params['scope']) || $params['scope'] == 'local') {
            $params['scope'] = 'local';
            $conditions['Organisation.local'] = 1;
        } elseif ($params['scope'] == 'external') {
            $conditions['Organisation.local'] = 0;
        }
        $orgs = array();
        $orgs = $this->Organisation->find('all', array(
                'recursive' => -1,
                'conditions' => $conditions,
                'fields' => array('id', 'name', 'description', 'local', 'contacts', 'type', 'sector', 'nationality'),
        ));
        $orgs = Set::combine($orgs, '{n}.Organisation.id', '{n}.Organisation');
        $users = $this->User->find('all', array(
            'group' => 'User.org_id',
            'conditions' => array('User.org_id' => array_keys($orgs)),
            'recursive' => -1,
            'fields' => array('org_id', 'count(*)')
        ));
        foreach ($users as $user) {
            $orgs[$user['User']['org_id']]['userCount'] = $user[0]['count(*)'];
        }
        unset($users);
        $events = $this->User->Event->find('all', array(
            'group' => 'Event.orgc_id',
            'conditions' => array('Event.orgc_id' => array_keys($orgs)),
            'recursive' => -1,
            'fields' => array('Event.orgc_id', 'count(*)')
        ));
        foreach ($events as $event) {
            $orgs[$event['Event']['orgc_id']]['eventCount'] = $event[0]['count(*)'];
        }
        unset($events);
        $orgs = Set::combine($orgs, '{n}.name', '{n}');
        // f*** php
        uksort($orgs, 'strcasecmp');
        foreach ($orgs as $k => $value) {
            if (file_exists(APP . 'webroot' . DS . 'img' . DS . 'orgs' . DS . $k . '.png')) {
                $orgs[$k]['logo'] = true;
            }
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($orgs, $this->response->type());
        } else {
            $this->set('scope', $params['scope']);
            $this->set('orgs', $orgs);
            $this->render('statistics_orgs');
        }
    }

    private function __statisticsUsers($params = array())
    {
        $this->loadModel('Organisation');
        $this->loadModel('User');
        $this_month = strtotime(date('Y/m') . '/01');
        $this_year = strtotime(date('Y') . '/01/01');
        $ranges = array(
            'total' => null,
            'month' => $this_month,
            'year' => $this_year
        );
        $scopes = array(
            'user' => array(
                'conditions' => array(),
                'model' => 'User',
                'date_created' => 'timestamp'
            ),
            'org_local' => array(
                'conditions' => array('Organisation.local' => 1),
                'model' => 'Organisation',
                'date_created' => 'datetime'
            ),
            'org_external' => array(
                'conditions' => array('Organisation.local' => 0),
                'model' => 'Organisation',
                'date_created' => 'datetime'
            )
        );
        $statistics = array();
        foreach ($scopes as $scope => $scope_data) {
            foreach ($ranges as $range => $condition) {
                $params = array(
                    'recursive' => -1
                );
                $filter = array();
                if (!empty($condition)) {
                    if ($scope_data['date_created'] === 'datetime') {
                        $condition = date('Y-m-d H:i:s', $condition);
                    }
                    $filter = array($scope_data['model'] . '.date_created >=' => $condition);
                }
                $params['conditions'] = array_merge($scopes[$scope]['conditions'], $filter);
                $statistics[$scope]['data'][$range] = $this->{$scope_data['model']}->find('count', $params);
            }
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($statistics, $this->response->type());
        } else {
            $this->set('statistics', $statistics);
            $this->render('statistics_users');
        }
    }

    public function tagStatisticsGraph()
    {
        $this->loadModel('EventTag');
        $tags = $this->EventTag->getSortedTagList();
        $this->loadModel('Taxonomy');
        $taxonomies = $this->Taxonomy->find('list', array(
                'conditions' => array('enabled' => true),
                'fields' => array('Taxonomy.namespace')
        ));
        $flatData = array();
        $tagIds = $this->EventTag->Tag->find('list', array('fields' => array('Tag.name', 'Tag.id')));
        $this->set('tagIds', $tagIds);
        foreach ($tags as $key => $value) {
            $name = explode(':', $value['name']);
            $tags[$key]['taxonomy'] = 'custom';
            if (count($name) > 1) {
                if (in_array($name[0], $taxonomies)) {
                    $tags[$key]['taxonomy'] = $name[0];
                }
            }
            $flatData[$tags[$key]['taxonomy']][$value['name']] = array('name' => $value['name'], 'size' => $value['eventCount']);
        }
        $treemap = array(
                'name' => 'tags',
                'children' => array()
        );

        foreach ($flatData as $key => $value) {
            $newElement = array(
                'name' => $key,
                'children' => array()
            );
            foreach ($value as $tag) {
                $newElement['children'][] = array('name' => $tag['name'], 'size' => $tag['size']);
            }
            $treemap['children'][] = $newElement;
        }
        $taxonomyColourCodes = array();
        $taxonomies = array_merge(array('custom'), $taxonomies);
        if ($this->_isRest()) {
            $data = array(
                'flatData' => $flatData,
                'treemap' => $treemap
            );
            return $this->RestResponse->viewData($data, $this->response->type());
        } else {
            $this->set('taxonomyColourCodes', $taxonomyColourCodes);
            $this->set('taxonomies', $taxonomies);
            $this->set('flatData', $flatData);
            $this->set('treemap', $treemap);
            $this->set('tags', $tags);
            $this->layout = 'treemap';
            $this->render('ajax/tag_statistics_graph');
        }
    }

    private function __statisticsTags($params = array())
    {
        $trending_tags = array();
        $all_tags = array();
        if ($this->_isRest()) {
            return $this->tagStatisticsGraph();
        } else {
            $this->render('statistics_tags');
        }
    }

    private function __statisticsAttackMatrix($params = array())
    {
        $this->loadModel('Event');
        $this->loadModel('Galaxy');
        $attackTacticData = $this->Galaxy->getMitreAttackMatrix();
        $attackTactic = $attackTacticData['attackTactic'];
        $attackTags = $attackTacticData['attackTags'];
        $killChainOrders = $attackTacticData['killChain'];
        $instanceUUID = $attackTacticData['instance-uuid'];

        $scoresDataAttr = $this->Event->Attribute->AttributeTag->getTagScores(0, $attackTags);
        $scoresDataEvent = $this->Event->EventTag->getTagScores(0, $attackTags);
        $scoresData = array();
        foreach (array_keys($scoresDataAttr['scores'] + $scoresDataEvent['scores']) as $key) {
            $scoresData[$key] = (isset($scoresDataAttr['scores'][$key]) ? $scoresDataAttr['scores'][$key] : 0) + (isset($scoresDataEvent['scores'][$key]) ? $scoresDataEvent['scores'][$key] : 0);
        }
        $maxScore = max($scoresDataAttr['maxScore'], $scoresDataEvent['maxScore']);
        $scores = $scoresData;

        if ($this->_isRest()) {
            $json = array('matrix' => $attackTactic, 'scores' => $scores, 'instance-uuid' => $instanceUUID);
            return $this->RestResponse->viewData($json, $this->response->type());
        } else {
            App::uses('ColourGradientTool', 'Tools');
            $gradientTool = new ColourGradientTool();
            $colours = $gradientTool->createGradientFromValues($scores);

            $this->set('target_type', 'attribute');
            $this->set('killChainOrders', $killChainOrders);
            $this->set('attackTactic', $attackTactic);
            $this->set('scores', $scores);
            $this->set('maxScore', $maxScore);
            $this->set('colours', $colours);
            $this->set('pickingMode', false);

            $this->render('statistics_attackmatrix');
        }
    }

    public function verifyGPG($full = false)
    {
        if (!self::_isSiteAdmin()) {
            throw new NotFoundException();
        }
        $user_results = $this->User->verifyGPG($full);
        $this->set('users', $user_results);
    }

    public function verifyCertificate()
    {
        $user_results = $this->User->verifyCertificate();
        $this->set('users', $user_results);
    }

    // Refreshes the Auth session with new/updated data
    protected function _refreshAuth()
    {
        $oldUser = $this->Auth->user();
        $newUser = $this->User->find('first', array('conditions' => array('User.id' => $oldUser['id']), 'recursive' => -1,'contain' => array('Organisation', 'Role')));
        // Rearrange it a bit to match the Auth object created during the login
        $newUser['User']['Role'] = $newUser['Role'];
        $newUser['User']['Organisation'] = $newUser['Organisation'];
        unset($newUser['Organisation'], $newUser['Role']);
        $this->Auth->login($newUser['User']);
    }

    public function fetchPGPKey($email = false)
    {
        if ($email == false) {
            throw new NotFoundException('No email provided.');
        }
        $keys = $this->User->fetchPGPKey($email);
        if (is_numeric($keys)) {
            throw new NotFoundException('Could not retrieved any keys from the key server.');
        }
        $this->set('keys', $keys);
        $this->autorender = false;
        $this->layout = false;
        $this->render('ajax/fetchpgpkey');
    }

    public function dashboard()
    {
        $events = array();
        // the last login in the session is not updated after the login - only in the db, so let's fetch it.
        $lastLogin = $this->Auth->user('last_login');
        $this->loadModel('Event');
        $events['changed'] = count($this->Event->fetchEventIds($this->Auth->user(), false, false, false, true, $lastLogin));
        $events['published'] = count($this->Event->fetchEventIds($this->Auth->user(), false, false, false, true, false, $lastLogin));
        $notifications = $this->{$this->modelClass}->populateNotifications($this->Auth->user());
        $this->set('notifications', $notifications);
        $this->set('events', $events);
    }

    public function checkIfLoggedIn()
    {
        return new CakeResponse(array('body'=> 'OK','status' => 200));
    }
}
